"""Claim-fenced gateway lifecycle with durable, non-replayable create intents."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime

from openstack.exceptions import ResourceNotFound
from sqlalchemy import select

from waygate.config import get_settings, require_public_callback_base_url
from waygate.db import get_session_factory
from waygate.models.orm import WaygateJob, WaygateServer
from waygate.services import execution, neutron, waygate_agent_auth, waygate_config, waygate_db
from waygate.services.openstack_ops import _extract_fixed_ip

_logger = logging.getLogger(__name__)
_WG_INGRESS_SG_NAME = "afterglow-waygate-wireguard"
_INTENTS = "waygate.provision_intents"
_PROTOCOL = "waygate.provision_protocol"
_ID_FIELDS = {"port": "provider_port_id", "vm": "server_vm_id", "fip": "fip_id"}


class ProvisionIntentUnresolved(RuntimeError):
    """An accepted create cannot yet be identified exactly; never replay it."""


def _admitted_protocol(record: dict, claim) -> bool:
    admission = (record.get("resource_policy_snapshot") or {}).get(_PROTOCOL)
    version = admission.get("version") if isinstance(admission, dict) else None
    return isinstance(version, int) and not isinstance(version, bool) and admission == {
        "version": 1,
        "job_id": claim.job_id,
        "project_id": claim.project_id,
        "server_id": claim.server_id,
    }


async def _check() -> None:
    claim = execution.current_claim.get()
    if claim is not None:
        await claim.check()


async def _store(fn, *args, **kwargs):
    """Hold the attempt fence until an existing store transaction commits."""
    await _check()
    claim = execution.current_claim.get()
    if claim is None:
        return await fn(*args, **kwargs)
    async with get_session_factory()() as session, session.begin():
        await claim.locked_job(session)
        return await fn(*args, **kwargs)


async def _provider(fn, *args, **kwargs):
    # Native sessions also check each HTTP request (including pagination). This
    # boundary protects nonnative connections and keeps threads owned until exit.
    await _check()
    return await execution.drain_thread(fn, *args, **kwargs)


async def _update(server_id: str, status=None, reason=None, *, only_if_status=None, **fields) -> None:
    claim = execution.current_claim.get()
    if claim is None:
        await waygate_db.update_server_status(server_id, status, reason, only_if_status=only_if_status, **fields)
        return
    # Lifecycle status, identity and intent commits share the SQL attempt fence;
    # a preceding check alone can become stale before this transaction commits.
    async with get_session_factory()() as session, session.begin():
        await claim.locked_job(session)
        if server_id != claim.server_id:
            raise execution.ExecutionDenied("Waygate lifecycle write does not match the claimed server")
        row = await session.get(WaygateServer, server_id, with_for_update=True)
        if row is None or row.deleted_at is not None:
            raise ProvisionIntentUnresolved("Waygate server is unavailable for durable identity")
        if row.project_id != claim.project_id:
            raise execution.ExecutionDenied("Waygate lifecycle write does not match the claimed project")
        if status is not None and (only_if_status is None or row.status == only_if_status):
            row.status = status
            if reason is not None:
                row.status_reason = reason
        for key, value in fields.items():
            setattr(row, key, value)
        row.updated_at = datetime.now(UTC)


async def _save_intent(record: dict, kind: str, intent: dict, **fields) -> None:
    snapshot = dict(record.get("resource_policy_snapshot") or {})
    intents = dict(snapshot.get(_INTENTS) or {})
    intents[kind] = dict(intent)
    snapshot[_INTENTS] = intents
    await _check()
    await _update(record["id"], resource_policy_snapshot=snapshot, **fields)
    # The existing store intentionally ignores vanished/deleted rows. A POST is
    # permitted only after positively observing its committed intent.
    saved = await waygate_db.get_server_by_id(record["id"])
    if not saved or (saved.get("resource_policy_snapshot") or {}).get(_INTENTS, {}).get(kind) != intent:
        raise ProvisionIntentUnresolved("Waygate create intent was not durably recorded")
    record.update(fields)
    record["resource_policy_snapshot"] = snapshot


def _value(resource, key, default=None):
    if isinstance(resource, dict):
        return resource.get(key, default)
    return getattr(resource, key, default)


def _description(record: dict, kind: str, intent: dict) -> str:
    return f"waygate:{record['id']}:{kind}:{intent['marker']}"


def _intent(record: dict, kind: str) -> dict | None:
    intents = (record.get("resource_policy_snapshot") or {}).get(_INTENTS) or {}
    intent = intents.get(kind)
    if intent is None:
        return None
    try:
        marker = intent["marker"]
        valid = str(uuid.UUID(marker)) == marker and intent["project_id"] == record["project_id"]
        network_field = "floating_network_id" if kind == "fip" else "provider_network_id"
        valid = valid and bool(intent.get("network_id")) and intent["network_id"] == record.get(network_field)
        if kind in ("vm", "fip"):
            valid = valid and bool(intent.get("port_id")) and intent["port_id"] == record.get("provider_port_id")
    except (KeyError, TypeError, ValueError, AttributeError):
        valid = False
    if not valid:
        raise ProvisionIntentUnresolved(f"Waygate {kind} intent scope is invalid")
    if intent.get("resource_id") and record.get(_ID_FIELDS[kind]) not in (None, intent["resource_id"]):
        raise ProvisionIntentUnresolved(f"Waygate {kind} durable identity conflicts")
    return intent


async def _get(conn, kind: str, resource_id: str):
    def get_resource():
        if kind == "vm":
            return conn.compute.get_server(resource_id)
        if kind == "port":
            return conn.network.get_port(resource_id)
        return conn.network.get_ip(resource_id)

    try:
        return await _provider(get_resource)
    except ResourceNotFound:
        return None


async def _observe(conn, record: dict, kind: str, *, deleting=False):
    """Recover only the exact marker and scope, or keep the intent unresolved."""
    intent = _intent(record, kind)
    resource_id = record.get(_ID_FIELDS[kind]) or (intent or {}).get("resource_id")
    recorded_identity = bool(resource_id)
    if not intent and not resource_id:
        return None
    if resource_id:
        resource = await _get(conn, kind, resource_id)
        if resource is None:
            if deleting:
                return None  # A previously committed identity is conclusively absent.
            raise ProvisionIntentUnresolved(f"Waygate {kind} recorded target is unavailable")
    else:
        if kind == "vm":
            resources = await _provider(lambda: list(conn.compute.servers()))
            matches = [r for r in resources if (_value(r, "metadata") or {}).get("waygate_create_intent") == intent["marker"]]
        else:
            resources = await _provider(lambda: list(
                (conn.network.ports if kind == "port" else conn.network.ips)(project_id=record["project_id"])
            ))
            matches = [r for r in resources if _value(r, "description") == _description(record, kind, intent)]
        if len(matches) != 1:
            raise ProvisionIntentUnresolved(f"Waygate {kind} create intent has no unique owned target")
        resource = matches[0]
        resource_id = _value(resource, "id")
        # Nova list representations may omit metadata/project details.
        resource = await _get(conn, kind, resource_id)
        if resource is None:
            raise ProvisionIntentUnresolved(f"Waygate {kind} target disappeared during recovery")

    project = _value(resource, "project_id") or _value(resource, "tenant_id")
    valid = bool(resource_id) and _value(resource, "id") == resource_id and project == record["project_id"]
    if kind == "vm":
        metadata = _value(resource, "metadata") or {}
        valid = valid and all(metadata.get(key) == value for key, value in {
            "afterglow_managed": "true", "waygate_type": "gateway", "waygate_server_id": record["id"],
        }.items())
        if intent:
            valid = valid and metadata.get("waygate_create_intent") == intent["marker"]
        port_id = (intent or {}).get("port_id") or record.get("provider_port_id")
        port = await _get(conn, "port", port_id) if port_id else None
        valid = valid and port is not None and _value(port, "device_id") == resource_id
        valid = valid and (_value(port, "project_id") or _value(port, "tenant_id")) == record["project_id"]
        valid = valid and _value(port, "network_id") == ((intent or {}).get("network_id") or record.get("provider_network_id"))
    else:
        network_key = "network_id" if kind == "port" else "floating_network_id"
        expected_network = (intent or {}).get("network_id") or record.get("provider_network_id" if kind == "port" else "floating_network_id")
        valid = valid and _value(resource, network_key) == expected_network
        if intent:
            valid = valid and _value(resource, "description") == _description(record, kind, intent)
        if kind == "port":
            groups = (intent or {}).get("security_group_ids")
            if groups is not None:
                valid = valid and set(_value(resource, "security_group_ids", _value(resource, "security_groups", [])) or []) == set(groups)
            vm_intent = _intent(record, "vm")
            vm_id = record.get("server_vm_id") or (vm_intent or {}).get("resource_id")
            # An accepted VM may have attached this port before its reply was
            # recorded. The VM observer below proves that exact attachment.
            if vm_id or vm_intent is None:
                valid = valid and _value(resource, "device_id", "") in ("", None, vm_id)
        else:
            expected_port = (intent or {}).get("port_id") or record.get("provider_port_id")
            association = _value(resource, "port_id")
            valid = valid and (association == expected_port or (
                deleting and recorded_identity and association in (None, "")
            ))
    if not valid:
        raise ProvisionIntentUnresolved(f"Waygate {kind} target does not match exact owned scope")
    if intent and (intent.get("resource_id") != resource_id or record.get(_ID_FIELDS[kind]) != resource_id):
        await _save_intent(record, kind, {**intent, "resource_id": resource_id}, **{_ID_FIELDS[kind]: resource_id})
    return resource


async def _create(conn, record: dict, kind: str, scope: dict, fn, **kwargs):
    if _intent(record, kind) is not None or record.get(_ID_FIELDS[kind]):
        return await _observe(conn, record, kind)
    intent = {"marker": str(uuid.uuid4()), "project_id": record["project_id"], **scope}
    await _save_intent(record, kind, intent)
    if kind == "vm":
        kwargs["metadata"] = {**kwargs["metadata"], "waygate_create_intent": intent["marker"]}
    else:
        kwargs["description"] = _description(record, kind, intent)
    try:
        resource = await _provider(fn, **kwargs)
    except (execution.ClaimLost, execution.ExecutionDenied, execution.ExecutionUnavailable):
        raise
    except Exception as exc:
        # A failure says nothing about provider acceptance. Recovery is read-only
        # and happens on the next attempt; no compensating deletion is safe here.
        raise ProvisionIntentUnresolved(f"Waygate {kind} create response is unresolved") from exc
    resource_id = _value(resource, "id")
    if not resource_id:
        raise ProvisionIntentUnresolved(f"Waygate {kind} create response omitted identity")
    await _save_intent(record, kind, {**intent, "resource_id": resource_id}, **{_ID_FIELDS[kind]: resource_id})
    return resource


async def _ensure_wireguard_sg(conn, project_id: str, listen_port: int) -> str:
    sgs = await _provider(neutron.list_security_groups, conn, project_id=project_id)
    existing = next((sg for sg in sgs if sg["name"] == _WG_INGRESS_SG_NAME), None)
    if existing is None:
        existing = await _provider(neutron.create_security_group, conn, _WG_INGRESS_SG_NAME,
                                   f"Waygate WireGuard gateway UDP ingress {neutron.AFTERGLOW_MANAGED_TAG}")
    keys = {(r.get("protocol"), r.get("port_range_min"), r.get("port_range_max"), r.get("remote_ip_prefix"))
            for r in existing.get("rules", []) if r.get("direction") == "ingress"}
    if ("udp", listen_port, listen_port, "0.0.0.0/0") not in keys:
        await _provider(neutron.create_security_group_rule, conn, existing["id"], direction="ingress", protocol="udp",
                        port_range_min=listen_port, port_range_max=listen_port, remote_ip_prefix="0.0.0.0/0")
    return existing["id"]


async def _boot_kwargs(conn, flavor_id: str, image_id: str) -> dict:
    flavor = await _provider(lambda: conn.compute.get_flavor(flavor_id))
    if flavor is None:
        raise RuntimeError("Waygate flavor is unavailable in the execution scope")
    if flavor.disk != 0:
        return {"image_id": image_id}
    image = await _provider(lambda: conn.image.get_image(image_id))
    if image is None:
        raise RuntimeError("Waygate image is unavailable in the execution scope")
    return {"block_device_mapping": [{"uuid": image_id, "source_type": "image", "destination_type": "volume",
                                      "volume_size": max(10, int(image.min_disk or 0)), "boot_index": 0,
                                      "delete_on_termination": True}]}


async def _wait_for_active(conn, server_id: str, timeout_seconds: int = 600) -> None:
    for _ in range(timeout_seconds // 10):
        server = await _provider(lambda: conn.compute.get_server(server_id))
        if server.status == "ACTIVE":
            return
        if server.status == "ERROR":
            raise RuntimeError(f"Waygate VM {server_id} entered ERROR")
        await asyncio.sleep(10)
    raise TimeoutError(f"Waygate VM {server_id} did not become ACTIVE")


async def provision_waygate_server(project_id: str, server_id: str, user_id: str, username: str, *, conn) -> None:
    """Resume durable resources; never replay an intent or rotate an existing VM's bearer."""
    record = await waygate_db.get_server_by_id(server_id)
    if not record:
        raise RuntimeError("Waygate server is unavailable")
    if record["project_id"] != project_id:
        raise execution.ExecutionDenied("Waygate server project does not match execution")
    try:
        callback_base = require_public_callback_base_url(get_settings())
        snapshot = record.get("resource_policy_snapshot") or {}
        for field, policy in (("provider_network_id", "waygate.provider_network"), ("flavor_id", "waygate.flavor"),
                              ("image_id", "waygate.image"), ("floating_network_id", "waygate.floating_network")):
            record[field] = record.get(field) or (snapshot.get(policy) or {}).get("id")
        if not all(record.get(key) for key in ("provider_network_id", "flavor_id", "image_id")):
            raise RuntimeError("Waygate resource policy snapshot is incomplete")
        claim = execution.current_claim.get()
        if claim is not None and not snapshot.get(_INTENTS) and not _admitted_protocol(record, claim):
            required = ["provider_port_id", "server_vm_id"]
            if record["floating_network_id"]:
                required.append("fip_id")
            if any(not record.get(field) for field in required):
                raise ProvisionIntentUnresolved("Legacy Waygate create requires operator identity reconciliation")

        # Recover before any new mutation. In particular, an ambiguous VM must
        # not rotate its bootstrap credential while its acceptance is unknown.
        port = await _observe(conn, record, "port")
        vm = await _observe(conn, record, "vm")
        fip = await _observe(conn, record, "fip")
        if port is None:
            sg_id = await _ensure_wireguard_sg(conn, project_id, record["listen_port"])
            await _update(server_id, provider_network_id=record["provider_network_id"], security_group_id=sg_id,
                          flavor_id=record["flavor_id"], image_id=record["image_id"], floating_network_id=record["floating_network_id"])
            record["security_group_id"] = sg_id
            port = await _create(conn, record, "port", {"network_id": record["provider_network_id"], "security_group_ids": [sg_id]},
                                 lambda **kwargs: conn.network.create_port(**kwargs),
                                 network_id=record["provider_network_id"], name=f"{record['name']}-port",
                                 security_groups=[sg_id])
        if vm is None:
            boot_kwargs = await _boot_kwargs(conn, record["flavor_id"], record["image_id"])
            bootstrap_token = await _store(waygate_agent_auth.issue_report_token, server_id)
            userdata = waygate_config.render_agent_userdata(
                server_name=record["name"], listen_port=record["listen_port"], tunnel_cidr=record["tunnel_cidr"],
                register_url=f"{callback_base}/v1/servers/{server_id}/agent/register",
                desired_state_url=f"{callback_base}/v1/servers/{server_id}/agent/desired-state",
                status_url=f"{callback_base}/v1/servers/{server_id}/agent/status", bootstrap_token=bootstrap_token,
                install_packages=record.get("agent_install_mode", "cloud-init") != "prebuilt",
            )
            vm = await _create(conn, record, "vm", {"network_id": record["provider_network_id"], "port_id": record["provider_port_id"],
                                                    "flavor_id": record["flavor_id"], "image_id": record["image_id"]},
                               lambda **kwargs: conn.compute.create_server(**kwargs),
                               name=record["name"], **boot_kwargs, flavor_id=record["flavor_id"],
                               networks=[{"port": record["provider_port_id"]}], user_data=userdata,
                               metadata={"afterglow_managed": "true", "waygate_type": "gateway", "waygate_server_id": server_id})
        await _wait_for_active(conn, _value(vm, "id"))
        vm = await _provider(lambda: conn.compute.get_server(_value(vm, "id")))
        fixed_ip = _extract_fixed_ip(vm)
        if not fixed_ip:
            raise RuntimeError("Waygate VM has no fixed IP")
        if record["floating_network_id"]:
            if fip is None:
                fip = await _create(conn, record, "fip", {"network_id": record["floating_network_id"], "port_id": record["provider_port_id"]},
                                    lambda **kwargs: conn.network.create_ip(**kwargs),
                                    floating_network_id=record["floating_network_id"], port_id=record["provider_port_id"])
            endpoint_ip = _value(fip, "floating_ip_address")
            if not endpoint_ip:
                raise ProvisionIntentUnresolved("Waygate floating IP has no address")
        else:
            endpoint_ip = fixed_ip
        await _update(server_id, "PROVISIONING", "에이전트 register 대기 중",
                      only_if_status="ERROR" if record.get("status") == "ERROR" else "CREATING",
                      endpoint_ip=endpoint_ip, key_name=None)
        _logger.info("waygate_provisioner stage=provision status=ready")
    except (execution.ClaimLost, execution.ExecutionDenied, execution.ExecutionUnavailable, ProvisionIntentUnresolved):
        raise
    except Exception:
        # Keep every marker and accepted identity. A later job resumes rather
        # than destroying a VM and issuing another create under the same intent.
        await _update(server_id, "ERROR", "프로비저닝 실패")
        raise


async def _wait_deleted(conn, vm_id: str, timeout_seconds: int = 120) -> None:
    for _ in range(timeout_seconds // 3):
        if await _get(conn, "vm", vm_id) is None:
            return
        await asyncio.sleep(3)
    raise TimeoutError("Waygate VM deletion did not complete")


async def _cleanup_instance_fips(conn, record: dict, vm_id: str) -> None:
    ports = await _provider(lambda: list(conn.network.ports(device_id=vm_id)))
    for port in ports:
        if (not _value(port, "id") or _value(port, "device_id") != vm_id
                or (_value(port, "project_id") or _value(port, "tenant_id")) != record["project_id"]):
            raise ProvisionIntentUnresolved("Waygate cleanup port inventory does not match owned VM scope")
    port_ids = {_value(port, "id") for port in ports}
    if not port_ids:
        return
    floating_ips = await _provider(lambda: list(conn.network.ips(project_id=record["project_id"])))
    for floating_ip in floating_ips:
        if _value(floating_ip, "port_id") in port_ids:
            if (_value(floating_ip, "project_id") or _value(floating_ip, "tenant_id")) != record["project_id"]:
                raise ProvisionIntentUnresolved("Waygate associated floating IP project does not match")
            await _provider(lambda floating_ip=floating_ip: conn.network.delete_ip(_value(floating_ip, "id"), ignore_missing=True))


async def _no_unrecorded_create(record: dict) -> bool:
    """Prove no create ran from zero attempts or exact admitted protocol history."""
    if (
        (record.get("resource_policy_snapshot") or {}).get(_INTENTS)
        or any(record.get(field) for field in _ID_FIELDS.values())
    ):
        return False
    factory = get_session_factory()
    if factory is None:
        raise execution.ExecutionUnavailable("Waygate provisioning history is unavailable")
    async with factory() as session, session.begin():
        claim = execution.current_claim.get()
        if claim is not None:
            await claim.locked_job(session)
        provision_jobs = (
            await session.execute(
                select(WaygateJob).where(
                    WaygateJob.server_id == record["id"],
                    WaygateJob.project_id == record["project_id"],
                    WaygateJob.kind == "provision",
                )
            )
        ).scalars().all()
        admission = (record.get("resource_policy_snapshot") or {}).get(_PROTOCOL)
        version = admission.get("version") if isinstance(admission, dict) else None
        supported = isinstance(version, int) and not isinstance(version, bool)
        for job in provision_jobs:
            if job.attempts and (
                not supported
                or admission != {
                    "version": 1,
                    "job_id": job.id,
                    "project_id": job.project_id,
                    "server_id": job.server_id,
                }
            ):
                return False
        return bool(provision_jobs)


async def delete_waygate_server(project_id: str, server_id: str, user_id: str, *, conn) -> None:
    record = await waygate_db.get_server(project_id, server_id)
    if not record:
        return
    try:
        if (
            not (record.get("resource_policy_snapshot") or {}).get(_INTENTS)
            and not record.get("server_vm_id")
            and not await _no_unrecorded_create(record)
        ):
            raise ProvisionIntentUnresolved("Legacy Waygate deletion requires operator identity reconciliation")
        # All ambiguous creates must be resolved before destroying any resource:
        # deleting the port first would destroy the evidence needed to find a VM.
        port = await _observe(conn, record, "port", deleting=True)
        vm = await _observe(conn, record, "vm", deleting=True)
        fip = await _observe(conn, record, "fip", deleting=True)
        if vm is not None:
            vm_id = _value(vm, "id")
            await _cleanup_instance_fips(conn, record, vm_id)
            await _provider(lambda: conn.compute.delete_server(vm_id, force=True, ignore_missing=True))
            await _wait_deleted(conn, vm_id)
        if fip is not None:
            await _provider(lambda: conn.network.delete_ip(_value(fip, "id"), ignore_missing=True))
        attachments = await waygate_db.list_server_attachments(server_id)
        if any(att["status"] == "CREATING" for att in attachments):
            raise RuntimeError("Waygate attachment creation is still in progress")
        for att in attachments:
            if att["port_id"]:
                await _provider(neutron.delete_port, conn, att["port_id"])
                await _store(waygate_db.update_attachment, att["id"], port_id=None, status="DELETED")
        if port is not None:
            await _provider(neutron.delete_port, conn, _value(port, "id"))
        if not await _store(waygate_db.soft_delete_server, project_id, server_id, user_id, reason="사용자 요청"):
            raise RuntimeError("Waygate server deletion could not be finalized")
        _logger.info("waygate_provisioner stage=delete status=completed")
    except (execution.ClaimLost, execution.ExecutionDenied, execution.ExecutionUnavailable, ProvisionIntentUnresolved):
        raise
    except Exception:
        await _update(server_id, "ERROR", "삭제 실패")
        raise
