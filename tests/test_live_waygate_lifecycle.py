"""Opt-in lifecycle against a deployed Waygate service and disposable project.

WAYGATE_RUN_LIVE=1 enables the test; otherwise the entire test is skipped.
Required: WAYGATE_LIVE_BASE_URL, WAYGATE_LIVE_AUTH_TOKEN, WAYGATE_LIVE_NETWORK_ID.
Optional: WAYGATE_LIVE_SUBNET_ID, WAYGATE_LIVE_TIMEOUT_SECONDS (900), and
WAYGATE_LIVE_EXPECT_INSTALL_MODE (cloud-init or prebuilt).

WAYGATE_LIVE_DATAPLANE=1 additionally creates a disposable OpenStack probe VM.
It requires WAYGATE_LIVE_PROBE_NETWORK_ID (gateway endpoint/package repositories
must be reachable), WAYGATE_LIVE_PROBE_IMAGE_ID (Ubuntu cloud image),
WAYGATE_LIVE_PROBE_FLAVOR_ID, and WAYGATE_LIVE_PING_TARGET (an IPv4 address in the
attached subnet answering ICMP from the gateway NIC). OpenStack authentication
uses OS_CLOUD or OS_* through openstack.connect(); WAYGATE_LIVE_PROBE_KEYPAIR is
optional. The probe network must not bypass the gateway to reach the target.
No OpenStack SDK import or connection happens without both opt-in flags.
"""

from __future__ import annotations

import asyncio
import base64
import configparser
import ipaddress
import json
import math
import os
import re
import sys
import time
import uuid
from datetime import UTC, datetime

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("WAYGATE_RUN_LIVE") != "1",
    reason="set WAYGATE_RUN_LIVE=1 with live endpoint credentials and network IDs",
)


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.fail(f"{name} is required when WAYGATE_RUN_LIVE=1")
    return value


def _parse_ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


async def _wait_until(fetch, predicate, timeout: float, interval: float = 5, *, what: str):
    deadline = time.monotonic() + timeout
    while True:
        result = await fetch()
        if predicate(result):
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            pytest.fail(f"timed out waiting for {what}")
        await asyncio.sleep(min(interval, remaining))


async def _wait_for_server(
    client: httpx.AsyncClient,
    server_id: str,
    *,
    expected_status: str,
    timeout_seconds: float,
) -> dict:
    async def fetch():
        response = await client.get(f"/v1/servers/{server_id}")
        if response.status_code == 404 and expected_status == "DELETED":
            return {"status": "DELETED"}
        response.raise_for_status()
        server = response.json()
        if server["status"] == "ERROR":
            pytest.fail(f"Waygate server {server_id} entered ERROR")
        return server

    return await _wait_until(
        fetch,
        lambda server: server["status"] == expected_status,
        timeout_seconds,
        what=f"Waygate server {server_id} to reach {expected_status}",
    )


def _check_client_config(configuration: str, server: dict, tunnel_ip: str, cidr: str) -> dict:
    # Do not use rewritten assertions on config strings: failures would print keys.
    __tracebackhide__ = True
    parsed = configparser.ConfigParser(interpolation=None)
    try:
        parsed.read_string(configuration)
        valid = (
            bool(parsed["Interface"]["PrivateKey"])
            and parsed["Interface"]["Address"] == f"{tunnel_ip}/32"
            and parsed["Peer"]["Endpoint"] == f"{server['endpoint_ip']}:{server['listen_port']}"
            and parsed["Peer"]["PublicKey"] == server["server_public_key"]
            and cidr in [item.strip() for item in parsed["Peer"]["AllowedIPs"].split(",")]
        )
    except (configparser.Error, KeyError):
        pytest.fail("downloaded client configuration is malformed", pytrace=False)
    if not valid:
        pytest.fail("client configuration does not match the gateway and attachment", pytrace=False)
    return dict(parsed["Peer"])


def _probe_userdata(configuration: str, gateway_ip: str, target_ip: str) -> str:
    """Return Nova's base64 cloud-config, preserving the downloaded config verbatim."""
    gateway_ip = str(ipaddress.IPv4Address(gateway_ip))
    target_ip = str(ipaddress.IPv4Address(target_ip))
    script = f"""#!/bin/bash
set -eu
tunnel=fail
target=fail
handshake=0
finish() {{
    printf 'WAYGATE_PROBE_RESULT tunnel=%s target=%s handshake=%s\\n' "$tunnel" "$target" "$handshake" > /dev/console
}}
trap finish EXIT
wg-quick up wg0 > /var/log/waygate-probe.log 2>&1
for attempt in $(seq 1 36); do
    tunnel=fail
    target=fail
    ping -I wg0 -c 2 -W 2 {gateway_ip} > /dev/null 2>&1 && tunnel=ok
    ping -I wg0 -c 2 -W 2 {target_ip} > /dev/null 2>&1 && target=ok
    handshake=$(wg show wg0 latest-handshakes | awk 'NR == 1 {{print $2}}')
    handshake=${{handshake:-0}}
    if [ "$tunnel" = ok ] && [ "$target" = ok ] && [ "$handshake" -gt 0 ]; then
        break
    fi
    sleep 5
done
"""
    cloud_config = {
        "package_update": True,
        # wg-quick executes resolvconf when the generated client includes DNS.
        "packages": ["wireguard", "resolvconf", "iputils-ping"],
        "write_files": [
            {"path": "/etc/wireguard/wg0.conf", "permissions": "0600", "content": configuration},
            {"path": "/usr/local/sbin/waygate-probe", "permissions": "0700", "content": script},
        ],
        "runcmd": [["/bin/bash", "/usr/local/sbin/waygate-probe"]],
    }
    return base64.b64encode(("#cloud-config\n" + json.dumps(cloud_config)).encode()).decode()


async def _wait_for_probe_result(conn, probe_id: str, timeout_seconds: float) -> str:
    # Full-line matching ignores shell/cloud-init echoes and partial console writes.
    marker = re.compile(r"WAYGATE_PROBE_RESULT tunnel=(ok|fail) target=(ok|fail) handshake=([0-9]+)")
    deadline = time.monotonic() + timeout_seconds
    while True:
        output = await asyncio.to_thread(conn.compute.get_server_console_output, probe_id, length=200)
        for line in (output.get("output") or "").splitlines():
            match = marker.fullmatch(line.strip())
            if match:
                if match[1] != "ok" or match[2] != "ok" or int(match[3]) <= 0:
                    pytest.fail(f"probe VM {probe_id}: {match[0]}")
                return match[0]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            # Never dump the console: cloud-init may include sensitive user-data.
            pytest.fail(f"timed out waiting for probe VM {probe_id} result marker")
        await asyncio.sleep(min(10, remaining))


@pytest.mark.asyncio
async def test_live_gateway_full_lifecycle():
    base_url = _required_environment("WAYGATE_LIVE_BASE_URL").rstrip("/")
    auth_token = _required_environment("WAYGATE_LIVE_AUTH_TOKEN")
    network_id = _required_environment("WAYGATE_LIVE_NETWORK_ID")
    subnet_id = os.environ.get("WAYGATE_LIVE_SUBNET_ID", "").strip() or None
    timeout_seconds = float(os.environ.get("WAYGATE_LIVE_TIMEOUT_SECONDS", "900"))
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        pytest.fail("WAYGATE_LIVE_TIMEOUT_SECONDS must be finite and positive")
    expected_mode = os.environ.get("WAYGATE_LIVE_EXPECT_INSTALL_MODE", "").strip()
    if expected_mode and expected_mode not in {"cloud-init", "prebuilt"}:
        pytest.fail("WAYGATE_LIVE_EXPECT_INSTALL_MODE must be cloud-init or prebuilt")
    dataplane = os.environ.get("WAYGATE_LIVE_DATAPLANE") == "1"
    probe_options = {}
    if dataplane:
        probe_options = {
            "image_id": _required_environment("WAYGATE_LIVE_PROBE_IMAGE_ID"),
            "flavor_id": _required_environment("WAYGATE_LIVE_PROBE_FLAVOR_ID"),
            "networks": [{"uuid": _required_environment("WAYGATE_LIVE_PROBE_NETWORK_ID")}],
        }
        try:
            target_ip = str(ipaddress.IPv4Address(_required_environment("WAYGATE_LIVE_PING_TARGET")))
        except ipaddress.AddressValueError:
            pytest.fail("WAYGATE_LIVE_PING_TARGET must be an IPv4 address", pytrace=False)
        keypair = os.environ.get("WAYGATE_LIVE_PROBE_KEYPAIR", "").strip()
        if keypair:
            probe_options["key_name"] = keypair

    server_id = attachment_id = probe_id = None
    conn = None
    async with httpx.AsyncClient(base_url=base_url, headers={"X-Auth-Token": auth_token}, timeout=30) as client:
        async def fetch_server():
            response = await client.get(f"/v1/servers/{server_id}")
            response.raise_for_status()
            result = response.json()
            if result["status"] == "ERROR":
                pytest.fail(f"Waygate server {server_id} entered ERROR")
            return result

        async def fetch_clients():
            response = await client.get(f"/v1/servers/{server_id}/clients")
            response.raise_for_status()
            return response.json()

        async def wait_peers(count):
            return await _wait_until(
                fetch_server, lambda value: value.get("peer_count") == count,
                timeout_seconds, what=f"agent to report {count} peers",
            )

        try:
            response = await client.post("/v1/servers", json={"name": f"waygate-live-{uuid.uuid4().hex[:8]}"})
            response.raise_for_status()
            server = response.json()
            server_id = server["id"]
            assert response.status_code == 201
            assert server["status"] == "CREATING"
            server = await _wait_for_server(
                client, server_id, expected_status="ACTIVE", timeout_seconds=timeout_seconds,
            )
            assert server["server_vm_id"]
            assert server["server_public_key"]
            assert server["endpoint_ip"]
            if expected_mode:
                assert server["agent_install_mode"] == expected_mode
            server = await _wait_until(
                fetch_server, lambda value: value.get("last_status_reported_at") is not None,
                timeout_seconds, what="initial agent status report",
            )
            if expected_mode:
                assert server["agent_source"] == expected_mode

            attach_payload = {"network_id": network_id, "nat_mode": "snat"}
            if subnet_id:
                attach_payload["subnet_id"] = subnet_id
            response = await client.post(f"/v1/servers/{server_id}/networks", json=attach_payload)
            response.raise_for_status()
            attachment = response.json()
            attachment_id = attachment["id"]
            assert response.status_code == 201
            assert attachment["status"] == "ACTIVE"
            assert attachment["network_id"] == network_id
            if subnet_id:
                assert attachment["subnet_id"] == subnet_id
            cidr = attachment["cidr"]
            response = await client.get(f"/v1/servers/{server_id}/networks")
            response.raise_for_status()
            assert any(item["id"] == attachment_id for item in response.json())

            clients_path = f"/v1/servers/{server_id}/clients"
            response = await client.post(clients_path, json={"name": "probe"})
            response.raise_for_status()
            assert response.status_code == 201
            peer = response.json()
            client_id = peer["id"]
            client_path = f"{clients_path}/{client_id}"
            expected_peer = _check_client_config(peer.pop("tunnel_conf"), server, peer["tunnel_ip"], cidr)
            assert any(item["id"] == client_id for item in await fetch_clients())
            response = await client.get(f"{client_path}/config")
            response.raise_for_status()
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/plain")
            downloaded_peer = _check_client_config(response.text, server, peer["tunnel_ip"], cidr)
            assert downloaded_peer == expected_peer

            await wait_peers(1)
            response = await client.patch(client_path, json={"enabled": False})
            response.raise_for_status()
            assert response.status_code == 200
            assert response.json()["enabled"] is False
            await wait_peers(0)
            response = await client.patch(client_path, json={"enabled": True, "name": "probe-renamed"})
            response.raise_for_status()
            assert response.status_code == 200
            assert response.json()["enabled"] is True
            server = await wait_peers(1)
            assert next(item for item in await fetch_clients() if item["id"] == client_id)["name"] == "probe-renamed"

            issued_before = _parse_ts(server["agent_token_issued_at"])
            response = await client.post(f"/v1/servers/{server_id}/agent-token/rotate")
            response.raise_for_status()
            assert response.status_code == 202
            assert response.json()["agent_token_rotation_pending"] is True
            server = await _wait_until(
                fetch_server,
                lambda value: value["agent_token_rotation_pending"] is False
                and _parse_ts(value["agent_token_issued_at"]) > issued_before,
                timeout_seconds, what="agent token promotion",
            )
            promoted_at = _parse_ts(server["agent_token_issued_at"])
            await _wait_until(
                fetch_server,
                lambda value: bool(value.get("last_status_reported_at"))
                and _parse_ts(value["last_status_reported_at"]) > promoted_at,
                timeout_seconds, what="agent status after token promotion",
            )

            if dataplane:
                import openstack

                from waygate.services.ipam import server_tunnel_ip
                from waygate.services.openstack_ops import _wait_for_active, wait_server_deleted

                if ipaddress.IPv4Address(target_ip) not in ipaddress.IPv4Network(cidr):
                    pytest.fail("WAYGATE_LIVE_PING_TARGET must belong to the attached subnet")
                response = await client.get(f"{client_path}/config")
                response.raise_for_status()
                conn = await asyncio.to_thread(openstack.connect)
                probe = await asyncio.to_thread(
                    conn.compute.create_server,
                    name=f"waygate-probe-{uuid.uuid4().hex[:8]}",
                    user_data=_probe_userdata(response.text, server_tunnel_ip(server["tunnel_cidr"]), target_ip),
                    **probe_options,
                )
                probe_id = probe.id
                await _wait_for_active(conn, probe_id, timeout_seconds=max(10, math.ceil(timeout_seconds)))
                await _wait_for_probe_result(conn, probe_id, timeout_seconds)
                await _wait_until(
                    fetch_clients,
                    lambda values: any(
                        value["id"] == client_id and value.get("online") is True
                        and value.get("last_handshake_at") is not None for value in values
                    ),
                    timeout_seconds, what="agent to report the probe handshake",
                )
                await asyncio.to_thread(conn.compute.delete_server, probe_id, force=True)
                await asyncio.to_thread(wait_server_deleted, conn, probe_id, timeout=math.ceil(timeout_seconds))
                probe_id = None

            response = await client.delete(client_path)
            assert response.status_code == 204
            assert await fetch_clients() == []
            response = await client.delete(f"/v1/servers/{server_id}/networks/{attachment_id}")
            assert response.status_code == 204
            attachment_id = None
            response = await client.get(f"/v1/servers/{server_id}/networks")
            response.raise_for_status()
            assert response.json() == []
            response = await client.delete(f"/v1/servers/{server_id}")
            assert response.status_code == 202
            await _wait_for_server(client, server_id, expected_status="DELETED", timeout_seconds=timeout_seconds)
            server_id = None
        finally:
            original_error = sys.exception()
            cleanup_errors = []

            async def cleanup(label, action):
                try:
                    await action()
                except (Exception, pytest.fail.Exception) as error:
                    # SDK/HTTP exceptions can embed request bodies; record only type.
                    cleanup_errors.append(f"{label}: {type(error).__name__}")

            if probe_id is not None:
                await cleanup(
                    f"delete probe {probe_id}",
                    lambda: asyncio.to_thread(conn.compute.delete_server, probe_id, force=True),
                )
                await cleanup(
                    f"wait for probe {probe_id} deletion",
                    lambda: asyncio.to_thread(wait_server_deleted, conn, probe_id, timeout=math.ceil(timeout_seconds)),
                )
            if attachment_id is not None and server_id is not None:
                async def detach():
                    response = await client.delete(f"/v1/servers/{server_id}/networks/{attachment_id}")
                    if response.status_code != 404:
                        response.raise_for_status()

                await cleanup(f"detach network {attachment_id}", detach)
            if server_id is not None:
                async def delete_gateway():
                    response = await client.delete(f"/v1/servers/{server_id}")
                    if response.status_code != 404:
                        response.raise_for_status()
                    await _wait_for_server(
                        client, server_id, expected_status="DELETED", timeout_seconds=timeout_seconds,
                    )

                await cleanup(f"delete gateway {server_id}", delete_gateway)
            if conn is not None:
                await cleanup("close OpenStack connection", lambda: asyncio.to_thread(conn.close))
            if cleanup_errors:
                message = "Live lifecycle cleanup failed: " + "; ".join(cleanup_errors)
                if original_error is not None:
                    original_error.add_note(message)
                else:
                    pytest.fail(message)
