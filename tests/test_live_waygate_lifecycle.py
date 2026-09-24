"""Opt-in live Waygate lifecycle verification against a deployed service."""

from __future__ import annotations

import asyncio
import os
import time
import uuid

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


async def _wait_for_server(
    client: httpx.AsyncClient,
    server_id: str,
    *,
    expected_status: str,
    timeout_seconds: float,
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    last_response: dict | None = None
    while time.monotonic() < deadline:
        response = await client.get(f"/v1/servers/{server_id}")
        if response.status_code == 404 and expected_status == "DELETED":
            return {"status": "DELETED"}
        response.raise_for_status()
        last_response = response.json()
        status = last_response["status"]
        if status == expected_status:
            return last_response
        if status == "ERROR":
            pytest.fail(f"Waygate server entered ERROR: {last_response.get('status_reason')}")
        await asyncio.sleep(5)
    pytest.fail(
        f"timed out waiting for Waygate server {server_id} to reach {expected_status}; last response={last_response}"
    )


@pytest.mark.asyncio
async def test_live_gateway_create_attach_detach_delete_lifecycle():
    base_url = _required_environment("WAYGATE_LIVE_BASE_URL").rstrip("/")
    auth_token = _required_environment("WAYGATE_LIVE_AUTH_TOKEN")
    network_id = _required_environment("WAYGATE_LIVE_NETWORK_ID")
    subnet_id = os.environ.get("WAYGATE_LIVE_SUBNET_ID", "").strip() or None
    timeout_seconds = float(os.environ.get("WAYGATE_LIVE_TIMEOUT_SECONDS", "900"))

    server_id: str | None = None
    attachment_id: int | None = None
    headers = {"X-Auth-Token": auth_token}
    async with httpx.AsyncClient(base_url=base_url, headers=headers, timeout=30) as client:
        try:
            create_response = await client.post(
                "/v1/servers",
                json={"name": f"waygate-live-{uuid.uuid4().hex[:8]}"},
            )
            create_response.raise_for_status()
            server = create_response.json()
            server_id = server["id"]
            assert server["status"] == "CREATING"

            active_server = await _wait_for_server(
                client,
                server_id,
                expected_status="ACTIVE",
                timeout_seconds=timeout_seconds,
            )
            assert active_server["server_vm_id"]
            assert active_server["server_public_key"]

            attach_payload = {"network_id": network_id, "nat_mode": "snat"}
            if subnet_id:
                attach_payload["subnet_id"] = subnet_id
            attach_response = await client.post(
                f"/v1/servers/{server_id}/networks",
                json=attach_payload,
            )
            attach_response.raise_for_status()
            attachment = attach_response.json()
            attachment_id = attachment["id"]
            assert attachment["status"] == "ACTIVE"
            assert attachment["network_id"] == network_id
            if subnet_id:
                assert attachment["subnet_id"] == subnet_id

            list_response = await client.get(f"/v1/servers/{server_id}/networks")
            list_response.raise_for_status()
            assert any(item["id"] == attachment_id for item in list_response.json())

            detach_response = await client.delete(f"/v1/servers/{server_id}/networks/{attachment_id}")
            assert detach_response.status_code == 204
            attachment_id = None

            after_detach = await client.get(f"/v1/servers/{server_id}/networks")
            after_detach.raise_for_status()
            assert all(item["network_id"] != network_id for item in after_detach.json())

            delete_response = await client.delete(f"/v1/servers/{server_id}")
            assert delete_response.status_code == 202
            await _wait_for_server(
                client,
                server_id,
                expected_status="DELETED",
                timeout_seconds=timeout_seconds,
            )
            server_id = None
        finally:
            if attachment_id is not None and server_id is not None:
                await client.delete(f"/v1/servers/{server_id}/networks/{attachment_id}")
            if server_id is not None:
                await client.delete(f"/v1/servers/{server_id}")
