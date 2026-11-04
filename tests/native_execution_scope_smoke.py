"""Actual Uvicorn/worker/installed SDK smoke; loopback synthetic cloud and scratch SQL only."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from test_execution_delegation import (
    FLAVOR,
    IMAGE,
    NETWORK,
    PASSWORD,
    SERVICE_PROJECT,
    SERVICE_USER,
    SyntheticCloud,
    _handler,
)

from waygate import db
from waygate.models.orm import ResourcePolicy


async def schema(url):
    engine = create_async_engine(url)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(db.Base.metadata.create_all)
        async with async_sessionmaker(engine)() as session, session.begin():
            for key, kind, resource_id in (
                ("waygate.flavor", "flavor", FLAVOR), ("waygate.image", "image", IMAGE),
                ("waygate.provider_network", "network", NETWORK),
            ):
                session.add(ResourcePolicy(policy_key=key, resource_kind=kind, resource_id=resource_id))
    finally:
        await engine.dispose()


def main():
    cloud = SyntheticCloud()
    # Match actual deployed Keystone: member→reader; token expiration=86400.
    cloud.token_lifetime = timedelta(hours=24)
    provider = ThreadingHTTPServer(("127.0.0.1", 0), _handler(cloud))
    cloud.base = f"http://127.0.0.1:{provider.server_port}"
    thread = threading.Thread(target=provider.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    results = []
    try:
        with tempfile.TemporaryDirectory(prefix="waygate-execution-scope-") as scratch:
            root = Path(scratch)
            url = f"sqlite+aiosqlite:///{root / 'scope.sqlite'}"
            asyncio.run(schema(url))
            config = root / "waygate.conf"
            config.write_text("")
            env = {
                "PATH": os.environ["PATH"], "HOME": os.environ["HOME"], "TMPDIR": scratch,
                "PYTHONPATH": str(Path(__file__).resolve().parents[1]), "WAYGATE_CONFIG_FILE": str(config),
                "DATABASE_URL": url, "OS_AUTH_URL": cloud.base + ("" if "--unversioned" in sys.argv else "/v3"),
                "OS_USERNAME": SERVICE_USER,
                "OS_PASSWORD": PASSWORD, "OS_PROJECT_NAME": SERVICE_PROJECT, "OS_INTERFACE": "internal",
                "WAYGATE_ENCRYPTION_KEY": "a" * 64, "WAYGATE_CALLBACK_BASE_URL": "https://callbacks.example.test",
                "REDIS_URL": "redis://127.0.0.1:1/6", "LOG_LEVEL": "ERROR", "PYTHONDONTWRITEBYTECODE": "1",
            }
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            listener.close()

            def worker():
                result = subprocess.run([
                    sys.executable, "-c", "import asyncio;"
                    "from waygate.config import get_settings;from waygate.db import init_db,close_db;"
                    "from waygate.services.jobs import process_one_job;"
                    "init_db(get_settings().database_url);asyncio.run(process_one_job());asyncio.run(close_db())",
                ], env=env, capture_output=True, text=True, timeout=90)
                assert result.returncode == 0, result.stderr

            with (root / "api.log").open("w+") as log:
                api = subprocess.Popen([
                    sys.executable, "-m", "uvicorn", "waygate.main:app", "--host", "127.0.0.1", "--port", str(port),
                    "--no-access-log", "--log-level", "error",
                ], env=env, stdout=log, stderr=log)
                try:
                    with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=30) as client:
                        for _ in range(150):
                            try:
                                if client.get("/v1/health").status_code == 200:
                                    break
                            except httpx.TransportError:
                                pass
                            time.sleep(0.1)
                        else:
                            raise AssertionError("Scratch Uvicorn readiness failed")
                        original = cloud.login("user-a", "project-a")
                        headers = {"X-Auth-Token": original, "X-Project-Id": "project-a"}
                        created = client.post("/v1/servers", json={"name": "native-24h-member"}, headers=headers)
                        assert created.status_code == 201, created.text
                        [trust] = cloud.trusts.values()
                        assert trust["roles"] == ["member"]
                        issued = [record for record in cloud.tokens.values() if record["trust"] is not None]
                        assert issued and all(record["expires"] > trust["expires"] for record in issued)
                        worker()
                        visible = client.get(f"/v1/servers/{created.json()['id']}", headers=headers)
                        assert visible.status_code == 200 and visible.json()["status"] == "PROVISIONING", visible.text
                        assert all(record["roles"] == {"member", "reader"} for _, _, record in cloud.cloud_requests)
                        results.append({"case": "24h-native-token-2h-operation", "create": 201,
                                        "worker": "completed", "status": "PROVISIONING", "delegated_roles": ["member"]})
                        before = len(cloud.cloud_requests)
                        old_reader = cloud.issue(["password"], "user-a", "project-a", {"reader"})
                        denied = client.post("/v1/servers", json={"name": "no-token-upgrade"},
                                             headers={"X-Auth-Token": old_reader, "X-Project-Id": "project-a"})
                        assert denied.status_code == 403 and len(cloud.cloud_requests) == before, denied.text
                        results.append({"case": "original-reader-current-member", "status": 403, "provider_sends": 0})
                        queued = client.post("/v1/servers", json={"name": "revoked-member"}, headers=headers)
                        assert queued.status_code == 201, queued.text
                        before = len(cloud.cloud_requests)
                        cloud.assignments["user-a", "project-a"] = {"reader"}
                        worker()
                        assert cloud.cloud_requests[before:] == []
                        visible = client.get(f"/v1/servers/{queued.json()['id']}", headers=headers)
                        assert visible.status_code == 200 and visible.json()["status"] == "ERROR", visible.text
                        results.append({"case": "queued-member-revoked", "status": "ERROR", "provider_sends": 0})
                        assert all(document["auth"]["identity"]["methods"] == ["password"]
                                   for document in cloud.auth_requests)
                        results.append({"case": "original-token-preserved", "token_exchanges": 0})
                finally:
                    api.terminate()
                    api.wait(timeout=30)
    finally:
        provider.shutdown()
        provider.server_close()
        thread.join()
    print(json.dumps({"service": "waygate", "transport": "actual-uvicorn-worker-installed-sdk-loopback",
                      "schema": "scratch-sqlite", "cloud_writes": "synthetic-only", "results": results}, sort_keys=True))


if __name__ == "__main__":
    main()
