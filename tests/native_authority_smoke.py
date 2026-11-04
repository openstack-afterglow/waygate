"""Real loopback Uvicorn/installed-SDK core-role smoke; synthetic cloud only."""
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
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
from sqlalchemy.ext.asyncio import create_async_engine
from test_execution_delegation import (
    FLAVOR,
    IMAGE,
    IMPLIES,
    NETWORK,
    PASSWORD,
    SERVICE_PROJECT,
    SERVICE_USER,
    SyntheticCloud,
    _handler,
)

from waygate import __version__, db
from waygate.models.orm import ResourcePolicy


async def schema(url):
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(db.Base.metadata.create_all)
        from sqlalchemy.ext.asyncio import async_sessionmaker

        async with async_sessionmaker(engine)() as session, session.begin():
            for key, kind, resource_id in (
                ("waygate.flavor", "flavor", FLAVOR),
                ("waygate.image", "image", IMAGE),
                ("waygate.provider_network", "network", NETWORK),
            ):
                session.add(ResourcePolicy(policy_key=key, resource_kind=kind, resource_id=resource_id))
    finally:
        await engine.dispose()


def main():
    cloud = SyntheticCloud()
    saved_implies = dict(IMPLIES)
    IMPLIES.clear()  # Prove manager/admin without any implied member.
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(cloud))
    cloud.base = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    results = []
    try:
        with tempfile.TemporaryDirectory(prefix="native-authority-", dir=os.environ["TMPDIR"]) as scratch:
            root = Path(scratch)
            url = f"sqlite+aiosqlite:///{root / 'authority.sqlite'}"
            asyncio.run(schema(url))
            config = root / "waygate.conf"
            config.write_text("")
            env = {
                "PATH": os.environ["PATH"],
                "HOME": os.environ["HOME"],
                "TMPDIR": str(root),
                "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
                "WAYGATE_CONFIG_FILE": str(config),
                "DATABASE_URL": url,
                "OS_AUTH_URL": cloud.base + "/v3",
                "OS_USERNAME": SERVICE_USER,
                "OS_PASSWORD": PASSWORD,
                "OS_PROJECT_NAME": SERVICE_PROJECT,
                "OS_INTERFACE": "internal",
                "WAYGATE_ENCRYPTION_KEY": "a" * 64,
                "WAYGATE_CALLBACK_BASE_URL": "https://callbacks.example.test",
                "REDIS_URL": "redis://127.0.0.1:1/6",
                "LOG_LEVEL": "ERROR",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            listener.close()
            with (root / "api.log").open("w+") as log:
                api = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "waygate.main:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                        "--no-access-log",
                        "--log-level",
                        "error",
                    ],
                    env=env,
                    stdout=log,
                    stderr=log,
                )
                try:
                    with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=30) as client:
                        for _ in range(100):
                            try:
                                if client.get("/v1/health").status_code == 200:
                                    break
                            except httpx.TransportError:
                                pass
                            time.sleep(0.1)
                        else:
                            log.flush()
                            log.seek(0)
                            raise AssertionError("Uvicorn readiness failed: " + log.read())
                        for role in ("member", "manager", "admin"):
                            IMPLIES.clear()
                            if role == "member":
                                IMPLIES.update(saved_implies)
                            cloud.assignments["user-a", "project-a"] = {role}
                            token = cloud.login("user-a", "project-a")
                            headers = {"X-Auth-Token": token, "X-Project-Id": "project-a"}
                            caps = client.get("/v1/policy/capabilities", headers=headers)
                            assert caps.status_code == 200, caps.text
                            assert caps.headers["cache-control"] == "no-store"
                            assert "waygate:server:create" in caps.json()["actions"]
                            created = client.post("/v1/servers", json={"name": role}, headers=headers)
                            assert created.status_code == 201, created.text
                            server_id = created.json()["id"]
                            trust = list(cloud.trusts.values())[-1]
                            assert trust["roles"] == [role]
                            worker = subprocess.run(
                                [
                                    sys.executable,
                                    "-c",
                                    "import asyncio;"
                                    "from waygate.config import get_settings;"
                                    "from waygate.db import init_db,close_db;"
                                    "from waygate.services.jobs import process_one_job;"
                                    "s=get_settings();init_db(s.database_url);"
                                    "asyncio.run(process_one_job());asyncio.run(close_db())",
                                ],
                                env=env,
                                capture_output=True,
                                text=True,
                                timeout=90,
                            )
                            assert worker.returncode == 0, worker.stderr
                            item = client.get(f"/v1/servers/{server_id}", headers=headers)
                            assert item.status_code == 200, item.text
                            assert item.json()["status"] == "PROVISIONING", item.text
                            deleted = client.delete(f"/v1/servers/{server_id}", headers=headers)
                            assert deleted.status_code == 202, deleted.text
                            worker = subprocess.run(
                                [
                                    sys.executable,
                                    "-c",
                                    "import asyncio;"
                                    "from waygate.config import get_settings;"
                                    "from waygate.db import init_db,close_db;"
                                    "from waygate.services.jobs import process_one_job;"
                                    "s=get_settings();init_db(s.database_url);"
                                    "asyncio.run(process_one_job());asyncio.run(close_db())",
                                ],
                                env=env,
                                capture_output=True,
                                text=True,
                                timeout=90,
                            )
                            assert worker.returncode == 0, worker.stderr
                            assert not cloud.servers and not cloud.ports
                            results.append(
                                {
                                    "role": role,
                                    "capabilities": caps.status_code,
                                    "create": created.status_code,
                                    "provider_completed": True,
                                    "delete": deleted.status_code,
                                    "delegated_roles": trust["roles"],
                                }
                            )
                        IMPLIES.clear()
                        IMPLIES.update(saved_implies)
                        cloud.assignments["user-a", "project-a"] = {"reader"}
                        reader = {"X-Auth-Token": cloud.login("user-a", "project-a")}
                        assert client.get("/v1/servers", headers=reader).status_code == 200
                        assert client.post("/v1/servers", json={"name": "denied"}, headers=reader).status_code == 403
                        caps = client.get("/v1/policy/capabilities", headers=reader)
                        assert caps.json()["capabilities"] == ["waygate-inventory_reader"]
                        results.append({"role": "reader", "inventory": 200, "write": 403})
                        cloud.assignments["user-a", "project-a"] = {"member"}
                        restricted = cloud.issue(["application_credential"], "user-a", "project-a", {"reader"})
                        headers = {"X-Auth-Token": restricted}
                        caps = client.get("/v1/policy/capabilities", headers=headers)
                        assert caps.status_code == 200, caps.text
                        assert caps.json()["capabilities"] == ["waygate-inventory_reader"], caps.text
                        denied = client.post("/v1/servers", json={"name": "denied"}, headers=headers)
                        assert denied.status_code == 403, denied.text
                        results.append({"role": "restricted-reader-current-member", "capabilities": 200, "write": 403})
                finally:
                    api.terminate()
                    api.wait(timeout=30)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    print(
        json.dumps(
            {
                "service": "waygate",
                "version": __version__,
                "transport": "real-loopback-uvicorn-installed-sdk",
                "schema": "disposable-sqlite",
                "native_implications": {},
                "results": results,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
