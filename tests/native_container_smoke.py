"""Opt-in real-image/MariaDB smoke support; never connects to configured production services."""
from __future__ import annotations

import asyncio
import json
import secrets
import subprocess
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from waygate import db
from waygate.scripts import migrate
from waygate.services import k3s_crypto, waygate_db, waygate_keys
from waygate.services.store import WaygateClientOwnerConflictError


def docker(*args):
    result = subprocess.run(["docker", *args], check=True, capture_output=True, text=True, timeout=180)
    return (result.stdout + (result.stderr if args[0] == "logs" else "")).strip()


@contextmanager
def directory_http(parents, capabilities):
    """Real python-keystoneclient wire shapes, including grouped inference rules."""
    state = SimpleNamespace(roles={}, graph={name: list(leaves) for name, leaves in parents.items()},
                            enabled={"user-a": True, "user-b": True, "disabled-user": False}, requests=[])
    names = set(parents) | set(capabilities) | {"member", "reader", "admin", "manager", "project_admin"}

    def role(name):
        return {"id": "role-" + name, "name": name}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def send(self, status, document, subject=None):
            body = json.dumps(document).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if subject:
                self.send_header("X-Subject-Token", subject)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlsplit(self.path)
            query = parse_qs(url.query, keep_blank_values=True)
            state.requests.append((url.path, query))
            if url.path.rstrip("/") == "/v3":
                self.send(200, {"version": {"id": "v3.13", "status": "stable", "updated": "2026-01-01T00:00:00Z",
                                          "links": [{"rel": "self", "href": state.auth_url + "/"}]}})
                return
            if self.headers.get("X-Auth-Token") != "directory-service-token":
                self.send(401, {"error": {"code": 401, "message": "Synthetic service token required"}})
                return
            if url.path == "/v3/roles":
                rows = [role(name) for name in sorted(names) if not query.get("name") or name == query["name"][0]]
                self.send(200, {"roles": rows, "links": {"next": None}})
            elif url.path == "/v3/role_inferences":
                self.send(200, {"role_inferences": [
                    {"prior_role": role(parent), "implies": [role(leaf) for leaf in leaves]}
                    for parent, leaves in state.graph.items()
                ], "links": {"next": None}})
            elif url.path == "/v3/role_assignments":
                user = query.get("user.id", [""])[0]
                project = query.get("scope.project.id", [""])[0]
                rows = []
                if project:
                    rows = [{"user": {"id": user}, "scope": {"project": {"id": project}}, "role": role(name)}
                            for name in state.roles.get((user, project), ["member"] if user in state.enabled else [])]
                self.send(200, {"role_assignments": rows, "links": {"next": None}})
            elif url.path.startswith("/v3/users/"):
                user = url.path.rsplit("/", 1)[1]
                if user not in state.enabled:
                    self.send(404, {"error": {"code": 404, "message": "Unknown synthetic user"}})
                else:
                    self.send(200, {"user": {"id": user, "name": user, "enabled": state.enabled[user]}})
            else:
                self.send(404, {"error": {"code": 404, "message": "Unknown synthetic route"}})

        def do_POST(self):
            document = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            identity = document["auth"]["identity"]
            methods = identity["methods"]
            if methods == ["password"]:
                user, project, roles, subject = "service", "service-project", [], "directory-service-token"
            else:
                token = identity.get("token", {}).get("id", "")
                parts = token.split(":")
                if len(parts) != 4 or parts[0] != "native":
                    self.send(401, {"error": {"code": 401, "message": "Invalid synthetic token"}})
                    return
                _, user, project, grade = parts
                roles, subject = ["member", grade], token
            self.send(201, {"token": {
                "methods": methods, "expires_at": "2099-01-01T00:00:00Z", "issued_at": "2026-01-01T00:00:00Z",
                "audit_ids": ["synthetic-audit"], "user": {"id": user, "name": user, "domain": {"id": "default"}},
                "project": {"id": project, "name": project, "domain": {"id": "default"}},
                "roles": [role(name) for name in roles], "catalog": [{"id": "identity", "name": "keystone",
                    "type": "identity", "endpoints": [{"id": "identity-public", "interface": "public",
                    "region": "RegionOne", "url": state.auth_url}]}],
            }}, subject=subject)

    server = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
    state.auth_url = f"http://host.docker.internal:{server.server_port}/v3"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


async def wait_sql(engine):
    deadline = time.monotonic() + 90
    while True:
        try:
            async with engine.connect() as connection:
                version = await connection.scalar(text("SELECT VERSION()"))
                assert "MariaDB" in version
                return version
        except Exception:
            if time.monotonic() >= deadline:
                raise
            await asyncio.sleep(0.5)


async def snapshot(engine):
    async with engine.connect() as connection:
        keys = {"schema_migrations": "logical_id", "resource_policies": "policy_key"}
        return {table: [dict(row) for row in (await connection.execute(
                    text(f"SELECT * FROM {table} ORDER BY {keys.get(table, 'id')}"))).mappings()]
                for table in ("schema_migrations", "waygate_servers", "waygate_clients", "waygate_jobs",
                              "waygate_network_attachments", "resource_policies")}


async def run_container_smoke(architecture, parents, capabilities, monkeypatch):
    """Build separately; execute canonical API/worker targets with owned disposable SQL/Redis."""
    from keystoneauth1 import session, token_endpoint
    from openstack.connection import Connection
    from waygate_sdk import register

    name = "waygate-native-" + uuid4().hex[:12]
    api_image = f"waygate-native-20261007-api:{architecture}"
    worker_image = f"waygate-native-20261007-worker:{architecture}"
    containers = []
    network_created = False
    engine = None
    key = secrets.token_hex(32)
    password = secrets.token_hex(16)

    def start(suffix, image, *args):
        container = name + "-" + suffix
        docker("run", "-d", "--name", container, "--network", name, *args, image)
        containers.append(container)
        return container

    def port(container, target):
        return int(docker("port", container, target).rsplit(":", 1)[1])

    try:
        docker("network", "create", name)
        network_created = True
        sql = start("sql", "mariadb:11.4", "-e", "MARIADB_DATABASE=waygate", "-e", "MARIADB_USER=waygate",
                    "-e", f"MARIADB_PASSWORD={password}", "-e", f"MARIADB_ROOT_PASSWORD={password}",
                    "-p", "127.0.0.1::3306")
        redis = start("redis", "redis:7")
        dsn = f"mysql+aiomysql://waygate:{password}@127.0.0.1:{port(sql, '3306/tcp')}/waygate"
        internal_dsn = f"mysql+aiomysql://waygate:{password}@{sql}:3306/waygate"
        engine = create_async_engine(dsn, pool_pre_ping=True)
        version = await wait_sql(engine)
        docker("exec", "--env", f"MYSQL_PWD={password}", sql, "mariadb", "-uroot", "-e",
               "SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON")
        entries = migrate.load_manifest()
        assert len(entries) == 6
        with monkeypatch.context() as context:
            context.setattr(migrate, "load_manifest", lambda: entries[:4])
            assert await migrate.migrate(dsn, apply=True) == [entry.logical_id for entry in entries[:4]]
        private, public = waygate_keys.generate_keypair()
        psk = waygate_keys.generate_preshared_key()
        from waygate import crypto
        monkeypatch.setattr(crypto, "get_settings", lambda: SimpleNamespace(waygate_encryption_key=key))
        agent_token = secrets.token_urlsafe(32)
        encrypted_agent = crypto.encrypt_wg_agent_token(agent_token)
        encrypted_private = k3s_crypto.encrypt_wg_client_key(private)
        encrypted_psk = k3s_crypto.encrypt_wg_client_key(psk)
        async with engine.begin() as connection:
            for server_id, project in [("server-a", "project-a"), ("server-b", "project-b")]:
                await connection.execute(text("""INSERT INTO waygate_servers
                    (id, project_id, name, status, endpoint_ip, server_public_key, created_by_user_id,
                     agent_token_encrypted, agent_token_issued_at, created_at, updated_at)
                    VALUES (:id, :project, :id, 'ACTIVE', '203.0.113.10', :public, 'not-the-owner',
                            :agent, NOW(6), NOW(6), NOW(6))"""),
                    {"id": server_id, "project": project, "public": public,
                     "agent": encrypted_agent if server_id == "server-a" else crypto.encrypt_wg_agent_token(secrets.token_urlsafe(32))})
            for index, client_id in enumerate(("legacy", "own", "other", "disabled", "unassigned"), 2):
                await connection.execute(text("""INSERT INTO waygate_clients
                    (id, server_id, project_id, name, enabled, public_key, private_key_encrypted, preshared_key_encrypted,
                     tunnel_ip, allowed_ips, dns, mtu, persistent_keepalive, created_at, updated_at)
                    VALUES (:id, 'server-a', 'project-a', :id, :enabled, :public, :private, :psk, :ip,
                            '["10.8.0.0/24"]', '9.9.9.9', 1380, 0, NOW(6), NOW(6))"""),
                    {"id": client_id, "enabled": client_id != "disabled", "public": public,
                     "private": encrypted_private, "psk": encrypted_psk, "ip": f"10.8.0.{index}"})
        before = await snapshot(engine)
        await engine.dispose()
        common = ["--platform", f"linux/{architecture}", "-e", f"DATABASE_URL={internal_dsn}",
                  "-e", f"REDIS_URL=redis://{redis}:6379/6", "-e", f"WAYGATE_ENCRYPTION_KEY={key}",
                  "-e", "WAYGATE_CALLBACK_BASE_URL=https://callbacks.example.test"]
        docker("run", "--rm", "--network", name, *common, api_image,
               "waygate-migrate", "--database-url", internal_dsn, "--apply")
        engine = create_async_engine(dsn, pool_pre_ping=True)
        after = await snapshot(engine)
        assert after["schema_migrations"][:4] == before["schema_migrations"]
        assert {(row["logical_id"], row["relative_path"], row["sha256"]) for row in after["schema_migrations"]} == {
            (entry.logical_id, entry.relative_path, entry.sha256) for entry in entries}
        assert all(row["owner_user_id"] is None for row in after["waygate_clients"])
        after["schema_migrations"] = before["schema_migrations"]
        after["waygate_clients"] = [{k: v for k, v in row.items() if k != "owner_user_id"}
                                   for row in after["waygate_clients"]]
        assert after == before
        assert await migrate.migrate(dsn, apply=True) == []
        db.init_db(dsn)
        # NULL survives pool closure/reopening and competing claims serialize on the real parent lock.
        assert (await waygate_db.get_client("server-a", "project-a", "legacy"))["owner_user_id"] is None
        claims = await asyncio.gather(*(waygate_db.update_client("server-a", "project-a", "own", owner_user_id=user)
                                       for user in ("user-a", "user-b")), return_exceptions=True)
        assert sum(isinstance(result, WaygateClientOwnerConflictError) for result in claims) == 1
        winner = next(result["owner_user_id"] for result in claims if isinstance(result, dict))
        await waygate_db.update_client("server-a", "project-a", "other", owner_user_id="user-b")
        await waygate_db.update_client("server-a", "project-a", "disabled", owner_user_id="user-a")
        await db.close_db()
        db.init_db(dsn)
        own = await waygate_db.get_client("server-a", "project-a", "own")
        assert own["owner_user_id"] == winner
        assert own["private_key_encrypted"] == encrypted_private and own["preshared_key_encrypted"] == encrypted_psk
        assert k3s_crypto.decrypt_wg_client_key(own["private_key_encrypted"]) == private
        assert k3s_crypto.decrypt_wg_client_key(own["preshared_key_encrypted"]) == psk
        # Use the deterministic owned profile for HTTP; the raced profile remains immutable.
        async with engine.begin() as connection:
            await connection.execute(text("UPDATE waygate_clients SET name='raced' WHERE id='own'"))
        with directory_http(parents, capabilities) as directory:
            common.extend(["-e", f"OS_AUTH_URL={directory.auth_url}", "-e", "OS_USERNAME=synthetic-service",
                           "-e", "OS_PASSWORD=synthetic-password", "-e", "OS_PROJECT_NAME=service-project"])
            api = start("api", api_image, *common, "-p", "127.0.0.1::8010")
            worker = start("worker", worker_image, *common)
            base = f"http://127.0.0.1:{port(api, '8010/tcp')}"
            async with httpx.AsyncClient(base_url=base, timeout=30) as client:
                deadline = time.monotonic() + 90
                while True:
                    try:
                        if (await client.get("/v1/health")).status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    assert time.monotonic() < deadline, "API readiness timeout"
                    await asyncio.sleep(0.5)

                def headers(grade, user="user-a", project="project-a"):
                    directory.roles[user, project] = ["member", grade]
                    return {"X-Auth-Token": f"native:{user}:{project}:{grade}"}

                async def request(method, path, grade, status, body=None, user="user-a", project="project-a"):
                    response = await client.request(method, path, headers=headers(grade, user, project), json=body)
                    assert response.status_code == status, (method, path, response.status_code)
                    return response

                server = "/v1/servers/server-a"
                legacy = server + "/clients/legacy"
                for grade in ("member", "project_admin"):
                    await request("GET", "/v1/servers", grade, 403)
                metadata = await request("GET", server + "/clients", "waygate_reader", 200)
                assert private not in metadata.text and psk not in metadata.text
                for forbidden in ("private_key_encrypted", "preshared_key_encrypted", "tunnel_conf"):
                    assert forbidden not in metadata.text
                await request("POST", server + "/clients", "waygate_reader", 403, {"name": "deny"})
                reader_base = headers("waygate_admin")
                directory.roles["user-a", "project-a"] = ["reader", "waygate_admin"]
                assert (await client.get(server, headers=reader_base)).status_code == 200
                assert (await client.post(server + "/clients", headers=reader_base, json={"name": "deny"})).status_code == 403
                await request("GET", legacy + "/config", "waygate_user", 403)
                await request("POST", server + "/clients", "waygate_user", 403, {"name": "deny"})
                created = await request("POST", server + "/clients", "waygate_editor", 201, {"name": "new-client"})
                assert created.json()["owner_user_id"] == "user-a" and created.json()["tunnel_conf"]
                created_path = server + "/clients/" + created.json()["id"]
                await request("PATCH", created_path, "waygate_editor", 200, {"name": "updated-client"})
                leaf_created = await request("POST", server + "/clients", "waygate-clients_editor", 201,
                                             {"name": "editor-only"})
                assert leaf_created.json()["tunnel_conf"] is None
                await request("GET", server + "/clients/" + leaf_created.json()["id"] + "/config",
                              "waygate-clients_editor", 403)
                for method, suffix, body in [("DELETE", "/clients/legacy", None), ("POST", "/agent-token/rotate", None),
                                              ("POST", "/export", {"passphrase": "synthetic-passphrase"}),
                                              ("POST", "/networks", {"network_id": "never-contact-cloud"})]:
                    await request(method, server + suffix, "waygate_editor", 403, body)
                await request("PATCH", legacy, "waygate_editor", 422, {"owner_user_id": "disabled-user"})
                await request("PATCH", legacy, "waygate_editor", 422, {"owner_user_id": "unknown-user"})
                await request("PATCH", legacy, "waygate_editor", 200, {"owner_user_id": "user-a"})
                await request("PATCH", legacy, "waygate_editor", 409, {"owner_user_id": "user-b"})
                await request("PATCH", legacy, "waygate_editor", 422, {"owner_user_id": None})
                conf = await request("GET", legacy + "/config", "waygate_user", 200)
                assert conf.headers["cache-control"] == "no-store" and private in conf.text and psk in conf.text
                for grade in ("waygate_user", "waygate_editor", "waygate_admin"):
                    await request("GET", server + "/clients/other/config", grade, 403)
                    await request("GET", server + "/clients/disabled/config", grade, 403)
                await request("GET", "/v1/servers/server-b", "waygate_admin", 404)
                await request("GET", "/v1/admin/resource-policies", "waygate_admin", 403)
                await request("PATCH", created_path, "waygate_admin", 200, {"enabled": False})
                await request("GET", created_path + "/config", "waygate_user", 403)
                await request("DELETE", created_path, "waygate_admin", 204)
                # A corrupt foreign PSK proves subset exclusion occurs before decryption.
                async with engine.begin() as connection:
                    await connection.execute(text("UPDATE waygate_clients SET preshared_key_encrypted='invalid-foreign-cipher' WHERE id='other'"))
                exported = await request("POST", server + "/export", "waygate_admin", 200,
                                         {"passphrase": "synthetic-passphrase"})
                bundle = exported.json()
                assert bundle["export_scope"] == "caller_owned_and_unassigned_profiles"
                assert "other" in bundle["excluded_assigned_client_ids"]
                assert bundle["excluded_assigned_client_count"] == len(bundle["excluded_assigned_client_ids"])
                assert "other" not in {entry["name"] for entry in bundle["clients"]}
                assert "unassigned" in {entry["name"] for entry in bundle["clients"]}
                assert all("owner_user_id" not in entry for entry in bundle["clients"])
                assert exported.headers["cache-control"] == "no-store"
                assert "export: 클라이언트 키 복호화 실패" not in docker("logs", api)
                old = headers("waygate_admin")
                directory.graph["waygate_admin"] = []
                assert (await client.get(server, headers=old)).status_code == 403
                directory.graph["waygate_admin"] = list(parents["waygate_admin"])
                directory.roles["user-a", "project-a"] = ["member"]
                assert (await client.get(server, headers=old)).status_code == 403
                await request("POST", server + "/agent-token/rotate", "waygate_admin", 202)
                async with engine.connect() as connection:
                    agent_cipher = await connection.scalar(text("SELECT agent_token_encrypted FROM waygate_servers WHERE id='server-a'"))
                agent = {"Authorization": "Bearer " + crypto.decrypt_wg_agent_token(agent_cipher)}
                assert (await client.get(server + "/agent/desired-state", headers=headers("waygate_admin"))).status_code == 401
                desired = await client.get(server + "/agent/desired-state", headers=agent)
                assert desired.status_code == 200
                next_agent = {"Authorization": "Bearer " + desired.json()["next_token"]}
                assert (await client.post(server + "/agent/register", headers=next_agent,
                                          json={"public_key": public})).status_code == 204
                assert (await client.get(server + "/agent/desired-state", headers=agent)).status_code == 401
                agent = next_agent
                assert (await client.get("/v1/servers/server-b/agent/desired-state", headers=agent)).status_code == 401
                directory.roles["user-a", "project-a"] = ["member"]
                assert (await client.post(server + "/agent/status", headers=agent,
                                         json={"peers": []})).status_code == 204
                # Public installed Waygate SDK, root and versioned discovery endpoints, real HTTP.
                headers("waygate_user")
                def sdk_smoke():
                    for endpoint in (base, base + "/v1"):
                        connection = Connection(session=session.Session(auth=token_endpoint.Token(
                            endpoint=endpoint, token="native:user-a:project-a:waygate_user")),
                            waygate_endpoint_override=endpoint, waygate_api_version="1")
                        try:
                            proxy = register(connection)
                            assert proxy.get_server("server-a")["id"] == "server-a"
                            assert private in proxy.client_config("server-a", "legacy")
                        finally:
                            connection.close()
                await asyncio.to_thread(sdk_smoke)
                assert any(path == "/v3/role_inferences" for path, _ in directory.requests)
                assert any(path == "/v3/role_assignments" and "effective" in query and
                           query.get("scope.project.id") == ["project-a"] for path, query in directory.requests)
                assert any(path == "/v3/users/user-a" for path, _ in directory.requests)
            for container, image in ((api, api_image), (worker, worker_image)):
                machine = docker("exec", container, "python", "-c", "import platform; print(platform.machine())")
                assert machine == {"arm64": "aarch64", "amd64": "x86_64"}[architecture]
                print(f"{image}: {machine}, image={docker('image', 'inspect', image, '--format', '{{.Id}}')}")
            # SQL readiness/queue polling, not merely the process-health route.
            logs = docker("logs", worker)
            assert "worker stage=ready status=started" in logs
            polls = int(docker("exec", "--env", f"MYSQL_PWD={password}", sql, "mariadb", "-uroot", "-N", "-e",
                               "SELECT COUNT(*) FROM mysql.general_log WHERE command_type='Query' "
                               "AND argument LIKE 'SELECT%waygate_jobs%'"))
            assert polls > 1
            assert "worker stage=poll status=failed" not in logs
            print(f"{architecture}: worker real queue SELECTs={polls}; no cloud jobs enqueued")
            docker("stop", "-t", "30", api, worker)
            for container, marker in ((api, "api"), (worker, "worker")):
                assert docker("inspect", container, "--format", "{{.State.ExitCode}}") == "0"
                assert f"{marker} stage=shutdown status=stopped" in docker("logs", container)
            print(f"MariaDB {version}: 001–004 ledger/records/ciphertext preserved by packaged 005–006; NULL survives reopen; competing claim assign-once passed")
            print(f"{architecture}: native HTTP/installed directory SDK/public Waygate SDK/ownership/downgrade/export subset/machine callbacks passed")
    finally:
        await db.close_db()
        if engine is not None:
            await engine.dispose()
        for container in reversed(containers):
            docker("rm", "-f", "-v", container)
        if network_created:
            docker("network", "rm", name)
