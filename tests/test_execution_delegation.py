"""Native Trust delegation through real keystoneauth1, keystoneclient and openstacksdk.

A loopback synthetic Keystone/Nova/Glance/Neutron enforces the Keystone contract
this service relies on: trustor-only Trust creation, ADMIN_OR_TRUSTOR deletion,
impersonating trust-scoped tokens that require the trustor's current roles, and
no tenant assignment for the service identity. The registered application, its
real token dependencies, SQL store and durable worker run unchanged.

Direct system-all admin assignments also exercise the installed SDK's HTTP
decoder: an incompatible effective-system envelope must not hide a valid direct
assignment, while project authority continues to use effective assignments.

Set WAYGATE_DELEGATION_MARIADB_URL to a disposable server's privileged DSN to run
the same cases on a per-test database built by the packaged migration ledger.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from httpx import ASGITransport, AsyncClient
from keystoneclient.v3.role_assignments import RoleAssignment, RoleAssignmentManager
from sqlalchemy import make_url, select, text, update
from sqlalchemy.ext.asyncio import create_async_engine

from waygate import auth, db
from waygate.config import get_settings
from waygate.main import app
from waygate.models.orm import ResourcePolicy, WaygateClient, WaygateExecutionGrant, WaygateJob, WaygateServer
from waygate.scripts import migrate
from waygate.services import k3s_crypto, openstack_ops, waygate_jobs, waygate_keys

pytestmark = pytest.mark.asyncio

SERVICE_USER = "waygate-svc"
SERVICE_PROJECT = "waygate-service"
PASSWORD = "synthetic-service-secret"
FLAVOR, IMAGE, NETWORK = "flavor-zero", "image-ubuntu", "network-provider"
EDITOR = {"member", "waygate-inventory_reader", "waygate-gateways_editor"}
ADMIN = {"member", "waygate-inventory_reader", "waygate-gateways_admin"}
ROLE_NAMES = (
    "admin",
    "member",
    "reader",
    "manager",
    "waygate-inventory_reader",
    "waygate-connect_user",
    "waygate-clients_editor",
    "waygate-gateways_editor",
    "waygate-clients_admin",
    "waygate-gateways_admin",
    "waygate-routing_admin",
)
IMPLIES = {"admin": ["member"], "member": ["reader"]}


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _role(name: str) -> dict:
    return {"id": "role-" + name, "name": name, "domain_id": None, "links": {"self": "synthetic"}}


class SyntheticCloud:
    def __init__(self):
        self.lock = threading.Lock()
        self.base = ""
        self.users = {"user-a": True, "user-b": True, SERVICE_USER: True}
        self.projects = {"project-a": True, SERVICE_PROJECT: True}
        self.assignments = {
            ("user-a", "project-a"): set(EDITOR),
            ("user-b", "project-a"): set(ADMIN),
            (SERVICE_USER, SERVICE_PROJECT): {"admin"},
        }
        self.system_assignments: list[dict] = []
        self.role_assignment_queries: list[dict] = []
        self.incompatible_effective_system = False
        self.fail_system_assignments = False
        self.tokens: dict[str, dict] = {}
        self.trusts: dict[str, dict] = {}
        self.auth_requests: list[dict] = []
        self.cloud_requests: list[tuple[str, str, dict]] = []
        self.trust_deletes: list[tuple[str, str]] = []
        self.fail_trust_delete = 0
        self.refuse_trust_tokens = False
        self.flavor_disk = 0
        self.after_cloud_request = None
        self.servers: dict[str, dict] = {}
        self.server_bodies: list[dict] = []
        self.ports: dict[str, dict] = {}
        self.groups: dict[str, dict] = {}

    # Keystone ---------------------------------------------------------
    def closure(self, names) -> set[str]:
        result, pending = set(), list(names)
        while pending:
            name = pending.pop()
            if name not in result:
                result.add(name)
                pending.extend(IMPLIES.get(name, []))
        return result

    def effective(self, user: str, project: str) -> set[str]:
        if not self.users.get(user) or not self.projects.get(project):
            return set()
        return self.closure(self.assignments.get((user, project), set()))

    def login(self, user: str, project: str) -> str:
        return self.issue(["password"], user, project, self.effective(user, project))

    def issue(self, methods, user, project, roles, trust=None) -> str:
        token = "tok-" + uuid.uuid4().hex
        expires = datetime.now(UTC) + timedelta(hours=1)
        if trust is not None:
            expires = min(expires, trust["expires"])
        self.tokens[token] = {
            "methods": methods,
            "user": user,
            "project": project,
            "roles": set(roles),
            "trust": trust,
            "expires": expires,
        }
        return token

    def token_body(self, token: str) -> dict:
        record = self.tokens[token]
        body = {
            "methods": record["methods"],
            "expires_at": _iso(record["expires"]),
            "issued_at": _iso(datetime.now(UTC)),
            "audit_ids": [token[-8:]],
            "user": {"id": record["user"], "name": record["user"], "domain": {"id": "default", "name": "Default"}},
            "project": {
                "id": record["project"],
                "name": record["project"],
                "domain": {"id": "default", "name": "Default"},
            },
            "roles": [{"id": "role-" + name, "name": name} for name in sorted(record["roles"])],
            "catalog": [
                {
                    "id": kind,
                    "type": kind,
                    "name": kind,
                    "endpoints": [
                        {
                            "id": f"{kind}-{interface}",
                            "interface": interface,
                            "region": "RegionOne",
                            "region_id": "RegionOne",
                            "url": url,
                        }
                        for interface in ("public", "internal", "admin")
                    ],
                }
                for kind, url in (
                    ("identity", self.base + "/v3"),
                    ("compute", self.base + "/compute/v2.1"),
                    ("image", self.base + "/image"),
                    ("network", self.base + "/network"),
                )
            ],
        }
        if trust := record["trust"]:
            body["OS-TRUST:trust"] = {
                "id": trust["id"],
                "impersonation": True,
                "trustee_user": {"id": trust["trustee_user_id"]},
                "trustor_user": {"id": trust["trustor_user_id"]},
            }
        return {"token": body}

    def live_trust(self, trust_id: str) -> dict | None:
        trust = self.trusts.get(trust_id)
        if trust is None or trust["deleted"] or trust["expires"] <= datetime.now(UTC):
            return None
        return trust

    def authenticate(self, document: dict) -> tuple[int, str | None]:
        identity, scope = document["auth"]["identity"], document["auth"].get("scope") or {}
        self.auth_requests.append(document)
        if identity["methods"] == ["password"]:
            user = identity["password"]["user"]
            user_id = user.get("id") or user.get("name")
            if user_id != SERVICE_USER or user.get("password") != PASSWORD:
                return 401, None
            if "OS-TRUST:trust" in scope:
                trust = self.live_trust(scope["OS-TRUST:trust"]["id"])
                if trust is None or trust["trustee_user_id"] != user_id:
                    return 404, None
                held = self.effective(trust["trustor_user_id"], trust["project_id"])
                if self.refuse_trust_tokens or not set(trust["roles"]) <= held:
                    return 403, None
                return 201, self.issue(
                    ["password"],
                    trust["trustor_user_id"],
                    trust["project_id"],
                    self.closure(trust["roles"]),
                    trust=trust,
                )
            project = scope.get("project") or {}
            if SERVICE_PROJECT not in (project.get("name"), project.get("id")):
                # The service identity has no tenant role assignment.
                return 401, None
            return 201, self.issue(
                ["password"], SERVICE_USER, SERVICE_PROJECT, self.effective(SERVICE_USER, SERVICE_PROJECT)
            )
        if identity["methods"] == ["token"]:
            source = self.tokens.get(identity["token"]["id"])
            if source is None or source["trust"] is not None:
                return 401, None
            project = (scope.get("project") or {}).get("id") or source["project"]
            roles = self.effective(source["user"], project)
            if not roles:
                return 401, None
            return 201, self.issue(["token"], source["user"], project, roles)
        return 401, None

    def trust_body(self, trust: dict) -> dict:
        return {
            "trust": {
                "id": trust["id"],
                "trustor_user_id": trust["trustor_user_id"],
                "trustee_user_id": trust["trustee_user_id"],
                "project_id": trust["project_id"],
                "impersonation": trust["impersonation"],
                "expires_at": _iso(trust["expires"]),
                "remaining_uses": None,
                "redelegation_count": 0,
                "roles": [_role(name) for name in sorted(trust["roles"])],
                "roles_links": {"self": "synthetic", "next": None, "previous": None},
                "links": {"self": self.base + "/v3/OS-TRUST/trusts/" + trust["id"]},
            }
        }


def _handler(cloud: SyntheticCloud):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def send(self, status, document=None, subject=None):
            body = b"" if document is None else json.dumps(document).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if subject:
                self.send_header("X-Subject-Token", subject)
            self.end_headers()
            self.wfile.write(body)

        def body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(length)) if length else {}

        def caller(self) -> dict | None:
            record = cloud.tokens.get(self.headers.get("X-Auth-Token", ""))
            if record is None or record["expires"] <= datetime.now(UTC):
                return None
            if record["trust"] is not None and cloud.live_trust(record["trust"]["id"]) is None:
                return None
            return record

        def dispatch(self, method: str):
            url = urlsplit(self.path)
            query = parse_qs(url.query, keep_blank_values=True)
            body = self.body() if method in {"POST", "PUT", "PATCH"} else {}
            with cloud.lock:
                status, document = self.route(method, url.path.rstrip("/") or "/", query, body)
            if isinstance(document, tuple):
                self.send(status, *document)
            else:
                self.send(status, document)

        def do_GET(self):
            self.dispatch("GET")

        def do_POST(self):
            self.dispatch("POST")

        def do_DELETE(self):
            self.dispatch("DELETE")

        def route(self, method, path, query, body):
            if path == "/v3" and method == "GET":
                return 200, {
                    "version": {
                        "id": "v3.14",
                        "status": "stable",
                        "updated": "2026-01-01T00:00:00Z",
                        "links": [{"rel": "self", "href": cloud.base + "/v3/"}],
                        "media-types": [
                            {"base": "application/json", "type": "application/vnd.openstack.identity-v3+json"}
                        ],
                    }
                }
            if path == "/v3/auth/tokens" and method == "POST":
                status, token = cloud.authenticate(body)
                if token is None:
                    return status, {"error": {"code": status, "message": "synthetic authentication refused"}}
                return 201, (cloud.token_body(token), token)
            caller = self.caller()
            if caller is None:
                return 401, {"error": {"code": 401, "message": "synthetic token required"}}
            if path.startswith("/v3/"):
                return self.identity(method, path, query, body, caller)
            cloud.cloud_requests.append((method, path, caller))
            if caller["trust"] is None:
                return 403, {"error": {"code": 403, "message": "tenant cloud calls require delegation"}}
            if path.startswith("/compute"):
                result = self.compute(method, path.removeprefix("/compute"), body)
            elif path.startswith("/image"):
                result = self.image(path.removeprefix("/image"))
            elif path.startswith("/network"):
                result = self.network(method, path.removeprefix("/network"), query, body)
            else:
                result = 404, {"error": {"code": 404, "message": "unknown synthetic route"}}
            if cloud.after_cloud_request is not None:
                cloud.after_cloud_request(method, path)
            return result

        def identity(self, method, path, query, body, caller):
            if path == "/v3/OS-TRUST/trusts" and method == "POST":
                requested = body["trust"]
                project = requested.get("project_id")
                if (
                    caller["trust"] is not None
                    or requested.get("trustor_user_id") != caller["user"]
                    or project != caller["project"]
                ):
                    return 403, {"error": {"code": 403, "message": "The authenticated user should match the trustor"}}
                names = {role["id"].removeprefix("role-") for role in requested.get("roles") or []}
                if not names or not names <= cloud.effective(caller["user"], project):
                    return 404, {"error": {"code": 404, "message": "Could not find role"}}
                trust = {
                    "id": uuid.uuid4().hex,
                    "trustor_user_id": caller["user"],
                    "trustee_user_id": requested["trustee_user_id"],
                    "project_id": project,
                    "impersonation": requested.get("impersonation") is True,
                    "roles": sorted(names),
                    "expires": datetime.fromisoformat(requested["expires_at"].replace("Z", "+00:00")),
                    "deleted": False,
                }
                cloud.trusts[trust["id"]] = trust
                return 201, cloud.trust_body(trust)
            if path.startswith("/v3/OS-TRUST/trusts/"):
                trust = cloud.live_trust(path.rsplit("/", 1)[1])
                if trust is None:
                    return 404, {"error": {"code": 404, "message": "Could not find trust"}}
                is_admin = "admin" in caller["roles"]
                related = caller["user"] in (trust["trustor_user_id"], trust["trustee_user_id"])
                if method == "GET" and (is_admin or related):
                    return 200, cloud.trust_body(trust)
                if method == "DELETE" and (is_admin or caller["user"] == trust["trustor_user_id"]):
                    if cloud.fail_trust_delete:
                        cloud.fail_trust_delete -= 1
                        return 503, {"error": {"code": 503, "message": "synthetic identity outage"}}
                    trust["deleted"] = True
                    cloud.trust_deletes.append((trust["id"], caller["user"]))
                    return 204, None
                return 403, {"error": {"code": 403, "message": "Only admin or trustor can manage this trust"}}
            if caller["user"] != SERVICE_USER or caller["trust"] is not None:
                return 403, {"error": {"code": 403, "message": "directory reads require the service identity"}}
            if path == "/v3/roles":
                names = [name for name in ROLE_NAMES if not query.get("name") or query["name"][0] == name]
                return 200, {"roles": [_role(name) for name in names], "links": {"next": None}}
            if path == "/v3/role_inferences":
                return 200, {
                    "role_inferences": [
                        {"prior_role": _role(prior), "implies": [_role(child) for child in children]}
                        for prior, children in IMPLIES.items()
                    ],
                    "links": {"next": None},
                }
            if path == "/v3/role_assignments":
                cloud.role_assignment_queries.append(query)
                if query.get("scope.system"):
                    if cloud.fail_system_assignments:
                        return 503, {"error": {"code": 503, "message": "synthetic system directory outage"}}
                    if cloud.incompatible_effective_system and "effective" in query:
                        # HTTP succeeds, but python-keystoneclient's collection decoder
                        # cannot consume this effective endpoint's incompatible envelope.
                        return 200, {"assignments": cloud.system_assignments, "links": {"next": None}}
                    # Return even unexpected rows so the consumer must verify all
                    # three filters, not trust that a server honored its query.
                    return 200, {"role_assignments": cloud.system_assignments, "links": {"next": None}}
                user, project = query.get("user.id", [""])[0], query.get("scope.project.id", [""])[0]
                rows = (
                    []
                    if not project
                    else [
                        {"user": {"id": user}, "scope": {"project": {"id": project}}, "role": {"id": "role-" + name}}
                        for name in sorted(
                            cloud.effective(user, project)
                            if "effective" in query
                            else cloud.assignments.get((user, project), set())
                        )
                    ]
                )
                return 200, {"role_assignments": rows, "links": {"next": None}}
            kind, _, item = path.removeprefix("/v3/").partition("/")
            table = {"users": cloud.users, "projects": cloud.projects}.get(kind)
            if table is None or item not in table:
                return 404, {"error": {"code": 404, "message": "not found"}}
            return 200, {kind[:-1]: {"id": item, "name": item, "enabled": table[item], "domain_id": "default"}}

        def compute(self, method, path, body):
            if path in {"", "/v2.1"}:
                return 200, {
                    "version": {
                        "id": "v2.1",
                        "status": "CURRENT",
                        "version": "2.90",
                        "min_version": "2.1",
                        "updated": "2013-07-23T11:33:21Z",
                        "links": [{"rel": "self", "href": cloud.base + "/compute/v2.1/"}],
                    }
                }
            path = path.removeprefix("/v2.1")
            if path == "/flavors/" + FLAVOR:
                return 200, {
                    "flavor": {
                        "id": FLAVOR,
                        "name": "cpu.zero",
                        "vcpus": 1,
                        "ram": 1024,
                        "disk": cloud.flavor_disk,
                        "OS-FLV-EXT-DATA:ephemeral": 0,
                        "swap": 0,
                        "os-flavor-access:is_public": True,
                        "rxtx_factor": 1.0,
                        "extra_specs": {},
                        "description": None,
                        "links": [],
                    }
                }
            if path == "/servers" and method == "POST":
                cloud.server_bodies.append(body["server"])
                server_id = "vm-" + uuid.uuid4().hex[:8]
                cloud.ports[body["server"]["networks"][0]["port"]]["device_id"] = server_id
                cloud.servers[server_id] = {
                    "id": server_id,
                    "name": body["server"]["name"],
                    "status": "ACTIVE",
                    "addresses": {"provider": [{"addr": "10.0.0.5", "version": 4, "OS-EXT-IPS:type": "fixed"}]},
                    "metadata": body["server"].get("metadata") or {},
                    "links": [],
                }
                return 202, {"server": {"id": server_id, "links": [], "adminPass": "unused"}}
            if path == "/servers/detail":
                return 200, {"servers": []}
            parts = path.split("/")
            if len(parts) >= 3 and parts[1] == "servers":
                server = cloud.servers.get(parts[2])
                if server is None:
                    return 404, {"itemNotFound": {"code": 404, "message": "Instance could not be found"}}
                if method == "GET" and len(parts) == 3:
                    return 200, {"server": server}
                if method == "POST" and parts[3:] == ["action"] and "forceDelete" in body:
                    del cloud.servers[parts[2]]
                    return 202, None
            return 404, {"itemNotFound": {"code": 404, "message": "unknown compute route"}}

        def image(self, path):
            if path in {"", "/"}:
                return 200, {
                    "versions": [
                        {
                            "id": "v2.16",
                            "status": "CURRENT",
                            "links": [{"rel": "self", "href": cloud.base + "/image/v2/"}],
                        }
                    ]
                }
            if path == "/v2/images/" + IMAGE:
                return 200, {
                    "id": IMAGE,
                    "name": "ubuntu",
                    "status": "active",
                    "visibility": "public",
                    "min_disk": 12,
                    "min_ram": 0,
                    "disk_format": "qcow2",
                    "container_format": "bare",
                }
            return 404, {"message": "unknown image"}

        def network(self, method, path, query, body):
            if path in {"", "/"}:
                return 200, {
                    "versions": [
                        {
                            "id": "v2.0",
                            "status": "CURRENT",
                            "links": [{"rel": "self", "href": cloud.base + "/network/v2.0/"}],
                        }
                    ]
                }
            path = path.removeprefix("/v2.0")
            if path == "/networks/" + NETWORK:
                return 200, {
                    "network": {
                        "id": NETWORK,
                        "name": "provider",
                        "shared": True,
                        "router:external": False,
                        "status": "ACTIVE",
                        "subnets": [],
                    }
                }
            if path == "/security-groups" and method == "GET":
                return 200, {"security_groups": list(cloud.groups.values())}
            if path == "/security-groups" and method == "POST":
                group = {
                    "id": "sg-" + uuid.uuid4().hex[:8],
                    "name": body["security_group"]["name"],
                    "description": body["security_group"].get("description", ""),
                    "security_group_rules": [],
                    "project_id": "project-a",
                }
                cloud.groups[group["id"]] = group
                return 201, {"security_group": group}
            if path == "/security-group-rules" and method == "POST":
                rule = {"id": "rule-" + uuid.uuid4().hex[:8], **body["security_group_rule"]}
                cloud.groups[rule["security_group_id"]]["security_group_rules"].append(rule)
                return 201, {"security_group_rule": rule}
            if path == "/ports" and method == "POST":
                port = {
                    "id": "port-" + uuid.uuid4().hex[:8],
                    "device_id": "",
                    "status": "DOWN",
                    "fixed_ips": [{"ip_address": "10.0.0.5", "subnet_id": "subnet-a"}],
                    **body["port"],
                }
                cloud.ports[port["id"]] = port
                return 201, {"port": port}
            if path == "/ports" and method == "GET":
                device = query.get("device_id", [None])[0]
                return 200, {
                    "ports": [port for port in cloud.ports.values() if device is None or port["device_id"] == device]
                }
            if path.startswith("/ports/") and method == "DELETE":
                if cloud.ports.pop(path.rsplit("/", 1)[1], None) is None:
                    return 404, {"NeutronError": {"message": "port not found"}}
                return 204, None
            if path == "/floatingips" and method == "GET":
                return 200, {"floatingips": []}
            return 404, {"NeutronError": {"message": "unknown network route"}}

    return Handler


@pytest.fixture
def synthetic_cloud():
    cloud = SyntheticCloud()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(cloud))
    cloud.base = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield cloud
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@contextlib.asynccontextmanager
async def _database(tmp_path):
    """SQLite metadata by default; an opt-in disposable MariaDB built only from the migration ledger."""
    server_url = os.environ.get("WAYGATE_DELEGATION_MARIADB_URL", "").strip()
    if not server_url:
        url = f"sqlite+aiosqlite:///{tmp_path / 'delegation.sqlite'}"
        engine = create_async_engine(url)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(db.Base.metadata.create_all)
        finally:
            await engine.dispose()
        yield url
        return
    name = "waygate_delegation_" + uuid.uuid4().hex[:12]
    admin = create_async_engine(server_url)
    try:
        async with admin.begin() as connection:
            await connection.execute(text(f"CREATE DATABASE {name}"))
        url = make_url(server_url).set(database=name).render_as_string(hide_password=False)
        assert await migrate.migrate(url, apply=True) == [entry.logical_id for entry in migrate.load_manifest()]
        yield url
    finally:
        async with admin.begin() as connection:
            await connection.execute(text(f"DROP DATABASE IF EXISTS {name}"))
        await admin.dispose()


@pytest.fixture
async def native(tmp_path, monkeypatch, synthetic_cloud):
    async with _database(tmp_path) as database_url:
        async for value in _native(tmp_path, monkeypatch, synthetic_cloud, database_url):
            yield value


async def _native(tmp_path, monkeypatch, synthetic_cloud, database_url):
    empty = tmp_path / "waygate.conf"
    empty.write_text("")
    for key, value in {
        "WAYGATE_CONFIG_FILE": str(empty),
        "DATABASE_URL": database_url,
        "OS_AUTH_URL": synthetic_cloud.base + "/v3",
        "OS_USERNAME": SERVICE_USER,
        "OS_PASSWORD": PASSWORD,
        "OS_PROJECT_NAME": SERVICE_PROJECT,
        "OS_REGION_NAME": "RegionOne",
        "OS_INTERFACE": "internal",
        "WAYGATE_CALLBACK_BASE_URL": "https://callbacks.example.test",
        "WAYGATE_ENCRYPTION_KEY": "a" * 64,
    }.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    monkeypatch.setattr(db, "_engine", None)
    monkeypatch.setattr(db, "_session_factory", None)
    monkeypatch.setattr(app, "dependency_overrides", {})

    async def instant(_seconds):
        await asyncio.sleep(0)

    monkeypatch.setattr(openstack_ops, "asyncio", SimpleNamespace(sleep=instant, to_thread=asyncio.to_thread))
    monkeypatch.setattr(openstack_ops, "time", SimpleNamespace(monotonic=time.monotonic, sleep=lambda _seconds: None))

    async with app.router.lifespan_context(app):
        async with db.get_session_factory()() as session, session.begin():
            # The migration ledger seeds unconfigured rows; metadata-built SQLite starts empty.
            for key, kind, resource_id in (
                ("waygate.flavor", "flavor", FLAVOR),
                ("waygate.image", "image", IMAGE),
                ("waygate.provider_network", "network", NETWORK),
            ):
                await session.merge(ResourcePolicy(policy_key=key, resource_kind=kind, resource_id=resource_id))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://waygate.test") as client:

            def headers(user: str) -> dict:
                return {"X-Auth-Token": synthetic_cloud.login(user, "project-a"), "X-Project-Id": "project-a"}

            yield SimpleNamespace(client=client, cloud=synthetic_cloud, headers=headers)


async def _rows(model, **filters):
    async with db.get_session_factory()() as session:
        return list((await session.execute(select(model).filter_by(**filters))).scalars())


async def _create(native, user="user-a") -> str:
    response = await native.client.post("/v1/servers", json={"name": "gw"}, headers=native.headers(user))
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "CREATING"
    return response.json()["id"]


def _trust_users(cloud: SyntheticCloud, start: int = 0) -> set[tuple[str, str | None]]:
    return {
        (record["user"], record["trust"] and record["trust"]["id"])
        for _method, _path, record in cloud.cloud_requests[start:]
    }


def _system_admin_row(user="user-a") -> dict:
    return {"user": {"id": user}, "role": {"id": "role-admin"}, "scope": {"system": {"all": True}}}


def _assert_assignment_queries(cloud, start=0):
    queries = cloud.role_assignment_queries[start:]
    system = [query for query in queries if "scope.system" in query]
    project = [query for query in queries if "scope.project.id" in query]
    assert system and project
    assert len(system) + len(project) == len(queries)
    for query in system:
        assert query == {
            "user.id": query["user.id"], "role.id": ["role-admin"], "scope.system": ["all"],
        }
        assert query["user.id"] in (["user-a"], ["user-b"])
    for query in project:
        assert query == {
            "user.id": query["user.id"], "scope.project.id": ["project-a"], "effective": ["True"],
        }
        assert query["user.id"] in (["user-a"], ["user-b"])


async def _seed_unassigned_profile():
    private_key, public_key = waygate_keys.generate_keypair()
    async with db.get_session_factory()() as session, session.begin():
        session.add(WaygateServer(
            id="owner-server", project_id="project-a", name="owner-gateway", status="ACTIVE",
            endpoint_ip="203.0.113.10", server_public_key=public_key,
        ))
        await session.flush()
        session.add(WaygateClient(
            id="unassigned", server_id="owner-server", project_id="project-a", name="legacy",
            owner_user_id=None, enabled=True, public_key=public_key, tunnel_ip="10.8.0.2",
            private_key_encrypted=k3s_crypto.encrypt_wg_client_key(private_key), allowed_ips=["10.8.0.0/24"],
        ))
    return private_key


async def test_direct_system_admin_owner_patch_survives_installed_sdk_effective_decoder_failure(native):
    cloud = native.cloud
    cloud.assignments["user-a", "project-a"] = {"admin"}
    cloud.system_assignments = [_system_admin_row()]
    cloud.incompatible_effective_system = True
    private_key = await _seed_unassigned_profile()
    path = "/v1/servers/owner-server/clients/unassigned"

    # This is an installed python-keystoneclient manager backed by a real
    # keystoneauth1 session, not a replacement directory/decoder object.
    sdk = auth._get_admin_ks_client()
    assert type(sdk.role_assignments) is RoleAssignmentManager
    with pytest.raises(KeyError, match="role_assignments"):
        await asyncio.to_thread(
            sdk.role_assignments.list, user="user-a", role="role-admin", system="all", effective=True,
        )
    assert cloud.role_assignment_queries[-1] == {
        "user.id": ["user-a"], "role.id": ["role-admin"], "scope.system": ["all"], "effective": ["True"],
    }
    [decoded] = await asyncio.to_thread(
        sdk.role_assignments.list, user="user-a", role="role-admin", system="all",
    )
    assert type(decoded) is RoleAssignment
    assert decoded.to_dict() == _system_admin_row()

    start = len(cloud.role_assignment_queries)
    headers = native.headers("user-a")
    assigned = await native.client.patch(path, json={"owner_user_id": "user-a"}, headers=headers)
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["owner_user_id"] == "user-a"
    [stored] = await _rows(WaygateClient, id="unassigned")
    assert stored.owner_user_id == "user-a"
    assert k3s_crypto.decrypt_wg_client_key(stored.private_key_encrypted) == private_key
    assert private_key not in stored.private_key_encrypted
    downloaded = await native.client.get(path + "/config", headers=headers)
    assert downloaded.status_code == 200, downloaded.text
    assert "PrivateKey = " + private_key in downloaded.text
    assert downloaded.headers["cache-control"] == "no-store"
    _assert_assignment_queries(cloud, start)
    assert all(query["user.id"] == ["user-a"] for query in cloud.role_assignment_queries[start:])
    assert sum("scope.system" in query for query in cloud.role_assignment_queries[start:]) >= 3

    # A system administrator is still not allowed to transfer or clear a known
    # owner, or download someone else's private profile.
    transferred = await native.client.patch(path, json={"owner_user_id": "user-b"}, headers=headers)
    assert transferred.status_code == 409, transferred.text
    cleared = await native.client.patch(path, json={"owner_user_id": None}, headers=headers)
    assert cleared.status_code == 422, cleared.text
    cloud.system_assignments.append(_system_admin_row("user-b"))
    foreign = await native.client.get(path + "/config", headers=native.headers("user-b"))
    assert foreign.status_code == 403, foreign.text
    assert (await _rows(WaygateClient, id="unassigned"))[0].owner_user_id == "user-a"
    assert cloud.cloud_requests == [] and cloud.trusts == {}
    assert await _rows(WaygateExecutionGrant) == [] and await _rows(WaygateJob) == []


@pytest.mark.parametrize("failure", [
    "wrong-role", "wrong-subject", "project-scope", "domain-scope", "false-system",
    "nonboolean-system", "group-system", "missing", "outage",
])
async def test_direct_system_admin_owner_patch_rejects_nonmatching_rows_and_outage(native, failure):
    cloud = native.cloud
    cloud.assignments["user-a", "project-a"] = {"admin"}
    cloud.assignments["user-b", "project-a"] = {"member", "waygate-clients_editor"}
    row = _system_admin_row()
    if failure == "wrong-role":
        row["role"] = {"id": "role-member"}
    elif failure == "wrong-subject":
        row["user"] = {"id": "another-user"}
    elif failure == "project-scope":
        row["scope"] = {"project": {"id": "project-a"}}
    elif failure == "domain-scope":
        row["scope"] = {"domain": {"id": "default"}}
    elif failure == "false-system":
        row["scope"] = {"system": {"all": False}}
    elif failure == "nonboolean-system":
        row["scope"] = {"system": {"all": "true"}}
    elif failure == "group-system":
        del row["user"]
        row["group"] = {"id": "system-admins"}
    cloud.system_assignments = [] if failure == "missing" else [row]
    cloud.fail_system_assignments = failure == "outage"
    await _seed_unassigned_profile()
    path = "/v1/servers/owner-server/clients/unassigned"

    # The editor caller is independently authorized; denial must come from
    # validation of the proposed platform-role owner's current direct grant.
    response = await native.client.patch(
        path, json={"owner_user_id": "user-a"}, headers=native.headers("user-b"),
    )
    assert response.status_code == 422, response.text
    [stored] = await _rows(WaygateClient, id="unassigned")
    assert stored.owner_user_id is None
    assert stored.name == "legacy" and stored.enabled is True
    _assert_assignment_queries(cloud)
    assert {
        "user.id": ["user-a"], "role.id": ["role-admin"], "scope.system": ["all"],
    } in cloud.role_assignment_queries
    denied = await native.client.get(path + "/config", headers=native.headers("user-a"))
    assert denied.status_code == 403, denied.text
    assert cloud.cloud_requests == [] and cloud.trusts == {}
    assert await _rows(WaygateExecutionGrant) == [] and await _rows(WaygateJob) == []


async def test_direct_system_admin_execution_still_delegates_only_member(native):
    cloud = native.cloud
    cloud.assignments["user-a", "project-a"] = {"admin"}
    cloud.system_assignments = [_system_admin_row()]
    cloud.incompatible_effective_system = True
    server_id = await _create(native)
    [trust] = cloud.trusts.values()
    assert trust["roles"] == ["member"]
    assert trust["impersonation"] is True
    assert (trust["trustor_user_id"], trust["trustee_user_id"], trust["project_id"]) == (
        "user-a", SERVICE_USER, "project-a",
    )
    [grant] = await _rows(WaygateExecutionGrant)
    assert grant.role_id == "role-member"
    assert (await _rows(WaygateJob, server_id=server_id))[0].execution_grant_id == grant.id
    assert cloud.cloud_requests
    assert _trust_users(cloud) == {("user-a", trust["id"])}
    assert all(record["roles"] == {"member", "reader"} for _, _, record in cloud.cloud_requests)
    assert await waygate_jobs.process_one_job() is True
    assert (await _rows(WaygateJob, server_id=server_id))[0].status == "completed"
    assert (await _rows(WaygateExecutionGrant))[0].status == "revoked"
    assert cloud.trust_deletes == [(trust["id"], SERVICE_USER)]
    assert all(record["roles"] == {"member", "reader"} for _, _, record in cloud.cloud_requests)
    _assert_assignment_queries(cloud)


async def test_direct_system_admin_without_project_member_cannot_own_or_delegate(native):
    cloud = native.cloud
    cloud.assignments["user-a", "project-a"] = {"reader"}
    cloud.assignments["user-b", "project-a"] = {"member", "waygate-clients_editor"}
    cloud.system_assignments = [_system_admin_row()]
    cloud.incompatible_effective_system = True
    await _seed_unassigned_profile()
    assigned = await native.client.patch(
        "/v1/servers/owner-server/clients/unassigned", json={"owner_user_id": "user-a"},
        headers=native.headers("user-b"),
    )
    assert assigned.status_code == 422, assigned.text
    assert (await _rows(WaygateClient, id="unassigned"))[0].owner_user_id is None
    admitted = await native.client.post("/v1/servers", json={"name": "denied"}, headers=native.headers("user-a"))
    assert admitted.status_code == 403, admitted.text
    assert [row.id for row in await _rows(WaygateServer)] == ["owner-server"]
    assert await _rows(WaygateJob) == []
    assert all(row.status != "active" for row in await _rows(WaygateExecutionGrant))
    assert cloud.trusts == {} and cloud.cloud_requests == []
    _assert_assignment_queries(cloud)


async def test_tenant_cloud_io_uses_only_the_requesters_bounded_trust(native):
    cloud = native.cloud
    server_id = await _create(native)

    [trust] = cloud.trusts.values()
    assert (trust["trustor_user_id"], trust["trustee_user_id"], trust["project_id"]) == (
        "user-a",
        SERVICE_USER,
        "project-a",
    )
    assert trust["impersonation"] is True and trust["roles"] == ["member"]
    assert timedelta(minutes=115) < trust["expires"] - datetime.now(UTC) <= timedelta(hours=2)
    # Admission validated image, flavor and network with the requester's Trust.
    assert _trust_users(cloud) == {("user-a", trust["id"])}
    [grant] = await _rows(WaygateExecutionGrant)
    [job] = await _rows(WaygateJob, server_id=server_id)
    assert (grant.status, grant.trust_id, grant.purpose, grant.user_id) == (
        "active",
        trust["id"],
        "provision",
        "user-a",
    )
    assert (job.status, job.execution_grant_id) == ("queued", grant.id)

    assert await waygate_jobs.process_one_job() is True

    [server] = await _rows(WaygateServer, id=server_id)
    assert (server.status, server.endpoint_ip) == ("PROVISIONING", "10.0.0.5")
    [body] = cloud.server_bodies
    assert not body.get("imageRef")
    assert body["block_device_mapping_v2"] == [
        {
            "uuid": IMAGE,
            "source_type": "image",
            "destination_type": "volume",
            "volume_size": 12,
            "boot_index": 0,
            "delete_on_termination": True,
        }
    ]
    assert _trust_users(cloud) == {("user-a", trust["id"])}
    assert (await _rows(WaygateJob, server_id=server_id))[0].status == "completed"
    assert (await _rows(WaygateExecutionGrant))[0].status == "revoked"
    assert cloud.trust_deletes == [(trust["id"], SERVICE_USER)]
    # No password authentication ever selected a tenant project for the service identity.
    for document in cloud.auth_requests:
        scope = document["auth"].get("scope") or {}
        if document["auth"]["identity"]["methods"] == ["password"]:
            assert "OS-TRUST:trust" in scope or scope["project"]["name"] == SERVICE_PROJECT


async def test_positive_disk_flavor_keeps_image_backed_boot(native):
    native.cloud.flavor_disk = 20
    await _create(native)
    assert await waygate_jobs.process_one_job() is True
    [body] = native.cloud.server_bodies
    assert body["imageRef"] == IMAGE
    assert "block_device_mapping_v2" not in body


@pytest.mark.parametrize("revocation", ["capability", "member", "user", "project", "trust"])
async def test_revoked_authority_stops_worker_before_any_cloud_mutation(native, revocation):
    cloud = native.cloud
    server_id = await _create(native)
    [trust] = cloud.trusts.values()
    if revocation == "capability":
        cloud.assignments["user-a", "project-a"].discard("waygate-gateways_editor")
    elif revocation == "member":
        cloud.assignments["user-a", "project-a"].discard("member")
    elif revocation == "user":
        cloud.users["user-a"] = False
    elif revocation == "project":
        cloud.projects["project-a"] = False
    else:
        trust["deleted"] = True
    before = len(cloud.cloud_requests)

    assert await waygate_jobs.process_one_job() is True

    assert cloud.cloud_requests[before:] == []
    assert cloud.server_bodies == [] and cloud.ports == {}
    [job] = await _rows(WaygateJob, server_id=server_id)
    [server] = await _rows(WaygateServer, id=server_id)
    assert (job.status, job.attempts) == ("failed", 1)
    assert server.status == "ERROR"
    assert [grant.status for grant in await _rows(WaygateExecutionGrant)] == ["revoked"]


async def test_authority_removed_mid_provision_denies_the_next_cloud_request(native):
    cloud = native.cloud
    server_id = await _create(native)

    def revoke_after_port(method, path):
        if (method, path) == ("POST", "/network/v2.0/ports"):
            cloud.assignments["user-a", "project-a"].discard("waygate-gateways_editor")

    cloud.after_cloud_request = revoke_after_port
    assert await waygate_jobs.process_one_job() is True

    assert ("POST", "/network/v2.0/ports") == cloud.cloud_requests[-1][:2]
    assert cloud.server_bodies == []
    [job] = await _rows(WaygateJob, server_id=server_id)
    assert (job.status, job.attempts) == ("failed", 1)
    assert [grant.status for grant in await _rows(WaygateExecutionGrant)] == ["revoked"]


async def test_deletion_uses_the_current_admins_fresh_trust_after_creator_leaves(native):
    cloud = native.cloud
    server_id = await _create(native)
    assert await waygate_jobs.process_one_job() is True
    del cloud.assignments["user-a", "project-a"]
    provisioned = len(cloud.cloud_requests)

    response = await native.client.delete(f"/v1/servers/{server_id}", headers=native.headers("user-b"))
    assert response.status_code == 202, response.text
    delete_trust = next(trust for trust in cloud.trusts.values() if trust["trustor_user_id"] == "user-b")
    assert await waygate_jobs.process_one_job() is True

    assert _trust_users(cloud, provisioned) == {("user-b", delete_trust["id"])}
    assert cloud.servers == {} and cloud.ports == {}
    [server] = await _rows(WaygateServer, id=server_id)
    assert (server.status, server.deleted_by_user_id) == ("DELETED", "user-b")
    assert [job.status for job in await _rows(WaygateJob, kind="delete")] == ["completed"]
    assert {grant.status for grant in await _rows(WaygateExecutionGrant)} == {"revoked"}


async def test_revocation_outage_keeps_completed_mutation_terminal(native):
    cloud = native.cloud
    cloud.fail_trust_delete = 1
    server_id = await _create(native)
    assert await waygate_jobs.process_one_job() is True

    [grant] = await _rows(WaygateExecutionGrant)
    assert grant.status == "cleanup_pending"
    assert (await _rows(WaygateJob, server_id=server_id))[0].status == "completed"
    async with db.get_session_factory()() as session, session.begin():
        await session.execute(update(WaygateExecutionGrant).values(updated_at=datetime.now(UTC) - timedelta(minutes=1)))
    assert await waygate_jobs.process_one_job() is True

    assert (await _rows(WaygateExecutionGrant))[0].status == "revoked"
    assert len(cloud.server_bodies) == 1
    assert [trust_id for trust_id, _user in cloud.trust_deletes] == [grant.trust_id]


async def test_legacy_job_without_delegation_fails_without_minting_one(native):
    async with db.get_session_factory()() as session, session.begin():
        session.add(WaygateServer(id="legacy-server", project_id="project-a", name="legacy", status="CREATING"))
        session.add(
            WaygateJob(
                id="legacy-job",
                server_id="legacy-server",
                project_id="project-a",
                kind="provision",
                status="queued",
                user_id="user-a",
            )
        )
    auth_before = len(native.cloud.auth_requests)

    assert await waygate_jobs.process_one_job() is True

    [job] = await _rows(WaygateJob, id="legacy-job")
    assert (job.status, job.attempts) == ("failed", 1)
    assert (await _rows(WaygateServer, id="legacy-server"))[0].status == "ERROR"
    assert native.cloud.trusts == {} and native.cloud.cloud_requests == []
    assert native.cloud.auth_requests[auth_before:] == []


async def test_unusable_trust_at_admission_is_deleted_and_refused(native):
    native.cloud.refuse_trust_tokens = True
    response = await native.client.post("/v1/servers", json={"name": "gw"}, headers=native.headers("user-a"))

    assert response.status_code == 403
    [trust] = native.cloud.trusts.values()
    assert native.cloud.trust_deletes == [(trust["id"], SERVICE_USER)]
    assert native.cloud.cloud_requests == []
    assert await _rows(WaygateServer) == [] and await _rows(WaygateJob) == []
    assert [grant.status for grant in await _rows(WaygateExecutionGrant)] == ["revoked"]
