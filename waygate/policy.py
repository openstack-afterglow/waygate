"""Registered oslo.policy actions; identity and resource boundaries remain native."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from threading import RLock, get_ident

import yaml
from fastapi import HTTPException
from oslo_config import cfg
from oslo_policy import _checks, _parser, policy

from waygate.config import get_settings

_LOG = logging.getLogger(__name__)
_LOCK = RLock()
DEFAULT_POLICY_FILE = "/etc/waygate/policy.yaml"

# Labels are UI projections, not roles added to Keystone tokens or execution Trusts.
CAPABILITY_ACTIONS = {
    "waygate-inventory_reader": (
        "waygate:server:list", "waygate:server:get", "waygate:client:list", "waygate:network:list",
    ),
    "waygate-connect_user": ("waygate:client:download",),
    "waygate-clients_editor": ("waygate:client:create", "waygate:client:update"),
    "waygate-clients_admin": ("waygate:client:set-enabled", "waygate:client:delete"),
    "waygate-gateways_editor": ("waygate:server:create", "waygate:server:update"),
    "waygate-gateways_admin": ("waygate:server:delete", "waygate:server:rotate-agent-token"),
    "waygate-routing_admin": ("waygate:network:attach", "waygate:network:detach"),
}

_PROJECT_READ_ROLES = ("reader", "member", "manager", "admin")
_PROJECT_MANAGE_ROLES = ("member", "manager", "admin")


def _check(label: str) -> str:
    roles = _PROJECT_READ_ROLES if label == "waygate-inventory_reader" else _PROJECT_MANAGE_ROLES
    return "system_admin:True or " + " or ".join("role:" + role for role in roles)


# Every HTTP operation has its own override, including PATCH enabled transitions.
_OPERATIONS = {
    "waygate:server:list": ("GET", "/v1/servers"),
    "waygate:server:get": ("GET", "/v1/servers/{server_id}"),
    "waygate:server:create": ("POST", "/v1/servers"),
    "waygate:server:update": ("PATCH", "/v1/servers/{server_id}"),
    "waygate:server:delete": ("DELETE", "/v1/servers/{server_id}"),
    "waygate:server:rotate-agent-token": ("POST", "/v1/servers/{server_id}/agent-token/rotate"),
    "waygate:client:list": ("GET", "/v1/servers/{server_id}/clients"),
    "waygate:client:create": ("POST", "/v1/servers/{server_id}/clients"),
    "waygate:client:update": ("PATCH", "/v1/servers/{server_id}/clients/{client_id}"),
    "waygate:client:set-enabled": ("PATCH", "/v1/servers/{server_id}/clients/{client_id}"),
    "waygate:client:delete": ("DELETE", "/v1/servers/{server_id}/clients/{client_id}"),
    "waygate:client:download": ("GET", "/v1/servers/{server_id}/clients/{client_id}/config"),
    "waygate:network:list": ("GET", "/v1/servers/{server_id}/networks"),
    "waygate:network:attach": ("POST", "/v1/servers/{server_id}/networks"),
    "waygate:network:detach": ("DELETE", "/v1/servers/{server_id}/networks/{attachment_id}"),
    "waygate:bundle:export": ("POST", "/v1/servers/{server_id}/export"),
    "waygate:bundle:import": ("POST", "/v1/servers/{server_id}/import"),
    "waygate:resource-policy:list": ("GET", "/v1/admin/resource-policies"),
    "waygate:resource-policy:catalog": ("GET", "/v1/admin/resource-policies/catalog/{policy_key}"),
    "waygate:resource-policy:update": ("PUT", "/v1/admin/resource-policies/{policy_key}"),
}
SYSTEM_ACTIONS = frozenset(action for action in _OPERATIONS if action.startswith("waygate:resource-policy:"))
ACTION_NAMES = frozenset(_OPERATIONS)

CLOUD_ACTIONS = frozenset({"waygate:server:create", "waygate:server:delete", "waygate:network:attach", "waygate:network:detach"})


def list_rules() -> list[policy.RuleDefault]:
    checks = {action: _check(label) for label, actions in CAPABILITY_ACTIONS.items() for action in actions}
    bundle_check = _check("waygate-clients_admin")
    checks.update({"waygate:bundle:export": bundle_check, "waygate:bundle:import": bundle_check})
    checks.update({action: "system_admin:True" for action in SYSTEM_ACTIONS})
    return [
        policy.DocumentedRuleDefault(
            name=action, check_str=checks[action], description=f"Authorize {action}; native ownership and credential ceilings also apply.",
            operations=[{"method": method, "path": path}], scope_types=["system"] if action in SYSTEM_ACTIONS else ["project"],
        )
        for action, (method, path) in _OPERATIONS.items()
    ]


class _ParserDiagnostics:
    """Observe native parser failure reports even if logging is disabled."""

    def __init__(self, logger):
        self.logger = logger
        self.thread_id = get_ident()
        self.failed = False

    def error(self, *args, **kwargs):
        self.failed |= get_ident() == self.thread_id
        return self.logger.error(*args, **kwargs)

    def exception(self, *args, **kwargs):
        self.failed |= get_ident() == self.thread_id
        return self.logger.exception(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.logger, name)


class _StringPolicyEnforcer(policy.Enforcer):
    """Validate documents and native parser diagnostics, never parse expressions."""

    _reload_failed = False

    def load_rules(self, force_reload: bool = False) -> None:
        # Native parsing can report an error and return FalseCheck; `not` can
        # otherwise invert that failed parse into allow. Do not reinterpret it.
        with _LOCK:
            original = _parser.LOG
            diagnostics = _ParserDiagnostics(original)
            _parser.LOG = diagnostics
            try:
                main = self.conf.find_file(self.policy_file)
                if self.policy_file != DEFAULT_POLICY_FILE and main is None:
                    raise FileNotFoundError("Configured policy file is unavailable")
                for directory in self.conf.oslo_policy.policy_dirs:
                    resolved = self.conf.find_file(directory)
                    if resolved is None or not Path(resolved).is_dir():
                        raise FileNotFoundError("Configured policy directory is unavailable")
                super().load_rules(force_reload=force_reload or self._reload_failed)
                if diagnostics.failed:
                    raise ValueError("Native policy parser rejected a check expression")
                self.check_rules(raise_on_violation=True)
                _validate_native_rule_graph(self)
                self._reload_failed = False
            except Exception:
                self._reload_failed = True
                raise
            finally:
                _parser.LOG = original

    def _record_file_rules(self, data: str, overwrite: bool = False) -> None:
        document = yaml.safe_load(data)
        if not isinstance(document, dict) or any(
            not isinstance(name, str) or not name.strip() or not isinstance(check, str)
            for name, check in document.items()
        ):
            raise ValueError("Policy must map nonempty rule names to check strings")
        super()._record_file_rules(data, overwrite=overwrite)


@lru_cache(maxsize=8)
def _enforcer(policy_file: str, policy_dirs: tuple[str, ...]) -> policy.Enforcer:
    conf = cfg.ConfigOpts()
    conf([], project="waygate", default_config_files=[])
    engine = _StringPolicyEnforcer(conf, policy_file=policy_file)
    conf.set_override("policy_dirs", list(policy_dirs), group="oslo_policy")
    engine.register_defaults(list_rules())
    return engine


def get_enforcer() -> policy.Enforcer:
    """Standard oslo.policy tooling entry point, using the native TOML bridge."""
    settings = get_settings()
    return _enforcer(settings.oslo_policy_file, tuple(settings.oslo_policy_dirs))


def _credentials(info: dict, *, system: bool) -> dict:
    # Expose no token/password/access-rule material to policy checks.
    return {
        "roles": list(info.get("roles") or []), "user_id": info.get("user_id", ""),
        "project_id": None if system else info.get("project_id"),
        "system_scope": "all" if system else None,
        "system_admin": info.get("is_system_admin") is True,
        "credential_restricted": bool(info.get("credential_restricted")),
    }


def _allows(engine: policy.Enforcer, info: dict, action: str) -> bool:
    """Native scope/credential ceilings are independent of operator expressions."""
    if action not in ACTION_NAMES:
        return False
    if info.get("is_system_admin") is not True and not info.get("roles"):
        return False
    system = action in SYSTEM_ACTIONS
    if system:
        if info.get("is_system_admin") is not True or info.get("credential_restricted"):
            return False
    elif not info.get("project_id"):
        return False
    elif info.get("is_system_admin") is not True:
        required = _PROJECT_READ_ROLES if action in CAPABILITY_ACTIONS["waygate-inventory_reader"] else _PROJECT_MANAGE_ROLES
        if not set(info.get("roles") or []).intersection(required):
            return False
    if action in CLOUD_ACTIONS and info.get("credential_restricted"):
        return False
    return bool(engine.authorize(action, {"project_id": info.get("project_id"), "user_id": info.get("user_id")}, _credentials(info, system=system)))

def _validate_native_rule_graph(engine: policy.Enforcer) -> None:
    """Walk native parsed nodes, including negation's singular child."""
    complete: set[str] = set()

    def visit_rule(name: str, active: frozenset[str]) -> None:
        if name not in engine.rules or name in active:
            raise ValueError("Undefined or cyclic native policy reference")
        if name in complete:
            return
        visit_check(engine.rules[name], active | {name})
        complete.add(name)

    def visit_check(check, active: frozenset[str]) -> None:
        if isinstance(check, _checks.RuleCheck):
            visit_rule(check.match, active)
        elif isinstance(check, _checks.NotCheck):
            visit_check(check.rule, active)
        else:
            for child in getattr(check, "rules", ()):
                visit_check(child, active)

    for name in engine.rules:
        visit_rule(name, frozenset())



@contextmanager
def _checked_engine():
    with _LOCK:
        try:
            engine = get_enforcer()
            engine.load_rules()
            yield engine
        except Exception:
            # Never retain partial rules after a failed reload or fall back to defaults.
            _enforcer.cache_clear()
            _LOG.warning("Waygate policy evaluation unavailable")
            raise HTTPException(status_code=503, detail="Waygate policy is temporarily unavailable") from None


def allows(info: dict, action: str) -> bool:
    """Evaluate one registered action against current native principal context."""
    if action not in ACTION_NAMES:
        return False
    with _checked_engine() as engine:
        return _allows(engine, info, action)


def enforce(info: dict, action: str) -> dict:
    if not allows(info, action):
        raise HTTPException(status_code=403, detail="Waygate action is not authorized")
    return info


def capabilities(info: dict) -> dict:
    with _checked_engine() as engine:
        actions = sorted(action for action in ACTION_NAMES if _allows(engine, info, action))
    allowed = set(actions)
    return {
        "service": "waygate", "actions": actions,
        "capabilities": sorted(label for label, candidates in CAPABILITY_ACTIONS.items() if allowed.intersection(candidates)),
    }
