"""Waygate domain services with lazy local aliases."""

from __future__ import annotations

import importlib

_ALIASES = {
    "keystone": "waygate.auth",
    "k3s_crypto": "waygate.crypto",
    "neutron": "waygate.services.openstack_ops",
    "nova": "waygate.services.openstack_ops",
    "waygate_agent_auth": "waygate.services.agent_auth",
    "waygate_config": "waygate.services.config_render",
    "waygate_db": "waygate.services.store",
    "waygate_ipam": "waygate.services.ipam",
    "waygate_jobs": "waygate.services.jobs",
    "waygate_keys": "waygate.services.keys",
    "waygate_migration": "waygate.services.migration",
    "waygate_network": "waygate.services.network",
}


def __getattr__(name: str):
    if module_name := _ALIASES.get(name):
        module = importlib.import_module(module_name)
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_ALIASES)
