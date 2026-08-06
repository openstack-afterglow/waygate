"""Register Waygate as an OpenStack SDK service."""

from waygate_sdk.service import WaygateService

__version__ = "0.1.0"


def register(conn):
    """Enable Waygate and return ``conn.waygate``."""
    conn.config.enable_service("waygate")
    conn.add_service(WaygateService())
    return conn.waygate


__all__ = ["WaygateService", "register"]
