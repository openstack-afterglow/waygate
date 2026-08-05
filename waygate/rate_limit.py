"""Rate limiting with trusted-proxy-aware client addresses."""

from __future__ import annotations

import ipaddress
import logging

from slowapi import Limiter
from slowapi.util import get_remote_address

from waygate.config import get_settings

_logger = logging.getLogger(__name__)


def _real_ip(request) -> str:
    direct = get_remote_address(request)
    trusted = []
    for value in get_settings().trusted_proxies.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            trusted.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            _logger.warning("Ignoring invalid trusted proxy network: %s", value)
    try:
        direct_ip = ipaddress.ip_address(direct)
    except ValueError:
        return direct
    if not any(direct_ip in network for network in trusted):
        return direct
    forwarded = [part.strip() for part in request.headers.get("X-Forwarded-For", "").split(",") if part.strip()]
    if forwarded:
        return forwarded[-2] if len(forwarded) >= 2 else forwarded[0]
    return request.headers.get("X-Real-IP", direct).strip()


limiter = Limiter(key_func=_real_ip)
