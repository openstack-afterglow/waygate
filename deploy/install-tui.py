#!/usr/bin/env python3
"""Small standard-library setup wizard for deploy/install.sh."""

from __future__ import annotations

import getpass
import ipaddress
import os
import shlex
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def ask(label: str, default: str | None = None, *, secret: bool = False, required: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        prompt = f"{label}{suffix}: "
        value = getpass.getpass(prompt) if secret else input(prompt)
        value = value.strip()
        if not value and default is not None:
            return default
        if value or not required:
            return value
        print("  value is required")


def ask_yes_no(label: str, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        value = input(f"{label} [{suffix}]: ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("  answer y or n")


def default_interface() -> str:
    try:
        output = subprocess.check_output(
            ["ip", "-4", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    fields = output.split()
    if "dev" in fields:
        return fields[fields.index("dev") + 1]
    return ""


def validate_cidr(value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR: {value}") from exc
    return value


def main() -> int:
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Usage: python3 deploy/install-tui.py")
        print("Interactively collect environment variables and run deploy/install.sh.")
        return 0
    print("Afterglow WireGuard Agent installer")
    print("Values are written to a temporary root-only file and removed after install.\n")

    server_host = ask("Public WireGuard server IP/DNS", required=True)
    token = ask("API_AUTH_TOKEN (blank generates one)", secret=True)
    if not token:
        token = secrets.token_urlsafe(32)
        print("  generated a random API token")
    if len(token) < 32:
        print("API_AUTH_TOKEN must contain at least 32 characters", file=sys.stderr)
        return 2

    api_host = ask("API bind host", "127.0.0.1")
    api_port = ask("API port", "8080")
    allowed_cidrs = ""
    allow_insecure = False
    public_base_url = ""
    if api_host not in LOOPBACK_HOSTS:
        allowed_cidrs = ask("API_ALLOWED_CIDRS (for example 198.51.100.10/32)", required=True)
        try:
            for cidr in allowed_cidrs.split(","):
                validate_cidr(cidr.strip())
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        allow_insecure = ask_yes_no("Allow plain HTTP on the non-loopback API", False)
        public_base_url = ask("API_PUBLIC_BASE_URL (blank for derived URL)", "")

    values = {
        "WG_INTERFACE": ask("WireGuard interface", "wg0"),
        "WG_PORT": ask("WireGuard UDP port", "51820"),
        "WG_SERVER_HOST": server_host,
        "WG_SERVER_NET": ask("WireGuard server network", "10.8.0.0/24"),
        "WG_DEFAULT_DNS": ask("Default client DNS", "1.1.1.1"),
        "API_AUTH_TOKEN": token,
        "API_HOST": api_host,
        "API_PORT": api_port,
        "WG_PERSISTENT_KEEPALIVE": ask("Persistent keepalive seconds", "25"),
        "WG_OUTBOUND_INTERFACE": ask("Outbound interface", default_interface()),
        "ALLOW_INSECURE_HTTP": str(allow_insecure).lower(),
        "API_ALLOWED_CIDRS": allowed_cidrs,
        "API_DOCS_ENABLED": str(ask_yes_no("Enable API docs", False)).lower(),
    }
    if public_base_url:
        values["API_PUBLIC_BASE_URL"] = public_base_url

    print("\nConfiguration")
    for key, value in values.items():
        shown = "<hidden>" if key == "API_AUTH_TOKEN" else (value or "<empty>")
        print(f"  {key}={shown}")
    if not ask_yes_no("Install and start the native service", True):
        print("cancelled")
        return 0

    installer = Path(__file__).resolve().with_name("install.sh")
    if not installer.is_file():
        print(f"installer not found: {installer}", file=sys.stderr)
        return 1

    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", prefix="afterglow-tui-", suffix=".env", delete=False
        ) as handle:
            temp_path = handle.name
            os.chmod(temp_path, 0o600)
            for key, value in values.items():
                handle.write(f"{key}={shlex.quote(value)}\n")
        command = [str(installer), "--env-file", temp_path, "--source-dir", str(installer.parent.parent)]
        if os.geteuid() != 0:
            command.insert(0, "sudo")
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as exc:
        return exc.returncode or 1
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        return 130
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)

    print("\nInstallation complete.")
    print("The generated API token is stored in /etc/afterglow-wg-agent.env with mode 0600.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
