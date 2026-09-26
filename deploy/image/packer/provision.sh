#!/bin/bash
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive
cloud-init status --wait
. /etc/os-release
[ "$ID" = ubuntu ]
[ "$VERSION_ID" = 24.04 ]
[ "$(dpkg --print-architecture)" = amd64 ]
apt-get update
packages=()
while read -r package || [ -n "$package" ]; do
    case "$package" in ''|'#'*) continue ;; esac
    packages+=("$package")
done < /tmp/waygate-agent/packages.txt
apt-get install -y --no-install-recommends "${packages[@]}"
sh /tmp/waygate-agent/install.sh /tmp/waygate-agent /
python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path
path = Path('/etc/waygate/image-info.json')
path.write_text(json.dumps({
    'waygate_agent': 'prebuilt',
    'agent_version': os.environ['AGENT_VERSION'],
    'agent_sha256': os.environ['AGENT_SHA256'],
    'built_at': datetime.now(timezone.utc).isoformat(),
}, indent=2) + '\n')
path.chmod(0o644)
PY
python3 -m py_compile /opt/afterglow/waygate_agent.py
systemctl daemon-reload
# Instance cloud-init enables the timer only after writing agent.json.
systemctl disable afterglow-waygate-reconcile.timer
[ ! -e /etc/waygate/agent.json ]
[ ! -e /etc/wireguard/privatekey ]
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/waygate-agent
cloud-init clean --logs --seed --configs all
# Snapshot images must not inherit base-image or temporary build SSH access.
python3 - <<'PY'
import pwd
from pathlib import Path
for account in pwd.getpwall():
    for name in ('authorized_keys', 'authorized_keys2'):
        path = Path(account.pw_dir) / '.ssh' / name
        if path.is_file():
            path.write_text('')
PY
rm -f /etc/ssh/ssh_host_* /var/lib/dhcp/*.leases
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id
sync
