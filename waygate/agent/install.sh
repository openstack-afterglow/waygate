#!/bin/sh
set -eu
SRC=${1:-$(dirname "$0")}
DEST=${2:-}
install -d -m 0755 "$DEST/opt/afterglow" "$DEST/etc/waygate" "$DEST/etc/wireguard" "$DEST/etc/systemd/system" "$DEST/etc/sysctl.d"
install -m 0750 "$SRC/waygate_agent.py" "$DEST/opt/afterglow/waygate_agent.py"
install -m 0644 "$SRC/afterglow-waygate-reconcile.service" "$DEST/etc/systemd/system/afterglow-waygate-reconcile.service"
install -m 0644 "$SRC/afterglow-waygate-reconcile.timer" "$DEST/etc/systemd/system/afterglow-waygate-reconcile.timer"
install -m 0644 "$SRC/99-afterglow-wg-forward.conf" "$DEST/etc/sysctl.d/99-afterglow-wg-forward.conf"
