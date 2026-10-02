#!/bin/sh
set -eu
SRC=${1:-$(dirname "$0")}
DEST=${2:-}
# Stop old executions before replacing their script/unit. A staging root must
# never call the host service manager, even when upgrading staged timer assets.
case "$DEST" in
    ''|/)
        timer_state=$(systemctl show --property=LoadState --value afterglow-waygate-reconcile.timer)
        if [ "$timer_state" != not-found ]; then
            systemctl stop afterglow-waygate-reconcile.timer
            systemctl disable afterglow-waygate-reconcile.timer
        fi
        service_state=$(systemctl show --property=LoadState --value afterglow-waygate-reconcile.service)
        if [ "$service_state" != not-found ]; then
            systemctl stop afterglow-waygate-reconcile.service
        fi
        ;;
esac
rm -f "$DEST/etc/systemd/system/afterglow-waygate-reconcile.timer" \
    "$DEST/etc/systemd/system/timers.target.wants/afterglow-waygate-reconcile.timer"
install -d -m 0755 "$DEST/opt/afterglow" "$DEST/etc/waygate" "$DEST/etc/wireguard" "$DEST/etc/systemd/system" "$DEST/etc/sysctl.d"
install -m 0750 "$SRC/waygate_agent.py" "$DEST/opt/afterglow/waygate_agent.py"
install -m 0644 "$SRC/afterglow-waygate-reconcile.service" "$DEST/etc/systemd/system/afterglow-waygate-reconcile.service"
install -m 0644 "$SRC/99-afterglow-wg-forward.conf" "$DEST/etc/sysctl.d/99-afterglow-wg-forward.conf"
case "$DEST" in
    ''|/)
        systemctl daemon-reload
        # Image creation has no per-server config and must stay inactive. An
        # explicit upgrade of a configured gateway replaces its timer cadence.
        if [ -f "$DEST/etc/waygate/agent.json" ]; then
            systemctl enable --now afterglow-waygate-reconcile.service
        fi
        ;;
esac
