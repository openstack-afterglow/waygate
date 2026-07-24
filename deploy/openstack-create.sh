#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${WAYGATE_CLOUD_INIT_TEMPLATE:-$SCRIPT_DIR/cloud-init-openstack.yaml}"
SERVER_NAME="${WAYGATE_SERVER_NAME:-waygate-wg}"
SECURITY_GROUP="${WAYGATE_SECURITY_GROUP:-waygate-wg}"
WEB_PORT="${WAYGATE_WEB_PORT:-8080}"
WG_PORT="${WAYGATE_WG_PORT:-51820}"

: "${OS_IMAGE:?Set OS_IMAGE to an Ubuntu image name or ID}"
: "${OS_FLAVOR:?Set OS_FLAVOR to an OpenStack flavor name or ID}"
: "${OS_NETWORK:?Set OS_NETWORK to the tenant network name or ID}"
: "${OS_EXTERNAL_NETWORK:?Set OS_EXTERNAL_NETWORK to the floating-IP network name or ID}"
: "${OS_KEYPAIR:?Set OS_KEYPAIR to an existing OpenStack keypair name}"
: "${OS_ADMIN_CIDR:?Set OS_ADMIN_CIDR to the administrator CIDR, for example 198.51.100.10/32}"

command -v openstack >/dev/null 2>&1 || { echo "openstack CLI is required" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required to verify the Waygate web console" >&2; exit 1; }
[[ -f "$TEMPLATE" ]] || { echo "cloud-init template not found: $TEMPLATE" >&2; exit 1; }

case "$OS_ADMIN_CIDR" in
  */*) ;;
  *) echo "OS_ADMIN_CIDR must be a CIDR, for example 198.51.100.10/32" >&2; exit 2 ;;
esac

if ! openstack security group show "$SECURITY_GROUP" >/dev/null 2>&1; then
  openstack security group create --description "Waygate WireGuard prototype" "$SECURITY_GROUP" >/dev/null
fi

add_rule() {
  if ! openstack security group rule create "$@" "$SECURITY_GROUP" >/dev/null 2>&1; then
    echo "security-group rule already exists or could not be added: $*" >&2
  fi
}

# SSH and prototype API are restricted to the administrator CIDR.
add_rule --ingress --protocol tcp --dst-port 22:22 --remote-ip "$OS_ADMIN_CIDR"
add_rule --ingress --protocol tcp --dst-port "$WEB_PORT:$WEB_PORT" --remote-ip "$OS_ADMIN_CIDR"
# WireGuard peer traffic must be reachable from the public Internet.
add_rule --ingress --protocol udp --dst-port "$WG_PORT:$WG_PORT" --remote-ip 0.0.0.0/0

FLOATING_IP="$(openstack floating ip create "$OS_EXTERNAL_NETWORK" -f value -c floating_ip_address)"
USER_DATA="$(mktemp "${TMPDIR:-/tmp}/waygate-user-data.XXXXXX")"
cleanup() {
  rm -f -- "$USER_DATA"
}
trap cleanup EXIT

sed \
  -e "s|__PUBLIC_IP__|$FLOATING_IP|g" \
  -e "s|__ADMIN_CIDR__|$OS_ADMIN_CIDR|g" \
  "$TEMPLATE" > "$USER_DATA"

SERVER_ID="$(openstack server create \
  --image "$OS_IMAGE" \
  --flavor "$OS_FLAVOR" \
  --key-name "$OS_KEYPAIR" \
  --network "$OS_NETWORK" \
  --security-group "$SECURITY_GROUP" \
  --user-data "$USER_DATA" \
  -f value -c id "$SERVER_NAME")"

openstack server add floating ip "$SERVER_NAME" "$FLOATING_IP"

for _ in {1..60}; do
  status="$(openstack server show "$SERVER_ID" -f value -c status 2>/dev/null || true)"
  case "$status" in
    ACTIVE) break ;;
    ERROR) echo "OpenStack server entered ERROR state: $SERVER_ID" >&2; exit 1 ;;
  esac
  sleep 5
done
[[ "${status:-}" == ACTIVE ]] || { echo "Timed out waiting for ACTIVE server: $SERVER_ID" >&2; exit 1; }

WEB_URL="http://$FLOATING_IP:$WEB_PORT/"
web_ready=0
for _ in {1..120}; do
  if curl --fail --silent --show-error --max-time 3 "$WEB_URL" >/dev/null; then
    web_ready=1
    break
  fi
  sleep 5
done
((web_ready == 1)) || { echo "Waygate web console did not become ready at $WEB_URL" >&2; exit 1; }

printf 'system=waygate\n'
printf 'server=%s\n' "$SERVER_NAME"
printf 'server_id=%s\n' "$SERVER_ID"
printf 'floating_ip=%s\n' "$FLOATING_IP"
printf 'ssh=ssh ubuntu@%s\n' "$FLOATING_IP"
printf 'web_console=%s\n' "$WEB_URL"
printf 'api_status=http://%s:%s/api/v1/status\n' "$FLOATING_IP" "$WEB_PORT"
printf 'api_token=ssh ubuntu@%s "sudo cat /etc/afterglow-wg-agent.env"\n' "$FLOATING_IP"
printf 'cloud_init=complete\n'
