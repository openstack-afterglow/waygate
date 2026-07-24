#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

OLD_STATE=/var/lib/afterglow-wg-agent
NEW_STATE=/var/lib/waygate
OLD_ENV=/etc/afterglow-wg-agent.env
NEW_ENV=/etc/waygate.env
OLD_UNIT=/etc/systemd/system/afterglow-wg-agent.service
OLD_TMPFILES=/etc/tmpfiles.d/afterglow-wg-agent.conf
WG_INTERFACE="${WG_INTERFACE:-}"

legacy_filter=(
  AFTERGLOW_INPUT_A AFTERGLOW_INPUT_B AFTERGLOW_FWD_A AFTERGLOW_FWD_B
  AFTERGLOW_STAGE_IN AFTERGLOW_STAGE_FWD AFTERGLOW_STAGE_OUT
  AFTERGLOW_BOOT_INPUT AFTERGLOW_BOOT_FWD
)
legacy_nat=(AFTERGLOW_NAT)
all_chains=("${legacy_filter[@]}" "${legacy_nat[@]}")

[[ $EUID == 0 ]] || { echo "migrate-legacy.sh must run as root" >&2; exit 1; }

legacy_chain_present() {
  local chain="$1"
  if command -v iptables >/dev/null 2>&1; then
    iptables -w 5 -S "$chain" >/dev/null 2>&1 && return 0
    iptables -w 5 -t nat -S "$chain" >/dev/null 2>&1 && return 0
  fi
  return 1
}

legacy_footprint=0
for path in "$OLD_STATE" "$OLD_ENV" "$OLD_UNIT" "$OLD_TMPFILES" /opt/afterglow-wg-agent; do
  if [[ -e "$path" ]]; then
    legacy_footprint=1
    break
  fi
done
if ((legacy_footprint == 0)); then
  for chain in "${all_chains[@]}"; do
    if legacy_chain_present "$chain"; then
      legacy_footprint=1
      break
    fi
  done
fi
if ((legacy_footprint == 0)); then
  printf 'legacy_migration=not_needed\n'
  exit 0
fi

# A state directory is the ownership authority for an old installation. Do not
# touch an unrelated wg0 or orphaned firewall chain without that authority.
[[ -d "$OLD_STATE" && -f "$OLD_STATE/agent.db" && -d "$OLD_STATE/keys" ]] || {
  echo "legacy footprint exists but its state authority is incomplete" >&2
  exit 1
}

if [[ -z "$WG_INTERFACE" && -f "$OLD_ENV" ]]; then
  WG_INTERFACE="$(awk -F= '$1 == "WG_INTERFACE" { print $2; exit }' "$OLD_ENV")"
fi
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
if [[ -f "$WG_CONFIG" ]]; then
  first_line="$(sed -n '1p' "$WG_CONFIG")"
  case "$first_line" in
    "# Managed by afterglow-wg-agent; DO NOT EDIT."|"# Managed by waygate; DO NOT EDIT.") ;;
    *) echo "legacy config ownership marker is not recognized: $WG_CONFIG" >&2; exit 1 ;;
  esac
fi

# Stop data-plane traffic before removing the old policy. A non-WireGuard
# interface with the configured name is never taken down.
if command -v ip >/dev/null 2>&1 && ip link show "$WG_INTERFACE" >/dev/null 2>&1; then
  command -v wg >/dev/null 2>&1 || { echo "wireguard-tools is required to migrate an existing interface" >&2; exit 1; }
  wg show "$WG_INTERFACE" >/dev/null 2>&1 || { echo "$WG_INTERFACE is not a WireGuard interface" >&2; exit 1; }
  ip link set "$WG_INTERFACE" down
fi

move_directory() {
  local old="$1" new="$2"
  [[ -e "$old" ]] || return 0
  if [[ -e "$new" ]]; then
    echo "migration conflict: both $old and $new exist" >&2
    exit 1
  fi
  install -d -o root -g root "$(dirname "$new")"
  mv -- "$old" "$new"
  chmod 700 "$new"
}

move_file() {
  local old="$1" new="$2"
  [[ -e "$old" ]] || return 0
  if [[ -e "$new" ]]; then
    cmp -s "$old" "$new" || { echo "migration conflict: $old and $new differ" >&2; exit 1; }
    rm -f -- "$old"
    return 0
  fi
  install -d -o root -g root "$(dirname "$new")"
  mv -- "$old" "$new"
  chmod 600 "$new"
}

move_directory "$OLD_STATE" "$NEW_STATE"
move_file "$OLD_ENV" "$NEW_ENV"

if [[ -f "$WG_CONFIG" ]]; then
  staged="$(mktemp /etc/wireguard/.waygate-migrate.XXXXXX)"
  chmod 600 "$staged"
  sed \
    -e '1s/^# Managed by afterglow-wg-agent; DO NOT EDIT\.$/# Managed by waygate; DO NOT EDIT./' \
    -e 's/\.afterglow-stage-/.waygate-stage-/g' \
    "$WG_CONFIG" > "$staged"
  chown root:root "$staged"
  mv -f -- "$staged" "$WG_CONFIG"
  chmod 600 "$WG_CONFIG"
fi

rename_stage_dirs() {
  local root="$1"
  [[ -d "$root" ]] || return 0
  while IFS= read -r -d '' old_stage; do
    new_stage="${old_stage//.afterglow-stage-/.waygate-stage-}"
    [[ "$old_stage" == "$new_stage" ]] && continue
    [[ ! -e "$new_stage" ]] || { echo "migration conflict: $new_stage exists" >&2; exit 1; }
    mv -- "$old_stage" "$new_stage"
  done < <(find "$root" -mindepth 1 -maxdepth 1 -type d -name '.afterglow-stage-*' -print0)
}

rename_stage_dirs /etc/wireguard
rename_stage_dirs "$NEW_STATE/keys"

command -v iptables >/dev/null 2>&1 || { echo "iptables is required for legacy policy cleanup" >&2; exit 1; }
filter_parents=(INPUT FORWARD OUTPUT "${legacy_filter[@]}")
nat_parents=(POSTROUTING "${legacy_nat[@]}")

chain_exists() {
  local table="$1" chain="$2"
  if [[ "$table" == nat ]]; then
    iptables -w 5 -t nat -S "$chain" >/dev/null 2>&1
  else
    iptables -w 5 -S "$chain" >/dev/null 2>&1
  fi
}

for parent in "${filter_parents[@]}"; do
  for chain in "${all_chains[@]}"; do
    while iptables -w 5 -C "$parent" -j "$chain" >/dev/null 2>&1; do
      iptables -w 5 -D "$parent" -j "$chain"
    done
  done
done
for parent in "${nat_parents[@]}"; do
  for chain in "${all_chains[@]}"; do
    while iptables -w 5 -t nat -C "$parent" -j "$chain" >/dev/null 2>&1; do
      iptables -w 5 -t nat -D "$parent" -j "$chain"
    done
  done
done
for chain in "${legacy_filter[@]}"; do
  if chain_exists filter "$chain"; then
    iptables -w 5 -F "$chain"
    iptables -w 5 -X "$chain"
  fi
done
for chain in "${legacy_nat[@]}"; do
  if chain_exists nat "$chain"; then
    iptables -w 5 -t nat -F "$chain"
    iptables -w 5 -t nat -X "$chain"
  fi
done
for chain in "${legacy_filter[@]}"; do
  chain_exists filter "$chain" && { echo "legacy filter chain remains: $chain" >&2; exit 1; } || true
done
for chain in "${legacy_nat[@]}"; do
  chain_exists nat "$chain" && { echo "legacy nat chain remains: $chain" >&2; exit 1; } || true
done

systemctl disable afterglow-wg-agent.service >/dev/null 2>&1 || true
rm -f -- "$OLD_UNIT" "$OLD_TMPFILES"
rm -rf -- /run/afterglow-wg-agent
systemctl daemon-reload
printf 'legacy_migration=complete\n'
