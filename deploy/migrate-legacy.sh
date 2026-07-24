#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

OLD_STATE=/var/lib/afterglow-wg-agent
NEW_STATE=/var/lib/waygate
OLD_ENV=/etc/afterglow-wg-agent.env
NEW_ENV=/etc/waygate.env
OLD_UNIT=/etc/systemd/system/afterglow-wg-agent.service
OLD_TMPFILES=/etc/tmpfiles.d/afterglow-wg-agent.conf
WG_CONFIG=/etc/wireguard/wg0.conf

[[ $EUID == 0 ]] || { echo "migrate-legacy.sh must run as root" >&2; exit 1; }

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

if [[ -d "$NEW_STATE/keys" ]]; then
  while IFS= read -r -d '' old_stage; do
    new_stage="${old_stage//.afterglow-stage-/.waygate-stage-}"
    [[ "$old_stage" == "$new_stage" ]] && continue
    [[ ! -e "$new_stage" ]] || { echo "migration conflict: $new_stage exists" >&2; exit 1; }
    mv -- "$old_stage" "$new_stage"
  done < <(find "$NEW_STATE/keys" -mindepth 1 -maxdepth 1 -type d -name '.afterglow-stage-*' -print0)
fi

if command -v iptables >/dev/null 2>&1; then
  legacy_filter=(
    AFTERGLOW_INPUT_A AFTERGLOW_INPUT_B AFTERGLOW_FWD_A AFTERGLOW_FWD_B
    AFTERGLOW_STAGE_IN AFTERGLOW_STAGE_FWD AFTERGLOW_STAGE_OUT
    AFTERGLOW_BOOT_INPUT AFTERGLOW_BOOT_FWD
  )
  legacy_nat=(AFTERGLOW_NAT)
  all_chains=("${legacy_filter[@]}" "${legacy_nat[@]}")
  filter_parents=(INPUT FORWARD OUTPUT "${legacy_filter[@]}")
  nat_parents=(POSTROUTING "${legacy_nat[@]}")

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
    iptables -w 5 -F "$chain" >/dev/null 2>&1 || true
    iptables -w 5 -X "$chain" >/dev/null 2>&1 || true
  done
  for chain in "${legacy_nat[@]}"; do
    iptables -w 5 -t nat -F "$chain" >/dev/null 2>&1 || true
    iptables -w 5 -t nat -X "$chain" >/dev/null 2>&1 || true
  done
fi

systemctl disable afterglow-wg-agent.service >/dev/null 2>&1 || true
rm -f -- "$OLD_UNIT" "$OLD_TMPFILES"
rm -rf -- /run/afterglow-wg-agent
systemctl daemon-reload
printf 'legacy_migration=complete\n'
