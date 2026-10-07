#!/bin/bash
#
# unifi-blocklist: feed HaGeZi / OISD (or any domain list) into UniFi's own
# content-filtering engine (CoreDNS "hostSet" plugin) on UniFi OS gateways.
#
# Blocks are performed and logged by UniFi itself, so they still show up in the
# UniFi UI, and the UI allow list keeps working (it is evaluated first).
#
# Usage: blocklist.sh {menu|categories|enable|disable|update|apply|status|check|install|uninstall|watch}

set -uo pipefail

BASE_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
CONF_FILE="${BASE_DIR}/blocklist.conf"
CATALOG="${BASE_DIR}/categories.list"         # category -> list mapping (shipped)
ENABLED_FILE="${BASE_DIR}/categories.enabled" # selected category keys (yours)
DEFAULT_CATEGORIES="ADS_PRO BOTNETS MALWARE PHISHING"

# Defaults (override in blocklist.conf)
LIST_URLS=()               # extra list URLs on top of the selected categories
MIN_ENTRIES=1000           # refuse to apply a merged list smaller than this
MAX_ENTRIES=1500000        # refuse to apply a merged list larger than this (gateway memory)
WATCH_INTERVAL=15          # seconds between checks that our list is still in place
CUSTOM_BLOCK_FILE="${BASE_DIR}/custom-block.list"   # optional extra domains, one per line

# shellcheck source=/dev/null
[ -f "$CONF_FILE" ] && . "$CONF_FILE"

UTM_DIR="/run/utm"
TARGET="${UTM_DIR}/domain_list/domainlist_0.list"   # "include" = block list
COREDNS_PIDFILE="${UTM_DIR}/coredns.pid"
STATE_DIR="${BASE_DIR}/state"
CACHE_DIR="${STATE_DIR}/sources"       # last good normalised copy of each source
MERGED="${STATE_DIR}/merged.list"      # last good merged list
UI_LIST="${STATE_DIR}/ui-block.list"   # domains UniFi itself put in the block list
APPLIED="${STATE_DIR}/applied.sha256"  # checksum of the list CoreDNS was last restarted with
LOCK="/run/unifi-blocklist.lock"
SYSTEMD_DIR="/etc/systemd/system"
# Marks the boundary between UniFi's own entries and ours. ".invalid" is a
# reserved TLD (RFC 2606) so blocking it is harmless.
SENTINEL="unifi-blocklist-sentinel.invalid"

log() { logger -t unifi-blocklist -- "$*"; echo "$(date '+%F %T') $*"; }

# Strip comments and convert hosts / adblock / plain formats into bare domains.
normalise() {
  tr -d '\r' \
    | sed -E 's/[#!].*$//; s/^\|\|//; s/\^.*$//; s/^(0\.0\.0\.0|127\.0\.0\.1|::1?)[[:space:]]+//; s/^\*\.//' \
    | awk '{print tolower($1)}' \
    | grep -E '^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$' \
    | grep -vE '^[0-9.]+$' \
    | grep -vxE 'localhost|localhost\.localdomain|local|broadcasthost'
}

# --- category catalog -------------------------------------------------------

enabled_keys() {
  if [ -f "$ENABLED_FILE" ]; then grep -vE '^\s*(#|$)' "$ENABLED_FILE"; else tr ' ' '\n' <<< "$DEFAULT_CATEGORIES"; fi
}
is_enabled() { enabled_keys | grep -qxF "$1"; }
save_enabled() { printf '%s\n' "$@" | grep -v '^$' | sort -u > "$ENABLED_FILE"; }

# Unique source ids for the enabled categories.
enabled_sources() {
  local keys
  keys="$(enabled_keys | paste -sd'|')"
  [ -n "$keys" ] || return 0
  awk -F'|' -v keys="$keys" 'BEGIN{n=split(keys,k,"|"); for(i=1;i<=n;i++) want[k[i]]=1}
    $1=="C" && ($3 in want) && $5!="-" {m=split($5,s," "); for(i=1;i<=m;i++) print s[i]}' "$CATALOG" | sort -u
}
source_url() { awk -F'|' -v id="$1" '$1=="S" && $2==id {print $3}' "$CATALOG"; }

# Download one source into the cache. On failure, or if it shrank by more than
# half (truncated mirror), the previous cached copy is kept.
fetch_source() {
  local id="$1" url="$2" tmp="$3" n old
  if ! curl -fsSL --retry 3 --max-time 180 -o "$tmp/raw" "$url"; then
    log "WARNING: download failed for $id, using cached copy"
  else
    normalise < "$tmp/raw" | sort -u > "$tmp/norm"
    n=$(wc -l < "$tmp/norm")
    old=$( [ -f "$CACHE_DIR/$id" ] && wc -l < "$CACHE_DIR/$id" || echo 0)
    if [ "$n" -eq 0 ] || [ "$n" -lt $((old / 2)) ]; then
      log "WARNING: $id returned $n domains (cached: $old), using cached copy"
    else
      mv "$tmp/norm" "$CACHE_DIR/$id"
    fi
  fi
  [ -f "$CACHE_DIR/$id" ]
}

coredns_pid() { cat "$COREDNS_PIDFILE" 2>/dev/null; }

# CoreDNS only reads the list files at start-up. ubios-udapi-server supervises
# it and respawns it within ~1s, so a plain kill is the reload mechanism.
restart_coredns() {
  local old new i
  old="$(coredns_pid)"
  [ -n "$old" ] && kill -0 "$old" 2>/dev/null || { log "CoreDNS not running, nothing to restart"; return 0; }
  kill "$old"
  for i in $(seq 1 30); do
    sleep 1
    new="$(coredns_pid)"
    if [ -n "$new" ] && [ "$new" != "$old" ] && kill -0 "$new" 2>/dev/null; then
      log "CoreDNS restarted (pid $old -> $new)"
      return 0
    fi
  done
  log "WARNING: CoreDNS did not come back within 30s after restart"
  return 1
}

# Download the sources of the enabled categories (+ LIST_URLS), merge, apply.
cmd_update() {
  local tmp id url n i=0 files=()
  mkdir -p "$CACHE_DIR"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  for id in $(enabled_sources); do
    url="$(source_url "$id")"
    [ -n "$url" ] || { log "WARNING: unknown source $id in catalog"; continue; }
    if fetch_source "$id" "$url" "$tmp"; then files+=("$CACHE_DIR/$id"); else log "ERROR: no copy of $id available, skipping it"; fi
  done
  for url in "${LIST_URLS[@]}"; do
    i=$((i + 1))
    if fetch_source "extra$i" "$url" "$tmp"; then files+=("$CACHE_DIR/extra$i"); fi
  done
  [ -f "$CUSTOM_BLOCK_FILE" ] && normalise < "$CUSTOM_BLOCK_FILE" > "$tmp/custom" && files+=("$tmp/custom")
  [ ${#files[@]} -gt 0 ] || { log "ERROR: nothing selected, enable categories with: $0 menu"; return 1; }
  sort -u "${files[@]}" > "$tmp/merged"
  n=$(wc -l < "$tmp/merged")
  if [ "$n" -lt "$MIN_ENTRIES" ] || [ "$n" -gt "$MAX_ENTRIES" ]; then
    log "ERROR: merged list has $n domains (allowed $MIN_ENTRIES-$MAX_ENTRIES), keeping previous list"
    return 1
  fi
  if [ -f "$MERGED" ] && cmp -s "$tmp/merged" "$MERGED"; then
    if [ "$(sha256sum < "$MERGED")" = "$(cat "$APPLIED" 2>/dev/null)" ]; then
      log "List unchanged ($n domains)"
      return 0
    fi
  else
    mv "$tmp/merged" "$MERGED"
    log "Downloaded new list: $n domains"
  fi
  cmd_apply force
}

# Write UniFi's own entries + sentinel + our list into the CoreDNS block file.
# Runs in a subshell holding the lock, so the lock is always released on return.
cmd_apply() {
  [ -f "$MERGED" ] || { log "No downloaded list yet, run: $0 update"; return 1; }
  [ -d "$(dirname "$TARGET")" ] || { log "$(dirname "$TARGET") missing: content filtering is off for all networks, skipping"; return 0; }
  (
    flock -w 600 9 || { log "ERROR: could not get lock $LOCK"; exit 1; }
    apply_locked "${1:-}"
  ) 9>"$LOCK"
}

apply_locked() {
  local force="$1" tmp
  if [ -f "$TARGET" ] && grep -qxF "$SENTINEL" "$TARGET"; then
    [ "$force" = "force" ] || return 0   # already applied
    # Everything above the sentinel came from UniFi.
    sed "/^${SENTINEL//./\\.}\$/,\$d" "$TARGET" > "$UI_LIST"
  else
    # UniFi (re)generated the file: its whole content is the UI block list.
    cp "$TARGET" "$UI_LIST" 2>/dev/null || : > "$UI_LIST"
  fi

  tmp="$(mktemp "$(dirname "$TARGET")/.domainlist_0.XXXXXX")"
  { cat "$UI_LIST"; echo "$SENTINEL"; cat "$MERGED"; } > "$tmp"
  chmod 644 "$tmp"
  mv "$tmp" "$TARGET"
  log "Applied $(wc -l < "$MERGED") domains (+$(grep -c . "$UI_LIST") from UniFi UI) to $TARGET"
  restart_coredns && sha256sum < "$MERGED" > "$APPLIED"
}

# Re-apply whenever UniFi regenerates the list (reboot, UI settings change).
cmd_watch() {
  log "Watching $TARGET every ${WATCH_INTERVAL}s"
  while :; do
    if [ -f "$TARGET" ] && ! grep -qxF "$SENTINEL" "$TARGET"; then
      log "Block list was regenerated by UniFi, re-applying"
      cmd_apply
    fi
    sleep "$WATCH_INTERVAL"
  done
}

cmd_status() {
  local pid
  pid="$(coredns_pid)"
  echo "Categories      : $(enabled_keys | paste -sd' ')"
  echo "Downloaded list : $( [ -f "$MERGED" ] && echo "$(wc -l < "$MERGED") domains, $(date -r "$MERGED" '+%F %T')" || echo none)"
  if [ -f "$TARGET" ] && grep -qxF "$SENTINEL" "$TARGET"; then
    echo "Applied         : yes ($(wc -l < "$TARGET") lines in $TARGET)"
  else
    echo "Applied         : NO"
  fi
  echo "CoreDNS         : ${pid:-not running}$( [ -n "$pid" ] && echo ", $(($(ps -o rss= -p "$pid") / 1024)) MB RSS")"
  systemctl --no-pager list-timers unifi-blocklist-update.timer 2>/dev/null | sed -n 2p
  systemctl is-active --quiet unifi-blocklist-watch.service && echo "Watcher         : running" || echo "Watcher         : stopped"
}

# Units are copied (not symlinked) into /etc so systemd can read them at early
# boot; /etc/systemd/system survives firmware updates on UniFi OS.
cmd_install() {
  local u
  cmd_check || { echo; echo "Compatibility check failed, not installing. See the hints above."; return 1; }
  chmod +x "$BASE_DIR/blocklist.sh"
  [ -f "$CONF_FILE" ] || cp "$BASE_DIR/blocklist.conf.example" "$CONF_FILE"
  [ -f "$ENABLED_FILE" ] || save_enabled $DEFAULT_CATEGORIES
  for u in unifi-blocklist-watch.service unifi-blocklist-update.service unifi-blocklist-update.timer; do
    sed "s#@BASE_DIR@#${BASE_DIR}#g" "$BASE_DIR/systemd/$u" > "$SYSTEMD_DIR/$u"
  done
  systemctl daemon-reload
  systemctl enable unifi-blocklist-watch.service unifi-blocklist-update.timer
  systemctl restart unifi-blocklist-watch.service
  systemctl start unifi-blocklist-update.timer
  echo
  run_update_detached
  echo
  cmd_status
}

# Read-only compatibility check: does this gateway use the same filtering engine?
cmd_check() {
  local ok=0 conf="${UTM_DIR}/coredns_config.conf" mem
  pass() { printf '  [ OK ] %s\n' "$1"; }
  fail() { printf '  [FAIL] %s\n         %s\n' "$1" "$2"; ok=1; }
  warn() { printf '  [WARN] %s\n         %s\n' "$1" "$2"; }
  echo "Compatibility check"
  [ "$(id -u)" = 0 ] && pass "running as root" || fail "not running as root" "Log in over SSH as root."
  [ -x /usr/bin/ubios-udapi-server ] && pass "UniFi OS gateway ($(cat /usr/lib/version 2>/dev/null || echo unknown version))" \
    || fail "ubios-udapi-server not found" "This does not look like a UniFi OS gateway (UCG/UDM/UDR/UXG)."
  [ -x /usr/bin/coredns ] && pass "UniFi CoreDNS present ($(dpkg-query -W -f='${Version}' coredns 2>/dev/null))" \
    || fail "/usr/bin/coredns not found" "This firmware does not use the CoreDNS-based content filter."
  if [ -f "$conf" ] && grep -q include_domain_files "$conf"; then
    pass "content filter engine running with a custom block list ($conf)"
  else
    fail "content filter engine not running" "In UniFi Network: Settings > CyberSecure > Content Filter, turn on Ad Block for your network(s), wait a minute and run this again."
  fi
  [ -d "$(dirname "$TARGET")" ] && pass "block list directory $(dirname "$TARGET")" \
    || fail "$(dirname "$TARGET") missing" "Turn on Ad Block for at least one network (see above)."
  if ipset list dnsfilter 2>/dev/null | sed -n '/Members/,$p' | grep -q '[0-9]'; then
    pass "filtered networks: $(ipset list dnsfilter | sed -n '/Members/,$p' | tail -n +2 | paste -sd' ')"
  else
    warn "no networks in the filter (ipset dnsfilter is empty)" "Turn on Ad Block for the networks you want covered, otherwise nothing gets filtered."
  fi
  for t in curl flock sha256sum systemctl ipset; do
    command -v "$t" >/dev/null || fail "missing tool: $t" "Unexpected on UniFi OS; please open an issue with your model and firmware."
  done
  touch /data/.unifi-blocklist-test 2>/dev/null && rm -f /data/.unifi-blocklist-test && pass "/data is writable (survives reboots and firmware updates)" \
    || fail "/data not writable" "Unexpected on UniFi OS; please open an issue with your model and firmware."
  mem=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
  [ "$mem" -ge 300 ] && pass "memory available: ${mem} MB" \
    || warn "only ${mem} MB memory available" "Choose fewer/smaller categories, or lower MAX_ENTRIES in blocklist.conf."
  command -v dialog >/dev/null && pass "dialog present (menu available)" || warn "dialog not installed" "The menu won't work; use the categories/enable/disable commands instead."
  echo
  [ $ok = 0 ] && echo "Result: compatible." || echo "Result: NOT compatible (see FAIL lines)."
  return $ok
}

cmd_uninstall() {
  local u
  systemctl disable --now unifi-blocklist-watch.service unifi-blocklist-update.timer 2>/dev/null
  for u in unifi-blocklist-watch.service unifi-blocklist-update.service unifi-blocklist-update.timer; do
    rm -f "$SYSTEMD_DIR/$u"
  done
  systemctl daemon-reload
  # Put back only what UniFi itself had in the block list.
  if [ -f "$TARGET" ] && grep -qxF "$SENTINEL" "$TARGET"; then
    sed "/^${SENTINEL//./\\.}\$/,\$d" "$TARGET" > "$TARGET.tmp" && mv "$TARGET.tmp" "$TARGET"
    restart_coredns
  fi
  log "Uninstalled. Files in $BASE_DIR were left in place."
}

# --- category selection -----------------------------------------------------

cmd_categories() {
  local group="" g key label src mark
  while IFS='|' read -r _ g key label src; do
    [ "$g" != "$group" ] && { group="$g"; printf '\n%s\n' "$group"; }
    if [ "$src" = "-" ]; then mark="  n/a"; elif is_enabled "$key"; then mark="[ON] "; else mark="[  ] "; fi
    printf '  %s %-28s %s\n' "$mark" "$key" "$label"
  done < <(grep '^C|' "$CATALOG")
  echo; echo "n/a = no free list available for this category yet"
}

cmd_toggle() {
  local action="$1" key keys
  shift
  keys="$(enabled_keys)"
  for key in "$@"; do
    key="${key^^}"
    grep -q "^C|[^|]*|${key}|" "$CATALOG" || { echo "Unknown category: $key"; return 1; }
    grep -q "^C|[^|]*|${key}|[^|]*|-$" "$CATALOG" && { echo "$key has no free list (n/a)"; return 1; }
    if [ "$action" = enable ]; then keys="$keys"$'\n'"$key"; else keys="$(grep -vxF "$key" <<< "$keys")"; fi
  done
  # shellcheck disable=SC2086
  save_enabled $keys
  echo "Saved. Run '$0 update' to download and apply."
}

# Run the update under systemd so closing the SSH session can't interrupt it.
run_update_detached() {
  local since
  if systemctl cat unifi-blocklist-update.service >/dev/null 2>&1; then
    since="$(date '+%F %T')"
    echo "Updating (runs in the background service; safe to disconnect)..."
    systemctl start unifi-blocklist-update.service
    journalctl -u unifi-blocklist-update.service --since "$since" -o cat --no-pager | grep -v '^20'
  else
    cmd_update
  fi
}

# Text UI (dialog): one checklist per UniFi category group.
cmd_menu() {
  command -v dialog >/dev/null || { echo "dialog not installed, use: $0 categories / enable / disable"; return 1; }
  local groups=() sel choice g i items na picked current dirty=0 keys
  mapfile -t groups < <(awk -F'|' '$1=="C" && !seen[$2]++ {print $2}' "$CATALOG")
  keys="$(enabled_keys)"

  while :; do
    local menu=()
    for i in "${!groups[@]}"; do
      g="${groups[$i]}"
      local total on
      total=$(awk -F'|' -v g="$g" '$1=="C" && $2==g && $5!="-"' "$CATALOG" | wc -l)
      on=$(awk -F'|' -v g="$g" '$1=="C" && $2==g {print $3}' "$CATALOG" | grep -cxF -f <(echo "$keys") || true)
      menu+=("$((i + 1))" "$(printf '%-34s %2s/%-2s on' "$g" "$on" "$total")")
    done
    menu+=("" "" "A" "Apply now (download lists + reload)" "S" "Status" "Q" "Quit$( [ $dirty = 1 ] && echo ' (unsaved changes)')")

    choice=$(dialog --clear --title "unifi-blocklist" --cancel-label "Quit" \
      --menu "UniFi content filter categories backed by free lists.\nChanges are saved when you leave a group; Apply downloads and reloads." \
      25 72 17 "${menu[@]}" 3>&1 1>&2 2>&3) || choice=Q

    case "$choice" in
      "") continue ;;
      A)
        save_enabled $keys; dirty=0; clear
        run_update_detached; echo; read -rp "Press Enter to return to the menu" _ ;;
      S)
        dialog --title "Status" --msgbox "$(cmd_status 2>&1)\n\nEnabled: $(echo $keys)" 20 76 ;;
      Q)
        if [ $dirty = 1 ] && dialog --yesno "Apply the changed categories now?\n(downloads lists and reloads CoreDNS, ~1-10 s DNS blip)" 8 60; then
          save_enabled $keys; clear; run_update_detached
        else
          clear
          [ $dirty = 1 ] && save_enabled $keys && echo "Saved, will be applied on the next scheduled update (or run: $0 update)"
        fi
        return 0 ;;
      *)
        g="${groups[$((choice - 1))]}"
        items=(); na=""
        while IFS='|' read -r _ _ key label src; do
          if [ "$src" = "-" ]; then na="${na}${label}, "; continue; fi
          grep -qxF "$key" <<< "$keys" && current=on || current=off
          items+=("$key" "$label" "$current")
        done < <(awk -F'|' -v g="$g" '$1=="C" && $2==g' "$CATALOG")
        picked=$(dialog --title "$g" --no-tags --separate-output --checklist \
          "Space = toggle, Enter = OK.${na:+\n\nNo free list (not shown): ${na%, }}" 24 76 14 "${items[@]}" 3>&1 1>&2 2>&3) || continue
        # Replace this group's keys with the picked ones.
        for ((i = 0; i < ${#items[@]}; i += 3)); do keys="$(grep -vxF "${items[$i]}" <<< "$keys")"; done
        keys="$(printf '%s\n%s\n' "$keys" "$picked" | grep -v '^$' | sort -u)"
        dirty=1 ;;
    esac
  done
}

case "${1:-}" in
  menu)       cmd_menu ;;
  categories) cmd_categories ;;
  enable)     shift; cmd_toggle enable "$@" ;;
  disable)    shift; cmd_toggle disable "$@" ;;
  install)    cmd_install ;;
  uninstall)  cmd_uninstall ;;
  update)     cmd_update ;;
  apply)      cmd_apply force ;;
  watch)      cmd_watch ;;
  status)     cmd_status ;;
  check)      cmd_check ;;
  *) echo "Usage: $0 {menu|categories|enable KEY..|disable KEY..|update|apply|status|check|install|uninstall|watch}"; exit 1 ;;
esac
