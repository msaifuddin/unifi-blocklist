#!/bin/bash
#
# unifi-blocklist: feed HaGeZi / OISD (or any domain list) into UniFi's own
# content-filtering engine (CoreDNS "hostSet" plugin) on UniFi OS gateways.
#
# Blocks are performed and logged by UniFi itself, so they still show up in the
# UniFi UI, and the UI allow list keeps working (it is evaluated first).
#
# Usage: blocklist.sh help

set -uo pipefail

VERSION="1.3.0"
REPO="msaifuddin/unifi-blocklist"

BASE_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
CONF_FILE="${BASE_DIR}/blocklist.conf"
CATALOG="${BASE_DIR}/categories.list"         # category -> list mapping (shipped)
ENABLED_FILE="${BASE_DIR}/categories.enabled" # selected category keys (yours)
DEFAULT_CATEGORIES="ADS_PRO BOTNETS MALWARE PHISHING"
EXCLUSIVE_GROUP="Ad Block (HaGeZi)"  # its levels include each other, so only one can be on

# Defaults (override in blocklist.conf)
LIST_URLS=()               # extra list URLs on top of the selected categories
MIN_ENTRIES=1000           # refuse to apply a merged list smaller than this
MAX_ENTRIES=1300000        # refuse to apply lists larger than this in total (CoreDNS memory limit)
WATCH_INTERVAL=15          # seconds between checks that our list is still in place
RESTART_TIMEOUT=120        # seconds to wait for CoreDNS to load the list and answer again
UPDATE_CHECK=1             # 1 = look for a newer release during the scheduled update (notify only)
CUSTOM_BLOCK_FILE="${BASE_DIR}/custom-block.list"   # optional extra domains, one per line
REPLACE_UNIFI_ADBLOCK=1    # 1 = the selected Ad Block level replaces UniFi's own Ad Block list
BLOCK_PAGE=1               # 1 = UniFi's block page shows which category and list blocked the site

# shellcheck source=/dev/null
[ -f "$CONF_FILE" ] && . "$CONF_FILE"

UTM_DIR="/run/utm"
TARGET="${UTM_DIR}/domain_list/domainlist_0.list"   # "include" = block list
ALLOW_LIST="${UTM_DIR}/domain_list/domainlist_1.list" # UniFi UI allow list (checked first)
COREDNS_PIDFILE="${UTM_DIR}/coredns.pid"
COREDNS_CONF="${UTM_DIR}/coredns_config.conf"
STATE_DIR="${BASE_DIR}/state"
CACHE_DIR="${STATE_DIR}/sources"       # last good normalised copy of each source
MERGED="${STATE_DIR}/merged.list"      # last good merged list
UI_LIST="${STATE_DIR}/ui-block.list"   # domains UniFi itself put in the block list
APPLIED="${STATE_DIR}/applied.sha256"  # checksum of the list CoreDNS was last verified with
PREVIOUS="${STATE_DIR}/target.prev"    # block file as it was before the last apply (rollback)
LATEST="${STATE_DIR}/latest-version"   # newest release seen on GitHub
ADS="${STATE_DIR}/ads.list"            # last good Ad Block list, when it replaces UniFi's
ADS_DIR="${STATE_DIR}/unifi-adblock"   # replacement for UNIFI_LIST_DIR (mounted read-only)
ADS_PREV="${STATE_DIR}/unifi-adblock.prev"  # replacement as it was before the last apply (rollback)
UNIFI_OTHER="${STATE_DIR}/unifi-other-rows.csv"  # UniFi's rows for other categories, kept as they are
UPDATER_BLOCK_DIR="${STATE_DIR}/updater-tmp"    # empty, mounted read-only over UNIFI_UPDATER_TMP
ADS_MOUNTED="${STATE_DIR}/unifi-adblock.mounted" # exists while we have UniFi's Ad Block list replaced
UNIFI_LIST_DIR="/etc/utm/pre_categorized_list"            # UniFi's Ad Block list (CSV)
UNIFI_UPDATER_TMP="/usr/share/ubios-udapi-server/utm/tmp"   # where UniFi's updater unpacks new lists
CGROUP="/sys/fs/cgroup/utm_content_filtering_service"     # CoreDNS's memory-limited cgroup
MERGED_SOURCES="${STATE_DIR}/merged.sources"   # lists in the block list, one id (or id|url) per line
BLOCKPAGE_SRC="${BASE_DIR}/blockpage.html"     # the block page (shipped)
BLOCKPAGE_DIR="${STATE_DIR}/blockpage"         # page + index, mounted read-only over LIGHTTPD_WWW
BP_SUM="${STATE_DIR}/blockpage.sha256"         # inputs the index was last built from
BP_MOUNTED="${STATE_DIR}/blockpage.mounted"    # exists while our block page is mounted
LIGHTTPD_WWW="/usr/share/lighttpd/www"         # UniFi's block page (served for 203.0.113.250)
LOCK="/run/unifi-blocklist.lock"
SYSTEMD_DIR="/etc/systemd/system"
# Marks the boundary between UniFi's own entries and ours. ".invalid" is a
# reserved TLD (RFC 2606) so blocking it is harmless.
SENTINEL="unifi-blocklist-sentinel.invalid"
AD_SENTINEL="unifi-blocklist-adblock.invalid"   # always in our Ad Block list, answered with 0.0.0.0

log() { logger -t unifi-blocklist -- "$*"; echo "$(date '+%F %T') $*"; }

# --- releases ---------------------------------------------------------------

# Tag of the newest GitHub release (e.g. v1.1.0). Uses the API without a token
# (60 requests per hour per address; this runs twice a day).
latest_release() {
  local json tag
  # Read the whole response first: grep -m1 on the pipe can cut curl off ("Failed writing body").
  json="$(curl -fsS --max-time 20 -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/${REPO}/releases/latest")" || return 1
  tag="$(grep -o -m1 '"tag_name": *"[^"]*"' <<< "$json" | sed -E 's/.*"([^"]*)"$/\1/')"
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  echo "$tag"
}

# True if version $1 is newer than $2.
version_gt() { [ "$1" != "$2" ] && [ "$(printf '%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]; }

# Notify only: never installs anything and never affects the list update.
check_for_update() {
  local tag
  [ "$UPDATE_CHECK" = 1 ] || return 0
  tag="$(latest_release)" || return 0
  echo "${tag#v}" > "$LATEST"
  version_gt "${tag#v}" "$VERSION" && log "Update available: ${tag#v} (installed: $VERSION), run: $0 upgrade"
  return 0
}

# One-line notice if a newer release was seen, empty otherwise.
update_notice() {
  local latest
  latest="$(cat "$LATEST" 2>/dev/null)"
  [ -n "$latest" ] && version_gt "$latest" "$VERSION" && echo "update available: $latest, run: blocklist.sh upgrade"
}

# Reinstall from the newest release; the installer keeps settings and state.
cmd_upgrade() {
  local tag
  tag="$(latest_release)" || { echo "Could not find the latest release on GitHub."; return 1; }
  echo "Installed: $VERSION, latest release: ${tag#v}"
  if ! version_gt "${tag#v}" "$VERSION" && [ "${1:-}" != "--force" ]; then
    echo "Already up to date (use 'upgrade --force' to reinstall)."
    return 0
  fi
  curl -fsSL "https://raw.githubusercontent.com/${REPO}/${tag}/install.sh" | TAG="$tag" bash
}

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

# Unique source ids for the enabled categories: all of them, or only the Ad Block
# level ("ads") or only the other categories ("other").
enabled_sources() {
  local keys
  keys="$(enabled_keys | paste -sd'|')"
  [ -n "$keys" ] || return 0
  awk -F'|' -v keys="$keys" -v part="${1:-all}" -v ads="$EXCLUSIVE_GROUP" 'BEGIN{n=split(keys,k,"|"); for(i=1;i<=n;i++) want[k[i]]=1}
    $1=="C" && ($3 in want) && $5!="-" && (part=="all" || (part=="ads") == ($2==ads)) {m=split($5,s," "); for(i=1;i<=m;i++) print s[i]}' "$CATALOG" | sort -u
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

# CoreDNS writes its pidfile only after it has loaded the lists, so look the
# process up by name while it is still loading.
coredns_pid() { cat "$COREDNS_PIDFILE" 2>/dev/null || pidof -s coredns; }

# CoreDNS only sends a query through the block list when it comes from a
# filtered LAN range, so health checks use the gateway's address in that range.
filter_source_ip() {
  awk '$1=="rule" && /hostSet/ {for (i = 1; i < NF; i++) if ($i=="sourceCidrs") {split($(i+1), a, ","); sub(/\/.*/, "", a[1]); print a[1]; exit}}' "$COREDNS_CONF" 2>/dev/null
}
block_address() { awk '$1=="block_address_v4" {print $2; exit}' "$COREDNS_CONF" 2>/dev/null; }

# Ask the filtering CoreDNS for a name (default: the sentinel, which is always
# in our block file).
filter_query() {
  dig +short +time=2 +tries=1 -b "$1" @127.0.0.1 -p 1053 "${2:-$SENTINEL}" A 2>/dev/null
}

# The filter blocks with the new lists: the block list sentinel gets the block page
# address and, while our Ad Block list is mounted, its sentinel gets 0.0.0.0.
filter_ok() {
  [ "$(filter_query "$1")" = "$2" ] || return 1
  mountpoint -q "$UNIFI_LIST_DIR" || return 0
  [ "$(filter_query "$1" "$AD_SENTINEL")" = 0.0.0.0 ]
}

# CoreDNS only reads the list files at start-up. ubios-udapi-server supervises
# it and respawns it within ~1s, so a plain kill is the reload mechanism (its
# SIGUSR1 reload also starts a new process). CoreDNS answers nothing while it
# loads the list, about 10s for 900k domains.
# With "verify", success means CoreDNS blocks the sentinel and still does 5s later.
# Returns 0 on success, 1 on failure, 2 if CoreDNS isn't running.
restart_coredns() {
  local verify="${1:-}" old new t src="" want=""
  old="$(coredns_pid)"
  [ -n "$old" ] && kill -0 "$old" 2>/dev/null || { log "CoreDNS not running, it will load the list when it starts"; return 2; }
  if [ "$verify" = verify ]; then
    src="$(filter_source_ip)"; want="$(block_address)"
    # Only rely on the query if it works against the running CoreDNS.
    if [ -z "$src" ] || [ -z "$want" ] || ! command -v dig >/dev/null || ! ip -o addr show | grep -qF " inet $src/" || ! filter_query "$src" >/dev/null; then
      log "WARNING: can't query the filter directly, only checking that CoreDNS restarts"
      src=""
    fi
  fi
  kill "$old"
  for ((t = 0; t < RESTART_TIMEOUT; t++)); do
    sleep 1
    new="$(coredns_pid)"
    [ -n "$new" ] && [ "$new" != "$old" ] && kill -0 "$new" 2>/dev/null || continue
    [ -z "$src" ] || filter_ok "$src" "$want" || continue
    [ "$verify" = verify ] || { log "CoreDNS restarted (pid $old -> $new)"; return 0; }
    sleep 5; t=$((t + 5))
    if [ "$(coredns_pid)" = "$new" ] && kill -0 "$new" 2>/dev/null && { [ -z "$src" ] || filter_ok "$src" "$want"; }; then
      log "CoreDNS restarted (pid $old -> $new)${src:+ and is blocking from the new list}"
      return 0
    fi
  done
  log "ERROR: CoreDNS did not come back${src:+ with the new list} within ${RESTART_TIMEOUT}s"
  return 1
}

# Run a function while holding the lock that serialises changes to the block file.
with_lock() {
  (
    flock -w 600 9 || { log "ERROR: could not get lock $LOCK"; exit 1; }
    "$@"
  ) 9>"$LOCK"
}

# Download the sources of the enabled categories (+ LIST_URLS), merge, apply.
cmd_update() {
  local tmp id url ad_ids="" lists=0 files=() ad_files=() srcs=()
  mkdir -p "$CACHE_DIR"
  check_for_update
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  # The Ad Block level goes into UniFi's Ad Block list instead of the block list.
  replacing_adblock && ad_ids=" $(enabled_sources ads | paste -sd' ') "
  for id in $(enabled_sources); do
    url="$(source_url "$id")"
    [ -n "$url" ] || { log "WARNING: unknown source $id in catalog"; continue; }
    lists=$((lists + 1))
    if ! fetch_source "$id" "$url" "$tmp"; then
      log "ERROR: no copy of $id available, skipping it"
    elif [[ "$ad_ids" == *" $id "* ]]; then
      ad_files+=("$CACHE_DIR/$id")
    else
      files+=("$CACHE_DIR/$id"); srcs+=("$id")
    fi
  done
  for url in "${LIST_URLS[@]}"; do
    # Cache by URL, so reordering or replacing URLs never mixes up their copies.
    id="extra-$(printf '%s' "$url" | sha256sum | cut -c1-12)"
    lists=$((lists + 1))
    if fetch_source "$id" "$url" "$tmp"; then files+=("$CACHE_DIR/$id"); srcs+=("$id|$url"); else log "ERROR: no copy of $url available, skipping it"; fi
  done
  if [ "$lists" -gt 0 ] && [ $((${#files[@]} + ${#ad_files[@]})) -eq 0 ]; then
    log "ERROR: none of the selected lists could be downloaded, keeping previous list"
    return 1
  fi
  [ -f "$CUSTOM_BLOCK_FILE" ] && normalise < "$CUSTOM_BLOCK_FILE" > "$tmp/custom" && files+=("$tmp/custom") && srcs+=("custom")
  with_lock merge_and_apply
}

# Second half of cmd_update, under the lock: uses its tmp, lists, files, ad_files and srcs.
merge_and_apply() {
  local n n_ads
  if [ ${#files[@]} -gt 0 ]; then sort -u "${files[@]}" > "$tmp/merged"; else : > "$tmp/merged"; fi
  if [ ${#ad_files[@]} -gt 0 ]; then sort -u "${ad_files[@]}" > "$tmp/ads"; else : > "$tmp/ads"; fi
  n=$(wc -l < "$tmp/merged"); n_ads=$(wc -l < "$tmp/ads")
  # The lower bound guards against truncated downloads; custom domains alone can be any size.
  if { [ "$lists" -gt 0 ] && [ $((n + n_ads)) -lt "$MIN_ENTRIES" ]; } || [ $((n + n_ads)) -gt "$MAX_ENTRIES" ]; then
    log "ERROR: lists have $((n + n_ads)) domains in total (allowed $MIN_ENTRIES-$MAX_ENTRIES), keeping previous list"
    return 1
  fi
  [ $((n + n_ads)) -eq 0 ] && log "Nothing selected: only UniFi's own block list entries will be active"
  printf '%s\n' "${srcs[@]}" | grep . > "$MERGED_SOURCES"
  if [ -f "$MERGED" ] && cmp -s "$tmp/merged" "$MERGED" && cmp -s "$tmp/ads" "$ADS"; then
    if [ "$(list_sum)" = "$(cat "$APPLIED" 2>/dev/null)" ]; then
      log "List unchanged ($n domains + $n_ads Ad Block)"
      build_blockpage
      return 0
    fi
  else
    mv "$tmp/merged" "$MERGED" && mv "$tmp/ads" "$ADS" || { log "ERROR: could not write $MERGED / $ADS"; return 1; }
    log "Downloaded new list: $n domains + $n_ads Ad Block"
  fi
  apply_now force
}

# Write UniFi's own entries + sentinel + our list into the CoreDNS block file.
cmd_apply() { with_lock apply_now "${1:-}"; }

# Checksum of the lists as applied, so status can tell whether CoreDNS has them.
list_sum() { { cat "$MERGED"; echo "--- ads"; cat "$ADS"; } 2>/dev/null | sha256sum; }

# Callers hold the lock.
apply_now() {
  [ -f "$MERGED" ] || { log "No downloaded list yet, run: $0 update"; return 1; }
  [ -d "$(dirname "$TARGET")" ] || { log "$(dirname "$TARGET") missing: content filtering is off for all networks, skipping"; return 0; }
  apply_locked "${1:-}"
}

apply_locked() {
  local force="$1" tmp err
  if [ -f "$TARGET" ] && grep -qxF "$SENTINEL" "$TARGET"; then
    [ "$force" = "force" ] || return 0   # already applied
    # Everything above the sentinel came from UniFi.
    sed "/^${SENTINEL//./\\.}\$/,\$d" "$TARGET" > "$UI_LIST"
  else
    # UniFi (re)generated the file: its whole content is the UI block list.
    cp "$TARGET" "$UI_LIST" 2>/dev/null || : > "$UI_LIST"
  fi

  # Keep the file CoreDNS is running with, to roll back to.
  # Write failures return 3: CoreDNS wasn't touched, so retrying soon is harmless.
  if [ -f "$TARGET" ]; then
    err="$(cp "$TARGET" "$PREVIOUS" 2>&1)" || { log "ERROR: could not back up $TARGET (${err:-unknown error})"; return 3; }
  else
    rm -f "$PREVIOUS"
  fi
  tmp="$(mktemp "$(dirname "$TARGET")/.domainlist_0.XXXXXX" 2>&1)" || { log "ERROR: could not create a file in $(dirname "$TARGET") ($tmp)"; return 3; }
  if ! err="$( { { cat "$UI_LIST" && echo "$SENTINEL" && cat "$MERGED"; } > "$tmp" && chmod 644 "$tmp" && mv "$tmp" "$TARGET"; } 2>&1 )"; then
    rm -f "$tmp"; log "ERROR: could not write $TARGET (${err:-unknown error}), previous list left in place"; return 3
  fi
  log "Applied $(wc -l < "$MERGED") domains (+$(grep -c . "$UI_LIST") from UniFi UI) to $TARGET"
  if replacing_adblock; then
    load_unifi_adblock || { rollback_files; return 3; }
  else
    release_unifi_adblock
  fi
  restart_coredns verify
  case $? in
    0) list_sum > "$APPLIED"; memory_note; build_blockpage ;;
    2) build_blockpage; return 0 ;;
    *) rollback; return 1 ;;
  esac
}

# Put back the files CoreDNS was running with before the failed apply.
rollback() {
  log "Restoring the previous block list"
  rollback_files || return 1
  restart_coredns
}

rollback_files() {
  local tmp
  tmp="$(mktemp "$(dirname "$TARGET")/.domainlist_0.XXXXXX")" || return 1
  if [ -f "$PREVIOUS" ]; then cp "$PREVIOUS" "$tmp"; else cp "$UI_LIST" "$tmp"; fi
  chmod 644 "$tmp" && mv "$tmp" "$TARGET" || { rm -f "$tmp"; log "ERROR: could not restore $TARGET"; return 1; }
  # No earlier replacement to go back to: give UniFi its own Ad Block list back.
  if [ -f "$ADS_PREV" ]; then cp "$ADS_PREV" "$ADS_DIR/content_filtering_list_01.csv"; else release_unifi_adblock; fi
  return 0
}

# --- UniFi's Ad Block list ----------------------------------------------------
#
# UniFi's free Ad Block uses a list of ad hostnames that CoreDNS reads from
# UNIFI_LIST_DIR at start-up and that UniFi's updater replaces from the cloud,
# followed by an in-place reload that can exceed CoreDNS's memory limit. We put a
# CSV in the same format, built from the selected Ad Block level, read-only over
# that directory, and an empty read-only directory over the updater's unpack
# directory so its updates stop before they install or reload anything. UniFi's
# own files stay untouched underneath; unmounting restores them.

replacing_adblock() { [ "${REPLACE_UNIFI_ADBLOCK:-0}" = 1 ] && [ -d "$UNIFI_LIST_DIR" ] && [ -d "$UNIFI_UPDATER_TMP" ]; }
adblock_mounted() { mountpoint -q "$UNIFI_LIST_DIR" && mountpoint -q "$UNIFI_UPDATER_TMP"; }

ro_mount() {
  mountpoint -q "$2" && return 0
  mount --bind "$1" "$2" && mount -o remount,ro,bind "$2" && return 0
  umount "$2" 2>/dev/null
  log "ERROR: could not mount $1 read-only on $2"
  return 1
}

# Write the replacement list and mount it. Returns 1 without touching CoreDNS on failure.
load_unifi_adblock() {
  local tmp csv="$ADS_DIR/content_filtering_list_01.csv"
  mkdir -p "$ADS_DIR" "$UPDATER_BLOCK_DIR" || return 1
  # Keep UniFi's rows for other categories (they only apply with a subscription).
  if ! mountpoint -q "$UNIFI_LIST_DIR" || ! [ -f "$UNIFI_OTHER" ]; then
    { cat "$UNIFI_LIST_DIR"/content_filtering_list_*.csv 2>/dev/null | tr -d '\r' \
        | awk -F, 'NF == 3 && $1 != "category" && $1 != "ADVERTISEMENT"' > "$UNIFI_OTHER.tmp" && mv "$UNIFI_OTHER.tmp" "$UNIFI_OTHER"; } \
      || { log "ERROR: could not read UniFi's Ad Block list in $UNIFI_LIST_DIR"; return 1; }
  fi
  rm -f "$ADS_PREV"; [ -f "$csv" ] && cp "$csv" "$ADS_PREV"
  # domain_zone rows also cover subdomains, like the block list (UniFi's own rows are exact names).
  tmp="$(mktemp "$ADS_DIR/.list.XXXXXX")" || return 1
  if ! { echo "category,host,type"; cat "$UNIFI_OTHER"; echo "ADVERTISEMENT,$AD_SENTINEL,domain_zone"
         awk '{print "ADVERTISEMENT," $1 ",domain_zone"}' "$ADS" 2>/dev/null; } | sed 's/$/\r/' > "$tmp" \
     || ! chmod 644 "$tmp" || ! mv "$tmp" "$csv"; then
    rm -f "$tmp"; log "ERROR: could not write $csv"; return 1
  fi
  ro_mount "$ADS_DIR" "$UNIFI_LIST_DIR" && ro_mount "$UPDATER_BLOCK_DIR" "$UNIFI_UPDATER_TMP" || return 1
  touch "$ADS_MOUNTED"
  log "Ad Block: $(wc -l < "$ADS" 2>/dev/null || echo 0) domains replace UniFi's own list"
}

# Give UniFi its own Ad Block list and updater back. CoreDNS picks the list up at its next start.
release_unifi_adblock() {
  if mountpoint -q "$UNIFI_LIST_DIR"; then
    umount "$UNIFI_LIST_DIR" && log "UniFi's own Ad Block list is back" || log "ERROR: could not unmount $UNIFI_LIST_DIR"
  fi
  if mountpoint -q "$UNIFI_UPDATER_TMP"; then
    umount "$UNIFI_UPDATER_TMP" && log "UniFi's Ad Block list updates are back" || log "ERROR: could not unmount $UNIFI_UPDATER_TMP"
  fi
  rm -f "$ADS_MOUNTED"
  return 0
}

# CoreDNS runs in a memory-limited cgroup and is killed (then restarted by UniFi) when it hits the limit.
coredns_memory() {
  local cur max
  cur="$(cat "$CGROUP/memory.current" 2>/dev/null)"; max="$(cat "$CGROUP/memory.max" 2>/dev/null)"
  [[ "$cur" =~ ^[0-9]+$ && "$max" =~ ^[0-9]+$ ]] && echo "$((cur >> 20)) $((max >> 20))"
}
memory_note() {
  local cur max
  read -r cur max <<< "$(coredns_memory)"
  [ -n "${max:-}" ] && [ $((cur * 100 / max)) -ge 85 ] \
    && log "WARNING: CoreDNS uses $cur of its $max MB memory limit. Choose fewer or smaller categories."
  return 0
}

# --- block page -----------------------------------------------------------------
#
# Names on the block list are answered with 203.0.113.250, where UniFi's lighttpd
# serves a generic page from LIGHTTPD_WWW (for HTTPS with a certificate made for the
# visited name, signed by UniFi's own CA). We mount our page there read-only, with
# an index of the block list split into BP_SHARDS files by a hash of the domain.
# The page hashes the visited name and its parents the same way, fetches those few
# files from the same address and shows the category and list that matched.

BP_SHARDS=1024
BP_CHARS="abcdefghijklmnopqrstuvwxyz0123456789-._"

blockpage_wanted() { [ "${BLOCK_PAGE:-0}" = 1 ] && [ -d "$LIGHTTPD_WWW" ] && [ -f "$BLOCKPAGE_SRC" ]; }

# List names and the enabled categories behind them, as JSON for the page.
blockpage_meta() {
  local keys
  keys="$(enabled_keys | paste -sd'|')"
  awk -F'|' -v keys="$keys" -v ads="$EXCLUSIVE_GROUP" -v updated="$(date -r "$MERGED" '+%F %H:%M')" \
      -v shards="$BP_SHARDS" -v chars="$BP_CHARS" -v custom="$(basename "$CUSTOM_BLOCK_FILE")" '
    function js(v) { gsub(/\\/, "\\\\", v); gsub(/"/, "\\\"", v); return "\"" v "\"" }
    BEGIN { n = split(keys, k, "|"); for (i = 1; i <= n; i++) want[k[i]] = 1 }
    FILENAME != ARGV[1] { if ($2 != "") extra[++ne] = $1 "|" $2; next }
    $1 == "S" { name[$2] = $4; order[++ns] = $2 }
    $1 == "C" && ($3 in want) && $5 != "-" {
      label = $4; sub(/ \([^)]*\)$/, "", label); group = $2
      if (group == ads) { label = "Ads and tracking"; group = "Ad Block" }
      m = split($5, s, " ")
      obj = "{\"name\":" js(label) ",\"group\":" js(group) "}"
      # Test first: mawk creates cats[x] on the left of an assignment before evaluating the right.
      for (i = 1; i <= m; i++) if (s[i] in cats) cats[s[i]] = cats[s[i]] "," obj; else cats[s[i]] = obj
    }
    END {
      printf "{\"updated\":%s,\"shards\":%d,\"chars\":%s,\"sources\":{", js(updated), shards, js(chars)
      printf "\"ui\":{\"name\":\"UniFi block list\",\"categories\":[]},\"custom\":{\"name\":%s,\"categories\":[]}", js(custom)
      for (i = 1; i <= ns; i++) if (order[i] in cats) printf ",%s:{\"name\":%s,\"categories\":[%s]}", js(order[i]), js(name[order[i]]), cats[order[i]]
      for (i = 1; i <= ne; i++) { split(extra[i], e, "|"); printf ",%s:{\"name\":%s,\"categories\":[]}", js(e[1]), js(e[2]) }
      print "}}"
    }' "$CATALOG" "$MERGED_SOURCES"
}

# (Re)build the index when the block list changed, then make sure the page is mounted.
# Callers hold the lock. Failures are logged; blocking is never affected.
build_blockpage() {
  local tmp sum tab=$'\t'
  blockpage_wanted || { release_blockpage; return 0; }
  [ -f "$MERGED" ] && [ -f "$MERGED_SOURCES" ] || return 0
  sum="$({ cat "$BASE_DIR/blocklist.sh" "$CATALOG" "$MERGED_SOURCES" "$UI_LIST" "$ENABLED_FILE" "$BLOCKPAGE_SRC"; sha256sum < "$MERGED"
           [ -f "$CUSTOM_BLOCK_FILE" ] && cat "$CUSTOM_BLOCK_FILE"; } 2>/dev/null | sha256sum)"
  if [ "$sum" != "$(cat "$BP_SUM" 2>/dev/null)" ] || ! [ -f "$BLOCKPAGE_DIR/__ub/meta.json" ]; then
    tmp="$(mktemp -d "$STATE_DIR/.blockpage.XXXXXX")" || { log "ERROR: could not build the block page"; return 1; }
    mkdir -p "$tmp/__ub/i" "$BLOCKPAGE_DIR"
    # "domain<TAB>id,id" for every block list entry, then one file per hash bucket.
    {
      while IFS='|' read -r id _; do
        case "$id" in
          custom) [ -f "$CUSTOM_BLOCK_FILE" ] && normalise < "$CUSTOM_BLOCK_FILE" | awk '{print $1 "\tcustom"}' ;;
          *) [ -f "$CACHE_DIR/$id" ] && awk -v id="$id" '{print $1 "\t" id}' "$CACHE_DIR/$id" ;;
        esac
      done < "$MERGED_SOURCES"
      [ -f "$UI_LIST" ] && awk 'NF {print tolower($1) "\tui"}' "$UI_LIST"
    } | LC_ALL=C sort -u \
      | awk -F'\t' '$1 == p {ids = ids "," $2; next} {if (p != "") print p "\t" ids; p = $1; ids = $2} END {if (p != "") print p "\t" ids}' \
      | awk -F'\t' -v C="$BP_CHARS" -v N="$BP_SHARDS" \
          '{h = 0; n = length($1); for (i = 1; i <= n; i++) h = (h * 31 + index(C, substr($1, i, 1))) % N; print h "\t" $0}' \
      | LC_ALL=C sort -t "$tab" -k1,1n -s \
      | awk -F'\t' -v d="$tmp/__ub/i" '{if (!started || $1 != b) {if (started) close(f); f = d "/" $1; b = $1; started = 1} print $2 "\t" $3 > f}'
    if ! blockpage_meta > "$tmp/__ub/meta.json" || ! cp "$BLOCKPAGE_SRC" "$tmp/index.html"; then
      rm -rf "$tmp"; log "ERROR: could not build the block page"; return 1
    fi
    # Swap in place: the mount refers to BLOCKPAGE_DIR itself, so replace what's inside it.
    chmod -R u=rwX,go=rX "$tmp"
    rm -rf "$BLOCKPAGE_DIR/__ub.old"
    [ -d "$BLOCKPAGE_DIR/__ub" ] && mv "$BLOCKPAGE_DIR/__ub" "$BLOCKPAGE_DIR/__ub.old"
    mv "$tmp/__ub" "$BLOCKPAGE_DIR/__ub" && mv "$tmp/index.html" "$BLOCKPAGE_DIR/index.html"
    chmod 755 "$BLOCKPAGE_DIR"
    rm -rf "$BLOCKPAGE_DIR/__ub.old" "$tmp"
    echo "$sum" > "$BP_SUM"
    log "Block page: index of $(cat "$BLOCKPAGE_DIR"/__ub/i/* 2>/dev/null | wc -l) domains"
  fi
  if ! mountpoint -q "$LIGHTTPD_WWW"; then
    ro_mount "$BLOCKPAGE_DIR" "$LIGHTTPD_WWW" || return 1
    log "Block page: shows why a site is blocked"
  fi
  touch "$BP_MOUNTED"
}

# Give UniFi its own block page back.
release_blockpage() {
  # lighttpd may have a file open for a moment; a lazy unmount then detaches it once it's done.
  if mountpoint -q "$LIGHTTPD_WWW"; then
    { umount "$LIGHTTPD_WWW" 2>/dev/null || umount -l "$LIGHTTPD_WWW"; } && log "UniFi's own block page is back" || log "ERROR: could not unmount $LIGHTTPD_WWW"
  fi
  rm -f "$BP_MOUNTED"
  return 0
}

# Re-apply whenever UniFi regenerates the list (reboot, UI settings change).
# After a failed restart, wait 1, 2, 4 ... 60 minutes before trying again, since
# every attempt pauses DNS. A failed write is retried at the normal interval.
cmd_watch() {
  local fails=0 wait rc
  log "Watching $TARGET every ${WATCH_INTERVAL}s"
  while :; do
    # Pick up changes to blocklist.conf without restarting the watcher.
    # shellcheck source=/dev/null
    [ -f "$CONF_FILE" ] && . "$CONF_FILE"
    rc=""
    if [ -f "$TARGET" ] && ! grep -qxF "$SENTINEL" "$TARGET"; then
      log "Block list was regenerated by UniFi, re-applying"
      cmd_apply; rc=$?
    elif [ -f "$TARGET" ] && [ -f "$ADS_MOUNTED" ] && replacing_adblock && ! adblock_mounted; then
      # Only mounts we had in place; turning the setting on or off is for 'update'.
      log "UniFi's Ad Block list isn't replaced any more (it was unmounted), re-applying"
      cmd_apply force; rc=$?
    fi
    # The block page doesn't need CoreDNS: just mount it again (after a reboot, for example).
    if [ -z "$rc" ] && [ -f "$BP_MOUNTED" ] && blockpage_wanted && ! mountpoint -q "$LIGHTTPD_WWW"; then
      with_lock build_blockpage
    fi
    if [ -n "$rc" ]; then
      if [ "$rc" -eq 0 ]; then
        fails=0
      elif [ "$rc" -eq 3 ]; then
        log "Re-applying failed, trying again in ${WATCH_INTERVAL}s"
      else
        [ "$fails" -lt 6 ] && fails=$((fails + 1))
        wait=$((60 << (fails - 1))); [ "$wait" -gt 3600 ] && wait=3600
        log "Re-applying failed, trying again in ${wait}s"
        sleep "$wait"
        continue
      fi
    fi
    sleep "$WATCH_INTERVAL"
  done
}

# "Fri 2026-10-09 03:53:54 AEDT 12h left ..." from list-timers -> "2026-10-09 03:53|12h".
next_update() {
  systemctl --no-pager --no-legend list-timers unifi-blocklist-update.timer 2>/dev/null | awk '
    NR == 1 && $1 != "n/a" { l = ""; for (i = 5; i <= NF && $i != "left"; i++) l = l (l ? " " : "") $i; print $2 " " substr($3, 1, 5) "|" l; exit }'
}

# Last finished run of the update service (timer, menu, install or upgrade).
last_update() {
  local when result
  when="$(systemctl show unifi-blocklist-update.service -p ExecMainExitTimestamp --value 2>/dev/null)"
  result="$(systemctl show unifi-blocklist-update.service -p Result --value 2>/dev/null)"
  [ -n "$when" ] || { echo "not since boot"; return; }
  when="$(date -d "$when" '+%F %H:%M' 2>/dev/null || echo "$when")"
  [ "$result" = success ] && echo "$when (ok)" || echo "$when (failed, see: grep unifi-blocklist /var/log/messages)"
}

# Print a space-separated list wrapped to fit beside the status labels.
wrap_list() { fold -s -w 56 | sed 's/ *$//; 1!s/^/              /'; }

# 1234567 -> 1,234,567
commas() { sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'; }

cmd_status() {
  local pid mem notice n n_ads next left
  pid="$(coredns_pid)"
  mem="$(coredns_memory)"
  notice="$(update_notice)"
  echo "Version     : ${VERSION}${notice:+ ($notice)}"
  echo "Categories  : $(enabled_keys | paste -sd' ' | wrap_list)"
  if [ -f "$MERGED" ]; then
    n="$(wc -l < "$MERGED" | commas)"; n_ads="$(cat "$ADS" 2>/dev/null | wc -l | commas)"
    [ "$n_ads" = 0 ] && n_ads=""
    echo "Domains     : $n${n_ads:+ + $n_ads Ad Block} (downloaded $(date -r "$MERGED" '+%F %H:%M'))"
  else
    echo "Domains     : none downloaded yet"
  fi
  if adblock_mounted && [ -s "$ADS" ]; then
    echo "Ad Block    : selected level replaces UniFi's own list"
  elif adblock_mounted; then
    echo "Ad Block    : off (no level selected, UniFi's own list isn't used either)"
  elif [ "${REPLACE_UNIFI_ADBLOCK:-0}" = 1 ]; then
    echo "Ad Block    : UniFi's own list (replacement not loaded yet)"
  else
    echo "Ad Block    : UniFi's own list (REPLACE_UNIFI_ADBLOCK=0)"
  fi
  if mountpoint -q "$LIGHTTPD_WWW" && [ -f "$BLOCKPAGE_DIR/__ub/meta.json" ]; then
    echo "Block page  : shows the category and list"
  elif [ "${BLOCK_PAGE:-0}" = 1 ]; then
    echo "Block page  : UniFi's own page (not loaded yet)"
  else
    echo "Block page  : UniFi's own page (BLOCK_PAGE=0)"
  fi
  if ! [ -f "$TARGET" ] || ! grep -qxF "$SENTINEL" "$TARGET"; then
    echo "Applied     : NO"
  elif [ -f "$MERGED" ] && [ "$(list_sum)" = "$(cat "$APPLIED" 2>/dev/null)" ] \
       && { ! replacing_adblock || ! [ -f "$ADS" ] || adblock_mounted; }; then
    echo "Applied     : yes"
  else
    echo "Applied     : pending (last apply failed or still running)"
    echo "              see: grep unifi-blocklist /var/log/messages"
  fi
  if [ -n "$pid" ]; then echo "CoreDNS     : running (pid $pid${mem:+, ${mem% *} of ${mem#* } MB memory limit})"; else echo "CoreDNS     : not running"; fi
  systemctl is-active --quiet unifi-blocklist-watch.service && echo "Watcher     : running" || echo "Watcher     : stopped"
  echo "Last update : $(last_update)"
  IFS='|' read -r next left <<< "$(next_update)"
  echo "Next update : ${next:-timer not running}${left:+ (in $left)}"
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
  local ok=0 conf="${UTM_DIR}/coredns_config.conf" mem cur max
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
  if [ -d "$UNIFI_LIST_DIR" ] && [ -d "$UNIFI_UPDATER_TMP" ]; then
    pass "UniFi's Ad Block list can be replaced ($UNIFI_LIST_DIR)"
  else
    warn "UniFi's Ad Block list not found ($UNIFI_LIST_DIR)" "The selected Ad Block level goes into the block list instead, next to UniFi's own Ad Block list."
  fi
  if [ -d "$LIGHTTPD_WWW" ]; then
    pass "UniFi's block page can be replaced ($LIGHTTPD_WWW)"
  else
    warn "UniFi's block page not found ($LIGHTTPD_WWW)" "Blocking works; the block page just won't show the reason."
  fi
  read -r cur max <<< "$(coredns_memory)"
  [ -n "${max:-}" ] && pass "CoreDNS memory limit: ${max} MB (using ${cur} MB)"
  if ipset list dnsfilter 2>/dev/null | sed -n '/Members/,$p' | grep -q '[0-9]'; then
    pass "filtered networks: $(ipset list dnsfilter | sed -n '/Members/,$p' | tail -n +2 | paste -sd' ')"
  else
    warn "no networks in the filter (ipset dnsfilter is empty)" "Turn on Ad Block for the networks you want covered, otherwise nothing gets filtered."
  fi
  for t in curl flock sha256sum systemctl ipset dig; do
    command -v "$t" >/dev/null || fail "missing tool: $t" "Unexpected on UniFi OS."
  done
  touch /data/.unifi-blocklist-test 2>/dev/null && rm -f /data/.unifi-blocklist-test && pass "/data is writable (survives reboots and firmware updates)" \
    || fail "/data not writable" "Unexpected on UniFi OS."
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
  systemctl stop unifi-blocklist-update.service 2>/dev/null
  for u in unifi-blocklist-watch.service unifi-blocklist-update.service unifi-blocklist-update.timer; do
    rm -f "$SYSTEMD_DIR/$u"
  done
  systemctl daemon-reload
  with_lock remove_our_entries
  log "Uninstalled. Files in $BASE_DIR were left in place."
}

# Put back only what UniFi itself had in the block list, and UniFi's own Ad Block list and block page.
remove_our_entries() {
  local changed=0
  release_blockpage
  if mountpoint -q "$UNIFI_LIST_DIR" || mountpoint -q "$UNIFI_UPDATER_TMP"; then release_unifi_adblock; changed=1; fi
  if [ -f "$TARGET" ] && grep -qxF "$SENTINEL" "$TARGET"; then
    sed "/^${SENTINEL//./\\.}\$/,\$d" "$TARGET" > "$TARGET.tmp" && mv "$TARGET.tmp" "$TARGET"
    changed=1
  fi
  [ "$changed" = 1 ] && restart_coredns
  return 0
}

# --- category selection -----------------------------------------------------

cmd_categories() {
  local group="" g key label src mark
  while IFS='|' read -r _ g key label src; do
    [ "$g" != "$group" ] && { group="$g"; printf '\n%s\n' "$group"; }
    if [ "$src" = "-" ]; then mark="  n/a"; elif is_enabled "$key"; then mark="[ON] "; else mark="[  ] "; fi
    printf '  %s %-28s %s\n' "$mark" "$key" "$label"
  done < <(grep '^C|' "$CATALOG")
  echo; echo "n/a = no free list available for this category"
}

group_keys() { awk -F'|' -v g="$1" '$1=="C" && $2==g {print $3}' "$CATALOG"; }

cmd_toggle() {
  local action="$1" key keys other
  shift
  keys="$(enabled_keys)"
  for key in "$@"; do
    key="${key^^}"
    grep -q "^C|[^|]*|${key}|" "$CATALOG" || { echo "Unknown category: $key"; return 1; }
    grep -q "^C|[^|]*|${key}|[^|]*|-$" "$CATALOG" && { echo "$key has no free list (n/a)"; return 1; }
    if [ "$action" = enable ] && group_keys "$EXCLUSIVE_GROUP" | grep -qxF "$key"; then
      other="$(group_keys "$EXCLUSIVE_GROUP" | grep -vxF "$key" | grep -xF -f - <(printf '%s\n' "$keys") | head -1)"
      [ -z "$other" ] || { echo "Only one $EXCLUSIVE_GROUP level can be on. Disable $other first."; return 1; }
    fi
    if [ "$action" = enable ]; then keys="$keys"$'\n'"$key"; else keys="$(grep -vxF "$key" <<< "$keys")"; fi
  done
  # shellcheck disable=SC2086
  save_enabled $keys
  echo "Saved. Run '$0 update' to download and apply."
}

# --- lookup -----------------------------------------------------------------

# The domain and each parent that still has a dot: a.b.example.com,
# b.example.com, example.com. A list entry also blocks its subdomains.
domain_suffixes() {
  awk -F. '{for (i = 1; i < NF; i++) {s = $i; for (j = i + 1; j <= NF; j++) s = s "." $j; print s}}' <<< "$1"
}

# Enabled categories that use a source, as "group|label" (size notes dropped).
source_categories() {
  local keys
  keys="$(enabled_keys | paste -sd'|')"
  awk -F'|' -v id="$1" -v keys="$keys" 'BEGIN{n=split(keys,k,"|"); for(i=1;i<=n;i++) want[k[i]]=1}
    $1=="C" && ($3 in want) && index(" " $5 " ", " " id " ") {sub(/ \([^)]*\)$/, "", $4); print $2 "|" $4}' "$CATALOG"
}

# Print "Label       : value", wrapped to fit the menu and indented under the label.
field() { printf '%-12s: %s\n' "$1" "$(fold -s -w 58 <<< "$2" | sed 's/ *$//; 1!s/^/              /')"; }

# Explain why a domain is or isn't blocked: the matching list entries and their
# categories, the UniFi allow list, and what the filtering CoreDNS answers.
cmd_why() {
  local input="${1:-}" name sfx srcs id url ours="" ui="" hits allow="" applied="" cats="" src want answer="" queried="" result
  [ -n "$input" ] || { echo "Usage: $0 why DOMAIN"; return 1; }
  # Accept a pasted URL: drop the scheme, path, port and a trailing dot.
  name="$(sed -E 's#^[a-zA-Z]+://##; s#[/?\#].*$##; s#:[0-9]+$##; s#\.$##' <<< "$input" | tr 'A-Z' 'a-z')"
  [[ "$name" =~ ^([a-z0-9_]([a-z0-9_-]*[a-z0-9_])?\.)+[a-z0-9-]{2,63}$ ]] || { echo "Not a domain name: $input"; return 1; }
  sfx="$(domain_suffixes "$name")"

  # Our matches as "entry  (list)", plus the categories behind each source.
  srcs="$(enabled_sources)"
  if [ -n "$srcs" ] && [ -d "$CACHE_DIR" ]; then
    # shellcheck disable=SC2086
    ours="$(cd "$CACHE_DIR" && grep -HxF -- "$sfx" $srcs 2>/dev/null | awk -F: '{print $2 "  (" $1 ")"}')"
    for id in $(awk '{print substr($2, 2, length($2) - 2)}' <<< "$ours" | sort -u); do
      cats="$cats$(source_categories "$id")"$'\n'
    done
  fi
  for url in "${LIST_URLS[@]}"; do
    id="extra-$(printf '%s' "$url" | sha256sum | cut -c1-12)"
    [ -f "$CACHE_DIR/$id" ] && ours="$ours"$'\n'"$(grep -xF -- "$sfx" "$CACHE_DIR/$id" | awk -v u="$url" '{print $0 "  (LIST_URLS: " u ")"}')"
  done
  [ -f "$CUSTOM_BLOCK_FILE" ] && ours="$ours"$'\n'"$(normalise < "$CUSTOM_BLOCK_FILE" | grep -xF -- "$sfx" | sed 's/$/  (custom-block.list)/')"
  ours="$(grep . <<< "$ours")"
  [ -f "$UI_LIST" ] && ui="$(grep -xF -- "$sfx" "$UI_LIST" | sed 's/$/  (UniFi UI block list)/')"
  [ -f "$ALLOW_LIST" ] && allow="$(grep -xF -- "$sfx" "$ALLOW_LIST" | head -1)"
  [ -f "$MERGED" ] && applied="$(cat "$MERGED" "$ADS" 2>/dev/null | grep -xF -- "$sfx" | head -1)"
  # Most specific entry first.
  hits="$(printf '%s\n%s\n' "$ui" "$ours" | grep . | awk '{print length($1) "\t" $0}' | sort -s -k1,1nr | cut -f2-)"
  cats="$(grep . <<< "$cats" | sort -u | awk -F'|' '{a[$1] = a[$1] (a[$1] ? ", " : "") $2} END {for (g in a) print g ": " a[g]}' | sort)"

  # Ask CoreDNS the way a device on a filtered network would.
  src="$(filter_source_ip)"; want="$(block_address)"
  if [ -n "$src" ] && command -v dig >/dev/null && ip -o addr show | grep -qF " inet $src/"; then
    # Retry: a query now and then times out, mostly just after CoreDNS has loaded the lists.
    for _ in 1 2 3; do answer="$(filter_query "$src" "$name" | tail -1)" && { queried=1; break; }; done
  fi

  if [ -n "$queried" ] && [ -n "$want" ] && [ "$answer" = "$want" ]; then
    if [ -n "$hits" ]; then result="blocked by the list entries above"
    else result="blocked by UniFi itself, not by these lists"; fi
  elif [ -n "$queried" ] && [ "$answer" = "0.0.0.0" ]; then
    # Ad Block answers 0.0.0.0, not the block page address.
    if adblock_mounted && [ -n "$ours" ]; then result="blocked by Ad Block (the selected level, loaded into UniFi's Ad Block list)"
    elif adblock_mounted; then result="blocked by Ad Block (UniFi's rows kept in the Ad Block list)"
    else result="blocked by UniFi's own Ad Block list, not by these lists"; fi
  elif [ -n "$queried" ]; then
    result="not blocked"
    if [ -n "$allow" ]; then result="not blocked: on the UniFi allow list ($allow)"
    elif [ -n "$hits" ]; then result="not blocked yet: on a list, but not applied (see: $0 status)"; fi
  elif [ -n "$allow" ]; then
    result="on the UniFi allow list ($allow), which overrides these lists (could not ask CoreDNS to confirm)"
  elif [ -n "$hits" ]; then
    result="on the lists above (could not ask CoreDNS to confirm)"
  else
    result="not on any list (could not ask CoreDNS to confirm)"
  fi

  field "Domain" "$name"
  field "Lists" "${hits:-none}"
  [ -n "$cats" ] && field "Categories" "$cats"
  [ -n "$queried" ] && field "DNS answer" "${answer:-no address}$([ -n "$answer" ] && case "$answer" in "$want") echo ' (block page address)' ;; 0.0.0.0) echo ' (Ad Block)' ;; esac)"
  field "Result" "$result"
  if [ -n "$ours" ] && [ -f "$MERGED" ] && [ -z "$applied" ]; then
    field "Note" "its list was selected after the last update. Run: $0 update"
  elif [ -z "$ours" ] && [ -n "$applied" ]; then
    field "Note" "$applied is still in the applied list from a category switched off since. The next update removes it."
  fi
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
  local groups=() choice g i items na picked current dirty=0 keys saved kind hint notice sel
  # One character per group: dialog jumps to the next tag starting with the typed key,
  # so "1" and "10" would clash. A, L, S and Q are taken by the other menu entries.
  local tags="1234567890BCDEFGHIJKMNOPRTUVWXYZ"
  mapfile -t groups < <(awk -F'|' '$1=="C" && !seen[$2]++ {print $2}' "$CATALOG")
  keys="$(enabled_keys | grep -v '^$' | sort -u)"; saved="$keys"

  while :; do
    local menu=()
    for i in "${!groups[@]}"; do
      g="${groups[$i]}"
      local total on
      total=$(awk -F'|' -v g="$g" '$1=="C" && $2==g && $5!="-"' "$CATALOG" | wc -l)
      on=$(awk -F'|' -v g="$g" '$1=="C" && $2==g {print $3}' "$CATALOG" | grep -cxF -f <(echo "$keys") || true)
      menu+=("${tags:i:1}" "$(printf '%-34s %2s/%-2s on' "$g" "$on" "$total")")
    done
    menu+=("" "" "A" "Apply now (download lists + reload)" "L" "Look up why a domain is blocked" "S" "Status" "Q" "Quit$( [ $dirty = 1 ] && echo ' (unsaved changes)')")

    notice="$(update_notice)"
    choice=$(dialog --clear --title "unifi-blocklist $VERSION" --cancel-label "Quit" \
      --menu "UniFi content filter categories backed by free lists.\nChanges are saved when you leave a group; Apply downloads and reloads.${notice:+\n\nNote: ${notice}.}" \
      25 72 17 "${menu[@]}" 3>&1 1>&2 2>&3) || choice=Q

    case "$choice" in
      "") continue ;;
      A)
        save_enabled $keys; saved="$keys"; dirty=0; clear
        run_update_detached; echo; read -rp "Press Enter to return to the menu" _ ;;
      L)
        sel=$(dialog --title "Look up a domain" --inputbox "Domain or URL, e.g. ads.example.com" 8 60 3>&1 1>&2 2>&3) || continue
        [ -n "$sel" ] || continue
        sel="$(cmd_why "$sel" 2>&1)"
        dialog --title "Look up" --cr-wrap --no-collapse --msgbox "$sel" $(( $(wc -l <<< "$sel") + 4 )) 76 ;;
      S)
        sel="$(cmd_status 2>&1)"
        [ $dirty = 1 ] && sel="$sel"$'\n\n'"Unsaved     : $(paste -sd' ' <<< "$keys" | wrap_list)"
        dialog --title "Status" --cr-wrap --no-collapse --msgbox "$sel" $(( $(wc -l <<< "$sel") + 4 )) 76 ;;
      Q)
        if [ $dirty = 1 ] && dialog --yesno "Apply the changed categories now?\n(downloads lists and reloads CoreDNS, DNS pauses ~10-20 s)" 8 66; then
          save_enabled $keys; clear; run_update_detached
        else
          clear
          [ $dirty = 1 ] && save_enabled $keys && echo "Saved, will be applied on the next scheduled update (or run: $0 update)"
        fi
        return 0 ;;
      *)
        i="${tags%%"$choice"*}"; g="${groups[${#i}]:-}"
        [ -n "$g" ] || continue
        items=(); na=""
        while IFS='|' read -r _ _ key label src; do
          if [ "$src" = "-" ]; then na="${na}${label}, "; continue; fi
          grep -qxF "$key" <<< "$keys" && current=on || current=off
          items+=("$key" "$label" "$current")
        done < <(awk -F'|' -v g="$g" '$1=="C" && $2==g' "$CATALOG")
        # --separate-output is only valid for checklists; dialog 1.3 rejects it with --radiolist.
        kind=(--separate-output --checklist); hint="Space = toggle, Enter = OK."
        if [ "$g" = "$EXCLUSIVE_GROUP" ]; then
          # One level at a time, or off.
          kind=(--radiolist); hint="Space = select one level, Enter = OK."
          printf '%s\n' "${items[@]}" | grep -qx on && current=off || current=on
          items=(OFF "Off" "$current" "${items[@]}")
        fi
        picked=$(dialog --title "$g" --no-tags "${kind[@]}" \
          "${hint}${na:+\n\nNo free list (not shown): ${na%, }}" 24 76 14 "${items[@]}" 3>&1 1>&2 2>&3) || continue
        [ "$picked" = OFF ] && picked=""
        # Replace this group's keys with the picked ones; unsaved = differs from what's saved.
        for ((i = 0; i < ${#items[@]}; i += 3)); do keys="$(grep -vxF "${items[$i]}" <<< "$keys")"; done
        keys="$(printf '%s\n%s\n' "$keys" "$picked" | grep -v '^$' | sort -u)"
        if [ "$keys" = "$saved" ]; then dirty=0; else dirty=1; fi ;;
    esac
  done
}

cmd_help() {
  cat <<EOF
unifi-blocklist $VERSION: free blocklists in UniFi's own content filter

Usage: $0 <command>

Everyday
  menu                Choose categories in a menu and apply them
  status              Show what is selected, applied and running
  update              Download the lists now and apply them if they changed
  why DOMAIN          Show which list and category block a domain, if any

Categories
  categories          List all categories and which ones are on
  enable KEY...       Turn categories on, e.g.: enable GAMBLING MALWARE
  disable KEY...      Turn categories off

Maintenance
  check               Check that this gateway is compatible (changes nothing)
  apply               Load the downloaded list again (DNS pauses ~10 s)
  upgrade [--force]   Install the newest release, keeping your settings
  version             Show the installed version
  install             Set up the background services
  uninstall           Remove the services and restore UniFi's own list

Settings: $CONF_FILE
Log:      grep unifi-blocklist /var/log/messages
EOF
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
  why)        shift; cmd_why "$@" ;;
  check)      cmd_check ;;
  upgrade)    shift; cmd_upgrade "$@" ;;
  version)    echo "$VERSION" ;;
  ""|help|-h|--help) cmd_help ;;
  *) echo "Unknown command: $1"; echo; cmd_help; exit 1 ;;
esac
