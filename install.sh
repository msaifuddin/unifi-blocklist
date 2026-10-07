#!/bin/bash
#
# Installer / updater for unifi-blocklist. Run on the gateway as root:
#
#   curl -fsSL https://raw.githubusercontent.com/msaifuddin/unifi-blocklist/main/install.sh | bash
#
# Re-running it updates the scripts and keeps your settings
# (blocklist.conf, categories.enabled, custom-block.list, state/).

set -euo pipefail

REPO="msaifuddin/unifi-blocklist"
BRANCH="${BRANCH:-main}"
DEST="/data/unifi-blocklist"
FILES="blocklist.sh install.sh categories.list blocklist.conf.example README.md LICENSE systemd"

[ "$(id -u)" = 0 ] || { echo "Please run as root (ssh root@<gateway-ip>)."; exit 1; }
[ -d /data ] || { echo "/data not found: this does not look like a UniFi OS gateway."; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${REPO} (${BRANCH})..."
curl -fsSL "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" | tar -xz -C "$tmp"
src="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -1)"

mkdir -p "$DEST"
for f in $FILES; do
  rm -rf "${DEST:?}/$f"
  cp -r "$src/$f" "$DEST/$f"
done
chmod +x "$DEST/blocklist.sh" "$DEST/install.sh"
echo "Installed files to $DEST"
echo

"$DEST/blocklist.sh" install
echo
echo "Done. Pick categories with:  $DEST/blocklist.sh menu"
