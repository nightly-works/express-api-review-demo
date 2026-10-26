#!/bin/sh
# Renders the Upwork portfolio thumbnail (1600×1200, 4:3) from thumbnail.html.
# Chromium needs writable config and cache folders (see the environment playbook).
cd "$(dirname "$0")"
tmp=$(mktemp -d)
XDG_CONFIG_HOME="$tmp" XDG_CACHE_HOME="$tmp" chromium --headless --no-sandbox --disable-gpu \
  --hide-scrollbars --user-data-dir="$tmp/profile" --window-size=1600,1200 \
  --screenshot=thumbnail.png "file://$PWD/thumbnail.html"
rm -rf "$tmp"
