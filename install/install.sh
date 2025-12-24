#!/bin/sh
set -eu

BIN_SRC="${1:-}"
BIN_DST_DIR="/opt/fpp-monitor-agent"
BIN_DST="$BIN_DST_DIR/fpp-monitor-agent"
CFG_DIR="/etc/fpp-monitor-agent"
CFG_FILE="$CFG_DIR/config.json"
DATA_DIR="/var/lib/fpp-monitor-agent/downloads"
UNIT_SRC="/opt/fpp-monitor-agent/fpp-monitor-agent.service"
UNIT_DST="/etc/systemd/system/fpp-monitor-agent.service"

if [ -z "$BIN_SRC" ]; then
  echo "usage: install.sh /path/to/fpp-monitor-agent" >&2
  exit 1
fi

mkdir -p "$BIN_DST_DIR" "$CFG_DIR" "$DATA_DIR"
install -m 0755 "$BIN_SRC" "$BIN_DST"

if [ ! -f "$CFG_FILE" ]; then
  if [ -f "$(dirname "$0")/config.json" ]; then
    install -m 0644 "$(dirname "$0")/config.json" "$CFG_FILE"
  else
    echo "missing config template; create $CFG_FILE manually" >&2
  fi
fi

# Install unit if systemctl exists
if command -v systemctl >/dev/null 2>&1; then
  if [ -f "$(dirname "$0")/../systemd/fpp-monitor-agent.service" ]; then
    install -m 0644 "$(dirname "$0")/../systemd/fpp-monitor-agent.service" "$UNIT_DST"
  fi
  systemctl daemon-reload
  systemctl enable fpp-monitor-agent.service
  systemctl restart fpp-monitor-agent.service
fi

echo "installed to $BIN_DST"
