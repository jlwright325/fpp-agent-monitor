#!/bin/sh
set -eu

PURGE=0
if [ "${1:-}" = "--purge" ]; then
  PURGE=1
fi

BIN_DST_DIR="/opt/fpp-monitor-agent"
CFG_FILE="/home/fpp/media/config/fpp-monitor-agent.json"
UNIT_DST="/etc/systemd/system/fpp-monitor-agent.service"

if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files | grep -q fpp-monitor-agent.service; then
    systemctl stop fpp-monitor-agent.service || true
    systemctl disable fpp-monitor-agent.service || true
  fi
  if [ -f "$UNIT_DST" ]; then
    rm -f "$UNIT_DST"
    systemctl daemon-reload
  fi
fi

rm -f "$BIN_DST_DIR/fpp-monitor-agent"

if [ $PURGE -eq 1 ]; then
  rm -f "$CFG_FILE"
  rm -rf "/var/lib/fpp-monitor-agent"
fi

echo "uninstalled"
