#!/bin/sh
set -eu

CONFIG="${1:-./scripts/local-config.json}"

if [ ! -f "$CONFIG" ]; then
  echo "missing config: $CONFIG" >&2
  echo "create a config file or pass a path: ./scripts/run_local.sh /path/to/config.json" >&2
  exit 1
fi

exec go run ./cmd/agent --config "$CONFIG"
