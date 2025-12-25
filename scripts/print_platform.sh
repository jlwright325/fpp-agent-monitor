#!/bin/sh
set -eu

ARCH="$(uname -m)"
case "$ARCH" in
  armv7l|armv7*) echo "armv7" ;;
  aarch64|arm64) echo "arm64" ;;
  *) echo "unknown" ;;
 esac
