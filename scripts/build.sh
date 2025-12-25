#!/bin/sh
set -eu

VERSION="${VERSION:-dev}"
OUT_DIR="dist"
mkdir -p "$OUT_DIR"

build() {
  CGO_ENABLED=0 GOOS=linux GOARCH=$1 GOARM=${2:-} \
    go build -ldflags "-s -w -X main.version=$VERSION" \
    -o "$OUT_DIR/fpp-monitor-agent-linux-$3" ./cmd/agent
}

build arm 7 armv7
build arm64 "" arm64

echo "built to $OUT_DIR"
