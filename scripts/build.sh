#!/bin/sh
set -eu

VERSION="${VERSION:-dev}"
OUT_DIR="dist"
CLOUDFLARED_VERSION="${CLOUDFLARED_VERSION:-latest}"
mkdir -p "$OUT_DIR"

cloudflared_url() {
  local arch="$1"
  if [ "$CLOUDFLARED_VERSION" = "latest" ]; then
    echo "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$arch"
  else
    echo "https://github.com/cloudflare/cloudflared/releases/download/$CLOUDFLARED_VERSION/cloudflared-linux-$arch"
  fi
}

ensure_cloudflared() {
  local arch="$1"
  local dest="$OUT_DIR/cloudflared-linux-$arch"
  if [ -x "$dest" ]; then
    return 0
  fi
  echo "Downloading cloudflared ($arch) to $dest"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$dest" "$(cloudflared_url "$arch")"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$dest" "$(cloudflared_url "$arch")"
  else
    echo "curl or wget required to download cloudflared" >&2
    exit 1
  fi
  chmod +x "$dest"
}

build() {
  CGO_ENABLED=0 GOOS=linux GOARCH=$1 GOARM=${2:-} \
    go build -ldflags "-s -w -X main.version=$VERSION" \
    -o "$OUT_DIR/fpp-monitor-agent-linux-$3" ./cmd/agent
}

package() {
  local arch="$1"
  local agent_bin="$OUT_DIR/fpp-monitor-agent-linux-$arch"
  local cloudflared_bin="$OUT_DIR/cloudflared-linux-$2"
  local pkg_dir="$OUT_DIR/package-$arch"
  local tarball="$OUT_DIR/fpp-monitor-agent-linux-$arch.tar.gz"

  mkdir -p "$pkg_dir"
  cp "$agent_bin" "$pkg_dir/fpp-monitor-agent"
  cp "$cloudflared_bin" "$pkg_dir/cloudflared"
  tar -czf "$tarball" -C "$pkg_dir" .
}

build arm 7 armv7
build arm64 "" arm64

ensure_cloudflared arm
ensure_cloudflared arm64
package armv7 arm
package arm64 arm64

echo "built to $OUT_DIR"
