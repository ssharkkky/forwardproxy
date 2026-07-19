#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
output=${1:?usage: build-naive-caddy.sh OUTPUT}
go_bin=${GO_BIN:-go}
xcaddy_bin=${XCADDY_BIN:-xcaddy}
source "$repo_root/M4_TOOLCHAIN.lock"

test "$($go_bin version | awk '{print $3}')" = "go$GO_VERSION"
test "$($xcaddy_bin version | awk '{print $1}')" = "v$XCADDY_VERSION"
test "$(git -C "${CADDY_SOURCE_DIR:?set CADDY_SOURCE_DIR}" rev-parse HEAD)" = "$CADDY_PATCH_COMMIT"

args=(
  build v2.11.2
  --output "$output"
  --with "github.com/caddyserver/forwardproxy=$repo_root"
  --replace "github.com/caddyserver/caddy/v2=$CADDY_SOURCE_DIR"
)

"$xcaddy_bin" "${args[@]}"
"$output" version
