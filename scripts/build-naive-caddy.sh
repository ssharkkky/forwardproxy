#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
output=${1:?usage: build-naive-caddy.sh OUTPUT}
go_bin=${GO_BIN:-go}
xcaddy_bin=${XCADDY_BIN:-xcaddy}

test "$($go_bin version | awk '{print $3}')" = "go1.25.12"
test "$($xcaddy_bin version | awk '{print $1}')" = "v0.4.5"

args=(
  build v2.11.2
  --output "$output"
  --with "github.com/caddyserver/forwardproxy=$repo_root"
)

if [[ -n ${CADDY_SOURCE_DIR:-} ]]; then
  test "$(git -C "$CADDY_SOURCE_DIR" rev-parse HEAD)" = "${CADDY_SOURCE_COMMIT:?set CADDY_SOURCE_COMMIT}"
  args+=(--with "github.com/caddyserver/caddy/v2=$CADDY_SOURCE_DIR")
fi

"$xcaddy_bin" "${args[@]}"
"$output" version
