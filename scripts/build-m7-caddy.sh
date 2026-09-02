#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
output=${1:?usage: build-m7-caddy.sh OUTPUT}
go_bin=${GO_BIN:-go}
xcaddy_bin=${XCADDY_BIN:-xcaddy}
source "$repo_root/M7_TOOLCHAIN.lock"

test "$($go_bin version | awk '{print $3}')" = "go$GO_VERSION"
test "$($xcaddy_bin version | awk '{print $1}')" = "v$XCADDY_VERSION"
caddy_source=${CADDY_SOURCE_DIR:?set CADDY_SOURCE_DIR to the M7 Caddy worktree}
test "$(git -C "$caddy_source" rev-parse HEAD)" = "$CADDY_PATCH_COMMIT"

# xcaddy builds a temporary main module, so every dependency replacement must
# be passed here explicitly. A replacement in forwardproxy/go.mod is not
# inherited by that temporary module.
args=(
  build "$CADDY_VERSION"
  --output "$output"
  --with "github.com/caddyserver/forwardproxy=$repo_root"
  --replace "github.com/caddyserver/caddy/v2=$caddy_source"
  --replace "github.com/quic-go/quic-go=github.com/ssharkkky/quic-go@$QUIC_GO_VERSION"
)

PATH="$(dirname "$go_bin"):$PATH" "$xcaddy_bin" "${args[@]}"

test "$($go_bin version -m "$output" | awk 'NR == 1 {print $2}')" = "go$GO_VERSION"
module_info=$(mktemp)
module_list=$(mktemp)
trap 'rm -f "$module_info" "$module_list"' EXIT
"$go_bin" version -m "$output" >"$module_info"
"$output" list-modules >"$module_list"
grep -F $'github.com/ssharkkky/quic-go\t' "$module_info"
grep -F 'github.com/caddyserver/caddy/v2' "$module_info"
grep -F "$caddy_source" "$module_info"
grep -F 'http.handlers.forward_proxy' "$module_list"
"$output" version
