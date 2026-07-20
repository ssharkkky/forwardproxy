#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
go_bin=${GO_BIN:-/Users/stoneshi/.local/naive-m4/go1.25.12/bin/go}
caddy_bin=${CADDY_BIN:-"$repo_root/build/m4-caddy"}
proxy_port=${M6_PROXY_PORT:-19444}
proxy_address="m5-proxy.localhost:$proxy_port"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/naive-m6-hostless.XXXXXX")
client_bin="$tmp_dir/m4-rfc9298-client"
server_log="$tmp_dir/caddy.log"
access_log="$tmp_dir/access.log"
server_pid=

cleanup() {
	if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
		kill "$server_pid" 2>/dev/null || true
		wait "$server_pid" 2>/dev/null || true
	fi
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

test -x "$caddy_bin"
command -v openssl >/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-subj '/CN=m5-proxy.localhost' \
	-addext 'subjectAltName=DNS:m5-proxy.localhost,DNS:localhost,IP:127.0.0.1,IP:::1' \
	-keyout "$tmp_dir/server-key.pem" -out "$tmp_dir/server-cert.pem" \
	>/dev/null 2>&1
"$go_bin" build -trimpath -o "$client_bin" ./cmd/m4-rfc9298-client

M5_PROXY_PORT="$proxy_port" \
M5_SERVER_CERT="$tmp_dir/server-cert.pem" \
M5_SERVER_KEY="$tmp_dir/server-key.pem" \
M5_ACCESS_LOG="$access_log" \
XDG_DATA_HOME="$tmp_dir/data" \
XDG_CONFIG_HOME="$tmp_dir/config" \
	"$caddy_bin" run --config "$repo_root/tests/m5/Caddyfile-trusted" \
		--adapter caddyfile >"$server_log" 2>&1 &
server_pid=$!

for _ in $(seq 1 80); do
	if grep -q 'server running' "$server_log" 2>/dev/null; then
		break
	fi
	if ! kill -0 "$server_pid" 2>/dev/null; then
		wait "$server_pid" || true
		server_pid=
		cat "$server_log" >&2
		exit 1
	fi
	sleep 0.25
done
grep -q 'server running' "$server_log"

"$client_bin" -mode tcp-padding -proxy "$proxy_address" \
	-username m5-user -password m5-pass -timeout 20s
"$client_bin" -mode smoke -proxy "$proxy_address" \
	-username m5-user -password m5-pass -timeout 20s

printf '%s\n' M6_HOSTLESS_TCP_UDP_INTEROP_OK
