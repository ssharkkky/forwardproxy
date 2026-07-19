#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
go_bin=${GO_BIN:-/Users/stoneshi/.local/naive-m4/go1.25.12/bin/go}
caddy_bin=${CADDY_BIN:-"$repo_root/build/m4-caddy"}
proxy_address=${M4_PROXY_ADDRESS:-127.0.0.1:19443}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/naive-m4-g5.XXXXXX")
client_bin="$tmp_dir/m4-rfc9298-client"
server_log="$tmp_dir/caddy.log"
access_log="$tmp_dir/access.log"
shutdown_log="$tmp_dir/shutdown-client.log"
server_pid=
shutdown_pid=

cleanup() {
	if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
		kill "$server_pid" 2>/dev/null || true
		wait "$server_pid" 2>/dev/null || true
	fi
	if [[ -n "$shutdown_pid" ]] && kill -0 "$shutdown_pid" 2>/dev/null; then
		kill "$shutdown_pid" 2>/dev/null || true
		wait "$shutdown_pid" 2>/dev/null || true
	fi
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

start_server() {
	touch "$server_log"
	M4_ACCESS_LOG="$access_log" \
	XDG_DATA_HOME="$tmp_dir/data" \
	XDG_CONFIG_HOME="$tmp_dir/config" \
	"$caddy_bin" run --config "$repo_root/tests/m4/Caddyfile" --adapter caddyfile \
		>>"$server_log" 2>&1 &
	server_pid=$!
	for _ in $(seq 1 40); do
		if "$client_bin" -mode smoke -proxy "$proxy_address" -timeout 3s >/dev/null 2>&1; then
			return
		fi
		if ! kill -0 "$server_pid" 2>/dev/null; then
			wait "$server_pid" || true
			printf 'Caddy exited during startup\n' >&2
			grep -v 'certificate maintenance' "$server_log" >&2 || true
			exit 1
		fi
		sleep 0.25
	done
	printf 'Caddy did not become ready\n' >&2
	grep -v 'certificate maintenance' "$server_log" >&2 || true
	exit 1
}

stop_server() {
	kill "$server_pid"
	wait "$server_pid"
	server_pid=
}

test -x "$caddy_bin"
"$go_bin" build -trimpath -o "$client_bin" ./cmd/m4-rfc9298-client

cd "$repo_root"
start_server
"$client_bin" -mode matrix -proxy "$proxy_address" -timeout 30s
"$client_bin" -mode limits -proxy "$proxy_address" -timeout 30s
"$client_bin" -mode idle -proxy "$proxy_address" -timeout 135s
if ! grep -q 'idle_expired' "$server_log"; then
	printf 'production idle expiry was not observed in the server lifecycle log\n' >&2
	exit 1
fi
printf '%s\n' M4_G5_IDLE_EXPIRY_OK

for _ in 1 2 3; do
	"$client_bin" -mode matrix -proxy "$proxy_address" -timeout 30s >/dev/null
done
printf '%s\n' M4_G5_STRESS_OK

"$client_bin" -mode shutdown -proxy "$proxy_address" -timeout 30s >"$shutdown_log" 2>&1 &
shutdown_pid=$!
for _ in $(seq 1 40); do
	if grep -q M4_G5_SHUTDOWN_CLIENT_READY "$shutdown_log"; then
		break
	fi
	if ! kill -0 "$shutdown_pid" 2>/dev/null; then
		wait "$shutdown_pid" || true
		cat "$shutdown_log" >&2
		exit 1
	fi
	sleep 0.1
done
grep -q M4_G5_SHUTDOWN_CLIENT_READY "$shutdown_log"
stop_server
wait "$shutdown_pid"
shutdown_pid=
grep -q M4_G5_SERVER_SHUTDOWN_OBSERVED "$shutdown_log"
start_server
"$client_bin" -mode smoke -proxy "$proxy_address" -timeout 10s
stop_server
printf '%s\n' M4_G5_SHUTDOWN_RESTART_OK

if grep -E 'm4-private-target\.localhost|m4-g5-private-payload|dGVzdDpwYXNz|ZEdWemREcHdZWE56' "$server_log" "$access_log" >/dev/null 2>&1; then
	printf 'private CONNECT-UDP data appeared in Caddy logs\n' >&2
	exit 1
fi
printf '%s\n' M4_G5_SERVER_LOG_PRIVACY_OK
printf '%s\n' M4_G5_SERVER_INTEROP_OK
