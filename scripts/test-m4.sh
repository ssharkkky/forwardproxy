#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

go test -run TestM4G0ContractBaseline -v .
go test ./...
printf '%s\n' M4_G0_SERVER_BASELINE_OK
