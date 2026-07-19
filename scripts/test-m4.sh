#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

go test -run 'TestM4G0ContractBaseline|TestM4G1CaddyH3DatagramCapability|TestM4G2ProtocolStatusGate|TestM4G3ProductionUDPAssociation|TestM4G4ForwardProxyIntegration' -v .
go test ./...
printf '%s\n' M4_G0_SERVER_BASELINE_OK M4_G1_CADDY_H3_DATAGRAM_OK M4_G2_PROTOCOL_POLICY_OK M4_G3_UDP_ASSOCIATION_OK M4_G4_FORWARDPROXY_INTEGRATION_OK
