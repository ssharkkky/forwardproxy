# M7 Server Build SOP

This procedure builds the native-UDP server from the pinned Caddy,
forwardproxy, and quic-go forks. It is separate from the legacy M4 build,
which intentionally remains unchanged.

## Inputs

`M7_TOOLCHAIN.lock` is the source of truth for Go, xcaddy, Caddy, and quic-go.
The Caddy checkout must match `CADDY_PATCH_COMMIT`. The quic-go pseudo-version
must contain `QUIC_GO_COMMIT`.

## Reproducible build

```sh
git clone https://github.com/ssharkkky/forwardproxy.git
cd forwardproxy
git checkout 75f7081178f2b9ee858e62b6b4d2cb867437d502
git clone https://github.com/ssharkkky/caddy.git ../caddy-m7
git -C ../caddy-m7 checkout 3bcce47fa48fec241072539d061cb7429f443f5a
go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.5
GO_BIN="$(command -v go)" \
XCADDY_BIN="$(go env GOPATH)/bin/xcaddy" \
CADDY_SOURCE_DIR="$(cd ../caddy-m7 && pwd)" \
  scripts/build-m7-caddy.sh ./caddy
```

The script fails closed if Go, xcaddy, Caddy, or quic-go does not match the
lock. It also checks that `http.handlers.forward_proxy` is present in the
resulting binary.

## Required checks

```sh
go test ./...
go vet ./... # advisory until the pre-existing Handler-copy diagnostics are removed
go test -race ./...
go version -m ./caddy
./caddy list-modules | grep '^http.handlers.forward_proxy$'
```

Package the binary together with `M7_TOOLCHAIN.lock` and a SHA256 file. Never
publish a server binary built from a floating branch or an unrecorded module
replacement.

## Update procedure

Update one dependency at a time. For quic-go, rebase the BBR fork first; then
update Caddy's replacement; then update forwardproxy's lock and rebuild. For a
Caddy or forwardproxy update, keep the other pins fixed until its own tests
pass. Finally update the product lock in NaiveProxy and run the product
combination workflow.

Do not automatically merge dependency update PRs. A failed build, changed
QUIC config site, or changed native-UDP behavior requires a new compatibility
review.

## Rollback

Set `NAIVE_QUIC_CONGESTION=cubic` and restart for a runtime rollback. For a
build rollback, restore the previous product lock and server artifact.
