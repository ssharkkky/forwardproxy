//go:build w2w3

// W3 experiment: isolated standard-library Happy Eyeballs prototype.
//
// It drives Go's built-in net.Dialer Happy Eyeballs (the 7307332 baseline's
// comparison target) with the production resolver mode and the same
// controlled target world as the current scheduler path:
//
//   - net.Resolver{Dial: ...} points the pure-Go resolver (the release
//     server's mode, CGO_ENABLED=0) at the in-test UDP DNS fixture,
//   - ControlContext enforces the ACL on the actual numeric destination
//     just before connect (no stale pre-resolve reuse) and applies the
//     per-run pre-connect behavior,
//   - the total request deadline is carried by the dial context exactly
//     like the production request context,
//   - error-to-status mapping mirrors tcpDialError (timeout/504 vs other/502),
//     and DNS-stage failures map like the production lookup-failure path
//     (IsTimeout -> 504, else 502).
package forwardproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"
)

// w3HEDialer builds the prototype dialer for one run. The ControlContext
// closure records into the run's state (ACL gate + per-run behavior).
func w3HEDialer(t *testing.T, w *w3World, fx *w3DNSFixture, rs *w3RunState, fallbackDelay time.Duration) *net.Dialer {
	t.Helper()
	d := &net.Dialer{
		FallbackDelay: fallbackDelay,
		ControlContext: func(ctx context.Context, network, address string, c syscall.RawConn) error {
			return w.startDialTo(ctx, address, rs)
		},
		Resolver: &net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("udp", fx.pcAddr())
			},
		},
	}
	return d
}

// w3DialStatus mirrors tcpDialError's status mapping for a dial-stage
// failure.
func w3DialStatus(err error) int {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

// w3DNSStatus maps a DNS-stage failure exactly like the production
// lookup-failure path (tcpDialError applied to the DNSError).
func w3DNSStatus(err error) int {
	return w3DialStatus(err)
}

// w3ClassifyHEError splits a prototype DialContext error into the DNS stage
// or the dial stage and returns the mapped HTTP status plus a short class.
func w3ClassifyHEError(ctx context.Context, err error) (status int, class string) {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return w3DNSStatus(err), "dns"
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return w3DialStatus(ctxErr), "ctx"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, "timeout"
	}
	return w3DialStatus(err), "dial"
}
