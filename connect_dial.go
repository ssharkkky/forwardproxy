package forwardproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	tcpFallbackDelay  = 250 * time.Millisecond
	tcpMinimumDelay   = 100 * time.Millisecond
	tcpAttemptTimeout = 5 * time.Second
)

var errTCPDialFailed = errors.New("target connection failed")

func tcpDialError(err error) error {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
		return caddyhttp.Error(http.StatusGatewayTimeout, errors.New("target connection timed out"))
	}
	return caddyhttp.Error(http.StatusBadGateway, errTCPDialFailed)
}

// Dial only the numeric addresses that passed ACL checks; resolving the name
// again in net.Dialer would permit DNS changes to bypass the checked set.
func (h *Handler) dialTCPAddresses(ctx context.Context, network string, addresses []string) (net.Conn, error) {
	addresses = interleaveTCPAddresses(network, addresses)
	if len(addresses) == 0 {
		return nil, errTCPDialFailed
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	start := func(address string) {
		go func() {
			attemptCtx, attemptCancel := context.WithTimeout(ctx, tcpAttemptTimeout)
			conn, err := h.dialContext(attemptCtx, network, address)
			attemptErr := attemptCtx.Err()
			attemptCancel()
			if attemptErr != nil {
				err = attemptErr
			}
			if err != nil && conn != nil {
				conn.Close()
				conn = nil
			}
			if err == nil && conn == nil {
				err = errTCPDialFailed
			}
			// An unbuffered handoff gives exactly one winner ownership. Late
			// successful losers must close even when cancellation races success.
			select {
			case results <- result{conn, err}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	start(addresses[0])
	lastStart := time.Now()
	next, pending := 1, 1
	timer := time.NewTimer(tcpFallbackDelay)
	defer timer.Stop()
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-results:
			pending--
			if res.conn != nil {
				if err := ctx.Err(); err != nil {
					res.conn.Close()
					return nil, err
				}
				return res.conn, nil
			}
			lastErr = res.err
			if next == len(addresses) && pending == 0 {
				return nil, lastErr
			}
			// Accelerate failures while retaining RFC 8305's recommended
			// minimum spacing, including when an older attempt fails late.
			if next < len(addresses) {
				timer.Reset(max(0, tcpMinimumDelay-time.Since(lastStart)))
			}
			continue
		case <-timer.C:
		}
		if next < len(addresses) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			start(addresses[next])
			lastStart = time.Now()
			next++
			pending++
			timer.Reset(tcpFallbackDelay)
		}
	}
}

// Preserve resolver preference within each family, alternating families with
// RFC 8305's recommended First Address Family Count of one. Explicit tcp4/tcp6
// callers never race an address outside the requested family.
func interleaveTCPAddresses(network string, addresses []string) []string {
	var primary, fallback []string
	var primaryV4 bool
	for _, address := range addresses {
		host, _, err := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if err != nil || ip == nil {
			continue
		}
		v4 := ip.To4() != nil
		if network == "tcp4" && !v4 || network == "tcp6" && v4 {
			continue
		}
		if len(primary) == 0 {
			primaryV4 = v4
		}
		if v4 == primaryV4 {
			primary = append(primary, address)
		} else {
			fallback = append(fallback, address)
		}
	}
	ordered := make([]string, 0, len(primary)+len(fallback))
	for i := 0; i < len(primary) || i < len(fallback); i++ {
		if i < len(primary) {
			ordered = append(ordered, primary[i])
		}
		if i < len(fallback) {
			ordered = append(ordered, fallback[i])
		}
	}
	return ordered
}
