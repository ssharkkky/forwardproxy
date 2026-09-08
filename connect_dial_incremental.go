package forwardproxy

import (
	"context"
	"net"
	"sync"
	"time"
)

// TCP candidate admission (RFC 8305 section 3-style dynamic candidate set,
// no Resolution Delay).
//
// The legacy path resolved the target with one merged A+AAAA lookup and
// waited for both families before the first TCP dial started; a slow or
// dropped family gated every dial (W2: up to 10 s for a dropped
// sub-query). dialTCPIncremental instead resolves ip4 and ip6 in parallel
// and admits each family's ACL-approved addresses into the dial race as
// soon as that family completes:
//
//   - the first-arriving family starts dialing immediately,
//   - a late-arriving family is ACL-filtered and deduplicated against the
//     already-admitted set, then merged at the tail of the start queue
//     while no winner exists and the total deadline has not passed,
//   - a winner (or total-deadline expiry / request cancellation) cancels
//     the other family's in-flight lookup,
//   - per-family resolver order is preserved, and explicit tcp4/tcp6
//     callers never dial the other family.
//
// The scheduling policy is unchanged from dialTCPAddresses (7307332):
// 250 ms stagger, 100 ms minimum spacing after failures, 5 s per-attempt
// cap, single winner, total deadline (including DNS) carried by ctx.
// Error mapping is unchanged: DNS all-failed -> 502 (504 when the cause
// is a deadline/timeout), all ACL-denied -> 403, all dials failed ->
// 502/504.

// tcpFamilyFeed carries ACL-approved candidates admitted per family into
// the TCP dial race. Admission order within a family preserves resolver
// order; a late family is appended at the tail of the start queue (RFC
// 8305 section 6 dynamic candidate update).
type tcpFamilyFeed struct {
	mu   sync.Mutex
	v4   []string
	v6   []string
	seen map[string]struct{}
	// closed is true once both family lookups have completed (success or
	// failure); no further admissions are possible.
	closed bool
	wake   chan struct{}

	errV4, errV6 error
	passedACL    int
}

func newTCPFamilyFeed() *tcpFamilyFeed {
	return &tcpFamilyFeed{
		seen: make(map[string]struct{}, 8),
		wake: make(chan struct{}, 1),
	}
}

func (f *tcpFamilyFeed) pulse() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// popLocked returns the next candidate under the lazy interleave rule
// that reproduces interleaveTCPAddresses for a static set (first-family
// count one, then strict alternation). lastFamily is 0 before the first
// start; a simultaneous first-arrival tie breaks to v6 (the RFC 6724
// order observed from the production pure-Go resolver on the verified
// deployment host). Callers hold f.mu.
func (f *tcpFamilyFeed) popLocked(lastFamily byte) (string, bool) {
	if len(f.v4) == 0 && len(f.v6) == 0 {
		return "", false
	}
	takeV6 := false
	switch lastFamily {
	case 0: // first candidate: v6-first tie-break
		takeV6 = len(f.v6) > 0
	case 4: // last start was v4: prefer v6, else keep v4
		takeV6 = len(f.v6) > 0
	default: // last start was v6: prefer v4, else keep v6
		takeV6 = len(f.v4) == 0
	}
	if takeV6 {
		addr := f.v6[0]
		f.v6 = f.v6[1:]
		return addr, true
	}
	addr := f.v4[0]
	f.v4 = f.v4[1:]
	return addr, true
}

// advance returns the next candidate only when a start is due (spacing
// satisfied), plus the feed state for the termination check.
func (f *tcpFamilyFeed) advance(due bool, lastFamily byte) (string, bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	empty := len(f.v4) == 0 && len(f.v6) == 0
	if due && !empty {
		if addr, ok := f.popLocked(lastFamily); ok {
			return addr, f.closed, false
		}
	}
	return "", f.closed, empty
}

// finalError maps the feed's terminal state to the same error classes the
// legacy path maps:
//
//   - both families failed (DNS all-failed, including all-NODATA):
//     targetPolicyLookupFailed -> 502, or 504 when the cause is a
//     deadline/timeout;
//   - at least one family answered but every address was ACL-denied:
//     targetPolicyNoAllowedAddress -> 403;
//   - addresses passed ACL but none matched the requested family:
//     errTCPDialFailed -> 502 (matches the legacy tcp4/tcp6 mapping);
//   - at least one dial started: the last dial error (502/504 mapping).
func (f *tcpFamilyFeed) finalError(started int, lastErr error) error {
	if started > 0 {
		if lastErr == nil {
			return errTCPDialFailed
		}
		return lastErr
	}
	if f.errV4 != nil && f.errV6 != nil {
		return &targetPolicyFailure{kind: targetPolicyLookupFailed, cause: f.errV4}
	}
	if f.passedACL == 0 {
		return &targetPolicyFailure{kind: targetPolicyNoAllowedAddress}
	}
	return errTCPDialFailed
}

// lookupIPFamilyDefault is the production per-family resolver: one query
// per address family, each honoring ctx (deadline and cancellation).
func lookupIPFamilyDefault(ctx context.Context, family, host string) ([]net.IPAddr, error) {
	addrs, err := net.DefaultResolver.LookupIP(ctx, family, host)
	if err != nil {
		return nil, err
	}
	result := make([]net.IPAddr, 0, len(addrs))
	for _, ip := range addrs {
		result = append(result, net.IPAddr{IP: ip})
	}
	return result, nil
}

// dialTCPIncremental resolves the target per address family and races
// ACL-approved candidates as each family completes. ctx carries the total
// deadline (including DNS) and request cancellation.
func (h *Handler) dialTCPIncremental(ctx context.Context, network, host, port string) (net.Conn, error) {
	lookup := h.lookupIPFamily
	if lookup == nil {
		lookup = lookupIPFamilyDefault
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	feed := newTCPFamilyFeed()
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		resolve := func(family string, isV6 bool) {
			defer wg.Done()
			addrs, err := lookup(ctx, family, host)
			added := false
			feed.mu.Lock()
			if err != nil {
				if isV6 {
					feed.errV6 = err
				} else {
					feed.errV4 = err
				}
			} else {
				for _, a := range addrs {
					ip := a.IP
					if ip == nil {
						continue
					}
					if !h.hostIsAllowed(host, ip) {
						continue
					}
					feed.passedACL++
					v4 := ip.To4() != nil
					if v4 == isV6 {
						continue // family mismatch from the resolver; never dial
					}
					if network == "tcp4" && !v4 || network == "tcp6" && v4 {
						continue
					}
					addr := net.JoinHostPort(ip.String(), port)
					if _, dup := feed.seen[addr]; dup {
						continue
					}
					feed.seen[addr] = struct{}{}
					if isV6 {
						feed.v6 = append(feed.v6, addr)
					} else {
						feed.v4 = append(feed.v4, addr)
					}
					added = true
				}
			}
			feed.mu.Unlock()
			if added {
				feed.pulse()
			}
		}
		go resolve("ip4", false)
		go resolve("ip6", true)
		wg.Wait()
		feed.mu.Lock()
		feed.closed = true
		feed.mu.Unlock()
		feed.pulse()
	}()

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
			// An unbuffered handoff gives exactly one winner ownership.
			// Late successful losers must close even when cancellation
			// races success.
			select {
			case results <- result{conn, err}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}

	var (
		started    int
		pending    int
		lastStart  time.Time
		lastFamily byte
		lastErr    error
	)
	timer := time.NewTimer(tcpFallbackDelay)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	familyByte := func(address string) byte {
		ipHost, _, err := net.SplitHostPort(address)
		if err != nil {
			return 0
		}
		if ip := net.ParseIP(ipHost); ip != nil && ip.To4() != nil {
			return 4
		}
		return 6
	}

	for {
		due := started == 0 || time.Since(lastStart) >= tcpMinimumDelay
		if addr, closed, empty := feed.advance(due, lastFamily); addr != "" {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			start(addr)
			started++
			pending++
			lastStart = time.Now()
			lastFamily = familyByte(addr)
			timer.Reset(tcpFallbackDelay)
			continue
		} else if closed && empty && pending == 0 {
			return nil, feed.finalError(started, lastErr)
		}
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
			// Accelerate failures while retaining the minimum spacing,
			// mirroring the production scheduler.
			timer.Reset(max(0, tcpMinimumDelay-time.Since(lastStart)))
		case <-feed.wake:
		case <-timer.C:
		}
	}
}
