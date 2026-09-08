//go:build w2w3

// Route B experiment: incremental per-family DNS candidate admission for
// TCP CONNECT (RFC 8305 section 3-style dynamic candidate set, no
// Resolution Delay: first-arriving family dials first).
//
// The prototype w2w3RouteBDial is isolated (not production code). It
// replaces the single wait-for-both LookupIPAddr call with two parallel
// per-family lookups (ip4/ip6, shared request context) and admits each
// family's ACL-approved addresses into the dial race as soon as that
// family completes:
//
//   - first-arriving family's addresses start dialing immediately,
//   - a late-arriving family is ACL-filtered, deduplicated against the
//     already-admitted set, and merged at the tail of the start queue
//     only while no winner exists and the total deadline has not passed,
//   - a winner cancels the other family's in-flight lookup.
//
// The scheduling policy is unchanged from the audited scheduler (7307332):
// 250 ms stagger, 100 ms minimum spacing after failures, 5 s per-attempt
// cap, single winner, total deadline (including DNS) carried by ctx.
//
// Safety invariants asserted per run:
//   - every dialed address passed the handler ACL (denied: 0 dials),
//   - per-family resolver order is preserved,
//   - tcp4/tcp6 never dial the other family,
//   - 502 (DNS all-failed or no usable address) / 504 (timeout) mapping
//     matches the current path,
//   - no goroutine leaks, no late address starts a dial after a winner.
//
// Only aggregate timings are recorded (placeholder host "target.example",
// documentation-range addresses); results land in
// experiments/w2w3/results/.
package forwardproxy

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	w2w3BHost = "target.example"
	w2w3BPort = "443"
)

type w2w3BFamily struct {
	kind  string // "answer" | "nodata" | "error" | "drop"
	delay time.Duration
	addrs []string
}

// w2w3BFixture models per-family resolver sub-queries. Unlike the merged
// W2 fixture (which waited for both), each family completes independently
// after its own delay. Per the verified Go 1.26.0 pure-Go resolver, a
// NODATA family surfaces as a no-such-host error of that sub-query; a
// dropped exchange surfaces as an i/o timeout DNSError (IsTimeout).
// Cancellation of the shared context aborts a pending sub-query.
type w2w3BFixture struct {
	v4, v6                 w2w3BFamily
	mu                     sync.Mutex
	v4Canceled, v6Canceled bool
}

func (f *w2w3BFixture) lookupFamily(ctx context.Context, family, host string) ([]net.IPAddr, error) {
	fam, isV6 := f.v4, false
	if family == "ip6" {
		fam, isV6 = f.v6, true
	}
	var canceled bool
	select {
	case <-time.After(fam.delay):
	case <-ctx.Done():
		canceled = true
		f.mark(isV6, canceled)
		return nil, ctx.Err()
	}
	var err error
	switch fam.kind {
	case "answer":
	case "nodata":
		err = &net.DNSError{Err: "no such host (simulated NODATA)", Name: host, IsNotFound: true}
	case "error":
		err = &net.DNSError{Err: "server failure (simulated SERVFAIL)", Name: host}
	case "drop":
		err = &net.DNSError{Err: "i/o timeout (simulated dropped exchange)", Name: host, IsTimeout: true}
	}
	f.mark(isV6, false)
	if err != nil {
		return nil, err
	}
	var out []net.IPAddr
	for _, a := range fam.addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

func (f *w2w3BFixture) mark(isV6, canceled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if canceled {
		if isV6 {
			f.v6Canceled = true
		} else {
			f.v4Canceled = true
		}
	}
}

func (f *w2w3BFixture) canceled() (v4, v6 bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.v4Canceled, f.v6Canceled
}

// w2w3BFeed carries ACL-approved candidates admitted per family into the
// dial race. Admission order within a family preserves resolver order; a
// late family is appended at the tail of the start queue (dynamic
// candidate update per RFC 8305 section 6).
type w2w3BFeed struct {
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

func newW2w3BFeed() *w2w3BFeed {
	return &w2w3BFeed{
		seen: make(map[string]struct{}, 8),
		wake: make(chan struct{}, 1),
	}
}

func (f *w2w3BFeed) pulse() {
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
// host). Callers hold f.mu.
func (f *w2w3BFeed) popLocked(lastFamily byte) (string, bool) {
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
func (f *w2w3BFeed) advance(due bool, lastFamily byte) (string, bool, bool) {
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
// current path maps:
//
//   - both families failed (DNS all-failed, including all-NODATA):
//     targetPolicyLookupFailed -> 502, or 504 when the cause is a
//     deadline/timeout;
//   - at least one family answered but every address was ACL-denied:
//     targetPolicyNoAllowedAddress -> 403;
//   - addresses passed ACL but none matched the requested family:
//     errTCPDialFailed -> 502 (matches the current tcp4/tcp6 mapping);
//   - at least one dial started: the last dial error (502/504 mapping).
func (f *w2w3BFeed) finalError(started int, lastErr error) error {
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

// w2w3RouteBDial is the Route B prototype: parallel per-family lookups
// with incremental candidate admission feeding the audited scheduling
// policy. ctx carries the total deadline (including DNS).
func w2w3RouteBDial(ctx context.Context, h *Handler, host, port, network string,
	lookupFamily func(ctx context.Context, family, host string) ([]net.IPAddr, error)) (net.Conn, error) {

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	feed := newW2w3BFeed()
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		resolve := func(family string, isV6 bool) {
			defer wg.Done()
			addrs, err := lookupFamily(ctx, family, host)
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
						continue // family mismatch from the fixture; never dial
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

// w2w3BStatus maps a prototype result through the production error
// mapping (the same helpers the TCP CONNECT path uses).
func w2w3BStatus(err error, host, port string) string {
	if err == nil {
		return "200"
	}
	var mappable error
	var pol *targetPolicyFailure
	if errors.As(err, &pol) {
		if pol.kind == targetPolicyLookupFailed {
			mappable = tcpDialError(pol.cause)
		} else {
			mappable = legacyTargetPolicyError(pol, host, port)
		}
	} else {
		mappable = tcpDialError(err)
	}
	var handlerErr caddyhttp.HandlerError
	if errors.As(mappable, &handlerErr) {
		return strconv.Itoa(handlerErr.StatusCode)
	}
	return "error"
}

type w2w3BRun struct {
	ID           string  `json:"id"`
	Mode         string  `json:"mode"`
	Run          int     `json:"run"`
	Status       string  `json:"status"`
	Err          string  `json:"err,omitempty"`
	TFirstms     float64 `json:"t_first_ms"`
	TConnms      float64 `json:"t_conn_ms"`
	TErrms       float64 `json:"t_err_ms"`
	Attempts     int     `json:"attempts"`
	AttemptOrder string  `json:"attempt_order,omitempty"`
	Winner       string  `json:"winner,omitempty"`
	V4Canceled   bool    `json:"v4_canceled,omitempty"`
	V6Canceled   bool    `json:"v6_canceled,omitempty"`
}

// w2w3BScenario is one Route B matrix scenario with re-derived expected
// values under the incremental admission rules (see the file header).
type w2w3BScenario struct {
	id          string
	network     string
	v4, v6      w2w3BFamily
	winnerIP    string
	denyIPs     []string
	repeats     int
	cancelAfter time.Duration
	wantStatus  string
	wantOrder   []string
	// timing bands in ms; 0 disables a band.
	tFirstMaxMs float64
	tConnMinMs  float64
	tConnMaxMs  float64
	tErrMinMs   float64
	tErrMaxMs   float64
	// fixture cancellation assertions.
	wantV4Canceled, wantV6Canceled bool
}

func (s *w2w3BScenario) wantRepeats() int {
	if s.repeats > 0 {
		return s.repeats
	}
	switch s.id {
	case "D6_v4_drop_v6_ok", "D7_v6_drop_v4_ok", "D10_all_dropped":
		return 20
	}
	return 30
}

func (s *w2w3BScenario) runOnce(t *testing.T, run int) w2w3BRun {
	t.Helper()
	start := time.Now()
	row := w2w3BRun{ID: s.id, Mode: "routeb", Run: run}

	var dial *w2w3Dial
	if len(s.wantOrder) > 0 {
		winner, peer := net.Pipe()
		peer.Close()
		t.Cleanup(func() { winner.Close() })
		dial = &w2w3Dial{winner: net.JoinHostPort(s.winnerIP, w2w3BPort), winConn: winner}
	}

	h := Handler{
		HideIP:      true,
		DialTimeout: caddy.Duration(30 * time.Second),
		aclRules:    []aclRule{&aclAllRule{allow: true}},
	}
	for _, denied := range s.denyIPs {
		rule, err := newACLRule(denied, false)
		if err != nil {
			t.Fatalf("deny rule: %v", err)
		}
		h.aclRules = append([]aclRule{rule}, h.aclRules...)
	}
	if dial != nil {
		h.dialContext = dial.dial
	}

	fix := &w2w3BFixture{v4: s.v4, v6: s.v6}

	var baseCtx context.Context
	var cancel context.CancelFunc
	if s.cancelAfter > 0 {
		baseCtx, cancel = context.WithCancel(context.Background())
		go func() {
			select {
			case <-time.After(s.cancelAfter):
			case <-baseCtx.Done():
			}
			cancel()
		}()
	} else {
		baseCtx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	}
	t.Cleanup(cancel)

	conn, err := w2w3RouteBDial(baseCtx, &h, w2w3BHost, w2w3BPort, s.network, fix.lookupFamily)
	if conn != nil {
		conn.Close()
	}
	if err != nil {
		row.Err = err.Error()
		row.TErrms = msSince(start, time.Now())
	}
	row.Status = w2w3BStatus(err, w2w3BHost, w2w3BPort)
	if dial != nil {
		row.TFirstms = msSince(start, dial.tFirst)
		row.TConnms = msSince(start, dial.tWin)
		row.Attempts = dial.attemptCount()
		row.Winner = dial.winnerAttempt()
		row.AttemptOrder = dial.orderString()
	}
	// Settle so winner/timeout cancellation can drain the fixture
	// goroutines before the next measurement.
	time.Sleep(100 * time.Millisecond)
	row.V4Canceled, row.V6Canceled = fix.canceled()
	return row
}

// w2w3BMatrixScenarios is the re-derived D1-D11 matrix plus the new
// Route B scenarios. Dual-fast scenarios use a deterministic 15 ms gap
// (v6 answers first) instead of the W2 merged fixture's simultaneous
// answers, so the first-candidate tie-break is never exercised in a racy
// band; the tie-break itself is covered by a direct unit test of the pop
// rule in the production test suite.
func w2w3BMatrixScenarios() []w2w3BScenario {
	fast := 10 * time.Millisecond
	slow := 500 * time.Millisecond
	drop := 2 * time.Second
	v4a := w2w3Join(w2w3V4a)
	v6a := w2w3Join(w2w3V6a)
	return []w2w3BScenario{
		{
			// D1: dual-stack both fast (v6-first model). New: v6a is
			// the first candidate and wins immediately (old: v4a
			// blackholed, v6a wins at the 250 ms stagger, 2 attempts).
			id:       "D1_dual_fast_blackhole",
			v4:       w2w3BFamily{kind: "answer", delay: 25 * time.Millisecond, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V6a, wantStatus: "200", wantOrder: []string{v6a},
			tFirstMaxMs: 200, tConnMaxMs: 200,
		},
		{
			// D2: A fast / AAAA slow. New: first dial at the fast family
			// (~10 ms) instead of the full 500 ms lookup.
			id:       "D2_v4_fast_v6_slow",
			v4:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "answer", delay: slow, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V4a, wantStatus: "200", wantOrder: []string{v4a},
			tFirstMaxMs: 200, tConnMaxMs: 200,
		},
		{
			// D3: mirror of D2 (AAAA fast / A delayed).
			id:       "D3_v6_fast_v4_slow",
			v4:       w2w3BFamily{kind: "answer", delay: slow, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V6a, wantStatus: "200", wantOrder: []string{v6a},
			tFirstMaxMs: 200, tConnMaxMs: 200,
		},
		{
			// D4: A only (AAAA NODATA). Same outcome as the current path.
			id:       "D4_v4_only",
			v4:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "nodata", delay: fast},
			winnerIP: w2w3V4a, wantStatus: "200", wantOrder: []string{v4a},
			tFirstMaxMs: 200, tConnMaxMs: 200,
		},
		{
			// D5: AAAA only (A NODATA). Same outcome as the current path.
			id:       "D5_v6_only",
			v4:       w2w3BFamily{kind: "nodata", delay: fast},
			v6:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V6a, wantStatus: "200", wantOrder: []string{v6a},
			tFirstMaxMs: 200, tConnMaxMs: 200,
		},
		{
			// D6: A dropped (2 s model), AAAA fast. New: the fast family
			// dials immediately; the dropped family's error (after the
			// winner) must not delay anything. Old: gated on the 2 s
			// drop.
			id:       "D6_v4_drop_v6_ok",
			v4:       w2w3BFamily{kind: "drop", delay: drop},
			v6:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V6a, wantStatus: "200", wantOrder: []string{v6a},
			tFirstMaxMs: 200, tConnMaxMs: 200, wantV4Canceled: true,
		},
		{
			// D7: mirror of D6.
			id:       "D7_v6_drop_v4_ok",
			v4:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "drop", delay: drop},
			winnerIP: w2w3V4a, wantStatus: "200", wantOrder: []string{v4a},
			tFirstMaxMs: 200, tConnMaxMs: 200, wantV6Canceled: true,
		},
		{
			// D8: A SERVFAIL, AAAA answers. Same outcome as the current
			// path (partial success hides the failed family).
			id:       "D8_v4_servfail_v6_ok",
			v4:       w2w3BFamily{kind: "error", delay: fast},
			v6:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V6a, wantStatus: "200", wantOrder: []string{v6a},
			tFirstMaxMs: 200, tConnMaxMs: 200,
		},
		{
			// D9: both slow (300/400 ms). New: the first-completing
			// family (v4 at 300 ms) wins; v6 is discarded after the
			// winner. Old: gated on the 400 ms family.
			id:       "D9_both_slow",
			v4:       w2w3BFamily{kind: "answer", delay: 300 * time.Millisecond, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "answer", delay: 400 * time.Millisecond, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V4a, wantStatus: "200", wantOrder: []string{v4a},
			tConnMinMs: 250, tConnMaxMs: 500,
		},
		{
			// D10: both dropped -> DNS all-failed with IsTimeout errors
			// -> 504 (unchanged mapping), no dial.
			id:         "D10_all_dropped",
			v4:         w2w3BFamily{kind: "drop", delay: drop},
			v6:         w2w3BFamily{kind: "drop", delay: drop},
			wantStatus: "504", tErrMinMs: 1900,
		},
		{
			// D11: total cancellation at 100 ms while both lookups are
			// pending (5 s). No dial may start; both lookups must
			// observe cancellation (unchanged 502 mapping).
			id:          "D11_total_cancel",
			v4:          w2w3BFamily{kind: "answer", delay: 5 * time.Second, addrs: []string{w2w3V4a}},
			v6:          w2w3BFamily{kind: "answer", delay: 5 * time.Second, addrs: []string{w2w3V6a}},
			cancelAfter: 100 * time.Millisecond, wantStatus: "502",
			tErrMaxMs: 500, wantV4Canceled: true, wantV6Canceled: true,
		},
		{
			// D2w: warm control, v6-first model. New vs old: the
			// v6-first tie-break makes v6a the first candidate (old
			// fixture order was v4a first); v6a blackholes and v4a
			// wins at the 250 ms stagger.
			id:       "D2w_warm",
			v4:       w2w3BFamily{kind: "answer", delay: 12 * time.Millisecond, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "answer", delay: 2 * time.Millisecond, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V4a, wantStatus: "200", wantOrder: []string{v6a, v4a},
			tConnMinMs: 200, tConnMaxMs: 450,
		},
		{
			// N1: late family arrives after the winner: never dialed,
			// its lookup canceled, no leak.
			id:       "N1_late_after_winner",
			v4:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "answer", delay: slow, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V4a, wantStatus: "200", wantOrder: []string{v4a},
			tFirstMaxMs: 200, tConnMaxMs: 200, wantV6Canceled: true,
		},
		{
			// N2a: early-arriving family is ACL-denied: 0 dials to the
			// denied address; the allowed family wins.
			id:       "N2a_denied_early",
			v4:       w2w3BFamily{kind: "answer", delay: 25 * time.Millisecond, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V4a, denyIPs: []string{w2w3V6a}, wantStatus: "200",
			wantOrder: []string{v4a}, tConnMaxMs: 300,
		},
		{
			// N2b: late-arriving family is ACL-denied after the winner
			// already won: 0 dials to the denied address.
			id:       "N2b_denied_late",
			v4:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "answer", delay: slow, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V4a, denyIPs: []string{w2w3V6a}, wantStatus: "200",
			wantOrder: []string{v4a}, tConnMaxMs: 200,
		},
		{
			// N3: both families fail fast (SERVFAIL) -> 502, no dial
			// (DNS all-failed mapping, unchanged).
			id:         "N3_both_servfail",
			v4:         w2w3BFamily{kind: "error", delay: fast},
			v6:         w2w3BFamily{kind: "error", delay: fast},
			wantStatus: "502", tErrMaxMs: 500,
		},
		{
			// N4: total cancellation while lookups are in flight (2 s):
			// 502, no dial, both lookups canceled, no leak.
			id:          "N4_cancel_inflight",
			v4:          w2w3BFamily{kind: "answer", delay: 2 * time.Second, addrs: []string{w2w3V4a}},
			v6:          w2w3BFamily{kind: "answer", delay: 2 * time.Second, addrs: []string{w2w3V6a}},
			cancelAfter: 100 * time.Millisecond, wantStatus: "502",
			tErrMaxMs: 500, wantV4Canceled: true, wantV6Canceled: true,
		},
		{
			// N6: tcp4 with a dual-stack answer: the v6 address passes
			// ACL but is never dialed (family isolation).
			id: "N6_tcp4_dual", network: "tcp4",
			v4:       w2w3BFamily{kind: "answer", delay: 25 * time.Millisecond, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V4a, wantStatus: "200", wantOrder: []string{v4a},
			tConnMaxMs: 300,
		},
		{
			// N6b: tcp6 mirror.
			id: "N6b_tcp6_dual", network: "tcp6",
			v4:       w2w3BFamily{kind: "answer", delay: 25 * time.Millisecond, addrs: []string{w2w3V4a}},
			v6:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V6a}},
			winnerIP: w2w3V6a, wantStatus: "200", wantOrder: []string{v6a},
			tFirstMaxMs: 200, tConnMaxMs: 200,
		},
		{
			// N7: both families ACL-denied -> 403 (no allowed address),
			// 0 dials.
			id:      "N7_all_denied",
			v4:      w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V4a}},
			v6:      w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V6a}},
			denyIPs: []string{w2w3V4a, w2w3V6a}, wantStatus: "403",
		},
		{
			// N8: tcp6 with a v4-only answer: the address passes ACL but
			// none match the family -> 502, 0 dials (matches the
			// current tcp4/tcp6 empty-interleave mapping).
			id: "N8_tcp6_v4only", network: "tcp6",
			v4:         w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V4a}},
			v6:         w2w3BFamily{kind: "nodata", delay: fast},
			wantStatus: "502",
		},
		{
			// N9: multi-candidate per family, both fast: the lazy
			// interleave must reproduce the audited static order
			// [v6a, v4a, v6b] with the 250 ms stagger (winner is v6b).
			id:       "N9_multi_order",
			v4:       w2w3BFamily{kind: "answer", delay: 25 * time.Millisecond, addrs: []string{w2w3V4a, w2w3V4c}},
			v6:       w2w3BFamily{kind: "answer", delay: fast, addrs: []string{w2w3V6a, w2w3V6b}},
			winnerIP: w2w3V6b, wantStatus: "200",
			wantOrder:  []string{v6a, v4a, w2w3Join(w2w3V6b)},
			tConnMinMs: 450, tConnMaxMs: 800,
		},
	}
}

func w2w3BVerifyRow(t *testing.T, s *w2w3BScenario, row w2w3BRun) {
	t.Helper()
	if row.Status != s.wantStatus {
		t.Fatalf("%s: status=%s want %s (err=%s)", s.id, row.Status, s.wantStatus, row.Err)
	}
	wantOrder := strings.Join(s.wantOrder, ",")
	if row.AttemptOrder != wantOrder {
		t.Fatalf("%s: attempt order=%q want %q", s.id, row.AttemptOrder, wantOrder)
	}
	if len(s.wantOrder) > 0 {
		if row.Attempts != len(s.wantOrder) {
			t.Fatalf("%s: attempts=%d want %d", s.id, row.Attempts, len(s.wantOrder))
		}
		if row.Winner != net.JoinHostPort(s.winnerIP, w2w3BPort) {
			t.Fatalf("%s: winner=%s", s.id, row.Winner)
		}
	}
	if s.tFirstMaxMs > 0 && row.TFirstms > s.tFirstMaxMs {
		t.Fatalf("%s: first dial too late: %.1f ms", s.id, row.TFirstms)
	}
	if s.tConnMinMs > 0 && row.TConnms < s.tConnMinMs {
		t.Fatalf("%s: connection too early: %.1f ms (want > %v)", s.id, row.TConnms, s.tConnMinMs)
	}
	if s.tConnMaxMs > 0 && row.TConnms > s.tConnMaxMs {
		t.Fatalf("%s: connection too late: %.1f ms (want <= %v)", s.id, row.TConnms, s.tConnMaxMs)
	}
	if s.tErrMinMs > 0 && row.TErrms < s.tErrMinMs {
		t.Fatalf("%s: error too early: %.1f ms (want > %v)", s.id, row.TErrms, s.tErrMinMs)
	}
	if s.tErrMaxMs > 0 && row.TErrms > s.tErrMaxMs {
		t.Fatalf("%s: error too late: %.1f ms (want <= %v)", s.id, row.TErrms, s.tErrMaxMs)
	}
	if s.wantV4Canceled && !row.V4Canceled {
		t.Fatalf("%s: v4 lookup was not canceled", s.id)
	}
	if s.wantV6Canceled && !row.V6Canceled {
		t.Fatalf("%s: v6 lookup was not canceled", s.id)
	}
	for _, denied := range s.denyIPs {
		for _, a := range strings.Split(row.AttemptOrder, ",") {
			if a == net.JoinHostPort(denied, w2w3BPort) {
				t.Fatalf("%s: ACL-denied address was dialed: %s", s.id, denied)
			}
		}
	}
}

func TestW2W3RouteBMatrix(t *testing.T) {
	scenarios := w2w3BMatrixScenarios()
	baseGoroutines := runtime.NumGoroutine()
	for i := range scenarios {
		s := &scenarios[i]
		t.Run(s.id, func(t *testing.T) {
			repeats := s.wantRepeats()
			statuses := make([]string, 0, repeats)
			for i := 1; i <= repeats; i++ {
				row := s.runOnce(t, i)
				w2w3AppendJSONL(t, "w2_routeb_matrix.jsonl", row)
				w2w3BVerifyRow(t, s, row)
				statuses = append(statuses, row.Status)
			}
			summary := w2w3Summary{
				ID: s.id, Mode: "routeb", N: repeats,
				StatusOK: countStatus(statuses, s.wantStatus),
			}
			w2w3AppendJSONL(t, "w2_routeb_summary.jsonl", summary)
			t.Logf("%s: %v", s.id, summary)
		})
	}
	// Post-matrix leak budget: goroutine count must return to baseline
	// (W3 budget: baseline + 2).
	time.Sleep(200 * time.Millisecond)
	if leaked := runtime.NumGoroutine() - baseGoroutines; leaked > 2 {
		t.Fatalf("goroutine leak after matrix: %d above baseline", leaked)
	}
}

// orderString renders the recorded attempt order of the shared dial
// fixture (comma-separated dial addresses).
func (d *w2w3Dial) orderString() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.attempts, ",")
}

// w2w3Join renders an IP literal as a dial address (bracketed for v6).
func w2w3Join(ip string) string {
	return net.JoinHostPort(ip, w2w3BPort)
}
