//go:build w2w3

// W3 experiment: A/B matrix of the current forwardproxy TCP scheduler
// (7307332: 250 ms stagger, 100 ms post-failure minimum, 5 s per-attempt
// timeout) against Go 1.26.0's built-in net.Dialer Happy Eyeballs
// (FallbackDelay 250 ms; Go's default 300 ms reported separately).
//
// Both paths run through the same controlled target world and the same DNS
// scenario table:
//
//   - current: Handler.dialContextCheckACL (production entry) with the
//     injected lookup fixture and the world dial wrapper (h.dialContext);
//   - he:      net.Dialer (stdlib) with the fixture resolver and the world
//     applied in ControlContext (ACL gate + per-run behavior).
//
// Recorded per request: status (200/502/504), t_dns (DNS-stage completion),
// t_first (first dial start), t_conn (winner established), attempts, denied
// (ACL rejections), winner, plus per-run peak in-flight dials and peak
// goroutines. Only aggregate values and the RFC 2606 / loopback candidate
// addresses are recorded.
package forwardproxy

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Pre-declared comparison parameters (fixed before running the matrix).
const (
	w3FallbackMS     = 250 // primary comparison: matches tcpFallbackDelay
	w3FallbackAltMS  = 300 // Go default, reported separately
	w3TotalDeadline  = 12 * time.Second
	w3HappyHeadroom  = 100 * time.Millisecond // B1: HE p95 may lead by at most this on healthy dual scenarios
	w3MaxPeakDials   = 4   // B4: single-request scenarios
	w3GorHeadroom    = 40  // B4: per-run goroutine headroom over baseline
	w3FDHeadroom     = 2   // B4: post-batch fd headroom over baseline
	w3GorSettleHead  = 2   // B4: post-settle goroutine headroom
	w3FlakySeedBase  = 2026090882
	w3RTTSeedBase    = 2026090881
	w3RTTDelay       = 100 * time.Millisecond
	w3RTTJitter      = 20 * time.Millisecond
)

// w3Row is one recorded request.
type w3Row struct {
	ID       string   `json:"id"`
	Path     string   `json:"path"`
	Req      int      `json:"req"`
	Run      int      `json:"run"`
	Status   string   `json:"status"`
	Err      string   `json:"err,omitempty"`
	TDNSms   float64  `json:"t_dns_ms"`
	TFirstms float64  `json:"t_first_ms"`
	TConnms  float64  `json:"t_conn_ms"`
	Attempts int      `json:"attempts"`
	Denied   int      `json:"denied"`
	TryList  []string `json:"attempts_list,omitempty"`
	DenyList []string `json:"denied_list,omitempty"`
	Winner       string `json:"winner,omitempty"`
	PeakDials    int64  `json:"peak_dials,omitempty"`
	PeakGoroutes int64  `json:"peak_goroutines,omitempty"`
}

// w3RoundRow summarizes one concurrency round.
type w3RoundRow struct {
	ID             string  `json:"id"`
	Path           string  `json:"path"`
	Round          int     `json:"round"`
	N              int     `json:"n"`
	N200           int     `json:"n200"`
	N502           int     `json:"n502"`
	N504           int     `json:"n504"`
	RoundMs        float64 `json:"round_ms"`
	PeakDials      int64   `json:"peak_dials"`
	PeakGoroutines int64   `json:"peak_goroutines"`
}

// w3Summary is the per-(scenario, path, req) aggregate.
type w3Summary struct {
	ID         string  `json:"id"`
	Path       string  `json:"path"`
	Req        int     `json:"req"`
	N          int     `json:"n"`
	N200       int     `json:"n200"`
	N502       int     `json:"n502"`
	N504       int     `json:"n504"`
	TDNS       w3Pct   `json:"t_dns_ms"`
	TConn      w3Pct   `json:"t_conn_ms"`
	Attempts   w3PctI  `json:"attempts"`
	MinConnMS  float64 `json:"min_conn_ms"`
}

type w3Pct struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
}

type w3PctI struct {
	P50 int `json:"p50"`
	Max int `json:"max"`
}

func w3PctOf(vals []float64) w3Pct {
	if len(vals) == 0 {
		return w3Pct{}
	}
	return w3Pct{
		P50: w2w3Percentile(vals, 0.50),
		P95: w2w3Percentile(vals, 0.95),
		P99: w2w3Percentile(vals, 0.99),
	}
}

func w3PctIOf(vals []int) w3PctI {
	if len(vals) == 0 {
		return w3PctI{}
	}
	f := make([]float64, len(vals))
	for i, v := range vals {
		f[i] = float64(v)
	}
	max := vals[0]
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	return w3PctI{P50: int(w2w3Percentile(f, 0.50)), Max: max}
}

// w3DNSPair is one request's DNS family behavior (both paths).
type w3DNSPair struct {
	V4, V6          w3DNSAnswer
	ResolverOrder   []string // merged addresses in resolver (RFC 6724) order
}

// w3Scenario is one controlled comparison scenario.
type w3Scenario struct {
	ID        string
	Network   string // "tcp" | "tcp4"
	Repeats   int
	Rounds    int // concurrency rounds (0/1 = sequential single requests)
	Parallel  int // requests per round (default 1)
	Total     time.Duration
	CancelAfter time.Duration
	// Per-request DNS behavior (req 0, and req 1 for the DNS-change case).
	DNS []w3DNSPair
	// Static per-scenario target kinds (world layout).
	V4Kinds, V6Kinds []w3CandidateKind
	// Per-run behavior builder. Called once per path per run with a fresh
	// seeded RNG (same seed on both paths => same per-candidate draws).
	Behaviors func(runIdx int) map[string]w3Behavior
	// Candidate ids denied by the ACL.
	Deny []string
	// Expectations.
	WantStatus string
	// WantStatusHE optionally expects a different HE status (as-implemented
	// divergence, e.g. H21's resolver partial-answer difference).
	WantStatusHE string
	Check      func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World)
}

func (s *w3Scenario) dns(reqIdx int) w3DNSPair {
	if reqIdx < len(s.DNS) {
		return s.DNS[reqIdx]
	}
	return s.DNS[0]
}

// w3IP maps a candidate id to its placeholder IP.
func w3IP(id string) string {
	switch id {
	case "v4a":
		return w3V4a
	case "v4b":
		return w3V4b
	case "v4c":
		return w3V4c
	case "v4d":
		return w3V4d
	case "v6a":
		return w3V6a
	case "v6b":
		return w3V6b
	case "v6c":
		return w3V6c
	case "v6d":
		return w3V6d
	}
	panic("unknown candidate " + id)
}

// w3Behavior builders.
func w3BehOK(ids ...string) map[string]w3Behavior {
	m := map[string]w3Behavior{}
	for _, id := range ids {
		m[id] = w3Behavior{kind: "ok"}
	}
	return m
}

func w3BehRefuse(ids ...string) map[string]w3Behavior {
	m := map[string]w3Behavior{}
	for _, id := range ids {
		m[id] = w3Behavior{kind: "refuse"}
	}
	return m
}

func w3BehBlackhole(ids ...string) map[string]w3Behavior {
	m := map[string]w3Behavior{}
	for _, id := range ids {
		m[id] = w3Behavior{kind: "blackhole"}
	}
	return m
}

func w3BehTargeted(at time.Duration, ids ...string) map[string]w3Behavior {
	m := map[string]w3Behavior{}
	for _, id := range ids {
		m[id] = w3Behavior{kind: "targeted", targetAt: at}
	}
	return m
}

func w3MergeMaps(maps ...map[string]w3Behavior) map[string]w3Behavior {
	out := map[string]w3Behavior{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// w3RNG returns the per-run seeded RNG for a candidate (same seed on both
// paths so per-candidate draws are identical).
func w3RNG(seedBase int64, runIdx int, id string) *rand.Rand {
	idx := 0
	for _, c := range id {
		idx = idx*31 + int(c)
	}
	return rand.New(rand.NewSource(seedBase + int64(runIdx)*7919 + int64(idx)))
}

// w3Delayed builds per-run delayed behaviors with seeded jitter.
func w3Delayed(seedBase int64, runIdx int, delay, jitter time.Duration, ids ...string) map[string]w3Behavior {
	m := map[string]w3Behavior{}
	for _, id := range ids {
		m[id] = w3Behavior{kind: "delayed", delay: delay, jitter: jitter, rng: w3RNG(seedBase, runIdx, id)}
	}
	return m
}

// w3Flaky builds per-run flaky behaviors (p = 0.5 loss).
func w3Flaky(seedBase int64, runIdx int, ids ...string) map[string]w3Behavior {
	m := map[string]w3Behavior{}
	for _, id := range ids {
		m[id] = w3Behavior{kind: "flaky", lossProb: 0.5, jitter: w3RTTJitter, rng: w3RNG(seedBase, runIdx, id)}
	}
	return m
}

// ---------------------------------------------------------------------------
// Current-path driver (production entry: Handler.dialContextCheckACL).
// ---------------------------------------------------------------------------

// w3LookupFixture models the production pure-Go resolver's A+AAAA
// wait-for-both semantics for the current path, mirroring the behavior the
// W2 real-resolver probe measured on this toolchain:
//   - each family sub-query completes at its delay (drop: never),
//   - the lookup completes when both are done or the context dies,
//   - if at least one family answered, the merged addresses are returned
//     (sub-query errors not propagated), including at context death,
//   - otherwise a DNSError is returned (IsTimeout on deadline expiry).
type w3LookupFixture struct {
	pair w3DNSPair
	mu   sync.Mutex
	done time.Time
}

func (fx *w3LookupFixture) lookup(ctx context.Context, host string) ([]net.IPAddr, error) {
	s := fx.pair
	v4Done := make(chan struct{})
	v6Done := make(chan struct{})
	go w3SubQuery(ctx, s.V4, v4Done)
	go w3SubQuery(ctx, s.V6, v6Done)
	finished := false
	for _, ch := range []chan struct{}{v4Done, v6Done} {
		select {
		case <-ch:
			finished = true
		case <-ctx.Done():
			finished = false
		}
		if !finished {
			break
		}
	}
	addrs := w3Merged(s.ResolverOrder)
	if !finished {
		fx.record()
		if ctx.Err() == context.DeadlineExceeded {
			if s.V4.Kind == "answer" || s.V6.Kind == "answer" {
				return addrs, nil // partial answer at deadline (W2 P4)
			}
			return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
		}
		return nil, ctx.Err()
	}
	fx.record()
	if s.V4.Kind == "answer" || s.V6.Kind == "answer" {
		return addrs, nil
	}
	if s.V4.Kind == "servfail" || s.V6.Kind == "servfail" {
		return nil, &net.DNSError{Err: "server failure (simulated SERVFAIL)", Name: host}
	}
	return nil, &net.DNSError{Err: "no answer from DNS server", Name: host}
}

func (fx *w3LookupFixture) record() {
	fx.mu.Lock()
	if fx.done.IsZero() {
		fx.done = time.Now()
	}
	fx.mu.Unlock()
}

func (fx *w3LookupFixture) doneAt() time.Time {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return fx.done
}

func w3SubQuery(ctx context.Context, fam w3DNSAnswer, done chan struct{}) {
	defer close(done)
	if fam.Kind == "drop" {
		<-ctx.Done()
		return
	}
	select {
	case <-time.After(fam.Delay):
	case <-ctx.Done():
	}
}

// w3Merged maps the ordered candidate ids to their placeholder IPs (the
// merged resolver result in RFC 6724 order).
func w3Merged(order []string) []net.IPAddr {
	var out []net.IPAddr
	for _, id := range order {
		out = append(out, net.IPAddr{IP: net.ParseIP(w3IP(id))})
	}
	return out
}

// w3DriveCurrent runs one request on the production path. sharedBehav
// skips setRun (concurrency rounds configure the world once).
func w3DriveCurrent(t *testing.T, w *w3World, fx *w3DNSFixture, scen *w3Scenario, runIdx, reqIdx int, pathLabel string, sharedBehav bool) w3Row {
	t.Helper()
	row := w3Row{ID: scen.ID, Path: pathLabel, Req: reqIdx, Run: runIdx}
	pair := scen.dns(reqIdx)
	name := w3Name(scen.ID, runIdx, reqIdx)

	rs := &w3RunState{}
	start := time.Now()
	rs.tRunStart = start
	if !sharedBehav {
		behav := map[string]w3Behavior{}
		if scen.Behaviors != nil {
			behav = scen.Behaviors(runIdx)
		}
		w.setRun(behav, scen.approvedSet())
	}

	lfix := &w3LookupFixture{pair: pair}
	h := Handler{
		HideIP:      true,
		DialTimeout: caddy.Duration(30 * time.Second),
		aclRules:    w3ACLRules(t, scen.denyIPs()),
	}
	h.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return w.dialTargetTo(ctx, network, address, rs)
	}
	h.lookupIP = lfix.lookup

	ctx, cancel := w3RequestCtx(scen)
	defer cancel()

	conn, err := h.dialContextCheckACL(ctx, scen.Network, name+":443")
	row.TDNSms = msSince(start, lfix.doneAt())
	if rs.tFirst != (time.Time{}) {
		row.TFirstms = msSince(start, rs.tFirst)
	}
	row.Attempts = len(rs.attemptsList())
	row.Denied = len(rs.deniedList())
	row.TryList = rs.attemptsList()
	if len(row.TryList) > 0 {
		row.DenyList = rs.deniedList()
	}
	peakDials, peakGor := w.endRun()
	row.PeakDials = peakDials
	row.PeakGoroutes = peakGor

	if err != nil {
		var handlerErr caddyhttp.HandlerError
		status := "502"
		if errors.As(err, &handlerErr) {
			status = strconv.Itoa(handlerErr.StatusCode)
		}
		row.Status = status
		row.Err = err.Error()
		row.TConnms = msSince(start, time.Now())
	} else {
		row.Status = "200"
		// Symmetric with the HE driver: t_conn is measured when the
		// scheduler hands a usable connection to the caller.
		row.TConnms = msSince(start, time.Now())
		row.Winner = w.candidateOf(conn.RemoteAddr().String())
		conn.Close()
	}
	return row
}

// ---------------------------------------------------------------------------
// HE-path driver (stdlib net.Dialer Happy Eyeballs prototype).
// ---------------------------------------------------------------------------

// w3DriveHE runs one request on the stdlib Happy Eyeballs prototype.
func w3DriveHE(t *testing.T, w *w3World, fx *w3DNSFixture, scen *w3Scenario, runIdx, reqIdx int, pathLabel string, fallbackDelay time.Duration, sharedBehav bool) w3Row {
	t.Helper()
	row := w3Row{ID: scen.ID, Path: pathLabel, Req: reqIdx, Run: runIdx}
	pair := scen.dns(reqIdx)
	name := w3Name(scen.ID, runIdx, reqIdx)
	fx.behavior(name, pair.V4, pair.V6)

	rs := &w3RunState{}
	start := time.Now()
	rs.tRunStart = start
	if !sharedBehav {
		behav := map[string]w3Behavior{}
		if scen.Behaviors != nil {
			behav = scen.Behaviors(runIdx)
		}
		w.setRun(behav, scen.approvedSet())
	}

	dialer := w3HEDialer(t, w, fx, rs, fallbackDelay)

	ctx, cancel := w3RequestCtx(scen)
	defer cancel()

	conn, err := dialer.DialContext(ctx, scen.Network, name+":443")
	row.TDNSms = msSince(start, fx.answeredAt(name))
	if !rs.tFirst.IsZero() {
		row.TFirstms = msSince(start, rs.tFirst)
	}
	row.Attempts = len(rs.attemptsList())
	row.Denied = len(rs.deniedList())
	row.TryList = rs.attemptsList()
	if len(row.TryList) > 0 {
		row.DenyList = rs.deniedList()
	}
	peakDials, peakGor := w.endRun()
	row.PeakDials = peakDials
	row.PeakGoroutes = peakGor

	if err != nil {
		status, class := w3ClassifyHEError(ctx, err)
		row.Status = strconv.Itoa(status)
		row.Err = class + ": " + err.Error()
		row.TConnms = msSince(start, time.Now())
	} else {
		row.Status = "200"
		row.TConnms = msSince(start, time.Now())
		row.Winner = w.candidateOf(conn.RemoteAddr().String())
		conn.Close()
	}
	return row
}

func w3Name(id string, runIdx, reqIdx int) string {
	if reqIdx > 0 {
		return fmt.Sprintf("w3-%s-r%d-q%d.example", strings.ToLower(id), runIdx, reqIdx)
	}
	return fmt.Sprintf("w3-%s-r%d.example", strings.ToLower(id), runIdx)
}

// w3RequestCtx builds the request context with the scenario's total
// deadline (and optional early cancellation).
func w3RequestCtx(scen *w3Scenario) (context.Context, context.CancelFunc) {
	total := scen.Total
	if total <= 0 {
		total = w3TotalDeadline
	}
	if scen.CancelAfter > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-time.After(scen.CancelAfter):
			case <-ctx.Done():
			}
			cancel()
		}()
		return ctx, cancel
	}
	return context.WithTimeout(context.Background(), total)
}

func (s *w3Scenario) approvedSet() map[string]bool {
	m := map[string]bool{}
	// Every candidate that appears in any request's resolver order or
	// per-family list is approved unless explicitly denied.
	seen := map[string]bool{}
	for _, pair := range s.DNS {
		for _, id := range pair.ResolverOrder {
			if !seen[id] {
				seen[id] = true
				m[id] = true
			}
		}
	}
	for _, id := range s.Deny {
		if seen[id] {
			m[id] = false
		}
	}
	return m
}

func (s *w3Scenario) denyIPs() []string {
	out := make([]string, 0, len(s.Deny))
	for _, id := range s.Deny {
		out = append(out, w3IP(id))
	}
	return out
}

func w3ACLRules(t *testing.T, denyIPs []string) []aclRule {
	t.Helper()
	rules := make([]aclRule, 0, 1+len(denyIPs))
	for _, ip := range denyIPs {
		r, err := newACLRule(ip, false)
		if err != nil {
			t.Fatalf("w3 acl rule %s: %v", ip, err)
		}
		rules = append(rules, r)
	}
	rules = append(rules, &aclAllRule{allow: true})
	return rules
}

// ---------------------------------------------------------------------------
// Scenario table (pre-declared, fixed before the matrix run).
// ---------------------------------------------------------------------------

func w3Answer(addrs ...string) w3DNSAnswer {
	return w3DNSAnswer{Kind: "answer", Addrs: addrs, Record: true}
}

func w3AnswerDelayed(d time.Duration, addrs ...string) w3DNSAnswer {
	return w3DNSAnswer{Kind: "answer", Delay: d, Addrs: addrs, Record: true}
}

var w3Scenarios = []w3Scenario{
	{
		ID: "H1", Network: "tcp", Repeats: 30, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior { return w3BehOK("v4a", "v6a") },
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if cur.Winner != "v6a" {
				t.Errorf("H1 run %d: current winner %s, want v6a", runIdx, cur.Winner)
			}
			if he.Winner != "v6a" {
				t.Errorf("H1 run %d: HE winner %s, want v6a (first-listed family is primary)", runIdx, he.Winner)
			}
		},
	},
	{
		ID: "H2", Network: "tcp", Repeats: 30, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindBlackhole},
		V6Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior {
			return w3MergeMaps(w3BehOK("v6a"), w3BehBlackhole("v4a"))
		},
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if cur.Winner != "v6a" || he.Winner != "v6a" {
				t.Errorf("H2 run %d: winners cur=%s he=%s, want v6a/v6a", runIdx, cur.Winner, he.Winner)
			}
			if he.TConnms > 200 {
				t.Errorf("H2 run %d: HE t_conn %.0fms, primary family should win in ~1ms", runIdx, he.TConnms)
			}
		},
	},
	{
		ID: "H3", Network: "tcp", Repeats: 30, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindBlackhole},
		Behaviors: func(runIdx int) map[string]w3Behavior {
			return w3MergeMaps(w3BehOK("v4a"), w3BehBlackhole("v6a"))
		},
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if cur.Winner != "v4a" || he.Winner != "v4a" {
				t.Errorf("H3 run %d: winners cur=%s he=%s, want v4a/v4a", runIdx, cur.Winner, he.Winner)
			}
			// Both paths wait ~250 ms for the second family to start.
			if he.TConnms < 240 || he.TConnms > 400 {
				t.Errorf("H3 run %d: HE t_conn %.0fms, want ~250-300ms (fallback window)", runIdx, he.TConnms)
			}
			if cur.TConnms < 240 || cur.TConnms > 400 {
				t.Errorf("H3 run %d: current t_conn %.0fms, want ~250-300ms (stagger)", runIdx, cur.TConnms)
			}
		},
	},
	{
		ID: "H4", Network: "tcp", Repeats: 15, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a, w3V4b), V6: w3Answer(w3V6a, w3V6b),
			ResolverOrder: []string{"v6a", "v4a", "v6b", "v4b"},
		}},
		V4Kinds: []w3CandidateKind{w3KindBlackhole, w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindBlackhole, w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior {
			return w3MergeMaps(w3BehOK("v4b", "v6b"), w3BehBlackhole("v4a", "v6a"))
		},
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if cur.Winner != "v6b" {
				t.Errorf("H4 run %d: current winner %s, want v6b (250ms stagger reaches it)", runIdx, cur.Winner)
			}
			if he.Winner != "v6b" {
				t.Errorf("H4 run %d: HE winner %s, want v6b (primary family's second candidate)", runIdx, he.Winner)
			}
			if cur.TConnms > 1500 {
				t.Errorf("H4 run %d: current t_conn %.0fms too slow", runIdx, cur.TConnms)
			}
			if he.TConnms < 4500 || he.TConnms > 9000 {
				t.Errorf("H4 run %d: HE t_conn %.0fms, want ~6s (first candidate's full slice)", runIdx, he.TConnms)
			}
		},
	},
	{
		ID: "H5", Network: "tcp", Repeats: 30, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a), V6: w3DNSAnswer{Kind: "nodata", Record: true},
			ResolverOrder: []string{"v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior { return w3BehOK("v4a") },
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if cur.Winner != "v4a" || he.Winner != "v4a" {
				t.Errorf("H5 run %d: winners cur=%s he=%s, want v4a", runIdx, cur.Winner, he.Winner)
			}
			if he.TConnms > 100 {
				t.Errorf("H5 run %d: HE t_conn %.0fms too slow (single family)", runIdx, he.TConnms)
			}
		},
	},
	{
		ID: "H6", Network: "tcp", Repeats: 30, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3DNSAnswer{Kind: "nodata", Record: true}, V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a"},
		}},
		V6Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior { return w3BehOK("v6a") },
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if cur.Winner != "v6a" || he.Winner != "v6a" {
				t.Errorf("H6 run %d: winners cur=%s he=%s, want v6a", runIdx, cur.Winner, he.Winner)
			}
			if he.TConnms > 100 {
				t.Errorf("H6 run %d: HE t_conn %.0fms too slow (single family)", runIdx, he.TConnms)
			}
		},
	},
	{
		ID: "H7", Network: "tcp", Repeats: 30, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindRefuse},
		V6Kinds: []w3CandidateKind{w3KindRefuse},
		Behaviors: func(runIdx int) map[string]w3Behavior { return w3BehRefuse("v4a", "v6a") },
		WantStatus: "502",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			// HE advances immediately after definitive failures; the current
			// scheduler keeps at least a 100 ms spacing after a failure.
			if he.TConnms > 200 {
				t.Errorf("H7 run %d: HE t_conn %.0fms too slow (immediate advance expected)", runIdx, he.TConnms)
			}
			if cur.TConnms > 500 {
				t.Errorf("H7 run %d: current t_conn %.0fms too slow", runIdx, cur.TConnms)
			}
		},
	},
	{
		ID: "H8", Network: "tcp", Repeats: 30, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior {
			return w3MergeMaps(
				w3Delayed(w3RTTSeedBase, runIdx, w3RTTDelay, w3RTTJitter, "v4a"),
				w3Delayed(w3RTTSeedBase, runIdx, w3RTTDelay, w3RTTJitter, "v6a"))
		},
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if cur.Winner != "v6a" || he.Winner != "v6a" {
				t.Errorf("H8 run %d: winners cur=%s he=%s, want v6a (first candidate wins on both)", runIdx, cur.Winner, he.Winner)
			}
			// Both candidates are delayed 100-119ms; the first-listed
			// candidate (v6a) wins on both paths at ~delay + connect.
			if he.TConnms < 100 || he.TConnms > 260 {
				t.Errorf("H8 run %d: HE t_conn %.0fms out of band", runIdx, he.TConnms)
			}
			if cur.TConnms < 100 || cur.TConnms > 260 {
				t.Errorf("H8 run %d: current t_conn %.0fms out of band", runIdx, cur.TConnms)
			}
		},
	},
	{
		ID: "H9", Network: "tcp", Repeats: 30, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a, w3V4b), V6: w3Answer(w3V6a, w3V6b),
			ResolverOrder: []string{"v6a", "v4a", "v6b", "v4b"},
		}},
		V4Kinds: []w3CandidateKind{w3KindOK, w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindOK, w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior {
			return w3MergeMaps(
				w3Flaky(w3FlakySeedBase, runIdx, "v4a", "v6a"),
				w3BehOK("v4b", "v6b"))
		},
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			// Same per-candidate seeds on both paths: the same candidate
			// must win on both paths.
			if cur.Winner != he.Winner {
				t.Errorf("H9 run %d: winner mismatch cur=%s he=%s (same seed expected)", runIdx, cur.Winner, he.Winner)
			}
		},
	},
	{
		ID: "H10", Network: "tcp", Repeats: 10, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindBlackhole},
		V6Kinds: []w3CandidateKind{w3KindBlackhole},
		Behaviors: func(runIdx int) map[string]w3Behavior { return w3BehBlackhole("v4a", "v6a") },
		WantStatus: "504",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			// Current: candidates start on the 250 ms stagger timer while
			// earlier attempts stay pending, each capped at 5 s; both
			// blackholes therefore surface at ~250+5001 ms.
			// HE: candidate slices span until the full 12 s deadline.
			if cur.TConnms < 5050 || cur.TConnms > 5600 {
				t.Errorf("H10 run %d: current t_conn %.0fms, want ~5.25s", runIdx, cur.TConnms)
			}
			if he.TConnms < 11000 || he.TConnms > 13000 {
				t.Errorf("H10 run %d: HE t_conn %.0fms, want ~12s", runIdx, he.TConnms)
			}
		},
	},
	{
		ID: "H11", Network: "tcp", Rounds: 10, Parallel: 20, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a, w3V4b), V6: w3Answer(w3V6a, w3V6b),
			ResolverOrder: []string{"v6a", "v4a", "v6b", "v4b"},
		}},
		V4Kinds: []w3CandidateKind{w3KindBlackhole, w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindBlackhole, w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior {
			return w3MergeMaps(w3BehOK("v4b", "v6b"), w3BehBlackhole("v4a", "v6a"))
		},
		WantStatus: "200",
	},
	{
		ID: "H12", Network: "tcp", Repeats: 30, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a, w3V4b), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a", "v4b"},
		}},
		V4Kinds: []w3CandidateKind{w3KindRefuse, w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindRefuse},
		Behaviors: func(runIdx int) map[string]w3Behavior {
			return w3MergeMaps(w3BehRefuse("v4a", "v6a"), w3BehOK("v4b"))
		},
		Deny:       []string{"v4b"},
		WantStatus: "502",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			// Current: v4b filtered before dialing (0 dials to it).
			for _, id := range cur.TryList {
				if id == "v4b" {
					t.Errorf("H12 run %d: current dialed denied v4b", runIdx)
				}
			}
			// HE: v4b dialed exactly once and rejected by the ACL gate.
			if he.Denied != 1 {
				t.Errorf("H12 run %d: HE denied=%d, want 1", runIdx, he.Denied)
			}
			if w.deniedTargetConns() != 0 {
				t.Errorf("H12 run %d: denied candidate saw %d connections", runIdx, w.deniedTargetConns())
			}
		},
	},
	{
		ID: "H13", Network: "tcp", Repeats: 20, Total: w3TotalDeadline,
		DNS: []w3DNSPair{
			{
				V4: w3Answer(w3V4a), V6: w3Answer(w3V6a),
				ResolverOrder: []string{"v6a", "v4a"},
			},
			{
				V4: w3DNSAnswer{Kind: "nodata", Record: true}, V6: w3Answer(w3V6a),
				ResolverOrder: []string{"v6a"},
			},
		},
		V4Kinds: []w3CandidateKind{w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior { return w3BehOK("v4a", "v6a") },
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if reqIdx == 0 {
				if cur.Winner != "v6a" || he.Winner != "v6a" {
					t.Errorf("H13 run %d: req0 winners cur=%s he=%s, want v6a", runIdx, cur.Winner, he.Winner)
				}
				return
			}
			// Request 2: v4a is no longer in the DNS answer set; neither
			// path may dial it.
			if cur.Winner != "v6a" || he.Winner != "v6a" {
				t.Errorf("H13 run %d: req1 winners cur=%s he=%s, want v6a", runIdx, cur.Winner, he.Winner)
			}
			for _, id := range append(append([]string{}, cur.TryList...), he.TryList...) {
				if id == "v4a" {
					t.Errorf("H13 run %d: req1 dialed stale v4a (path %s)", runIdx, "both")
				}
			}
		},
	},
	{
		ID: "H14", Network: "tcp", Repeats: 30, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3DNSAnswer{Kind: "nodata", Record: true}, V6: w3DNSAnswer{Kind: "nodata", Record: true},
			ResolverOrder: nil,
		}},
		WantStatus: "502",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if cur.Attempts != 0 || he.Attempts != 0 {
				t.Errorf("H14 run %d: attempts cur=%d he=%d, want 0/0 (DNS failed)", runIdx, cur.Attempts, he.Attempts)
			}
			if cur.TConnms > 1000 || he.TConnms > 1000 {
				t.Errorf("H14 run %d: too slow cur=%.0f he=%.0f", runIdx, cur.TConnms, he.TConnms)
			}
		},
	},
	{
		ID: "H15", Network: "tcp", Repeats: 10, Total: w3TotalDeadline, CancelAfter: time.Second,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindBlackhole},
		V6Kinds: []w3CandidateKind{w3KindBlackhole},
		Behaviors: func(runIdx int) map[string]w3Behavior { return w3BehBlackhole("v4a", "v6a") },
		WantStatus: "502",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if cur.TConnms < 900 || cur.TConnms > 1500 {
				t.Errorf("H15 run %d: current cancel t %.0fms, want ~1000ms", runIdx, cur.TConnms)
			}
			if he.TConnms < 900 || he.TConnms > 1500 {
				t.Errorf("H15 run %d: HE cancel t %.0fms, want ~1000ms", runIdx, he.TConnms)
			}
		},
	},
	{
		ID: "H16", Network: "tcp", Repeats: 20, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior {
			return w3MergeMaps(w3BehTargeted(280*time.Millisecond, "v4a"), w3BehTargeted(280*time.Millisecond, "v6a"))
		},
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			// Genuine simultaneous success: exactly one winner on each path.
			if cur.Winner != "v4a" && cur.Winner != "v6a" {
				t.Errorf("H16 run %d: current winner %q invalid", runIdx, cur.Winner)
			}
			if he.Winner != "v4a" && he.Winner != "v6a" {
				t.Errorf("H16 run %d: HE winner %q invalid", runIdx, he.Winner)
			}
			if cur.TConnms < 270 || cur.TConnms > 700 {
				t.Errorf("H16 run %d: current t_conn %.0fms out of band", runIdx, cur.TConnms)
			}
			if he.TConnms < 270 || he.TConnms > 700 {
				t.Errorf("H16 run %d: HE t_conn %.0fms out of band", runIdx, he.TConnms)
			}
		},
	},
	{
		ID: "H17", Network: "tcp", Repeats: 10, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior {
			return w3MergeMaps(w3BehTargeted(310*time.Millisecond, "v4a"), w3BehTargeted(410*time.Millisecond, "v6a"))
		},
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			// v4a completes at 310 ms on both paths; v6a's late success at
			// 410 ms must be a closed loser.
			if cur.Winner != "v4a" || he.Winner != "v4a" {
				t.Errorf("H17 run %d: winners cur=%s he=%s, want v4a", runIdx, cur.Winner, he.Winner)
			}
			if w.activeTargetConns() != 0 {
				t.Errorf("H17 run %d: %d target connections still open (late loser not closed)", runIdx, w.activeTargetConns())
			}
		},
	},
	{
		ID: "H18", Network: "tcp", Rounds: 5, Parallel: 10, Total: w3TotalDeadline, CancelAfter: 200 * time.Millisecond,
		DNS: []w3DNSPair{{
			V4: w3Answer(w3V4a), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior {
			return w3MergeMaps(w3BehTargeted(500*time.Millisecond, "v4a"), w3BehTargeted(500*time.Millisecond, "v6a"))
		},
		WantStatus: "502",
	},
	{
		ID: "H19", Network: "tcp4", Repeats: 10, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3DNSAnswer{Kind: "nodata", Record: true}, V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a"},
		}},
		V6Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior { return w3BehOK("v6a") },
		WantStatus: "502",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if cur.Attempts != 0 {
				t.Errorf("H19 run %d: current attempts %d, want 0 (tcp4 with no v4)", runIdx, cur.Attempts)
			}
			if he.Attempts != 0 {
				t.Errorf("H19 run %d: HE attempts %d, want 0 (tcp4 with no v4)", runIdx, he.Attempts)
			}
			if w.targets["v6a"].acceptedCount() != 0 {
				t.Errorf("H19 run %d: v6 target accepted %d connections under tcp4", runIdx, w.targets["v6a"].acceptedCount())
			}
		},
	},
	{
		ID: "H20", Network: "tcp", Repeats: 20, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3AnswerDelayed(500*time.Millisecond, w3V4a), V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a", "v4a"},
		}},
		V4Kinds: []w3CandidateKind{w3KindOK},
		V6Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior { return w3BehOK("v4a", "v6a") },
		WantStatus: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			// Both paths wait for the full A+AAAA merge (~500 ms) and then
			// win on the first candidate within ~1-10 ms.
			if cur.TDNSms < 450 || cur.TDNSms > 900 {
				t.Errorf("H20 run %d: current t_dns %.0fms, want ~500ms", runIdx, cur.TDNSms)
			}
			if he.TDNSms < 450 || he.TDNSms > 900 {
				t.Errorf("H20 run %d: HE t_dns %.0fms, want ~500ms", runIdx, he.TDNSms)
			}
			if cur.TConnms < 500 || cur.TConnms > 900 {
				t.Errorf("H20 run %d: current t_conn %.0fms, want ~510ms", runIdx, cur.TConnms)
			}
			if he.TConnms < 500 || he.TConnms > 900 {
				t.Errorf("H20 run %d: HE t_conn %.0fms, want ~505ms", runIdx, he.TConnms)
			}
		},
	},
	{
		ID: "H21", Network: "tcp", Repeats: 3, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3DNSAnswer{Kind: "drop", Record: true}, V6: w3Answer(w3V6a),
			ResolverOrder: []string{"v6a"},
		}},
		V6Kinds: []w3CandidateKind{w3KindOK},
		Behaviors: func(runIdx int) map[string]w3Behavior { return w3BehOK("v6a") },
		WantStatus:   "504",
		WantStatusHE: "200",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			// As-implemented divergence on a dropped A sub-query:
			//  - current: the W2 wait-for-both lookup model blocks until
			//    the total deadline, after which the dial cannot start
			//    (504 at ~12 s);
			//  - HE: Go 1.26's resolver retries the dropped A query
			//    (2 x 5 s attempts), then returns the partial AAAA answer
			//    at ~10 s; the dial starts and connects (~200 at ~10 s).
			if cur.TConnms < 11000 || cur.TConnms > 13000 {
				t.Errorf("H21 run %d: current t_conn %.0fms, want ~12s", runIdx, cur.TConnms)
			}
			if he.TConnms < 9500 || he.TConnms > 10500 {
				t.Errorf("H21 run %d: HE t_conn %.0fms, want ~10s", runIdx, he.TConnms)
			}
			if he.Winner != "v6a" {
				t.Errorf("H21 run %d: HE winner %s, want v6a", runIdx, he.Winner)
			}
		},
	},
	{
		ID: "H22", Network: "tcp", Repeats: 10, Total: w3TotalDeadline,
		DNS: []w3DNSPair{{
			V4: w3DNSAnswer{Kind: "servfail", Record: true}, V6: w3DNSAnswer{Kind: "servfail", Record: true},
			ResolverOrder: nil,
		}},
		WantStatus: "502",
		Check: func(t *testing.T, cur, he w3Row, scen *w3Scenario, runIdx, reqIdx int, w *w3World) {
			if cur.Attempts != 0 || he.Attempts != 0 {
				t.Errorf("H22 run %d: attempts cur=%d he=%d, want 0/0", runIdx, cur.Attempts, he.Attempts)
			}
		},
	},
}

// ---------------------------------------------------------------------------
// Matrix runner.
// ---------------------------------------------------------------------------

// w3FDCount returns the process fd count (leak baseline).
func w3FDCount() int {
	d, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(d)
}

// w3EstablishedTo443 counts ESTABLISHED kernel connections to the W3
// candidate addresses (leak check; TIME_WAIT is tolerated and disclosed).
// The host runs unrelated outbound :443 traffic, so the check is scoped
// to the candidate remotes (little-endian hex encoding of /proc/net/tcp*).
func w3EstablishedTo443() int {
	v4 := map[string]bool{
		"0B00007F": true, // 127.0.0.11
		"0C00007F": true, // 127.0.0.12
		"0D00007F": true, // 127.0.0.13
		"0E00007F": true, // 127.0.0.14
	}
	v6 := map[string]bool{
		"B80D0120000030000000000011000000": true, // 2001:db8:30::11
		"B80D0120000030000000000012000000": true, // 2001:db8:30::12
		"B80D0120000030000000000013000000": true, // 2001:db8:30::13
		"B80D0120000030000000000014000000": true, // 2001:db8:30::14
	}
	n := 0
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		allowed := v4
		if strings.HasSuffix(file, "tcp6") {
			allowed = v6
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 4 {
				continue
			}
			if f[3] != "01" { // ESTABLISHED
				continue
			}
			rem := f[2]
			i := strings.LastIndex(rem, ":")
			if i < 0 || rem[i+1:] != "01BB" { // 443 hex
				continue
			}
			if allowed[strings.ToUpper(rem[:i])] {
				n++
			}
		}
	}
	return n
}

func w3StatusCounts(rows []w3Row) (n200, n502, n504 int) {
	for _, r := range rows {
		switch r.Status {
		case "200":
			n200++
		case "502":
			n502++
		case "504":
			n504++
		}
	}
	return
}

// w3RunScenario runs one scenario on both paths and enforces invariants.
func w3RunScenario(t *testing.T, scen *w3Scenario) {
	t.Helper()
	// The world layout must cover the static kinds of every candidate the
	// scenario dials; refuse candidates need no listener.
	world := w3StartWorld(t, scen.V4Kinds, scen.V6Kinds)
	fx, _, _, stop := w3StartDNSFixture(t)
	defer stop()
	t0 := w3FDCount()

	gorBaseline := runtimeNumGoroutine()

	if scen.Rounds > 0 {
		w3RunConcurrency(t, world, fx, scen, t0, gorBaseline, false, 0, "current")
		w3RunConcurrency(t, world, fx, scen, t0, gorBaseline, true, time.Duration(w3FallbackMS)*time.Millisecond, "he250")
		return
	}

	for runIdx := 0; runIdx < scen.Repeats; runIdx++ {
		reqs := 1
		if len(scen.DNS) > 1 {
			reqs = len(scen.DNS)
		}
		for reqIdx := 0; reqIdx < reqs; reqIdx++ {
			cur := w3DriveCurrent(t, world, fx, scen, runIdx, reqIdx, "current", false)
			he := w3DriveHE(t, world, fx, scen, runIdx, reqIdx, "he250", time.Duration(w3FallbackMS)*time.Millisecond, false)
			w2w3AppendJSONL(t, "w3_matrix.jsonl", cur)
			w2w3AppendJSONL(t, "w3_matrix.jsonl", he)
			w3collect(cur, he)
			wantCur := scen.WantStatus
			wantHE := scen.WantStatus
			if scen.WantStatusHE != "" {
				wantHE = scen.WantStatusHE
			}
			if wantCur != "" && cur.Status != wantCur {
				t.Errorf("%s run %d req %d: cur status %s, want %s (err: %s)", scen.ID, runIdx, reqIdx, cur.Status, wantCur, cur.Err)
			}
			if wantHE != "" && he.Status != wantHE {
				t.Errorf("%s run %d req %d: HE status %s, want %s (err: %s)", scen.ID, runIdx, reqIdx, he.Status, wantHE, he.Err)
			}
			if cur.PeakDials > w3MaxPeakDials {
				t.Errorf("%s run %d: current peak dials %d > %d", scen.ID, runIdx, cur.PeakDials, w3MaxPeakDials)
			}
			if he.PeakDials > w3MaxPeakDials {
				t.Errorf("%s run %d: HE peak dials %d > %d", scen.ID, runIdx, he.PeakDials, w3MaxPeakDials)
			}
			if scen.Check != nil {
				scen.Check(t, cur, he, scen, runIdx, reqIdx, world)
			}
		}
	}
	w3PostBatchCheck(t, world, scen.ID, t0, gorBaseline)
}

// w3PostBatchCheck enforces the B4 cleanup budget after one scenario batch.
func w3PostBatchCheck(t *testing.T, world *w3World, id string, fdBaseline, gorBaseline int) {
	t.Helper()
	// Settle: late losers and target-side readers drain.
	time.Sleep(150 * time.Millisecond)
	if n := world.activeTargetConns(); n != 0 {
		t.Errorf("%s post-batch: %d target connections still open", id, n)
	}
	if n := world.deniedTargetConns(); n != 0 {
		t.Errorf("%s post-batch: %d connections reached denied candidates", id, n)
	}
	if n := w3EstablishedTo443(); n != 0 {
		t.Errorf("%s post-batch: %d ESTABLISHED kernel connections to :443 remain", id, n)
	}
	if fd := w3FDCount(); fd > fdBaseline+w3FDHeadroom {
		t.Errorf("%s post-batch: fd count %d exceeds baseline %d + %d", id, fd, fdBaseline, w3FDHeadroom)
	}
	time.Sleep(150 * time.Millisecond)
	if g := runtimeNumGoroutine(); g > gorBaseline+w3GorSettleHead {
		t.Errorf("%s post-batch: goroutines %d exceed baseline %d + %d", id, g, gorBaseline, w3GorSettleHead)
	}
}

// runtimeNumGoroutine indirection keeps the matrix imports tidy.
func runtimeNumGoroutine() int {
	return runtime.NumGoroutine()
}

// w3RunConcurrency runs the scenario's concurrency rounds on one path.
func w3RunConcurrency(t *testing.T, world *w3World, fx *w3DNSFixture, scen *w3Scenario, fdBaseline, gorBaseline int, isHE bool, fallback time.Duration, pathLabel string) {
	t.Helper()
	for round := 0; round < scen.Rounds; round++ {
		behav := map[string]w3Behavior{}
		if scen.Behaviors != nil {
			behav = scen.Behaviors(round)
		}
		world.setRun(behav, scen.approvedSet())
		start := time.Now()
		rows := make([]w3Row, scen.Parallel)
		var wg sync.WaitGroup
		for i := 0; i < scen.Parallel; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if isHE {
					rows[i] = w3DriveHE(t, world, fx, scen, round, i, pathLabel, fallback, true)
				} else {
					rows[i] = w3DriveCurrent(t, world, fx, scen, round, i, pathLabel, true)
				}
			}(i)
		}
		wg.Wait()
		roundMs := float64(time.Since(start)) / float64(time.Millisecond)
		peakDials, peakGor := world.endRun()
		n200, n502, n504 := w3StatusCounts(rows)
		rr := w3RoundRow{
			ID: scen.ID, Path: pathLabel, Round: round, N: scen.Parallel,
			N200: n200, N502: n502, N504: n504,
			RoundMs: roundMs, PeakDials: peakDials, PeakGoroutines: peakGor,
		}
		w2w3AppendJSONL(t, "w3_matrix.jsonl", rr)
		if scen.WantStatus == "200" && n200 != scen.Parallel {
			t.Errorf("%s round %d (%s): n200=%d, want %d", scen.ID, round, pathLabel, n200, scen.Parallel)
		}
		if scen.WantStatus == "502" && n502 != scen.Parallel {
			t.Errorf("%s round %d (%s): n502=%d, want %d", scen.ID, round, pathLabel, n502, scen.Parallel)
		}
		for i, r := range rows {
			w2w3AppendJSONL(t, "w3_matrix.jsonl", r)
			w3collect(r)
			if r.Status != scen.WantStatus {
				t.Errorf("%s round %d req %d (%s): status %s, want %s", scen.ID, round, i, pathLabel, r.Status, scen.WantStatus)
			}
			if peakDials > int64(scen.Parallel)*w3MaxPeakDials {
				t.Errorf("%s round %d (%s): peak dials %d > %d", scen.ID, round, pathLabel, peakDials, scen.Parallel*w3MaxPeakDials)
			}
		}
	}
	w3PostBatchCheck(t, world, scen.ID+"-"+pathLabel, fdBaseline, gorBaseline)
}

// ---------------------------------------------------------------------------
// Test entry points.
// ---------------------------------------------------------------------------

// w3Collect rows across the matrix for the summary/budget pass.
var (
	w3CollectMu sync.Mutex
	w3Collect   []w3Row
)

func w3collect(rows ...w3Row) {
	w3CollectMu.Lock()
	defer w3CollectMu.Unlock()
	w3Collect = append(w3Collect, rows...)
}

// TestW3Matrix runs the pre-declared A/B scenario table on both paths.
func TestW3Matrix(t *testing.T) {
	// Superseded for the Route B production path (per-family
	// incremental resolution): TestW2W3RouteBMatrix plus the untagged
	// connect_dial_incremental_test.go re-verify the same scenarios
	// against the shipped path. Kept as a historical artifact of the W2
	// merged-lookup measurement.
	t.Skip("superseded by TestW2W3RouteBMatrix and untagged incremental tests")
	w3CollectMu.Lock()
	w3Collect = nil
	w3CollectMu.Unlock()
	for i := range w3Scenarios {
		sc := &w3Scenarios[i]
		t.Run(sc.ID, func(t *testing.T) {
			w3RunScenario(t, sc)
		})
	}
	w3Summarize(t, w3CollectRows())
}

func w3CollectRows() []w3Row {
	w3CollectMu.Lock()
	defer w3CollectMu.Unlock()
	out := make([]w3Row, len(w3Collect))
	copy(out, w3Collect)
	return out
}

// w3Summarize writes per-(scenario,path,req) aggregates and enforces the
// B1 happy-path headroom budget (HE p95 t_conn may lead the current path's
// p95 by at most w3HappyHeadroom on healthy dual scenarios).
func w3Summarize(t *testing.T, rows []w3Row) {
	t.Helper()
	type key struct{ id, path string; req int }
	byKey := map[key][]w3Row{}
	for _, r := range rows {
		k := key{r.ID, r.Path, r.Req}
		byKey[k] = append(byKey[k], r)
	}
	healthy := map[string]bool{"H1": true, "H5": true, "H6": true, "H8": true, "H16": true, "H17": true, "H20": true}
	for k, rs := range byKey {
		if len(rs) == 0 {
			continue
		}
		sum := w3Summary{ID: k.id, Path: k.path, Req: k.req, N: len(rs)}
		var tConn []float64
		var tDNS []float64
		var atts []int
		minConn := 0.0
		for _, r := range rs {
			switch r.Status {
			case "200":
				sum.N200++
			case "502":
				sum.N502++
			case "504":
				sum.N504++
			}
			tConn = append(tConn, r.TConnms)
			tDNS = append(tDNS, r.TDNSms)
			atts = append(atts, r.Attempts)
			if minConn == 0 || r.TConnms < minConn {
				minConn = r.TConnms
			}
		}
		sum.TConn = w3PctOf(tConn)
		sum.TDNS = w3PctOf(tDNS)
		sum.Attempts = w3PctIOf(atts)
		sum.MinConnMS = minConn
		w2w3AppendJSONL(t, "w3_summary.jsonl", sum)

		if !healthy[k.id] {
			continue
		}
		cur, ok1 := byKey[key{k.id, "current", k.req}]
		he, ok2 := byKey[key{k.id, "he250", k.req}]
		if !ok1 || !ok2 || sum.N200 != len(rs) {
			continue
		}
		var curT, heT []float64
		for _, r := range cur {
			curT = append(curT, r.TConnms)
		}
		for _, r := range he {
			heT = append(heT, r.TConnms)
		}
		curP95 := w2w3Percentile(curT, 0.95)
		heP95 := w2w3Percentile(heT, 0.95)
		if heP95 > curP95+float64(w3HappyHeadroom)/float64(time.Millisecond) {
			t.Errorf("B1 %s: HE p95 t_conn %.0fms exceeds current p95 %.0fms + %v",
				k.id, heP95, curP95, w3HappyHeadroom)
		}
	}
}

// TestW3HE300 reports the same fast scenarios under Go's default
// FallbackDelay (300 ms) for the record (not part of the 250 ms A/B
// decision).
func TestW3HE300(t *testing.T) {
	// Superseded for the Route B production path (per-family
	// incremental resolution): TestW2W3RouteBMatrix plus the untagged
	// connect_dial_incremental_test.go re-verify the same scenarios
	// against the shipped path. Kept as a historical artifact of the W2
	// merged-lookup measurement.
	t.Skip("superseded by TestW2W3RouteBMatrix and untagged incremental tests")
	subset := map[string]bool{"H1": true, "H2": true, "H3": true, "H4": true, "H7": true, "H9": true}
	const repeats = 10
	for i := range w3Scenarios {
		sc := &w3Scenarios[i]
		if !subset[sc.ID] {
			continue
		}
		t.Run(sc.ID, func(t *testing.T) {
			world := w3StartWorld(t, sc.V4Kinds, sc.V6Kinds)
			fx, _, _, stop := w3StartDNSFixture(t)
			defer stop()
			t0 := w3FDCount()
			gorBaseline := runtimeNumGoroutine()
			for runIdx := 0; runIdx < repeats; runIdx++ {
				he := w3DriveHE(t, world, fx, sc, runIdx, 0, "he300", time.Duration(w3FallbackAltMS)*time.Millisecond, false)
				w2w3AppendJSONL(t, "w3_matrix.jsonl", he)
				if sc.WantStatus != "" && he.Status != sc.WantStatus {
					t.Errorf("%s he300 run %d: status %s, want %s (err: %s)", sc.ID, runIdx, he.Status, sc.WantStatus, he.Err)
				}
			}
			w3PostBatchCheck(t, world, sc.ID+"-he300", t0, gorBaseline)
		})
	}
}
