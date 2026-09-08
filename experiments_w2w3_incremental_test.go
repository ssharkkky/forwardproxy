//go:build w2w3

// W2 experiment: incremental candidate prototype (isolated experiment, not
// production code). Instead of waiting for the merged LookupIPAddr result,
// w2w3IncrementalDial consumes a stream of per-family resolver result
// batches and starts dialing as soon as the first family's addresses are
// known.
//
// Policy is identical to dialTCPAddresses:
//   - 250 ms stagger between attempt starts,
//   - 100 ms minimum spacing after failures,
//   - 5 s per-attempt timeout,
//   - the first successful dial wins and cancels all outstanding work,
//   - the caller's context carries the total deadline.
//
// Safety properties (mirroring resolveTargetCheckACL):
//   - every candidate passes the handler ACL before dialing,
//   - candidates are deduplicated across batches,
//   - after the stream closes, if no candidate ever succeeded the dial
//     returns the last recorded error.
package forwardproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// w2w3Batch is one per-family resolver result event.
type w2w3Batch struct {
	family string // "v4" | "v6" (experiment label only)
	addrs  []string
	err    error
}

// w2w3IncrementalDial is the prototype scheduler described above.
func w2w3IncrementalDial(ctx context.Context, h *Handler, host string, stream <-chan w2w3Batch) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex
	var candidates []string
	seen := map[string]struct{}{}
	streamClosed := false
	var lastBatchErr error

	go func() {
		defer func() {
			mu.Lock()
			streamClosed = true
			mu.Unlock()
		}()
		for batch := range stream {
			if batch.err != nil {
				mu.Lock()
				if lastBatchErr == nil {
					lastBatchErr = batch.err
				}
				mu.Unlock()
			}
			added := false
			mu.Lock()
			for _, a := range batch.addrs {
				ipHost, _, err := net.SplitHostPort(a)
				if err != nil {
					continue
				}
				ip := net.ParseIP(ipHost)
				if ip == nil || !h.hostIsAllowed(host, ip) {
					continue // never dial an unapproved address
				}
				if _, dup := seen[a]; dup {
					continue
				}
				seen[a] = struct{}{}
				candidates = append(candidates, a)
				added = true
			}
			mu.Unlock()
			if added {
				select {
				case w2w3Wake <- struct{}{}:
				default:
				}
			}
		}
	}()

	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)

	next := 0
	pending := 0
	var lastStart time.Time
	started := false
	var lastErr error

	start := func(address string) {
		go func() {
			attemptCtx, attemptCancel := context.WithTimeout(ctx, tcpAttemptTimeout)
			conn, err := h.dialContext(attemptCtx, "tcp", address)
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

	// tryStart returns true if it started the next candidate. The spacing
	// rule matches dialTCPAddresses: at least tcpMinimumDelay after the
	// previous start.
	tryStart := func() bool {
		mu.Lock()
		if next >= len(candidates) {
			mu.Unlock()
			return false
		}
		if started && time.Since(lastStart) < tcpMinimumDelay {
			mu.Unlock()
			return false
		}
		address := candidates[next]
		mu.Unlock()
		start(address)
		next++
		pending++
		started = true
		lastStart = time.Now()
		return true
	}

	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-w2w3Wake:
			if tryStart() {
				timer.Reset(tcpFallbackDelay)
			}
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
			mu.Lock()
			done := next >= len(candidates) && streamClosed
			mu.Unlock()
			if done && pending == 0 {
				if lastErr == nil {
					return nil, errTCPDialFailed
				}
				return nil, lastErr
			}
			if !tryStart() {
				// Accelerate the next start opportunity while keeping the
				// minimum spacing, mirroring the production scheduler.
				timer.Reset(max(0, tcpMinimumDelay-time.Since(lastStart)))
			} else {
				timer.Reset(tcpFallbackDelay)
			}
			continue
		case <-timer.C:
			if !tryStart() {
				// No candidate available yet: re-arm the minimum-spacing
				// poll so late-arriving batches are picked up promptly
				// (they are also pushed through w2w3Wake).
				timer.Reset(tcpMinimumDelay)
			}
		}
	}
}

// w2w3Wake is a process-wide pulse channel used by the prototype's stream
// goroutine. It is safe for this experiment because only one incremental
// run executes at a time in the test binary.
var w2w3Wake = make(chan struct{}, 16)

// w2w3IncCase is one incremental-vs-current comparison case.
type w2w3IncCase struct {
	id          string
	v4          w2w3Family
	v6          w2w3Family
	v4Addrs     []string
	v6Addrs     []string
	winnerIP    string // the address the dial fixture succeeds on
	winnerFirst bool   // winner is the first-arriving candidate
}

// w2w3RunIncremental drives the prototype with a modeled resolver stream
// (v4 batch at v4.delay, v6 batch at v6.delay, then the stream closes).
func (c *w2w3IncCase) runIncremental(t *testing.T, run int) w2w3Run {
	t.Helper()
	start := time.Now()
	row := w2w3Run{ID: c.id, Mode: "incremental", Run: run}

	stream := make(chan w2w3Batch, 4)
	batchFor := func(f w2w3Family, addrs []string, family string) {
			b := w2w3Batch{family: family}
			switch f.kind {
			case "answer":
				for _, a := range addrs {
					b.addrs = append(b.addrs, net.JoinHostPort(a, "443"))
				}
			case "drop":
				b.err = &net.DNSError{Err: "i/o timeout", Name: "w2w3", IsTimeout: true}
			case "error":
				b.err = errors.New("dns: simulated SERVFAIL")
			case "nodata":
			}
			if f.delay > 0 {
				select {
				case <-time.After(f.delay):
				}
			}
			stream <- b
		}
	go func() {
		defer close(stream)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); batchFor(c.v4, c.v4Addrs, "v4") }()
		go func() { defer wg.Done(); batchFor(c.v6, c.v6Addrs, "v6") }()
		wg.Wait()
	}()

	var winConn net.Conn
	winner, peer := net.Pipe()
	peer.Close()
	t.Cleanup(func() { winner.Close() })
	winConn = winner
	d := &w2w3Dial{winner: net.JoinHostPort(c.winnerIP, "443"), winConn: winConn}

	h := &Handler{
		aclRules:    []aclRule{&aclAllRule{allow: true}},
		dialContext: d.dial,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := w2w3IncrementalDial(ctx, h, "target.example", stream)
	if conn != nil {
		conn.Close()
	}

	row.TFirstms = msSince(start, d.tFirst)
	row.TConnms = msSince(start, d.tWin)
	row.Attempts = d.attemptCount()
	if err == nil {
		row.Status = "200"
		row.Winner = d.winnerAttempt()
	} else {
		row.Status = "error"
		row.Err = err.Error()
	}
	return row
}

// w2w3RunCurrent drives the production path (dialContextCheckACL) for the
// same case, using the merged-lookup fixture.
func (c *w2w3IncCase) runCurrent(t *testing.T, run int) w2w3Run {
	t.Helper()
	// Only include families that actually answered (the production
	// resolver returns the merged answer of the families that had data).
	var answered []string
	if c.v4.kind == "answer" {
		answered = append(answered, c.v4Addrs...)
	}
	if c.v6.kind == "answer" {
		answered = append(answered, c.v6Addrs...)
	}
	scen := w2w3Scenario{
		id:            c.id,
		v4:            c.v4,
		v6:            c.v6,
		resolverOrder: answered,
	}
	if c.winnerFirst {
		scen.winner = "first"
	} else {
		scen.winner = "second"
	}
	row := scen.runOnce(t, "current", run, 0)
	row.ID = c.id
	return row
}

func TestW2W3IncrementalComparison(t *testing.T) {
	// Superseded for the Route B production path (per-family
	// incremental resolution): TestW2W3RouteBMatrix plus the untagged
	// connect_dial_incremental_test.go re-verify the same scenarios
	// against the shipped path. Kept as a historical artifact of the W2
	// merged-lookup measurement.
	t.Skip("superseded by TestW2W3RouteBMatrix and untagged incremental tests")
	const repeats = 30
	cases := []w2w3IncCase{
		{
			// C1: no skew — both families answer fast. The prototype must
			// not change the outcome (winner is the second candidate).
			id: "C1_both_fast",
			v4: w2w3Family{kind: "answer", delay: 10 * time.Millisecond},
			v6: w2w3Family{kind: "answer", delay: 10 * time.Millisecond},
			v4Addrs: []string{w2w3V4a}, v6Addrs: []string{w2w3V6a},
			winnerIP: w2w3V6a, winnerFirst: false,
		},
		{
			// C2: A fast, AAAA delayed — winner is the fast A address.
			// Current path waits for the full lookup; incremental dials at
			// the first batch.
			id: "C2_v4_fast_v6_slow",
			v4: w2w3Family{kind: "answer", delay: 10 * time.Millisecond},
			v6: w2w3Family{kind: "answer", delay: 500 * time.Millisecond},
			v4Addrs: []string{w2w3V4a}, v6Addrs: []string{w2w3V6a},
			winnerIP: w2w3V4a, winnerFirst: true,
		},
		{
			// C3: A query dropped (modeled resolver timeout), AAAA fast —
			// winner is the fast AAAA address.
			id: "C3_v4_drop_v6_ok",
			v4: w2w3Family{kind: "drop", delay: 2 * time.Second},
			v6: w2w3Family{kind: "answer", delay: 10 * time.Millisecond},
			v4Addrs: []string{w2w3V4a}, v6Addrs: []string{w2w3V6a},
			winnerIP: w2w3V6a, winnerFirst: true,
		},
		{
			// C4: AAAA query dropped, A fast — winner is the fast A address.
			id: "C4_v6_drop_v4_ok",
			v4: w2w3Family{kind: "answer", delay: 10 * time.Millisecond},
			v6: w2w3Family{kind: "drop", delay: 2 * time.Second},
			v4Addrs: []string{w2w3V4a}, v6Addrs: []string{w2w3V6a},
			winnerIP: w2w3V4a, winnerFirst: true,
		},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			var curConn, incConn []float64
			for i := 1; i <= repeats; i++ {
				cur := c.runCurrent(t, i)
				w2w3AppendJSONL(t, "w2_incremental.jsonl", cur)
				inc := c.runIncremental(t, i)
				w2w3AppendJSONL(t, "w2_incremental.jsonl", inc)
				// Invariants for both sides.
				for _, row := range []w2w3Run{cur, inc} {
					if row.Status != "200" {
						t.Fatalf("%s %s: status=%s err=%s", c.id, row.Mode, row.Status, row.Err)
					}
					if row.Winner != net.JoinHostPort(c.winnerIP, "443") {
						t.Fatalf("%s %s: winner=%s", c.id, row.Mode, row.Winner)
					}
				}
				if cur.TConnms > 0 {
					curConn = append(curConn, cur.TConnms)
				}
				if inc.TConnms > 0 {
					incConn = append(incConn, inc.TConnms)
				}
			}
			summary := w2w3Summary{
				ID: c.id + "_delta", Mode: "summary", N: repeats,
				StatusOK: repeats,
				TConn: w2w3Pct{
					P50: w2w3Percentile(curConn, 0.5) - w2w3Percentile(incConn, 0.5),
					P95: w2w3Percentile(curConn, 0.95) - w2w3Percentile(incConn, 0.95),
					Max: w2w3Percentile(curConn, 1.0) - w2w3Percentile(incConn, 1.0),
				},
			}
			w2w3AppendJSONL(t, "w2_incremental_summary.jsonl", summary)
			t.Logf("%s: current-vs-incremental t_conn delta (p50/p95/max) = %v ms",
				c.id, summary.TConn)
		})
	}
}
