package forwardproxy

// Untagged coverage for the per-family incremental resolution on the
// production TCP CONNECT path (connect_dial_incremental.go). The tagged
// experiments/w2w3 harness keeps the full scenario matrix; these tests
// gate the shipped invariants in the default build.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// incrDial records dial attempts. The configured winner returns a live
// pipe connection; with a winner configured, non-winners are blackholed
// until their dial context is canceled; with no winner, non-winners fail
// immediately (connection refused).
type incrDial struct {
	mu       sync.Mutex
	attempts []string
	tFirst   time.Time
	winner   string
}

func (d *incrDial) dial(ctx context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	now := time.Now()
	if d.tFirst.IsZero() {
		d.tFirst = now
	}
	d.attempts = append(d.attempts, address)
	isWinner := address == d.winner
	d.mu.Unlock()
	if isWinner {
		conn, peer := net.Pipe()
		go peer.Close()
		return conn, nil
	}
	if d.winner == "" {
		return nil, errors.New("refused")
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// familyFixture simulates one per-family resolver answer.
type familyFixture struct {
	// kind: "answer", "nodata", "error", "drop"
	kind  string
	delay time.Duration
	addrs []string

	mu       sync.Mutex
	canceled bool
}

func (f *familyFixture) lookup(ctx context.Context) ([]net.IPAddr, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			f.markCanceled()
			return nil, ctx.Err()
		}
	}
	switch f.kind {
	case "answer":
		var result []net.IPAddr
		for _, a := range f.addrs {
			result = append(result, net.IPAddr{IP: net.ParseIP(a)})
		}
		return result, nil
	case "nodata":
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	case "error":
		return nil, errors.New("dns server failure")
	case "drop":
		return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	}
	return nil, errors.New("bad fixture kind")
}

func (f *familyFixture) markCanceled() {
	f.mu.Lock()
	f.canceled = true
	f.mu.Unlock()
}

func (f *familyFixture) wasCanceled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.canceled
}

// incrHandler builds a production Handler with per-family resolution and
// attempt recording injected.
func incrHandler(v4, v6 *familyFixture, dialer *incrDial, denied ...string) Handler {
	h := Handler{
		HideIP:      true,
		DialTimeout: caddy.Duration(30 * time.Second),
		aclRules:    []aclRule{&aclAllRule{allow: true}},
		dialContext: dialer.dial,
	}
	for _, ip := range denied {
		rule, err := newACLRule(ip, false)
		if err != nil {
			panic(err)
		}
		h.aclRules = append([]aclRule{rule}, h.aclRules...)
	}
	h.lookupIPFamily = func(ctx context.Context, family, _ string) ([]net.IPAddr, error) {
		if family == "ip4" {
			return v4.lookup(ctx)
		}
		return v6.lookup(ctx)
	}
	return h
}

func (d *incrDial) attemptList() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.attempts...)
}

// A slow family must not gate the first dial of a fast family.
func TestTCPDNSIncrementalSkew(t *testing.T) {
	run := func(t *testing.T, v4Delay, v6Delay time.Duration, v4Addrs, v6Addrs []string, winner string) {
		v4 := &familyFixture{kind: "answer", delay: v4Delay, addrs: v4Addrs}
		v6 := &familyFixture{kind: "answer", delay: v6Delay, addrs: v6Addrs}
		d := &incrDial{winner: winner}
		h := incrHandler(v4, v6, d)

		start := time.Now()
		conn, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
		if err != nil || conn == nil {
			t.Fatalf("dial = %v, %v; want success", conn, err)
		}
		conn.Close()
		if elapsed := d.tFirst.Sub(start); elapsed > 200*time.Millisecond {
			t.Fatalf("first dial waited for the slow family: %v", elapsed)
		}
		if got := d.attemptList(); !reflect.DeepEqual(got, []string{winner}) {
			t.Fatalf("attempts = %v, want [%s]", got, winner)
		}
	}
	t.Run("v4_first", func(t *testing.T) {
		run(t, 15*time.Millisecond, 400*time.Millisecond,
			[]string{"192.0.2.10"}, []string{"2001:db8:10::10"}, "192.0.2.10:443")
	})
	t.Run("v6_first", func(t *testing.T) {
		run(t, 400*time.Millisecond, 15*time.Millisecond,
			[]string{"192.0.2.10"}, []string{"2001:db8:10::10"}, "[2001:db8:10::10]:443")
	})
}

// A dropped (timed-out) family must not gate the other family's dial.
func TestTCPDNSIncrementalDroppedFamily(t *testing.T) {
	v4 := &familyFixture{kind: "drop", delay: 400 * time.Millisecond}
	v6 := &familyFixture{kind: "answer", delay: 15 * time.Millisecond, addrs: []string{"2001:db8:10::10"}}
	d := &incrDial{winner: "[2001:db8:10::10]:443"}
	h := incrHandler(v4, v6, d)

	start := time.Now()
	conn, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
	if err != nil || conn == nil {
		t.Fatalf("dial = %v, %v; want success", conn, err)
	}
	conn.Close()
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("dropped v4 gated the v6 dial: %v", elapsed)
	}
}

func TestTCPDNSIncrementalAllDropped(t *testing.T) {
	v4 := &familyFixture{kind: "drop", delay: 120 * time.Millisecond}
	v6 := &familyFixture{kind: "drop", delay: 150 * time.Millisecond}
	d := &incrDial{}
	h := incrHandler(v4, v6, d)
	_, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
	requireTCPStatus(t, err, http.StatusGatewayTimeout)
	if got := d.attemptList(); len(got) != 0 {
		t.Fatalf("attempts = %v, want none", got)
	}
}

func TestTCPDNSIncrementalAllFail(t *testing.T) {
	v4 := &familyFixture{kind: "error", delay: 15 * time.Millisecond}
	v6 := &familyFixture{kind: "nodata", delay: 15 * time.Millisecond}
	d := &incrDial{}
	h := incrHandler(v4, v6, d)
	_, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
	requireTCPStatus(t, err, http.StatusBadGateway)
	if got := d.attemptList(); len(got) != 0 {
		t.Fatalf("attempts = %v, want none", got)
	}
}

// Every address ACL-denied (both families) stays 403 with zero dials.
func TestTCPDNSIncrementalAllDenied(t *testing.T) {
	v4 := &familyFixture{kind: "answer", addrs: []string{"192.0.2.10"}}
	v6 := &familyFixture{kind: "answer", addrs: []string{"2001:db8:10::10"}}
	d := &incrDial{}
	h := incrHandler(v4, v6, d, "192.0.2.10", "2001:db8:10::10")
	_, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
	requireTCPStatus(t, err, http.StatusForbidden)
	if got := d.attemptList(); len(got) != 0 {
		t.Fatalf("attempts = %v, want none", got)
	}
}

// Explicit tcp4/tcp6 callers never dial the other family.
func TestTCPDNSIncrementalFamilyIsolation(t *testing.T) {
	t.Run("tcp4_dual", func(t *testing.T) {
		v4 := &familyFixture{kind: "answer", addrs: []string{"192.0.2.10"}}
		v6 := &familyFixture{kind: "answer", addrs: []string{"2001:db8:10::10"}}
		d := &incrDial{winner: "192.0.2.10:443"}
		h := incrHandler(v4, v6, d)
		conn, err := h.dialContextCheckACL(context.Background(), "tcp4", "target.example:443")
		if err != nil || conn == nil {
			t.Fatalf("dial = %v, %v; want success", conn, err)
		}
		conn.Close()
		if got := d.attemptList(); !reflect.DeepEqual(got, []string{"192.0.2.10:443"}) {
			t.Fatalf("attempts = %v, want v4 only", got)
		}
	})
	t.Run("tcp6_v4only", func(t *testing.T) {
		v4 := &familyFixture{kind: "answer", addrs: []string{"192.0.2.10"}}
		v6 := &familyFixture{kind: "nodata"}
		d := &incrDial{}
		h := incrHandler(v4, v6, d)
		_, err := h.dialContextCheckACL(context.Background(), "tcp6", "target.example:443")
		requireTCPStatus(t, err, http.StatusBadGateway)
		if got := d.attemptList(); len(got) != 0 {
			t.Fatalf("attempts = %v, want none", got)
		}
	})
}

// A late family that is ACL-denied must never be dialed.
func TestTCPDNSIncrementalLateDenied(t *testing.T) {
	v4 := &familyFixture{kind: "answer", delay: 15 * time.Millisecond, addrs: []string{"192.0.2.10"}}
	v6 := &familyFixture{kind: "answer", delay: 400 * time.Millisecond, addrs: []string{"2001:db8:10::10"}}
	d := &incrDial{winner: "192.0.2.10:443"}
	h := incrHandler(v4, v6, d, "2001:db8:10::10")
	conn, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
	if err != nil || conn == nil {
		t.Fatalf("dial = %v, %v; want success", conn, err)
	}
	conn.Close()
	if got := d.attemptList(); !reflect.DeepEqual(got, []string{"192.0.2.10:443"}) {
		t.Fatalf("attempts = %v, want winner only (denied v6 never dialed)", got)
	}
}

// A late healthy family after the winner is discarded: no dial, no
// goroutine leak, in-flight lookup canceled.
func TestTCPDNSIncrementalLateAfterWinner(t *testing.T) {
	v4 := &familyFixture{kind: "answer", delay: 15 * time.Millisecond, addrs: []string{"192.0.2.10"}}
	v6 := &familyFixture{kind: "answer", delay: 400 * time.Millisecond, addrs: []string{"2001:db8:10::10"}}
	d := &incrDial{winner: "192.0.2.10:443"}
	h := incrHandler(v4, v6, d)

	baseline := runtime.NumGoroutine()
	conn, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
	if err != nil || conn == nil {
		t.Fatalf("dial = %v, %v; want success", conn, err)
	}
	conn.Close()
	if got := d.attemptList(); !reflect.DeepEqual(got, []string{"192.0.2.10:443"}) {
		t.Fatalf("attempts = %v, want winner only", got)
	}

	deadline := time.Now().Add(2 * time.Second)
	for !v6.wasCanceled() {
		if time.Now().After(deadline) {
			t.Fatal("late family lookup was not canceled after the winner")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > baseline+2 {
		t.Fatalf("goroutine leak: %d before, %d after", baseline, after)
	}
}

// Request cancellation propagates into in-flight lookups and dials.
func TestTCPDNSIncrementalCancelInFlight(t *testing.T) {
	v4 := &familyFixture{kind: "answer", delay: 2 * time.Second, addrs: []string{"192.0.2.10"}}
	v6 := &familyFixture{kind: "answer", delay: 2 * time.Second, addrs: []string{"2001:db8:10::10"}}
	d := &incrDial{winner: "192.0.2.10:443"}
	h := incrHandler(v4, v6, d)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := h.dialContextCheckACL(ctx, "tcp", "target.example:443")
	requireTCPStatus(t, err, http.StatusBadGateway)
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Fatalf("cancellation returned before the lookups were in flight: %v", elapsed)
	}
	if got := d.attemptList(); len(got) != 0 {
		t.Fatalf("attempts = %v, want none", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !v4.wasCanceled() || !v6.wasCanceled() {
		if time.Now().After(deadline) {
			t.Fatalf("lookups not canceled: v4=%v v6=%v", v4.wasCanceled(), v6.wasCanceled())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The dynamic candidate set pops in the same order as the audited static
// interleave (7307332): first candidate, 250 ms stagger, alternating
// families, per-family resolver order preserved.
func TestTCPDNSIncrementalInterleaveOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		v4 := &familyFixture{kind: "answer", delay: 10 * time.Millisecond, addrs: []string{"192.0.2.10", "192.0.2.11"}}
		v6 := &familyFixture{kind: "answer", addrs: []string{"2001:db8:10::10", "2001:db8:10::11"}}
		d := &incrDial{winner: "[2001:db8:10::11]:443"}
		h := incrHandler(v4, v6, d)

		start := time.Now()
		conn, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
		if err != nil || conn == nil {
			t.Fatalf("dial = %v, %v; want success", conn, err)
		}
		conn.Close()
		want := []string{"[2001:db8:10::10]:443", "192.0.2.10:443", "[2001:db8:10::11]:443"}
		if got := d.attemptList(); !reflect.DeepEqual(got, want) {
			t.Fatalf("attempts = %v, want %v", got, want)
		}
		if elapsed := time.Since(start); elapsed != 500*time.Millisecond {
			t.Fatalf("elapsed = %v, want 500ms (two 250ms staggers)", elapsed)
		}
	})
}

// Per-family resolver order is preserved within the race.
func TestTCPDNSIncrementalPerFamilyOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		v4 := &familyFixture{kind: "answer", addrs: []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"}}
		v6 := &familyFixture{kind: "nodata"}
		d := &incrDial{winner: "192.0.2.12:443"}
		h := incrHandler(v4, v6, d)

		conn, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
		if err != nil || conn == nil {
			t.Fatalf("dial = %v, %v; want success", conn, err)
		}
		conn.Close()
		want := []string{"192.0.2.10:443", "192.0.2.11:443", "192.0.2.12:443"}
		if got := d.attemptList(); !reflect.DeepEqual(got, want) {
			t.Fatalf("attempts = %v, want resolver order %v", got, want)
		}
	})
}

// Duplicate addresses across the resolver's answer list are dialed once.
func TestTCPDNSIncrementalDedup(t *testing.T) {
	v4 := &familyFixture{kind: "answer", addrs: []string{"192.0.2.10", "192.0.2.10"}}
	v6 := &familyFixture{kind: "nodata"}
	d := &incrDial{winner: "192.0.2.10:443"}
	h := incrHandler(v4, v6, d)
	conn, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
	if err != nil || conn == nil {
		t.Fatalf("dial = %v, %v; want success", conn, err)
	}
	conn.Close()
	if got := d.attemptList(); !reflect.DeepEqual(got, []string{"192.0.2.10:443"}) {
		t.Fatalf("attempts = %v, want one dial to the deduplicated address", got)
	}
}

// The lazy interleave pop rule itself: v6-first tie-break on a
// simultaneous first arrival, then strict alternation, then same-family
// continuation once the other family is exhausted.
func TestTCPFamilyFeedPopOrder(t *testing.T) {
	popAll := func(v4, v6 []string) []string {
		feed := newTCPFamilyFeed()
		feed.v4 = append([]string(nil), v4...)
		feed.v6 = append([]string(nil), v6...)
		var got []string
		var last byte
		for {
			addr, _, _ := feed.advance(true, last)
			if addr == "" {
				break
			}
			ip, _, err := net.SplitHostPort(addr)
			if err != nil {
				panic(err)
			}
			if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
				last = 4
			} else {
				last = 6
			}
			got = append(got, addr)
		}
		return got
	}
	t.Run("alternating", func(t *testing.T) {
		want := []string{"[2001:db8::10]:1", "192.0.2.10:1", "[2001:db8::11]:1", "192.0.2.11:1"}
		got := popAll([]string{"192.0.2.10:1", "192.0.2.11:1"}, []string{"[2001:db8::10]:1", "[2001:db8::11]:1"})
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("pops = %v, want %v", got, want)
		}
	})
	t.Run("v4_continuation", func(t *testing.T) {
		want := []string{"[2001:db8::10]:1", "192.0.2.10:1", "192.0.2.11:1", "192.0.2.12:1"}
		got := popAll([]string{"192.0.2.10:1", "192.0.2.11:1", "192.0.2.12:1"}, []string{"[2001:db8::10]:1"})
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("pops = %v, want %v", got, want)
		}
	})
	t.Run("v6_only", func(t *testing.T) {
		want := []string{"[2001:db8::10]:1", "[2001:db8::11]:1"}
		if got := popAll(nil, []string{"[2001:db8::10]:1", "[2001:db8::11]:1"}); !reflect.DeepEqual(got, want) {
			t.Fatalf("pops = %v, want %v", got, want)
		}
	})
}
