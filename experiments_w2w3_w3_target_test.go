//go:build w2w3

// W3 experiment: controlled TCP target world shared by both dial paths.
//
// Every candidate is a real loopback address that the dialer reaches on the
// production CONNECT port (443). Candidate behavior is realized the same way
// for both paths:
//
//   - "ok"         accepting listener; the kernel handshake completes in ~1 ms
//   - "refuse"     no listener on 443; the kernel answers RST (ECONNREFUSED)
//   - "blackhole"  listener that never Accepts; queued SYNs stay pending in
//     the kernel until the dial context dies (models a dropped-connect path)
//   - "delayed"    accepting listener plus a pre-connect delay in the dial
//     hook (models RTT before handshake completion)
//   - "targeted"   accepting listener; the pre-connect delay ends at an
//     absolute run-relative time (simultaneous-success scenarios)
//   - "flaky"      accepting listener; a seeded per-run draw decides
//     success (pre-connect delay) vs loss (the hook blocks until the dial
//     context dies, modeling dropped SYNs)
//
// The pre-connect delay lives inside the dial call for both paths (the
// production dial wrapper for the current scheduler, net.Dialer's
// ControlContext for the standard-library Happy Eyeballs path), so the
// scheduler observes "attempt pending for N ms then success" identically.
// The kernel handshake itself completes in ~1 ms.
package forwardproxy

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// W3 candidate placeholder addresses (RFC 2606 / loopback, no real
// destinations).
const (
	w3V4a = "127.0.0.11"
	w3V4b = "127.0.0.12"
	w3V4c = "127.0.0.13"
	w3V4d = "127.0.0.14"
	w3V6a = "2001:db8:30::11"
	w3V6b = "2001:db8:30::12"
	w3V6c = "2001:db8:30::13"
	w3V6d = "2001:db8:30::14"
)

const w3PortStr = "443"

// w3CandidateKind is the static, per-scenario target kind.
type w3CandidateKind int

const (
	w3KindOK w3CandidateKind = iota
	w3KindRefuse
	w3KindBlackhole
)

// w3StaticKind maps a static target kind to its behavior name.
func w3StaticKind(k w3CandidateKind) string {
	switch k {
	case w3KindOK:
		return "ok"
	case w3KindRefuse:
		return "refuse"
	default:
		return "blackhole"
	}
}

// w3Behavior is the per-run candidate behavior.
type w3Behavior struct {
	kind     string // "ok" | "refuse" | "blackhole" | "delayed" | "targeted" | "flaky"
	delay    time.Duration
	targetAt time.Duration // targeted: run-relative completion time
	lossProb float64
	jitter   time.Duration
	rng      *rand.Rand
	draws    int
}

// w3Target tracks one candidate's target-side state.
type w3Target struct {
	id     string
	ip     string
	kind   w3CandidateKind
	listen net.Listener
	mu     sync.Mutex
	accepted int
	active   int
}

func (tg *w3Target) addr() string {
	return net.JoinHostPort(tg.ip, w3PortStr)
}

func (tg *w3Target) acceptedCount() int {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return tg.accepted
}

func (tg *w3Target) activeConns() int {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return tg.active
}

// w3World owns one scenario's targets, the per-run behavior assignment, and
// the shared dial instrumentation.
type w3World struct {
	t        *testing.T
	targets  map[string]*w3Target // candidate id -> target
	byAddr   map[string]string    // "ip:443" -> candidate id
	mu        sync.Mutex
	behav     map[string]w3Behavior
	approved  map[string]bool
// instrumentation
	inFlight atomic.Int64
	peak     atomic.Int64
	gorPeak  atomic.Int64
	sampleStop chan struct{}
}

// w3RunState is the per-run instrumentation sink (one per path per run).
type w3RunState struct {
	mu        sync.Mutex
	tRunStart time.Time
	attempts  []string // candidate ids in dial-start order
	denied    []string // candidate ids rejected by the ACL gate
	tFirst    time.Time
	tWin      time.Time
	winner    string
}

func (rs *w3RunState) recordAttempt(id string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.tFirst.IsZero() {
		rs.tFirst = time.Now()
	}
	rs.attempts = append(rs.attempts, id)
}

func (rs *w3RunState) recordDenied(id string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.denied = append(rs.denied, id)
}

func (rs *w3RunState) recordWin(id string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.tWin.IsZero() {
		rs.tWin = time.Now()
		rs.winner = id
	}
}

func (rs *w3RunState) attemptsList() []string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([]string, len(rs.attempts))
	copy(out, rs.attempts)
	return out
}

func (rs *w3RunState) deniedList() []string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([]string, len(rs.denied))
	copy(out, rs.denied)
	return out
}

func (rs *w3RunState) winnerInfo() (string, time.Time) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.winner, rs.tWin
}

func (rs *w3RunState) firstTime() time.Time {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.tFirst
}

// w3StartWorld creates the scenario's targets (listeners per static kind)
// and returns the world.
func w3StartWorld(t *testing.T, v4Kinds, v6Kinds []w3CandidateKind) *w3World {
	t.Helper()
	w := &w3World{
		t:        t,
		targets:  map[string]*w3Target{},
		byAddr:   map[string]string{},
		approved: map[string]bool{},
		behav:    map[string]w3Behavior{},
	}
	v4IPs := []string{w3V4a, w3V4b, w3V4c, w3V4d}
	v6IPs := []string{w3V6a, w3V6b, w3V6c, w3V6d}
	add := func(id, ip string, kind w3CandidateKind, v6 bool) {
		tg := &w3Target{id: id, ip: ip, kind: kind}
		switch kind {
		case w3KindOK:
			network := "tcp"
			if v6 {
				network = "tcp6"
			}
			l, err := net.Listen(network, net.JoinHostPort(ip, w3PortStr))
			if err != nil {
				t.Fatalf("w3 listen %s: %v", ip, err)
			}
			tg.listen = l
			go tg.acceptLoop()
		case w3KindBlackhole:
			// No listener: the behavior layer blocks the pre-connect
			// phase until the dial context dies, which is
			// scheduler-indistinguishable from a kernel SYN drop (the
			// attempt never completes; only the per-attempt deadline
			// observes it).
		}
		w.targets[id] = tg
		w.byAddr[tg.addr()] = id
	}
	for i, k := range v4Kinds {
		add("v4"+string(rune('a'+i)), v4IPs[i], k, false)
	}
	for i, k := range v6Kinds {
		add("v6"+string(rune('a'+i)), v6IPs[i], k, true)
	}
	t.Cleanup(w.stop)
	return w
}

func (w *w3World) stop() {
	for _, tg := range w.targets {
		if tg.listen != nil {
			tg.listen.Close()
		}
	}
}


func (tg *w3Target) acceptLoop() {
	for {
		c, err := tg.listen.Accept()
		if err != nil {
			return
		}
		tg.mu.Lock()
		tg.accepted++
		tg.active++
		tg.mu.Unlock()
		go func(c net.Conn) {
			defer func() {
				tg.mu.Lock()
				tg.active--
				tg.mu.Unlock()
				c.Close()
			}()
			buf := make([]byte, 1)
			for {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		}(c)
	}
}

// candidateOf maps a dial address ("ip:443") to the candidate id.
func (w *w3World) candidateOf(address string) string {
	w.mu.Lock()
	id, ok := w.byAddr[address]
	w.mu.Unlock()
	if !ok {
		w.t.Fatalf("w3: unknown dial target %q", address)
	}
	return id
}

// setRun installs the per-run behaviors and ACL approved set and
// (re)starts the goroutine sampler.
func (w *w3World) setRun(behav map[string]w3Behavior, approved map[string]bool) {
	w.mu.Lock()
	w.behav = behav
	w.approved = approved
	if w.sampleStop != nil {
		close(w.sampleStop)
	}
	w.sampleStop = make(chan struct{})
	stop := w.sampleStop
	w.mu.Unlock()
	w.resetPeaks()
	go w.sampleLoop(stop)
}

// sampleLoop tracks the goroutine peak until stopped.
func (w *w3World) sampleLoop(stop chan struct{}) {
	for {
		g := int64(runtime.NumGoroutine())
		for {
			old := w.gorPeak.Load()
			if g <= old || w.gorPeak.CompareAndSwap(old, g) {
				break
			}
		}
		select {
		case <-stop:
			return
		case <-time.After(time.Millisecond):
		}
	}
}

// startDialTo instruments one in-flight dial and applies the per-run
// pre-connect behavior, recording into the given run state. It returns an
// error when the behavior blocks until the dial context dies (flaky loss)
// or the context is canceled; a nil error means "proceed with the real
// connect".
func (w *w3World) startDialTo(ctx context.Context, address string, rs *w3RunState) error {
	id := w.candidateOf(address)
	w.inFlight.Add(1)
	if cur := w.inFlight.Load(); cur > w.peak.Load() {
		w.peak.CompareAndSwap(w.peak.Load(), cur)
	}
	rs.recordAttempt(id)

	w.mu.Lock()
	approved := w.approved
	allowed := approved[id]
	b := w.behav[id]
	tg := w.targets[id]
	w.mu.Unlock()

	if approved != nil && !allowed {
		rs.recordDenied(id)
		w.inFlight.Add(-1)
		return context.Canceled // ACL gate: fails the dial before connect
	}

	defer w.inFlight.Add(-1)
	if b.kind == "" {
		if tg == nil {
			return fmt.Errorf("w3: unknown target %q", address)
		}
		// No per-run behavior: fall back to the target's static kind.
		b.kind = w3StaticKind(tg.kind)
	}
	switch b.kind {
	case "ok", "refuse":
		return nil // the kernel realizes the behavior on the real connect
	case "blackhole":
		// SYN-drop equivalent: block until the dial context dies; the
		// per-attempt deadline then observes a deadline error exactly as
		// a kernel blackhole would.
		<-ctx.Done()
		return ctx.Err()
	case "delayed":
		d := b.delay
		if b.rng != nil && b.jitter > 0 {
			d += time.Duration(b.rng.Int63n(int64(b.jitter)))
			b.draws++
		}
		select {
		case <-time.After(d):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	case "targeted":
		rs.mu.Lock()
		runStart := rs.tRunStart
		rs.mu.Unlock()
		if !runStart.IsZero() {
			if wait := time.Until(runStart.Add(b.targetAt)); wait > 0 {
				select {
				case <-time.After(wait):
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		return nil
	case "flaky":
		loss := b.rng != nil && b.rng.Float64() < b.lossProb
		b.draws++
		if !loss {
			d := 20 * time.Millisecond
			if b.rng != nil && b.jitter > 0 {
				d += time.Duration(b.rng.Int63n(int64(b.jitter)))
			}
			select {
			case <-time.After(d):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		// Loss: dropped SYNs — pending until the dial context dies.
		<-ctx.Done()
		return ctx.Err()
	default:
		w.t.Fatalf("w3: unknown behavior %q", b.kind)
	}
	return nil
}

// dialTargetTo applies the per-run behavior and performs the real connect.
func (w *w3World) dialTargetTo(ctx context.Context, network, address string, rs *w3RunState) (net.Conn, error) {
	if err := w.startDialTo(ctx, address, rs); err != nil {
		return nil, err
	}
	var plain net.Dialer
	return plain.DialContext(ctx, network, address)
}

// endRun stops the sampler and reports the run's peak metrics.
// endRun stops the sampler and reports the run's peak metrics. Concurrent
// calls are safe: the sampler channel is closed at most once.
func (w *w3World) endRun() (peakDials, peakGoroutines int64) {
	w.mu.Lock()
	stop := w.sampleStop
	w.sampleStop = nil
	w.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	return w.peak.Load(), w.gorPeak.Load()
}

func (w *w3World) resetPeaks() {
	w.peak.Store(0)
	w.gorPeak.Store(0)
}

// activeTargetConns sums the still-open target connections (leak check).
func (w *w3World) activeTargetConns() int {
	n := 0
	for _, tg := range w.targets {
		n += tg.activeConns()
	}
	return n
}

// deniedTargetConns sums accepted connections on denied candidates (ACL
// safety check: must stay 0).
func (w *w3World) deniedTargetConns() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for id, allowed := range w.approved {
		if allowed {
			continue
		}
		if tg, ok := w.targets[id]; ok {
			n += tg.acceptedCount()
		}
	}
	return n
}
