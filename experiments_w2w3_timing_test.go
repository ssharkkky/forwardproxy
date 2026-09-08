//go:build w2w3

// Package forwardproxy — W2 experiment harness (untracked, build tag w2w3;
// not committed to master).
//
// It drives the production CONNECT path
//
//	Handler.ServeHTTP -> dialContextCheckACL
//	  -> resolveTargetCheckACL   (h.lookupIP injection point)
//	  -> dialTCPAddresses        (h.dialContext injection point)
//
// with a controlled DNS fixture and a dial fixture, and records per-stage
// timings (DNS completion, first TCP attempt, target connection, CONNECT
// response). Scenario definitions and run commands are in
// experiments/w2w3/README.md. Only aggregate timings are recorded; the
// request host is the documentation placeholder "target.example".
package forwardproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const w2w3ResultsDir = "experiments/w2w3/results"

// w2w3Family models one resolver sub-query (A or AAAA) outcome for the
// injected lookupIP fixture.
type w2w3Family struct {
	kind  string // "answer" | "nodata" | "error" | "drop"
	delay time.Duration
}

// w2w3Scenario is one controlled DNS outcome.
//
// Merge semantics mirror Go 1.26.0's pure-Go resolver, which is what the
// release server artifacts use (CGO_ENABLED=0; verified with `go version -m`
// on the release-5 server binary): both A and AAAA sub-queries run in
// parallel and LookupIPAddr completes only when both are done. If at least
// one sub-query returned addresses, the merged addresses are returned and
// sub-query errors are not propagated. Only when no sub-query returned
// addresses does the lookup return the recorded error (a dropped query is
// modeled as the resolver's per-query timeout elapsing, as a DNSError with
// IsTimeout).
type w2w3Scenario struct {
	id string
	v4 w2w3Family
	v6 w2w3Family
	// resolverOrder is the final merged address order the production
	// resolver would hand to the handler (after its RFC 6724 sort), as IP
	// literals. It is the input ordering for the order-preservation
	// properties under test.
	resolverOrder []string
	// winner selects the dial fixture outcome: "first" = the first
	// candidate succeeds at once; "second" = the first candidate
	// blackholes until cancelled and the last candidate wins (exercising
	// the 250 ms stagger and loser cancellation).
	winner string
}

// w2w3Run is one recorded measurement row (aggregate, redacted).
type w2w3Run struct {
	ID       string  `json:"id"`
	Mode     string  `json:"mode"`
	Run      int     `json:"run"`
	Status   string  `json:"status"`
	Err      string  `json:"err,omitempty"`
	TDNSms   float64 `json:"t_dns_ms"`
	TFirstms float64 `json:"t_first_ms"`
	TConnms  float64 `json:"t_conn_ms"`
	TRespms  float64 `json:"t_resp_ms"`
	Attempts int     `json:"attempts"`
	Winner   string  `json:"winner,omitempty"`
}

// w2w3Dial is the dial fixture injected through h.dialContext. The winner
// address returns a pre-created pipe; every other address blackholes until
// the attempt context is canceled.
type w2w3Dial struct {
	mu       sync.Mutex
	attempts []string
	tFirst   time.Time
	tWin     time.Time
	winner   string
	winConn  net.Conn
}

func (d *w2w3Dial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	if d.tFirst.IsZero() {
		d.tFirst = time.Now()
	}
	d.attempts = append(d.attempts, address)
	d.mu.Unlock()
	if address == d.winner {
		d.tWin = time.Now()
		return d.winConn, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d *w2w3Dial) attemptCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.attempts)
}

func (d *w2w3Dial) winnerAttempt() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.attempts) == 0 {
		return ""
	}
	return d.attempts[len(d.attempts)-1]
}

// w2w3TimingWriter records when the handler commits the CONNECT response.
type w2w3TimingWriter struct {
	header http.Header
	mu     sync.Mutex
	tHead  time.Time
	tFlush time.Time
}

func (w *w2w3TimingWriter) Header() http.Header { return w.header }

func (w *w2w3TimingWriter) Write(b []byte) (int, error) { return len(b), nil }

func (w *w2w3TimingWriter) WriteHeader(code int) {
	w.mu.Lock()
	if w.tHead.IsZero() {
		w.tHead = time.Now()
	}
	w.mu.Unlock()
}

func (w *w2w3TimingWriter) Flush() {
	w.mu.Lock()
	if w.tFlush.IsZero() {
		w.tFlush = time.Now()
	}
	w.mu.Unlock()
}

func (w *w2w3TimingWriter) headTime() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tHead
}

// w2w3DNSFixture wraps a scenario lookup and records when the emulated
// lookup completes (relative to the run start).
type w2w3DNSFixture struct {
	scen      *w2w3Scenario
	mu        sync.Mutex
	completedAt time.Time
}

func (f *w2w3DNSFixture) lookup(ctx context.Context, host string) ([]net.IPAddr, error) {
	// One fresh sub-query channel per call so the fixture is safe to reuse
	// across repeated runs.
	v4Done := make(chan struct{})
	v6Done := make(chan struct{})
	startSubQuery(ctx, f.scen.v4, v4Done)
	startSubQuery(ctx, f.scen.v6, v6Done)
	// Wait for both sub-queries, but never past request cancellation.
	for _, ch := range []chan struct{}{v4Done, v6Done} {
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	addrs, err := f.scen.mergeResults(host)
	f.mu.Lock()
	f.completedAt = time.Now()
	f.mu.Unlock()
	return addrs, err
}

func (f *w2w3DNSFixture) doneAt() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.completedAt
}

// startSubQuery starts the modeled sub-query for one family: it completes
// after the family's delay, or immediately when ctx is canceled.
func startSubQuery(ctx context.Context, f w2w3Family, done chan struct{}) {
	go func() {
		defer func() { close(done) }()
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
		}
	}()
}

// mergeResults applies the pure-Go resolver merge semantics (see
// w2w3Scenario doc).
func (s *w2w3Scenario) mergeResults(host string) ([]net.IPAddr, error) {
	if s.v4.kind == "answer" || s.v6.kind == "answer" {
		var addrs []net.IPAddr
		for _, ip := range s.resolverOrder {
			addrs = append(addrs, net.IPAddr{IP: net.ParseIP(ip)})
		}
		return addrs, nil
	}
	if s.v4.kind == "drop" || s.v6.kind == "drop" {
		return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
	}
	if s.v4.kind == "error" || s.v6.kind == "error" {
		return nil, &net.DNSError{Err: "server failure (simulated SERVFAIL)", Name: host}
	}
	return nil, &net.DNSError{Err: "no answer from DNS server", Name: host}
}

// pickWinner returns the IP literal the dial fixture should succeed on.
func (s *w2w3Scenario) pickWinner() string {
	if s.winner == "second" {
		return s.resolverOrder[len(s.resolverOrder)-1]
	}
	return s.resolverOrder[0]
}

// runOnce drives the full production CONNECT path for one scenario run and
// returns the recorded row. cancelAfter > 0 cancels the request context
// after that delay (total-cancellation scenario).
func (s *w2w3Scenario) runOnce(t *testing.T, mode string, run int, cancelAfter time.Duration) w2w3Run {
	t.Helper()
	start := time.Now()
	row := w2w3Run{ID: s.id, Mode: mode, Run: run}

	var dial *w2w3Dial
	if len(s.resolverOrder) > 0 {
		winner, peer := net.Pipe()
		// The tunnel carries no data; the 200 flush is the observation
		// point, so close the peer before driving the handler.
		peer.Close()
		t.Cleanup(func() { winner.Close() })
		dial = &w2w3Dial{winner: net.JoinHostPort(s.pickWinner(), "443"), winConn: winner}
	}

	h := Handler{
		HideIP:      true,
		DialTimeout: caddy.Duration(30 * time.Second),
		aclRules:    []aclRule{&aclAllRule{allow: true}},
	}
	if dial != nil {
		h.dialContext = dial.dial
	}
	dnsFix := &w2w3DNSFixture{scen: s}
	h.lookupIP = dnsFix.lookup

	requestCtx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
	var cancel context.CancelFunc
	if cancelAfter > 0 {
		requestCtx, cancel = context.WithCancel(requestCtx)
		go func() {
			select {
			case <-time.After(cancelAfter):
			case <-requestCtx.Done():
			}
			cancel()
		}()
	} else {
		requestCtx, cancel = context.WithTimeout(requestCtx, 15*time.Second)
	}
	t.Cleanup(cancel)

	r := (&http.Request{
		Method: http.MethodConnect, URL: &url.URL{Host: "target.example:443"},
		Host: "target.example:443", ProtoMajor: 3, Proto: "HTTP/3.0",
		Header: make(http.Header), Body: io.NopCloser(http.NoBody),
	}).WithContext(requestCtx)

	w := &w2w3TimingWriter{header: make(http.Header)}
	err := h.ServeHTTP(w, r, nil)

	row.TDNSms = msSince(start, dnsFix.doneAt())
	if dial != nil {
		row.TFirstms = msSince(start, dial.tFirst)
		row.TConnms = msSince(start, dial.tWin)
		row.Attempts = dial.attemptCount()
	}
	if !w.headTime().IsZero() {
		row.TRespms = msSince(start, w.headTime())
	}
	if err == nil {
		row.Status = "200"
		if dial != nil {
			row.Winner = dial.winnerAttempt()
		}
	} else {
		row.Status = "error"
		row.Err = err.Error()
		var handlerErr caddyhttp.HandlerError
		if errors.As(err, &handlerErr) {
			row.Status = strconv.Itoa(handlerErr.StatusCode)
		}
	}
	return row
}

var _ = fmt.Sprintf

// msSince returns millisecond precision from base to t (0 if t is unset).
func msSince(base, t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.Sub(base)) / float64(time.Millisecond)
}

// w2w3AppendJSONL appends one JSON line under experiments/w2w3/results.
func w2w3AppendJSONL(t *testing.T, file string, v any) {
	t.Helper()
	if err := os.MkdirAll(w2w3ResultsDir, 0o755); err != nil {
		t.Fatalf("create results dir: %v", err)
	}
	f, err := os.OpenFile(filepath.Join(w2w3ResultsDir, file), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open results file: %v", err)
	}
	defer f.Close()
	line, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal row: %v", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatalf("append row: %v", err)
	}
}

// w2w3Summary aggregates the rows of one scenario for the report.
type w2w3Summary struct {
	ID       string  `json:"id"`
	Mode     string  `json:"mode"`
	N        int     `json:"n"`
	StatusOK int     `json:"status_ok"`
	TDNS     w2w3Pct `json:"t_dns_ms"`
	TFirst   w2w3Pct `json:"t_first_ms"`
	TConn    w2w3Pct `json:"t_conn_ms"`
	TResp    w2w3Pct `json:"t_resp_ms"`
}

type w2w3Pct struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	Max float64 `json:"max"`
}

func w2w3Percentile(vals []float64, p float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := append([]float64(nil), vals...)
	sort.Float64s(sorted)
	idx := int(p * float64(len(sorted)-1))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func w2w3PctOf(vals []float64) w2w3Pct {
	return w2w3Pct{
		P50: w2w3Percentile(vals, 0.50),
		P95: w2w3Percentile(vals, 0.95),
		Max: w2w3Percentile(vals, 1.0),
	}
}
