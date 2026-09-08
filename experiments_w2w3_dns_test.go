//go:build w2w3

// W2 experiment: controlled DNS fixture matrix through the h.lookupIP
// injection point, driving the full production CONNECT path. See
// experiments/w2w3/README.md for scenario definitions.
package forwardproxy

import (
	"testing"
	"time"
)

// w2w3IP pool: documentation-range placeholders only (never real targets).
const (
	w2w3V4a = "192.0.2.10"
	w2w3V4b = "192.0.2.11"
	w2w3V4c = "192.0.2.12"
	w2w3V6a = "2001:db8:10::10"
	w2w3V6b = "2001:db8:10::11"
)

// w2w3MatrixScenarios is the W2 DNS fixture matrix. "drop" is modeled as the
// resolver's per-query timeout elapsing (2 s here to bound runtime; the real
// Go 1.26.0 resolver default is 2 attempts x 5 s = 10 s per sub-query,
// measured separately by the real-resolver probe).
func w2w3MatrixScenarios() []w2w3Scenario {
	fast := 10 * time.Millisecond
	slow := 500 * time.Millisecond
	drop := 2 * time.Second
	return []w2w3Scenario{
		{
			// D1: dual-stack, both answers fast, first candidate
			// blackholes, second wins (stagger + loser cancellation).
			id: "D1_dual_fast_blackhole", v4: w2w3Family{kind: "answer", delay: fast},
			v6: w2w3Family{kind: "answer", delay: fast},
			resolverOrder: []string{w2w3V4a, w2w3V6a}, winner: "second",
		},
		{
			// D2: A answer fast, AAAA answer delayed (cold). The current
			// scheduler must wait for the full lookup before dialing.
			id: "D2_v4_fast_v6_slow", v4: w2w3Family{kind: "answer", delay: fast},
			v6: w2w3Family{kind: "answer", delay: slow},
			resolverOrder: []string{w2w3V4a, w2w3V6a}, winner: "first",
		},
		{
			// D3: mirror of D2 (AAAA fast, A delayed).
			id: "D3_v6_fast_v4_slow", v4: w2w3Family{kind: "answer", delay: slow},
			v6: w2w3Family{kind: "answer", delay: fast},
			resolverOrder: []string{w2w3V4a, w2w3V6a}, winner: "first",
		},
		{
			// D4: single-family success, A only (AAAA is NODATA).
			id: "D4_v4_only", v4: w2w3Family{kind: "answer", delay: fast},
			v6: w2w3Family{kind: "nodata", delay: fast},
			resolverOrder: []string{w2w3V4a}, winner: "first",
		},
		{
			// D5: single-family success, AAAA only (A is NODATA).
			id: "D5_v6_only", v4: w2w3Family{kind: "nodata", delay: fast},
			v6: w2w3Family{kind: "answer", delay: fast},
			resolverOrder: []string{w2w3V6a}, winner: "first",
		},
		{
			// D6: A query dropped (no response; modeled resolver timeout),
			// AAAA answers fast.
			id: "D6_v4_drop_v6_ok", v4: w2w3Family{kind: "drop", delay: drop},
			v6: w2w3Family{kind: "answer", delay: fast},
			resolverOrder: []string{w2w3V6a}, winner: "first",
		},
		{
			// D7: AAAA query dropped, A answers fast.
			id: "D7_v6_drop_v4_ok", v4: w2w3Family{kind: "answer", delay: fast},
			v6: w2w3Family{kind: "drop", delay: drop},
			resolverOrder: []string{w2w3V4a}, winner: "first",
		},
		{
			// D8: A sub-query fails fast (SERVFAIL), AAAA answers; the
			// pure-Go resolver returns the partial addresses.
			id: "D8_v4_servfail_v6_ok", v4: w2w3Family{kind: "error", delay: fast},
			v6: w2w3Family{kind: "answer", delay: fast},
			resolverOrder: []string{w2w3V6a}, winner: "first",
		},
		{
			// D9: both answers delayed (both slow).
			id: "D9_both_slow", v4: w2w3Family{kind: "answer", delay: 300 * time.Millisecond},
			v6: w2w3Family{kind: "answer", delay: 400 * time.Millisecond},
			resolverOrder: []string{w2w3V4a, w2w3V6a}, winner: "first",
		},
		{
			// D10: both sub-queries dropped -> lookup timeout error -> the
			// handler must map it to 504 (DNSError with IsTimeout).
			id: "D10_all_dropped", v4: w2w3Family{kind: "drop", delay: drop},
			v6: w2w3Family{kind: "drop", delay: drop},
		},
		{
			// D11: total cancellation. Both sub-queries pending (5 s), the
			// request context is canceled at 100 ms; no dial may start.
			id: "D11_total_cancel", v4: w2w3Family{kind: "answer", delay: 5 * time.Second},
			v6: w2w3Family{kind: "answer", delay: 5 * time.Second},
			resolverOrder: []string{w2w3V4a, w2w3V6a}, winner: "first",
		},
		{
			// D2w: warm control for D2 — both sub-queries answer
			// immediately (models cached/instant resolver behavior).
			id: "D2w_warm", v4: w2w3Family{kind: "answer", delay: 2 * time.Millisecond},
			v6: w2w3Family{kind: "answer", delay: 2 * time.Millisecond},
			resolverOrder: []string{w2w3V4a, w2w3V6a}, winner: "first",
		},
	}
}

func TestW2W3DNSMatrix(t *testing.T) {
	// Superseded for the Route B production path (per-family
	// incremental resolution): TestW2W3RouteBMatrix plus the untagged
	// connect_dial_incremental_test.go re-verify the same scenarios
	// against the shipped path. Kept as a historical artifact of the W2
	// merged-lookup measurement.
	t.Skip("superseded by TestW2W3RouteBMatrix and untagged incremental tests")
	const repeats = 30
	scenarios := w2w3MatrixScenarios()
	for i := range scenarios {
		s := &scenarios[i]
		t.Run(s.id, func(t *testing.T) {
			var (
				dns, first, conn, resp []float64
				statuses               []string
			)
			for i := 1; i <= repeats; i++ {
				cancelAfter := time.Duration(0)
				if s.id == "D11_total_cancel" {
					cancelAfter = 100 * time.Millisecond
				}
				row := s.runOnce(t, "cold", i, cancelAfter)
				w2w3AppendJSONL(t, "w2_dns_matrix.jsonl", row)
				statuses = append(statuses, row.Status)
				if row.TDNSms > 0 {
					dns = append(dns, row.TDNSms)
				}
				if row.TFirstms > 0 {
					first = append(first, row.TFirstms)
				}
				if row.TConnms > 0 {
					conn = append(conn, row.TConnms)
				}
				if row.TRespms > 0 {
					resp = append(resp, row.TRespms)
				}
				w2w3VerifyRow(t, s, row)
			}
			summary := w2w3Summary{
				ID: s.id, Mode: "cold", N: repeats,
				StatusOK: countStatus(statuses, expectedStatus(s)),
				TDNS:     w2w3PctOf(dns), TFirst: w2w3PctOf(first),
				TConn: w2w3PctOf(conn), TResp: w2w3PctOf(resp),
			}
			w2w3AppendJSONL(t, "w2_dns_matrix_summary.jsonl", summary)
			t.Logf("%s: %v", s.id, summary)
		})
	}
}

func expectedStatus(s *w2w3Scenario) string {
	if s.id == "D10_all_dropped" {
		return "504"
	}
	if s.id == "D11_total_cancel" {
		// Canceled lookup maps through tcpDialError to 502 (the client is
		// already gone; this matches the existing cancellation behavior).
		return "502"
	}
	return "200"
}

func countStatus(statuses []string, want string) int {
	n := 0
	for _, got := range statuses {
		if got == want {
			n++
		}
	}
	return n
}

// w2w3VerifyRow hard-checks the behavioral invariants of each scenario
// (statuses, attempt counts, winner identity, cancellation). Latency values
// are recorded, not asserted, because they are the measurement target.
func w2w3VerifyRow(t *testing.T, s *w2w3Scenario, row w2w3Run) {
	t.Helper()
	switch s.id {
	case "D1_dual_fast_blackhole":
		if row.Status != "200" || row.Attempts != 2 {
			t.Fatalf("D1: status=%s attempts=%d", row.Status, row.Attempts)
		}
		if row.Winner != "[2001:db8:10::10]:443" {
			t.Fatalf("D1: winner=%s", row.Winner)
		}
	case "D2_v4_fast_v6_slow", "D3_v6_fast_v4_slow", "D9_both_slow":
		if row.Status != "200" || row.Attempts != 1 {
			t.Fatalf("%s: status=%s attempts=%d (winner first: no second attempt)",
				s.id, row.Status, row.Attempts)
		}
	case "D4_v4_only", "D5_v6_only", "D6_v4_drop_v6_ok", "D7_v6_drop_v4_ok",
		"D8_v4_servfail_v6_ok":
		if row.Status != "200" || row.Attempts != 1 {
			t.Fatalf("%s: status=%s attempts=%d", s.id, row.Status, row.Attempts)
		}
	case "D10_all_dropped":
		if row.Status != "504" || row.Attempts != 0 {
			t.Fatalf("D10: status=%s attempts=%d err=%s", row.Status, row.Attempts, row.Err)
		}
	case "D11_total_cancel":
		if row.Attempts != 0 {
			t.Fatalf("D11: dial started after request cancellation: attempts=%d", row.Attempts)
		}
		if row.TFirstms != 0 {
			t.Fatalf("D11: first attempt timestamp recorded: %v ms", row.TFirstms)
		}
	default:
		if row.Status != "200" {
			t.Fatalf("%s: status=%s err=%s", s.id, row.Status, row.Err)
		}
	}
}
