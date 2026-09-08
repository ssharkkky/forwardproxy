//go:build w2w3

// W3 smoke: verify the isolated standard-library Happy Eyeballs prototype
// end to end before running the matrix:
//   - the loopback UDP DNS fixture (A + AAAA bare-IP answers) feeds the
//     dialer's resolver (pure-Go path, as in the release server),
//   - net.Dialer with FallbackDelay races the two family queues,
//   - ControlContext validates the actual numeric destination against the
//     approved set before connect and records every attempt.
package forwardproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestW3Smoke(t *testing.T) {
	// Superseded for the Route B production path (per-family
	// incremental resolution): TestW2W3RouteBMatrix plus the untagged
	// connect_dial_incremental_test.go re-verify the same scenarios
	// against the shipped path. Kept as a historical artifact of the W2
	// merged-lookup measurement.
	t.Skip("superseded by TestW2W3RouteBMatrix and untagged incremental tests")
	// One candidate per family on the production CONNECT port (443).
	l4, err := net.Listen("tcp", net.JoinHostPort(w3V4a, w3PortStr))
	if err != nil {
		t.Fatalf("listen v4: %v", err)
	}
	defer l4.Close()
	l6, err := net.Listen("tcp6", net.JoinHostPort(w3V6a, w3PortStr))
	if err != nil {
		t.Fatalf("listen v6: %v", err)
	}
	defer l6.Close()
	go func() {
		for {
			c, err := l4.Accept()
			if err != nil {
				return
			}
			go c.Close()
		}
	}()
	go func() {
		for {
			c, err := l6.Accept()
			if err != nil {
				return
			}
			go c.Close()
		}
	}()

	fx, dialFn, _, stop := w3StartDNSFixture(t)
	defer stop()
	name := "w3smoke.example"
	fx.behavior(name,
		w3DNSAnswer{Kind: "answer", Addrs: []string{w3V4a}, Record: true},
		w3DNSAnswer{Kind: "answer", Addrs: []string{w3V6a}, Record: true})

	approved := map[string]struct{}{
		net.JoinHostPort(w3V4a, w3PortStr): {},
		net.JoinHostPort(w3V6a, w3PortStr): {},
	}
	var (
		mu       sync.Mutex
		attempts []string
		tFirst   time.Time
	)
	dd := net.Dialer{
		FallbackDelay: 250 * time.Millisecond,
		ControlContext: func(ctx context.Context, network, address string, c syscall.RawConn) error {
			mu.Lock()
			if tFirst.IsZero() {
				tFirst = time.Now()
			}
			mu.Unlock()
			// ACL gate on the actual numeric destination (map is immutable
			// after setup, no locking needed).
			_, ok := approved[address]
			mu.Lock()
			attempts = append(attempts, address)
			mu.Unlock()
			if !ok {
				return errors.New("destination not approved by ACL")
			}
			return nil
		},
		Resolver: &net.Resolver{Dial: dialFn},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dd.DialContext(ctx, "tcp", name+":443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tConn := time.Now()
	winner := conn.RemoteAddr().String()
	conn.Close()

	mu.Lock()
	nAttempts := len(attempts)
	mu.Unlock()
	if nAttempts == 0 {
		t.Fatal("no attempts recorded")
	}
	if tConn.Sub(start) > 2*time.Second {
		t.Fatalf("dial too slow: %v", tConn.Sub(start))
	}
	// Sanity: the resolver must have seen one A and one AAAA query.
	aQ, aaaaQ := fx.queryStats(name)
	if aQ != 1 || aaaaQ != 1 {
		t.Fatalf("fixture queries: A=%d AAAA=%d, want 1/1", aQ, aaaaQ)
	}
	t.Logf("ok winner=%s attempts=%d t=%v", winner, nAttempts, tConn.Sub(start).Round(time.Millisecond))
}
