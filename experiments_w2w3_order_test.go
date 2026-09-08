//go:build w2w3

// W2 experiment: order-preservation, ACL, and family-isolation checks for
// resolveTargetCheckACL (ACL filter + dedup) and interleaveTCPAddresses
// (RFC 8305-style interleaving). All dials fail immediately with "refused"
// so the scheduler walks the entire candidate list; the recorded attempt
// order is the assertion target.
package forwardproxy

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
)

// w2w3OrderHandler builds a handler whose lookup returns the given resolver
// order (IP literals, host:port joined by the handler for port 443) and
// whose dials all refuse immediately, recording every attempt. Numeric
// hosts are short-circuited exactly like the production resolver's
// netip.ParseAddr path (no DNS query for IP literals).
func w2w3OrderHandler(t *testing.T, resolverOrder []string, denyIPs ...string) (*Handler, *w2w3OrderDial) {
	t.Helper()
	h := Handler{
		HideIP: true,
		aclRules: func() []aclRule {
			rules := make([]aclRule, 0, 1+len(denyIPs))
			for _, ip := range denyIPs {
				r, err := newACLRule(ip, false)
				if err != nil {
					t.Fatalf("deny rule %s: %v", ip, err)
				}
				rules = append(rules, r)
			}
			rules = append(rules, &aclAllRule{allow: true})
			return rules
		}(),
	}
	d := &w2w3OrderDial{}
	h.dialContext = d.dial
	h.lookupIP = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if ip := net.ParseIP(host); ip != nil {
			// Production resolver numeric short-circuit.
			return []net.IPAddr{{IP: ip}}, nil
		}
		var out []net.IPAddr
		for _, a := range resolverOrder {
			out = append(out, net.IPAddr{IP: net.ParseIP(a)})
		}
		return out, nil
	}
	return &h, d
}

type w2w3OrderDial struct {
	attempts []string
}

func (d *w2w3OrderDial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.attempts = append(d.attempts, address)
	return nil, errors.New("refused")
}

func w2w3RunOrderCase(t *testing.T, network string, hostPort string, resolverOrder []string, denyIPs []string, wantAttempts []string) {
	t.Helper()
	h, d := w2w3OrderHandler(t, resolverOrder, denyIPs...)
	ctx := context.Background()
	_, err := h.dialContextCheckACL(ctx, network, hostPort)
	if wantAttempts == nil {
		if err == nil {
			t.Fatalf("expected failure for empty candidate set")
		}
		if len(d.attempts) != 0 {
			t.Fatalf("attempts = %v, want none", d.attempts)
		}
		return
	}
	if err == nil {
		t.Fatal("expected all candidates to fail")
	}
	got := d.attempts
	want := make([]string, 0, len(wantAttempts))
	for _, ip := range wantAttempts {
		want = append(want, net.JoinHostPort(ip, "443"))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("attempts = %v, want %v", got, want)
	}
}

func TestW2W3OrderPreservation(t *testing.T) {
	// Superseded for the Route B production path (per-family
	// incremental resolution): TestW2W3RouteBMatrix plus the untagged
	// connect_dial_incremental_test.go re-verify the same scenarios
	// against the shipped path. Kept as a historical artifact of the W2
	// merged-lookup measurement.
	t.Skip("superseded by TestW2W3RouteBMatrix and untagged incremental tests")
	hostPort := "target.example:443"
	cases := []struct {
		name          string
		network       string
		resolverOrder []string
		denyIPs       []string
		want          []string
	}{
		{
			// O1a: resolver order survives ACL filter + dedup. Input has a
			// duplicate v4a and a denied v4b; output keeps first-occurrence
			// order of the survivors.
			name: "O1a_deny_middle_dedup", network: "tcp",
			resolverOrder: []string{w2w3V4a, w2w3V4b, w2w3V6a, w2w3V4a, w2w3V6b},
			denyIPs:       []string{w2w3V4b},
			want:          []string{w2w3V4a, w2w3V6a, w2w3V6b},
		},
		{
			// O1b: preferred family (v6) first; denying a middle v4 keeps
			// per-family resolver order, then interleave alternates
			// (first-family count one): v6a, v4a, v6b, v4b.
			name: "O1b_v6_first_deny_v4", network: "tcp",
			resolverOrder: []string{w2w3V6a, w2w3V4a, w2w3V4b, w2w3V4c, w2w3V6b},
			denyIPs:       []string{w2w3V4c},
			want:          []string{w2w3V6a, w2w3V4a, w2w3V6b, w2w3V4b},
		},
		{
			// O2a: multiple v4 candidates keep relative order; interleave
			// alternates with first-family count one.
			name: "O2a_multi_v4", network: "tcp",
			resolverOrder: []string{w2w3V4a, w2w3V4b, w2w3V4c, w2w3V6a, w2w3V6b},
			want:          []string{w2w3V4a, w2w3V6a, w2w3V4b, w2w3V6b, w2w3V4c},
		},
		{
			// O2b: v6-primary ordering.
			name: "O2b_multi_v6", network: "tcp",
			resolverOrder: []string{w2w3V6a, w2w3V6b, w2w3V4a, w2w3V4b},
			want:          []string{w2w3V6a, w2w3V4a, w2w3V6b, w2w3V4b},
		},
		{
			// O2c: mixed input order; primary family is the family of the
			// first address.
			name: "O2c_mixed", network: "tcp",
			resolverOrder: []string{w2w3V6a, w2w3V4a, w2w3V6b, w2w3V4b, w2w3V4c},
			want:          []string{w2w3V6a, w2w3V4a, w2w3V6b, w2w3V4b, w2w3V4c},
		},
		{
			// O3a: tcp4 never dials the v6 family.
			name: "O3a_tcp4_isolation", network: "tcp4",
			resolverOrder: []string{w2w3V6a, w2w3V4a, w2w3V4b},
			want:          []string{w2w3V4a, w2w3V4b},
		},
		{
			// O3b: tcp6 never dials the v4 family.
			name: "O3b_tcp6_isolation", network: "tcp6",
			resolverOrder: []string{w2w3V4a, w2w3V6a, w2w3V6b},
			want:          []string{w2w3V6a, w2w3V6b},
		},
		{
			// O3c: tcp4 with only v6 candidates -> no dial, failure.
			name: "O3c_tcp4_no_v4", network: "tcp4",
			resolverOrder: []string{w2w3V6a},
			want:          nil,
		},
		{
			// O4a: ACL removes the preferred family (first-listed v6);
			// remaining v4 candidates proceed in order with no v6 dial.
			name: "O4a_deny_preferred_v6", network: "tcp",
			resolverOrder: []string{w2w3V6a, w2w3V4a, w2w3V4b},
			denyIPs:       []string{w2w3V6a},
			want:          []string{w2w3V4a, w2w3V4b},
		},
		{
			// O4b: ACL removes the first-listed v4; remaining v6 candidates
			// proceed in order with no v4 dial.
			name: "O4b_deny_preferred_v4", network: "tcp",
			resolverOrder: []string{w2w3V4a, w2w3V6a, w2w3V6b},
			denyIPs:       []string{w2w3V4a},
			want:          []string{w2w3V6a, w2w3V6b},
		},
		{
			// O5: dedup + ACL + interleave combined.
			name: "O5_combined", network: "tcp",
			resolverOrder: []string{w2w3V4a, w2w3V4b, w2w3V4c, w2w3V6a, w2w3V6b, w2w3V4b},
			denyIPs:       []string{w2w3V4c},
			want:          []string{w2w3V4a, w2w3V6a, w2w3V4b, w2w3V6b},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w2w3RunOrderCase(t, tc.network, hostPort, tc.resolverOrder, tc.denyIPs, tc.want)
		})
	}
}

func TestW2W3NumericPassthrough(t *testing.T) {
	// O6: numeric targets bypass DNS (resolver numeric short-circuit) and
	// still pass through ACL + interleave.
	t.Run("v4", func(t *testing.T) {
		w2w3RunOrderCase(t, "tcp", "192.0.2.9:443", nil, nil, []string{"192.0.2.9"})
	})
	t.Run("v6", func(t *testing.T) {
		w2w3RunOrderCase(t, "tcp", "[2001:db8:20::9]:443", nil, nil, []string{"2001:db8:20::9"})
	})
	t.Run("numeric_denied", func(t *testing.T) {
		h, d := w2w3OrderHandler(t, nil, "192.0.2.9")
		if _, err := h.dialContextCheckACL(context.Background(), "tcp", "192.0.2.9:443"); err == nil {
			t.Fatal("expected denied numeric target to fail")
		}
		if len(d.attempts) != 0 {
			t.Fatalf("denied numeric target was dialed: %v", d.attempts)
		}
	})
}
