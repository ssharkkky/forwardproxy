//go:build w2w3

// W3 experiment: in-test UDP DNS fixture for the standard-library
// Happy Eyeballs prototype.
//
// The prototype must use the production resolver mode (pure-Go,
// CGO_ENABLED=0) with the same A+AAAA parallel wait-for-both semantics the
// release server has. A loopback UDP DNS server with per-(name,qtype)
// behavior (answer/delay/drop/SERVFAIL/NODATA) feeds the dialer's resolver
// through net.Resolver{Dial: ...}. The server records, per name, when all
// of its sub-queries for that name have been answered, which is the
// observation point for the DNS stage (t_dns). Only aggregate timings and
// the RFC 2606 placeholder addresses the harness assigns to candidates are
// recorded.
package forwardproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// w3DNSAnswer describes the fixture answer for one (name, qtype).
type w3DNSAnswer struct {
	Kind   string   // "answer" | "nodata" | "servfail" | "drop"
	Delay  time.Duration
	Addrs  []string // answer addresses (when Kind == "answer")
	Record bool     // whether this (name,qtype) is part of the name's query set
}

// w3DNSFixture is a loopback UDP DNS server with per-name scenario control.
type w3DNSFixture struct {
	pc      net.PacketConn
	mu      sync.Mutex
	answers map[string]map[string]w3DNSAnswer // name -> qtype -> answer
	// answeredAt records, per name, when every tracked sub-query had been
	// answered (the DNS-stage completion observation point).
	completedAt map[string]time.Time
	// pending counts tracked sub-queries not yet answered per name.
	pending map[string]int
	// queries counts the sub-queries observed per name (fixture sanity).
	queries map[string]int
	// queriesByQtype is per name, for asserting that a tcp4 lookup sent
	// no AAAA query.
	queriesByQtype map[string]map[string]int
	// behaviorAt records when each (name,qtype) answer was actually sent.
	behaviorAt map[string]time.Time

	t *testing.T
}

// w3StartDNSFixture starts the fixture and returns the fixture handle,
// the dial function that points a net.Resolver at it, a per-(name,qtype)
// behavior setter, and a stop function.
func w3StartDNSFixture(t *testing.T) (*w3DNSFixture, func(ctx context.Context, network, address string) (net.Conn, error), func(name, qtype string, a w3DNSAnswer), func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns fixture listen: %v", err)
	}
	f := &w3DNSFixture{
		pc:             pc,
		answers:        map[string]map[string]w3DNSAnswer{},
		completedAt:   map[string]time.Time{},
		pending:        map[string]int{},
		queries:        map[string]int{},
		queriesByQtype: map[string]map[string]int{},
		behaviorAt:     map[string]time.Time{},
		t:              t,
	}
	go f.serveLoop()
	dialFn := func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial("udp", pc.LocalAddr().String())
	}
	set := func(name, qtype string, a w3DNSAnswer) {
		f.mu.Lock()
		defer f.mu.Unlock()
		m := f.answers[name]
		if m == nil {
			m = map[string]w3DNSAnswer{}
			f.answers[name] = m
		}
		m[qtype] = a
	}
	stop := func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.answers = map[string]map[string]w3DNSAnswer{}
		pc.Close()
	}
	return f, dialFn, set, stop
}

// behavior configures both sub-queries for one name and resets its
// completion tracking.
func (f *w3DNSFixture) behavior(name string, a4, a6 w3DNSAnswer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.answers[name]
	if m == nil {
		m = map[string]w3DNSAnswer{}
		f.answers[name] = m
	}
	f.pending[name] = 0
	if a4.Record {
		f.pending[name]++
	}
	if a6.Record {
		f.pending[name]++
	}
	f.completedAt[name] = time.Time{}
	f.queries[name] = 0
	f.queriesByQtype[name] = map[string]int{}
	m["1"] = a4
	m["28"] = a6
}

// pcAddr exposes the fixture's UDP endpoint for the resolver dial function.
func (f *w3DNSFixture) pcAddr() string { return f.pc.LocalAddr().String() }

// answeredAt returns when all tracked sub-queries for the name had been
// answered (zero time = not yet).
func (f *w3DNSFixture) answeredAt(name string) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.completedAt[name]
}

// queryStats returns how many A / AAAA queries the fixture observed for the
// name (fixture sanity + tcp4 isolation assertions).
func (f *w3DNSFixture) queryStats(name string) (aQueries, aaaaQueries int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.queriesByQtype[name]
	if m == nil {
		return 0, 0
	}
	return m["1"], m["28"]
}

func (f *w3DNSFixture) serveLoop() {
	buf := make([]byte, 1500)
	for {
		n, src, err := f.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		id := buf[0:2]
		// Parse the question qname (labels are never compressed in the
		// question section), then read the qtype after it.
		qname, end, ok := parseQuestionName(buf, 12)
		if !ok || qname == "" || end+4 > len(buf) {
			continue
		}
		qtype := binary.BigEndian.Uint16(buf[end : end+2])
		f.mu.Lock()
		if m := f.answers[qname]; m != nil {
			f.queries[qname]++
			qtm := f.queriesByQtype[qname]
			if qtm == nil {
				qtm = map[string]int{}
				f.queriesByQtype[qname] = qtm
			}
			qtm[itoa16(qtype)]++
		}
		ans := f.answers[qname]
		f.mu.Unlock()

		resp, ok := f.buildResponse(id, qtype, qname, ans)
		if !ok {
			continue // untracked query: no answer
		}
		a := ans[itoa16(qtype)]
		tracked := a.Record
		go func(dst net.Addr, payload []byte, sentAt time.Time, tracked bool, delay time.Duration) {
			// Hold the response until the configured delay elapses
			// (delayed answer) or send it immediately.
			if delay > 0 {
				select {
				case <-time.After(delay):
				}
			}
			f.pc.WriteTo(payload, dst)
			if !tracked {
				return
			}
			f.mu.Lock()
			if f.completedAt[qname].IsZero() && f.pending[qname] > 0 {
				f.pending[qname]--
				if f.pending[qname] == 0 {
					f.completedAt[qname] = time.Now()
				}
			}
			f.mu.Unlock()
			f.mu.Lock()
			f.behaviorAt[qname+itoa16(qtype)] = sentAt
			f.mu.Unlock()
		}(src, resp, time.Now(), tracked, a.Delay)
	}
}

// buildResponse renders the answer for (id, qtype, name) under the current
// scenario answer for the name. ok=false means "drop the query".
func (f *w3DNSFixture) buildResponse(id []byte, qtype uint16, name string, ans map[string]w3DNSAnswer) ([]byte, bool) {
	a := ans[itoa16(qtype)]
	if a.Kind == "" {
		return nil, false
	}
	switch a.Kind {
	case "drop":
		return nil, false
	case "nodata":
		return buildDNSEmpty(id, name, qtype)
	case "servfail":
		return buildDNSServfail(id, name, qtype)
	case "answer":
		return buildDNSAnswer(id, name, qtype, a.Addrs)
	default:
		return nil, false
	}
}

func itoa16(v uint16) string {
	if v == 1 {
		return "1"
	}
	if v == 28 {
		return "28"
	}
	return fmt.Sprintf("%d", v)
}

// buildDNSEmpty renders a zero-answer (NOERROR, no RRs) response.
func buildDNSEmpty(id []byte, name string, qtype uint16) ([]byte, bool) {
	var b []byte
	b = append(b, id...)
	b = append(b, 0x81, 0x80) // QR=1, RD=1, RA=1
	b = append(b, 0, 1)       // QDCOUNT=1
	b = append(b, 0, 0)       // ANCOUNT=0
	b = append(b, 0, 0)
	b = append(b, 0, 0)
	b = append(b, nameBytes(name)...)
	b = append(b, byte(qtype>>8), byte(qtype))
	b = append(b, 0, 1) // class IN
	return b, true
}

// buildDNSServfail renders a SERVFAIL response.
func buildDNSServfail(id []byte, name string, qtype uint16) ([]byte, bool) {
	var b []byte
	b = append(b, id...)
	b = append(b, 0x81, 0x80)
	b = append(b, 0, 1) // QDCOUNT=1
	b = append(b, 0, 0)
	b = append(b, 0, 0)
	b = append(b, 0, 0)
	b = append(b, nameBytes(name)...)
	b = append(b, byte(qtype>>8), byte(qtype))
	b = append(b, 0, 1)
	b = append(b, 0, 2) // RCODE=2 SERVFAIL
	return b, true
}

// buildDNSAnswer renders one or more A / AAAA records.
func buildDNSAnswer(id []byte, name string, qtype uint16, addrs []string) ([]byte, bool) {
	var rrs []byte
	for _, s := range addrs {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, false
		}
		if qtype == 1 && ip.To4() == nil {
			return nil, false
		}
		if qtype == 28 && ip.To4() != nil {
			ip = ip.To16()
		}
		var rd []byte
		rd = append(rd, nameBytes(name)...)
		rd = append(rd, byte(qtype>>8), byte(qtype))
		rd = append(rd, 0, 1)          // class IN
		rd = append(rd, 0, 0, 0, 1)    // TTL 1s
		if qtype == 1 {
			rd = append(rd, 0, 4)
			rd = append(rd, ip.To4()...)
		} else {
			rd = append(rd, 0, 16)
			rd = append(rd, ip.To16()...)
		}
		rrs = append(rrs, rd...)
	}
	var b []byte
	b = append(b, id...)
	b = append(b, 0x81, 0x80)
	qd := byte(1)
	anc := byte(len(addrs))
	b = append(b, 0, qd)
	b = append(b, 0, anc)
	b = append(b, 0, 0)
	b = append(b, 0, 0)
	b = append(b, nameBytes(name)...)
	b = append(b, byte(qtype>>8), byte(qtype))
	b = append(b, 0, 1)
	b = append(b, rrs...)
	return b, true
}

func nameBytes(name string) []byte {
	var b []byte
	for _, part := range splitDots(name) {
		if len(part) > 63 {
			break
		}
		b = append(b, byte(len(part)))
		b = append(b, part...)
	}
	b = append(b, 0)
	return b
}

func splitDots(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}

// parseQuestionName walks the question qname starting at byte start and
// returns the name, the offset just past the qname, and whether it parsed.
func parseQuestionName(buf []byte, start int) (string, int, bool) {
	pos := start
	var labels []string
	for pos < len(buf) {
		l := int(buf[pos])
		pos++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || pos+l > len(buf) {
			return "", 0, false
		}
		labels = append(labels, string(buf[pos:pos+l]))
		pos += l
	}
	if len(labels) == 0 {
		return "", 0, false
	}
	out := labels[0]
	for _, l := range labels[1:] {
		out += "." + l
	}
	return out, pos, true
}


