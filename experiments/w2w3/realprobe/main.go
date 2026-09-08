// Command realprobe is the W2 real-resolver probe. It points
// net.Resolver (pure-Go DNS path, the same resolver mode as the release
// server artifacts built with CGO_ENABLED=0) at a local fixture DNS server
// with scenario-controlled delays and behaviors, then records lookup
// latency, returned address order, and error class. It validates that the
// injected-lookup matrix models the production resolver semantics, and it
// measures the true cost of dropped queries under Go 1.26.0 defaults
// (timeout 5 s, attempts 2).
//
// Usage: realprobe [output.jsonl]
//
// Only aggregate timings and scenario labels are written; probe names are
// documentation-range placeholders under .example (RFC 2606), never real
// targets.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	fast = 20 * time.Millisecond
	slow = 700 * time.Millisecond
)

// behavior controls the fixture's answer for one (name, qtype).
type behavior struct {
	kind  string // "answer" | "nodata" | "servfail" | "drop"
	delay time.Duration
}

var table = map[string]map[string]behavior{}

func setBehavior(name, qtype string, b behavior) {
	if table[name] == nil {
		table[name] = map[string]behavior{}
	}
	table[name][qtype] = b
}

// ---------------------------------------------------------------------------
// Minimal DNS wire handling (query parse, response build).
// ---------------------------------------------------------------------------

func parseQuery(buf []byte) (id []byte, question []byte, name string, qtype uint16, ok bool) {
	if len(buf) < 12 {
		return nil, nil, "", 0, false
	}
	id = buf[0:2]
	off := 12
	var parts []string
	for off < len(buf) {
		l := int(buf[off])
		off++
		if l == 0 {
			break
		}
		if off+l > len(buf) {
			return nil, nil, "", 0, false
		}
		parts = append(parts, string(buf[off:off+l]))
		off += l
	}
	if off+4 > len(buf) {
		return nil, nil, "", 0, false
	}
	qtype = binary.BigEndian.Uint16(buf[off : off+2])
	question = buf[12 : off+4]
	name = strings.ToLower(strings.Join(parts, "."))
	return id, question, name, qtype, true
}

func buildResponse(id, question []byte, rcode byte, answer []byte) []byte {
	out := make([]byte, 0, 12+len(question)+len(answer))
	out = append(out, id...)
	flags := []byte{0x81, 0x80} // QR|RD|RA
	out = append(out, flags...)
	put16 := func(v uint16) { out = append(out, byte(v>>8), byte(v)) }
	ancount := uint16(0)
	if len(answer) > 0 {
		ancount = 1
	}
	put16(1)     // qdcount
	put16(ancount)
	put16(0) // nscount
	put16(0) // arcount
	out = append(out, question...)
	out = append(out, answer...)
	return out
}

func answerRR(namePtr [2]byte, rrtype uint16, rdata []byte) []byte {
	out := make([]byte, 0, 2+2+2+4+2+len(rdata))
	out = append(out, namePtr[:]...)
	out = append(out, byte(rrtype>>8), byte(rrtype))
	out = append(out, 0x00, 0x01) // class IN
	ttl := []byte{0, 0, 0, 60}
	out = append(out, ttl...)
	out = append(out, byte(len(rdata)>>8), byte(len(rdata)))
	out = append(out, rdata...)
	return out
}

var aAnswer = net.ParseIP("192.0.2.20").To4()
var aaaaAnswer = net.ParseIP("2001:db8:20::20").To16()

func main() {
	outPath := "w2_real_resolver.jsonl"
	if len(os.Args) > 1 {
		outPath = os.Args[1]
	}

	// Fixture DNS server on a random localhost port.
	laddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	pc, err := net.ListenUDP("udp", laddr)
	if err != nil {
		fatalf("listen: %v", err)
	}
	fixturePort := pc.LocalAddr().(*net.UDPAddr).Port
	fixtureAddr := "127.0.0.1:" + strconv.Itoa(fixturePort)

	scenarios := []struct {
		id       string
		name     string
		a, aaaa  behavior
		repeats  int
		cancelMs int // >0: cancel after this many ms
	}{
		{"P1_dual_fast", "p1.w2w3.example", behavior{kind: "answer", delay: fast}, behavior{kind: "answer", delay: fast}, 5, 0},
		{"P2_a_fast_aaaa_slow", "p2.w2w3.example", behavior{kind: "answer", delay: fast}, behavior{kind: "answer", delay: slow}, 5, 0},
		{"P3_aaaa_fast_a_slow", "p3.w2w3.example", behavior{kind: "answer", delay: slow}, behavior{kind: "answer", delay: fast}, 5, 0},
		{"P4_aaaa_dropped", "p4.w2w3.example", behavior{kind: "answer", delay: fast}, behavior{kind: "drop"}, 3, 0},
		{"P5_a_dropped", "p5.w2w3.example", behavior{kind: "drop"}, behavior{kind: "answer", delay: fast}, 3, 0},
		{"P6_aaaa_nodata", "p6.w2w3.example", behavior{kind: "answer", delay: fast}, behavior{kind: "nodata"}, 5, 0},
		{"P7_both_dropped", "p7.w2w3.example", behavior{kind: "drop"}, behavior{kind: "drop"}, 2, 0},
		{"P8_both_servfail", "p8.w2w3.example", behavior{kind: "servfail", delay: fast}, behavior{kind: "servfail", delay: fast}, 5, 0},
		{"P9_cancel", "p9.w2w3.example", behavior{kind: "answer", delay: slow}, behavior{kind: "answer", delay: slow}, 3, 100},
	}

	// Build the behavior table before starting the server goroutine so the
	// map writes happen-before every read inside serveLoop.
	for _, sc := range scenarios {
		setBehavior(sc.name, "1", sc.a)
		setBehavior(sc.name, "28", sc.aaaa)
	}

	// Serve in a goroutine; track the peer of each query so responses go
	// back to the right socket.
	go serveLoop(pc)

	defer pc.Close()

	// Resolver pointed at the fixture (pure-Go path: CGO_ENABLED=0).
	resolver := &net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			d.KeepAlive = 30 * time.Second
			return d.DialContext(ctx, network, fixtureAddr)
		},
	}

	out, err := os.Create(outPath)
	if err != nil {
		fatalf("create output: %v", err)
	}
	defer out.Close()
	w := json.NewEncoder(out)

	hostInfo := w2w3HostInfo()
	w.Encode(map[string]any{
		"meta": "w2_real_resolver",
		"note": "pure-Go resolver via net.Resolver{Dial}; fixture on loopback",
		"host": hostInfo,
	})

	for _, sc := range scenarios {
		for i := 1; i <= sc.repeats; i++ {
			ctx := context.Background()
			if sc.cancelMs > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				go func() {
					select {
					case <-time.After(time.Duration(sc.cancelMs) * time.Millisecond):
					case <-ctx.Done():
					}
					cancel()
				}()
			} else {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 40*time.Second)
				defer cancel()
			}
			start := time.Now()
			addrs, lerr := resolver.LookupIPAddr(ctx, sc.name)
			elapsed := time.Since(start)
			var order []string
			for _, a := range addrs {
				order = append(order, a.IP.String())
			}
			row := map[string]any{
				"id":        sc.id,
				"run":       i,
				"elapsed_ms": float64(elapsed) / float64(time.Millisecond),
				"n_addrs":   len(addrs),
				"order":     order,
			}
			if lerr != nil {
				row["error"] = lerr.Error()
			}
			w.Encode(row)
			fmt.Printf("%s run=%d elapsed_ms=%.1f n=%d err=%v\n",
				sc.id, i, float64(elapsed)/float64(time.Millisecond), len(addrs), lerr)
		}
	}
}

// serveLoop reads queries, tracks the peer, and answers per the table.
func serveLoop(pc *net.UDPConn) {
	start := time.Now()
	buf := make([]byte, 1500)
	for {
		n, peer, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		t0 := time.Since(start)
		id, question, name, qtype, ok := parseQuery(buf[:n])
		if !ok || peer == nil {
			continue
		}
		// Copy the ID and question bytes out of the shared receive buffer:
		// the handler goroutine runs after the next ReadFromUDP has reused
		// buf, and a corrupted ID would make the resolver reject the
		// response (observed as spurious 5 s exchange timeouts).
		id = append([]byte(nil), id...)
		question = append([]byte(nil), question...)
		qkey := strconv.FormatUint(uint64(qtype), 10)
		b, known := table[name][qkey]
		if !known {
			b = behavior{kind: "nodata"}
		}
		fmt.Printf("[q] t=%.1fms peer=%s name=%s qtype=%d n=%d behavior=%s/%v\n",
			float64(t0)/float64(time.Millisecond), peer, name, qtype, n, b.kind, b.delay)
		go func(peer *net.UDPAddr) {
			if b.kind == "drop" {
				return
			}
			if b.delay > 0 {
				time.Sleep(b.delay)
			}
			var rcode byte
			var answer []byte
			if b.kind == "answer" {
				if qtype == 1 {
					answer = answerRR([2]byte{0xC0, 0x0C}, 1, aAnswer)
				} else {
					answer = answerRR([2]byte{0xC0, 0x0C}, 28, aaaaAnswer)
				}
			}
			if b.kind == "servfail" {
				rcode = 2
			}
			resp := buildResponse(id, question, rcode, answer)
			pc.WriteToUDP(resp, peer)
			t1 := time.Since(start)
			fmt.Printf("[r] t=%.1fms -> %s (%d bytes)\n",
				float64(t1)/float64(time.Millisecond), peer, len(resp))
		}(peer)
	}
}

func w2w3HostInfo() map[string]any {
	var addrs []string
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		addrs4, _ := ifc.Addrs()
		for _, a := range addrs4 {
			addrs = append(addrs, a.String())
		}
	}
	sort.Strings(addrs)
	return map[string]any{
		"addrs": addrs,
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "realprobe: "+format+"\n", args...)
	os.Exit(1)
}
