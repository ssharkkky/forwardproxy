// Diagnostic: one lookup against the fixture with nettrace DNS logging.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

func main() {
	laddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	pc, err := net.ListenUDP("udp", laddr)
	if err != nil {
		panic(err)
	}
	defer pc.Close()
	fixtureAddr := pc.LocalAddr().String()
	fmt.Println("fixture:", fixtureAddr)

	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Parse minimal: id, name, qtype
			if n < 16 {
				continue
			}
			id := buf[0:2]
			off := 12
			var parts []string
			for off < n {
				l := int(buf[off])
				off++
				if l == 0 {
					break
				}
				parts = append(parts, string(buf[off:off+l]))
				off += l
			}
			name := fmt.Sprintf("%q", parts)
			var qtype uint16
			if off+2 <= n {
				qtype = binary.BigEndian.Uint16(buf[off : off+2])
			}
			fmt.Printf("[q] %s name=%s qtype=%d n=%d hex=%s\n", peer, name, qtype, n, hex.EncodeToString(buf[:min(n, 48)]))
			// answer: A=192.0.2.20 or AAAA=2001:db8:20::20 after 1ms
			time.Sleep(1 * time.Millisecond)
			q := buf[12 : off+4]
			ancount := uint16(0)
			var answer []byte
			a := net.ParseIP("192.0.2.20").To4()
			v6 := net.ParseIP("2001:db8:20::20").To16()
			if qtype == 1 {
				answer = rr(1, a)
			} else {
				answer = rr(28, v6)
			}
			if len(answer) > 0 {
				ancount = 1
			}
			resp := make([]byte, 0, 12+len(q)+len(answer))
			resp = append(resp, id...)
			resp = append(resp, 0x81, 0x80)
			put16 := func(v uint16) { resp = append(resp, byte(v>>8), byte(v)) }
			put16(1)
			put16(ancount)
			put16(0)
			put16(0)
			resp = append(resp, q...)
			resp = append(resp, answer...)
			pc.WriteToUDP(resp, peer)
			fmt.Printf("[r] sent %d bytes to %s\n", len(resp), peer)
		}
	}()

	r := &net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, fixtureAddr)
		},
	}
	ctx := context.Background()
	start := time.Now()
	addrs, err := r.LookupIPAddr(ctx, "diag1.w2w3.example")
	fmt.Println("result:", addrs, "err:", err, "elapsed:", time.Since(start))
}

func rr(rrtype uint16, rdata []byte) []byte {
	out := []byte{0xC0, 0x0C}
	out = append(out, byte(rrtype>>8), byte(rrtype))
	out = append(out, 0x00, 0x01)
	out = append(out, 0, 0, 0, 60)
	out = append(out, byte(len(rdata)>>8), byte(len(rdata)))
	out = append(out, rdata...)
	return out
}

