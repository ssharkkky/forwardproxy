// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func startM4UDPEcho(t *testing.T, network, address string) *net.UDPConn {
	t.Helper()
	udpAddress, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP(network, udpAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, connectUDPMaxUDPPayload)
		for {
			n, peer, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:n], peer)
		}
	}()
	return conn
}

func connectUDPPath(host string, port int) string {
	return connectUDPURIPrefix + host + "/" + strconv.Itoa(port) + "/"
}

func expectConnectUDPStatus(
	t *testing.T,
	proxyAddress string,
	path string,
	authorization string,
	want int,
) {
	t.Helper()
	got := connectUDPStatus(t, proxyAddress, path, authorization)
	if got != want {
		t.Fatalf("CONNECT-UDP status: got %d want %d", got, want)
	}
}

func connectUDPStatus(t *testing.T, proxyAddress string, path string, authorization string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qconn, stream, response := openConnectUDPClientStream(t, ctx, proxyAddress, path, authorization)
	defer qconn.CloseWithError(0, "test complete")
	stream.CancelRead(0)
	stream.CancelWrite(0)
	return response.StatusCode
}

func expectConnectUDPEcho(
	t *testing.T,
	proxyAddress string,
	path string,
	authorization string,
	payload []byte,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qconn, stream, response := openConnectUDPClientStream(t, ctx, proxyAddress, path, authorization)
	defer qconn.CloseWithError(0, "test complete")
	defer stream.CancelRead(0)
	defer stream.CancelWrite(0)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected CONNECT-UDP response: %s", response.Status)
	}
	if err := stream.SendDatagram(encodeConnectUDPDatagram(payload)); err != nil {
		t.Fatal(err)
	}
	datagram, err := stream.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeConnectUDPDatagram(datagram)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %x want %x err=%v", got, payload, err)
	}
}

func TestM4G4ForwardProxyIntegration(t *testing.T) {
	ipv4Echo := startM4UDPEcho(t, "udp4", "127.0.0.1:0")
	ipv4Port := ipv4Echo.LocalAddr().(*net.UDPAddr).Port
	ipv4Path := connectUDPPath("127.0.0.1", ipv4Port)
	ipv6Echo := startM4UDPEcho(t, "udp6", "[::1]:0")
	ipv6Port := ipv6Echo.LocalAddr().(*net.UDPAddr).Port
	// Bind IPv4 on the same port so a domain target succeeds regardless of
	// whether the platform resolver orders ::1 or 127.0.0.1 first.
	_ = startM4UDPEcho(t, "udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(ipv6Port)))

	t.Run("ipv4", func(t *testing.T) {
		expectConnectUDPEcho(t, caddyForwardProxy.addr, ipv4Path, "", []byte("m4-g4-ipv4"))
	})
	t.Run("domain", func(t *testing.T) {
		expectConnectUDPEcho(t, caddyForwardProxy.addr, connectUDPPath("localhost", ipv6Port), "", []byte("m4-g4-domain"))
	})
	t.Run("ipv6", func(t *testing.T) {
		expectConnectUDPEcho(t, caddyForwardProxy.addr, connectUDPPath("%3A%3A1", ipv6Port), "", []byte("m4-g4-ipv6"))
	})

	t.Run("auth_missing", func(t *testing.T) {
		expectConnectUDPStatus(t, caddyForwardProxyAuth.addr, ipv4Path, "", http.StatusProxyAuthRequired)
	})
	t.Run("auth_wrong", func(t *testing.T) {
		expectConnectUDPStatus(t, caddyForwardProxyAuth.addr, ipv4Path, "Basic d3Jvbmc6Y3JlZGVudGlhbA==", http.StatusProxyAuthRequired)
	})
	t.Run("auth_correct", func(t *testing.T) {
		expectConnectUDPEcho(t, caddyForwardProxyAuth.addr, ipv4Path, credentialsCorrect, []byte("m4-g4-auth"))
	})

	t.Run("malformed", func(t *testing.T) {
		expectConnectUDPStatus(t, caddyForwardProxy.addr, connectUDPURIPrefix+"127.0.0.1/0/", "", http.StatusBadRequest)
	})
	t.Run("allowed_port_denied", func(t *testing.T) {
		expectConnectUDPStatus(t, caddyForwardProxyWhiteListing.addr, ipv4Path, "", http.StatusForbidden)
	})
	t.Run("acl_denied", func(t *testing.T) {
		expectConnectUDPStatus(t, caddyForwardProxyNoBlacklistOverride.addr, ipv4Path, "", http.StatusForbidden)
	})
	t.Run("upstream_unsupported", func(t *testing.T) {
		expectConnectUDPStatus(t, caddyAuthedUpstreamEnter.addr, ipv4Path, credentialsUpstreamCorrect, http.StatusNotImplemented)
	})
	t.Run("probe_resistance_passthrough", func(t *testing.T) {
		probeStatus := connectUDPStatus(t, caddyForwardProxyProbeResist.addr, ipv4Path, "")
		referenceStatus := connectUDPStatus(t, caddyDummyProbeResist.addr, ipv4Path, "")
		if probeStatus != referenceStatus || probeStatus == http.StatusProxyAuthRequired {
			t.Fatalf("probe response exposed proxy: probe=%d reference=%d", probeStatus, referenceStatus)
		}
	})

	t.Log("M4_G4_FORWARDPROXY_INTEGRATION_OK")
}

func TestConnectUDPRequestPrivacy(t *testing.T) {
	const target = "sensitive-target.example"
	originalPath := connectUDPPath(target, 4444)
	r := connectUDPRequest(t, originalPath)
	r.RequestURI = originalPath
	r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))

	h := Handler{
		Hosts:           caddyhttp.MatchHost{"proxy.localhost"},
		ProbeResistance: &ProbeResistance{},
		AuthCredentials: [][]byte{[]byte("different")},
	}
	var nextPath string
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) error {
		nextPath = request.URL.EscapedPath()
		return nil
	})
	if err := h.ServeHTTP(newPrivacyResponseWriter(), r, next); err != nil {
		t.Fatal(err)
	}
	if nextPath != originalPath {
		t.Fatalf("probe-resistance handler did not see original path: %q", nextPath)
	}
	if r.URL.Path != connectUDPRedactedPath || r.RequestURI != connectUDPRedactedPath {
		t.Fatalf("request was not redacted before return: URL=%q URI=%q", r.URL.Path, r.RequestURI)
	}
	serialized := fmt.Sprintf("%s %s %v", r.URL.String(), r.RequestURI, r.Header)
	if strings.Contains(serialized, target) {
		t.Fatalf("redacted request leaked target: %s", serialized)
	}
}

func TestConnectUDPAssociationPrivacyCounters(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	association := connectUDPAssociation{id: 77, logger: zap.New(core)}
	for range 4 {
		association.countEvent(&association.counters.malformedContext, "malformed_context", 9)
	}
	entries := observed.All()
	if len(entries) != 3 {
		t.Fatalf("powers-of-two logging: got %d entries want 3", len(entries))
	}
	wantCounts := []uint64{1, 2, 4}
	for i, entry := range entries {
		fields := entry.ContextMap()
		if fields["association_id"] != uint64(77) || fields["reason"] != "malformed_context" ||
			fields["count"] != wantCounts[i] || fields["bytes"] != int64(9) {
			t.Fatalf("unexpected structured counter %d: %#v", i, fields)
		}
		serialized := fmt.Sprintf("%s %#v", entry.Message, fields)
		for _, forbidden := range []string{"sensitive-target.example", connectUDPURIPrefix, "payload-secret", "credential-secret"} {
			if strings.Contains(serialized, forbidden) {
				t.Fatalf("counter leaked private value %q: %s", forbidden, serialized)
			}
		}
	}
}

type privacyResponseWriter struct {
	header http.Header
}

func newPrivacyResponseWriter() *privacyResponseWriter {
	return &privacyResponseWriter{header: make(http.Header)}
}

func (w *privacyResponseWriter) Header() http.Header       { return w.header }
func (w *privacyResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *privacyResponseWriter) WriteHeader(int)           {}
