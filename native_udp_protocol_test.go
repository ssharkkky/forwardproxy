// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func connectUDPRequest(t *testing.T, rawPath string) *http.Request {
	t.Helper()
	u, err := url.Parse("https://proxy.localhost" + rawPath)
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{
		Method:     http.MethodConnect,
		URL:        u,
		Host:       u.Host,
		Proto:      connectUDPProtocol,
		ProtoMajor: 3,
		Header:     make(http.Header),
	}
	r.Header.Set("Capsule-Protocol", "?1")
	return r
}

func TestConnectUDPTargetParser(t *testing.T) {
	valid := []struct {
		name     string
		path     string
		host     string
		port     string
		hostPort string
	}{
		{"ipv4", connectUDPURIPrefix + "192.0.2.1/53/", "192.0.2.1", "53", "192.0.2.1:53"},
		{"ipv6", connectUDPURIPrefix + "%3A%3A1/443/", "::1", "443", "[::1]:443"},
		{"domain", connectUDPURIPrefix + "Example.COM/65535/", "example.com", "65535", "example.com:65535"},
		{"unicode", connectUDPURIPrefix + "b%C3%BCcher.example/1/", "xn--bcher-kva.example", "1", "xn--bcher-kva.example:1"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			target, err := parseConnectUDPTarget(connectUDPRequest(t, tc.path))
			if err != nil {
				t.Fatal(err)
			}
			if target.host != tc.host || target.port != tc.port || target.hostPort != tc.hostPort {
				t.Fatalf("unexpected target: %+v", target)
			}
		})
	}

	invalidPaths := []string{
		connectUDPURIPrefix,
		connectUDPURIPrefix + "/53/",
		connectUDPURIPrefix + "example.com//",
		connectUDPURIPrefix + "example.com/0/",
		connectUDPURIPrefix + "example.com/65536/",
		connectUDPURIPrefix + "example.com/+53/",
		connectUDPURIPrefix + "example.com/5%33/",
		connectUDPURIPrefix + "example.com/53",
		connectUDPURIPrefix + "example.com/53/extra/",
		connectUDPURIPrefix + "example%2Fcom/53/",
		connectUDPURIPrefix + "example%5Ccom/53/",
		connectUDPURIPrefix + "%253A%253A1/53/",
		connectUDPURIPrefix + "%3A%3A1%25en0/53/",
		connectUDPURIPrefix + "%5B%3A%3A1%5D/53/",
		connectUDPURIPrefix + "-bad.example/53/",
		connectUDPURIPrefix + "bad-.example/53/",
		connectUDPURIPrefix + "bad_name.example/53/",
		connectUDPURIPrefix + "example.com/53/?query=1",
		connectUDPURIPrefix + "example.com/53/#fragment",
	}
	for _, path := range invalidPaths {
		t.Run(path, func(t *testing.T) {
			if _, err := parseConnectUDPTarget(connectUDPRequest(t, path)); !errors.Is(err, errConnectUDPMalformed) {
				t.Fatalf("expected malformed error, got %v", err)
			}
		})
	}

	mutations := []func(*http.Request){
		func(r *http.Request) { r.Method = http.MethodGet },
		func(r *http.Request) { r.ProtoMajor = 2 },
		func(r *http.Request) { r.Proto = "webtransport" },
		func(r *http.Request) { r.URL.Scheme = "http" },
		func(r *http.Request) { r.Host = "other.localhost" },
		func(r *http.Request) { r.URL.User = url.User("user") },
		func(r *http.Request) { r.Header.Del("Capsule-Protocol") },
	}
	for i, mutate := range mutations {
		r := connectUDPRequest(t, connectUDPURIPrefix+"example.com/53/")
		mutate(r)
		if _, err := parseConnectUDPTarget(r); !errors.Is(err, errConnectUDPMalformed) {
			t.Fatalf("mutation %d was accepted: %v", i, err)
		}
	}
}

func TestConnectUDPContextCodec(t *testing.T) {
	payloads := [][]byte{nil, {}, {0}, {0, 1, 2, 255}}
	for _, payload := range payloads {
		encoded := encodeConnectUDPDatagram(payload)
		if len(encoded) != len(payload)+1 || encoded[0] != 0 {
			t.Fatalf("unexpected encoding: %x", encoded)
		}
		decoded, err := decodeConnectUDPDatagram(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded, payload) && !(len(decoded) == 0 && len(payload) == 0) {
			t.Fatalf("round trip mismatch: got %x want %x", decoded, payload)
		}
	}
	for _, invalid := range [][]byte{
		nil,
		{1},
		{0x40},
		{0x40, 0}, // non-canonical Context ID 0
		{0x80, 0, 0, 0},
	} {
		if _, err := decodeConnectUDPDatagram(invalid); !errors.Is(err, errConnectUDPMalformed) {
			t.Fatalf("invalid context accepted: %x", invalid)
		}
	}
}

func mustRule(t *testing.T, subject string, allow bool) aclRule {
	t.Helper()
	rule, err := newACLRule(subject, allow)
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func TestConnectUDPTargetPolicy(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "allowed.example":
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}, {IP: net.ParseIP("2001:db8::10")}}, nil
		case "duplicate.example":
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}, {IP: net.ParseIP("192.0.2.10")}}, nil
		case "lookup-fails.example":
			return nil, errors.New("resolver failure")
		default:
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.1")}}, nil
		}
	}
	h := Handler{
		AllowedPorts: []int{53},
		lookupIP:     lookup,
		aclRules: []aclRule{
			mustRule(t, "blocked.example", false),
			mustRule(t, "203.0.113.0/24", false),
			mustRule(t, "all", true),
		},
	}

	resolved, failure := h.resolveTargetCheckACL(context.Background(), "allowed.example:53")
	if failure != nil {
		t.Fatal(failure)
	}
	want := []string{"192.0.2.10:53", "[2001:db8::10]:53"}
	if !reflect.DeepEqual(resolved.addresses, want) {
		t.Fatalf("addresses mismatch: got %v want %v", resolved.addresses, want)
	}
	resolved, failure = h.resolveTargetCheckACL(context.Background(), "duplicate.example:53")
	if failure != nil || len(resolved.addresses) != 1 {
		t.Fatalf("deduplication failed: %+v %v", resolved, failure)
	}

	cases := []struct {
		address string
		kind    targetPolicyFailureKind
		status  int
	}{
		{"missing-port", targetPolicyMalformed, http.StatusBadRequest},
		{"allowed.example:54", targetPolicyPortDenied, http.StatusForbidden},
		{"blocked.example:53", targetPolicyDomainDenied, http.StatusForbidden},
		{"lookup-fails.example:53", targetPolicyLookupFailed, http.StatusBadGateway},
		{"denied-by-ip.example:53", targetPolicyNoAllowedAddress, http.StatusForbidden},
	}
	for _, tc := range cases {
		_, failure := h.resolveTargetCheckACL(context.Background(), tc.address)
		if failure == nil || failure.kind != tc.kind || failure.statusCode() != tc.status {
			t.Fatalf("%s: unexpected failure: %+v", tc.address, failure)
		}
		if strings.Contains(failure.Error(), strings.Split(tc.address, ":")[0]) {
			t.Fatalf("policy error leaked target: %q", failure)
		}
	}
}

func TestM4G2ProtocolStatusGate(t *testing.T) {
	h := Handler{
		lookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
		},
		aclRules: []aclRule{mustRule(t, "all", true)},
	}
	statusOf := func(r *http.Request) int {
		t.Helper()
		err := h.serveConnectUDPProtocolGate(httptest.NewRecorder(), r)
		var handlerErr caddyhttp.HandlerError
		if !errors.As(err, &handlerErr) {
			t.Fatalf("expected HandlerError, got %v", err)
		}
		return handlerErr.StatusCode
	}
	valid := connectUDPRequest(t, connectUDPURIPrefix+"example.com/53/")
	if got := statusOf(valid); got != http.StatusNotImplemented {
		t.Fatalf("valid pre-G3 request: got %d", got)
	}
	malformed := connectUDPRequest(t, connectUDPURIPrefix+"example.com/0/")
	if got := statusOf(malformed); got != http.StatusBadRequest {
		t.Fatalf("malformed request: got %d", got)
	}
	h.AllowedPorts = []int{443}
	if got := statusOf(valid); got != http.StatusForbidden {
		t.Fatalf("denied request: got %d", got)
	}
	h.AllowedPorts = nil
	h.upstream = &url.URL{Scheme: "https", Host: "upstream.example"}
	if got := statusOf(valid); got != http.StatusNotImplemented {
		t.Fatalf("upstream request: got %d", got)
	}
	if !isUnsupportedExtendedConnect(&http.Request{Method: http.MethodConnect, ProtoMajor: 3, Proto: "webtransport"}) {
		t.Fatal("other Extended CONNECT protocol was not classified")
	}
	t.Log("M4_G2_PROTOCOL_POLICY_OK")
}
