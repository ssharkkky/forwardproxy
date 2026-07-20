// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"testing"
)

func fuzzConnectUDPRequest(rawPath string) (*http.Request, bool) {
	u, err := url.Parse("https://proxy.localhost" + rawPath)
	if err != nil {
		return nil, false
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
	return r, true
}

func FuzzParseConnectUDPTarget(f *testing.F) {
	for _, path := range []string{
		connectUDPURIPrefix + "192.0.2.1/53/",
		connectUDPURIPrefix + "%3A%3A1/443/",
		connectUDPURIPrefix + "example.test/65535/",
		connectUDPURIPrefix + "example%2Ftest/53/",
		"",
		"/",
	} {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, rawPath string) {
		if len(rawPath) > 4096 {
			t.Skip()
		}
		r, ok := fuzzConnectUDPRequest(rawPath)
		if !ok {
			return
		}
		target, err := parseConnectUDPTarget(r)
		if err != nil {
			return
		}
		if target.host == "" || target.port == "" ||
			target.hostPort != net.JoinHostPort(target.host, target.port) {
			t.Fatalf("accepted target violates output invariant")
		}
		port, err := strconv.Atoi(target.port)
		if err != nil || port < 1 || port > 65535 {
			t.Fatalf("accepted target has invalid port")
		}
	})
}

func FuzzConnectUDPContextCodec(f *testing.F) {
	for _, packet := range [][]byte{
		nil,
		{},
		{0},
		{0, 1, 2, 255},
		{1},
		{0x40, 0},
	} {
		f.Add(packet)
	}
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 65536 {
			t.Skip()
		}
		payload, err := decodeConnectUDPDatagram(packet)
		if err != nil {
			return
		}
		rebuilt := encodeConnectUDPDatagram(payload)
		reparsed, err := decodeConnectUDPDatagram(rebuilt)
		if err != nil || !reflect.DeepEqual(reparsed, payload) {
			t.Fatalf("accepted Context ID failed canonical round trip")
		}
	})
}
