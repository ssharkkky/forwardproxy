// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func init() {
	caddy.RegisterModule(h3DatagramEchoHandler{})
}

// h3DatagramEchoHandler is a G1-only capability fixture. It proves the real
// Caddy middleware boundary without implementing target parsing or UDP relay.
type h3DatagramEchoHandler struct{}

func (h3DatagramEchoHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.m4_h3_datagram_echo",
		New: func() caddy.Module { return new(h3DatagramEchoHandler) },
	}
}

func (h3DatagramEchoHandler) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct{}{})
}

func (h3DatagramEchoHandler) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
	next caddyhttp.Handler,
) error {
	if r.Method != http.MethodConnect || r.ProtoMajor != 3 || r.Proto != connectUDPProtocol {
		return next.ServeHTTP(w, r)
	}
	if r.URL.Scheme != "https" || r.URL.Path != "/.well-known/masque/udp/127.0.0.1/9/" {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}
	stream, err := http3StreamFromResponseWriter(w)
	if err != nil {
		return err
	}
	for {
		datagram, err := stream.ReceiveDatagram(r.Context())
		if err != nil {
			return nil
		}
		if err := stream.SendDatagram(datagram); err != nil {
			return nil
		}
	}
}

func TestM4G1CaddyH3DatagramCapability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         "h3-echo.localhost",
	}
	loopback, err := testLoopbackAddress(caddyH3DatagramEcho.addr)
	if err != nil {
		t.Fatal(err)
	}
	qconn, err := quic.DialAddr(
		ctx,
		loopback,
		tlsConf,
		&quic.Config{EnableDatagrams: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer qconn.CloseWithError(0, "test complete")

	transport := &http3.Transport{EnableDatagrams: true}
	client := transport.NewClientConn(qconn)
	select {
	case <-client.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	settings := client.Settings()
	if !settings.EnableDatagrams || !settings.EnableExtendedConnect {
		t.Fatalf("server settings missing datagram or Extended CONNECT: %+v", settings)
	}

	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requestURL, err := url.Parse("https://h3-echo.localhost:9443/.well-known/masque/udp/127.0.0.1/9/")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        requestURL,
		Host:       requestURL.Host,
		Proto:      connectUDPProtocol,
		ProtoMajor: 3,
		Header:     make(http.Header),
	}
	req.Header.Set("Capsule-Protocol", "?1")
	if err := stream.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response: %s", response.Status)
	}

	payload := []byte("m4-g1-caddy-h3-datagram")
	if err := stream.SendDatagram(payload); err != nil {
		t.Fatal(err)
	}
	echo, err := stream.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("datagram mismatch: got %x want %x", echo, payload)
	}
	if err := stream.SendDatagram(nil); err != nil {
		t.Fatal(err)
	}
	empty, err := stream.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("zero-length datagram changed size: %d", len(empty))
	}
	stream.CancelRead(0)
	stream.CancelWrite(0)
	t.Log("M4_G1_CADDY_H3_DATAGRAM_OK")
}

var (
	_ caddy.Module                = (*h3DatagramEchoHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*h3DatagramEchoHandler)(nil)
)
