// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func openConnectUDPClientStream(
	t *testing.T,
	ctx context.Context,
	proxyAddress string,
	rawPath string,
	authorization string,
) (*quic.Conn, *http3.RequestStream, *http.Response) {
	t.Helper()
	host, _, err := net.SplitHostPort(proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	qconn, err := quic.DialAddr(ctx, proxyAddress, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         host,
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http3.Transport{EnableDatagrams: true}
	client := transport.NewClientConn(qconn)
	select {
	case <-client.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	settings := client.Settings()
	if !settings.EnableDatagrams || !settings.EnableExtendedConnect {
		t.Fatalf("missing server H3 settings: %+v", settings)
	}
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requestURL, err := url.Parse("https://" + proxyAddress + rawPath)
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
	if authorization != "" {
		req.Header.Set("Proxy-Authorization", authorization)
	}
	if err := stream.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	return qconn, stream, response
}
