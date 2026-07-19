// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

// m4-rfc9298-client is an independent interoperability client for the M4
// production Caddy binary. It deliberately does not import forwardproxy or
// NaiveProxy test helpers.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	connectUDPProtocol  = "connect-udp"
	connectUDPURIPrefix = "/.well-known/masque/udp/"
	privateDomainTarget = "m4-private-target.localhost"
	privatePayload      = "m4-g5-private-payload"
)

type client struct {
	proxy     string
	auth      string
	quic      *quic.Conn
	http3     *http3.ClientConn
	transport *http3.Transport
}

func dialClient(ctx context.Context, proxy, username, password string) (*client, error) {
	host, _, err := net.SplitHostPort(proxy)
	if err != nil {
		return nil, err
	}
	qconn, err := quic.DialAddr(ctx, proxy, &tls.Config{
		InsecureSkipVerify: true, // controlled local M4 fixture
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         host,
	}, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
		MaxIdleTimeout:  3 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	transport := &http3.Transport{EnableDatagrams: true}
	h3conn := transport.NewClientConn(qconn)
	select {
	case <-h3conn.ReceivedSettings():
	case <-ctx.Done():
		_ = qconn.CloseWithError(0, "settings timeout")
		return nil, ctx.Err()
	}
	settings := h3conn.Settings()
	if settings == nil || !settings.EnableDatagrams || !settings.EnableExtendedConnect {
		_ = qconn.CloseWithError(0, "missing settings")
		return nil, fmt.Errorf("server did not negotiate RFC 9297 settings: %+v", settings)
	}
	auth := ""
	if username != "" || password != "" {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}
	return &client{proxy: proxy, auth: auth, quic: qconn, http3: h3conn, transport: transport}, nil
}

func (c *client) close() {
	_ = c.quic.CloseWithError(0, "interop complete")
}

func (c *client) open(ctx context.Context, host string, port int) (*http3.RequestStream, int, error) {
	stream, err := c.http3.OpenRequestStream(ctx)
	if err != nil {
		return nil, 0, err
	}
	rawURL := "https://" + c.proxy + connectUDPURIPrefix + url.PathEscape(host) + "/" + strconv.Itoa(port) + "/"
	requestURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, err
	}
	request := &http.Request{
		Method:     http.MethodConnect,
		URL:        requestURL,
		Host:       requestURL.Host,
		Proto:      connectUDPProtocol,
		ProtoMajor: 3,
		Header:     make(http.Header),
	}
	request.Header.Set("Capsule-Protocol", "?1")
	if c.auth != "" {
		request.Header.Set("Proxy-Authorization", c.auth)
	}
	if err := stream.SendRequestHeader(request); err != nil {
		return nil, 0, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return nil, 0, err
	}
	return stream, response.StatusCode, nil
}

func closeStream(stream *http3.RequestStream) {
	stream.CancelRead(0)
	stream.CancelWrite(0)
}

func encode(payload []byte) []byte {
	result := make([]byte, 1, len(payload)+1)
	return append(result, payload...)
}

func decode(datagram []byte) ([]byte, error) {
	if len(datagram) == 0 || datagram[0] != 0 {
		return nil, errors.New("non-canonical or unsupported Context ID")
	}
	return datagram[1:], nil
}

func (c *client) echo(ctx context.Context, host string, port int, payload []byte) error {
	stream, status, err := c.open(ctx, host, port)
	if err != nil {
		return err
	}
	defer closeStream(stream)
	if status != http.StatusOK {
		return fmt.Errorf("CONNECT-UDP returned %d", status)
	}
	if err := stream.SendDatagram(encode(payload)); err != nil {
		return err
	}
	datagram, err := stream.ReceiveDatagram(ctx)
	if err != nil {
		return err
	}
	got, err := decode(datagram)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch: got %x want %x", got, payload)
	}
	return nil
}

func startEcho(network, address string) (*net.UDPConn, error) {
	udpAddress, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP(network, udpAddress)
	if err != nil {
		return nil, err
	}
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:n], peer)
		}
	}()
	return conn, nil
}

func startDualStackEcho() (*net.UDPConn, *net.UDPConn, int, error) {
	ipv6, err := startEcho("udp6", "[::1]:0")
	if err != nil {
		return nil, nil, 0, err
	}
	port := ipv6.LocalAddr().(*net.UDPAddr).Port
	ipv4, err := startEcho("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		_ = ipv6.Close()
		return nil, nil, 0, err
	}
	return ipv4, ipv6, port, nil
}

func startDNSFixture() (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, err
	}
	go func() {
		buffer := make([]byte, 512)
		for {
			n, peer, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			response := append([]byte(nil), buffer[:n]...)
			response[2] |= 0x80 // QR=response, preserve the query and ID.
			response[3] |= 0x80 // recursion available
			response[6], response[7] = 0, 0
			_, _ = conn.WriteToUDP(response, peer)
		}
	}()
	return conn, nil
}

func dnsQuery() []byte {
	return []byte{
		0x4d, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x02, 'm', '4', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x00, 0x00, 0x01, 0x00, 0x01,
	}
}

func runMatrix(ctx context.Context, c *client) error {
	ipv4, err := startEcho("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ipv4.Close()
	ipv4Port := ipv4.LocalAddr().(*net.UDPAddr).Port
	ipv4Domain, ipv6, dualPort, err := startDualStackEcho()
	if err != nil {
		return err
	}
	defer ipv4Domain.Close()
	defer ipv6.Close()
	dns, err := startDNSFixture()
	if err != nil {
		return err
	}
	defer dns.Close()

	if err := c.echo(ctx, "127.0.0.1", ipv4Port, []byte(privatePayload+"-ipv4")); err != nil {
		return err
	}
	if err := c.echo(ctx, "::1", dualPort, []byte(privatePayload+"-ipv6")); err != nil {
		return err
	}
	if err := c.echo(ctx, privateDomainTarget, dualPort, []byte(privatePayload+"-domain")); err != nil {
		return err
	}
	if err := c.echo(ctx, "127.0.0.1", ipv4Port, nil); err != nil {
		return fmt.Errorf("zero-length datagram: %w", err)
	}
	if err := c.echo(ctx, "127.0.0.1", ipv4Port, bytes.Repeat([]byte{0xa5}, 1024)); err != nil {
		return fmt.Errorf("safe maximum probe: %w", err)
	}

	query := dnsQuery()
	stream, status, err := c.open(ctx, "127.0.0.1", dns.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		closeStream(stream)
		return fmt.Errorf("DNS CONNECT-UDP returned %d", status)
	}
	if err := stream.SendDatagram(encode(query)); err != nil {
		closeStream(stream)
		return err
	}
	dnsDatagram, err := stream.ReceiveDatagram(ctx)
	closeStream(stream)
	if err != nil {
		return err
	}
	dnsResponse, err := decode(dnsDatagram)
	if err != nil || len(dnsResponse) < 12 || dnsResponse[0] != 0x4d || dnsResponse[1] != 0x34 || dnsResponse[2]&0x80 == 0 {
		return fmt.Errorf("invalid deterministic DNS response: %x %v", dnsResponse, err)
	}

	stream, status, err = c.open(ctx, "127.0.0.1", ipv4Port)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("oversize stream: status=%d err=%v", status, err)
	}
	oversizeErr := stream.SendDatagram(encode(make([]byte, 65535)))
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(oversizeErr, &tooLarge) {
		closeStream(stream)
		return fmt.Errorf("oversize datagram was not rejected locally: %v", oversizeErr)
	}
	if err := stream.SendDatagram(encode([]byte("post-oversize"))); err != nil {
		closeStream(stream)
		return err
	}
	postOversize, err := stream.ReceiveDatagram(ctx)
	closeStream(stream)
	if err != nil {
		return err
	}
	decoded, err := decode(postOversize)
	if err != nil || !bytes.Equal(decoded, []byte("post-oversize")) {
		return fmt.Errorf("association unhealthy after oversize: %x %v", decoded, err)
	}

	var wg sync.WaitGroup
	errorsOut := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("parallel-%d", index))
			errorsOut <- c.echo(ctx, "127.0.0.1", ipv4Port, payload)
		}(i)
	}
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			return fmt.Errorf("parallel stream: %w", err)
		}
	}

	cancelStream, status, err := c.open(ctx, "127.0.0.1", ipv4Port)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("cancel stream: status=%d err=%v", status, err)
	}
	closeStream(cancelStream)
	time.Sleep(50 * time.Millisecond)
	if err := c.echo(ctx, "127.0.0.1", ipv4Port, []byte("post-cancel")); err != nil {
		return fmt.Errorf("association unhealthy after cancellation: %w", err)
	}

	fmt.Println("M4_G5_IPV4_OK")
	fmt.Println("M4_G5_IPV6_OK")
	fmt.Println("M4_G5_DOMAIN_OK")
	fmt.Println("M4_G5_DNS_OK")
	fmt.Println("M4_G5_ZERO_MAX_OVERSIZE_OK")
	fmt.Println("M4_G5_MULTISTREAM_CANCEL_OK")
	fmt.Println("M4_G5_H3_DATAGRAM_EVIDENCE_OK settings=extended-connect,datagram transport=RequestStream.SendDatagram")
	return nil
}

func runLimits(ctx context.Context, c *client) error {
	echo, err := startEcho("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer echo.Close()
	port := echo.LocalAddr().(*net.UDPAddr).Port
	streams := make([]*http3.RequestStream, 0, 32)
	defer func() {
		for _, stream := range streams {
			closeStream(stream)
		}
	}()
	for range 32 {
		stream, status, err := c.open(ctx, "127.0.0.1", port)
		if err != nil || status != http.StatusOK {
			return fmt.Errorf("association admission %d: status=%d err=%v", len(streams)+1, status, err)
		}
		streams = append(streams, stream)
	}
	rejected, status, err := c.open(ctx, "127.0.0.1", port)
	if err != nil {
		return err
	}
	closeStream(rejected)
	if status != http.StatusServiceUnavailable {
		return fmt.Errorf("33rd association: got %d want 503", status)
	}
	closeStream(streams[0])
	streams = streams[1:]
	for attempt := 0; attempt < 20; attempt++ {
		time.Sleep(50 * time.Millisecond)
		replacement, replacementStatus, err := c.open(ctx, "127.0.0.1", port)
		if err != nil {
			return err
		}
		if replacementStatus == http.StatusOK {
			streams = append(streams, replacement)
			fmt.Println("M4_G5_RESOURCE_LIMIT_OK")
			return nil
		}
		closeStream(replacement)
	}
	return errors.New("released association capacity was not reusable")
}

func runIdle(ctx context.Context, c *client) error {
	echo, err := startEcho("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer echo.Close()
	stream, status, err := c.open(ctx, "127.0.0.1", echo.LocalAddr().(*net.UDPAddr).Port)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("idle stream: status=%d err=%v", status, err)
	}
	defer closeStream(stream)
	started := time.Now()
	idleWait, cancel := context.WithTimeout(ctx, 125*time.Second)
	defer cancel()
	_, err = stream.ReceiveDatagram(idleWait)
	if err == nil {
		return errors.New("idle association unexpectedly produced a datagram")
	}
	if time.Since(started) < 120*time.Second {
		return fmt.Errorf("association closed before production idle bound: %v", time.Since(started))
	}
	if err := stream.SendDatagram(encode([]byte("expired-stream"))); err == nil {
		lateCtx, lateCancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer lateCancel()
		if datagram, receiveErr := stream.ReceiveDatagram(lateCtx); receiveErr == nil {
			return fmt.Errorf("expired association still echoed: %x", datagram)
		}
	}
	if err := c.echo(ctx, "127.0.0.1", echo.LocalAddr().(*net.UDPAddr).Port, []byte("post-idle")); err != nil {
		return fmt.Errorf("fresh association after idle expiry: %w", err)
	}
	fmt.Printf("M4_G5_IDLE_CLIENT_RECOVERY_OK elapsed=%s\n", time.Since(started).Round(time.Second))
	return nil
}

func runShutdown(ctx context.Context, c *client) error {
	echo, err := startEcho("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer echo.Close()
	stream, status, err := c.open(ctx, "127.0.0.1", echo.LocalAddr().(*net.UDPAddr).Port)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("shutdown stream: status=%d err=%v", status, err)
	}
	defer closeStream(stream)
	if err := stream.SendDatagram(encode([]byte("shutdown-ready"))); err != nil {
		return err
	}
	if _, err := stream.ReceiveDatagram(ctx); err != nil {
		return err
	}
	fmt.Println("M4_G5_SHUTDOWN_CLIENT_READY")
	select {
	case <-stream.Context().Done():
		fmt.Println("M4_G5_SERVER_SHUTDOWN_OBSERVED")
		return nil
	case <-ctx.Done():
		return errors.New("server shutdown did not close the active H3 stream")
	}
}

func main() {
	mode := flag.String("mode", "matrix", "smoke, matrix, limits, idle, or shutdown")
	proxy := flag.String("proxy", "127.0.0.1:19443", "production Caddy address")
	username := flag.String("username", "test", "proxy username")
	password := flag.String("password", "pass", "proxy password")
	timeout := flag.Duration("timeout", 30*time.Second, "operation timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c, err := dialClient(ctx, *proxy, *username, *password)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer c.close()

	switch *mode {
	case "smoke":
		echo, startErr := startEcho("udp4", "127.0.0.1:0")
		if startErr == nil {
			defer echo.Close()
			startErr = c.echo(ctx, "127.0.0.1", echo.LocalAddr().(*net.UDPAddr).Port, []byte("smoke"))
		}
		err = startErr
		if err == nil {
			fmt.Println("M4_G5_BINARY_SMOKE_OK")
		}
	case "matrix":
		err = runMatrix(ctx, c)
	case "limits":
		err = runLimits(ctx, c)
	case "idle":
		err = runIdle(ctx, c)
	case "shutdown":
		err = runShutdown(ctx, c)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
