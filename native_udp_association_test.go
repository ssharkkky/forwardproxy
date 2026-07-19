// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type fakeConnectUDPStream struct {
	ctx       context.Context
	cancel    context.CancelFunc
	receive   chan []byte
	sent      chan []byte
	sendError func([]byte) error
	closeOnce sync.Once
}

func newFakeConnectUDPStream() *fakeConnectUDPStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeConnectUDPStream{
		ctx:     ctx,
		cancel:  cancel,
		receive: make(chan []byte, 16),
		sent:    make(chan []byte, 16),
	}
}

func (s *fakeConnectUDPStream) Context() context.Context { return s.ctx }

func (s *fakeConnectUDPStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case datagram := <-s.receive:
		return append([]byte(nil), datagram...), nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.ctx.Done():
		return nil, context.Cause(s.ctx)
	}
}

func (s *fakeConnectUDPStream) SendDatagram(datagram []byte) error {
	if s.sendError != nil {
		if err := s.sendError(datagram); err != nil {
			return err
		}
	}
	select {
	case s.sent <- append([]byte(nil), datagram...):
		return nil
	case <-s.ctx.Done():
		return context.Cause(s.ctx)
	}
}

func (s *fakeConnectUDPStream) CancelRead(quic.StreamErrorCode)  { s.close() }
func (s *fakeConnectUDPStream) CancelWrite(quic.StreamErrorCode) { s.close() }
func (s *fakeConnectUDPStream) Close() error                     { s.close(); return nil }
func (s *fakeConnectUDPStream) close() {
	s.closeOnce.Do(s.cancel)
}

type fakeDatagramConn struct {
	reads     chan []byte
	writes    chan []byte
	writeErr  error
	writeCall int
	mu        sync.Mutex
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeDatagramConn() *fakeDatagramConn {
	return &fakeDatagramConn{
		reads:  make(chan []byte, 16),
		writes: make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func (c *fakeDatagramConn) Read(buffer []byte) (int, error) {
	select {
	case payload := <-c.reads:
		return copy(buffer, payload), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *fakeDatagramConn) Write(payload []byte) (int, error) {
	c.mu.Lock()
	c.writeCall++
	err := c.writeErr
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	select {
	case c.writes <- append([]byte(nil), payload...):
		return len(payload), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *fakeDatagramConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *fakeDatagramConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (c *fakeDatagramConn) RemoteAddr() net.Addr             { return fakeAddr("remote") }
func (c *fakeDatagramConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeDatagramConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeDatagramConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakeDatagramConn) calls() int                       { c.mu.Lock(); defer c.mu.Unlock(); return c.writeCall }

type fakeAddr string

func (a fakeAddr) Network() string { return "udp" }
func (a fakeAddr) String() string  { return string(a) }

func TestConnectUDPAssociationBidirectionalAndLifecycle(t *testing.T) {
	stream := newFakeConnectUDPStream()
	udp := newFakeDatagramConn()
	association := &connectUDPAssociation{
		id:          1,
		stream:      stream,
		udp:         udp,
		idleTimeout: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- association.run(ctx) }()

	stream.receive <- encodeConnectUDPDatagram([]byte("to-udp"))
	select {
	case got := <-udp.writes:
		if !bytes.Equal(got, []byte("to-udp")) {
			t.Fatalf("UDP payload mismatch: %x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("H3 to UDP pump timed out")
	}

	udp.reads <- []byte("to-h3")
	select {
	case datagram := <-stream.sent:
		got, err := decodeConnectUDPDatagram(datagram)
		if err != nil || !bytes.Equal(got, []byte("to-h3")) {
			t.Fatalf("H3 payload mismatch: %x %v", got, err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP to H3 pump timed out")
	}

	stream.receive <- []byte{1, 2, 3}
	time.Sleep(10 * time.Millisecond)
	if association.counters.malformedContext.Load() != 1 {
		t.Fatal("malformed Context ID was not counted")
	}
	cancel()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("association cancellation leaked a pump")
	}
}

func TestConnectUDPAssociationNoReplayAndIdle(t *testing.T) {
	stream := newFakeConnectUDPStream()
	udp := newFakeDatagramConn()
	udp.writeErr = errors.New("ambiguous UDP write")
	association := &connectUDPAssociation{
		id:          2,
		stream:      stream,
		udp:         udp,
		idleTimeout: time.Second,
	}
	stream.receive <- encodeConnectUDPDatagram([]byte("send-once"))
	if err := association.run(context.Background()); err == nil {
		t.Fatal("expected write failure")
	}
	if udp.calls() != 1 {
		t.Fatalf("ambiguous datagram was replayed: %d writes", udp.calls())
	}

	idleStream := newFakeConnectUDPStream()
	idleUDP := newFakeDatagramConn()
	idle := &connectUDPAssociation{
		id:          3,
		stream:      idleStream,
		udp:         idleUDP,
		idleTimeout: 25 * time.Millisecond,
	}
	started := time.Now()
	if err := idle.run(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected idle result: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("idle association did not close promptly")
	}
}

func TestConnectUDPAdmissionLimits(t *testing.T) {
	h := Handler{connectUDPMaxActive: 2, connectUDPMaxClientActive: 1}
	_, releaseA, ok := h.acquireConnectUDP("192.0.2.1")
	if !ok {
		t.Fatal("first association rejected")
	}
	if _, _, ok := h.acquireConnectUDP("192.0.2.1"); ok {
		t.Fatal("per-client limit not enforced")
	}
	_, releaseB, ok := h.acquireConnectUDP("192.0.2.2")
	if !ok {
		t.Fatal("second client rejected")
	}
	if _, _, ok := h.acquireConnectUDP("192.0.2.3"); ok {
		t.Fatal("global limit not enforced")
	}
	releaseA()
	releaseA()
	_, releaseC, ok := h.acquireConnectUDP("192.0.2.3")
	if !ok {
		t.Fatal("released capacity was not reusable")
	}
	releaseB()
	releaseC()
	h.connectUDPMu.Lock()
	defer h.connectUDPMu.Unlock()
	if h.connectUDPActive != 0 || len(h.connectUDPByClient) != 0 {
		t.Fatalf("admission leak: active=%d clients=%v", h.connectUDPActive, h.connectUDPByClient)
	}
}

func TestConnectUDPAssociationCloseReason(t *testing.T) {
	if got := connectUDPAssociationCloseReason(context.DeadlineExceeded); got != "idle_expired" {
		t.Fatalf("deadline reason: %q", got)
	}
	if got := connectUDPAssociationCloseReason(context.Canceled); got != "canceled" {
		t.Fatalf("cancellation reason: %q", got)
	}
	if got := connectUDPAssociationCloseReason(io.EOF); got != "closed" {
		t.Fatalf("generic close reason: %q", got)
	}
}

func TestM4G3ProductionUDPAssociation(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, connectUDPMaxUDPPayload)
		for {
			n, peer, err := echo.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buffer[:n], peer)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := connectUDPURIPrefix + "127.0.0.1/" + strconv.Itoa(echo.LocalAddr().(*net.UDPAddr).Port) + "/"
	qconn, stream, response := openConnectUDPClientStream(t, ctx, caddyForwardProxy.addr, path, "")
	defer qconn.CloseWithError(0, "test complete")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected CONNECT-UDP response: %s", response.Status)
	}

	payloads := [][]byte{[]byte("m4-g3-production-udp"), nil}
	for _, payload := range payloads {
		if err := stream.SendDatagram(encodeConnectUDPDatagram(payload)); err != nil {
			t.Fatal(err)
		}
		datagram, err := stream.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeConnectUDPDatagram(datagram)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("production echo mismatch: got %x want %x err=%v", got, payload, err)
		}
	}
	stream.CancelRead(0)
	stream.CancelWrite(0)
	t.Log("M4_G3_UDP_ASSOCIATION_OK")
}
