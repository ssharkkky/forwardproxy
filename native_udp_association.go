// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var (
	errConnectUDPResourceLimit = errors.New("connect-udp resource limit reached")
	errConnectUDPDial          = errors.New("connect-udp target connection failed")
	errConnectUDPClosed        = errors.New("connect-udp association closed")
)

type connectUDPDatagramStream interface {
	Context() context.Context
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	Close() error
}

type connectUDPAssociationCounters struct {
	malformedContext atomic.Uint64
	oversize         atomic.Uint64
	udpReadError     atomic.Uint64
	udpWriteError    atomic.Uint64
	h3ReadError      atomic.Uint64
	h3WriteError     atomic.Uint64
}

type connectUDPAssociation struct {
	id          uint64
	stream      connectUDPDatagramStream
	udp         net.Conn
	idleTimeout time.Duration
	counters    connectUDPAssociationCounters
}

func (h *Handler) serveConnectUDP(w http.ResponseWriter, r *http.Request) error {
	target, err := parseConnectUDPTarget(r)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, errConnectUDPMalformed)
	}
	if h.upstream != nil {
		return caddyhttp.Error(connectUDPUnsupportedStatus, errConnectUDPUnsupported)
	}

	associationID, release, ok := h.acquireConnectUDP(clientAddressKey(r.RemoteAddr))
	if !ok {
		return caddyhttp.Error(connectUDPResourceStatus, errConnectUDPResourceLimit)
	}
	defer release()

	resolved, failure := h.resolveTargetCheckACL(r.Context(), target.hostPort)
	if failure != nil {
		return caddyhttp.Error(failure.statusCode(), failure)
	}

	streamer, settingser, err := http3CapabilitiesFromResponseWriter(w)
	if err != nil {
		return caddyhttp.Error(connectUDPUnsupportedStatus, errConnectUDPUnsupported)
	}
	select {
	case <-settingser.ReceivedSettings():
	case <-r.Context().Done():
		return r.Context().Err()
	}
	settings := settingser.Settings()
	if settings == nil || !settings.EnableDatagrams {
		return caddyhttp.Error(connectUDPUnsupportedStatus, errConnectUDPUnsupported)
	}

	udp, err := h.dialConnectUDPTarget(r.Context(), resolved)
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, errConnectUDPDial)
	}
	defer udp.Close()

	w.WriteHeader(http.StatusOK)
	stream := streamer.HTTPStream()
	if stream == nil {
		return nil
	}
	idleTimeout := h.connectUDPIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = connectUDPAssociationIdleTime
	}
	association := connectUDPAssociation{
		id:          associationID,
		stream:      stream,
		udp:         udp,
		idleTimeout: idleTimeout,
	}
	_ = association.run(r.Context())
	return nil
}

func (h *Handler) dialConnectUDPTarget(ctx context.Context, target resolvedTarget) (net.Conn, error) {
	dial := h.connectUDPDial
	if dial == nil {
		timeout := time.Duration(h.DialTimeout)
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	for _, address := range target.addresses {
		conn, err := dial(ctx, "udp", address)
		if err == nil && conn != nil {
			return conn, nil
		}
	}
	return nil, errConnectUDPDial
}

func clientAddressKey(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil || host == "" {
		return "unknown"
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(host)
}

func (h *Handler) acquireConnectUDP(client string) (uint64, func(), bool) {
	maxActive := h.connectUDPMaxActive
	if maxActive <= 0 {
		maxActive = connectUDPMaxAssociations
	}
	maxClient := h.connectUDPMaxClientActive
	if maxClient <= 0 {
		maxClient = connectUDPMaxPerClient
	}

	h.connectUDPMu.Lock()
	if h.connectUDPByClient == nil {
		h.connectUDPByClient = make(map[string]int)
	}
	if h.connectUDPActive >= maxActive || h.connectUDPByClient[client] >= maxClient {
		h.connectUDPMu.Unlock()
		return 0, nil, false
	}
	h.connectUDPActive++
	h.connectUDPByClient[client]++
	h.connectUDPNextID++
	id := h.connectUDPNextID
	h.connectUDPMu.Unlock()

	var once sync.Once
	release := func() {
		once.Do(func() {
			h.connectUDPMu.Lock()
			h.connectUDPActive--
			h.connectUDPByClient[client]--
			if h.connectUDPByClient[client] == 0 {
				delete(h.connectUDPByClient, client)
			}
			h.connectUDPMu.Unlock()
		})
	}
	return id, release, true
}

func (a *connectUDPAssociation) run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	results := make(chan error, 2)
	activity := make(chan struct{}, 1)

	go func() { results <- a.pumpH3ToUDP(ctx, activity) }()
	go func() { results <- a.pumpUDPToH3(ctx, activity) }()

	timer := time.NewTimer(a.idleTimeout)
	defer timer.Stop()
	completed := 0
	var result error
	for result == nil {
		select {
		case err := <-results:
			completed++
			if err == nil {
				err = errConnectUDPClosed
			}
			result = err
		case <-activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(a.idleTimeout)
		case <-timer.C:
			result = context.DeadlineExceeded
		case <-parent.Done():
			result = context.Cause(parent)
		case <-a.stream.Context().Done():
			result = context.Cause(a.stream.Context())
		}
	}

	cancel()
	a.stream.CancelRead(0)
	a.stream.CancelWrite(0)
	_ = a.udp.Close()
	for completed < 2 {
		<-results
		completed++
	}
	_ = a.stream.Close()
	return result
}

func (a *connectUDPAssociation) pumpH3ToUDP(ctx context.Context, activity chan<- struct{}) error {
	for count := 1; ; count++ {
		datagram, err := a.stream.ReceiveDatagram(ctx)
		if err != nil {
			a.counters.h3ReadError.Add(1)
			return err
		}
		payload, err := decodeConnectUDPDatagram(datagram)
		if err != nil || len(payload) > connectUDPMaxUDPPayload {
			a.counters.malformedContext.Add(1)
			continue
		}
		n, err := a.udp.Write(payload)
		if err != nil {
			a.counters.udpWriteError.Add(1)
			return err
		}
		if n != len(payload) {
			a.counters.udpWriteError.Add(1)
			return io.ErrShortWrite
		}
		notifyConnectUDPActivity(activity)
		if count%connectUDPMaxPumpDatagrams == 0 {
			runtime.Gosched()
		}
	}
}

func (a *connectUDPAssociation) pumpUDPToH3(ctx context.Context, activity chan<- struct{}) error {
	buffer := make([]byte, connectUDPMaxUDPPayload)
	for count := 1; ; count++ {
		n, err := a.udp.Read(buffer)
		if err != nil {
			a.counters.udpReadError.Add(1)
			return err
		}
		datagram := encodeConnectUDPDatagram(buffer[:n])
		if err := a.stream.SendDatagram(datagram); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				a.counters.oversize.Add(1)
				continue
			}
			a.counters.h3WriteError.Add(1)
			return err
		}
		notifyConnectUDPActivity(activity)
		if count%connectUDPMaxPumpDatagrams == 0 {
			runtime.Gosched()
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		default:
		}
	}
}

func notifyConnectUDPActivity(activity chan<- struct{}) {
	select {
	case activity <- struct{}{}:
	default:
	}
}

var _ connectUDPDatagramStream = (*http3.Stream)(nil)
