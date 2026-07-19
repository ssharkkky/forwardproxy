// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"net/http"
	"time"
)

// Native UDP v1 is deliberately limited to standard HTTP/3 CONNECT-UDP and
// HTTP Datagrams. These constants are centralized so admission, lifecycle,
// and protocol tests cannot silently diverge from production behavior.
const (
	connectUDPProtocol            = "connect-udp"
	connectUDPURIPrefix           = "/.well-known/masque/udp/"
	connectUDPContextID           = uint64(0)
	connectUDPMaxAssociations     = 256
	connectUDPMaxPerClient        = 32
	connectUDPMaxUDPPayload       = 65535
	connectUDPMaxPumpDatagrams    = 32
	connectUDPResourceStatus      = http.StatusServiceUnavailable
	connectUDPUnsupportedStatus   = http.StatusNotImplemented
	connectUDPAssociationIdleTime = 2 * time.Minute
)

// There is no forwardproxy-owned packet queue in v1: each direction has one
// in-flight datagram and backpressure remains in the UDP or quic-go socket.
// In particular, a failed or ambiguous send is never replayed.
