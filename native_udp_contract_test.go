// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"net/http"
	"testing"
	"time"
)

func TestM4G0ContractBaseline(t *testing.T) {
	if connectUDPProtocol != "connect-udp" {
		t.Fatalf("unexpected Extended CONNECT protocol: %q", connectUDPProtocol)
	}
	if connectUDPURIPrefix != "/.well-known/masque/udp/" {
		t.Fatalf("unexpected URI template prefix: %q", connectUDPURIPrefix)
	}
	if connectUDPContextID != 0 {
		t.Fatalf("v1 only supports Context ID 0")
	}
	if connectUDPMaxAssociations <= connectUDPMaxPerClient || connectUDPMaxPerClient <= 0 {
		t.Fatalf("invalid association limits")
	}
	if connectUDPMaxUDPPayload != 65535 || connectUDPMaxPumpDatagrams <= 0 {
		t.Fatalf("invalid datagram limits")
	}
	if connectUDPAssociationIdleTime < time.Minute {
		t.Fatalf("idle timeout is too short for production")
	}
	if connectUDPResourceStatus != http.StatusServiceUnavailable ||
		connectUDPUnsupportedStatus != http.StatusNotImplemented {
		t.Fatalf("unexpected frozen HTTP result mapping")
	}
	t.Log("M4_G0_SERVER_BASELINE_OK")
}
