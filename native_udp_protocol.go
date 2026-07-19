// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/idna"
)

var (
	errConnectUDPMalformed   = errors.New("connect-udp request is malformed")
	errConnectUDPUnsupported = errors.New("connect-udp is unsupported")
)

type connectUDPTarget struct {
	host     string
	port     string
	hostPort string
}

const connectUDPRedactedPath = "/.well-known/masque/udp/redacted/0/"

type targetPolicyFailureKind uint8

const (
	targetPolicyMalformed targetPolicyFailureKind = iota
	targetPolicyPortDenied
	targetPolicyDomainDenied
	targetPolicyLookupFailed
	targetPolicyNoAllowedAddress
)

type targetPolicyFailure struct {
	kind  targetPolicyFailureKind
	cause error
}

func (e *targetPolicyFailure) Error() string {
	switch e.kind {
	case targetPolicyMalformed:
		return "target address is malformed"
	case targetPolicyPortDenied:
		return "target port is not allowed"
	case targetPolicyDomainDenied, targetPolicyNoAllowedAddress:
		return "target is not allowed"
	case targetPolicyLookupFailed:
		return "target lookup failed"
	default:
		return "target policy failed"
	}
}

func (e *targetPolicyFailure) Unwrap() error { return e.cause }

func (e *targetPolicyFailure) statusCode() int {
	switch e.kind {
	case targetPolicyMalformed:
		return http.StatusBadRequest
	case targetPolicyLookupFailed:
		return http.StatusBadGateway
	default:
		return http.StatusForbidden
	}
}

func isConnectUDPRequest(r *http.Request) bool {
	return r.Method == http.MethodConnect &&
		r.ProtoMajor == 3 &&
		r.Proto == connectUDPProtocol
}

func isUnsupportedExtendedConnect(r *http.Request) bool {
	return r.Method == http.MethodConnect &&
		r.ProtoMajor == 3 &&
		r.Proto != "HTTP/3.0" &&
		r.Proto != connectUDPProtocol
}

func parseConnectUDPTarget(r *http.Request) (connectUDPTarget, error) {
	if !isConnectUDPRequest(r) || r.URL == nil || r.URL.Scheme != "https" ||
		r.Host == "" || r.URL.Host == "" || !strings.EqualFold(r.Host, r.URL.Host) ||
		r.URL.User != nil || r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.URL.Fragment != "" || r.Header.Get("Capsule-Protocol") != "?1" {
		return connectUDPTarget{}, errConnectUDPMalformed
	}

	rawPath := r.URL.EscapedPath()
	if !strings.HasPrefix(rawPath, connectUDPURIPrefix) {
		return connectUDPTarget{}, errConnectUDPMalformed
	}
	parts := strings.Split(strings.TrimPrefix(rawPath, connectUDPURIPrefix), "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] != "" {
		return connectUDPTarget{}, errConnectUDPMalformed
	}
	rawHost, rawPort := parts[0], parts[1]
	lowerRawHost := strings.ToLower(rawHost)
	if strings.Contains(lowerRawHost, "%2f") || strings.Contains(lowerRawHost, "%5c") {
		return connectUDPTarget{}, errConnectUDPMalformed
	}
	host, err := url.PathUnescape(rawHost)
	if err != nil || host == "" || strings.ContainsAny(host, "/\\%@[]") {
		return connectUDPTarget{}, errConnectUDPMalformed
	}
	if strings.Contains(rawPort, "%") || !allASCIIDigits(rawPort) {
		return connectUDPTarget{}, errConnectUDPMalformed
	}
	portNumber, err := strconv.Atoi(rawPort)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return connectUDPTarget{}, errConnectUDPMalformed
	}

	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host, err = canonicalDomain(host)
		if err != nil {
			return connectUDPTarget{}, errConnectUDPMalformed
		}
	}
	port := strconv.Itoa(portNumber)
	return connectUDPTarget{
		host:     host,
		port:     port,
		hostPort: net.JoinHostPort(host, port),
	}, nil
}

func redactConnectUDPRequest(r *http.Request) {
	if r == nil || r.URL == nil {
		return
	}
	r.URL.Path = connectUDPRedactedPath
	r.URL.RawPath = ""
	r.URL.RawQuery = ""
	r.URL.ForceQuery = false
	r.URL.Fragment = ""
	r.RequestURI = connectUDPRedactedPath
}

func allASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func canonicalDomain(host string) (string, error) {
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", err
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) == 0 || len(ascii) > 253 || strings.HasSuffix(ascii, ".") {
		return "", errConnectUDPMalformed
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errConnectUDPMalformed
		}
		for i := range len(label) {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", errConnectUDPMalformed
			}
		}
	}
	return ascii, nil
}

func decodeConnectUDPDatagram(datagram []byte) ([]byte, error) {
	contextID, consumed, err := quicvarint.Parse(datagram)
	if err != nil || consumed != quicvarint.Len(contextID) || contextID != connectUDPContextID {
		return nil, errConnectUDPMalformed
	}
	return datagram[consumed:], nil
}

func encodeConnectUDPDatagram(payload []byte) []byte {
	datagram := make([]byte, 0, quicvarint.Len(connectUDPContextID)+len(payload))
	datagram = quicvarint.Append(datagram, connectUDPContextID)
	return append(datagram, payload...)
}

type resolvedTarget struct {
	host      string
	port      string
	addresses []string
}

func (h Handler) resolveTargetCheckACL(ctx context.Context, hostPort string) (resolvedTarget, *targetPolicyFailure) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return resolvedTarget{}, &targetPolicyFailure{kind: targetPolicyMalformed, cause: err}
	}
	if !h.portIsAllowed(port) {
		return resolvedTarget{}, &targetPolicyFailure{kind: targetPolicyPortDenied}
	}

	for _, rule := range h.aclRules {
		if _, ok := rule.(*aclDomainRule); !ok {
			continue
		}
		switch rule.tryMatch(nil, host) {
		case aclDecisionDeny:
			return resolvedTarget{}, &targetPolicyFailure{kind: targetPolicyDomainDenied}
		case aclDecisionAllow:
			goto resolve
		}
	}

resolve:
	lookup := h.lookupIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	ipAddresses, err := lookup(ctx, host)
	if err != nil {
		return resolvedTarget{}, &targetPolicyFailure{kind: targetPolicyLookupFailed, cause: err}
	}
	result := resolvedTarget{host: host, port: port}
	seen := make(map[string]struct{}, len(ipAddresses))
	for _, ipAddress := range ipAddresses {
		ip := ipAddress.IP
		if ip == nil || !h.hostIsAllowed(host, ip) {
			continue
		}
		address := net.JoinHostPort(ip.String(), port)
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		result.addresses = append(result.addresses, address)
	}
	if len(result.addresses) == 0 {
		return resolvedTarget{}, &targetPolicyFailure{kind: targetPolicyNoAllowedAddress}
	}
	return result, nil
}

func legacyTargetPolicyError(failure *targetPolicyFailure, host, port string) error {
	switch failure.kind {
	case targetPolicyMalformed:
		return caddyhttp.Error(http.StatusBadRequest, failure.cause)
	case targetPolicyPortDenied:
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("port %s is not allowed", port))
	case targetPolicyDomainDenied:
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("disallowed host %s", host))
	case targetPolicyLookupFailed:
		return caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("lookup of %s failed: %v", host, failure.cause))
	default:
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("no allowed IP addresses for %s", host))
	}
}
