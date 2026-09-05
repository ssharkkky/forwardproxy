package forwardproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func tcpTestHandler(addresses ...string) Handler {
	return Handler{
		HideIP:      true,
		DialTimeout: caddy.Duration(30 * time.Second),
		aclRules:    []aclRule{&aclAllRule{allow: true}},
		lookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			var result []net.IPAddr
			for _, address := range addresses {
				result = append(result, net.IPAddr{IP: net.ParseIP(address)})
			}
			return result, nil
		},
	}
}

func requireTCPStatus(t *testing.T, err error, want int) {
	t.Helper()
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != want {
		t.Fatalf("error = %v, want HTTP %d", err, want)
	}
}

func tcpConnectRequest(ctx context.Context, version int) *http.Request {
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	return (&http.Request{
		Method: http.MethodConnect, URL: &url.URL{Host: "target.example:443"},
		Host: "target.example:443", ProtoMajor: version, Proto: "HTTP/3.0",
		Header: make(http.Header), Body: io.NopCloser(http.NoBody),
	}).WithContext(ctx)
}

func TestTCPHappyEyeballsBlackhole(t *testing.T) {
	for _, addresses := range [][]string{
		{"2001:db8::1", "2001:db8::2", "192.0.2.1"},
		{"192.0.2.1", "192.0.2.2", "2001:db8::1"},
		{"192.0.2.1", "192.0.2.2"},
	} {
		t.Run(addresses[0]+"_"+addresses[len(addresses)-1], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := tcpTestHandler(addresses...)
				winner, peer := net.Pipe()
				defer peer.Close()
				defer winner.Close()
				var canceled bool
				var attempts []string
				var mu sync.Mutex
				h.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					mu.Lock()
					attempts = append(attempts, address)
					mu.Unlock()
					if address == net.JoinHostPort(addresses[len(addresses)-1], "443") {
						return winner, nil
					}
					<-ctx.Done()
					canceled = true
					return nil, ctx.Err()
				}
				start := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				conn, err := h.dialContextCheckACL(ctx, "tcp", "dual.example:443")
				if err != nil || conn != winner {
					t.Fatalf("dial = %v, %v", conn, err)
				}
				if elapsed := time.Since(start); elapsed != 250*time.Millisecond {
					t.Fatalf("fallback took %v, want 250ms", elapsed)
				}
				synctest.Wait()
				if !canceled {
					t.Fatal("losing dial was not canceled")
				}
				want := []string{net.JoinHostPort(addresses[0], "443"), net.JoinHostPort(addresses[len(addresses)-1], "443")}
				if !reflect.DeepEqual(attempts, want) {
					t.Fatalf("attempts = %v, want %v", attempts, want)
				}
			})
		})
	}
}

func TestTCPDialFailureStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
	}{
		{"refused", errors.New("refused"), http.StatusBadGateway},
		{"timeout", context.DeadlineExceeded, http.StatusGatewayTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := tcpTestHandler("192.0.2.1")
			h.dialContext = func(context.Context, string, string) (net.Conn, error) { return nil, tc.err }
			conn, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
			if conn != nil {
				t.Fatal("failed dial returned a connection")
			}
			requireTCPStatus(t, err, tc.code)
		})
	}
}

func TestTCPHappyEyeballsImmediateFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := tcpTestHandler("2001:db8::1", "192.0.2.1")
		winner, peer := net.Pipe()
		defer peer.Close()
		defer winner.Close()
		h.dialContext = func(_ context.Context, _, address string) (net.Conn, error) {
			if address == "192.0.2.1:443" {
				return winner, nil
			}
			return nil, errors.New("unreachable")
		}
		started := time.Now()
		conn, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
		if err != nil || conn != winner || time.Since(started) != 100*time.Millisecond {
			t.Fatalf("immediate failure did not retain minimum spacing: %v", err)
		}
	})
}

func TestTCPHappyEyeballsLateSuccessClosed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := tcpTestHandler("2001:db8::1", "192.0.2.1")
		winner, winnerPeer := net.Pipe()
		defer winnerPeer.Close()
		defer winner.Close()
		loser, loserPeer := net.Pipe()
		defer loserPeer.Close()
		defer loser.Close()
		h.dialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
			if address == "192.0.2.1:443" {
				return winner, nil
			}
			<-ctx.Done()
			return loser, nil
		}
		conn, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
		if err != nil || conn != winner {
			t.Fatal(err)
		}
		synctest.Wait()
		if _, err := loserPeer.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("late successful loser was not closed: %v", err)
		}
	})
}

func TestTCPHappyEyeballsAttemptDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := tcpTestHandler("192.0.2.1")
		h.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		started := time.Now()
		_, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
		requireTCPStatus(t, err, http.StatusGatewayTimeout)
		if time.Since(started) != 5*time.Second {
			t.Fatalf("per-address timeout = %v", time.Since(started))
		}
	})
}

func TestTCPHappyEyeballsACLAndNetwork(t *testing.T) {
	for _, network := range []string{"tcp", "tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			h := tcpTestHandler("2001:db8::1", "192.0.2.1", "192.0.2.2")
			disallowed, err := newACLRule("192.0.2.1", false)
			if err != nil {
				t.Fatal(err)
			}
			h.aclRules = append([]aclRule{disallowed}, h.aclRules...)
			var attempts []string
			h.dialContext = func(_ context.Context, _, address string) (net.Conn, error) {
				attempts = append(attempts, address)
				return nil, errors.New("refused")
			}
			_, err = h.dialContextCheckACL(context.Background(), network, "target.example:443")
			requireTCPStatus(t, err, http.StatusBadGateway)
			want := map[string][]string{
				"tcp":  {"[2001:db8::1]:443", "192.0.2.2:443"},
				"tcp4": {"192.0.2.2:443"}, "tcp6": {"[2001:db8::1]:443"},
			}[network]
			if !reflect.DeepEqual(attempts, want) {
				t.Fatalf("attempts = %v, want %v", attempts, want)
			}
		})
	}
}

func TestTCPDialDeadlineIncludesDNS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := tcpTestHandler()
		h.DialTimeout = caddy.Duration(time.Second)
		h.lookupIP = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(10 * time.Second):
				return nil, errors.New("DNS was not canceled")
			}
		}
		start := time.Now()
		_, err := h.dialContextCheckACL(context.Background(), "tcp", "target.example:443")
		requireTCPStatus(t, err, http.StatusGatewayTimeout)
		if elapsed := time.Since(start); elapsed != time.Second {
			t.Fatalf("DNS exceeded total deadline: %v", elapsed)
		}
	})
}

func TestTCPUpstreamContextSurvivesConnect(t *testing.T) {
	h := tcpTestHandler()
	h.upstream = &url.URL{Scheme: "https", Host: "proxy.example"}
	target, peer := net.Pipe()
	defer peer.Close()
	defer target.Close()
	var tunnelCtx context.Context
	h.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		tunnelCtx = ctx
		return target, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := h.dialContextCheckACL(ctx, "tcp", "target.example:443")
	if err != nil || conn != target || tunnelCtx.Err() != nil {
		t.Fatalf("upstream context canceled on successful connect: %v", err)
	}
	cancel()
	if !errors.Is(tunnelCtx.Err(), context.Canceled) {
		t.Fatal("upstream did not retain request cancellation")
	}
}

func TestCONNECTDoesNotAcknowledgeFailedDial(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(httpVersionName(version), func(t *testing.T) {
			h := tcpTestHandler("192.0.2.1")
			w := httptest.NewRecorder()
			h.dialContext = func(context.Context, string, string) (net.Conn, error) {
				if w.Flushed {
					t.Error("CONNECT sent success before target dial completed")
				}
				return nil, errors.New("refused")
			}
			r := tcpConnectRequest(context.Background(), version)
			err := h.ServeHTTP(w, r, nil)
			requireTCPStatus(t, err, http.StatusBadGateway)
			if w.Flushed {
				t.Fatal("failed CONNECT already committed response headers")
			}
		})
	}
}

func httpVersionName(version int) string {
	return map[int]string{1: "h1", 2: "h2", 3: "h3"}[version]
}

func TestCONNECTRequestCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := tcpTestHandler("192.0.2.1")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h.dialContext = func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			cancel()
			select {
			case <-dialCtx.Done():
				return nil, dialCtx.Err()
			case <-time.After(time.Second):
				t.Error("request cancellation did not reach dial")
				return nil, errors.New("not canceled")
			}
		}
		r := tcpConnectRequest(ctx, 3)
		w := httptest.NewRecorder()
		if err := h.ServeHTTP(w, r, nil); err == nil || w.Flushed {
			t.Fatalf("canceled CONNECT: err=%v flushed=%v", err, w.Flushed)
		}
	})
}

func TestCONNECTSuccessFlushesBeforeTargetData(t *testing.T) {
	for _, version := range []int{2, 3} {
		t.Run(httpVersionName(version), func(t *testing.T) {
			h := tcpTestHandler("192.0.2.1")
			w := httptest.NewRecorder()
			target, peer := net.Pipe()
			defer peer.Close()
			h.dialContext = func(context.Context, string, string) (net.Conn, error) {
				if w.Flushed {
					t.Error("success committed before dial")
				}
				return target, nil
			}
			// The peer sends no bytes: the handler must still flush the 200.
			peer.Close()
			r := tcpConnectRequest(context.Background(), version)
			r.Header.Set(naivePaddingTypeRequestHeader, "1, 0")
			if err := h.ServeHTTP(w, r, nil); err != nil {
				t.Fatal(err)
			}
			if !w.Flushed || w.Code != http.StatusOK || w.Header().Get(naivePaddingTypeReplyHeader) != "1" {
				t.Fatalf("success response: status=%d flushed=%v padding=%q", w.Code, w.Flushed, w.Header().Get(naivePaddingTypeReplyHeader))
			}
		})
	}
}
