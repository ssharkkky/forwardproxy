package forwardproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestNegotiateNaivePadding(t *testing.T) {
	tests := []struct {
		name    string
		header  http.Header
		want    int
		wantErr bool
	}{
		{name: "legacy none", header: http.Header{}, want: naivePaddingNone},
		{name: "legacy variant1", header: http.Header{"Padding": {"cover"}}, want: naivePaddingVariant1},
		{name: "prefer variant1", header: http.Header{"Padding-Type-Request": {"1, 0"}}, want: naivePaddingVariant1},
		{name: "request none", header: http.Header{"Padding-Type-Request": {"0"}}, want: naivePaddingNone},
		{name: "respect client order", header: http.Header{"Padding-Type-Request": {"0, 1"}}, want: naivePaddingNone},
		{name: "invalid type", header: http.Header{"Padding-Type-Request": {"2, 1"}}, wantErr: true},
		{name: "empty type", header: http.Header{"Padding-Type-Request": {""}}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := negotiateNaivePadding(test.header)
			if test.wantErr {
				if err == nil {
					t.Fatalf("negotiateNaivePadding() = %d, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("negotiateNaivePadding() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("negotiateNaivePadding() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestSetNaivePaddingResponseHeaders(t *testing.T) {
	request := http.Header{"Padding-Type-Request": {"1, 0"}}
	response := make(http.Header)
	setNaivePaddingResponseHeaders(response, request, naivePaddingVariant1)

	if got := response.Get("Padding-Type-Reply"); got != "1" {
		t.Fatalf("Padding-Type-Reply = %q, want 1", got)
	}
	if got := len(response.Get("Padding")); got < 30 || got >= 62 {
		t.Fatalf("Padding length = %d, want [30, 62)", got)
	}
}

func TestH3ConnectPaddingNegotiationAndRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetResult := make(chan error, 1)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			targetResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		request := make([]byte, 1)
		if _, err := io.ReadFull(conn, request); err != nil {
			targetResult <- err
			return
		}
		if request[0] != 'x' {
			targetResult <- fmt.Errorf("target received %q, want x", request)
			return
		}
		_, err = conn.Write([]byte{'y'})
		targetResult <- err
	}()

	proxyHost, _, err := net.SplitHostPort(caddyForwardProxyAuth.addr)
	if err != nil {
		t.Fatal(err)
	}
	loopback, err := testLoopbackAddress(caddyForwardProxyAuth.addr)
	if err != nil {
		t.Fatal(err)
	}
	qconn, err := quic.DialAddr(ctx, loopback, &tls.Config{
		InsecureSkipVerify: true, // controlled local test fixture
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         proxyHost,
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer qconn.CloseWithError(0, "test complete")

	transport := &http3.Transport{EnableDatagrams: true}
	client := transport.NewClientConn(qconn)
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.CancelRead(0)
	defer stream.CancelWrite(0)

	req, err := http.NewRequest(http.MethodConnect, "https://"+target.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", credentialsCorrect)
	req.Header.Set("Padding", "cover")
	req.Header.Set(naivePaddingTypeRequestHeader, "1, 0")
	if err := stream.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	// Emulate Naive's H3 fast-open path: write a Variant1 frame before the
	// CONNECT response headers arrive.
	if _, err := stream.Write([]byte{0, 1, 0, 'x'}); err != nil {
		t.Fatal(err)
	}

	response, err := stream.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", response.StatusCode)
	}
	if got := response.Header.Get(naivePaddingTypeReplyHeader); got != "1" {
		t.Fatalf("Padding-Type-Reply = %q, want 1", got)
	}
	if got := response.Header.Get("Padding"); got == "" {
		t.Fatal("CONNECT response lacks legacy Padding header")
	}

	header := make([]byte, 3)
	if _, err := io.ReadFull(stream, header); err != nil {
		t.Fatal(err)
	}
	payloadSize := int(header[0])<<8 | int(header[1])
	paddingSize := int(header[2])
	framed := make([]byte, payloadSize+paddingSize)
	if _, err := io.ReadFull(stream, framed); err != nil {
		t.Fatal(err)
	}
	if payloadSize != 1 || framed[0] != 'y' {
		t.Fatalf("padded response payload = %x, want y", framed[:payloadSize])
	}
	if err := <-targetResult; err != nil {
		t.Fatal(err)
	}
}
