// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"errors"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

var errHTTP3StreamUnavailable = errors.New("HTTP/3 stream unavailable")

type responseWriterUnwrapper interface {
	Unwrap() http.ResponseWriter
}

// http3StreamFromResponseWriter follows only the standard Caddy/Go Unwrap
// contract. It deliberately avoids reflection and unsafe access. Calling
// HTTPStream takes ownership of the stream and flushes the response headers.
func http3StreamFromResponseWriter(w http.ResponseWriter) (*http3.Stream, error) {
	for depth := 0; depth < 16 && w != nil; depth++ {
		if streamer, ok := w.(http3.HTTPStreamer); ok {
			return streamer.HTTPStream(), nil
		}
		unwrapper, ok := w.(responseWriterUnwrapper)
		if !ok {
			break
		}
		next := unwrapper.Unwrap()
		if next == nil || next == w {
			break
		}
		w = next
	}
	return nil, errHTTP3StreamUnavailable
}
