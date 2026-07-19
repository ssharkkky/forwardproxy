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

func http3CapabilitiesFromResponseWriter(
	w http.ResponseWriter,
) (http3.HTTPStreamer, http3.Settingser, error) {
	var streamer http3.HTTPStreamer
	var settings http3.Settingser
	for depth := 0; depth < 16 && w != nil; depth++ {
		if candidate, ok := w.(http3.HTTPStreamer); ok {
			streamer = candidate
		}
		if candidate, ok := w.(http3.Settingser); ok {
			settings = candidate
		}
		if streamer != nil && settings != nil {
			return streamer, settings, nil
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
	return nil, nil, errHTTP3StreamUnavailable
}

// http3StreamFromResponseWriter follows only the standard Caddy/Go Unwrap
// contract. It deliberately avoids reflection and unsafe access. Calling
// HTTPStream takes ownership of the stream and flushes the response headers.
func http3StreamFromResponseWriter(w http.ResponseWriter) (*http3.Stream, error) {
	streamer, _, err := http3CapabilitiesFromResponseWriter(w)
	if err != nil {
		return nil, err
	}
	return streamer.HTTPStream(), nil
}
