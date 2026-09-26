// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

// This file is heavily adapted from
//   github.com/corazawaf/coraza-caddy/v2@v2.6.1/interceptor.go
// (v2.26: v2.5.0 → v2.6.1 diff replayed — flush and hijack through
// the Unwrap chain, 101 header flush, Content-Length: 0 on block;
// pinned by interceptor_test.go)
// (Apache-2.0). Per AGPL-3.0 §13 the Apache-2.0 work it derives
// from is compatible (downstream-only direction), and the
// modifications are tracked in this header. The original
// upstream is itself a copy of coraza/v3's
// http/interceptor.go.
//
// Why we copy instead of import: coraza-caddy/v2 keeps these
// helpers package-private. The response-body inspection logic
// is security-critical (a bug silently weakens the WAF) and
// rewriting it from scratch would be reckless; copying the
// upstream verbatim keeps us at parity. When upstream bumps
// these helpers we should diff + replay.

package waf

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3/types"
)

// hijackerTracker wraps an http.Hijacker and marks the interceptor
// as hijacked once Hijack succeeds, so response processing is
// skipped on a connection that no longer speaks HTTP (WebSocket).
type hijackerTracker struct {
	hijacker    http.Hijacker
	interceptor *rwInterceptor
}

// Hijack delegates to the underlying hijacker.
func (h *hijackerTracker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := h.hijacker.Hijack()
	if err != nil {
		return conn, rw, err
	}
	h.interceptor.isHijacked = true
	return conn, rw, nil
}

// hijackerOf returns the http.Hijacker reachable from w, unwrapping
// writers that only expose it further down the chain, as Caddy's
// ResponseWriterWrapper does.
func hijackerOf(w http.ResponseWriter) (http.Hijacker, bool) {
	for {
		if h, ok := w.(http.Hijacker); ok {
			return h, true
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return nil, false
		}
		w = u.Unwrap()
	}
}

// rwInterceptor intercepts the ResponseWriter so the WAF can
// inspect response bytes (phase 4/5 rules). Buffers the body
// when accessible; passes through otherwise. Records the
// status code so a phase 3+ interruption can override it.
type rwInterceptor struct {
	w                             http.ResponseWriter
	tx                            types.Transaction
	statusCode                    int
	proto                         string
	isWriteHeaderFlush            bool
	wroteHeader                   bool
	wroteBufferedBodyToDownstream bool
	isHijacked                    bool
	allowFlushing                 bool
}

// WriteHeader records the status code to be sent right before
// the body is written.
func (i *rwInterceptor) WriteHeader(statusCode int) {
	if i.wroteHeader {
		return
	}
	for k, vv := range i.w.Header() {
		for _, v := range vv {
			i.tx.AddResponseHeader(k, v)
		}
	}
	i.statusCode = statusCode
	if it := i.tx.ProcessResponseHeaders(statusCode, i.proto); it != nil {
		i.cleanHeaders()
		i.Header().Set("Content-Length", "0")
		i.statusCode = obtainStatusCodeFromInterruptionOrDefault(it, i.statusCode)
		i.flushWriteHeader()
		return
	}
	// A 101 Switching Protocols is followed by a hijack for a
	// bidirectional stream: flush the headers now, there is no HTTP
	// body to process.
	if statusCode == http.StatusSwitchingProtocols {
		i.flushWriteHeader()
	}
	i.wroteHeader = true
	if !i.tx.IsResponseBodyAccessible() || !i.tx.IsResponseBodyProcessable() {
		// Nothing will be buffered for inspection: flushing is safe
		// from the first Flush() on.
		i.allowFlushing = true
	}
}

func (i *rwInterceptor) overrideWriteHeader(statusCode int) {
	i.statusCode = statusCode
}

func (i *rwInterceptor) flushWriteHeader() {
	if !i.isWriteHeaderFlush {
		i.w.WriteHeader(i.statusCode)
		i.isWriteHeaderFlush = true
	}
}

func (i *rwInterceptor) cleanHeaders() {
	for k := range i.w.Header() {
		i.w.Header().Del(k)
	}
}

func (i *rwInterceptor) Write(b []byte) (int, error) {
	if i.tx.IsInterrupted() {
		return len(b), nil
	}
	if !i.wroteHeader {
		i.WriteHeader(http.StatusOK)
	}
	if i.tx.IsResponseBodyAccessible() && i.tx.IsResponseBodyProcessable() && !i.wroteBufferedBodyToDownstream {
		it, n, err := i.tx.WriteResponseBody(b)
		if it != nil {
			i.cleanHeaders()
			i.Header().Set("Content-Length", "0")
			i.overrideWriteHeader(obtainStatusCodeFromInterruptionOrDefault(it, i.statusCode))
			i.flushWriteHeader()
			return len(b), nil
		}
		if err != nil || n == len(b) {
			return n, err
		}
		if err := i.writeBufferedResponseBodyToDownstream(); err != nil {
			return n, err
		}
		n2, err := i.w.Write(b[n:])
		return n + n2, err
	}
	i.flushWriteHeader()
	return i.w.Write(b)
}

func (i *rwInterceptor) Header() http.Header {
	return i.w.Header()
}

func (i *rwInterceptor) ReadFrom(r io.Reader) (n int64, err error) {
	return io.Copy(struct{ io.Writer }{i}, r)
}

func (i *rwInterceptor) Flush() {
	if !i.wroteHeader {
		i.WriteHeader(http.StatusOK)
	}
	// While the body is buffered for inspection nothing may reach the
	// client: a phase-4 rule can still replace status and body.
	if i.allowFlushing && i.isWriteHeaderFlush {
		// ResponseController, not an http.Flusher assertion: Caddy's
		// ResponseWriterWrapper only exposes the flusher further down
		// the Unwrap chain.
		_ = http.NewResponseController(i.w).Flush() //nolint:bodyclose
	}
}

func (i *rwInterceptor) writeBufferedResponseBodyToDownstream() error {
	if i.wroteBufferedBodyToDownstream {
		return nil
	}
	reader, err := i.tx.ResponseBodyReader()
	if err != nil {
		i.overrideWriteHeader(http.StatusInternalServerError)
		i.flushWriteHeader()
		return caddyhttp.HandlerError{
			ID:         i.tx.ID(),
			StatusCode: http.StatusInternalServerError,
			Err:        fmt.Errorf("failed to release the response body reader: %v", err),
		}
	}
	i.flushWriteHeader()
	if _, err := io.Copy(i.w, reader); err != nil {
		return caddyhttp.HandlerError{
			ID:         i.tx.ID(),
			StatusCode: http.StatusInternalServerError,
			Err:        fmt.Errorf("failed to copy the response body: %v", err),
		}
	}
	i.wroteBufferedBodyToDownstream = true
	return nil
}

type responseWriter interface {
	http.ResponseWriter
	io.ReaderFrom
	http.Flusher
}

var _ responseWriter = (*rwInterceptor)(nil)

// wrap returns the response writer + the response processor
// the module calls after next.ServeHTTP returns (or before,
// on interruption).
func wrap(w http.ResponseWriter, r *http.Request, tx types.Transaction) (
	http.ResponseWriter,
	func(types.Transaction, *http.Request) error,
) {
	i := &rwInterceptor{w: w, tx: tx, proto: r.Proto, statusCode: 200}

	responseProcessor := func(tx types.Transaction, r *http.Request) error {
		// A hijacked connection (WebSocket) must not be written to.
		if i.isHijacked {
			return nil
		}
		if tx.IsInterrupted() {
			return nil
		}
		if tx.IsResponseBodyAccessible() && tx.IsResponseBodyProcessable() && !i.wroteBufferedBodyToDownstream {
			if it, err := tx.ProcessResponseBody(); err != nil {
				i.overrideWriteHeader(http.StatusInternalServerError)
				i.flushWriteHeader()
				return caddyhttp.HandlerError{
					ID:         tx.ID(),
					StatusCode: http.StatusInternalServerError,
					Err:        err,
				}
			} else if it != nil {
				i.cleanHeaders()
				i.Header().Set("Content-Length", "0")
				code := obtainStatusCodeFromInterruptionOrDefault(it, i.statusCode)
				i.overrideWriteHeader(code)
				i.flushWriteHeader()
				return caddyhttp.HandlerError{
					ID:         tx.ID(),
					StatusCode: code,
					Err:        errInterruptionTriggered,
				}
			}
			return i.writeBufferedResponseBodyToDownstream()
		}
		i.allowFlushing = true
		i.flushWriteHeader()
		return nil
	}

	var (
		hijacker, isHijacker = hijackerOf(i.w)
		pusher, isPusher     = i.w.(http.Pusher)
	)
	switch {
	case !isHijacker && isPusher:
		return struct {
			responseWriter
			http.Pusher
		}{i, pusher}, responseProcessor
	case isHijacker && !isPusher:
		return struct {
			responseWriter
			http.Hijacker
		}{i, &hijackerTracker{hijacker: hijacker, interceptor: i}}, responseProcessor
	case isHijacker && isPusher:
		return struct {
			responseWriter
			http.Hijacker
			http.Pusher
		}{i, &hijackerTracker{hijacker: hijacker, interceptor: i}, pusher}, responseProcessor
	default:
		return struct {
			responseWriter
		}{i}, responseProcessor
	}
}

// obtainStatusCodeFromInterruptionOrDefault returns the status
// code Coraza wants for the interruption, falling back to the
// supplied default. Block-action interruptions land at 403
// unless overridden in the rule.
func obtainStatusCodeFromInterruptionOrDefault(it *types.Interruption, defaultStatusCode int) int {
	if it.Action == "deny" {
		statusCode := it.Status
		if statusCode == 0 {
			statusCode = 403
		}
		return statusCode
	}
	return defaultStatusCode
}
