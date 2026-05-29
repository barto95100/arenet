// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
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
//   github.com/corazawaf/coraza-caddy/v2@v2.5.0/interceptor.go
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
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3/types"
)

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
}

// WriteHeader records the status code to be sent right before
// the body is written.
func (i *rwInterceptor) WriteHeader(statusCode int) {
	if i.wroteHeader {
		log.Println("http: superfluous response.WriteHeader call")
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
		i.statusCode = obtainStatusCodeFromInterruptionOrDefault(it, i.statusCode)
		i.flushWriteHeader()
		return
	}
	i.wroteHeader = true
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
	if i.tx.IsResponseBodyAccessible() && i.tx.IsResponseBodyProcessable() && !i.wroteBufferedBodyToDownstream {
		return
	}
	i.flushWriteHeader()
	if f, ok := i.w.(http.Flusher); ok {
		f.Flush()
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
		i.flushWriteHeader()
		return nil
	}

	var (
		hijacker, isHijacker = i.w.(http.Hijacker)
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
		}{i, hijacker}, responseProcessor
	case isHijacker && isPusher:
		return struct {
			responseWriter
			http.Hijacker
			http.Pusher
		}{i, hijacker, pusher}, responseProcessor
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
