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

package waf

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Tests for the v2.26 replay of coraza-caddy v2.5.0 → v2.6.1 into
// interceptor.go. The cases that matter for Arenet: Caddy wraps the
// ResponseWriter in caddyhttp.ResponseWriterWrapper, which exposes
// NEITHER Flush NOR Hijack — only Unwrap (caddy v2.11.4
// modules/caddyhttp/responsewriter.go:38-57). A plain type assertion
// on the wrapper therefore loses the flush (SSE / streaming stalls in
// the server buffer) and the hijacker.
//
// Scope note (2026-09-21 smoke): in Arenet's CURRENT handler chain the
// writer reaching the WAF still implements http.Flusher, so an SSE
// upstream behind a block-mode WAF streamed tick-by-tick on v2.25.1
// too. These tests pin the upstream-parity behaviour for when a Caddy
// wrapper does sit in front of the WAF.

func newInterceptorTx(t *testing.T, directives string) types.Transaction {
	t.Helper()
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatal(err)
	}
	tx := w.NewTransaction()
	t.Cleanup(func() { _ = tx.Close() })
	return tx
}

// hijackRecorder is an httptest.ResponseRecorder that can be hijacked.
type hijackRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
	fail     bool
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h.fail {
		return nil, nil, errors.New("hijack refused")
	}
	h.hijacked = true
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

// caddyWrapped mimics what the WAF handler receives inside Caddy.
func caddyWrapped(w http.ResponseWriter) http.ResponseWriter {
	return &caddyhttp.ResponseWriterWrapper{ResponseWriter: w}
}

func TestInterceptor_FlushReachesWriterThroughCaddyWrapper(t *testing.T) {
	// No response body access: the pass-through (streaming) path.
	tx := newInterceptorTx(t, "SecRuleEngine On\nSecResponseBodyAccess Off")
	rec := httptest.NewRecorder()
	ww, _ := wrap(caddyWrapped(rec), httptest.NewRequest(http.MethodGet, "/events", nil), tx)

	ww.Header().Set("Content-Type", "text/event-stream")
	ww.WriteHeader(http.StatusOK)
	_, _ = ww.Write([]byte("data: ping\n\n"))
	http.NewResponseController(ww).Flush() //nolint:bodyclose

	if !rec.Flushed {
		t.Fatal("Flush did not reach the underlying writer through the Caddy wrapper (SSE would stall)")
	}
}

func TestInterceptor_FlushHeldWhileBufferingInspectedBody(t *testing.T) {
	// Response body inspected: status + body must stay buffered so a
	// phase-4 rule can still replace them.
	tx := newInterceptorTx(t, "SecRuleEngine On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/html")
	tx.ProcessConnection("127.0.0.1", 1234, "127.0.0.1", 80)
	tx.ProcessURI("/", http.MethodGet, "HTTP/1.1")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	ww, _ := wrap(caddyWrapped(rec), httptest.NewRequest(http.MethodGet, "/", nil), tx)

	ww.Header().Set("Content-Type", "text/html")
	ww.WriteHeader(http.StatusOK)
	_, _ = ww.Write([]byte("<html>"))
	http.NewResponseController(ww).Flush() //nolint:bodyclose

	if rec.Flushed || rec.Body.Len() != 0 {
		t.Fatalf("buffered body leaked downstream before inspection (flushed=%v body=%q)", rec.Flushed, rec.Body.String())
	}
}

func TestInterceptor_HijackerFoundThroughUnwrapAndTracked(t *testing.T) {
	tx := newInterceptorTx(t, "SecRuleEngine On")
	hr := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	ww, process := wrap(caddyWrapped(hr), httptest.NewRequest(http.MethodGet, "/ws", nil), tx)

	hj, ok := ww.(http.Hijacker)
	if !ok {
		t.Fatal("wrapped writer lost http.Hijacker behind the Caddy wrapper (WebSocket upgrade would fail)")
	}
	ww.WriteHeader(http.StatusSwitchingProtocols)
	if hr.Code != http.StatusSwitchingProtocols {
		t.Errorf("101 not flushed before the hijack: code=%d", hr.Code)
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !hr.hijacked {
		t.Fatal("Hijack not delegated")
	}
	if err := process(tx, httptest.NewRequest(http.MethodGet, "/ws", nil)); err != nil {
		t.Errorf("response processor must be a no-op on a hijacked connection: %v", err)
	}
}

func TestInterceptor_FailedHijackKeepsResponseProcessing(t *testing.T) {
	tx := newInterceptorTx(t, "SecRuleEngine On")
	hr := &hijackRecorder{ResponseRecorder: httptest.NewRecorder(), fail: true}
	ww, _ := wrap(caddyWrapped(hr), httptest.NewRequest(http.MethodGet, "/", nil), tx)
	hj, ok := ww.(http.Hijacker)
	if !ok {
		t.Fatal("Hijacker not exposed")
	}
	if _, _, err := hj.Hijack(); err == nil {
		t.Fatal("expected the hijack failure to propagate")
	}
	ww.WriteHeader(http.StatusOK)
	_, _ = ww.Write([]byte("body"))
	if hr.Body.String() != "body" {
		t.Errorf("response not written after a failed hijack: %q", hr.Body.String())
	}
}

func TestInterceptor_InterruptionResponseHasZeroContentLength(t *testing.T) {
	// Phase-3 deny on the response status.
	tx := newInterceptorTx(t, `SecRuleEngine On
SecRule RESPONSE_STATUS "@streq 200" "id:9001,phase:3,deny,status:403"`)
	tx.ProcessConnection("127.0.0.1", 1234, "127.0.0.1", 80)
	tx.ProcessURI("/", http.MethodGet, "HTTP/1.1")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	ww, _ := wrap(rec, httptest.NewRequest(http.MethodGet, "/", nil), tx)
	ww.Header().Set("Content-Length", "1234")
	ww.Header().Set("X-Upstream", "leak")
	ww.WriteHeader(http.StatusOK)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get("Content-Length"); got != "0" {
		t.Errorf("Content-Length = %q, want \"0\" (the upstream length must not survive the block)", got)
	}
	if rec.Header().Get("X-Upstream") != "" {
		t.Error("upstream headers must be cleaned on interruption")
	}
}

func TestInterceptor_PassThroughBodyStillWritten(t *testing.T) {
	tx := newInterceptorTx(t, "SecRuleEngine On\nSecResponseBodyAccess Off")
	rec := httptest.NewRecorder()
	ww, process := wrap(caddyWrapped(rec), httptest.NewRequest(http.MethodGet, "/", nil), tx)
	_, _ = ww.Write([]byte(strings.Repeat("x", 10)))
	if err := process(tx, httptest.NewRequest(http.MethodGet, "/", nil)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || rec.Body.Len() != 10 {
		t.Errorf("code=%d body=%d", rec.Code, rec.Body.Len())
	}
}
