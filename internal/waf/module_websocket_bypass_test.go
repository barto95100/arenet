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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// W.bugfix-followup — Coraza doesn't support WebSocket
// upgrades (the Coraza response writer doesn't implement
// http.Hijacker; HTTP 101 Switching Protocols can't proceed
// through the WAF). The fix is an unconditional bypass:
// WebSocket upgrades pass through to the upstream without
// Coraza inspection regardless of mode. These tests pin
// the bypass contract end-to-end.
//
// Coraza maintainer position:
// https://github.com/corazawaf/coraza/discussions/1399

// makeUpgradeRequest builds an httptest.NewRequest with
// the WebSocket-upgrade headers RFC 6455 §4.1 requires.
// Optional extras flag the case-sensitivity invariant
// each test cares about.
func makeUpgradeRequest(t *testing.T, upgradeHdr, connectionHdr string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/ws", nil)
	if upgradeHdr != "" {
		req.Header.Set("Upgrade", upgradeHdr)
	}
	if connectionHdr != "" {
		req.Header.Set("Connection", connectionHdr)
	}
	return req
}

// --- isWebSocketUpgrade helper -----------------------------

func TestIsWebSocketUpgrade_Cases(t *testing.T) {
	cases := []struct {
		name       string
		upgrade    string
		connection string
		want       bool
	}{
		{"canonical handshake", "websocket", "Upgrade", true},
		{"lowercase upgrade header", "websocket", "upgrade", true},
		{"uppercase upgrade header value", "WEBSOCKET", "Upgrade", true},
		{"mixed-case upgrade header value", "WebSocket", "Upgrade", true},
		// Some clients (older Firefox, some libraries)
		// send Connection: "keep-alive, Upgrade" per
		// RFC 7230 §6.1 — the WS upgrade must still be
		// honored.
		{"multi-token Connection: keep-alive, Upgrade", "websocket", "keep-alive, Upgrade", true},
		{"multi-token Connection: Upgrade, keep-alive", "websocket", "Upgrade, keep-alive", true},
		// Negative cases — must NOT bypass.
		{"missing upgrade header", "", "Upgrade", false},
		{"missing connection header", "websocket", "", false},
		{"both missing", "", "", false},
		{"upgrade value is not websocket", "h2c", "Upgrade", false},
		{"connection does not contain upgrade", "websocket", "keep-alive", false},
		{"connection: close", "websocket", "close", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := makeUpgradeRequest(t, tc.upgrade, tc.connection)
			if got := isWebSocketUpgrade(req); got != tc.want {
				t.Errorf("isWebSocketUpgrade(upgrade=%q, connection=%q) = %v; want %v",
					tc.upgrade, tc.connection, got, tc.want)
			}
		})
	}
}

// --- ServeHTTP bypass contract -----------------------------

// TestServeHTTP_WebSocketUpgrade_BypassesWAF — a WebSocket
// handshake request reaches the next handler without
// going through Coraza, regardless of the request payload
// (a "?badparam=evil-payload" query that would normally
// trip the test rule). Pin against a future regression
// that moves the bypass below tx.New, accidentally
// allocating Coraza state.
func TestServeHTTP_WebSocketUpgrade_BypassesWAF(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "block")
	req := makeUpgradeRequest(t, "websocket", "Upgrade")
	// Add the payload that WOULD trip the test rule on
	// a normal request — proves the WAF didn't get a
	// chance to inspect it.
	req.URL.RawQuery = "badparam=evil-payload"

	next := &passthroughHandler{}
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Error("next handler NOT called for WebSocket upgrade; bypass regressed")
	}
	if cap.eventCount() != 0 {
		t.Errorf("captureSink received %d events for WebSocket upgrade; want 0", cap.eventCount())
	}
}

// TestServeHTTP_WebSocketUpgrade_DetectMode_NoEvent —
// in detect mode the WAF normally emits a DETECT event +
// passes the request through. For a WebSocket upgrade,
// it must emit ZERO events (bypass is total, not just
// "skip the block").
func TestServeHTTP_WebSocketUpgrade_DetectMode_NoEvent(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "detect")
	req := makeUpgradeRequest(t, "websocket", "Upgrade")
	req.URL.RawQuery = "badparam=evil-payload"

	next := &passthroughHandler{}
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Error("next handler NOT called for detect-mode WebSocket upgrade")
	}
	if cap.eventCount() != 0 {
		t.Errorf("detect-mode WS upgrade emitted %d events; want 0 (bypass is total)", cap.eventCount())
	}
}

// TestServeHTTP_WebSocketUpgrade_BlockMode_NoBlock —
// in block mode the WAF normally returns 403 on a
// disruptive rule match. For a WebSocket upgrade, it
// must NOT block — the upstream gets the upgrade
// handshake even though the URL query would normally
// trigger a 403. Same defense as the detect-mode test
// above, but pins the block-mode path explicitly so a
// future "bypass only in detect mode" regression
// surfaces.
func TestServeHTTP_WebSocketUpgrade_BlockMode_NoBlock(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "block")
	req := makeUpgradeRequest(t, "websocket", "Upgrade")
	req.URL.RawQuery = "badparam=evil-payload"

	next := &passthroughHandler{}
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("block-mode WS upgrade ServeHTTP returned err: %v", err)
	}
	if !next.called {
		t.Error("next handler NOT called for block-mode WebSocket upgrade")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("block-mode WS upgrade response status = %d; want 200 (upstream's reply, not the WAF's 403)", rec.Code)
	}
}

// TestServeHTTP_NonUpgradeRequest_StillEvaluated —
// regression guard: a plain HTTP request (no Upgrade
// headers) still goes through the full Coraza pipeline.
// The bypass is narrow — only WS-upgrade handshakes get
// the pass. Pin against a future refactor that
// accidentally widens the bypass.
func TestServeHTTP_NonUpgradeRequest_StillEvaluated(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "detect")
	// Plain GET with a rule-tripping payload — no
	// Upgrade/Connection headers.
	req := httptest.NewRequest(http.MethodGet, "http://localhost/?badparam=evil-payload", nil)

	next := &passthroughHandler{}
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Error("next NOT called in detect mode; pass-through regressed")
	}
	if cap.eventCount() != 1 {
		t.Errorf("non-upgrade detect-mode request emitted %d events; want 1 (WAF still active)",
			cap.eventCount())
	}
}
