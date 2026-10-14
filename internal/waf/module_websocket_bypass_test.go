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

// makeUpgradeRequest builds a COMPLETE RFC 6455 §4.1 opening
// handshake, varying only the two headers whose parsing the
// case-sensitivity cases care about.
//
// Key and Version are set here because they are mandatory and
// the predicate now requires them (v2.73). A test that wants
// an incomplete handshake builds it explicitly, so "what is
// missing" is visible at the call site rather than hidden in
// this helper.
func makeUpgradeRequest(t *testing.T, upgradeHdr, connectionHdr string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/ws", nil)
	if upgradeHdr != "" {
		req.Header.Set("Upgrade", upgradeHdr)
	}
	if connectionHdr != "" {
		req.Header.Set("Connection", connectionHdr)
	}
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	return req
}

// recordingHandler captures the ResponseWriter it was handed,
// which is the invariant a handshake depends on: wrap()'s
// writer has no http.Hijacker, so the upstream's 101 can only
// work if next receives the ORIGINAL writer.
type recordingHandler struct {
	called bool
	got    http.ResponseWriter
}

func (p *recordingHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	p.called = true
	p.got = w
	w.WriteHeader(http.StatusOK)
	return nil
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
		// Negative cases — must NOT be treated as a handshake.
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

// The invariants added in v2.73. Each one on its own, because
// each closes a distinct shape of forged handshake: before
// this, two headers on a request of ANY method with ANY body
// skipped Coraza entirely.
func TestIsWebSocketUpgrade_RequiresTheMandatoryHandshakeFields(t *testing.T) {
	t.Run("POST is not a handshake", func(t *testing.T) {
		req := makeUpgradeRequest(t, "websocket", "Upgrade")
		req.Method = http.MethodPost
		if isWebSocketUpgrade(req) {
			t.Error("a POST carrying upgrade headers must not be treated as a handshake — " +
				"that shape is how a request body skipped inspection entirely")
		}
	})
	t.Run("missing Sec-WebSocket-Key", func(t *testing.T) {
		req := makeUpgradeRequest(t, "websocket", "Upgrade")
		req.Header.Del("Sec-WebSocket-Key")
		if isWebSocketUpgrade(req) {
			t.Error("RFC 6455 §4.1 item 7 makes the key mandatory; without it this is not a handshake")
		}
	})
	t.Run("missing Sec-WebSocket-Version", func(t *testing.T) {
		req := makeUpgradeRequest(t, "websocket", "Upgrade")
		req.Header.Del("Sec-WebSocket-Version")
		if isWebSocketUpgrade(req) {
			t.Error("RFC 6455 §4.1 item 9 makes the version mandatory; without it this is not a handshake")
		}
	})
	t.Run("HTTP/1.0 is not a handshake", func(t *testing.T) {
		req := makeUpgradeRequest(t, "websocket", "Upgrade")
		req.ProtoMajor, req.ProtoMinor = 1, 0
		if isWebSocketUpgrade(req) {
			t.Error("RFC 6455 §4.1 item 3 requires HTTP/1.1 or later")
		}
	})
	// And the direction that must NOT get stricter: a complete,
	// conforming handshake has to keep being recognised. A false
	// negative here wraps the response writer and breaks the 101,
	// which is a broken WebSocket app rather than a security hole.
	t.Run("a conforming handshake is still recognised", func(t *testing.T) {
		if !isWebSocketUpgrade(makeUpgradeRequest(t, "websocket", "Upgrade")) {
			t.Error("a complete RFC 6455 handshake must be recognised, or its 101 breaks")
		}
	})
}

// --- ServeHTTP bypass contract -----------------------------

// The three tests that follow replace three that pinned the
// defect (v2.73).
//
// They used to assert that a handshake skipped Coraza
// completely — "regardless of the request payload", in the
// words of the one named BypassesWAF, which added a
// rule-tripping query to prove the WAF never saw it. That was
// the contract, and the contract was the vulnerability: the
// only thing identifying a handshake is client-supplied
// headers, so two of them bought a full WAF bypass with no
// event emitted.
//
// What is skipped now is the response phase alone, because
// wrap()'s ResponseWriter has no http.Hijacker and HTTP 101
// needs one. The request phases run.

// A forged handshake carrying a payload is now refused in
// block mode. This is the inversion of the old BypassesWAF.
func TestServeHTTP_WebSocketHandshake_PayloadIsInspected(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "block")
	req := makeUpgradeRequest(t, "websocket", "Upgrade")
	// The payload the old test added to prove the WAF could
	// not see it.
	req.URL.RawQuery = "badparam=evil-payload"

	next := &recordingHandler{}
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP))
	if err == nil {
		t.Fatal("block mode must refuse a handshake whose URI trips a rule; " +
			"two client-supplied headers must not buy a WAF bypass")
	}
	if next.called {
		t.Error("the upstream must not be reached for a refused handshake")
	}
}

// Detect mode emits the event it never used to emit. The old
// test asserted zero events and called the bypass "total".
func TestServeHTTP_WebSocketHandshake_DetectMode_EmitsEvent(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "detect")
	req := makeUpgradeRequest(t, "websocket", "Upgrade")
	req.URL.RawQuery = "badparam=evil-payload"

	next := &recordingHandler{}
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("detect mode must not refuse the request: %v", err)
	}
	if !next.called {
		t.Error("detect mode must still reach the upstream")
	}
	if cap.eventCount() == 0 {
		t.Error("detect mode must emit an event for a handshake that trips a rule — " +
			"the silence was what made the bypass untraceable in the activity log")
	}
}

// The regression that matters for every real WebSocket app:
// a clean handshake reaches the upstream, with the ORIGINAL
// ResponseWriter, so the 101 can hijack the connection.
//
// This is the half of the old contract that was correct, and
// it is asserted on the writer's identity rather than on the
// status code: the status alone would stay 200 even if the
// response were wrapped, and the wrapper is exactly what
// breaks the upgrade.
func TestServeHTTP_WebSocketHandshake_CleanOneIsNotWrapped(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "block")
	req := makeUpgradeRequest(t, "websocket", "Upgrade")

	next := &recordingHandler{}
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("a clean handshake must pass: %v", err)
	}
	if !next.called {
		t.Fatal("a clean handshake must reach the upstream")
	}
	if next.got != http.ResponseWriter(rec) {
		t.Errorf("next received a wrapped ResponseWriter (%T); a handshake needs the original, "+
			"because wrap()'s writer has no http.Hijacker and the 101 cannot work without it",
			next.got)
	}
	if cap.eventCount() != 0 {
		t.Errorf("a clean handshake emitted %d events; want 0", cap.eventCount())
	}
}

// And a request that is NOT a handshake keeps its response
// wrapped, so the phase 4-5 rules still run on ordinary
// traffic. The guard on the other side of the branch.
func TestServeHTTP_OrdinaryRequest_IsStillWrapped(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "detect")
	req := httptest.NewRequest(http.MethodGet, "http://localhost/plain", nil)

	next := &recordingHandler{}
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Fatal("next not called")
	}
	if next.got == http.ResponseWriter(rec) {
		t.Error("an ordinary request must get Coraza's wrapped writer, or the response-phase " +
			"rules never run")
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
