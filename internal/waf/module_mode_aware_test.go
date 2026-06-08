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

// W.bugfix Fix #1 — pin the onMatch path's mode-aware Event
// construction. The existing module_test.go covers the
// "request reaches the upstream / is blocked" side; these
// tests cover the "the emitted Event row carries the right
// Action + StatusCode" side. Combined, they pin the contract
// end-to-end (mode in → ServeHTTP outcome + persisted Event
// shape out).

// TestOnMatch_BlockMode_EmitsBlockAction403 — a block-mode
// handler whose Coraza transaction trips a rule must emit
// Action=BLOCK + StatusCode=403 to the sink.
func TestOnMatch_BlockMode_EmitsBlockAction403(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "block")
	req := httptest.NewRequest(http.MethodGet, "http://localhost/?badparam=evil-payload", nil)
	rec := httptest.NewRecorder()
	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}))

	events := cap.eventsCopy()
	if len(events) == 0 {
		t.Fatal("captureSink received zero events; the test rule should have fired")
	}
	for i, ev := range events {
		if ev.Action != ActionBlock {
			t.Errorf("event[%d] Action = %q; want %q", i, ev.Action, ActionBlock)
		}
		if ev.StatusCode != 403 {
			t.Errorf("event[%d] StatusCode = %d; want 403", i, ev.StatusCode)
		}
	}
}

// TestOnMatch_DetectMode_EmitsDetectAction0 — a detect-mode
// handler whose Coraza transaction would have tripped a rule
// (the rule fires regardless of engine state) must emit
// Action=DETECT + StatusCode=0 to the sink.
//
// This is the direct fix for the operator-reported false-
// positive: pre-fix the event was emitted with no Action
// field, the frontend hardcoded "BLOCK 403" labels, and
// detect-mode routes appeared to block when they didn't.
func TestOnMatch_DetectMode_EmitsDetectAction0(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "detect")
	next := &passthroughHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/?badparam=evil-payload", nil)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("detect mode ServeHTTP: %v", err)
	}

	if !next.called {
		t.Fatal("next was NOT called in detect mode (the existing pass-through invariant must still hold)")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("response status = %d; want 200 (detect mode passes to upstream)", rec.Code)
	}

	events := cap.eventsCopy()
	if len(events) == 0 {
		t.Fatal("captureSink received zero events; the test rule should have fired in detect mode")
	}
	for i, ev := range events {
		if ev.Action != ActionDetect {
			t.Errorf("event[%d] Action = %q; want %q", i, ev.Action, ActionDetect)
		}
		if ev.StatusCode != 0 {
			t.Errorf("event[%d] StatusCode = %d; want 0 (detect mode; upstream status unknown at WAF callback time)", i, ev.StatusCode)
		}
		// Metadata still preserved.
		if ev.RuleID == "" {
			t.Errorf("event[%d] RuleID empty; metadata capture regressed", i)
		}
	}
}
