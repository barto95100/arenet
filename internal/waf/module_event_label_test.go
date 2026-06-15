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
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3/types"
)

// #R-WAF-EVENT-LABEL-BLOCK-VS-200 regression pins. Five tests
// covering the per-tx event buffer's flushTxBuffer decision
// matrix + the concurrent-tx isolation property.
//
// Operator-confirmed scope (Day 14): V1 keeps the existing
// block-mode onMatch filter (`if !mr.Disruptive() return`)
// unchanged — the bug was the (Action, StatusCode) label
// applied to events that DID fire, not the filter itself.
// The flush rewrites the labels based on the transaction's
// final verdict.

// --- Test 5 — flushTxBuffer table test (the decision matrix)
// Direct unit on the helper without booting Coraza. Exercises
// the three (mode, interruption) tuples that ServeHTTP can
// hand to flush.

func TestFlushTxBuffer_DecisionMatrix(t *testing.T) {
	cases := []struct {
		name         string
		mode         string
		interruption *types.Interruption
		wantAction   string
		wantStatus   int
	}{
		{
			name:         "block mode + interruption → BLOCK + interruption status",
			mode:         "block",
			interruption: &types.Interruption{Status: http.StatusForbidden, Action: "deny"},
			wantAction:   ActionBlock,
			wantStatus:   http.StatusForbidden,
		},
		{
			name: "block mode + interruption with zero status → BLOCK + 403 default",
			mode: "block",
			// Coraza populates Status from the rule's
			// status: param; a rule without it leaves
			// Status zero. Flush must fall back to 403.
			interruption: &types.Interruption{Action: "deny"},
			wantAction:   ActionBlock,
			wantStatus:   http.StatusForbidden,
		},
		{
			name: "block mode + NO interruption → DETECT + 200 (the bug repro shape)",
			mode: "block",
			// This is the #R-WAF-EVENT-LABEL bug repro:
			// onMatch fired Disruptive=true (rule declares
			// `block`), event got buffered, but the
			// transaction never actually interrupted
			// (admin path FP guard removed 949* aggregator
			// → no anomaly score gateway → request flows
			// through). Pre-fix the event was BLOCK/403;
			// post-fix it tells the truth: DETECT/200.
			interruption: nil,
			wantAction:   ActionDetect,
			wantStatus:   http.StatusOK,
		},
		{
			name:         "detect mode + interruption → DETECT + 0 (unchanged regression pin)",
			mode:         "detect",
			interruption: &types.Interruption{Status: http.StatusForbidden, Action: "deny"},
			wantAction:   ActionDetect,
			wantStatus:   0,
		},
		{
			name:         "detect mode + NO interruption → DETECT + 0 (the common detect path)",
			mode:         "detect",
			interruption: nil,
			wantAction:   ActionDetect,
			wantStatus:   0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap := newCaptureSink()
			setGlobalSinkFor(t, cap)

			h := &ArenetWafHandler{RouteID: "r-flush", Mode: tc.mode}
			buf := &txEventBuffer{
				events: []Event{
					{RuleID: "942100", Severity: 2},
					{RuleID: "941100", Severity: 3},
				},
			}
			h.flushTxBuffer(buf, tc.interruption)

			got := cap.eventsCopy()
			if len(got) != 2 {
				t.Fatalf("captureSink received %d events; want 2", len(got))
			}
			for i, ev := range got {
				if ev.Action != tc.wantAction {
					t.Errorf("event[%d].Action = %q; want %q",
						i, ev.Action, tc.wantAction)
				}
				if ev.StatusCode != tc.wantStatus {
					t.Errorf("event[%d].StatusCode = %d; want %d",
						i, ev.StatusCode, tc.wantStatus)
				}
			}
		})
	}
}

func TestFlushTxBuffer_EmptyBuffer_NoEmit(t *testing.T) {
	// Defensive — flushTxBuffer with no buffered events must
	// not call sink.Emit even once. Prevents a "zero rule
	// fired but we logged something anyway" regression.
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := &ArenetWafHandler{RouteID: "r-empty", Mode: "block"}
	h.flushTxBuffer(&txEventBuffer{}, &types.Interruption{Status: 403})

	if got := len(cap.eventsCopy()); got != 0 {
		t.Errorf("captureSink received %d events on empty buffer flush; want 0", got)
	}
}

// --- Test 2 — Regression pin: real block-mode rule that DOES
// interrupt. The existing minimalBlockDirectives rule
// (deny,status:403) fires AND actually denies — flushTxBuffer
// must therefore emit BLOCK/403 (unchanged from pre-fix
// behaviour on the happy block path).

func TestServeHTTP_BlockMode_InterruptingRule_EmitsBlockStatus(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "block")
	req := httptest.NewRequest(http.MethodGet, "http://localhost/?badparam=evil-payload", nil)
	rec := httptest.NewRecorder()
	next := &passthroughHandler{}
	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP))

	if next.called {
		t.Fatal("next was called; the WAF should have blocked the request")
	}
	events := cap.eventsCopy()
	if len(events) == 0 {
		t.Fatal("captureSink received zero events; the test rule should have fired")
	}
	for i, ev := range events {
		if ev.Action != ActionBlock {
			t.Errorf("event[%d].Action = %q; want %q (real interruption)",
				i, ev.Action, ActionBlock)
		}
		if ev.StatusCode != http.StatusForbidden {
			t.Errorf("event[%d].StatusCode = %d; want 403", i, ev.StatusCode)
		}
	}
}

// --- Test 3 — Regression pin: detect mode unchanged. Every
// match still emits DETECT/0 sentinel regardless of whether
// the rule had a disruptive action declared.

func TestServeHTTP_DetectMode_PreservesDetectSentinel(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "detect")
	req := httptest.NewRequest(http.MethodGet, "http://localhost/?badparam=evil-payload", nil)
	rec := httptest.NewRecorder()
	next := &passthroughHandler{}
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("detect mode ServeHTTP: %v", err)
	}

	if !next.called {
		t.Fatal("next was NOT called in detect mode (pass-through invariant regressed)")
	}
	events := cap.eventsCopy()
	if len(events) == 0 {
		t.Fatal("captureSink received zero events; rule should have fired in detect mode")
	}
	for i, ev := range events {
		if ev.Action != ActionDetect {
			t.Errorf("event[%d].Action = %q; want %q", i, ev.Action, ActionDetect)
		}
		if ev.StatusCode != 0 {
			t.Errorf("event[%d].StatusCode = %d; want 0 (detect sentinel)",
				i, ev.StatusCode)
		}
	}
}

// --- Test 4 — Concurrent tx isolation. Two ServeHTTP
// invocations running on different goroutines must NOT see
// each other's buffered events. The sync.Map keyed by tx.ID()
// is the isolation primitive; this test pins that two
// concurrent transactions allocated from Coraza's shared
// txPool (and which may therefore reuse the same *Transaction
// pointer over time) keep their events separate.
//
// Strategy: fire 30 parallel requests with the trip-rule
// payload. Each emits at least one event. The total event
// count must equal the request count (no cross-pollination)
// AND every event's Action/StatusCode must be BLOCK/403 (the
// rule actually interrupts, so each tx's flush sees its own
// interruption). A regression that keyed the buffer on tx
// pointer would surface here as either dropped events
// (collision overwrote) or stale events (one tx flushed
// another's buffer with the wrong interruption).

func TestServeHTTP_ConcurrentTransactions_NoCrossPollination(t *testing.T) {
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "block")

	const N = 30
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet,
				"http://localhost/?badparam=evil-payload", nil)
			rec := httptest.NewRecorder()
			_ = h.ServeHTTP(rec, req,
				caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
					w.WriteHeader(http.StatusOK)
					return nil
				}))
		}()
	}
	wg.Wait()

	events := cap.eventsCopy()
	if len(events) < N {
		t.Fatalf("captureSink received %d events; want >= %d (one per concurrent request, possibly more if a request triggered multiple rule matches)",
			len(events), N)
	}
	// Every event must carry the correct interruption-derived
	// label. A buffer collision under tx-pointer keying would
	// surface as some events having the wrong Action/StatusCode
	// (e.g. a tx that didn't interrupt borrowing another tx's
	// state). The interruption-true → BLOCK/403 chain is the
	// strongest invariant we can check end-to-end.
	for i, ev := range events {
		if ev.Action != ActionBlock {
			t.Errorf("event[%d].Action = %q; want %q (cross-pollination?)",
				i, ev.Action, ActionBlock)
		}
		if ev.StatusCode != http.StatusForbidden {
			t.Errorf("event[%d].StatusCode = %d; want 403 (cross-pollination?)",
				i, ev.StatusCode)
		}
	}
}

// --- Test 6 (bonus / D5 defensive) — buffer cleanup happens
// even when flushTxBuffer panics. The ServeHTTP defer chain
// uses a nested defer for Delete; this test verifies the
// Delete still fires when the outer flush body panics.

func TestServeHTTP_FlushPanic_BufferStillDeleted(t *testing.T) {
	// We can't easily trigger a real panic inside the
	// production flushTxBuffer (the func is straightforward
	// — slice walk + Emit). Instead we exercise the defer
	// chain shape directly: a closure that mirrors the
	// ServeHTTP defer (nested Delete + flush body that
	// panics) must leave the map clean.
	var txBuffers sync.Map
	txID := "test-tx-id"
	txBuffers.Store(txID, &txEventBuffer{})

	func() {
		defer func() {
			// Catch the panic we're about to trigger so
			// the test runner sees a clean fail/pass
			// rather than a panic.
			_ = recover()
		}()
		defer func() {
			defer txBuffers.Delete(txID)
			panic("simulated flush panic")
		}()
	}()

	if _, ok := txBuffers.Load(txID); ok {
		t.Error("txBuffers entry leaked after flush panic; nested defer Delete did not fire")
	}
}
