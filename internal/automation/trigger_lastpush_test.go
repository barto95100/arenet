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

package automation

import (
	"context"
	"sync"
	"testing"
	"time"
)

// scriptedWriter returns a pre-programmed sequence of PushAlert results,
// one per call, so a single test can drive success → failure → success.
type scriptedWriter struct {
	mu      sync.Mutex
	results []error
	i       int
}

func (s *scriptedWriter) EnsureJWT(_ context.Context) (string, error) { return "jwt", nil }
func (s *scriptedWriter) LoginFailed() bool                           { return false }
func (s *scriptedWriter) PushAlert(_ context.Context, _ Alert) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.i < len(s.results) {
		err = s.results[s.i]
	}
	s.i++
	if err != nil {
		return nil, err
	}
	return []string{"alert-1"}, nil
}

// TestEngine_RecordsLastPushAndClearsOnSuccess is the v2.83 point-3(a)
// guard: a successful push records LastPushAt and leaves no error; a
// permanent failure records LastPushError; and — the load-bearing half
// (spec D4) — the NEXT success clears that error, so LastPushError only
// ever reports a failure more recent than the last success.
//
// Reinjection that must fail this test: drop `e.lastPushErr.Store(nil)`
// from recordPushSuccess (so the error is never cleared). Step 3 below
// then still sees the stale error and the test fails.
func TestEngine_RecordsLastPushAndClearsOnSuccess(t *testing.T) {
	now := time.Now()
	// Sequence: success, ErrLoginFailed (permanent), success.
	sw := &scriptedWriter{results: []error{nil, ErrLoginFailed, nil}}

	rs := enableRule(SourceWafSQLi, 2, 60*time.Second, time.Hour, 24*time.Hour)
	e, err := NewEngine(EngineConfig{
		Waf: &fakeWafReader{}, Throttle: &fakeThrottleReader{}, Audit: &fakeAuditReader{},
		Rules:               NewRuleSetHolder(rs),
		Writer:              sw,
		Logger:              silentLogger(),
		TickInterval:        20 * time.Millisecond,
		Now:                 func() time.Time { return now },
		InitialCursorOffset: -time.Hour,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	intent := Intent{
		SrcIP: "1.2.3.4", Source: SourceWafSQLi,
		TriggeringEventID: "1", TriggeringEventCount: 2, DurationSeconds: 3600,
	}
	ctx := context.Background()

	// Before any push: both unset.
	if _, ok := e.LastPushAt(); ok {
		t.Fatal("LastPushAt set before any push")
	}
	if _, ok := e.LastPushError(); ok {
		t.Fatal("LastPushError set before any push")
	}

	// 1) Success → LastPushAt set to now, no error.
	e.processIntent(ctx, sw, intent)
	ts, ok := e.LastPushAt()
	if !ok || !ts.Equal(now) {
		t.Fatalf("after success: LastPushAt=%v ok=%v, want %v/true", ts, ok, now)
	}
	if msg, ok := e.LastPushError(); ok {
		t.Fatalf("after success: LastPushError=%q set, want unset", msg)
	}

	// 2) Permanent failure → LastPushError set.
	e.processIntent(ctx, sw, intent)
	if _, ok := e.LastPushError(); !ok {
		t.Fatal("after a permanent failure: LastPushError unset, want set")
	}
	if e.TotalPushPermanent() != 1 {
		t.Fatalf("TotalPushPermanent = %d, want 1", e.TotalPushPermanent())
	}

	// 3) Success again → error CLEARED (D4).
	e.processIntent(ctx, sw, intent)
	if msg, ok := e.LastPushError(); ok {
		t.Fatalf("after a later success: LastPushError=%q still set, want cleared", msg)
	}
	if e.TotalPushSuccess() != 2 {
		t.Fatalf("TotalPushSuccess = %d, want 2", e.TotalPushSuccess())
	}
}
