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

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/throttle"
)

// newTestRateLimiter constructs a RateLimiter with a logger writing
// into a buffer, and a controllable clock. Returns the limiter, the
// buffer to inspect, and a *time.Time pointer to advance the clock.
func newTestRateLimiter(t *testing.T) (*RateLimiter, *bytes.Buffer, *time.Time) {
	t.Helper()
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rl := NewRateLimiter(logger)

	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	clock := &now
	rl.nowFunc = func() time.Time { return *clock }
	return rl, buf, clock
}

// advance moves the test clock forward by d.
func advance(clock *time.Time, d time.Duration) {
	*clock = clock.Add(d)
}

func TestNewRateLimiter_NilLoggerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil logger, got none")
		}
	}()
	_ = NewRateLimiter(nil)
}

func TestRateLimiter_Allow_FreshIP(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)
	allowed, retry, dur := rl.Allow("203.0.113.5")
	if !allowed {
		t.Error("fresh IP should be allowed")
	}
	if retry != 0 || dur != 0 {
		t.Errorf("retry=%v dur=%v, want zeros", retry, dur)
	}
}

func TestRateLimiter_Allow_EmptyIPAllowed(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)
	for i := 0; i < 20; i++ {
		rl.Hit("", "admin")
	}
	allowed, _, _ := rl.Allow("")
	if !allowed {
		t.Error("empty IP must always be allowed (not associable to a bucket)")
	}
}

// AC-RATE-01: 5 failures in 5 min → block 15 min on 6th attempt.
func TestRateLimiter_Tier1_5FailuresIn5Min(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)
	ip := "203.0.113.5"

	for i := 0; i < 5; i++ {
		rl.Hit(ip, "admin")
	}

	// 6th attempt must be blocked, retry ≈ 15 minutes.
	allowed, retry, dur := rl.Allow(ip)
	if allowed {
		t.Fatal("after 5 failures, 6th attempt should be blocked")
	}
	if dur != Tier1Block {
		t.Errorf("blockDuration = %v, want %v (Tier 1)", dur, Tier1Block)
	}
	if retry <= 0 || retry > Tier1Block {
		t.Errorf("retryAfter = %v, want in (0, %v]", retry, Tier1Block)
	}
}

// AC-RATE-02: 10 failures in 1 hour → block 1 hour on 11th attempt.
func TestRateLimiter_Tier2_10FailuresIn1Hour(t *testing.T) {
	rl, _, clock := newTestRateLimiter(t)
	ip := "203.0.113.5"

	// 5 failures in fast succession would trigger Tier 1 → 15 min block.
	// To reach Tier 2 we need to spread failures outside the 5-min
	// window so Tier 1 doesn't fire each time. Spread 10 failures
	// across 10 minutes (1 every 1 minute), then a 30-min wait clears
	// Tier 1 partial count, then 5 more hits. Simpler: space 6 min apart
	// so Tier 1 window only sees one failure at a time.
	for i := 0; i < 10; i++ {
		rl.Hit(ip, "admin")
		advance(clock, 6*time.Minute) // outside Tier 1 window
	}
	// At this point Tier 1 only sees 1 recent hit; Tier 2 sees 10
	// over the past hour. The block on the last Hit comes from Tier 2.

	allowed, _, dur := rl.Allow(ip)
	if allowed {
		t.Fatal("after 10 spaced failures, 11th attempt should be blocked")
	}
	if dur != Tier2Block {
		t.Errorf("blockDuration = %v, want %v (Tier 2)", dur, Tier2Block)
	}
}

// AC-RATE-03: a successful login resets the failure counter.
func TestRateLimiter_ResetOnSuccess(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)
	ip := "203.0.113.5"

	// 4 failures (one short of Tier 1 trigger).
	for i := 0; i < 4; i++ {
		rl.Hit(ip, "admin")
	}
	allowed, _, _ := rl.Allow(ip)
	if !allowed {
		t.Fatal("4 failures should not block yet")
	}

	rl.Reset(ip)

	// After reset, can fail 4 more times without triggering.
	for i := 0; i < 4; i++ {
		rl.Hit(ip, "admin")
	}
	allowed, _, _ = rl.Allow(ip)
	if !allowed {
		t.Error("after Reset + 4 new failures, must still be allowed")
	}
}

// AC-RATE-04: every Tier 2 hit emits a structured slog.Warn with the
// expected fields. This is the security observability hook for
// operators to configure their upstream firewall.
func TestRateLimiter_Tier2_LogsWarnWithFields(t *testing.T) {
	rl, buf, clock := newTestRateLimiter(t)
	ip := "203.0.113.42"
	username := "admin"

	// Same approach as TestRateLimiter_Tier2: space hits 6 min apart
	// so Tier 1 does NOT fire. Only Tier 2 should trigger.
	for i := 0; i < 10; i++ {
		rl.Hit(ip, username)
		advance(clock, 6*time.Minute)
	}

	logs := buf.String()
	if !strings.Contains(logs, `"level":"WARN"`) {
		t.Errorf("expected WARN level log, got: %s", logs)
	}
	if !strings.Contains(logs, "rate limit tier 2 triggered") {
		t.Errorf("expected tier 2 message, got: %s", logs)
	}
	if !strings.Contains(logs, `"ip":"`+ip+`"`) {
		t.Errorf("expected ip field, got: %s", logs)
	}
	if !strings.Contains(logs, `"username_attempted":"`+username+`"`) {
		t.Errorf("expected username_attempted field, got: %s", logs)
	}
	if !strings.Contains(logs, `"failure_count_window":10`) {
		t.Errorf("expected failure_count_window=10, got: %s", logs)
	}
	if !strings.Contains(logs, `"suggestion":"consider blocking this IP at network level"`) {
		t.Errorf("expected suggestion field, got: %s", logs)
	}

	// Verify no log was emitted at Tier 1 (the explicit assertion
	// the spec doesn't make but the design enforces).
	if strings.Contains(logs, "tier 1") {
		t.Errorf("Tier 1 must NOT log Warn, got: %s", logs)
	}
}

// AC-RATE-04 hardening: empty attempted_username is logged as empty
// string (the field is always present so log parsers can rely on it).
func TestRateLimiter_Tier2_EmptyUsernameLogged(t *testing.T) {
	rl, buf, clock := newTestRateLimiter(t)
	for i := 0; i < 10; i++ {
		rl.Hit("203.0.113.99", "")
		advance(clock, 6*time.Minute)
	}
	if !strings.Contains(buf.String(), `"username_attempted":""`) {
		t.Errorf("empty username must be logged as empty string, got: %s", buf.String())
	}
}

// AC-RATE-05: in-memory storage; restart clears all counters.
// Simulated here by constructing a fresh limiter (representing the
// restarted server) and confirming the previously-blocked IP starts
// from zero.
func TestRateLimiter_RestartClearsCounters(t *testing.T) {
	rl1, _, _ := newTestRateLimiter(t)
	ip := "203.0.113.5"
	for i := 0; i < 5; i++ {
		rl1.Hit(ip, "admin")
	}
	if allowed, _, _ := rl1.Allow(ip); allowed {
		t.Fatal("seed: IP must be blocked after 5 failures")
	}

	// "Restart" → fresh limiter.
	rl2, _, _ := newTestRateLimiter(t)
	if allowed, _, _ := rl2.Allow(ip); !allowed {
		t.Error("after restart, the IP must start unblocked")
	}
}

// AC-RATE-06: rate limit is per-IP, not per-username. Two different
// attackers from the same IP attempting different usernames share
// the same counter.
func TestRateLimiter_PerIPNotPerUsername(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)
	ip := "203.0.113.5"

	// 3 failures with username "admin", 2 failures with "root" — same IP.
	for i := 0; i < 3; i++ {
		rl.Hit(ip, "admin")
	}
	for i := 0; i < 2; i++ {
		rl.Hit(ip, "root")
	}

	allowed, _, dur := rl.Allow(ip)
	if allowed {
		t.Fatal("5 mixed-username failures from same IP should trigger Tier 1")
	}
	if dur != Tier1Block {
		t.Errorf("expected Tier 1 block, got %v", dur)
	}
}

// Block expiry: after the block duration elapses, the IP becomes
// allowed again. Critical for fairness — Tier 1 block must clear
// after 15 min, not be permanent.
func TestRateLimiter_BlockExpires(t *testing.T) {
	rl, _, clock := newTestRateLimiter(t)
	ip := "203.0.113.5"

	for i := 0; i < 5; i++ {
		rl.Hit(ip, "admin")
	}
	if allowed, _, _ := rl.Allow(ip); allowed {
		t.Fatal("seed block")
	}

	advance(clock, Tier1Block+time.Second)
	if allowed, _, _ := rl.Allow(ip); !allowed {
		t.Error("block must clear after Tier 1 duration")
	}
}

// Sliding window: 5 failures spread over 6 min (one outside the
// 5-min window) must NOT trigger Tier 1.
func TestRateLimiter_SlidingWindowTier1(t *testing.T) {
	rl, _, clock := newTestRateLimiter(t)
	ip := "203.0.113.5"

	rl.Hit(ip, "admin") // t=0
	advance(clock, 6*time.Minute)
	for i := 0; i < 4; i++ {
		rl.Hit(ip, "admin") // 4 hits at t=6min
	}

	allowed, _, _ := rl.Allow(ip)
	if !allowed {
		t.Error("oldest hit is outside the 5-min window; should NOT block")
	}
}

// GetBlockedIPs returns the currently-blocked entries; expired
// blocks are excluded.
func TestRateLimiter_GetBlockedIPs(t *testing.T) {
	rl, _, clock := newTestRateLimiter(t)

	// Block 2 IPs in Tier 1.
	for _, ip := range []string{"1.2.3.4", "5.6.7.8"} {
		for i := 0; i < 5; i++ {
			rl.Hit(ip, "admin")
		}
	}
	got := rl.GetBlockedIPs()
	if len(got) != 2 {
		t.Fatalf("want 2 blocked, got %d", len(got))
	}
	if got[0].IP != "1.2.3.4" || got[1].IP != "5.6.7.8" {
		t.Errorf("expected sorted output, got %+v", got)
	}

	// After Tier 1 expiry, both should disappear from the list.
	advance(clock, Tier1Block+time.Second)
	if got := rl.GetBlockedIPs(); len(got) != 0 {
		t.Errorf("expired blocks must not appear, got %d", len(got))
	}
}

// Sweep removes inactive entries; active blocks are preserved.
func TestRateLimiter_Sweep(t *testing.T) {
	rl, _, clock := newTestRateLimiter(t)

	// Inactive entry: 1 failure, then idle for > InactiveAfter.
	rl.Hit("inactive.example", "admin")
	advance(clock, InactiveAfter+time.Minute)

	// Active block: 5 failures right before sweep.
	for i := 0; i < 5; i++ {
		rl.Hit("active.example", "admin")
	}

	rl.sweep()

	// Active block must remain.
	if _, ok := rl.state["active.example"]; !ok {
		t.Error("active block was swept away")
	}
	// Inactive entry must be gone.
	if _, ok := rl.state["inactive.example"]; ok {
		t.Error("inactive entry was not swept")
	}
}

func TestRateLimiter_StartStops(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)
	ctx, cancel := context.WithCancel(context.Background())
	rl.Start(ctx)
	// Give goroutine a brief moment to enter the for-select.
	time.Sleep(10 * time.Millisecond)
	cancel()
	// No deterministic way to assert goroutine exit without leak
	// detection; the test mainly confirms Start does not panic.
}

// --- Middleware tests --------------------------------------------------

// inject a test IP into context, then run the middleware.
func runMW(rl *RateLimiter, ip, attemptedUsername string, handlerStatus int) (status int, body string, headers http.Header) {
	mw := rl.Middleware()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handlerStatus != 0 {
			w.WriteHeader(handlerStatus)
		}
	})
	wrapped := mw(inner)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	ctx := context.WithValue(r.Context(), ClientIPKey, ip)
	if attemptedUsername != "" {
		ctx = SetAttemptedUsername(ctx, attemptedUsername)
	}
	r = r.WithContext(ctx)

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, r)
	bodyBytes, _ := io.ReadAll(rec.Body)
	return rec.Code, string(bodyBytes), rec.Header()
}

func TestMiddleware_IncrementsOn401(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)
	for i := 0; i < 5; i++ {
		status, _, _ := runMW(rl, "203.0.113.5", "admin", http.StatusUnauthorized)
		if status != http.StatusUnauthorized {
			t.Errorf("expected 401 passthrough, got %d", status)
		}
	}
	// 6th request: middleware blocks before handler.
	status, body, hdr := runMW(rl, "203.0.113.5", "admin", http.StatusOK)
	if status != http.StatusTooManyRequests {
		t.Errorf("6th request: got %d, want 429", status)
	}
	if !strings.Contains(body, "retry after 15 minutes") {
		t.Errorf("body lacks expected message: %s", body)
	}
	if hdr.Get("Retry-After") == "" {
		t.Error("Retry-After header missing")
	}
}

func TestMiddleware_IncrementsOn403(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)
	for i := 0; i < 5; i++ {
		runMW(rl, "203.0.113.5", "admin", http.StatusForbidden)
	}
	status, _, _ := runMW(rl, "203.0.113.5", "admin", http.StatusOK)
	if status != http.StatusTooManyRequests {
		t.Errorf("got %d, want 429", status)
	}
}

func TestMiddleware_NotIncrementedOn200(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)
	for i := 0; i < 10; i++ {
		runMW(rl, "203.0.113.5", "admin", http.StatusOK)
	}
	if allowed, _, _ := rl.Allow("203.0.113.5"); !allowed {
		t.Error("200 responses must NOT increment failure counter")
	}
}

func TestMiddleware_EmptyIPNotRateLimited(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)
	for i := 0; i < 20; i++ {
		status, _, _ := runMW(rl, "", "admin", http.StatusUnauthorized)
		if status != http.StatusUnauthorized {
			t.Errorf("iter %d: empty-IP requests should never be blocked, got %d", i, status)
		}
	}
}

// Verify the 429 response body for Tier 2 says "retry after 1 hour".
func TestMiddleware_Tier2Message(t *testing.T) {
	rl, _, clock := newTestRateLimiter(t)
	ip := "203.0.113.42"

	// Trigger Tier 2: 10 failures spaced 6 min apart so Tier 1 never fires.
	for i := 0; i < 10; i++ {
		rl.Hit(ip, "admin")
		advance(clock, 6*time.Minute)
	}
	// Now the IP is blocked. A new request must get the Tier 2 message.
	status, body, hdr := runMW(rl, ip, "", 0)
	if status != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", status)
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("body not JSON: %s (%v)", body, err)
	}
	if parsed["error"] != "too many attempts, retry after 1 hour" {
		t.Errorf("error msg = %q, want \"too many attempts, retry after 1 hour\"", parsed["error"])
	}
	// Retry-After should be ≤ 3600.
	if s, _ := strconv.Atoi(hdr.Get("Retry-After")); s <= 0 || s > 3600 {
		t.Errorf("Retry-After = %s, want 1..3600", hdr.Get("Retry-After"))
	}
}

// Race-detector smoke test: many goroutines hitting the limiter
// concurrently must not panic or trigger -race warnings.
func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := "203.0.113." + strconv.Itoa(i%5)
			for j := 0; j < 20; j++ {
				rl.Hit(ip, "user")
				rl.Allow(ip)
				if j%3 == 0 {
					rl.Reset(ip)
				}
			}
			_ = rl.GetBlockedIPs()
		}(i)
	}
	wg.Wait()
}

// captureSink is a minimal throttle.EventSink fake used only
// by the Step Q rate-limit emit tests. Lives in the test
// file so production code carries no test-only dependency.
type captureSink struct {
	mu     sync.Mutex
	events []throttle.Event
}

func (c *captureSink) Emit(e throttle.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureSink) snapshot() []throttle.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]throttle.Event, len(c.events))
	copy(out, c.events)
	return out
}

func TestRateLimiter_Tier1Block_EmitsThrottleEvent(t *testing.T) {
	rl, _, _ := newTestRateLimiter(t)

	cs := &captureSink{}
	throttle.SetGlobalSink(cs)
	t.Cleanup(func() { throttle.SetGlobalSink(nil) })

	for i := 0; i < Tier1Threshold; i++ {
		rl.Hit("198.51.100.10", "admin")
	}

	got := cs.snapshot()
	if len(got) == 0 {
		t.Fatal("Tier 1 threshold crossing should have emitted at least one throttle event")
	}
	last := got[len(got)-1]
	if last.Tier != 1 {
		t.Errorf("last event Tier = %d, want 1", last.Tier)
	}
	if last.SrcIP != "198.51.100.10" {
		t.Errorf("last event SrcIP = %q, want 198.51.100.10", last.SrcIP)
	}
	if last.AttemptedUsername != "admin" {
		t.Errorf("last event AttemptedUsername = %q, want admin", last.AttemptedUsername)
	}
	wantSec := int((Tier1Block).Round(time.Second) / time.Second)
	if last.BlockDurationSeconds != wantSec {
		t.Errorf("last event BlockDurationSeconds = %d, want %d (= Tier1Block)", last.BlockDurationSeconds, wantSec)
	}
}

func TestRateLimiter_Tier2Block_EmitsThrottleEvent(t *testing.T) {
	rl, _, clock := newTestRateLimiter(t)

	cs := &captureSink{}
	throttle.SetGlobalSink(cs)
	t.Cleanup(func() { throttle.SetGlobalSink(nil) })

	// Same shape as TestRateLimiter_Tier2_10FailuresIn1Hour:
	// space hits 6 min apart so Tier 1's 5-min window never
	// trips, only Tier 2's 1h window. (Tier1 would otherwise
	// fire first and we'd see Tier-1 events.)
	for i := 0; i < Tier2Threshold; i++ {
		rl.Hit("198.51.100.20", "root")
		advance(clock, 6*time.Minute)
	}

	got := cs.snapshot()
	if len(got) == 0 {
		t.Fatal("Tier 2 threshold crossing should have emitted at least one throttle event")
	}
	// Find a Tier-2 event in the captures (the last few hits
	// should produce Tier-2; earlier hits could not have
	// produced any block).
	found := false
	for _, e := range got {
		if e.Tier == 2 && e.SrcIP == "198.51.100.20" && e.AttemptedUsername == "root" {
			found = true
			wantSec := int((Tier2Block).Round(time.Second) / time.Second)
			if e.BlockDurationSeconds != wantSec {
				t.Errorf("Tier-2 event BlockDurationSeconds = %d, want %d (= Tier2Block)", e.BlockDurationSeconds, wantSec)
			}
			break
		}
	}
	if !found {
		t.Errorf("no Tier-2 event found in captured emissions: %+v", got)
	}
}

func TestRateLimiter_NoBlock_NoEmit(t *testing.T) {
	// Pre-threshold failures must NOT emit throttle events.
	// The audit log carries them; the throttle event log is
	// for BLOCK decisions only (spec D1.A).
	rl, _, _ := newTestRateLimiter(t)

	cs := &captureSink{}
	throttle.SetGlobalSink(cs)
	t.Cleanup(func() { throttle.SetGlobalSink(nil) })

	for i := 0; i < Tier1Threshold-1; i++ {
		rl.Hit("198.51.100.30", "user")
	}

	if got := cs.snapshot(); len(got) != 0 {
		t.Errorf("expected 0 emissions before threshold crossed, got %d: %+v", len(got), got)
	}
}

func TestRateLimiter_NoGlobalSink_DoesNotPanic(t *testing.T) {
	// AC #13 degraded mode: rate limiter MUST tolerate a nil
	// global sink (e.g. observability store failed at boot).
	rl, _, _ := newTestRateLimiter(t)
	throttle.SetGlobalSink(nil) // belt-and-braces

	for i := 0; i < Tier1Threshold; i++ {
		rl.Hit("198.51.100.40", "user")
	}
	// Test passes if Hit didn't panic.
}
