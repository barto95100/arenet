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

package auth

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func quietLimiter() *RateLimiter {
	return NewRateLimiter(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// A success for one account must not erase the failures accumulated
// while brute-forcing another from the same IP (F51/F57).
func TestRateLimiter_ResetForUser_KeepsOtherAccountsFailures(t *testing.T) {
	rl := quietLimiter()
	const ip = "203.0.113.5"

	// Four failed admin guesses — below the tier-1 threshold of five.
	for i := 0; i < Tier1Threshold-1; i++ {
		rl.Hit(ip, "admin")
	}
	// A low-privilege holder logs in successfully as themselves.
	rl.ResetForUser(ip, "viewer")
	// The admin failures must survive: the next admin failure trips the
	// block. Were the viewer success to have cleared the whole bucket,
	// this Hit would be the first and no block would fire.
	rl.Hit(ip, "admin")
	if allowed, _, _ := rl.Allow(ip); allowed {
		t.Error("a viewer success wiped the admin brute-force failures — the per-IP ceiling is defeated (F51/F57)")
	}

	// A success AS admin does clear admin's own failures (the legitimate
	// "typed it wrong, then right" case is still forgiven).
	rl2 := quietLimiter()
	for i := 0; i < Tier1Threshold-1; i++ {
		rl2.Hit(ip, "admin")
	}
	rl2.ResetForUser(ip, "admin")
	rl2.Hit(ip, "admin") // only this one failure remains in the window
	if allowed, _, _ := rl2.Allow(ip); !allowed {
		t.Error("a success as admin should have cleared admin's own earlier failures")
	}
}

// A concurrent burst from one IP must not all clear the Allow gate
// before any failure is recorded. With per-IP serialisation the block
// kicks in after the tier-1 threshold, so only a bounded number of the
// burst reach the handler (F33/F56).
func TestRateLimiter_Middleware_SerialisesConcurrentBurst(t *testing.T) {
	rl := quietLimiter()
	var reached atomic.Int32
	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		time.Sleep(3 * time.Millisecond)       // overlap the burst, as argon2id does in prod
		w.WriteHeader(http.StatusUnauthorized) // every attempt fails
	}))

	const n = 60
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
			r = r.WithContext(context.WithValue(r.Context(), ClientIPKey, "203.0.113.9"))
			h.ServeHTTP(httptest.NewRecorder(), r)
		}()
	}
	wg.Wait()

	// After Tier1Threshold recorded failures the gate blocks, so the
	// handler sees at most that many (plus the one whose Hit sets the
	// block). A raced gate would let all n through.
	if got := reached.Load(); got > int32(Tier1Threshold+1) {
		t.Errorf("%d of %d concurrent attempts reached the handler; the burst outran the counter (want <= %d) — F33/F56",
			got, n, Tier1Threshold+1)
	}
}

// The per-IP state map must not grow without bound: at the cap, inserting
// a new key evicts the least-recently-seen entry, so an attacker cycling
// through distinct source addresses cannot drive unbounded memory (F50).
func TestRateLimiter_CapsCardinality(t *testing.T) {
	rl := quietLimiter()
	rl.maxEntries = 3

	// Record failures from more distinct IPs than the cap. Each Hit sets
	// a fresh lastSeen, so the earliest IPs are the eviction victims.
	for i := 0; i < 10; i++ {
		rl.Hit(fmt.Sprintf("10.0.0.%d", i), "admin")
	}

	rl.mu.Lock()
	n := len(rl.state)
	rl.mu.Unlock()
	if n > rl.maxEntries {
		t.Errorf("state holds %d entries, cap is %d — the map grew past the cap (F50)", n, rl.maxEntries)
	}
}
