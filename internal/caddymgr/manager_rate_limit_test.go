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

package caddymgr

import (
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// Step Q (2026-06-18) — buildRateLimitHandler emit shape
// tests. Mirror of the X.1 buildWAFHandler test pattern :
// assert the exact JSON map shape so a future change can't
// silently drift the contract Caddy's caddy-ratelimit
// module reads.

func TestBuildRateLimitHandler_Nil_ReturnsNil(t *testing.T) {
	// Pre-Q routes (and routes that don't opt in) MUST
	// produce no handler entry — the chain stays byte-equal
	// to the pre-Q shape so pool dedup / Caddy parse cost /
	// boot smoke comparisons all hold.
	if got := buildRateLimitHandler("r-1", nil); got != nil {
		t.Errorf("buildRateLimitHandler(nil) = %+v ; want nil", got)
	}
}

func TestBuildRateLimitHandler_Happy_EmitsRateLimitZone(t *testing.T) {
	rl := &storage.RouteRateLimit{
		Events: 60,
		Window: "1m",
		Key:    "{http.request.remote.host}",
	}
	got := buildRateLimitHandler("r-1", rl)
	if got == nil {
		t.Fatalf("buildRateLimitHandler returned nil for valid config")
	}
	if v, _ := got["handler"].(string); v != "rate_limit" {
		t.Errorf("handler = %q ; want %q", got["handler"], "rate_limit")
	}
	zones, _ := got["rate_limits"].(map[string]any)
	if zones == nil {
		t.Fatalf("rate_limits missing or wrong type ; got = %+v", got)
	}
	zone, _ := zones["route-r-1"].(map[string]any)
	if zone == nil {
		t.Fatalf("zone 'route-r-1' missing ; got zones = %+v", zones)
	}
	if v, _ := zone["max_events"].(int); v != 60 {
		t.Errorf("max_events = %v ; want 60", zone["max_events"])
	}
	if v, _ := zone["key"].(string); v != "{http.request.remote.host}" {
		t.Errorf("key = %q ; want default placeholder", zone["key"])
	}
	// window emitted as time.Duration (caddy.Duration
	// JSON-marshals as nanoseconds — match the parse-back).
	if d, ok := zone["window"].(time.Duration); !ok || d != time.Minute {
		t.Errorf("window = %v (%T) ; want 1m time.Duration", zone["window"], zone["window"])
	}
}

func TestBuildRateLimitHandler_EmptyKey_Defaulted(t *testing.T) {
	// Empty Key from the operator → defaulted to the safe
	// raw-socket placeholder.
	rl := &storage.RouteRateLimit{Events: 100, Window: "30s", Key: ""}
	got := buildRateLimitHandler("r-empty", rl)
	if got == nil {
		t.Fatalf("buildRateLimitHandler returned nil for valid config")
	}
	zone := got["rate_limits"].(map[string]any)["route-r-empty"].(map[string]any)
	if zone["key"].(string) != "{http.request.remote.host}" {
		t.Errorf("empty-key default = %q ; want %q",
			zone["key"], "{http.request.remote.host}")
	}
}

func TestBuildRateLimitHandler_InvalidWindow_ReturnsNil(t *testing.T) {
	// Validation defence in depth : a stored row with a
	// garbled Window logs a warn + skips the handler. The
	// route just runs without the rate limit instead of
	// crashing the whole config build.
	cases := []string{"", "not-a-duration", "10", "0s", "-1m"}
	for _, w := range cases {
		t.Run("window="+w, func(t *testing.T) {
			rl := &storage.RouteRateLimit{Events: 60, Window: w}
			if got := buildRateLimitHandler("r-bad", rl); got != nil {
				t.Errorf("invalid window %q produced a handler %+v ; want nil", w, got)
			}
		})
	}
}

func TestBuildRateLimitHandler_NonPositiveEvents_ReturnsNil(t *testing.T) {
	// Events == 0 would block every request (rate-limit
	// zone with a 0 cap rejects on the first event).
	// Negative is non-sensical. Defence : skip the handler
	// in both cases.
	cases := []int{0, -1, -100}
	for _, e := range cases {
		rl := &storage.RouteRateLimit{Events: e, Window: "1m"}
		if got := buildRateLimitHandler("r-zero", rl); got != nil {
			t.Errorf("non-positive Events=%d produced a handler %+v ; want nil", e, got)
		}
	}
}

func TestBuildRateLimitHandler_ZoneNamePerRoute(t *testing.T) {
	// mholt/caddy-ratelimit README warns the zone NAME
	// must be globally unique across handler instances —
	// otherwise two routes share a counter and a brute-
	// force on route A throttles legitimate traffic on
	// route B. The "route-<UUID>" prefix guarantees
	// uniqueness ; pin it.
	a := buildRateLimitHandler("uuid-aaa", &storage.RouteRateLimit{Events: 1, Window: "1m"})
	b := buildRateLimitHandler("uuid-bbb", &storage.RouteRateLimit{Events: 1, Window: "1m"})
	zoneA := firstKey(a["rate_limits"].(map[string]any))
	zoneB := firstKey(b["rate_limits"].(map[string]any))
	if zoneA == zoneB {
		t.Errorf("two distinct routes produced the same zone name %q ; counters would collide",
			zoneA)
	}
	if zoneA != "route-uuid-aaa" || zoneB != "route-uuid-bbb" {
		t.Errorf("zone naming convention drifted : got %q / %q ; want route-<uuid> shape",
			zoneA, zoneB)
	}
}

func firstKey(m map[string]any) string {
	for k := range m {
		return k
	}
	return ""
}
