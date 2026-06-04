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

package caddyhc

import (
	"sync"
	"testing"
)

func TestTracker_EmptyReturnsUnknown(t *testing.T) {
	tr := NewTracker()
	if got := tr.Status("10.0.0.1:80"); got != StatusUnknown {
		t.Errorf("Status on empty tracker = %q, want %q", got, StatusUnknown)
	}
}

func TestTracker_RecordHealthyAndUnhealthy(t *testing.T) {
	tr := NewTracker()
	tr.RecordHealthy("10.0.0.1:80")
	if got := tr.Status("10.0.0.1:80"); got != StatusHealthy {
		t.Errorf("after RecordHealthy: got %q, want %q", got, StatusHealthy)
	}
	tr.RecordUnhealthy("10.0.0.1:80")
	if got := tr.Status("10.0.0.1:80"); got != StatusUnhealthy {
		t.Errorf("after RecordUnhealthy: got %q, want %q", got, StatusUnhealthy)
	}
	// Verify recovery: unhealthy → healthy on next healthy event.
	tr.RecordHealthy("10.0.0.1:80")
	if got := tr.Status("10.0.0.1:80"); got != StatusHealthy {
		t.Errorf("after recovery: got %q, want %q", got, StatusHealthy)
	}
}

func TestTracker_DistinctAddrsTrackedIndependently(t *testing.T) {
	tr := NewTracker()
	tr.RecordHealthy("10.0.0.1:80")
	tr.RecordUnhealthy("10.0.0.2:80")
	if got := tr.Status("10.0.0.1:80"); got != StatusHealthy {
		t.Errorf("addr1 status: got %q, want %q", got, StatusHealthy)
	}
	if got := tr.Status("10.0.0.2:80"); got != StatusUnhealthy {
		t.Errorf("addr2 status: got %q, want %q", got, StatusUnhealthy)
	}
	if got := tr.Status("10.0.0.3:80"); got != StatusUnknown {
		t.Errorf("untouched addr: got %q, want %q", got, StatusUnknown)
	}
}

func TestTracker_NormalizesAddrOnRecordAndQuery(t *testing.T) {
	// Events from Caddy arrive as bare "host:port". Storage upstream
	// URLs land with schemes ("http://host:port" or
	// "https://host:port/path"). The tracker must produce the same
	// key for both so the topology builder finds the recorded state
	// regardless of which side does the lookup.
	tr := NewTracker()
	tr.RecordHealthy("10.0.0.1:80")
	cases := []string{
		"10.0.0.1:80",
		"http://10.0.0.1:80",
		"http://10.0.0.1:80/",
		"https://10.0.0.1:80/",
		"http://10.0.0.1:80/healthz?token=x",
		"h2c://10.0.0.1:80",
		"h2://10.0.0.1:80",
	}
	for _, q := range cases {
		if got := tr.Status(q); got != StatusHealthy {
			t.Errorf("Status(%q) = %q, want %q (normalization mismatch)", q, got, StatusHealthy)
		}
	}
}

func TestTracker_EmptyAddrIgnored(t *testing.T) {
	tr := NewTracker()
	// Recording an empty address must not insert a "" entry that
	// every subsequent empty-string query would match. The
	// normalize-then-bail path protects the map.
	tr.RecordHealthy("")
	tr.RecordUnhealthy("")
	if got := tr.Status(""); got != StatusUnknown {
		t.Errorf("Status on empty addr: got %q, want %q", got, StatusUnknown)
	}
}

func TestTracker_ConcurrentRecordAndQuery(t *testing.T) {
	// Race detector test: many goroutines hammering Record + Status
	// must not produce a Go race report. The actual end state
	// (healthy vs unhealthy on a given addr) is intentionally
	// non-deterministic — we only assert no data race and no panic.
	tr := NewTracker()
	const goroutines = 50
	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		gi := g
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				addr := "10.0.0.1:80"
				if gi%2 == 0 {
					tr.RecordHealthy(addr)
				} else {
					tr.RecordUnhealthy(addr)
				}
				_ = tr.Status(addr)
			}
		}()
	}
	wg.Wait()
	// Final state must be one of the two real statuses — never an
	// empty string, because at least one record landed.
	got := tr.Status("10.0.0.1:80")
	if got != StatusHealthy && got != StatusUnhealthy {
		t.Errorf("post-race final state = %q, want healthy or unhealthy", got)
	}
}

func TestNormalizeAddr(t *testing.T) {
	cases := map[string]string{
		"":                                "",
		"10.0.0.1:80":                     "10.0.0.1:80",
		"http://10.0.0.1:80":              "10.0.0.1:80",
		"http://10.0.0.1:80/":             "10.0.0.1:80",
		"http://10.0.0.1:80/healthz":      "10.0.0.1:80",
		"http://10.0.0.1:80/healthz?x=1":  "10.0.0.1:80",
		"http://10.0.0.1:80/#frag":        "10.0.0.1:80",
		"https://api.example.com:8443/v2": "api.example.com:8443",
		"h2c://10.0.0.1:80":               "10.0.0.1:80",
		"h2://10.0.0.1:80":                "10.0.0.1:80",
		// Defensive cases: scheme-less but with query/path
		"10.0.0.1:80/healthz":  "10.0.0.1:80",
		"10.0.0.1:80?x=1":      "10.0.0.1:80",
		"10.0.0.1:80#fragment": "10.0.0.1:80",
	}
	for in, want := range cases {
		if got := NormalizeAddr(in); got != want {
			t.Errorf("NormalizeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
