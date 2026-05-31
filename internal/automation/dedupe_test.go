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

package automation

import (
	"testing"
	"time"
)

func TestDedupeLRU_MissOnFresh(t *testing.T) {
	l := newDedupeLRU()
	_, hit := l.Lookup("Ip", "1.2.3.4", "arenet/waf-sqli")
	if hit {
		t.Error("fresh LRU should report cache miss")
	}
}

func TestDedupeLRU_HitWithinTTL(t *testing.T) {
	c := newFakeClock()
	l := newDedupeLRUWithClock(c.now)

	l.Record("Ip", "1.2.3.4", "arenet/waf-sqli", true)
	c.Advance(30 * time.Second) // well within 60s TTL

	active, hit := l.Lookup("Ip", "1.2.3.4", "arenet/waf-sqli")
	if !hit {
		t.Fatal("expected cache hit within TTL")
	}
	if !active {
		t.Error("recorded active=true should round-trip")
	}
}

func TestDedupeLRU_ExpiresAfterTTL(t *testing.T) {
	c := newFakeClock()
	l := newDedupeLRUWithClock(c.now)

	l.Record("Ip", "1.2.3.4", "arenet/waf-sqli", true)
	c.Advance(61 * time.Second) // past 60s dedupeTTL

	_, hit := l.Lookup("Ip", "1.2.3.4", "arenet/waf-sqli")
	if hit {
		t.Error("expected cache miss after TTL")
	}
	if l.Size() != 0 {
		t.Errorf("expired entry not evicted on lookup: Size=%d", l.Size())
	}
}

func TestDedupeLRU_InvalidateSweepsAllScenarios(t *testing.T) {
	// Spec §3.4: a tombstone for (scope, value) invalidates
	// every scenario entry for that pair.
	l := newDedupeLRU()
	l.Record("Ip", "1.2.3.4", "arenet/waf-sqli", true)
	l.Record("Ip", "1.2.3.4", "arenet/throttle-tier2", true)
	l.Record("Ip", "5.6.7.8", "arenet/waf-sqli", true) // different IP — must NOT be invalidated

	l.Invalidate("Ip", "1.2.3.4")

	if _, hit := l.Lookup("Ip", "1.2.3.4", "arenet/waf-sqli"); hit {
		t.Error("Invalidate should clear (1.2.3.4, waf-sqli)")
	}
	if _, hit := l.Lookup("Ip", "1.2.3.4", "arenet/throttle-tier2"); hit {
		t.Error("Invalidate should clear (1.2.3.4, throttle-tier2)")
	}
	if _, hit := l.Lookup("Ip", "5.6.7.8", "arenet/waf-sqli"); !hit {
		t.Error("Invalidate should NOT clear other IPs")
	}
}

func TestDedupeLRU_RecordOverwritesActive(t *testing.T) {
	l := newDedupeLRU()
	l.Record("Ip", "1.2.3.4", "arenet/waf-sqli", false)
	if active, _ := l.Lookup("Ip", "1.2.3.4", "arenet/waf-sqli"); active {
		t.Fatal("initial active should be false")
	}
	l.Record("Ip", "1.2.3.4", "arenet/waf-sqli", true)
	if active, _ := l.Lookup("Ip", "1.2.3.4", "arenet/waf-sqli"); !active {
		t.Error("re-record should overwrite active to true")
	}
}

func TestDedupeLRU_EvictsOldestOnCapSaturation(t *testing.T) {
	c := newFakeClock()
	l := newDedupeLRUWithClock(c.now)
	l.maxSize = 3

	l.Record("Ip", "ip1", "arenet/waf-sqli", true)
	c.Advance(1 * time.Second)
	l.Record("Ip", "ip2", "arenet/waf-sqli", true)
	c.Advance(1 * time.Second)
	l.Record("Ip", "ip3", "arenet/waf-sqli", true)
	c.Advance(1 * time.Second)
	l.Record("Ip", "ip4", "arenet/waf-sqli", true) // evicts ip1

	if l.Size() != 3 {
		t.Errorf("Size=%d, want 3 (cap holds)", l.Size())
	}
	if _, hit := l.Lookup("Ip", "ip1", "arenet/waf-sqli"); hit {
		t.Error("ip1 (oldest) should have been evicted")
	}
}
