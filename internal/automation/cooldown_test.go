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

// fakeClock is a controllable time source for LRU tests.
// Calls to fakeClock.now return the current setting; Advance
// moves it forward.
type fakeClock struct {
	t time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func TestCooldownLRU_RecordThenHasCooldown(t *testing.T) {
	c := newFakeClock()
	l := newCooldownLRUWithClock(c.now)

	if l.HasCooldown("1.2.3.4", "arenet/waf-sqli") {
		t.Fatal("empty LRU should not report cooldown")
	}

	l.Record("1.2.3.4", "arenet/waf-sqli", 24*time.Hour)
	if !l.HasCooldown("1.2.3.4", "arenet/waf-sqli") {
		t.Fatal("after Record, HasCooldown should return true")
	}
	if l.Size() != 1 {
		t.Errorf("Size() = %d, want 1", l.Size())
	}
}

func TestCooldownLRU_ExpiresAtTTLBoundary(t *testing.T) {
	c := newFakeClock()
	l := newCooldownLRUWithClock(c.now)

	l.Record("1.2.3.4", "arenet/waf-sqli", 1*time.Hour)

	// Mid-window → still in cooldown.
	c.Advance(30 * time.Minute)
	if !l.HasCooldown("1.2.3.4", "arenet/waf-sqli") {
		t.Error("at T+30m of 1h cooldown, should still be in cooldown")
	}

	// Past boundary → no cooldown, entry lazily removed.
	c.Advance(31 * time.Minute) // now T+61m
	if l.HasCooldown("1.2.3.4", "arenet/waf-sqli") {
		t.Error("at T+61m of 1h cooldown, should NOT be in cooldown")
	}
	if l.Size() != 0 {
		t.Errorf("expired entry not evicted on lookup: Size()=%d", l.Size())
	}
}

func TestCooldownLRU_ZeroTTLIsNoOp(t *testing.T) {
	l := newCooldownLRU()
	l.Record("1.2.3.4", "arenet/waf-sqli", 0)
	if l.Size() != 0 {
		t.Errorf("Record(ttl=0) should be no-op, got Size=%d", l.Size())
	}
	l.Record("1.2.3.4", "arenet/waf-sqli", -1*time.Hour)
	if l.Size() != 0 {
		t.Errorf("Record(ttl<0) should be no-op, got Size=%d", l.Size())
	}
}

func TestCooldownLRU_ReRecordExtends(t *testing.T) {
	c := newFakeClock()
	l := newCooldownLRUWithClock(c.now)

	l.Record("1.2.3.4", "arenet/waf-sqli", 1*time.Hour)
	c.Advance(45 * time.Minute) // T+45m
	// Re-record with fresh 1h TTL.
	l.Record("1.2.3.4", "arenet/waf-sqli", 1*time.Hour)
	// At T+90m, the original 1h would have expired, but
	// the re-record TTL is from T+45m so cooldown ends at
	// T+105m. At T+90m we're still in cooldown.
	c.Advance(45 * time.Minute) // T+90m
	if !l.HasCooldown("1.2.3.4", "arenet/waf-sqli") {
		t.Error("re-record should extend cooldown forward")
	}
}

func TestCooldownLRU_DistinctScenarios(t *testing.T) {
	l := newCooldownLRU()
	l.Record("1.2.3.4", "arenet/waf-sqli", 1*time.Hour)
	if l.HasCooldown("1.2.3.4", "arenet/auth-burst") {
		t.Error("cooldown should be scenario-specific")
	}
	if !l.HasCooldown("1.2.3.4", "arenet/waf-sqli") {
		t.Error("original cooldown should still fire")
	}
}

func TestCooldownLRU_EvictsOldestOnCapSaturation(t *testing.T) {
	c := newFakeClock()
	l := newCooldownLRUWithClock(c.now)
	l.maxSize = 3 // shrink for the test

	// Fill exactly to cap.
	l.Record("ip1", "arenet/waf-sqli", 1*time.Hour)
	c.Advance(1 * time.Second)
	l.Record("ip2", "arenet/waf-sqli", 1*time.Hour)
	c.Advance(1 * time.Second)
	l.Record("ip3", "arenet/waf-sqli", 1*time.Hour)
	if l.Size() != 3 {
		t.Fatalf("Size=%d, want 3", l.Size())
	}

	// Cap saturation → next Record evicts oldest (ip1).
	c.Advance(1 * time.Second)
	l.Record("ip4", "arenet/waf-sqli", 1*time.Hour)
	if l.Size() != 3 {
		t.Errorf("Size=%d, want 3 (cap holds)", l.Size())
	}
	if l.HasCooldown("ip1", "arenet/waf-sqli") {
		t.Error("ip1 (oldest) should have been evicted on cap saturation")
	}
	for _, ip := range []string{"ip2", "ip3", "ip4"} {
		if !l.HasCooldown(ip, "arenet/waf-sqli") {
			t.Errorf("%s should still be in cooldown after eviction of ip1", ip)
		}
	}
}
