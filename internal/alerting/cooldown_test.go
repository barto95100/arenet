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

package alerting

import (
	"sync"
	"testing"
	"time"
)

// AL.2.b — CooldownLRU pinning tests.

// clockMock is the canonical injectable clock for the
// alerting watcher tests. now is mutable behind a mutex
// so tests can advance it across goroutine boundaries.
type clockMock struct {
	mu  sync.Mutex
	now time.Time
}

func newClockMock(start time.Time) *clockMock {
	return &clockMock{now: start}
}
func (c *clockMock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *clockMock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestCooldownLRU_OnCooldown_FalseBeforeMark(t *testing.T) {
	c := NewCooldownLRU(nil)
	if c.OnCooldown("rule-1", "ch-1", 60*time.Second) {
		t.Errorf("OnCooldown = true before Mark; want false")
	}
}

func TestCooldownLRU_OnCooldown_TrueAfterMark(t *testing.T) {
	clk := newClockMock(time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC))
	c := NewCooldownLRU(clk.Now)
	c.Mark("rule-1", "ch-1")
	if !c.OnCooldown("rule-1", "ch-1", 5*time.Minute) {
		t.Errorf("OnCooldown = false right after Mark; want true")
	}
}

func TestCooldownLRU_OnCooldown_FalseAfterWindow(t *testing.T) {
	clk := newClockMock(time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC))
	c := NewCooldownLRU(clk.Now)
	c.Mark("rule-1", "ch-1")

	clk.Advance(5*time.Minute + time.Second)
	if c.OnCooldown("rule-1", "ch-1", 5*time.Minute) {
		t.Errorf("OnCooldown = true after window elapsed; want false")
	}
}

func TestCooldownLRU_PerChannelIndependent(t *testing.T) {
	c := NewCooldownLRU(nil)
	c.Mark("rule-1", "ch-1")
	if c.OnCooldown("rule-1", "ch-2", time.Minute) {
		t.Errorf("ch-2 cooldown bled from ch-1 mark; want isolated")
	}
}

func TestCooldownLRU_PerRuleIndependent(t *testing.T) {
	c := NewCooldownLRU(nil)
	c.Mark("rule-1", "ch-1")
	if c.OnCooldown("rule-2", "ch-1", time.Minute) {
		t.Errorf("rule-2 cooldown bled from rule-1 mark; want isolated")
	}
}

func TestCooldownLRU_EvictStale_DropsAgedEntries(t *testing.T) {
	clk := newClockMock(time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC))
	c := NewCooldownLRU(clk.Now)
	c.evictionFloor = 1 * time.Hour
	c.Mark("rule-1", "ch-1")

	// 2 hours later, the entry should be evicted (> 1h
	// floor) even if no rule was removed.
	clk.Advance(2 * time.Hour)
	evicted := c.EvictStale(map[string]struct{}{"rule-1": {}})
	if evicted != 1 {
		t.Errorf("evicted = %d; want 1", evicted)
	}
	if c.Size() != 0 {
		t.Errorf("Size = %d after Evict; want 0", c.Size())
	}
}

func TestCooldownLRU_EvictStale_DropsMissingRules(t *testing.T) {
	c := NewCooldownLRU(nil)
	c.Mark("rule-ghost", "ch-1")
	c.Mark("rule-alive", "ch-1")

	// Only rule-alive is in the keep set; rule-ghost gets
	// dropped despite being within its window.
	evicted := c.EvictStale(map[string]struct{}{"rule-alive": {}})
	if evicted != 1 {
		t.Errorf("evicted = %d; want 1", evicted)
	}
	if c.Size() != 1 {
		t.Errorf("Size = %d; want 1 (rule-alive retained)", c.Size())
	}
}

func TestCooldownLRU_EvictStale_NilKeepRulesOnlyStalenessCheck(t *testing.T) {
	clk := newClockMock(time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC))
	c := NewCooldownLRU(clk.Now)
	c.evictionFloor = 1 * time.Hour
	c.Mark("rule-1", "ch-1")

	// nil keepRules → only the staleness check runs;
	// fresh entry survives.
	evicted := c.EvictStale(nil)
	if evicted != 0 {
		t.Errorf("evicted = %d; want 0 (fresh + nil keepRules)", evicted)
	}
	if c.Size() != 1 {
		t.Errorf("Size = %d; want 1", c.Size())
	}
}

func TestCooldownLRU_Mark_OverwritesPriorEntry(t *testing.T) {
	clk := newClockMock(time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC))
	c := NewCooldownLRU(clk.Now)
	c.Mark("rule-1", "ch-1")
	clk.Advance(4 * time.Minute) // still within 5-min window
	c.Mark("rule-1", "ch-1")     // re-mark resets the window

	clk.Advance(4 * time.Minute) // 8 min from first mark; 4 min from second
	if !c.OnCooldown("rule-1", "ch-1", 5*time.Minute) {
		t.Errorf("OnCooldown = false; second Mark didn't reset the window")
	}
}
