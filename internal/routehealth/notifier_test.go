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

package routehealth

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/caddyhc"
	"github.com/barto95100/arenet/internal/storage"
)

// --- fakes ------------------------------------------------------------

type fakeStatus struct {
	mu sync.Mutex
	m  map[string]string
}

func newFakeStatus() *fakeStatus { return &fakeStatus{m: map[string]string{}} }
func (f *fakeStatus) set(addr, s string) {
	f.mu.Lock()
	f.m[addr] = s
	f.mu.Unlock()
}
func (f *fakeStatus) Status(addr string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[addr]
}

type dispatchCall struct {
	evt      alerting.AlertEvent
	channels []string
}

type fakeDisp struct {
	mu    sync.Mutex
	calls []dispatchCall
}

func (d *fakeDisp) Dispatch(_ context.Context, evt alerting.AlertEvent, channels []string) alerting.DispatchResult {
	d.mu.Lock()
	d.calls = append(d.calls, dispatchCall{evt, channels})
	d.mu.Unlock()
	return alerting.DispatchResult{}
}
func (d *fakeDisp) snapshot() []dispatchCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dispatchCall(nil), d.calls...)
}

// manualClock fires timers by advancing a virtual now, firing earliest
// due first (and picking up timers scheduled while firing).
type manualClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}
type fakeTimer struct {
	due     time.Time
	f       func()
	stopped bool
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *manualClock) AfterFunc(d time.Duration, f func()) timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	ft := &fakeTimer{due: c.now.Add(d), f: f}
	c.timers = append(c.timers, ft)
	return ft
}
func (t *fakeTimer) Stop() bool {
	was := !t.stopped
	t.stopped = true
	return was
}
func (c *manualClock) advance(d time.Duration) {
	target := c.now.Add(d)
	for {
		c.mu.Lock()
		var next *fakeTimer
		for _, t := range c.timers {
			if t.stopped || t.due.After(target) {
				continue
			}
			if next == nil || t.due.Before(next.due) {
				next = t
			}
		}
		if next == nil {
			c.now = target
			c.mu.Unlock()
			return
		}
		c.now = next.due
		next.stopped = true
		f := next.f
		c.mu.Unlock()
		f() // may schedule new timers; picked up on the next loop
	}
}

func newTestNotifier(ts *fakeStatus, d *fakeDisp, start time.Time) (*Notifier, *manualClock) {
	n := NewNotifier(ts, d, nil)
	clk := &manualClock{now: start}
	n.clk = clk
	n.window = 3 * time.Second
	return n, clk
}

func enabled(id, host, channel string, reminderMin int, upstreams ...string) storage.Route {
	ups := make([]storage.Upstream, len(upstreams))
	for i, u := range upstreams {
		ups[i] = storage.Upstream{URL: u, Weight: 1}
	}
	return storage.Route{
		ID: id, Host: host, Upstreams: ups,
		HealthNotify: storage.HealthNotifyConfig{Enabled: true, ChannelID: channel, ReminderMinutes: reminderMin},
	}
}

// --- aggregate (pure) -------------------------------------------------

func TestAggregate(t *testing.T) {
	H, U, unk := caddyhc.StatusHealthy, caddyhc.StatusUnhealthy, caddyhc.StatusUnknown
	cases := []struct {
		in   []string
		want aggState
	}{
		{[]string{H}, stateHealthy},
		{[]string{U}, stateDown},
		{[]string{U, U}, stateDown},
		{[]string{U, H}, stateDegraded},
		{[]string{U, unk}, stateDegraded},  // unknown is not down, so some-but-not-all
		{[]string{unk, unk}, stateHealthy}, // warm-up: nothing observed unhealthy
		{[]string{H, H}, stateHealthy},
		{nil, stateHealthy},
	}
	for _, tc := range cases {
		if got := aggregate(tc.in); got != tc.want {
			t.Errorf("aggregate(%v) = %d; want %d", tc.in, got, tc.want)
		}
	}
}

// --- gate: edge, not level -------------------------------------------

func TestNotifier_EdgeNotLevel(t *testing.T) {
	ts := newFakeStatus()
	d := &fakeDisp{}
	t0 := time.Unix(1000, 0).UTC()
	n, clk := newTestNotifier(ts, d, t0)
	n.Refresh([]storage.Route{enabled("r1", "app.example.com", "ch1", 0, "http://10.0.0.5:80")})

	const addr = "10.0.0.5:80"
	// down edge, flushed in its own window
	ts.set(addr, caddyhc.StatusUnhealthy)
	n.OnTransition(addr, "", "", t0)
	clk.advance(3 * time.Second) // flush → one down

	// a second unhealthy report (level, no aggregate change) in a SEPARATE
	// window: a level-triggered notifier would flush a second "down" here.
	n.OnTransition(addr, "", "", clk.now)
	clk.advance(3 * time.Second)

	// recovery edge 2 hours after the first down
	recAt := t0.Add(2 * time.Hour)
	clk.now = recAt
	ts.set(addr, caddyhc.StatusHealthy)
	n.OnTransition(addr, "", "", recAt)
	clk.advance(3 * time.Second)

	calls := d.snapshot()
	if len(calls) != 2 {
		t.Fatalf("got %d dispatches, want exactly 2 (down, recovered); level repeats must not fire: %+v", len(calls), subjects(calls))
	}
	if calls[0].evt.Severity != alerting.SeverityCritical || !strings.Contains(calls[0].evt.Subject, "down") {
		t.Errorf("first dispatch = %q (%v); want a Critical down", calls[0].evt.Subject, calls[0].evt.Severity)
	}
	if calls[1].evt.Severity != alerting.SeverityInfo || !strings.Contains(calls[1].evt.Subject, "recovered") {
		t.Errorf("second dispatch = %q (%v); want an Info recovered", calls[1].evt.Subject, calls[1].evt.Severity)
	}
	if !strings.Contains(calls[1].evt.Body, "2 hours") {
		t.Errorf("recovered body = %q; want the outage duration \"2 hours\"", calls[1].evt.Body)
	}
	for _, c := range calls {
		if len(c.channels) != 1 || c.channels[0] != "ch1" {
			t.Errorf("dispatched to %v; want the route's chosen channel [ch1]", c.channels)
		}
	}
}

// --- gate: grouping by upstream --------------------------------------

func TestNotifier_GroupsRoutesSharingAnUpstream(t *testing.T) {
	ts := newFakeStatus()
	d := &fakeDisp{}
	t0 := time.Unix(2000, 0).UTC()
	n, clk := newTestNotifier(ts, d, t0)
	const addr = "10.0.0.9:80"
	n.Refresh([]storage.Route{
		enabled("r1", "a.example.com", "ch1", 0, "http://"+addr),
		enabled("r2", "b.example.com", "ch1", 0, "http://"+addr),
		enabled("r3", "c.example.com", "ch1", 0, "http://"+addr),
	})

	ts.set(addr, caddyhc.StatusUnhealthy)
	n.OnTransition(addr, "", "", t0) // one flip, three routes edge
	clk.advance(3 * time.Second)

	calls := d.snapshot()
	if len(calls) != 1 {
		t.Fatalf("got %d dispatches, want 1 (same upstream + channel grouped): %+v", len(calls), subjects(calls))
	}
	body := calls[0].evt.Body
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if !strings.Contains(body, host) {
			t.Errorf("grouped message missing %s; body=%q", host, body)
		}
	}
	if !strings.Contains(calls[0].evt.Subject, "3 routes") {
		t.Errorf("subject = %q; want it to count 3 routes", calls[0].evt.Subject)
	}
}

func TestNotifier_DifferentChannelsNotGrouped(t *testing.T) {
	ts := newFakeStatus()
	d := &fakeDisp{}
	t0 := time.Unix(2500, 0).UTC()
	n, clk := newTestNotifier(ts, d, t0)
	const addr = "10.0.0.9:80"
	n.Refresh([]storage.Route{
		enabled("r1", "a.example.com", "ch1", 0, "http://"+addr),
		enabled("r2", "b.example.com", "ch2", 0, "http://"+addr),
	})
	ts.set(addr, caddyhc.StatusUnhealthy)
	n.OnTransition(addr, "", "", t0)
	clk.advance(3 * time.Second)

	calls := d.snapshot()
	if len(calls) != 2 {
		t.Fatalf("got %d dispatches, want 2 (one per channel): %+v", len(calls), subjects(calls))
	}
}

// --- gate: degraded vs down ------------------------------------------

func TestNotifier_DegradedThenDown(t *testing.T) {
	ts := newFakeStatus()
	d := &fakeDisp{}
	t0 := time.Unix(3000, 0).UTC()
	n, clk := newTestNotifier(ts, d, t0)
	u1, u2 := "10.0.0.1:80", "10.0.0.2:80"
	n.Refresh([]storage.Route{enabled("r1", "app.example.com", "ch1", 0, "http://"+u1, "http://"+u2)})

	// one upstream down, the other healthy → degraded
	ts.set(u1, caddyhc.StatusUnhealthy)
	ts.set(u2, caddyhc.StatusHealthy)
	n.OnTransition(u1, "", "", t0)
	clk.advance(3 * time.Second)

	// the second upstream down too → down
	ts.set(u2, caddyhc.StatusUnhealthy)
	n.OnTransition(u2, "", "", t0.Add(time.Minute))
	clk.advance(3 * time.Second)

	calls := d.snapshot()
	if len(calls) != 2 {
		t.Fatalf("got %d dispatches, want 2 (degraded, down): %+v", len(calls), subjects(calls))
	}
	if calls[0].evt.Severity != alerting.SeverityWarning || !strings.Contains(calls[0].evt.Subject, "degraded") {
		t.Errorf("first = %q (%v); want Warning degraded", calls[0].evt.Subject, calls[0].evt.Severity)
	}
	if calls[1].evt.Severity != alerting.SeverityCritical || !strings.Contains(calls[1].evt.Subject, "down") {
		t.Errorf("second = %q (%v); want Critical down", calls[1].evt.Subject, calls[1].evt.Severity)
	}
}

// --- gate: reminder cadence ------------------------------------------

func TestNotifier_ReminderWhileDown_StopsOnRecovery(t *testing.T) {
	ts := newFakeStatus()
	d := &fakeDisp{}
	t0 := time.Unix(4000, 0).UTC()
	n, clk := newTestNotifier(ts, d, t0)
	const addr = "10.0.0.7:80"
	n.Refresh([]storage.Route{enabled("r1", "app.example.com", "ch1", 5, "http://"+addr)}) // reminder every 5 min

	ts.set(addr, caddyhc.StatusUnhealthy)
	n.OnTransition(addr, "", "", t0)
	clk.advance(3 * time.Second) // flush down

	clk.advance(5 * time.Minute) // one reminder
	clk.advance(5 * time.Minute) // second reminder

	if got := countReminders(d.snapshot()); got != 2 {
		t.Fatalf("got %d reminders, want 2 (one per 5-minute interval while down)", got)
	}

	// recovery stops the nag
	ts.set(addr, caddyhc.StatusHealthy)
	n.OnTransition(addr, "", "", clk.now)
	clk.advance(3 * time.Second)  // flush recovered
	clk.advance(30 * time.Minute) // plenty of intervals
	if got := countReminders(d.snapshot()); got != 2 {
		t.Errorf("reminders kept firing after recovery: got %d, want 2", got)
	}
}

func subjects(calls []dispatchCall) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = c.evt.Subject
	}
	sort.Strings(out)
	return out
}

func countReminders(calls []dispatchCall) int {
	n := 0
	for _, c := range calls {
		if c.evt.Labels["reminder"] == "1" {
			n++
		}
	}
	return n
}

// TestNotifier_SharedUpstream_PagesOnlyTheDownRoute is the v2.76 gate #1:
// two routes share one upstream; with the per-route reader wired, a flip
// on the shared address pages ONLY the route whose own backend is down.
// Without the reader (pre-v2.76) both would read the collapsed tracker
// state and both would be named — which is the reported bug.
func TestNotifier_SharedUpstream_PagesOnlyTheDownRoute(t *testing.T) {
	ts := &fakeStatus{m: map[string]string{"10.66.0.2:80": caddyhc.StatusUnhealthy}} // collapsed shared state
	d := &fakeDisp{}
	n, clk := newTestNotifier(ts, d, time.Now())

	// Per-route truth: meet's backend is down, www's is up.
	n.SetPerRouteStatus(func(routeID, _ string) (string, bool) {
		switch routeID {
		case "meet":
			return caddyhc.StatusUnhealthy, true
		case "www":
			return caddyhc.StatusHealthy, true
		}
		return "", false
	})
	n.Refresh([]storage.Route{
		enabled("meet", "meet.hacf.fr", "ch1", 0, "http://10.66.0.2:80"),
		enabled("www", "www.hacf.fr", "ch1", 0, "http://10.66.0.2:80"),
	})

	n.OnTransition("10.66.0.2:80", "", "", clk.Now())
	clk.advance(5 * time.Second) // past the debounce window → flush

	calls := d.snapshot()
	if len(calls) != 1 {
		t.Fatalf("dispatch calls = %d; want 1 (only meet)", len(calls))
	}
	body := calls[0].evt.Body
	if !strings.Contains(body, "meet.hacf.fr") {
		t.Errorf("notification omits meet.hacf.fr (the down route): %q", body)
	}
	if strings.Contains(body, "www.hacf.fr") {
		t.Errorf("notification names www.hacf.fr, which is UP: %q", body)
	}
	if !strings.Contains(strings.ToLower(calls[0].evt.Subject), "down") {
		t.Errorf("subject = %q; want a 'down' notification", calls[0].evt.Subject)
	}
}
