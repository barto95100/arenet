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
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/caddyhc"
	"github.com/barto95100/arenet/internal/storage"
)

// DefaultWindow is how long the notifier waits after the first edge on an
// upstream before flushing, so several routes sharing a dead backend
// coalesce into one message (spec D6). Bounded and small — long enough to
// group a reload-storm of events, short enough that an operator is not
// kept waiting on a real outage.
const DefaultWindow = 3 * time.Second

// aggState is a route's aggregate health across its upstreams.
type aggState int

const (
	stateHealthy  aggState = iota // no upstream unhealthy
	stateDegraded                 // some, but not all, upstreams unhealthy
	stateDown                     // every upstream unhealthy
)

// aggregate reduces the per-upstream statuses of one route to its
// aggregate state. StatusUnknown (warm-up, no event yet) is treated as
// not-unhealthy, so a route whose upstreams have never reported does not
// page — only observed unhealthy transitions count.
func aggregate(statuses []string) aggState {
	if len(statuses) == 0 {
		return stateHealthy
	}
	unhealthy := 0
	for _, s := range statuses {
		if s == caddyhc.StatusUnhealthy {
			unhealthy++
		}
	}
	switch {
	case unhealthy == 0:
		return stateHealthy
	case unhealthy == len(statuses):
		return stateDown
	default:
		return stateDegraded
	}
}

// statusReader is the slice of the tracker the notifier reads.
type statusReader interface {
	Status(addr string) string
}

// eventDispatcher is the slice of alerting.Dispatcher the notifier uses;
// an interface so tests substitute a recording fake. *alerting.Dispatcher
// satisfies it.
type eventDispatcher interface {
	Dispatch(ctx context.Context, evt alerting.AlertEvent, channelIDs []string) alerting.DispatchResult
}

// timer is the subset of *time.Timer the notifier needs; a clock returns
// it so tests can fire scheduled work deterministically.
type timer interface{ Stop() bool }

// clock abstracts time for the debounce window and the reminder, so the
// tests do not sleep.
type clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) timer
}

type realClock struct{}

func (realClock) Now() time.Time                            { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) timer { return time.AfterFunc(d, f) }

// edge is one route's confirmed aggregate change, buffered for the
// coalescing flush.
type edge struct {
	routeID, host, channelID string
	state                    aggState
	at                       time.Time
	downSince                time.Time // set on a recovery edge, for the duration line
}

type pendingBatch struct {
	t     timer
	edges []edge
}

// Notifier turns per-upstream health transitions into per-route
// notifications on each route's chosen channel (spec 2026-10-17). It is
// fed by caddyhc's OnTransition hook and dispatches through
// alerting.Dispatcher. Safe for concurrent use.
type Notifier struct {
	tracker statusReader
	index   *index
	disp    eventDispatcher
	clk     clock
	window  time.Duration
	logger  *slog.Logger

	mu        sync.Mutex
	last      map[string]aggState  // routeID -> last-notified aggregate
	downSince map[string]time.Time // routeID -> when it entered a non-healthy state
	reminders map[string]timer     // routeID -> active reminder timer
	pending   map[string]*pendingBatch
}

// NewNotifier builds a notifier. tracker is read for the current status
// of a route's other upstreams; disp delivers the events. The index is
// refreshed by the caller at each reload via Index().
func NewNotifier(tracker statusReader, disp eventDispatcher, logger *slog.Logger) *Notifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &Notifier{
		tracker:   tracker,
		index:     newIndex(),
		disp:      disp,
		clk:       realClock{},
		window:    DefaultWindow,
		logger:    logger,
		last:      make(map[string]aggState),
		downSince: make(map[string]time.Time),
		reminders: make(map[string]timer),
		pending:   make(map[string]*pendingBatch),
	}
}

// Refresh updates the route index from the current route set. Call it at
// each Caddy reload (the same seam that resets the tracker).
func (n *Notifier) Refresh(routes []storage.Route) {
	n.index.Refresh(routes)
}

// OnTransition is registered on the caddyhc tracker. It recomputes the
// aggregate state of every route using the flipped upstream, buffers the
// ones whose aggregate changed, and arms the coalescing timer.
func (n *Notifier) OnTransition(addr, _, _ string, at time.Time) {
	refs := n.index.routesFor(addr)
	if len(refs) == 0 {
		return
	}

	n.mu.Lock()
	for _, ref := range refs {
		statuses := make([]string, 0, len(ref.upstream))
		for _, u := range ref.upstream {
			statuses = append(statuses, n.tracker.Status(u))
		}
		newState := aggregate(statuses)
		prev := n.last[ref.routeID]
		if newState == prev {
			continue // no aggregate edge for this route
		}
		n.last[ref.routeID] = newState

		e := edge{routeID: ref.routeID, host: ref.host, channelID: ref.notify.ChannelID, state: newState, at: at}
		switch {
		case prev == stateHealthy && newState != stateHealthy:
			// Entering an outage: remember when, so recovery can state
			// the duration.
			n.downSince[ref.routeID] = at
		case newState == stateHealthy:
			// Recovery: capture the outage start for the duration line,
			// then clear it and stop any reminder.
			e.downSince = n.downSince[ref.routeID]
			delete(n.downSince, ref.routeID)
			n.stopReminderLocked(ref.routeID)
		}
		// A reminder nags only while fully down.
		if newState == stateDown {
			n.armReminderLocked(ref)
		} else {
			n.stopReminderLocked(ref.routeID)
		}
		n.bufferLocked(addr, e)
	}
	n.mu.Unlock()
}

// bufferLocked appends an edge to the pending batch for an upstream and
// arms the window timer on the first edge. Caller holds n.mu.
func (n *Notifier) bufferLocked(addr string, e edge) {
	b := n.pending[addr]
	if b == nil {
		b = &pendingBatch{}
		n.pending[addr] = b
		b.t = n.clk.AfterFunc(n.window, func() { n.flush(addr) })
	}
	b.edges = append(b.edges, e)
}

// flush delivers the coalesced batch for an upstream: one message per
// (state, channel) group, so routes sharing an upstream AND a channel
// collapse into a single notification, while routes on different channels
// each get their own.
func (n *Notifier) flush(addr string) {
	n.mu.Lock()
	b := n.pending[addr]
	delete(n.pending, addr)
	n.mu.Unlock()
	if b == nil {
		return
	}

	type key struct {
		state     aggState
		channelID string
	}
	groups := map[key][]edge{}
	for _, e := range b.edges {
		k := key{e.state, e.channelID}
		groups[k] = append(groups[k], e)
	}
	for k, edges := range groups {
		evt := n.buildEvent(addr, k.state, edges)
		n.disp.Dispatch(context.Background(), evt, []string{k.channelID})
	}
}

// buildEvent renders one AlertEvent for a group of routes that changed to
// the same state on the same upstream.
func (n *Notifier) buildEvent(addr string, state aggState, edges []edge) alerting.AlertEvent {
	hosts := make([]string, 0, len(edges))
	for _, e := range edges {
		hosts = append(hosts, e.host)
	}
	sort.Strings(hosts)

	var subject, body string
	var sev alerting.Severity
	switch state {
	case stateDown:
		sev = alerting.SeverityCritical
		subject = fmt.Sprintf("%s down", countedRoutes(len(hosts)))
		body = fmt.Sprintf("Every upstream of %s is unreachable via %s.\n\n%s",
			countedRoutes(len(hosts)), addr, bulletHosts(hosts))
	case stateDegraded:
		sev = alerting.SeverityWarning
		subject = fmt.Sprintf("%s degraded", countedRoutes(len(hosts)))
		body = fmt.Sprintf("An upstream of %s (%s) is unhealthy; the route still has a healthy upstream.\n\n%s",
			countedRoutes(len(hosts)), addr, bulletHosts(hosts))
	default: // stateHealthy == recovered
		sev = alerting.SeverityInfo
		subject = fmt.Sprintf("%s recovered", countedRoutes(len(hosts)))
		body = fmt.Sprintf("%s recovered via %s.\n\n%s",
			countedRoutes(len(hosts)), addr, bulletRecovered(edges))
	}

	return alerting.AlertEvent{
		ID:        uuid.NewString(),
		Timestamp: n.clk.Now().UTC(),
		RuleName:  "route-health",
		Category:  "route_health",
		Severity:  sev,
		Subject:   subject,
		Body:      body,
		Labels:    map[string]string{"upstream": addr, "category": "route_health"},
	}
}

// armReminderLocked (re)schedules the still-down reminder for a route,
// if the route asked for one. Caller holds n.mu.
func (n *Notifier) armReminderLocked(ref routeRef) {
	if ref.notify.ReminderMinutes <= 0 {
		return
	}
	n.stopReminderLocked(ref.routeID)
	d := time.Duration(ref.notify.ReminderMinutes) * time.Minute
	n.reminders[ref.routeID] = n.clk.AfterFunc(d, func() { n.fireReminder(ref) })
}

func (n *Notifier) stopReminderLocked(routeID string) {
	if t := n.reminders[routeID]; t != nil {
		t.Stop()
		delete(n.reminders, routeID)
	}
}

// fireReminder re-sends a down notification while the route is still
// down, then reschedules. If the route recovered in the meantime the
// reminder is gone and this does nothing.
func (n *Notifier) fireReminder(ref routeRef) {
	n.mu.Lock()
	if n.last[ref.routeID] != stateDown {
		n.stopReminderLocked(ref.routeID)
		n.mu.Unlock()
		return
	}
	since := n.downSince[ref.routeID]
	addr := ""
	if len(ref.upstream) > 0 {
		addr = ref.upstream[0]
	}
	// Reschedule before dispatching so the cadence does not drift by the
	// dispatch duration.
	d := time.Duration(ref.notify.ReminderMinutes) * time.Minute
	n.reminders[ref.routeID] = n.clk.AfterFunc(d, func() { n.fireReminder(ref) })
	n.mu.Unlock()

	evt := alerting.AlertEvent{
		ID:        uuid.NewString(),
		Timestamp: n.clk.Now().UTC(),
		RuleName:  "route-health",
		Category:  "route_health",
		Severity:  alerting.SeverityCritical,
		Subject:   fmt.Sprintf("%s still down", ref.host),
		Body:      fmt.Sprintf("%s has been down for %s (upstream %s).", ref.host, humanSince(n.clk.Now(), since), addr),
		Labels:    map[string]string{"upstream": addr, "category": "route_health", "reminder": "1"},
	}
	n.disp.Dispatch(context.Background(), evt, []string{ref.notify.ChannelID})
}

func countedRoutes(n int) string {
	if n == 1 {
		return "1 route"
	}
	return fmt.Sprintf("%d routes", n)
}

func bulletHosts(hosts []string) string {
	var b strings.Builder
	for _, h := range hosts {
		b.WriteString("• " + h + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func bulletRecovered(edges []edge) string {
	lines := make([]string, 0, len(edges))
	for _, e := range edges {
		lines = append(lines, fmt.Sprintf("• %s (down for %s)", e.host, humanSince(e.at, e.downSince)))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// humanSince renders an outage duration in words. Falls back to "an
// unknown time" when the start is missing (a down edge the notifier
// never saw, e.g. a reminder after a restart).
func humanSince(now, since time.Time) string {
	if since.IsZero() || !now.After(since) {
		return "an unknown time"
	}
	return formatDurationHuman(now.Sub(since))
}

// formatDurationHuman renders a duration as a short English phrase
// ("3 days", "2 hours", "45 minutes", "30 seconds"), coarsening to the
// largest whole unit — an outage line wants "down for 2 hours", not a
// stopwatch. Mirrors the intent of caddymgr.formatRetryAfterHuman, which
// is unexported there.
func formatDurationHuman(d time.Duration) string {
	plural := func(n int, unit string) string {
		if n == 1 {
			return fmt.Sprintf("1 %s", unit)
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d >= 24*time.Hour:
		return plural(int(d/(24*time.Hour)), "day")
	case d >= time.Hour:
		return plural(int(d/time.Hour), "hour")
	case d >= time.Minute:
		return plural(int(d/time.Minute), "minute")
	default:
		secs := int(d / time.Second)
		if secs < 1 {
			secs = 1
		}
		return plural(secs, "second")
	}
}
