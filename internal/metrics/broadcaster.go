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

package metrics

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Broadcaster fans out per-tick Snapshots to every subscribed WebSocket
// client (spec §4.2). Subscribe / Unsubscribe are O(1); Publish is
// O(N_subscribers) under the broadcaster lock. The lock is never
// nested with the Registry's lock (spec §4.4).
//
// Backpressure (spec §5.6): each subscriber's channel has capacity
// SubscriberChanCap (1). A non-blocking select skips slow subscribers
// — their tick is dropped with a debug-level log, rate-limited to one
// line per DropLogInterval (1 min) per subscriber.
type Broadcaster struct {
	logger *slog.Logger

	mu   sync.Mutex
	subs map[*Subscriber]struct{}
}

// Subscriber identifies one WebSocket client's subscription. Returned
// by Subscribe; passed to Unsubscribe. Callers receive Snapshots by
// reading from Ch.
//
// lastDropLogAt is updated only under broadcaster.mu, so no separate
// synchronization is needed for it.
type Subscriber struct {
	Ch chan Snapshot

	lastDropLogAt time.Time
}

// NewBroadcaster constructs an empty broadcaster. The logger is used
// only for the rate-limited backpressure debug log; pass slog.Default()
// or any other configured logger.
func NewBroadcaster(logger *slog.Logger) *Broadcaster {
	if logger == nil {
		logger = slog.Default()
	}
	return &Broadcaster{
		logger: logger,
		subs:   make(map[*Subscriber]struct{}),
	}
}

// Subscribe registers a new subscriber and returns its handle. The
// subscriber's Ch is a buffered channel of capacity SubscriberChanCap;
// readers should drain it in a loop.
//
// Safe to call from any goroutine.
func (b *Broadcaster) Subscribe() *Subscriber {
	s := &Subscriber{
		Ch: make(chan Snapshot, SubscriberChanCap),
	}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

// Unsubscribe removes s from the broadcaster and closes its channel.
// Idempotent: calling Unsubscribe twice with the same Subscriber is
// safe (the second call is a no-op rather than a double-close panic).
//
// Safe to call from any goroutine.
func (b *Broadcaster) Unsubscribe(s *Subscriber) {
	if s == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subs[s]; !ok {
		return // already unsubscribed; double-close-safe
	}
	delete(b.subs, s)
	close(s.Ch)
}

// Publish sends snap to every subscriber via a non-blocking select.
// Subscribers whose channel is full (capacity 1, previous tick not yet
// drained) miss this tick; a debug log is emitted at most once per
// DropLogInterval per subscriber.
//
// Returns the number of subscribers that received the snapshot, and
// the number that dropped it. Useful for tests and metrics.
//
// Safe to call from any goroutine; typically invoked by Ticker at 1 Hz.
func (b *Broadcaster) Publish(snap Snapshot) (sent, dropped int) {
	now := time.Now()

	b.mu.Lock()
	defer b.mu.Unlock()

	for s := range b.subs {
		select {
		case s.Ch <- snap:
			sent++
		default:
			dropped++
			if now.Sub(s.lastDropLogAt) >= DropLogInterval {
				// Debug-only and rate-limited per §5.6. We log the
				// subscriber pointer as a stable identifier; nothing
				// from the snapshot payload is logged (no PII risk).
				b.logger.Debug("metrics: broadcaster dropped tick (slow subscriber)",
					slog.String("subscriber", subscriberIDString(s)),
				)
				s.lastDropLogAt = now
			}
		}
	}
	return sent, dropped
}

// SubscriberCount returns the current number of active subscribers.
// Useful for tests and for a future /metrics endpoint.
func (b *Broadcaster) SubscriberCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

// subscriberIDString produces a stable string identifier for a
// Subscriber pointer suitable for log correlation. The format is
// implementation-defined; do not parse. Cold path (rate-limited
// debug log only), so the fmt.Sprintf allocation is acceptable.
func subscriberIDString(s *Subscriber) string {
	return fmt.Sprintf("%p", s)
}
