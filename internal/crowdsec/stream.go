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

package crowdsec

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// StreamDelta is the producer's view of one LAPI poll cycle's
// payload: a slice of NEW decisions appearing since the
// previous poll + a slice of UUIDs that were REVOKED or
// EXPIRED since the previous poll.
//
// Mirror of the LAPI `/v1/decisions/stream` response shape
// (per N spec research §1.1 from agent #2: handler returns
// `{"new":[...], "deleted":[...]}`, default scope filter is
// `ip,range`, the 2-second-overlap protocol detail is the
// LAPI's own concern). The actual transport (apiclient
// streaming bouncer goroutine vs a test harness) sits outside
// this package — see Source below.
type StreamDelta struct {
	New     []Decision
	Deleted []string // UUIDs to tombstone
}

// Source is the abstraction the Consumer reads its deltas
// from. Production wiring (cmd/arenet/main.go) wraps the
// crowdsec/pkg/apiclient StreamingBouncer; tests inject a
// stub that pushes canned deltas onto Out.
//
// Lifecycle: Start launches the streaming goroutine; Stop
// halts it cleanly. Out is the channel deltas land on (one
// per poll cycle). The Consumer reads Out + dispatches
// {new, deleted} to the Sink.
type Source interface {
	// Start kicks off the source's polling loop (or
	// equivalent). MUST be safe to call exactly once;
	// subsequent calls are undefined.
	Start(ctx context.Context) error
	// Out returns the channel on which deltas arrive.
	// Closed by the source when its goroutine exits.
	Out() <-chan StreamDelta
}

// Consumer drives the bridge from a Source to the global
// Sink: drains the Source.Out() channel, dispatches new[] to
// Sink.Emit and deleted[] to Sink.Tombstone, swallows panics
// at the goroutine boundary (AC #13).
//
// Defined as its own type (vs a free function) so the
// consumer state — a panic counter, a started flag — is
// explicit and observable.
type Consumer struct {
	source Source
	sink   EventSink
	logger *slog.Logger

	totalDeltas      atomic.Uint64
	totalEmits       atomic.Uint64
	totalTombstones  atomic.Uint64
	totalPanicRecovs atomic.Uint64

	done chan struct{}
}

// NewConsumer builds a consumer bridging the given source to
// the given sink. sink may be nil (degraded mode — Run drains
// the source channel but does not dispatch). logger may be
// nil (slog.Default fallback).
func NewConsumer(source Source, sink EventSink, logger *slog.Logger) *Consumer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Consumer{
		source: source,
		sink:   sink,
		logger: logger,
		done:   make(chan struct{}),
	}
}

// Run drives the consumer until ctx is cancelled OR the
// source's Out channel is closed. AC #13: any panic inside
// the dispatch loop is recovered + logged; the goroutine
// exits cleanly without bringing down the data plane.
//
// Calls source.Start(ctx) once at entry, so the source's
// polling goroutine spawns lazily — the Consumer's lifecycle
// owns the Source's.
func (c *Consumer) Run(ctx context.Context) {
	defer close(c.done)
	defer func() {
		if r := recover(); r != nil {
			c.totalPanicRecovs.Add(1)
			c.logger.Error("crowdsec: stream consumer panic; LAPI mirror disabled for the rest of this process",
				slog.Any("panic", r),
			)
		}
	}()

	if err := c.source.Start(ctx); err != nil {
		// Start failures are returned by the source itself
		// (e.g. invalid config). Logged + Run exits. AC #13
		// degraded path: the bouncer-side enforcement
		// continues; Arenet's mirror surface is just empty.
		c.logger.Error("crowdsec: stream source start failed; mirror disabled",
			slog.String("err", err.Error()),
		)
		return
	}

	out := c.source.Out()
	for {
		select {
		case <-ctx.Done():
			return
		case delta, ok := <-out:
			if !ok {
				c.logger.Info("crowdsec: stream source channel closed; consumer exiting")
				return
			}
			c.totalDeltas.Add(1)
			c.dispatch(delta)
		}
	}
}

// dispatch fans one delta out to the Sink. nil-tolerant on
// the sink (degraded mode at boot before SetGlobalSink).
func (c *Consumer) dispatch(delta StreamDelta) {
	if c.sink == nil {
		return
	}
	for _, d := range delta.New {
		c.sink.Emit(d)
		c.totalEmits.Add(1)
	}
	for _, uuid := range delta.Deleted {
		c.sink.Tombstone(uuid)
		c.totalTombstones.Add(1)
	}
}

// Done returns a channel closed once Run has exited.
func (c *Consumer) Done() <-chan struct{} {
	return c.done
}

// TotalDeltas returns the number of {new, deleted} payloads
// the consumer has absorbed since start.
func (c *Consumer) TotalDeltas() uint64 {
	return c.totalDeltas.Load()
}

// TotalEmits returns the number of New decisions the consumer
// has forwarded to Sink.Emit since start.
func (c *Consumer) TotalEmits() uint64 {
	return c.totalEmits.Load()
}

// TotalTombstones returns the number of Deleted UUIDs the
// consumer has forwarded to Sink.Tombstone since start.
func (c *Consumer) TotalTombstones() uint64 {
	return c.totalTombstones.Load()
}

// TotalPanicRecovs returns the number of times the consumer's
// recover() caught a panic in the dispatch loop. Should be 0
// in healthy operation; a non-zero value is an SLO violation
// the operator should investigate.
func (c *Consumer) TotalPanicRecovs() uint64 {
	return c.totalPanicRecovs.Load()
}

// --- helpers exposed for use by main.go wiring ------------------------------

// SleepInterval is the bouncer's recommended LAPI poll
// cadence. Step N spec D7.A (60s) matches the caddy-crowdsec-
// bouncer default. Exposed for the cmd/arenet/main.go wiring
// to pass to the StreamingBouncer constructor without
// hard-coding the literal at the call site (drift guard).
const SleepInterval = 60 * time.Second
