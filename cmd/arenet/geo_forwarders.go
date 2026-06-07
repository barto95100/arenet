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

package main

import (
	"github.com/barto95100/arenet/internal/crowdsec"
	"github.com/barto95100/arenet/internal/geo"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/throttle"
	"github.com/barto95100/arenet/internal/waf"
)

// Step V.3 — geo-forwarding sink wrappers.
//
// Each EventSink in the four security-event packages (waf,
// throttle, crowdsec) and the observability AuthSink seam
// (V.2's AuthEventSubmitter) gets wrapped by a thin
// forwarder that publishes the enriched GeoEvent to the V.3
// bus AND delegates to the underlying production sink. This
// keeps the cross-cutting fan-out concern entirely inside
// cmd/arenet — the four sink packages remain unaware of
// geo-enrichment, V.4's admin endpoints stay decoupled from
// the security packages, and adding a fifth sink in the
// future only needs a fifth ~10-line wrapper here.
//
// All wrappers are nil-safe on bus / enricher: if either is
// missing (V.1 degraded mode, V.2 still wiring up, future
// boot-failed observability), the wrapper falls through to
// the underlying sink. The data plane is unaffected.
//
// Trade-off considered: a single generic forwarder using
// `any` + a type switch was prototyped, but each sink's
// Emit/Submit signature differs (Emit(waf.Event) vs
// Emit(crowdsec.Decision) vs Emit(throttle.Event) vs
// Submit(observability.AuthEvent)), so four small typed
// wrappers + zero reflection wins on readability.

// geoForwardingWafSink wraps a waf.EventSink. The Caddy WAF
// module reads waf.GetGlobalSink() and calls Emit — installing
// this wrapper via waf.SetGlobalSink fans every event to both
// the bus (via enricher) and the real sink (persistence +
// counter bump). Satisfies waf.EventSink via the structural
// `Emit(waf.Event)` method.
type geoForwardingWafSink struct {
	bus      *geo.Bus
	enricher *geo.Enricher
	inner    waf.EventSink
}

func (g geoForwardingWafSink) Emit(e waf.Event) {
	if g.bus != nil && g.enricher != nil {
		g.bus.Publish(g.enricher.EnrichWAFEvent(e))
	}
	if g.inner != nil {
		g.inner.Emit(e)
	}
}

// geoForwardingThrottleSink wraps a throttle.EventSink.
// internal/auth reads throttle.GetGlobalSink() at rate-limit
// trigger; same wrapper pattern as the WAF variant. Satisfies
// throttle.EventSink via `Emit(throttle.Event)`.
type geoForwardingThrottleSink struct {
	bus      *geo.Bus
	enricher *geo.Enricher
	inner    throttle.EventSink
}

func (g geoForwardingThrottleSink) Emit(e throttle.Event) {
	if g.bus != nil && g.enricher != nil {
		// The enricher consumes the observability.ThrottleEvent
		// shape (the storage-flat sibling of throttle.Event);
		// the field shapes are nearly identical. Translate
		// the values that the enricher cares about (Ts +
		// SrcIP + AttemptedUsername) and leave the rest
		// zero — the enricher only reads those three fields.
		g.bus.Publish(g.enricher.EnrichThrottleEvent(observability.ThrottleEvent{
			Ts:                e.Ts,
			SrcIP:             e.SrcIP,
			AttemptedUsername: e.AttemptedUsername,
		}))
	}
	if g.inner != nil {
		g.inner.Emit(e)
	}
}

// geoForwardingCrowdsecSink wraps a crowdsec.EventSink. The
// StreamBouncer consumer calls Emit on every new decision;
// this wrapper fans to the bus before delegating. Satisfies
// crowdsec.EventSink via `Emit(crowdsec.Decision)`.
//
// Note: the enricher's EnrichCrowdsecDecision takes an
// observability.DecisionEvent (the storage-flat sibling).
// We translate the fields the enricher reads (Ts + Scope +
// Value + Scenario) and leave the rest zero.
type geoForwardingCrowdsecSink struct {
	bus      *geo.Bus
	enricher *geo.Enricher
	inner    crowdsec.EventSink
}

func (g geoForwardingCrowdsecSink) Emit(d crowdsec.Decision) {
	if g.bus != nil && g.enricher != nil {
		g.bus.Publish(g.enricher.EnrichCrowdsecDecision(observability.DecisionEvent{
			Ts:       d.Ts,
			Scope:    d.Scope,
			Value:    d.Value,
			Type:     d.Type,
			Scenario: d.Scenario,
		}))
	}
	if g.inner != nil {
		g.inner.Emit(d)
	}
}

// Tombstone delegates to the inner sink. Revocations are
// not surfaced on the geo map: the visual contract is
// "incoming threats arriving at Arenet", and a tombstone
// reverses a prior decision rather than adding a new event.
// The inner sink uses the tombstone to expire its LRU entry
// so a future re-grant of the same IP re-publishes
// downstream.
func (g geoForwardingCrowdsecSink) Tombstone(uuid string) {
	if g.inner != nil {
		g.inner.Tombstone(uuid)
	}
}

// geoForwardingAuthSink wraps the observability.AuthEventSink
// behind the api.AuthEventSubmitter interface (the V.2 seam
// audit_helpers.appendAudit fans into). On every Submit it
// publishes the enriched event to the bus then delegates to
// the real sink for the spec §3.6 persistence path. Satisfies
// api.AuthEventSubmitter via `Submit(observability.AuthEvent)`.
type geoForwardingAuthSink struct {
	bus      *geo.Bus
	enricher *geo.Enricher
	inner    *observability.AuthEventSink
}

func (g geoForwardingAuthSink) Submit(e observability.AuthEvent) {
	if g.bus != nil && g.enricher != nil {
		g.bus.Publish(g.enricher.EnrichAuthEvent(e))
	}
	if g.inner != nil {
		g.inner.Submit(e)
	}
}

// serverPositionRedetector satisfies api.ServerPositionRedetector
// for V.4's POST :redetect endpoint. Captures the boot-time
// *geo.Lookup so the handler can re-run V.1's
// DetectFromPublicIP path without taking a hard dependency
// on internal/geo at the api package boundary. The lookup
// pointer may be nil (degraded GeoIP mode); the underlying
// DetectFromPublicIP returns an error in that case and the
// handler renders the degraded shape.
type serverPositionRedetector struct {
	lookup *geo.Lookup
}

func (r serverPositionRedetector) Redetect() (*geo.ServerPosition, error) {
	return geo.DetectFromPublicIP(r.lookup)
}
