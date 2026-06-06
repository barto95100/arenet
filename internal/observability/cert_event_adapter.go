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

// CertEventAdapter — Step U.2 spec §4 (component 7). Translates
// the certinfo.Tracker's Subscribe-seam events (T.1 AC #18) into
// observability.CertEvent rows and forwards them to the
// CertEventSink for persistence to the cert_event table.
//
// Layering decision (deviation from the U.2 brief): the brief
// proposed internal/caddymgr/cert_event_adapter.go, but caddymgr
// has no other reason to import observability — it's the
// Caddy-config translator, not an event consumer. The adapter
// belongs next to the sink it submits to: observability already
// owns CertEvent + CertEventSink, and the only new import this
// file adds is internal/certinfo (for the Event type). The
// one-way dependency creates no cycle (certinfo does not import
// observability) and keeps the caddymgr package purely focused
// on Caddy JSON emission.
//
// The adapter is a thin certinfo.EventHandler. cmd/arenet
// constructs it after the sink is started and registers it via
// tracker.Subscribe() — the unsubscribe closure runs on
// shutdown before the sink Stop so the tracker stops sending
// into a closed-soon channel.

package observability

import (
	"github.com/barto95100/arenet/internal/certinfo"
)

// CertEventSubmitter is the persistence surface the adapter
// depends on. *CertEventSink satisfies it via Submit. Decoupled
// as an interface so unit tests can record submissions without
// spinning up a real channel + batcher.
type CertEventSubmitter interface {
	Submit(CertEvent)
}

// CertEventAdapter implements certinfo.EventHandler. Subscribed
// to the certinfo.Tracker via the AC #18 forward-compat seam,
// it filters out the event kinds spec §3 said NOT to persist
// and translates the rest into observability.CertEvent before
// submitting to the sink.
//
// Filter policy (spec §3.3, §3.5, §3.8 — all LOCKED):
//
//   - EventCertObtaining → DROP (§3.3: redundant with obtained/
//     failed which capture outcomes; certmagic's retry would
//     otherwise generate dozens of rows per failed domain).
//   - EventCertRemoved → DROP (§3.8: the audit log's
//     ActionManagedDomainDeleted is the canonical record of the
//     operator action; double-recording would mix
//     system-emitted events with operator-driven actions).
//   - cached_managed_cert / cached_unmanaged_cert → already
//     filtered upstream by the caddymgr subscription's events
//     array (T.1 + U.2 don't subscribe to these). Defensive
//     drop here too for the same reason as Obtaining: noise
//     with no operator-visible value.
//
// Translated kinds:
//
//   - EventCertObtained → CertEvent{Level: INFO, Type: Obtained,
//     Renewal: <from Event.IsRenewal>, Issuer, Domain}.
//   - EventCertFailed → CertEvent{Level: ERROR, Type: Failed,
//     Error, Domain}.
//   - EventCertOCSPRevoked → CertEvent{Level: ERROR, Type:
//     OcspRevoked, Domain}.
//
// Submit is non-blocking per the U.1 sink contract; the adapter
// itself adds no buffering or async hop (the certinfo.Tracker's
// fan-out is already synchronous + panic-recovered, so wrapping
// would just dilute the dispatch guarantees).
type CertEventAdapter struct {
	sink CertEventSubmitter
}

// NewCertEventAdapter constructs an adapter bound to a sink.
// A nil sink panics fast — this is a wiring bug, not a runtime
// condition; AC #13 degraded mode is handled at the sink layer
// (the sink with a nil inserter still accepts Submit calls and
// drains them into the void with a debug log).
func NewCertEventAdapter(sink CertEventSubmitter) *CertEventAdapter {
	if sink == nil {
		panic("observability.NewCertEventAdapter: sink is nil")
	}
	return &CertEventAdapter{sink: sink}
}

// HandleCertEvent satisfies certinfo.EventHandler. Runs
// synchronously on the tracker writer goroutine — must NOT
// block. Submit is the only call here and it is non-blocking
// per the U.1 contract.
func (a *CertEventAdapter) HandleCertEvent(e certinfo.Event) {
	ce, ok := translateCertinfoEvent(e)
	if !ok {
		return
	}
	a.sink.Submit(ce)
}

// translateCertinfoEvent maps a certinfo.Event to a CertEvent,
// returning (zero, false) for kinds that spec §3 said to drop.
// Pure function — no I/O, no clock reads (the Event.At carries
// the timestamp) — fully unit-testable.
func translateCertinfoEvent(e certinfo.Event) (CertEvent, bool) {
	switch e.Kind {
	case certinfo.EventCertObtained:
		return CertEvent{
			Ts:      e.At,
			Level:   CertEventLevelInfo,
			Type:    CertEventTypeObtained,
			Domain:  e.Domain,
			Issuer:  e.Issuer,
			Renewal: e.IsRenewal,
			// Challenge stays empty — the backend doesn't know
			// the challenge per cert (Step T discovery doc §3.4
			// open question, deferred to a future step). The
			// frontend's certificate-format.ts heuristic
			// (DNS-01 for wildcards, HTTP-01 default) handles
			// the Activity log render.
		}, true

	case certinfo.EventCertFailed:
		return CertEvent{
			Ts:     e.At,
			Level:  CertEventLevelError,
			Type:   CertEventTypeFailed,
			Domain: e.Domain,
			Error:  e.Error,
		}, true

	case certinfo.EventCertOCSPRevoked:
		return CertEvent{
			Ts:     e.At,
			Level:  CertEventLevelError,
			Type:   CertEventTypeOCSPRevoked,
			Domain: e.Domain,
		}, true

	case certinfo.EventCertObtaining,
		certinfo.EventCertRemoved:
		// Dropped per spec §3.3 (Obtaining is retry noise) and
		// §3.8 (Removed is double-recorded with the audit
		// log). Both still fire on the Subscribe seam for any
		// future real-time consumer that wants them; the sink
		// just doesn't see them.
		return CertEvent{}, false

	default:
		// Unknown EventKind — defensive drop. A future
		// EventKind addition (e.g. cert_renewed if certmagic
		// ever ships one) would need a translate case added
		// here AND a CertEventType added in cert_event.go;
		// dropping is the right default until both land.
		return CertEvent{}, false
	}
}
