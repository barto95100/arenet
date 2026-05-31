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
	"context"
	"time"
)

// SourceEvent is the normalised shape the trigger engine
// works with regardless of origin (WAF / throttle / audit).
// The three concrete readers (WafEventReader,
// ThrottleEventReader, AuditEventReader) project their own
// types into this shape so the engine's group-by /
// threshold loop stays homogeneous.
type SourceEvent struct {
	// ID is a string-encoded primary key from the source
	// store. Stable enough to use as the cursor for next-
	// tick incremental reads. WAF / throttle: the int64
	// auto-increment as string; audit: the v7 UUID.
	ID string

	// Ts is the event timestamp.
	Ts time.Time

	// SrcIP is the actor IP. For audit events this is
	// audit.Event.IP. For WAF / throttle events the
	// observability-layer src_ip. The cross-cutting
	// discrepancy with trusted-proxy resolution is
	// pre-existing (Q.5-2 backlog) and is NOT P's surface
	// to fix — P consumes the SrcIP as the source stores it.
	SrcIP string

	// Source is the trigger-engine category this event
	// counts toward. Computed by the per-reader adapter
	// from the underlying event's category / tier / action.
	Source Source

	// TriggeringEventID is the same as ID — kept as a
	// separate field so the audit row for an auto-classify
	// push can name the originating event explicitly even
	// when the engine has aggregated several events into
	// one decision.
	TriggeringEventID string
}

// WafEventReader is the read surface the trigger engine uses
// for WAF events. *observability.Store satisfies this via
// QueryWafEvents. Defined as an interface so tests inject
// fakes without booting SQLite.
//
// QueryWafEvents already takes a filter with From / To /
// Limit / RouteID / Category. The trigger engine reads with
// From = last-seen cursor and To = now; doesn't filter by
// category here (the engine groups events by Source after
// the query so a single read pass serves multiple rules).
type WafEventReader interface {
	QueryWafEvents(ctx context.Context, filter wafFilter) ([]SourceEvent, error)
}

// ThrottleEventReader is the throttle-side mirror.
type ThrottleEventReader interface {
	QueryThrottleEvents(ctx context.Context, filter throttleFilter) ([]SourceEvent, error)
}

// AuditEventReader is the audit-side mirror.
type AuditEventReader interface {
	QueryAuthFailureEvents(ctx context.Context, from, to time.Time, limit int) ([]SourceEvent, error)
}

// wafFilter / throttleFilter are tiny per-source filter
// shapes that match the observability-store filters at the
// fields the engine actually needs. Defined here (not in
// observability) so the engine stays independent of the
// observability package's wider filter surface (and so the
// fakes in tests don't need to import observability).
type wafFilter struct {
	From  time.Time
	To    time.Time
	Limit int
}

type throttleFilter struct {
	From  time.Time
	To    time.Time
	Limit int
}

// queryLimit caps each per-source read per tick. A homelab
// burst rarely exceeds this; the cap is a defence against
// pathological-attack-volume queries pinning the DB.
const queryLimit = 1000

// sourceFromWafCategory maps the observability-layer category
// string (M.1 OWASP enum) to the trigger-engine Source. Any
// unknown category falls through to SourceWafOther so a
// future M extension that adds a new category doesn't drop
// events silently.
func sourceFromWafCategory(cat string) Source {
	switch cat {
	case "SQLi":
		return SourceWafSQLi
	case "XSS":
		return SourceWafXSS
	case "RCE":
		return SourceWafRCE
	case "LFI":
		return SourceWafLFI
	case "PROTOCOL":
		return SourceWafProtocol
	default:
		return SourceWafOther
	}
}

// sourceFromThrottleTier maps the throttle Tier int (1 / 2)
// to the trigger-engine Source. Any other value lands in
// SourceThrottleTier1 (defensive — the upstream type only
// emits 1 or 2 per Q's enum).
func sourceFromThrottleTier(tier int) Source {
	switch tier {
	case 2:
		return SourceThrottleTier2
	default:
		return SourceThrottleTier1
	}
}
