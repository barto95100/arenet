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

// Package waf implements the Step M security dashboard's WAF
// event capture layer. The custom Caddy module `arenet_waf`
// wraps coraza/v3 directly to expose per-block events
// (rule_id, OWASP category, severity, src_ip, payload sample)
// the way the dashboard mocks require — coraza-caddy/v2
// exposes no match hook, so the only viable path is to consume
// coraza/v3 ourselves.
//
// See docs/superpowers/specs/2026-05-28-step-m-security.md §3.2
// for the design rationale and §1.6 for the threat-model
// deltas (payload caps, redaction, src_ip exposure, LRU
// rate-limit on event emission).
package waf

import "time"

// MaxRequestPathBytes is the cap applied to the request_path
// field before storage. Mocks need enough room to make the
// attack shape readable; 512 is generous for an attack URL
// and bounds storage growth. See spec §1.6.1.
const MaxRequestPathBytes = 512

// MaxPayloadSampleBytes is the cap applied to the payload
// sample. 256 is enough to see the attack payload's shape
// without retaining unbounded request bodies. See spec §1.6.1.
const MaxPayloadSampleBytes = 256

// OwaspCategory is the rolled-up classification surfaced on
// the dashboard. Each CRS rule maps to exactly one category
// via CategoryForRule (see category.go).
//
// The values are stored verbatim in the SQLite waf_event
// table; changing a value name is a backward-incompatible
// schema migration (existing rows would point at the old
// name). New categories are append-only.
type OwaspCategory string

const (
	CategorySQLi     OwaspCategory = "SQLi"
	CategoryXSS      OwaspCategory = "XSS"
	CategoryRCE      OwaspCategory = "RCE"
	CategoryLFI      OwaspCategory = "LFI"
	CategoryProtocol OwaspCategory = "PROTOCOL"
	CategoryOther    OwaspCategory = "OTHER"
)

// AllCategories lists the categories in dashboard-display order.
// Used by the frontend type generator and by the category
// distribution strip on the /security dashboard.
var AllCategories = []OwaspCategory{
	CategorySQLi,
	CategoryXSS,
	CategoryRCE,
	CategoryLFI,
	CategoryProtocol,
	CategoryOther,
}

// Event is one WAF rule-match event. Persisted into the
// waf_event table by the EventSink; surfaced to the operator
// via /api/v1/security/events. Path and PayloadSample have
// been capped + redacted by the time the event reaches Emit
// (see Truncate + redact.go).
//
// SrcIP is captured verbatim from the request's effective
// remote address (after the trusted-proxy chain resolution
// shared with the audit log). Spec §1.6.3 documents the
// exposure trade-off.
type Event struct {
	// ID is set by the storage layer on insert; zero on
	// freshly-built events.
	ID int64

	Ts            time.Time
	RouteID       string
	RuleID        string
	Category      OwaspCategory
	Severity      int
	SrcIP         string
	RequestMethod string
	RequestPath   string
	PayloadSample string

	// Action records what the WAF actually did with the
	// matched request. ActionBlock means the request was
	// short-circuited at the handler with the StatusCode
	// below; ActionDetect means the rule fired but the
	// request was allowed to reach the upstream (the route
	// is in detect mode — spec §1.4). Pre-W.bugfix rows
	// decode as "" (zero value); the storage migration
	// backfills to ActionBlock since that was the implicit
	// universal value when the field didn't exist.
	Action string

	// StatusCode is the HTTP status the handler returned
	// when Action == ActionBlock (always 403 today; spec
	// §1.4 may extend with operator-configurable status in
	// a future step). 0 when Action == ActionDetect — the
	// request passed to the upstream and the actual response
	// status is not visible at WAF callback time. Frontend
	// renders "—" for the zero value.
	StatusCode int
}

// Action enum (W.bugfix Fix #1 — mode-aware labels).
//
// Stored as a string in waf_event.action; the frontend keys
// off these exact values to colour the row level (block vs
// detect). Adding a new action MUST be backwards-compatible:
// existing values cannot be renamed.
const (
	// ActionBlock — the WAF interrupted the request with the
	// configured StatusCode. Set when handler.Mode == "block".
	ActionBlock = "BLOCK"

	// ActionDetect — the WAF logged the match but allowed the
	// request to reach the upstream. Set when handler.Mode
	// == "detect". The dashboard renders these distinctly so
	// operators see at a glance whether enforcement fired.
	ActionDetect = "DETECT"
)

// Truncate caps the byte length of s to maxBytes and appends
// an ellipsis when it had to cut. Returns s unchanged when
// already within the cap. UTF-8-safe: when the cut would land
// inside a multi-byte rune, the cap moves back to the previous
// rune boundary so the result is always valid UTF-8.
//
// Used at event-construction time on RequestPath +
// PayloadSample per the caps declared above. Pure function —
// no allocation when s is short enough.
func Truncate(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	// Move back from maxBytes to a rune boundary. A UTF-8
	// continuation byte has its top two bits set to 10
	// (0b10xxxxxx); the start byte of a rune has top bit 0
	// or top three bits 110/1110/11110. We back up until we
	// land on a start byte.
	cut := maxBytes
	for cut > 0 && isUTF8ContinuationByte(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// isUTF8ContinuationByte returns true when b is a 0b10xxxxxx
// continuation byte. Inlined for the Truncate hot path.
func isUTF8ContinuationByte(b byte) bool {
	return b&0xC0 == 0x80
}
