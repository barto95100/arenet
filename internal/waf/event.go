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
//
// Phase Y (2026-06-18) — refactored from 6 broad categories
// to 25 precise categories matching the upstream CRS file
// structure (OWASP_CRS/4.0.0-rc2, packaged in coraza-
// coreruleset@v0.0.0-20240226094324). Empirical mapping
// verified at audit time : every CRS conf file maps to
// exactly one Arenet category 1:1. Pre-Y mapping was
// over-aggregating (RCE counted PHP+Java+Generic together)
// AND under-counting (LFI missed RFI ; Protocol missed
// method/proto-attack/multipart ; OTHER hid scanner-
// detection / session-fixation / anomaly / data-leak /
// correlation).
//
// Storage migration : NONE (append-only enum policy). Pre-Y
// rows keep their historical category string ("RCE" covering
// 933+934+944, "OTHER" covering 913+943+95x+98x). The 24-h
// rolling-window dashboard flushes the mismatch naturally
// within a day. The historical strings remain valid
// OwaspCategory values for the existing SQLite rows so a
// frontend that doesn't recognise the old name simply
// surfaces them as raw — no crash.
//
// Forward enum members (added Phase Y) :
type OwaspCategory string

const (
	// Pre-Y categories (kept for storage compat) — the
	// CategoryForRule mapping no longer emits the over-
	// aggregating CategoryRCE for 933/934/944 or
	// CategoryLFI for 931 etc. ; new events emit the
	// precise category below. The constants below remain
	// because pre-Y stored rows still reference them as
	// strings.
	CategorySQLi     OwaspCategory = "SQLi"
	CategoryXSS      OwaspCategory = "XSS"
	CategoryRCE      OwaspCategory = "RCE"
	CategoryLFI      OwaspCategory = "LFI"
	CategoryProtocol OwaspCategory = "PROTOCOL"
	CategoryOther    OwaspCategory = "OTHER"

	// Phase Y new categories (one per CRS file). Mapped by
	// CategoryForRule in category.go ; pinned to ranges
	// captured empirically from the coreruleset embedded FS
	// at audit time.
	CategoryInit          OwaspCategory = "INIT"           // 901xxx
	CategoryCommonExcept  OwaspCategory = "COMMON_EXCEPT"  // 905xxx
	CategoryMethod        OwaspCategory = "METHOD"         // 911xxx
	CategoryScanner       OwaspCategory = "SCANNER"        // 913xxx
	CategoryProtocolAttack OwaspCategory = "PROTOCOL_ATK" // 921xxx
	CategoryMultipart     OwaspCategory = "MULTIPART"     // 922xxx
	CategoryRFI           OwaspCategory = "RFI"           // 931xxx
	CategoryPHP           OwaspCategory = "PHP"           // 933xxx
	CategoryGeneric       OwaspCategory = "GENERIC"       // 934xxx
	CategorySession       OwaspCategory = "SESSION"       // 943xxx
	CategoryJava          OwaspCategory = "JAVA"          // 944xxx
	CategoryAnomalyReq    OwaspCategory = "ANOMALY_REQ"   // 949xxx (inbound aggregator)
	CategoryDataLeak      OwaspCategory = "DATA_LEAK"     // 950xxx (generic)
	CategoryDataLeakSQL   OwaspCategory = "DATA_LEAK_SQL" // 951xxx
	CategoryDataLeakJava  OwaspCategory = "DATA_LEAK_JAVA" // 952xxx
	CategoryDataLeakPHP   OwaspCategory = "DATA_LEAK_PHP" // 953xxx
	CategoryDataLeakIIS   OwaspCategory = "DATA_LEAK_IIS" // 954xxx
	CategoryWebShell      OwaspCategory = "WEBSHELL"      // 955xxx
	CategoryAnomalyResp   OwaspCategory = "ANOMALY_RESP"  // 959xxx
	CategoryCorrelation   OwaspCategory = "CORRELATION"   // 980xxx
)

// AllCategories lists the categories in dashboard-display order.
// Used by the frontend type generator and by the category
// distribution strip on the /security dashboard.
//
// Phase Y order : focal request-attack families first (the
// ones the operator cares about most), then aggregators,
// then response-side / data-leak family, then infrastructure
// (init / common-exceptions / scanner). The frontend may
// group these into operator-meaningful families on display
// (cf. /waf page Phase Y refactor).
var AllCategories = []OwaspCategory{
	// Request attacks
	CategorySQLi,
	CategoryXSS,
	CategoryRCE,
	CategoryPHP,
	CategoryJava,
	CategoryGeneric,
	CategoryLFI,
	CategoryRFI,
	// Protocol / behaviour
	CategoryMethod,
	CategoryProtocol,
	CategoryProtocolAttack,
	CategoryMultipart,
	CategoryScanner,
	CategorySession,
	// Aggregators
	CategoryAnomalyReq,
	CategoryAnomalyResp,
	CategoryCorrelation,
	// Response-side / data leak
	CategoryDataLeak,
	CategoryDataLeakSQL,
	CategoryDataLeakJava,
	CategoryDataLeakPHP,
	CategoryDataLeakIIS,
	CategoryWebShell,
	// Infrastructure / catch-all
	CategoryInit,
	CategoryCommonExcept,
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
