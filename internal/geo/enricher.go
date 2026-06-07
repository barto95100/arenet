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

package geo

import (
	"net"
	"time"

	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/waf"
)

// GeoEvent is the wire shape spec §5.6 locks for the V.3 geo
// bus, the WebSocket /api/v1/ws/geo-events broadcast, and
// the GET /api/v1/observability/geo-events replay endpoint.
//
// Category is restricted to the 5-value enum spec §5.6 names:
// "normal" / "throttle" / "waf" / "crowdsec" / "auth". Cert
// events are explicitly NOT included — see the file-level
// note on EnrichCertEvent's absence below.
//
// SourceLat / SourceLon are 0 when the GeoIP lookup is
// degraded (no MMDB) or the source is a LAN address (§3.8
// renders LAN sources at the Arenet position with an
// `(LAN)` label rather than at the dropped coordinates).
// SourceCountry is "UNK" in the degraded case to match the
// spec §5.6 field note.
//
// StatusCode + RouteID + Details are optional per spec §5.6;
// the frontend tooltip surfaces them when populated.
type GeoEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	Category      string    `json:"category"`
	SourceIP      string    `json:"sourceIp"`
	SourceLat     float64   `json:"sourceLat"`
	SourceLon     float64   `json:"sourceLon"`
	SourceCountry string    `json:"sourceCountry"`
	SourceCity    string    `json:"sourceCity"`
	IsLAN         bool      `json:"isLan"`
	StatusCode    int       `json:"statusCode,omitempty"`
	RouteID       string    `json:"routeId,omitempty"`
	Details       string    `json:"details"`
}

// Category constants — single point of truth for the spec
// §5.6 enum. Anywhere a literal would otherwise appear (the
// enricher methods below, V.3 ring buffer + WebSocket
// broadcaster, frontend type union), reference these instead
// so the enum can only widen through an explicit code change.
const (
	CategoryNormal   = "normal"
	CategoryThrottle = "throttle"
	CategoryWAF      = "waf"
	CategoryCrowdSec = "crowdsec"
	CategoryAuth     = "auth"
)

// countryUnknown is the spec §5.6 sentinel for "geoip
// lookup degraded or returned no result". The frontend
// renders this with the "UNK" label badge.
const countryUnknown = "UNK"

// detailsMaxBytes caps the Details field at a defensive
// length so a malformed upstream event (e.g. a rule with a
// pathological category string) can't bloat the wire frame.
// Mirrors the waf.Truncate cap on PayloadSample.
const detailsMaxBytes = 256

// Enricher converts existing per-source event types into the
// common GeoEvent shape consumed by V.3's bus + WebSocket.
// One enricher per process; safe for concurrent use because
// the underlying *Lookup is goroutine-safe and the enricher
// itself holds no mutable state.
//
// A nil-Lookup enricher is the AC #13 degraded-mode case:
// every enrichment falls back to the "UNK" sentinel + 0,0
// coordinates rather than panicking. V.4 will surface this
// state on the frontend as the "GeoIP not configured" banner.
type Enricher struct {
	lookup *Lookup
}

// NewEnricher constructs an Enricher around the V.1 Lookup.
// A nil lookup is supported and ships the degraded-mode
// behavior described on the type.
func NewEnricher(lookup *Lookup) *Enricher {
	return &Enricher{lookup: lookup}
}

// HasLookup reports whether the enricher has a non-nil
// GeoIP Lookup. cmd/arenet logs this at boot per the HF4
// pattern so a missing MMDB is immediately visible.
func (e *Enricher) HasLookup() bool {
	return e != nil && e.lookup != nil
}

// EnrichWAFEvent maps a waf.Event to the common GeoEvent
// shape. Category is fixed to "waf". The WAF rule ID lands
// in Details (rule_id is the operator-relevant identifier
// for tooltip drill-down per spec §5.6). HTTP status code
// is fixed at 403 since the WAF block path is the only WAF
// emission today.
func (e *Enricher) EnrichWAFEvent(ev waf.Event) GeoEvent {
	out := e.enrichBase(ev.SrcIP, ev.Ts, CategoryWAF)
	out.RouteID = ev.RouteID
	out.Details = truncateDetails(ev.RuleID)
	out.StatusCode = 403
	return out
}

// EnrichThrottleEvent maps an observability.ThrottleEvent to
// GeoEvent. Category fixed to "throttle"; status code 429.
// AttemptedUsername lands in Details so the tooltip surfaces
// "who was the auth path trying when the rate-limit kicked".
func (e *Enricher) EnrichThrottleEvent(ev observability.ThrottleEvent) GeoEvent {
	out := e.enrichBase(ev.SrcIP, ev.Ts, CategoryThrottle)
	out.Details = truncateDetails(ev.AttemptedUsername)
	out.StatusCode = 429
	return out
}

// EnrichCrowdsecDecision maps an observability.DecisionEvent
// to GeoEvent. Category fixed to "crowdsec"; status code 403.
//
// CrowdSec decisions are NOT all IP-scoped: the Scope field
// can be "ip" / "range" / "country" / "as". Only Scope=="ip"
// yields a valid SourceIP for geo enrichment. For range /
// country / as scopes the enricher returns an "UNK"-country
// event with the Scope+Value pair in Details so the
// downstream consumer can still render something meaningful
// (the frontend may choose to suppress non-ip-scoped events
// from the map; V.3 decides). This contract matches spec
// §5.6 where SourceLat/Lon=0 is the "no geo" sentinel.
//
// The scenario name (e.g. "crowdsecurity/http-probing")
// lands in Details prefixed for tooltip context.
func (e *Enricher) EnrichCrowdsecDecision(ev observability.DecisionEvent) GeoEvent {
	srcIP := ""
	if ev.Scope == "ip" {
		srcIP = ev.Value
	}
	out := e.enrichBase(srcIP, ev.Ts, CategoryCrowdSec)

	details := ev.Scenario
	if ev.Scope != "ip" && ev.Value != "" {
		details = ev.Scope + ":" + ev.Value + " " + ev.Scenario
	}
	out.Details = truncateDetails(details)
	out.StatusCode = 403
	return out
}

// EnrichAuthEvent maps an observability.AuthEvent to GeoEvent.
// Category fixed to "auth". Status code derives from the
// AuthEventKind: 403 for AuthEventKindForbidden, 401 for
// every other kind (login failure, session expired, OIDC
// callback rejected) — matches the auth middleware's actual
// emission pattern at internal/auth/middleware.go:196 / :205.
//
// Kind + Username are concatenated into Details so the
// frontend tooltip surfaces both signals (e.g. "login_failure
// admin"). The Path field stays implicit in the AuthEvent
// row (audit log carries it canonically); the wire frame
// stays tight per the spec §5.6 minimal shape.
func (e *Enricher) EnrichAuthEvent(ev observability.AuthEvent) GeoEvent {
	out := e.enrichBase(ev.SrcIP, ev.Ts, CategoryAuth)
	if ev.Kind == observability.AuthEventKindForbidden {
		out.StatusCode = 403
	} else {
		out.StatusCode = 401
	}
	detail := ev.Kind.String()
	if ev.Username != "" {
		detail += " " + ev.Username
	}
	out.Details = truncateDetails(detail)
	return out
}

// EnrichNormal builds a GeoEvent for the Step V.1
// "normal" category — legitimate user traffic that
// successfully passed through Arenet to an upstream. Called
// by DefaultNormalSink AFTER the sampling + cooldown gates
// have passed, so this function is on the hot path only for
// the surviving 5% (with default sample_pct=5).
//
// The caller is responsible for the D2 RFC1918 short-
// circuit: NormalSink.Submit routes LAN sources to the V.6
// LAN pill counter and does NOT call EnrichNormal for them.
// As a defensive belt-and-braces, enrichBase still flips
// IsLAN=true if the IP happens to be in an RFC1918 range
// (a future caller might bypass the short-circuit; we
// don't want a malformed event reaching the bus).
//
// statusCode is the final response status (2xx or 3xx per
// the V.1 spec §D1 gate); the frontend tooltip surfaces it
// next to the route label. routeID identifies the arenet
// route (matches the per-route metrics keys); the frontend
// uses it for the optional "filter by route" UX deferred
// to a future increment.
func (e *Enricher) EnrichNormal(srcIP, routeID string, statusCode int) GeoEvent {
	out := e.enrichBase(srcIP, time.Now().UTC(), CategoryNormal)
	out.StatusCode = statusCode
	out.RouteID = routeID
	return out
}

// enrichBase is the shared geo-lookup core. Resolves the
// source IP, fills the SourceLat/Lon/Country/City + IsLAN
// fields, and stamps the timestamp + category. Empty SourceIP
// (CrowdSec non-ip-scoped decisions) yields a fully degraded
// GeoEvent with sourceCountry="UNK" + isLan=false.
func (e *Enricher) enrichBase(srcIP string, ts time.Time, category string) GeoEvent {
	ev := GeoEvent{
		Timestamp:     ts.UTC(),
		Category:      category,
		SourceIP:      srcIP,
		SourceCountry: countryUnknown,
	}
	if srcIP == "" {
		return ev
	}
	ip := net.ParseIP(srcIP)
	if ip == nil {
		return ev
	}

	// LAN check runs BEFORE the Lookup call so the IsLAN
	// classification is honest even when the GeoIP database
	// is absent (nil Lookup short-circuits to Found=false in
	// V.1 and never returns the "LAN" Country sentinel). Spec
	// §3.8 requires LAN sources to render at the Arenet
	// position with the (LAN) label regardless of GeoIP
	// availability, so this classification must be a pure
	// IP-range check.
	if isLAN(ip) {
		ev.IsLAN = true
		ev.SourceCountry = countryUnknown
		return ev
	}

	loc := e.lookup.LookupIP(ip)

	// Defensive: a real MMDB may also mark its result with
	// Country=="LAN" via V.1's contract when the V.1 LAN
	// ranges expand in the future. Treat both as equivalent.
	if loc.Country == "LAN" {
		ev.IsLAN = true
		ev.SourceCountry = countryUnknown
		return ev
	}
	if !loc.Found {
		return ev
	}
	ev.SourceLat = loc.Lat
	ev.SourceLon = loc.Lon
	ev.SourceCountry = loc.Country
	ev.SourceCity = loc.City
	if ev.SourceCountry == "" {
		ev.SourceCountry = countryUnknown
	}
	return ev
}

// truncateDetails caps the Details field per the documented
// detailsMaxBytes budget. Falls back to the verbatim string
// when already under the cap.
func truncateDetails(s string) string {
	if len(s) <= detailsMaxBytes {
		return s
	}
	cut := detailsMaxBytes
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}
