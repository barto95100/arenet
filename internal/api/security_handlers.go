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

package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/observability"
)

// securityEventsLimitCap mirrors the storage-layer cap on
// QueryWafEvents.Limit but lives here too as the authoritative
// HTTP-surface contract — a caller asking for limit=500 sees a
// 100-row response without an error, and the docs reference
// this constant.
const securityEventsLimitCap = 100

// securityEvent is the per-event wire shape — mirror of
// observability.WafEvent with camelCase JSON tags. Ts as an
// RFC3339 string so the frontend can parse with new Date()
// without bespoke handling.
type securityEvent struct {
	ID            int64  `json:"id"`
	Ts            string `json:"ts"`
	RouteID       string `json:"routeId"`
	RuleID        string `json:"ruleId"`
	Category      string `json:"category"`
	Severity      int    `json:"severity"`
	SrcIP         string `json:"srcIp"`
	RequestMethod string `json:"requestMethod"`
	RequestPath   string `json:"requestPath"`
	PayloadSample string `json:"payloadSample"`
}

// securityEventsResponse is the wire shape of
// GET /api/v1/security/events. `disabled` mirrors the L
// timeseries / summary semantics: true iff the observability
// subsystem failed at boot (AC #13) so the frontend can render
// a clean empty state.
type securityEventsResponse struct {
	Disabled bool            `json:"disabled,omitempty"`
	Events   []securityEvent `json:"events"`
}

// securityEvents handles GET /api/v1/security/events. Query
// parameters (all optional):
//   - limit: how many rows to return. Capped at
//     securityEventsLimitCap. Defaults to the cap when unset.
//   - route: filter to a single route UUID.
//   - category: filter to one OwaspCategory string. Unknown
//     values match nothing (no error — same shape as the
//     existing metrics handlers' permissive params).
//
// Response shape: { events: [ {id, ts, routeId, ruleId,
// category, severity, srcIp, requestMethod, requestPath,
// payloadSample}, ... ], disabled? }.
//
// Auth: hard-auth-no-admin gated at the route mount (viewer-
// accessible per AC #12). No body, no side effect — pure read.
//
// AC #13 degraded paths:
//   - h.wafEvents == nil (observability boot failed) → 200
//     with disabled=true and events=[]. The UI shows the
//     same empty-state shape as the metrics dashboards.
//   - QueryWafEvents returns an error → 503 with the
//     canonical error envelope; the operator can correlate
//     with /healthz.
func (h *Handler) securityEvents(w http.ResponseWriter, r *http.Request) {
	resp := securityEventsResponse{Events: []securityEvent{}}

	if h.wafEvents == nil {
		resp.Disabled = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	limit := securityEventsLimitCap
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		n, err := strconv.Atoi(rawLimit)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > securityEventsLimitCap {
			n = securityEventsLimitCap
		}
		limit = n
	}

	filter := observability.WafEventFilter{
		RouteID:  r.URL.Query().Get("route"),
		Category: r.URL.Query().Get("category"),
		Limit:    limit,
	}

	events, err := h.wafEvents.QueryWafEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("security: query waf_events failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "security events unavailable")
		return
	}

	resp.Events = make([]securityEvent, 0, len(events))
	for _, e := range events {
		resp.Events = append(resp.Events, securityEvent{
			ID:            e.ID,
			Ts:            e.Ts.Format(time.RFC3339),
			RouteID:       e.RouteID,
			RuleID:        e.RuleID,
			Category:      e.Category,
			Severity:      e.Severity,
			SrcIP:         e.SrcIP,
			RequestMethod: e.RequestMethod,
			RequestPath:   e.RequestPath,
			PayloadSample: e.PayloadSample,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- M.2 amendment #2: per-rule aggregate -----------------------------------

// securityEventByRule is one row of the aggregate response.
// ts is the most-recent event ts for the (rule_id, category)
// tuple over the window.
type securityEventByRule struct {
	RuleID   string `json:"ruleId"`
	Category string `json:"category"`
	Count    int64  `json:"count"`
	LastSeen string `json:"lastSeen"`
}

// securityEventsByRuleResponse is the wire shape of
// GET /api/v1/security/events/by-rule.
type securityEventsByRuleResponse struct {
	Disabled bool                  `json:"disabled,omitempty"`
	Rows     []securityEventByRule `json:"rows"`
}

// securityWindowParams maps a `window` query parameter
// (24h/30d) to a [from, to) time range relative to now. Mirrors
// the metrics-handler convention but returns just the time
// bounds (no Granularity — aggregation isn't bucketed).
func securityWindowParams(window string) (from, to time.Time, ok bool) {
	now := time.Now().UTC()
	switch window {
	case "24h":
		return now.Add(-24 * time.Hour), now, true
	case "30d":
		return now.Add(-30 * 24 * time.Hour), now, true
	}
	return time.Time{}, time.Time{}, false
}

// securityEventsByRule handles GET /api/v1/security/events/by-rule.
// Query parameters:
//   - route   (required): filter aggregation to a single route
//     UUID. Empty route would aggregate across all routes,
//     which the dashboard's per-route view never wants — the
//     handler requires it explicitly to surface 400 on
//     missing route rather than silently returning a
//     system-wide aggregate.
//   - window  (required): 24h or 30d. Same wording as the
//     metrics timeseries endpoint to keep operator mental
//     model consistent.
//
// Response shape:
//
//	{ rows: [{ruleId, category, count, lastSeen}, ...] }
//
// Ordered by count DESC (storage-layer guarantee).
//
// AC #13 paths mirror the events endpoint: nil WafEventReader
// → 200 disabled=true + rows=[]; storage error → 503.
//
// Closes the M.4 deviation flagged at review: the drill-down's
// per-rule table now reflects the full WINDOW, not just the
// most-recent 100 events.
func (h *Handler) securityEventsByRule(w http.ResponseWriter, r *http.Request) {
	resp := securityEventsByRuleResponse{Rows: []securityEventByRule{}}

	if h.wafEvents == nil {
		resp.Disabled = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	routeID := r.URL.Query().Get("route")
	if routeID == "" {
		writeError(w, http.StatusBadRequest, "route is required")
		return
	}
	from, to, ok := securityWindowParams(r.URL.Query().Get("window"))
	if !ok {
		writeError(w, http.StatusBadRequest, "window must be 24h or 30d")
		return
	}

	rows, err := h.wafEvents.AggregateWafEventsByRule(r.Context(), observability.WafEventAggregateFilter{
		RouteID: routeID,
		From:    from,
		To:      to,
	})
	if err != nil {
		h.logger.Error("security: aggregate waf_events by rule failed", "err", err, "route", routeID)
		writeError(w, http.StatusServiceUnavailable, "security events unavailable")
		return
	}

	resp.Rows = make([]securityEventByRule, 0, len(rows))
	for _, r := range rows {
		resp.Rows = append(resp.Rows, securityEventByRule{
			RuleID:   r.RuleID,
			Category: r.Category,
			Count:    r.Count,
			LastSeen: r.LastSeen.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- Step Q.2: auth-failures timeline ---------------------------------------

// authFailuresRecentCap bounds the `recent` feed in the
// /security/auth-failures response. Spec §1.5 — the dashboard
// only ever renders the most-recent N rows; deeper history is
// accessed via the /audit endpoint. 100 keeps the wire payload
// small and matches the WAF /security/events cap.
const authFailuresRecentCap = 100

// authFailuresScanCap is the hard cap on the audit-bucket
// scan. Picked to comfortably cover a 30d window of
// auth-failure events at credible homelab volume (spec D4: a
// handful per day in normal operation, bursts capped by the
// rate limiter itself — Tier 2 hard-blocks at 10/hour per IP).
// Higher than the recent-feed cap because the per-minute
// timeseries needs every matching row in the window, not just
// the top 100.
const authFailuresScanCap = audit.MaxLimit // 200

// authFailureTimeseriesPoint is one (ts, value) pair on the
// per-minute auth-failure timeline. Same wire shape as the L
// metrics timeseries — keeps the frontend's chart code
// uniform across data sources (spec §1.3 D4 trade-off
// acknowledged).
type authFailureTimeseriesPoint struct {
	Ts    string `json:"ts"`
	Value int    `json:"value"`
}

// authFailureRecentEvent is one row of the recent-events feed.
// camelCase JSON matches the WAF event shape; Ts is RFC3339.
//
// Username is the captured-verbatim attempted username from
// the audit record's actor_username_snapshot (parity with the
// audit log's existing exposure, per Step Q spec §1.3 D8.A).
// Message is the audit Event.Message (free text: "wrong
// password", "user not found", etc.).
type authFailureRecentEvent struct {
	Ts       string `json:"ts"`
	Action   string `json:"action"`
	Username string `json:"username,omitempty"`
	SrcIP    string `json:"srcIp,omitempty"`
	Message  string `json:"message,omitempty"`
}

// securityAuthFailuresResponse is the wire shape of
// GET /api/v1/security/auth-failures. Both projections come
// from ONE audit scan (spec §5.2): the timeseries powers the
// dashboard's auth-failure chart, the recent slice feeds the
// mixed events widget.
//
// `partial` is true when the audit-bucket scan hit its
// internal cap before reaching the window's `from` boundary —
// the operator is warned that earlier matching events exist
// but were not surfaced. Spec D4 — auth-failure volume is
// expected to be tiny, so `partial=true` should be rare in
// practice but is exposed for honesty.
type securityAuthFailuresResponse struct {
	Disabled   bool                         `json:"disabled,omitempty"`
	Window     string                       `json:"window"`
	Timeseries []authFailureTimeseriesPoint `json:"timeseries"`
	Recent     []authFailureRecentEvent     `json:"recent"`
	Partial    bool                         `json:"partial,omitempty"`
}

// securityAuthFailures handles GET /api/v1/security/auth-failures.
// Query parameters:
//   - window (required): 24h or 30d. Same vocabulary as the
//     metrics timeseries + /security/events/by-rule endpoints.
//
// Response shape:
//
//	{
//	  "window": "24h",
//	  "timeseries": [{ts, value}, ...],   // per-minute, gap-filled=0
//	  "recent":     [{ts, action, username, srcIp, message}, ...],
//	  "partial":    bool                   // true iff scan cap reached
//	}
//
// Implementation per spec §1.3 D4.B + §5.2: ONE audit-bucket
// scan filtered to the auth-failure action set + the window
// range, projected twice (groupBy minute + ts-desc head). No
// second scan, no bucket counter — the audit table is the
// single source of truth.
//
// Auth: viewer-accessible (hard-auth-no-admin gated at the
// route mount, per AC #12). Pure read, no side effect.
//
// AC #14 paths:
//   - h.authFailures == nil (audit/observability boot failed)
//     → 200 with disabled=true + empty timeseries/recent.
//   - scan error → 503 + canonical error envelope.
func (h *Handler) securityAuthFailures(w http.ResponseWriter, r *http.Request) {
	window := r.URL.Query().Get("window")
	resp := securityAuthFailuresResponse{
		Window:     window,
		Timeseries: []authFailureTimeseriesPoint{},
		Recent:     []authFailureRecentEvent{},
	}

	if h.authFailures == nil {
		resp.Disabled = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	from, to, ok := securityWindowParams(window)
	if !ok {
		writeError(w, http.StatusBadRequest, "window must be 24h or 30d")
		return
	}

	events, partial, err := h.authFailures.QueryByActionRange(
		r.Context(),
		audit.AuthFailureActions(),
		from,
		to,
		authFailuresScanCap,
	)
	if err != nil {
		h.logger.Error("security: query audit auth-failures failed", "err", err, "window", window)
		writeError(w, http.StatusServiceUnavailable, "auth failures unavailable")
		return
	}
	resp.Partial = partial

	// Two projections in one pass over the events slice.
	// `events` is reverse-chronological (QueryByActionRange
	// guarantee).
	resp.Timeseries = projectAuthFailureTimeseries(events, from, to)
	resp.Recent = projectAuthFailureRecent(events, authFailuresRecentCap)

	writeJSON(w, http.StatusOK, resp)
}

// projectAuthFailureTimeseries groups `events` into per-minute
// buckets across [from, to), gap-filled with 0 for empty
// minutes. Output is ts-ascending — same orientation as the L
// metrics timeseries so the frontend can plot it directly.
//
// The window may span a few minutes (24h → 1440 buckets) up to
// thousands (30d → 43200 buckets). A naive map[minute]int +
// sort would scale; the implementation below pre-allocates a
// dense slice and runs in O(events + buckets). Worth the
// complexity because the 30d case is the worst case the
// dashboard renders.
func projectAuthFailureTimeseries(events []audit.Event, from, to time.Time) []authFailureTimeseriesPoint {
	// Truncate from / to to whole minutes — the bucket key is
	// the minute-start in UTC. `to` is exclusive so the last
	// bucket included is the minute strictly before `to`.
	fromMin := from.UTC().Truncate(time.Minute)
	toMin := to.UTC().Truncate(time.Minute)
	if !toMin.After(fromMin) {
		return []authFailureTimeseriesPoint{}
	}
	bucketCount := int(toMin.Sub(fromMin) / time.Minute)
	if bucketCount <= 0 {
		return []authFailureTimeseriesPoint{}
	}
	counts := make([]int, bucketCount)
	for _, e := range events {
		ts := e.Timestamp.UTC().Truncate(time.Minute)
		// Out-of-window events are skipped — the QueryByActionRange
		// contract already filters but defence-in-depth costs
		// nothing here.
		if ts.Before(fromMin) || !ts.Before(toMin) {
			continue
		}
		idx := int(ts.Sub(fromMin) / time.Minute)
		if idx < 0 || idx >= bucketCount {
			continue
		}
		counts[idx]++
	}
	out := make([]authFailureTimeseriesPoint, bucketCount)
	for i := 0; i < bucketCount; i++ {
		out[i] = authFailureTimeseriesPoint{
			Ts:    fromMin.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			Value: counts[i],
		}
	}
	return out
}

// projectAuthFailureRecent takes the head of `events` (already
// reverse-chronological) up to `cap`, projected to the wire
// shape. Cheap O(min(len(events), cap)) — no allocation past
// the cap.
func projectAuthFailureRecent(events []audit.Event, cap int) []authFailureRecentEvent {
	if cap <= 0 || len(events) == 0 {
		return []authFailureRecentEvent{}
	}
	n := len(events)
	if n > cap {
		n = cap
	}
	out := make([]authFailureRecentEvent, n)
	for i := 0; i < n; i++ {
		e := events[i]
		out[i] = authFailureRecentEvent{
			Ts:       e.Timestamp.UTC().Format(time.RFC3339),
			Action:   e.Action,
			Username: e.ActorUsernameSnapshot,
			SrcIP:    e.IP,
			Message:  e.Message,
		}
	}
	return out
}

// --- Step Q.3: throttle event log -------------------------------------------

// securityThrottleEventsLimitCap mirrors the storage-layer
// throttleEventLimitCap (100) but lives here too as the
// authoritative HTTP-surface contract — same convention as
// securityEventsLimitCap.
const securityThrottleEventsLimitCap = 100

// securityThrottleEvent is the per-event wire shape — mirror
// of observability.ThrottleEvent with camelCase JSON. Ts and
// BlockedUntil are RFC3339 strings (same convention as the
// WAF event endpoint).
type securityThrottleEvent struct {
	ID                   int64  `json:"id"`
	Ts                   string `json:"ts"`
	Tier                 int    `json:"tier"`
	SrcIP                string `json:"srcIp"`
	AttemptedUsername    string `json:"attemptedUsername"`
	BlockedUntil         string `json:"blockedUntil"`
	BlockDurationSeconds int    `json:"blockDurationSeconds"`
}

// securityThrottleEventsResponse is the wire shape of
// GET /api/v1/security/throttle-events. Mirror of
// securityEventsResponse. `disabled` follows the same AC #14
// degraded-mode contract as the M endpoints.
type securityThrottleEventsResponse struct {
	Disabled bool                    `json:"disabled,omitempty"`
	Events   []securityThrottleEvent `json:"events"`
}

// --- Step Q.3: attackers summary --------------------------------------------

// attackersByBucketSource is the per-source count breakdown
// returned alongside the union total. Spec D6.A wording on
// Q.3 was "{waf: N, throttle: N, audit: N}"; Step N.3 adds a
// 4th source: "{waf: N, throttle: N, audit: N, crowdsec: N}".
//
// The crowdsec field carries the count of distinct values
// (IP / CIDR / country / AS) in the decision_event table
// over the window — including non-IP scopes. This is
// intentional: a CrowdSec community blocklist Range scope
// like "185.142.86.0/24" represents an attacker as much as
// a single IP and counts toward the operator's situational
// awareness.
type attackersByBucketSource struct {
	WAF      int `json:"waf"`
	Throttle int `json:"throttle"`
	Audit    int `json:"audit"`
	CrowdSec int `json:"crowdsec"`
}

// securityAttackersSummaryResponse is the wire shape of
// GET /api/v1/security/attackers-summary per AC #9.
//
// `uniqueIps` is the union count: an IP that hit BOTH a WAF
// rule AND a rate-limit block counts ONCE in the union, but
// shows up under both `waf` and `throttle` in the per-source
// breakdown. The frontend uses the union as the headline stat
// card and the breakdown for the "by source" pie chart.
//
// Three-state disabled / partial contract (aligned with Q.2):
//   - ALL three readers nil → `disabled: true` + empty body.
//   - At least one nil but not all → `partial: true`. The
//     union is honest about what we have, the dashboard can
//     render an "incomplete data" hint.
//   - All three present → neither flag set.
//
// The frontend uses `partial` to drive the same "incomplete"
// affordance Q.2's auth-failures endpoint uses on its
// scan-cap-hit case — operator mental model stays uniform.
type securityAttackersSummaryResponse struct {
	Disabled       bool                    `json:"disabled,omitempty"`
	Partial        bool                    `json:"partial,omitempty"`
	Window         string                  `json:"window"`
	UniqueIps      int                     `json:"uniqueIps"`
	ByBucketSource attackersByBucketSource `json:"byBucketSource"`
}

// securityAttackersSummary handles
// GET /api/v1/security/attackers-summary. Required query
// parameters:
//   - window: 24h or 30d.
//
// Server-side union over three source tables (D6.A):
//
//   - waf_event.src_ip DISTINCT (via WafEventReader.
//     DistinctWafEventSrcIPs)
//   - throttle_event.src_ip DISTINCT (via ThrottleEventReader.
//     DistinctThrottleEventSrcIPs)
//   - audit bucket auth-failure IPs (via AuthFailureReader.
//     QueryByActionRange + in-memory dedup over Event.IP)
//
// All three are unioned into one Go map[string]struct{} and
// the size is returned as `uniqueIps`. The per-source counts
// reflect the size of each source set BEFORE the union (so
// `waf + throttle + audit >= uniqueIps`, equal when no
// overlap).
//
// AC #14: ALL THREE readers missing → 200 with disabled=true.
// A subset missing → the available data is returned (no
// disabled flag); the missing source contributes 0 to its
// breakdown slot. Either reader returning an error → 503.
func (h *Handler) securityAttackersSummary(w http.ResponseWriter, r *http.Request) {
	window := r.URL.Query().Get("window")
	resp := securityAttackersSummaryResponse{Window: window}

	// Step N.3 extension: 4-source contract. ALL FOUR readers
	// nil → disabled. Any subset nil → partial. All four
	// present → neither flag set.
	if h.wafEvents == nil && h.throttleEvents == nil && h.authFailures == nil && h.decisions == nil {
		resp.Disabled = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	from, to, ok := securityWindowParams(window)
	if !ok {
		writeError(w, http.StatusBadRequest, "window must be 24h or 30d")
		return
	}

	// At least one reader present but not all four → the union
	// is honest about its sources, but the operator deserves a
	// "data incomplete" hint. Same shape as Q.2's `partial`
	// flag (scan-cap-hit there; subset-down here). The all-nil
	// short-circuit above takes precedence.
	if h.wafEvents == nil || h.throttleEvents == nil || h.authFailures == nil || h.decisions == nil {
		resp.Partial = true
	}

	union := make(map[string]struct{})

	if h.wafEvents != nil {
		ips, err := h.wafEvents.DistinctWafEventSrcIPs(r.Context(), from, to)
		if err != nil {
			h.logger.Error("security: distinct waf src ip query failed", "err", err, "window", window)
			writeError(w, http.StatusServiceUnavailable, "attackers summary unavailable")
			return
		}
		resp.ByBucketSource.WAF = len(ips)
		for _, ip := range ips {
			if ip == "" {
				continue
			}
			union[ip] = struct{}{}
		}
	}

	if h.throttleEvents != nil {
		ips, err := h.throttleEvents.DistinctThrottleEventSrcIPs(r.Context(), from, to)
		if err != nil {
			h.logger.Error("security: distinct throttle src ip query failed", "err", err, "window", window)
			writeError(w, http.StatusServiceUnavailable, "attackers summary unavailable")
			return
		}
		resp.ByBucketSource.Throttle = len(ips)
		for _, ip := range ips {
			if ip == "" {
				continue
			}
			union[ip] = struct{}{}
		}
	}

	if h.authFailures != nil {
		// Spec D6.A: union over the audit-bucket auth-failure
		// IPs. Reuse the same scan path as /security/auth-
		// failures (single source of truth, D4.B), then
		// collect distinct IPs in memory. Scan cap matches the
		// auth-failures endpoint so the two views report the
		// same "partial" horizon (consistency over the
		// dashboard's mental model). Returns 0 IPs counted if
		// the cap was hit before the window's `from` — the
		// honest answer; the operator can correlate with
		// /security/auth-failures's `partial` flag.
		events, _, err := h.authFailures.QueryByActionRange(
			r.Context(),
			audit.AuthFailureActions(),
			from,
			to,
			authFailuresScanCap,
		)
		if err != nil {
			h.logger.Error("security: audit auth-failure scan failed", "err", err, "window", window)
			writeError(w, http.StatusServiceUnavailable, "attackers summary unavailable")
			return
		}
		auditIPs := make(map[string]struct{})
		for _, e := range events {
			if e.IP == "" {
				continue
			}
			auditIPs[e.IP] = struct{}{}
		}
		resp.ByBucketSource.Audit = len(auditIPs)
		for ip := range auditIPs {
			union[ip] = struct{}{}
		}
	}

	// Step N.3 — CrowdSec arm of the union. Same shape as
	// the WAF / throttle distinct-IP queries: the storage
	// returns SELECT DISTINCT value (which can be an IP, a
	// CIDR, a country code, or an AS — depends on the
	// LAPI decision's scope). The bucket-source `crowdsec`
	// count INCLUDES non-IP scopes intentionally (see
	// attackersByBucketSource doc comment).
	if h.decisions != nil {
		ips, err := h.decisions.DistinctDecisionSrcIPs(r.Context(), from, to)
		if err != nil {
			h.logger.Error("security: distinct decision src ip query failed", "err", err, "window", window)
			writeError(w, http.StatusServiceUnavailable, "attackers summary unavailable")
			return
		}
		resp.ByBucketSource.CrowdSec = len(ips)
		for _, ip := range ips {
			if ip == "" {
				continue
			}
			union[ip] = struct{}{}
		}
	}

	resp.UniqueIps = len(union)
	writeJSON(w, http.StatusOK, resp)
}

// securityThrottleEvents handles GET /api/v1/security/throttle-events.
// Query parameters (all optional):
//   - limit: how many rows to return. Capped at
//     securityThrottleEventsLimitCap. Defaults to the cap when
//     unset.
//   - srcIp: filter to a single source IP.
//   - tier:  filter to tier 1 or 2.
//
// Response shape: {events: [{id, ts, tier, srcIp,
// attemptedUsername, blockedUntil, blockDurationSeconds}, ...],
// disabled?}. Auth: viewer-accessible (hard-auth-no-admin
// gated at the route mount, AC #12). Pure read, no side effect.
//
// AC #14 degraded paths mirror /security/events:
//   - h.throttleEvents == nil → 200 with disabled=true and
//     events=[].
//   - QueryThrottleEvents returns an error → 503 with the
//     canonical envelope.
func (h *Handler) securityThrottleEvents(w http.ResponseWriter, r *http.Request) {
	resp := securityThrottleEventsResponse{Events: []securityThrottleEvent{}}

	if h.throttleEvents == nil {
		resp.Disabled = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	limit := securityThrottleEventsLimitCap
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		n, err := strconv.Atoi(rawLimit)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > securityThrottleEventsLimitCap {
			n = securityThrottleEventsLimitCap
		}
		limit = n
	}

	tierFilter := 0
	if rawTier := r.URL.Query().Get("tier"); rawTier != "" {
		n, err := strconv.Atoi(rawTier)
		if err != nil || (n != 1 && n != 2) {
			writeError(w, http.StatusBadRequest, "tier must be 1 or 2")
			return
		}
		tierFilter = n
	}

	filter := observability.ThrottleEventFilter{
		SrcIP: r.URL.Query().Get("srcIp"),
		Tier:  tierFilter,
		Limit: limit,
	}

	events, err := h.throttleEvents.QueryThrottleEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("security: query throttle_events failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "throttle events unavailable")
		return
	}

	resp.Events = make([]securityThrottleEvent, 0, len(events))
	for _, e := range events {
		resp.Events = append(resp.Events, securityThrottleEvent{
			ID:                   e.ID,
			Ts:                   e.Ts.Format(time.RFC3339),
			Tier:                 e.Tier,
			SrcIP:                e.SrcIP,
			AttemptedUsername:    e.AttemptedUsername,
			BlockedUntil:         e.BlockedUntil.Format(time.RFC3339),
			BlockDurationSeconds: e.BlockDurationSeconds,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- Step N.3: CrowdSec decision log ----------------------------------------

// securityDecisionsLimitCap mirrors the storage-layer
// decisionEventLimitCap (100). Same convention as
// securityEventsLimitCap / securityThrottleEventsLimitCap.
const securityDecisionsLimitCap = 100

// securityDecision is the per-event wire shape — mirror of
// observability.DecisionEvent with camelCase JSON. Ts and
// ExpiresAt are RFC3339 strings (consistent with WAF + throttle
// event endpoints). Per Step N spec D5.B, the wire surface is
// the operator-facing subset (no `id` from upstream LAPI; `id`
// here is Arenet's local autoincrement, useful as a stable
// pagination cursor surface in a future revision).
type securityDecision struct {
	ID              int64  `json:"id"`
	UUID            string `json:"uuid"`
	Ts              string `json:"ts"`
	Scope           string `json:"scope"`
	Value           string `json:"value"`
	Type            string `json:"type"`
	Scenario        string `json:"scenario"`
	ExpiresAt       string `json:"expiresAt"`
	DurationSeconds int    `json:"durationSeconds"`
}

// securityDecisionsResponse is the wire shape of
// GET /api/v1/security/decisions. Mirror of
// securityThrottleEventsResponse. `disabled` follows the AC
// #15 degraded-mode contract (nil DecisionReader, e.g. LAPI
// key not configured + observability DB unavailable).
type securityDecisionsResponse struct {
	Disabled bool               `json:"disabled,omitempty"`
	Events   []securityDecision `json:"events"`
}

// securityDecisions handles GET /api/v1/security/decisions.
// Query parameters (all optional):
//   - limit:     how many rows to return. Capped at
//     securityDecisionsLimitCap. Defaults to the
//     cap when unset.
//   - scope:     filter to "ip" | "range" | "country" | "as".
//     Free-form on the wire (the storage layer
//     does an exact match without enum
//     validation — the LAPI scope vocabulary is
//     operator-controlled, and rejecting an
//     unknown scope here would force every spec
//     bump to coordinate with Arenet).
//   - srcIp:     exact-match filter on the decision's
//     `value` field (the LAPI value depends on
//     scope; for ip/range scopes it IS an IP /
//     CIDR). The query parameter is named
//     "srcIp" rather than "value" for consistency
//     with the throttle-events endpoint operator
//     mental model.
//   - scenario:  exact-match filter on the LAPI scenario
//     name (e.g. "crowdsecurity/http-probing").
//   - onlyActive: when "true", exclude rows whose
//     expires_at <= now (decision revoked or
//     expired). Default false: return all rows
//     in the window including expired ones, so
//     the operator dashboard can show forensic
//     "what WAS banned yesterday" views.
//
// Response shape: {events: [{id, uuid, ts, scope, value,
// type, scenario, expiresAt, durationSeconds}], disabled?}.
//
// Auth: viewer-accessible (hard-auth-no-admin gated at the
// route mount, AC #N.20). Pure read, no side effect.
//
// AC #15 degraded paths mirror /security/throttle-events:
//   - h.decisions == nil → 200 with disabled=true and
//     events=[].
//   - QueryDecisionEvents returns an error → 503.
func (h *Handler) securityDecisions(w http.ResponseWriter, r *http.Request) {
	resp := securityDecisionsResponse{Events: []securityDecision{}}

	if h.decisions == nil {
		resp.Disabled = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	limit := securityDecisionsLimitCap
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		n, err := strconv.Atoi(rawLimit)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > securityDecisionsLimitCap {
			n = securityDecisionsLimitCap
		}
		limit = n
	}

	onlyActive := r.URL.Query().Get("onlyActive") == "true"

	filter := observability.DecisionEventFilter{
		Scope:      r.URL.Query().Get("scope"),
		Value:      r.URL.Query().Get("srcIp"),
		Scenario:   r.URL.Query().Get("scenario"),
		Limit:      limit,
		OnlyActive: onlyActive,
	}

	events, err := h.decisions.QueryDecisionEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("security: query decision_events failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "decisions unavailable")
		return
	}

	resp.Events = make([]securityDecision, 0, len(events))
	for _, e := range events {
		resp.Events = append(resp.Events, securityDecision{
			ID:              e.ID,
			UUID:            e.UUID,
			Ts:              e.Ts.Format(time.RFC3339),
			Scope:           e.Scope,
			Value:           e.Value,
			Type:            e.Type,
			Scenario:        e.Scenario,
			ExpiresAt:       e.ExpiresAt.Format(time.RFC3339),
			DurationSeconds: e.DurationSeconds,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}
