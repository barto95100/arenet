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
