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
