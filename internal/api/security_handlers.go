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
