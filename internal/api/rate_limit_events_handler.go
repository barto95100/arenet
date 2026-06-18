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
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/barto95100/arenet/internal/observability"
)

// Step Z.1 — rate-limit events HTTP wire surface.
//
// Closes the Step Q observability gap: pre-Z, 429 events
// lived only in Caddy's zap log. This endpoint exposes
// the new rate_limit_event table (Z.1 schema v11) on the
// same wire shape as /security/throttle-events and
// /observability/country-block-events.

// rateLimitEventsLimitCap mirrors the storage-layer
// rateLimitEventLimitCap (defensive cap on hand-crafted
// query strings).
const rateLimitEventsLimitCap = 1000

// rateLimitEventsDefaultLimit is the limit returned when
// the `limit` query parameter is missing or zero.
const rateLimitEventsDefaultLimit = 100

// rateLimitEventResponseItem is the per-event wire shape
// returned by GET /api/v1/security/rate-limit-events.
// camelCase JSON tags + RFC 3339 ts mirror the other
// security-event payloads.
type rateLimitEventResponseItem struct {
	ID       int64  `json:"id"`
	Ts       string `json:"ts"`
	RouteID  string `json:"routeId"`
	Zone     string `json:"zone"`
	RemoteIP string `json:"remoteIp"`
	WaitMs   int64  `json:"waitMs"`
}

// rateLimitEventsResponse is the wire shape of GET
// /api/v1/security/rate-limit-events. Mirrors the
// country-block-events envelope ; degraded is omitempty
// so happy-path payloads stay compact.
type rateLimitEventsResponse struct {
	Events   []rateLimitEventResponseItem `json:"events"`
	Total    int64                        `json:"total"`
	HasMore  bool                         `json:"hasMore"`
	Degraded bool                         `json:"degraded,omitempty"`
}

// RateLimitEventReader is the read surface the handler
// depends on. *observability.Store satisfies it via
// QueryRateLimitEvents (Z.1) + CountRateLimitEventsByWindow
// (Z.2 dashboard summary counter). Same narrow-interface
// pattern as CountryBlockEventReader so tests can inject a
// fake without booting SQLite. Same nil-tolerance contract
// (AC #13 degraded-mode).
type RateLimitEventReader interface {
	QueryRateLimitEvents(ctx context.Context, filter observability.RateLimitEventFilter) ([]observability.RateLimitEvent, error)
	CountRateLimitEventsByWindow(ctx context.Context, from, to time.Time) (int64, error)
}

// securityRateLimitEvents handles GET
// /api/v1/security/rate-limit-events. Query parameters
// (all optional) :
//
//   - limit: rows to return. Clamped to
//     rateLimitEventsLimitCap (1000) silently — bad values
//     (negative, non-integer) return 400.
//   - route: filter to a single route UUID. Empty = no
//     filter.
//   - remoteIp: filter to a single client IP. Empty = no
//     filter.
//   - since: RFC 3339 lower bound on ts (inclusive). 400
//     on parse failure.
//   - until: RFC 3339 upper bound on ts (exclusive). 400
//     on parse failure OR when until <= since.
//
// Response: {events, total, hasMore, degraded?}.
//
// Auth: hard-auth gated at the route mount (viewer-
// accessible per the existing /security/* convention).
//
// AC #13 degraded paths :
//   - h.rateLimitEvents == nil → 200 with degraded=true
//     + empty events. Mirrors the W.5 CountryBlockEventReader
//     degraded contract.
//   - QueryRateLimitEvents error → 503 with the canonical
//     error envelope.
func (h *Handler) securityRateLimitEvents(w http.ResponseWriter, r *http.Request) {
	resp := rateLimitEventsResponse{Events: []rateLimitEventResponseItem{}}

	if h.rateLimitEvents == nil {
		resp.Degraded = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	limit := rateLimitEventsDefaultLimit
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		n, err := strconv.Atoi(rawLimit)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > rateLimitEventsLimitCap {
			n = rateLimitEventsLimitCap
		}
		limit = n
	}

	var since, until time.Time
	if rawSince := r.URL.Query().Get("since"); rawSince != "" {
		t, err := time.Parse(time.RFC3339, rawSince)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be RFC 3339 (e.g. 2026-06-01T00:00:00Z)")
			return
		}
		since = t
	}
	if rawUntil := r.URL.Query().Get("until"); rawUntil != "" {
		t, err := time.Parse(time.RFC3339, rawUntil)
		if err != nil {
			writeError(w, http.StatusBadRequest, "until must be RFC 3339")
			return
		}
		until = t
	}
	if !since.IsZero() && !until.IsZero() && !since.Before(until) {
		writeError(w, http.StatusBadRequest, "until must be strictly after since")
		return
	}

	filter := observability.RateLimitEventFilter{
		RouteID:  r.URL.Query().Get("route"),
		RemoteIP: r.URL.Query().Get("remoteIp"),
		From:     since,
		To:       until,
		Limit:    limit,
	}

	events, err := h.rateLimitEvents.QueryRateLimitEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("rate-limit events: query failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "rate-limit events unavailable")
		return
	}

	resp.Events = make([]rateLimitEventResponseItem, 0, len(events))
	for _, e := range events {
		resp.Events = append(resp.Events, rateLimitEventResponseItem{
			ID:       e.ID,
			Ts:       e.Ts.Format(time.RFC3339),
			RouteID:  e.RouteID,
			Zone:     e.Zone,
			RemoteIP: e.RemoteIP,
			WaitMs:   e.WaitMs,
		})
	}
	resp.Total = int64(len(events))
	// hasMore: results may be truncated below the real
	// total. True only when we hit the per-request limit
	// AND that limit was less than the absolute cap. Mirror
	// of country-block / cert-events.
	resp.HasMore = len(events) == limit && limit < rateLimitEventsLimitCap

	writeJSON(w, http.StatusOK, resp)
}
