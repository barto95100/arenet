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

// Step W.5 — country-block events HTTP wire surface.
//
// Closes the W.4 backend gap (W.4 shipped the
// country_block_event table + the
// observability.QueryCountryBlockEvents primitive but no
// HTTP endpoint). Mirrors the U.3 securityCertEvents
// handler shape verbatim — same {events, total, hasMore,
// degraded} envelope, same AC #13 degraded path.

// countryBlockEventsLimitCap mirrors the
// observability-layer countryBlockEventLimitCap. Callers
// asking for more get the cap silently.
const countryBlockEventsLimitCap = 1000

// countryBlockEventsDefaultLimit is the limit returned
// when the `limit` query parameter is missing or zero.
const countryBlockEventsDefaultLimit = 100

// countryBlockEventResponseItem is the per-event wire
// shape returned by
// GET /api/v1/observability/country-block-events. Field-
// for-field mirror of observability.CountryBlockEvent
// (W.4) with camelCase JSON tags and an RFC 3339 ts so
// the frontend can parse with new Date() — same
// convention as securityCertEvents.
//
// Host and ASN are NOT in the persisted row (W.4
// deferred); the frontend cross-references RouteID →
// host via the existing GET /api/v1/routes API.
type countryBlockEventResponseItem struct {
	ID         int64  `json:"id"`
	Ts         string `json:"ts"`
	RouteID    string `json:"routeId"`
	SrcIP      string `json:"srcIp"`
	Country    string `json:"country"`
	Mode       string `json:"mode"`
	StatusCode int    `json:"statusCode"`
	Reason     string `json:"reason"`
}

// countryBlockEventsResponse is the wire shape of
// GET /api/v1/observability/country-block-events.
// Mirrors securityCertEvents' envelope: degraded flag is
// omitempty so the happy-path payload doesn't carry it.
type countryBlockEventsResponse struct {
	Events   []countryBlockEventResponseItem `json:"events"`
	Total    int64                           `json:"total"`
	HasMore  bool                            `json:"hasMore"`
	Degraded bool                            `json:"degraded,omitempty"`
}

// CountryBlockEventReader is the read surface the
// observability handler depends on. *observability.Store
// satisfies it via QueryCountryBlockEvents (W.4). Same
// narrow-interface pattern as CertEventReader so tests
// can inject a fake without booting SQLite. Same nil-
// tolerance contract (AC #13 degraded-mode): handlers
// detect nil and return 200 with degraded=true rather
// than 5xx.
type CountryBlockEventReader interface {
	QueryCountryBlockEvents(ctx context.Context, filter observability.CountryBlockEventFilter) ([]observability.CountryBlockEvent, error)
}

// securityCountryBlockEvents handles
// GET /api/v1/observability/country-block-events. Query
// parameters (all optional):
//
//   - limit: rows to return. Clamped to
//     countryBlockEventsLimitCap (1000) silently — bad
//     values (negative, non-integer) return 400.
//   - route: filter to a single route UUID. Empty = no
//     filter.
//   - srcIp: filter to a single source IP. Empty = no
//     filter.
//   - country: filter to a single ISO 3166-1 alpha-2
//     country code. Empty = no filter.
//   - mode: filter to a single mode ("allow" or "deny").
//     Empty = no filter.
//   - since: RFC 3339 lower bound on ts (inclusive). 400
//     on parse failure.
//   - until: RFC 3339 upper bound on ts (exclusive). 400
//     on parse failure OR when until <= since.
//
// Response: {events, total, hasMore, degraded?}.
//
// Auth: hard-auth gated at the route mount (viewer-
// accessible per the existing /observability/* convention).
//
// AC #13 degraded paths:
//   - h.countryBlockEvents == nil → 200 with degraded=true
//   - empty events. Mirrors the U.3 CertEventReader
//     degraded contract.
//   - QueryCountryBlockEvents error → 503 with the
//     canonical error envelope.
//
// Note: the total + hasMore fields are computed from
// len(events) + the limit (no separate Count primitive
// in the W.4 observability layer; the activity-log UI
// uses these for "did the cap clamp this response?"
// signal). hasMore is true when len(events) == limit AND
// limit < cap (i.e. there could be more behind the cap).
func (h *Handler) securityCountryBlockEvents(w http.ResponseWriter, r *http.Request) {
	resp := countryBlockEventsResponse{Events: []countryBlockEventResponseItem{}}

	if h.countryBlockEvents == nil {
		resp.Degraded = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// limit parsing — bad value 400, beyond-cap clamp silent.
	limit := countryBlockEventsDefaultLimit
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		n, err := strconv.Atoi(rawLimit)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > countryBlockEventsLimitCap {
			n = countryBlockEventsLimitCap
		}
		limit = n
	}

	// since / until parsing — both RFC 3339, reversed bounds 400.
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

	filter := observability.CountryBlockEventFilter{
		RouteID: r.URL.Query().Get("route"),
		SrcIP:   r.URL.Query().Get("srcIp"),
		Country: r.URL.Query().Get("country"),
		Mode:    r.URL.Query().Get("mode"),
		From:    since,
		To:      until,
		Limit:   limit,
	}

	events, err := h.countryBlockEvents.QueryCountryBlockEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("country-block events: query failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "country-block events unavailable")
		return
	}

	resp.Events = make([]countryBlockEventResponseItem, 0, len(events))
	for _, e := range events {
		resp.Events = append(resp.Events, countryBlockEventResponseItem{
			ID:         e.ID,
			Ts:         e.Ts.Format(time.RFC3339),
			RouteID:    e.RouteID,
			SrcIP:      e.SrcIP,
			Country:    e.Country,
			Mode:       e.Mode,
			StatusCode: e.StatusCode,
			Reason:     e.Reason,
		})
	}
	resp.Total = int64(len(events))
	// hasMore semantic: "results may be truncated below the
	// real total". True only when we hit the per-request
	// limit AND that limit was less than the absolute cap
	// (so the operator's only escape hatch — raise limit —
	// is meaningful). Mirror of the U.3 cert-events shape.
	resp.HasMore = len(events) == limit && limit < countryBlockEventsLimitCap

	writeJSON(w, http.StatusOK, resp)
}
