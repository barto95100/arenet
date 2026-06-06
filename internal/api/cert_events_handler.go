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
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/observability"
)

// certEventsLimitCap mirrors observability.certEventAPILimitCap
// at the HTTP layer. Callers asking for more get the cap
// silently — same shape as the existing securityEventsLimitCap
// handling.
const certEventsLimitCap = 1000

// certEventsDefaultLimit is the limit returned when the
// `limit` query parameter is missing or zero. Sized smaller
// than the cap (which is the operator's escape hatch for
// investigations) so the default response stays cheap.
const certEventsDefaultLimit = 100

// certEventResponseItem is the per-event wire shape returned
// by GET /api/v1/observability/cert-events. Field-for-field
// mirror of spec §5.2:
//
//	{ timestamp, level, eventType, domain, issuer,
//	  challenge, renewal, error, details }
//
// All string fields default to "" rather than null (matches
// the U.1 schema defaults). The encoder respects omitempty on
// renewal so the false-default doesn't bloat the payload for
// non-renewal rows. Naming is camelCase consistent with the
// Step T CertRuntimeInfo wire shape — frontend types.ts maps
// to this 1-to-1 in U.4.
type certEventResponseItem struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	EventType string `json:"eventType"`
	Domain    string `json:"domain"`
	Issuer    string `json:"issuer,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	Renewal   bool   `json:"renewal,omitempty"`
	Error     string `json:"error,omitempty"`
	Details   string `json:"details,omitempty"`
}

// certEventsResponse is the wire shape of
// GET /api/v1/observability/cert-events per spec §5.2. The
// `degraded` flag follows the existing securityEventsResponse
// convention (omitempty so the happy-path payload doesn't
// carry the boolean) — matches AC #13 of Step T degraded mode.
type certEventsResponse struct {
	Events   []certEventResponseItem `json:"events"`
	Total    int64                   `json:"total"`
	HasMore  bool                    `json:"hasMore"`
	Degraded bool                    `json:"degraded,omitempty"`
}

// securityCertEvents handles GET /api/v1/observability/cert-
// events. Query parameters (all optional):
//
//   - limit: rows to return. Clamped to certEventsLimitCap
//     (1000) silently — bad values (negative, non-integer)
//     return 400.
//   - since: RFC 3339 lower bound on ts (inclusive). 400 on
//     parse failure.
//   - until: RFC 3339 upper bound on ts (exclusive). 400 on
//     parse failure OR when until <= since.
//   - level: comma-separated subset of {"INFO", "ERROR"}.
//     Unknown values → 400. Empty / unset = no level filter.
//   - search: substring match across domain, issuer,
//     error_msg, details (case-insensitive). Trimmed of
//     surrounding whitespace; empty = no filter.
//
// Response: { events: [...], total, hasMore, degraded? }.
// Auth: hard-auth gated at the route mount (viewer-accessible
// per the existing /security/* convention).
//
// AC #13 degraded paths:
//   - h.certEvents == nil → 200 with degraded=true and
//     events=[], total=0, hasMore=false. Mirrors the Step T
//     CertInfoReader degraded contract: an observability boot
//     failure (or a missed wire-up) does NOT take down the
//     Activity log page.
//   - QueryCertEvents / CountCertEvents error → 503 with the
//     canonical error envelope; the operator can correlate
//     with /healthz.
func (h *Handler) securityCertEvents(w http.ResponseWriter, r *http.Request) {
	resp := certEventsResponse{Events: []certEventResponseItem{}}

	if h.certEvents == nil {
		resp.Degraded = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// limit parsing — bad value 400, beyond-cap clamp silent.
	limit := certEventsDefaultLimit
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		n, err := strconv.Atoi(rawLimit)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > certEventsLimitCap {
			n = certEventsLimitCap
		}
		limit = n
	}

	// since / until parsing — both RFC 3339, reversed bounds 400.
	var since, until time.Time
	if rawSince := r.URL.Query().Get("since"); rawSince != "" {
		t, err := time.Parse(time.RFC3339, rawSince)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be an RFC 3339 timestamp")
			return
		}
		since = t
	}
	if rawUntil := r.URL.Query().Get("until"); rawUntil != "" {
		t, err := time.Parse(time.RFC3339, rawUntil)
		if err != nil {
			writeError(w, http.StatusBadRequest, "until must be an RFC 3339 timestamp")
			return
		}
		until = t
	}
	if !since.IsZero() && !until.IsZero() && !until.After(since) {
		writeError(w, http.StatusBadRequest, "until must be strictly greater than since")
		return
	}

	// level parsing — comma-separated subset of {INFO, ERROR}.
	// Empty / missing = no filter. Unknown token 400 so the
	// operator gets immediate feedback on typos.
	var levels []observability.CertEventLevel
	if raw := r.URL.Query().Get("level"); raw != "" {
		for _, tok := range strings.Split(raw, ",") {
			t := strings.TrimSpace(tok)
			if t == "" {
				continue
			}
			switch t {
			case "INFO":
				levels = append(levels, observability.CertEventLevelInfo)
			case "ERROR":
				levels = append(levels, observability.CertEventLevelError)
			default:
				writeError(w, http.StatusBadRequest,
					"level must be a comma-separated subset of {INFO, ERROR}")
				return
			}
		}
	}

	// search — trim, empty → no filter.
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	filter := observability.CertEventFilter{
		From:   since,
		To:     until,
		Levels: levels,
		Search: search,
		Limit:  limit,
	}

	events, err := h.certEvents.QueryCertEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("cert events: query failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "cert events unavailable")
		return
	}

	total, err := h.certEvents.CountCertEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("cert events: count failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "cert events unavailable")
		return
	}

	resp.Total = total
	resp.HasMore = total > int64(len(events))
	resp.Events = make([]certEventResponseItem, 0, len(events))
	for _, e := range events {
		resp.Events = append(resp.Events, certEventResponseItem{
			Timestamp: e.Ts.UTC().Format(timestampFormat),
			Level:     e.Level.String(),
			EventType: e.Type.String(),
			Domain:    e.Domain,
			Issuer:    e.Issuer,
			Challenge: e.Challenge,
			Renewal:   e.Renewal,
			Error:     e.Error,
			Details:   e.Details,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}
