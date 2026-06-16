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
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/observability"
)

// AL.4.a — GET /api/v1/observability/alert-events.
//
// Reads the alert_event table populated by the AL.4.a
// dispatcher sink. Powers the AL.4 History tab. Auth
// posture mirrors the other /observability/*-events
// endpoints (viewer+ via the hard-auth subtree).
//
// Pagination: cursor-based, mirrors the audit + cert-
// events pattern. NextCursor is opaque to the caller —
// pass back verbatim for the next page.

const (
	// alertEventsDefaultLimit is returned when the limit
	// query parameter is absent or zero. Sized for a
	// single screen of operator History tab content; the
	// cap (200) is the operator-side investigation
	// escape hatch.
	alertEventsDefaultLimit = 50
	alertEventsLimitCap     = 200
)

// alertEventResponseItem is the wire shape per row.
// JSON blobs (context, labels, channelsFired,
// channelsFailed) are decoded server-side so the
// frontend sees typed values, not stringified JSON.
type alertEventResponseItem struct {
	EventID        string            `json:"eventId"`
	Timestamp      string            `json:"timestamp"`
	RuleID         string            `json:"ruleId"`
	RuleName       string            `json:"ruleName"`
	Severity       int               `json:"severity"`
	Category       string            `json:"category"`
	Subject        string            `json:"subject"`
	Body           string            `json:"body,omitempty"`
	Context        map[string]any    `json:"context,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	ChannelsFired  []string          `json:"channelsFired"`
	ChannelsFailed map[string]string `json:"channelsFailed,omitempty"`
}

// alertEventsResponse is the envelope. NextCursor is "" on
// the last page; Degraded=true when the reader is unwired
// (boot-degraded observability).
type alertEventsResponse struct {
	Events     []alertEventResponseItem `json:"events"`
	NextCursor string                   `json:"nextCursor"`
	Degraded   bool                     `json:"degraded,omitempty"`
}

func (h *Handler) listAlertEvents(w http.ResponseWriter, r *http.Request) {
	resp := alertEventsResponse{Events: []alertEventResponseItem{}}

	if h.alertEvents == nil {
		resp.Degraded = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	q := r.URL.Query()
	filter := observability.AlertEventFilter{
		RuleID:   q.Get("rule_id"),
		Category: q.Get("category"),
		Cursor:   q.Get("cursor"),
	}

	// severity is an integer 0..3; parse explicitly so
	// missing-vs-zero is distinguishable (filter.Severity
	// is *int).
	if raw := q.Get("severity"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 3 {
			writeError(w, http.StatusBadRequest, "severity must be an integer 0..3")
			return
		}
		filter.Severity = &n
	}

	if raw := q.Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be an RFC 3339 timestamp")
			return
		}
		filter.From = t
	}
	if raw := q.Get("until"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "until must be an RFC 3339 timestamp")
			return
		}
		filter.To = t
	}
	if !filter.From.IsZero() && !filter.To.IsZero() && !filter.To.After(filter.From) {
		writeError(w, http.StatusBadRequest, "until must be strictly greater than since")
		return
	}

	limit := alertEventsDefaultLimit
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > alertEventsLimitCap {
			n = alertEventsLimitCap
		}
		limit = n
	}
	filter.Limit = limit

	events, nextCursor, err := h.alertEvents.QueryAlertEvents(r.Context(), filter)
	if err != nil {
		// Distinguish operator-supplied bad cursor (400)
		// from server faults (503 — matches the cert-events
		// degraded-failure convention).
		if strings.Contains(err.Error(), "invalid cursor") {
			writeError(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		h.logger.Error("alert events: query failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "failed to query alert events")
		return
	}

	wire := make([]alertEventResponseItem, 0, len(events))
	for _, e := range events {
		wire = append(wire, alertEventRowToWire(e))
	}

	writeJSON(w, http.StatusOK, alertEventsResponse{
		Events:     wire,
		NextCursor: nextCursor,
	})
}

// alertEventRowToWire converts a storage row to the wire
// shape. JSON-blob columns are decoded; decode failures
// surface as empty maps so the frontend never sees a
// stringified JSON value.
func alertEventRowToWire(e observability.AlertEvent) alertEventResponseItem {
	var ctxMap map[string]any
	if e.ContextJSON != "" {
		_ = json.Unmarshal([]byte(e.ContextJSON), &ctxMap)
	}
	var labels map[string]string
	if e.LabelsJSON != "" {
		_ = json.Unmarshal([]byte(e.LabelsJSON), &labels)
	}
	fired := []string{}
	if e.ChannelsFiredJSON != "" {
		_ = json.Unmarshal([]byte(e.ChannelsFiredJSON), &fired)
		if fired == nil {
			fired = []string{}
		}
	}
	var failed map[string]string
	if e.ChannelsFailedJSON != "" {
		_ = json.Unmarshal([]byte(e.ChannelsFailedJSON), &failed)
	}
	return alertEventResponseItem{
		EventID:        e.EventID,
		Timestamp:      e.Ts.UTC().Format(timestampFormat),
		RuleID:         e.RuleID,
		RuleName:       e.RuleName,
		Severity:       e.Severity,
		Category:       e.Category,
		Subject:        e.Subject,
		Body:           e.Body,
		Context:        ctxMap,
		Labels:         labels,
		ChannelsFired:  fired,
		ChannelsFailed: failed,
	}
}

// Silence unused-import linter if a refactor drops one
// of the err-derived helpers above.
var _ = errors.New
