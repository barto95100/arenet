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
	"fmt"
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
//   - domain: exact match on the domain field. Useful for
//     the /certs page Cert.B drill-down which wants the
//     last N events for a specific hostname without the
//     substring imprecision of `search` (foo.example.com
//     matches not-foo.example.com under LIKE %X%). Trimmed
//     of surrounding whitespace; empty = no filter.
//   - type: exact match on the eventType field (one of
//     "cert_obtained", "cert_failed", "cert_ocsp_revoked").
//     Empty = no filter. Unknown values pass through to the
//     storage layer which filters as a literal string match
//     — an unknown type returns 0 rows rather than 400,
//     because future certmagic versions may emit new event
//     types we don't yet recognise (defensive, mirrors the
//     storage layer's pass-through behaviour).
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

	// domain — Cert.B (2026-06-23) — exact match per the doc
	// comment above. Trim then pass through ; storage handles
	// empty = no filter.
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))

	// type — Cert.B (2026-06-23) — exact match on eventType.
	// Pass-through to storage. Unknown values return 0 rows
	// rather than 400 ; defensive against future certmagic
	// event-type additions.
	eventType := strings.TrimSpace(r.URL.Query().Get("type"))

	filter := observability.CertEventFilter{
		Domain: domain,
		Type:   eventType,
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

// Phase 5 — GET /api/v1/observability/cert-events/aggregate.
//
// Query parameters (all optional):
//   - window: duration string (e.g. "30d", "168h"). Clamped to
//     [certEventsAggregateMinWindow, certEventsAggregateMaxWindow]
//     silently. Default: 30d.
//   - interval: duration string for bucket size. Clamped to
//     [certEventsAggregateMinInterval, certEventsAggregateMaxInterval]
//     silently. Default: 24h.
//
// Response: { buckets: [{bucketStart, issued, renewed, failed}, ...],
// degraded? }. The buckets array is always emitted with one
// entry per interval within the window (empty buckets carry
// zero counts) so the frontend can render a continuous timeline
// without client-side gap-fill.
//
// Auth: same hard-auth gate as securityCertEvents — viewer-
// accessible. AC #13 degraded mode preserved: h.certEvents
// nil returns 200 with degraded=true and an empty buckets array.

const (
	// certEventsAggregateDefaultWindow matches the dashboard's
	// 30d view requested by the Phase 5 brief.
	certEventsAggregateDefaultWindow = 30 * 24 * time.Hour
	// certEventsAggregateMinWindow guards against zero-width
	// windows that would emit a single bucket with no content.
	certEventsAggregateMinWindow = time.Hour
	// certEventsAggregateMaxWindow matches the cert_event
	// retention horizon (90d, spec §3.2) — querying beyond is
	// a pointless DB scan over rows that were already pruned.
	certEventsAggregateMaxWindow = 90 * 24 * time.Hour
	// certEventsAggregateDefaultInterval matches Phase 5's
	// per-day bucket cadence for the 30d view.
	certEventsAggregateDefaultInterval = 24 * time.Hour
	// certEventsAggregateMinInterval prevents pathological
	// thousand-bucket payloads. 1h is the natural floor — finer
	// granularity has no operator signal.
	certEventsAggregateMinInterval = time.Hour
	// certEventsAggregateMaxInterval is purely defensive — a
	// week-wide bucket is meaningless on a 30d window. Capping
	// here keeps the response payload bounded.
	certEventsAggregateMaxInterval = 7 * 24 * time.Hour
)

type certEventsAggregateBucketResp struct {
	BucketStart string `json:"bucketStart"`
	Issued      int64  `json:"issued"`
	Renewed     int64  `json:"renewed"`
	Failed      int64  `json:"failed"`
}

type certEventsAggregateResponse struct {
	Buckets  []certEventsAggregateBucketResp `json:"buckets"`
	Degraded bool                            `json:"degraded,omitempty"`
}

func parseDurationParam(raw string, defaultVal, minVal, maxVal time.Duration) (time.Duration, error) {
	if raw == "" {
		return defaultVal, nil
	}
	// time.ParseDuration doesn't accept the "d" suffix; accept
	// it manually because the brief and the frontend speak in
	// days. Any non-numeric prefix is an error.
	if strings.HasSuffix(raw, "d") {
		nStr := strings.TrimSuffix(raw, "d")
		n, err := strconv.Atoi(nStr)
		if err != nil || n <= 0 {
			return 0, err
		}
		return clampDuration(time.Duration(n)*24*time.Hour, minVal, maxVal), nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive")
	}
	return clampDuration(d, minVal, maxVal), nil
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

func (h *Handler) aggregateCertEvents(w http.ResponseWriter, r *http.Request) {
	resp := certEventsAggregateResponse{Buckets: []certEventsAggregateBucketResp{}}

	if h.certEvents == nil {
		resp.Degraded = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	window, err := parseDurationParam(
		r.URL.Query().Get("window"),
		certEventsAggregateDefaultWindow,
		certEventsAggregateMinWindow,
		certEventsAggregateMaxWindow,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, "window must be a positive duration (e.g. \"30d\", \"168h\")")
		return
	}

	interval, err := parseDurationParam(
		r.URL.Query().Get("interval"),
		certEventsAggregateDefaultInterval,
		certEventsAggregateMinInterval,
		certEventsAggregateMaxInterval,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, "interval must be a positive duration (e.g. \"1d\", \"1h\")")
		return
	}

	// Anchor the window's "to" boundary at the floor of the
	// current interval so consecutive calls within the same
	// bucket return identical aggregations — important for the
	// frontend's expected idempotent loading behaviour.
	now := time.Now().UTC()
	intervalSecs := int64(interval / time.Second)
	floored := time.Unix((now.Unix()/intervalSecs+1)*intervalSecs, 0).UTC()
	to := floored
	from := to.Add(-window)

	filter := observability.CertEventAggregateFilter{
		From:     from,
		To:       to,
		Interval: interval,
	}
	buckets, err := h.certEvents.AggregateCertEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("cert events aggregate: query failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "cert events aggregate unavailable")
		return
	}

	resp.Buckets = make([]certEventsAggregateBucketResp, 0, len(buckets))
	for _, b := range buckets {
		resp.Buckets = append(resp.Buckets, certEventsAggregateBucketResp{
			BucketStart: b.BucketStart.UTC().Format(timestampFormat),
			Issued:      b.Issued,
			Renewed:     b.Renewed,
			Failed:      b.Failed,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}
