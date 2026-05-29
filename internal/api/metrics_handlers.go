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
	"errors"
	"net/http"
	"time"

	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/storage"
)

// metricName is the enum of metrics the /metrics/timeseries
// endpoint accepts on the `metric` query parameter. Mirrors the
// four columns persisted in bucket_1m / bucket_1h.
type metricName string

const (
	metricReqPerSec    metricName = "req_per_sec"
	metricFourXxRate   metricName = "four_xx_rate"
	metricFiveXxRate   metricName = "five_xx_rate"
	metricP95LatencyMs metricName = "p95_latency_ms"
	// Step M.2 — WAF block rate as a count metric. Routes
	// through the existing timeseries handler unchanged
	// (gap-fill rule = 0 for missing buckets, same as the
	// other count metrics). p95 null semantics do NOT apply.
	metricWafBlockRate metricName = "waf_block_rate"
)

// timeseriesPoint is one point on the timeline. Value is *float64
// so the JSON encoder emits `null` for missing p95 buckets (the
// AC #5 anti-fake-dip rule — a "0 ms p95" rendered as a real data
// point would draw a fake latency dip). Count metrics use a real
// 0 (no traffic = "0 req/sec" is a valid measurement).
type timeseriesPoint struct {
	Ts    string   `json:"ts"`
	Value *float64 `json:"value"`
}

// timeseriesResponse is the wire shape of GET /metrics/timeseries.
// `disabled` is true iff the observability subsystem failed at
// boot (AC #13 degraded mode); the client renders an "empty"
// state instead of an error.
type timeseriesResponse struct {
	RouteID           string            `json:"routeId"`
	Metric            metricName        `json:"metric"`
	Window            string            `json:"window"`
	BucketSizeSeconds int               `json:"bucketSizeSeconds"`
	Disabled          bool              `json:"disabled,omitempty"`
	Points            []timeseriesPoint `json:"points"`
}

// summaryRoute is the per-route entry of the summary response.
type summaryRoute struct {
	RouteID          string `json:"routeId"`
	Host             string `json:"host"`
	ReqsPerMin       uint64 `json:"reqsPerMin"`
	FourxxPerMin     uint64 `json:"fourxxPerMin"`
	FivexxPerMin     uint64 `json:"fivexxPerMin"`
	WafBlockedPerMin uint64 `json:"wafBlockedPerMin"`
}

// summaryResponse is the wire shape of GET /metrics/summary.
// AC #6: 4xx and 5xx are EXPOSED SEPARATELY. The fields below
// are independent counters; no aggregate "errors" field exists.
//
// Step M.2 (spec §3.4):
//   - TotalWafBlockedPerMin: sum of waf_block_count across all
//     routes for the just-closed minute. Independent from the
//     L counters — a WAF block increments THIS field, not
//     TotalFourXxPerMin / TotalFiveXxPerMin (AC #3 / #4).
//   - WafBlocksByCategory: per-OWASP-category breakdown of the
//     events emitted during the same window. Populated by
//     querying waf_event grouped by category client-side; the
//     dashboard's category distribution strip reads this map
//     directly. Empty when the WAF event reader is unavailable
//     (degraded mode) OR when no events landed in the window.
//
// Step M.2 Spec-1 amendment:
//   - TopAttackedRoute: the single route with the highest
//     WAF block count over the window, computed across ALL
//     routes (NOT filtered to TopRoutes' traffic-ranked set).
//     Critical for the M.3 dashboard's "top route blocks/min"
//     headline: a targeted attack on a low-traffic admin /
//     auth surface — exactly the case that matters on an
//     internet-exposed proxy — would otherwise be invisible
//     because the route never reaches the traffic top-5.
//     Nullable: null when no WAF activity in the window
//     (operator sees an honest zero rather than an arbitrary
//     route forced into the slot).
type summaryResponse struct {
	GeneratedAt         string            `json:"generatedAt"`
	WindowSeconds       int               `json:"windowSeconds"`
	Disabled            bool              `json:"disabled,omitempty"`
	TotalReqPerMin      uint64            `json:"totalReqPerMin"`
	TotalFourXxPerMin   uint64            `json:"totalFourXxPerMin"`
	TotalFiveXxPerMin   uint64            `json:"totalFiveXxPerMin"`
	TotalWafBlockedPerMin uint64          `json:"totalWafBlockedPerMin"`
	GlobalP95LatencyMs  *float64          `json:"globalP95LatencyMs"` // null when no traffic
	ActiveRouteCount    int               `json:"activeRouteCount"`
	TopRoutes           []summaryRoute    `json:"topRoutes"`            // top 5 by reqsPerMin
	TopAttackedRoute    *summaryRoute     `json:"topAttackedRoute"`    // single highest WAF count, all routes; null if none
	WafBlocksByCategory map[string]uint64 `json:"wafBlocksByCategory"` // category → count; empty when no events
}

// routeAllSentinel selects the global aggregated timeseries (per
// Spec-1 §10.1). Sentinel rather than a separate endpoint to keep
// the URL surface tight — same query shape, same response shape,
// only the data source changes.
//
// Collision analysis: Route IDs are generated by uuid.NewString
// (storage/routes.go:CreateRoute) — v4 UUIDs in the canonical
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx form. "all" is 3 chars
// with no dashes; collision with a generated route ID is
// cryptographically impossible.
//
// The only theoretical path for a route with ID "all" is a
// tampered backup restore (storage/backup_apply.go preserves
// backup-supplied keys verbatim). The handler resolves the
// sentinel BEFORE the per-route 404 lookup, so route=all
// always hits the aggregate even if such a row exists; the
// route's data still flows into the aggregate via SUM. No
// security or data-integrity impact. Pinned by
// TestMetricsTimeseries_RouteAll_SentinelBeatsCollidingRoute.
const routeAllSentinel = "all"

// metricsTimeseries handles GET /api/v1/metrics/timeseries.
// Query parameters:
//   - route  : storage route UUID (per-route) OR "all"
//              (global aggregate, Spec-1 §10.1)
//   - metric : one of req_per_sec / four_xx_rate / five_xx_rate / p95_latency_ms
//   - window : 24h (returns 1-minute buckets) or 30d (1-hour buckets)
//
// Response on success: 200 with timeseriesResponse, gap-filled
// per AC #5 (0 for counts, null for p95).
//
// Degraded paths (AC #13):
//   - h.metrics == nil (observability boot failed) → 200 with
//     disabled=true and points=[]. The UI shows an empty state
//     instead of an error toast.
//   - Query returns an error (locked DB, etc.) → 503 with the
//     canonical error envelope.
func (h *Handler) metricsTimeseries(w http.ResponseWriter, r *http.Request) {
	routeID := r.URL.Query().Get("route")
	metric := metricName(r.URL.Query().Get("metric"))
	window := r.URL.Query().Get("window")

	if routeID == "" {
		writeError(w, http.StatusBadRequest, "route is required (use \"all\" for the global aggregate)")
		return
	}
	if !isValidMetric(metric) {
		writeError(w, http.StatusBadRequest, "metric must be one of req_per_sec, four_xx_rate, five_xx_rate, p95_latency_ms, waf_block_rate")
		return
	}
	gran, step, windowDur, ok := windowParams(window)
	if !ok {
		writeError(w, http.StatusBadRequest, "window must be 24h or 30d")
		return
	}

	aggregated := routeID == routeAllSentinel

	// 404 on unknown route ID. Skipped for the "all" sentinel
	// since it does not correspond to a stored route.
	if !aggregated {
		if _, err := h.store.GetRoute(r.Context(), routeID); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeError(w, http.StatusNotFound, "route not found")
				return
			}
			h.logger.Error("metrics: route lookup failed", "err", err, "route", routeID)
			writeError(w, http.StatusServiceUnavailable, "storage unavailable")
			return
		}
	}

	resp := timeseriesResponse{
		RouteID:           routeID, // echoed verbatim — "all" or the UUID
		Metric:            metric,
		Window:            window,
		BucketSizeSeconds: int(step.Seconds()),
		Points:            []timeseriesPoint{},
	}

	if h.metrics == nil {
		// AC #13 degraded mode: respond with disabled=true and
		// empty points so the frontend can render a clean empty
		// state ("metrics history unavailable") rather than a
		// hostile error toast. 200, not 503 — the data plane is
		// healthy; only the history is missing.
		resp.Disabled = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	now := time.Now().UTC()
	to := now.Truncate(step).Add(step) // exclusive upper bound, next bucket boundary
	from := to.Add(-windowDur)

	var (
		rows []observability.MetricBucket
		err  error
	)
	if aggregated {
		rows, err = h.metrics.QueryAggregated(r.Context(), gran, from, to)
	} else {
		rows, err = h.metrics.Query(r.Context(), gran, routeID, from, to)
	}
	if err != nil {
		h.logger.Error("metrics: query failed", "err", err, "route", routeID, "metric", metric)
		writeError(w, http.StatusServiceUnavailable, "metrics history unavailable")
		return
	}

	resp.Points = gapFillTimeseries(rows, from, to, step, metric)
	writeJSON(w, http.StatusOK, resp)
}

// metricsSummary handles GET /api/v1/metrics/summary. Aggregates
// the most recent minute across all routes, surfaces top-5 by
// traffic + global p95. AC #6: 4xx and 5xx fields are
// independent in the JSON (no collapse into "errors").
func (h *Handler) metricsSummary(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	bucketTs := now.Truncate(time.Minute).Add(-time.Minute) // the just-closed minute
	resp := summaryResponse{
		GeneratedAt:         now.Format(time.RFC3339),
		WindowSeconds:       60,
		TopRoutes:           []summaryRoute{},
		WafBlocksByCategory: map[string]uint64{},
	}

	if h.metrics == nil {
		resp.Disabled = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Pull all routes from BoltDB (route catalog is the
	// authority for what to surface; metrics.db may not have
	// rows for idle routes).
	routes, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("metrics: list routes failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "storage unavailable")
		return
	}

	type rowAgg struct {
		Host         string
		Req          uint64
		Fourxx       uint64
		Fivexx       uint64
		WafBlocked   uint64
		LatencyP95Ms int32
	}
	byID := make(map[string]*rowAgg, len(routes))
	for _, rt := range routes {
		byID[rt.ID] = &rowAgg{Host: rt.Host}
	}

	// One Query per route over the just-closed minute window.
	// On a homelab with <100 routes this is cheap (SQLite
	// indexed lookup per route). For larger deployments a
	// future endpoint could do one aggregate Query — out of
	// scope for L.2.
	from := bucketTs
	to := bucketTs.Add(time.Minute)
	var latencyWeightedSum, latencyWeightDen uint64
	for id := range byID {
		rows, qerr := h.metrics.Query(r.Context(), observability.Granularity1m, id, from, to)
		if qerr != nil {
			h.logger.Error("metrics: summary query failed", "err", qerr, "route", id)
			writeError(w, http.StatusServiceUnavailable, "metrics history unavailable")
			return
		}
		if len(rows) == 0 {
			continue
		}
		// Each route × minute has exactly 1 row (PRIMARY KEY).
		row := rows[0]
		agg := byID[id]
		agg.Req = uint64(row.ReqCount)
		agg.Fourxx = uint64(row.FourxxCount)
		agg.Fivexx = uint64(row.FivexxCount)
		agg.WafBlocked = uint64(row.WafBlockCount)
		agg.LatencyP95Ms = row.LatencyP95Ms
		resp.TotalReqPerMin += agg.Req
		resp.TotalFourXxPerMin += agg.Fourxx
		resp.TotalFiveXxPerMin += agg.Fivexx
		resp.TotalWafBlockedPerMin += agg.WafBlocked
		if row.LatencyP95Ms > 0 && row.ReqCount > 0 {
			latencyWeightedSum += uint64(row.LatencyP95Ms) * uint64(row.ReqCount)
			latencyWeightDen += uint64(row.ReqCount)
		}
	}

	if latencyWeightDen > 0 {
		v := float64(latencyWeightedSum) / float64(latencyWeightDen)
		resp.GlobalP95LatencyMs = &v
	}
	// resp.GlobalP95LatencyMs stays nil → JSON null per AC #5
	// when no traffic landed in the window.

	// Step M.2 — WafBlocksByCategory. Pulled from the per-event
	// log, NOT the bucket counter, because the bucket only knows
	// the total (waf_block_count) — categories live on each
	// event row. Single query over the just-closed minute,
	// grouped client-side. The reader may be nil (degraded
	// mode); in that case the map stays empty and the dashboard
	// renders its category strip as all zeros, which is the
	// honest "no data" answer.
	if h.wafEvents != nil {
		events, qerr := h.wafEvents.QueryWafEvents(r.Context(), observability.WafEventFilter{
			From:  from,
			To:    to,
			Limit: 100, // cap per spec §1.4 / handler-layer convention
		})
		if qerr != nil {
			h.logger.Error("metrics: summary waf_event query failed", "err", qerr)
			// Don't fail the whole summary on a WAF-event read
			// error: the bucket-side numbers are already
			// populated and useful. Leave the category map
			// empty + log; the operator can correlate via the
			// /security/events endpoint directly.
		} else {
			for _, e := range events {
				resp.WafBlocksByCategory[e.Category]++
			}
		}
	}

	// Build top-5 by reqsPerMin.
	top := make([]summaryRoute, 0, len(byID))
	for id, agg := range byID {
		if agg.Req == 0 {
			continue
		}
		resp.ActiveRouteCount++
		top = append(top, summaryRoute{
			RouteID:          id,
			Host:             agg.Host,
			ReqsPerMin:       agg.Req,
			FourxxPerMin:     agg.Fourxx,
			FivexxPerMin:     agg.Fivexx,
			WafBlockedPerMin: agg.WafBlocked,
		})
	}
	sortTopByReqs(top)
	if len(top) > 5 {
		top = top[:5]
	}
	resp.TopRoutes = top

	// Step M.2 amendment — TopAttackedRoute: the single route
	// with the highest WAF block count over the window,
	// computed across ALL routes (NOT filtered to the
	// traffic-ranked top-5). This is the headline for the M.3
	// dashboard's "top route blocks/min" card; the spec
	// §1.3 D8 wording is explicit ("top-attacked-route
	// blocks/min"). A targeted attack on a low-traffic admin
	// or auth surface — exactly the case that matters on an
	// internet-exposed proxy — would be invisible if we
	// constrained the ranking to TopRoutes. Walks byID once;
	// O(N) over the route catalog. Stays nil when no WAF
	// activity in the window (operator sees an honest zero).
	var topAttacked *summaryRoute
	for id, agg := range byID {
		if agg.WafBlocked == 0 {
			continue
		}
		if topAttacked == nil || agg.WafBlocked > topAttacked.WafBlockedPerMin {
			topAttacked = &summaryRoute{
				RouteID:          id,
				Host:             agg.Host,
				ReqsPerMin:       agg.Req,
				FourxxPerMin:     agg.Fourxx,
				FivexxPerMin:     agg.Fivexx,
				WafBlockedPerMin: agg.WafBlocked,
			}
		}
	}
	resp.TopAttackedRoute = topAttacked

	writeJSON(w, http.StatusOK, resp)
}

// --- helpers -----------------------------------------------------------------

func isValidMetric(m metricName) bool {
	switch m {
	case metricReqPerSec, metricFourXxRate, metricFiveXxRate, metricP95LatencyMs, metricWafBlockRate:
		return true
	}
	return false
}

func windowParams(window string) (gran observability.Granularity, step time.Duration, windowDur time.Duration, ok bool) {
	switch window {
	case "24h":
		return observability.Granularity1m, time.Minute, 24 * time.Hour, true
	case "30d":
		return observability.Granularity1h, time.Hour, 30 * 24 * time.Hour, true
	}
	return 0, 0, 0, false
}

// gapFillTimeseries projects sparse Store rows into a dense slice
// of timeseriesPoint covering [from, to) at the given step. The
// AC #5 gap-fill rule lives here:
//   - count metrics (req / 4xx / 5xx) → missing buckets emit 0
//   - p95 metric → missing buckets emit null (Value=nil)
//
// The map lookup makes the projection O(N+M) where N is the
// dense slot count and M is the row count.
func gapFillTimeseries(rows []observability.MetricBucket, from, to time.Time, step time.Duration, metric metricName) []timeseriesPoint {
	byTs := make(map[int64]observability.MetricBucket, len(rows))
	for _, r := range rows {
		byTs[r.Ts.Unix()] = r
	}
	slots := int(to.Sub(from) / step)
	out := make([]timeseriesPoint, 0, slots)
	for slot := 0; slot < slots; slot++ {
		ts := from.Add(time.Duration(slot) * step)
		row, hit := byTs[ts.Unix()]
		out = append(out, timeseriesPoint{
			Ts:    ts.Format(time.RFC3339),
			Value: pickMetricValue(row, hit, metric),
		})
	}
	return out
}

// pickMetricValue extracts the requested metric from a bucket
// row, applying the AC #5 null-for-p95-gap rule.
//
//	hit=false (missing bucket):
//	  counts → 0 (real measurement: zero traffic)
//	  p95    → nil (no traffic = no latency; nil renders as null)
//	hit=true:
//	  counts → row value as float64
//	  p95    → row value if > 0, else nil (the row exists but
//	           no latency observation landed in it; treat
//	           identically to a missing bucket)
func pickMetricValue(row observability.MetricBucket, hit bool, metric metricName) *float64 {
	if !hit {
		if metric == metricP95LatencyMs {
			return nil
		}
		v := 0.0
		return &v
	}
	switch metric {
	case metricReqPerSec:
		v := float64(row.ReqCount)
		return &v
	case metricFourXxRate:
		v := float64(row.FourxxCount)
		return &v
	case metricFiveXxRate:
		v := float64(row.FivexxCount)
		return &v
	case metricWafBlockRate:
		v := float64(row.WafBlockCount)
		return &v
	case metricP95LatencyMs:
		if row.LatencyP95Ms <= 0 {
			return nil
		}
		v := float64(row.LatencyP95Ms)
		return &v
	}
	return nil
}

// sortTopByReqs sorts the slice in-place by ReqsPerMin descending.
// Inline insertion sort — the slice is bounded by the number of
// active routes (typically <100 on a homelab); avoids importing
// sort just for one site.
func sortTopByReqs(s []summaryRoute) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].ReqsPerMin > s[j-1].ReqsPerMin; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
