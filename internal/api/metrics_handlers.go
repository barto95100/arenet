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

	"github.com/barto95100/arenet/internal/audit"
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
	// Step Q.3 — throttle block rate. Reads
	// bucket.ThrottleBlockCount, gap-filled with 0. Spec §3.5:
	// throttle blocks aggregate under the sentinel
	// route_id="_throttle"; the handler enforces that, so
	// route=<uuid> returns all zeros (the bucket has no data
	// at that key).
	metricThrottleBlockRate metricName = "throttle_block_rate"
	// Step Q.3 — auth failure rate. SPECIAL-CASED: detours
	// through the AuthFailureReader.QueryByActionRange path
	// (spec D4.B single source of truth) rather than reading
	// a bucket column. The audit log is the canonical source;
	// no bucket counter exists for this metric. Handler
	// projects the audit-scan to the same {points: [{ts,
	// value}]} wire shape as the bucket metrics, gap-filled
	// with 0.
	metricAuthFailureRate metricName = "auth_failure_rate"
	// Step N.3 — crowdsec decision rate. Reads
	// bucket.CrowdSecDecisionCount, gap-filled with 0. Same
	// shape as throttle_block_rate. Spec N §3.5: decisions
	// aggregate under the sentinel route_id="_crowdsec".
	// The dashboard passes route=all (the
	// QueryAggregated path SUMs across all routes including
	// the sentinel — same trick as Q.4 uses for throttle).
	// route=<uuid> returns all zeros (no per-route concept
	// for CrowdSec decisions, mirror of AC #10 for throttle).
	metricCrowdSecDecisionRate metricName = "crowdsec_decision_rate"
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
	// #R-DASHBOARD-WAF-COUNTERS-ZERO — sibling of
	// WafBlockedPerMin populated from the new
	// waf_detect_count bucket column. Dashboard Top
	// Routes renders this in a parallel column so an
	// operator on the recommended detect-mode default
	// sees real per-route attack volume instead of a
	// row of zeros.
	WafDetectedPerMin uint64 `json:"wafDetectedPerMin"`
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
	GeneratedAt           string `json:"generatedAt"`
	WindowSeconds         int    `json:"windowSeconds"`
	Disabled              bool   `json:"disabled,omitempty"`
	TotalReqPerMin        uint64 `json:"totalReqPerMin"`
	TotalFourXxPerMin     uint64 `json:"totalFourXxPerMin"`
	TotalFiveXxPerMin     uint64 `json:"totalFiveXxPerMin"`
	TotalWafBlockedPerMin uint64 `json:"totalWafBlockedPerMin"`
	// #R-DASHBOARD-WAF-COUNTERS-ZERO — sibling counter
	// sourced from waf_detect_count bucket column. Lets
	// the dashboard show two cards (BLOQUÉ red /
	// DÉTECTÉ amber) so a homelab operator on
	// wafMode=detect (the recommended I.4 default) sees
	// real attack volume even when no requests were
	// actually blocked.
	TotalWafDetectedPerMin uint64 `json:"totalWafDetectedPerMin"`
	// Step Q.3 new fields per AC #11. Independent counters,
	// same shape contract as TotalWafBlockedPerMin (a throttle
	// block does NOT inflate the 4xx / 5xx fields, AC #15
	// anti-regression).
	TotalThrottlePerMin     uint64 `json:"totalThrottlePerMin"`
	TotalAuthFailuresPerMin uint64 `json:"totalAuthFailuresPerMin"`
	AttackerIpsUnique       int    `json:"attackerIpsUnique"` // union over WAF + throttle + audit + crowdsec, just-closed minute
	// Step N.3 new fields. Same independence contract as the
	// Q.3 trio above: a CrowdSec decision arriving in the
	// minute does NOT inflate 4xx / 5xx / waf_block_count /
	// throttle_block_count (AC #N.24 declared-divergence note:
	// the data-plane 403 emitted BY a CrowdSec block IS
	// counted in fourxx_count because hslatman's bouncer has
	// no callback to flag the request, but the BUCKET counter
	// `crowdsec_decision_count` populated here is the pure
	// CrowdSec signal — operator dashboard reads from this).
	TotalCrowdSecDecisionsPerMin uint64 `json:"totalCrowdSecDecisionsPerMin"`
	// ActiveCrowdSecIpsUnique counts distinct decision `value`
	// strings (IP / CIDR / country / AS) in the
	// decision_event table over the just-closed minute. Same
	// caveat as attackersByBucketSource.CrowdSec: includes
	// non-IP scopes intentionally.
	ActiveCrowdSecIpsUnique int               `json:"activeCrowdSecIpsUnique"`
	GlobalP95LatencyMs      *float64          `json:"globalP95LatencyMs"` // null when no traffic
	ActiveRouteCount        int               `json:"activeRouteCount"`
	TopRoutes               []summaryRoute    `json:"topRoutes"`           // top 5 by reqsPerMin
	TopAttackedRoute        *summaryRoute     `json:"topAttackedRoute"`    // single highest WAF count, all routes; null if none
	WafBlocksByCategory     map[string]uint64 `json:"wafBlocksByCategory"` // category → count of action=BLOCK events; empty when no events
	// #R-DASHBOARD-WAF-COUNTERS-ZERO — sibling map for
	// action=DETECT events. Semantically distinct from
	// WafBlocksByCategory: the two report DIFFERENT
	// populations (block-mode vs detect-mode rule
	// fires). Operators wanting a combined attack-
	// volume view sum the two maps client-side. Pre-fix
	// WafBlocksByCategory silently aggregated both
	// populations under a misleading name; this commit
	// tightens its semantics to BLOCK-only.
	WafDetectsByCategory map[string]uint64 `json:"wafDetectsByCategory"` // category → count of action=DETECT events; empty when no events
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
//     (global aggregate, Spec-1 §10.1)
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
		writeError(w, http.StatusBadRequest, "metric must be one of req_per_sec, four_xx_rate, five_xx_rate, p95_latency_ms, waf_block_rate, throttle_block_rate, auth_failure_rate, crowdsec_decision_rate")
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

	now := time.Now().UTC()
	to := now.Truncate(step).Add(step) // exclusive upper bound, next bucket boundary
	from := to.Add(-windowDur)

	// Step Q.3 — auth_failure_rate is special-cased per spec
	// D4.B + AC #10: the data lives in the audit log, not in
	// metrics.db. Detour through the AuthFailureReader and
	// return early. Per AC #10, the per-route variant is
	// "N/A — neither signal is per-route, so route=<uuid>
	// returns all-zero". The "all" sentinel returns the real
	// system-wide audit-scan projection.
	if metric == metricAuthFailureRate {
		if !aggregated {
			// route=<uuid>: return the dense zero-filled
			// timeseries WITHOUT scanning audit. AC #10
			// literal contract.
			resp.Points = gapFillAuthFailureZero(from, to, step)
			writeJSON(w, http.StatusOK, resp)
			return
		}
		if h.authFailures == nil {
			// AC #14 degraded shape mirror.
			resp.Disabled = true
			writeJSON(w, http.StatusOK, resp)
			return
		}
		events, _, err := h.authFailures.QueryByActionRange(
			r.Context(),
			audit.AuthFailureActions(),
			from, to,
			authFailuresScanCap,
		)
		if err != nil {
			h.logger.Error("metrics: auth-failure scan failed", "err", err, "window", window)
			writeError(w, http.StatusServiceUnavailable, "metrics history unavailable")
			return
		}
		resp.Points = gapFillAuthFailureTimeseries(events, from, to, step)
		writeJSON(w, http.StatusOK, resp)
		return
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
		GeneratedAt:          now.Format(time.RFC3339),
		WindowSeconds:        60,
		TopRoutes:            []summaryRoute{},
		WafBlocksByCategory:  map[string]uint64{},
		WafDetectsByCategory: map[string]uint64{},
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
		WafDetected  uint64
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
		agg.WafDetected = uint64(row.WafDetectCount)
		agg.LatencyP95Ms = row.LatencyP95Ms
		resp.TotalReqPerMin += agg.Req
		resp.TotalFourXxPerMin += agg.Fourxx
		resp.TotalFiveXxPerMin += agg.Fivexx
		resp.TotalWafBlockedPerMin += agg.WafBlocked
		resp.TotalWafDetectedPerMin += agg.WafDetected
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
			// #R-DASHBOARD-WAF-COUNTERS-ZERO — dispatch by
			// action. Pre-fix this loop incremented
			// WafBlocksByCategory unconditionally, which made
			// the map a misleading aggregate (block + detect
			// rows under a name claiming blocks-only). Post-
			// fix the two populations are reported on
			// separate maps; operators wanting the combined
			// view sum them client-side. Event rows with an
			// unexpected Action ("", future enum value) are
			// dropped silently — the W.bugfix v6→v7
			// migration backfilled every legacy row to
			// "BLOCK", so an empty Action would indicate a
			// data-layer bug we'd rather surface as a
			// missing category count than mis-categorise.
			for _, e := range events {
				switch e.Action {
				case "BLOCK":
					resp.WafBlocksByCategory[e.Category]++
				case "DETECT":
					resp.WafDetectsByCategory[e.Category]++
				}
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
			RouteID:           id,
			Host:              agg.Host,
			ReqsPerMin:        agg.Req,
			FourxxPerMin:      agg.Fourxx,
			FivexxPerMin:      agg.Fivexx,
			WafBlockedPerMin:  agg.WafBlocked,
			WafDetectedPerMin: agg.WafDetected,
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
				RouteID:           id,
				Host:              agg.Host,
				ReqsPerMin:        agg.Req,
				FourxxPerMin:      agg.Fourxx,
				FivexxPerMin:      agg.Fivexx,
				WafBlockedPerMin:  agg.WafBlocked,
				WafDetectedPerMin: agg.WafDetected,
			}
		}
	}
	resp.TopAttackedRoute = topAttacked

	// Step Q.3 — TotalThrottlePerMin: read the sentinel
	// route's bucket row for the just-closed minute. The
	// observability aggregator stores throttle blocks under
	// route_id = "_throttle" (spec §3.5); the per-route loop
	// above doesn't iterate this sentinel because it's not in
	// the storage.Route catalog. A targeted Query keeps the
	// summary cheap (1 SQLite indexed lookup).
	throttleRows, qerr := h.metrics.Query(r.Context(), observability.Granularity1m,
		observability.ThrottleSentinelRouteID, from, to)
	if qerr != nil {
		h.logger.Error("metrics: summary throttle sentinel query failed", "err", qerr)
		// Same trade-off as WafBlocksByCategory: don't fail
		// the whole summary; the L counters + WAF total are
		// useful on their own. Leave TotalThrottlePerMin=0.
	} else if len(throttleRows) > 0 {
		resp.TotalThrottlePerMin = uint64(throttleRows[0].ThrottleBlockCount)
	}

	// Step N.3 — TotalCrowdSecDecisionsPerMin: read the
	// CrowdSec sentinel row (spec N §3.5: "_crowdsec"). Same
	// pattern as TotalThrottlePerMin above. Independent of
	// the throttle counter; AC #N.24 anti-regression: a
	// CrowdSec decision does NOT inflate
	// totalThrottlePerMin and vice versa.
	crowdsecRows, qerr := h.metrics.Query(r.Context(), observability.Granularity1m,
		observability.CrowdSecSentinelRouteID, from, to)
	if qerr != nil {
		h.logger.Error("metrics: summary crowdsec sentinel query failed", "err", qerr)
		// Leave TotalCrowdSecDecisionsPerMin=0 — same
		// trade-off as the throttle sentinel above.
	} else if len(crowdsecRows) > 0 {
		resp.TotalCrowdSecDecisionsPerMin = uint64(crowdsecRows[0].CrowdSecDecisionCount)
	}

	// Step Q.3 — TotalAuthFailuresPerMin: audit-scan over the
	// just-closed minute (D4.B single source of truth — no
	// bucket counter for this metric). Same scan-cap discipline
	// as /security/auth-failures (200) but a 1-minute window
	// is tiny in practice; the cap is only the safety net.
	if h.authFailures != nil {
		events, _, aerr := h.authFailures.QueryByActionRange(r.Context(),
			audit.AuthFailureActions(), from, to, authFailuresScanCap)
		if aerr != nil {
			h.logger.Error("metrics: summary audit auth-failure scan failed", "err", aerr)
		} else {
			resp.TotalAuthFailuresPerMin = uint64(len(events))
		}
	}

	// Step Q.3 — AttackerIpsUnique: server-side union of WAF
	// + throttle + audit source IPs over the just-closed
	// minute. Same shape as /security/attackers-summary minus
	// the per-source breakdown (the summary endpoint only
	// surfaces the union count). Empty IPs filtered the same
	// way (defence-in-depth on the spec §8.5 case).
	attackers := make(map[string]struct{})
	if h.wafEvents != nil {
		ips, werr := h.wafEvents.DistinctWafEventSrcIPs(r.Context(), from, to)
		if werr != nil {
			h.logger.Error("metrics: summary waf distinct ip query failed", "err", werr)
		} else {
			for _, ip := range ips {
				if ip == "" {
					continue
				}
				attackers[ip] = struct{}{}
			}
		}
	}
	if h.throttleEvents != nil {
		ips, terr := h.throttleEvents.DistinctThrottleEventSrcIPs(r.Context(), from, to)
		if terr != nil {
			h.logger.Error("metrics: summary throttle distinct ip query failed", "err", terr)
		} else {
			for _, ip := range ips {
				if ip == "" {
					continue
				}
				attackers[ip] = struct{}{}
			}
		}
	}
	if h.authFailures != nil {
		events, _, aerr := h.authFailures.QueryByActionRange(r.Context(),
			audit.AuthFailureActions(), from, to, authFailuresScanCap)
		if aerr != nil {
			// Already logged above for TotalAuthFailuresPerMin.
		} else {
			for _, e := range events {
				if e.IP == "" {
					continue
				}
				attackers[e.IP] = struct{}{}
			}
		}
	}
	// Step N.3 — CrowdSec arm of the union + the
	// ActiveCrowdSecIpsUnique count. Same shape as the WAF /
	// throttle distinct-IP branches: storage SELECT DISTINCT
	// value over the window.
	if h.decisions != nil {
		ips, derr := h.decisions.DistinctDecisionSrcIPs(r.Context(), from, to)
		if derr != nil {
			h.logger.Error("metrics: summary decision distinct ip query failed", "err", derr)
		} else {
			// Count first (pre-union) for the per-source
			// dashboard card, then merge into the union.
			activeCrowdSecCount := 0
			for _, ip := range ips {
				if ip == "" {
					continue
				}
				activeCrowdSecCount++
				attackers[ip] = struct{}{}
			}
			resp.ActiveCrowdSecIpsUnique = activeCrowdSecCount
		}
	}
	resp.AttackerIpsUnique = len(attackers)

	writeJSON(w, http.StatusOK, resp)
}

// --- helpers -----------------------------------------------------------------

func isValidMetric(m metricName) bool {
	switch m {
	case metricReqPerSec, metricFourXxRate, metricFiveXxRate, metricP95LatencyMs,
		metricWafBlockRate, metricThrottleBlockRate, metricAuthFailureRate,
		metricCrowdSecDecisionRate:
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

// gapFillAuthFailureTimeseries projects a slice of audit
// events (reverse-chronological, action-filtered by the
// caller) into a dense timeseries of count-per-step buckets
// over [from, to). Step Q.3: powers the
// /metrics/timeseries?metric=auth_failure_rate detour. The
// 24h window uses step=1m (1440 buckets), the 30d window uses
// step=1h (720 buckets). Same gap-fill rule as the count
// metrics: empty bucket emits 0 (not nil).
//
// Mirror of projectAuthFailureTimeseries in
// security_handlers.go, generalised for variable step. Kept
// separate so the auth-failures dashboard endpoint stays
// per-minute-only (its frontend chart depends on it) while
// the /metrics/timeseries endpoint can serve both
// granularities through the same path.
func gapFillAuthFailureTimeseries(events []audit.Event, from, to time.Time, step time.Duration) []timeseriesPoint {
	fromBucket := from.UTC().Truncate(step)
	toBucket := to.UTC().Truncate(step)
	if !toBucket.After(fromBucket) {
		return []timeseriesPoint{}
	}
	bucketCount := int(toBucket.Sub(fromBucket) / step)
	if bucketCount <= 0 {
		return []timeseriesPoint{}
	}
	counts := make([]int, bucketCount)
	for _, e := range events {
		ts := e.Timestamp.UTC().Truncate(step)
		if ts.Before(fromBucket) || !ts.Before(toBucket) {
			continue
		}
		idx := int(ts.Sub(fromBucket) / step)
		if idx < 0 || idx >= bucketCount {
			continue
		}
		counts[idx]++
	}
	out := make([]timeseriesPoint, bucketCount)
	for i := 0; i < bucketCount; i++ {
		v := float64(counts[i])
		out[i] = timeseriesPoint{
			Ts:    fromBucket.Add(time.Duration(i) * step).Format(time.RFC3339),
			Value: &v,
		}
	}
	return out
}

// gapFillAuthFailureZero is the all-zero variant of
// gapFillAuthFailureTimeseries — used when route=<uuid> for
// the auth_failure_rate metric (AC #10 "per-route returns
// all-zero"). Cheap: skip the events scan entirely.
func gapFillAuthFailureZero(from, to time.Time, step time.Duration) []timeseriesPoint {
	fromBucket := from.UTC().Truncate(step)
	toBucket := to.UTC().Truncate(step)
	if !toBucket.After(fromBucket) {
		return []timeseriesPoint{}
	}
	bucketCount := int(toBucket.Sub(fromBucket) / step)
	if bucketCount <= 0 {
		return []timeseriesPoint{}
	}
	out := make([]timeseriesPoint, bucketCount)
	for i := 0; i < bucketCount; i++ {
		v := 0.0
		out[i] = timeseriesPoint{
			Ts:    fromBucket.Add(time.Duration(i) * step).Format(time.RFC3339),
			Value: &v,
		}
	}
	return out
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
	case metricThrottleBlockRate:
		v := float64(row.ThrottleBlockCount)
		return &v
	case metricCrowdSecDecisionRate:
		v := float64(row.CrowdSecDecisionCount)
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
