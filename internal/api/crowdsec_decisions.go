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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// Step CS.2.A — Live LAPI decisions proxy.
//
// GET /api/v1/security/crowdsec/decisions
//
// Purpose: source of truth for "what is being enforced RIGHT
// NOW". Distinct from /api/v1/security/decisions (Step N.3)
// which serves the local snapshot from metrics.db (decision_
// event table populated by the bouncer sink — freshness
// bounded by the sink's batch interval + the bouncer's
// stream-poll cadence).
//
// The two endpoints answer different questions:
//
//   - /security/decisions (local mirror)
//       "What decisions has Arenet seen historically?"
//       Cumulative, persisted across restarts, never blocks
//       on a LAPI hiccup. Fed by the StreamBouncer.
//
//   - /security/crowdsec/decisions (this endpoint)
//       "What is LAPI enforcing this exact moment?"
//       Live pass-through; if LAPI is unreachable we 502 and
//       the UI displays a clear retry affordance. Useful for
//       'is my new ban actually live?' verification.
//
// Implementation choice: pass-through proxy rather than
// wrapping the apiclient SDK. The SDK opens a long-lived
// HTTP/2 connection optimised for streaming + retries; we
// only want a single short-poll GET per UI refresh, so a
// stdlib http.Client with the stored creds + the test-probe
// auth header pattern (CS.1) is the right tool. Less code,
// no dependency on the apiclient's pool internals, identical
// error classification path as the Test connection probe.
//
// Filtering: LAPI's /v1/decisions accepts scope/value/type/
// ip/range (DecisionsListOpts, github.com/crowdsecurity/
// crowdsec/pkg/apiclient/decisions_service.go). It does NOT
// accept an origin filter (only /v1/alerts does). So source
// filtering is applied CLIENT-SIDE in this handler before
// pagination. Same logic for pagination — LAPI returns the
// full active set in one response; we slice for limit/offset.

// lapiDecision is the wire shape Arenet's frontend consumes.
// Mirrors github.com/crowdsecurity/crowdsec/pkg/models.
// Decision (Required: true on Duration/Origin/Scenario/Scope/
// Type/Value per the swagger), with camelCase JSON for parity
// with the existing /security/decisions response. The fields
// kept are exactly what the UI renders — id/duration/origin/
// scenario/scope/type/value + computed expiresAt.
type lapiDecision struct {
	// ID is LAPI's internal autoincrement (int64, not uuid).
	// Useful for the UI as a row key only; not stable across
	// LAPI restarts.
	ID int64 `json:"id"`
	// Duration is the original ban duration string, e.g.
	// "1h", "4h", "24h", "168h". Operator-readable; the UI
	// renders Expires (computed below) for live countdown.
	Duration string `json:"duration"`
	// Origin is LAPI's source identifier. Common values:
	//   "CAPI"        — community consensus blocklist
	//   "lists:<...>" — blocklist subscriptions
	//   "crowdsec"    — local scenario fire
	//   "cscli"       — manual ban / `cscli decisions add`
	// Reserved here so the frontend can filter by source.
	Origin string `json:"origin"`
	// Scenario is the full scenario identifier when Origin
	// is "crowdsec" or "cscli" (e.g.
	// "crowdsecurity/http-cve" / "manual"). For CAPI /
	// list-sourced decisions it's typically a placeholder
	// or the originating list name.
	Scenario string `json:"scenario"`
	// Scope: ip / range / country / as.
	Scope string `json:"scope"`
	// Type: ban / captcha / throttle.
	Type string `json:"type"`
	// Value is the decision's target — IP / CIDR / country
	// code / AS number — interpreted per Scope.
	Value string `json:"value"`
	// ExpiresAt is computed server-side from LAPI's `until`
	// field (or, when absent, by adding Duration to the
	// time the decision was observed). RFC3339, UTC.
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// lapiDecisionsResponse is the wire envelope the UI binds to.
// `totalBeforeFilter` is the raw size of LAPI's response; the
// `total` field on `meta` reflects what the UI is showing
// AFTER source filter (since LAPI doesn't filter by origin
// server-side). Both fields surfaced so the breakdown badges
// can compute "X CAPI · Y manual · Z scenario" accurately.
type lapiDecisionsResponse struct {
	Decisions []lapiDecision    `json:"decisions"`
	Meta      lapiDecisionsMeta `json:"meta"`
}

type lapiDecisionsMeta struct {
	// Total is the count AFTER origin filter, BEFORE pagination.
	Total int `json:"total"`
	// TotalByOrigin maps Origin → count over the full LAPI
	// response (the UI displays "47 CAPI · 3 LAPI · 2 manual"
	// breakdown independent of the active filter).
	TotalByOrigin map[string]int `json:"totalByOrigin"`
	// Limit + Offset echo what the handler applied for client
	// transparency (LAPI sent us N, we returned [offset:offset+limit]).
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// crowdSecDecisionsListMax caps how many decisions the
// handler will return in a single response. Matches the
// existing /security/decisions cap (Step N.4) so the UI's
// row-rendering budget stays predictable. The LAPI response
// itself can be much larger (~50k decisions on a community-
// blocklist-heavy install); the slice happens server-side
// so we don't ship 5 MB of JSON to the browser.
const crowdSecDecisionsListMax = 100

// listCrowdSecDecisions serves
// GET /api/v1/security/crowdsec/decisions
//
// Query params (all optional):
//   scope=<ip|range|country|as>    — server-side filter
//                                     (forwarded to LAPI)
//   source=<CAPI|crowdsec|cscli|…> — client-side filter
//                                     (LAPI has no origin
//                                     query param, so we
//                                     filter after fetch)
//   type=<ban|captcha|throttle>   — server-side filter
//   limit=<1..100>                 — pagination cap
//   offset=<0..>                    — pagination offset
//
// Response codes:
//   200 OK       — happy path, decisions array possibly empty
//   404 Not Found — bouncer not configured (no stored creds
//                   AND no env var). Distinct from "configured
//                   but unreachable" → 502.
//   502 Bad Gateway — LAPI unreachable (timeout / refused /
//                     DNS / TLS). Body carries a friendly
//                     error message.
//   500 Internal Server Error — storage read failed.
func (h *Handler) listCrowdSecDecisions(w http.ResponseWriter, r *http.Request) {
	// Resolve stored creds. AC #15 contract (mirror of the
	// Test Connection handler): an unconfigured bouncer
	// is a 404 with an operator-actionable message, NOT a
	// 500. The UI binds to the 404 → "Configure CrowdSec"
	// CTA that links to /settings.
	cfg, err := h.store.GetCrowdSecConfig(r.Context())
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		h.logger.Error("get crowdsec config (decisions list)", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load crowdsec config")
		return
	}
	if errors.Is(err, storage.ErrNotFound) || strings.TrimSpace(cfg.APIKey) == "" {
		writeError(w, http.StatusNotFound, "crowdsec bouncer not configured")
		return
	}

	// Parse + validate query params.
	q := r.URL.Query()
	scope := strings.TrimSpace(q.Get("scope"))
	sourceFilter := strings.TrimSpace(q.Get("source"))
	typeFilter := strings.TrimSpace(q.Get("type"))

	limit, offset, perr := parseLimitOffset(q.Get("limit"), q.Get("offset"))
	if perr != nil {
		writeError(w, http.StatusBadRequest, perr.Error())
		return
	}

	// Compose LAPI URL. Forward scope + type server-side
	// (LAPI native), leave origin to the client-side slice
	// below.
	probeURL := strings.TrimRight(cfg.LAPIURL, "/") + "/v1/decisions"
	qs := url.Values{}
	if scope != "" {
		qs.Set("scope", scope)
	}
	if typeFilter != "" {
		qs.Set("type", typeFilter)
	}
	if len(qs) > 0 {
		probeURL += "?" + qs.Encode()
	}

	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > 60*time.Second {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	req.Header.Set("X-Api-Key", cfg.APIKey)
	req.Header.Set("User-Agent", "arenet/crowdsec-decisions")

	resp, doErr := http.DefaultClient.Do(req)
	if doErr != nil {
		// Reuse the friendly classifier from the Test handler
		// (timeout / refused / DNS / TLS).
		writeError(w, http.StatusBadGateway, classifyProbeError(doErr, cfg.APIKey))
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		// happy paths
	case http.StatusUnauthorized, http.StatusForbidden:
		writeError(w, http.StatusBadGateway, "authentication failed (invalid bouncer API key)")
		return
	default:
		writeError(w, http.StatusBadGateway, fmt.Sprintf("LAPI returned unexpected status %d", resp.StatusCode))
		return
	}

	// 204 No Content from LAPI is the documented "no active
	// decisions" signal. Surface as empty array + zero totals
	// rather than a separate no-content semantic (the UI's
	// empty state is the same shape).
	var raw []rawDecision
	if resp.StatusCode == http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // 16 MiB cap
		if readErr != nil {
			writeError(w, http.StatusBadGateway, "failed to read LAPI response")
			return
		}
		if len(body) > 0 && body[0] == '[' {
			if err := json.Unmarshal(body, &raw); err != nil {
				h.logger.Error("crowdsec decisions: unmarshal LAPI body", "err", err)
				writeError(w, http.StatusBadGateway, "malformed LAPI response")
				return
			}
		}
		// `null` body (LAPI's representation of empty when
		// strict-typed clients are expected) → leave raw as
		// zero-value, no error.
	}

	// Project into Arenet's wire shape + compute ExpiresAt.
	// Default Origin to "unknown" so the breakdown counter
	// never displays a blank label.
	all := make([]lapiDecision, 0, len(raw))
	for _, d := range raw {
		all = append(all, projectLAPIDecision(d))
	}

	// Per-origin breakdown over the FULL response (operator
	// wants the totals badge to reflect reality, not the
	// currently-filtered view).
	byOrigin := make(map[string]int, 8)
	for _, d := range all {
		key := d.Origin
		if key == "" {
			key = "unknown"
		}
		byOrigin[key]++
	}

	// Client-side source filter (LAPI doesn't accept origin).
	if sourceFilter != "" {
		filtered := all[:0:cap(all)]
		for _, d := range all {
			if d.Origin == sourceFilter {
				filtered = append(filtered, d)
			}
		}
		all = filtered
	}

	totalAfterFilter := len(all)

	// Paginate. offset >= len = empty page (not an error;
	// matches the existing per-route metrics handler's
	// idempotent shape).
	pageStart := offset
	if pageStart > totalAfterFilter {
		pageStart = totalAfterFilter
	}
	pageEnd := pageStart + limit
	if pageEnd > totalAfterFilter {
		pageEnd = totalAfterFilter
	}
	page := all[pageStart:pageEnd]

	out := lapiDecisionsResponse{
		Decisions: page,
		Meta: lapiDecisionsMeta{
			Total:         totalAfterFilter,
			TotalByOrigin: byOrigin,
			Limit:         limit,
			Offset:        offset,
		},
	}
	writeJSON(w, http.StatusOK, out)
}

// rawDecision is the unmarshalling target for LAPI's
// /v1/decisions response. Pointer fields per the swagger
// (Required: true), nil-safe accessor in projectLAPIDecision.
type rawDecision struct {
	ID        int64   `json:"id"`
	Duration  *string `json:"duration"`
	Origin    *string `json:"origin"`
	Scenario  *string `json:"scenario"`
	Scope     *string `json:"scope"`
	Type      *string `json:"type"`
	Value     *string `json:"value"`
	Until     string  `json:"until,omitempty"`
	UUID      string  `json:"uuid,omitempty"`
	Simulated *bool   `json:"simulated,omitempty"`
}

// projectLAPIDecision converts the raw swagger pointers into
// the Arenet wire shape, computing ExpiresAt from `until` (if
// present) or by adding Duration to now. The fallback path is
// best-effort — LAPI usually emits `until` on responses; the
// `duration`-only path is for ancient versions / non-standard
// responses.
func projectLAPIDecision(d rawDecision) lapiDecision {
	out := lapiDecision{
		ID:       d.ID,
		Duration: deref(d.Duration),
		Origin:   deref(d.Origin),
		Scenario: deref(d.Scenario),
		Scope:    deref(d.Scope),
		Type:     deref(d.Type),
		Value:    deref(d.Value),
	}
	if d.Until != "" {
		// LAPI emits `until` as RFC3339 or RFC3339Nano —
		// re-parse + re-emit canonical to keep the UI's
		// countdown logic identical across the proxy + the
		// existing /security/decisions endpoint.
		if t, perr := time.Parse(time.RFC3339Nano, d.Until); perr == nil {
			out.ExpiresAt = t.UTC().Format(timestampFormat)
		} else if t, perr := time.Parse(time.RFC3339, d.Until); perr == nil {
			out.ExpiresAt = t.UTC().Format(timestampFormat)
		} else {
			// Pass through verbatim if we can't parse; the
			// UI will render it as a string with no countdown.
			out.ExpiresAt = d.Until
		}
	} else if out.Duration != "" {
		if dur, derr := time.ParseDuration(out.Duration); derr == nil {
			out.ExpiresAt = time.Now().UTC().Add(dur).Format(timestampFormat)
		}
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// parseLimitOffset extracts + validates pagination params.
// Defaults: limit=100, offset=0. Empty strings are accepted
// as defaults. Negative or > max → 400.
func parseLimitOffset(limitRaw, offsetRaw string) (int, int, error) {
	limit := crowdSecDecisionsListMax
	offset := 0
	if limitRaw != "" {
		v, err := strconv.Atoi(limitRaw)
		if err != nil || v < 1 || v > crowdSecDecisionsListMax {
			return 0, 0, fmt.Errorf("limit must be in [1, %d]", crowdSecDecisionsListMax)
		}
		limit = v
	}
	if offsetRaw != "" {
		v, err := strconv.Atoi(offsetRaw)
		if err != nil || v < 0 {
			return 0, 0, fmt.Errorf("offset must be >= 0")
		}
		offset = v
	}
	return limit, offset, nil
}
