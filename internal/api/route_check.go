// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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
	"io"
	"net/http"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/routecheck"
	"github.com/barto95100/arenet/internal/storage"
)

// Post-apply route check (v2.35) — see
// docs/superpowers/specs/2026-09-21-route-post-apply-check-design.md.

// codeRouteCheckRolledBack: an update broke a working route and was
// undone.
const codeRouteCheckRolledBack = "route_check_rolled_back"

// routeCheckTimeout bounds the check + rollback work once detached
// from the request (two probe series + two reloads, worst case).
const routeCheckTimeout = 60 * time.Second

// detachedCheckContext returns a context that survives the client
// connection: the change is already applied, so the check — and a
// rollback — must finish even when the browser's connection died.
// That happens on every reload for a UI reached through Arenet over
// HTTP/3: Caddy's App.Stop cancels the grace context as soon as it
// returns, and quic-go then closes every open HTTP/3 connection
// (caddyhttp/app.go Stop, quic-go http3 Server.Shutdown).
func detachedCheckContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), routeCheckTimeout)
}

// RouteProber probes a route through the local Caddy listener.
type RouteProber interface {
	Probe(ctx context.Context, r storage.Route) routecheck.Result
}

// SetRouteProber wires the post-apply check; nil disables it.
func (h *Handler) SetRouteProber(p RouteProber) { h.routeProber = p }

// checkRoute probes r after a successful apply, honouring the setting.
func (h *Handler) checkRoute(ctx context.Context, r storage.Route) routecheck.Result {
	if h.routeProber == nil {
		return routecheck.Result{Status: routecheck.StatusSkipped, Detail: "route check unavailable"}
	}
	cfg, err := h.store.GetRouteCheckConfig(ctx)
	if err != nil {
		h.logger.Warn("route check: read setting", "err", err)
		return routecheck.Result{Status: routecheck.StatusSkipped, Detail: "route check setting unreadable"}
	}
	if !cfg.Enabled {
		return routecheck.Result{Status: routecheck.StatusSkipped, Detail: "route check disabled in settings"}
	}
	return h.routeProber.Probe(ctx, r)
}

// rollbackIfItFixes handles a failed check after an UPDATE: it puts the
// previous version back and probes it. If the previous version answers,
// the rollback stays (rolledBack true) — the change broke a working
// route. Otherwise the change is re-applied (the route was not working
// before either: e.g. the upstream is simply down) and only a warning
// remains. Returns the check to report.
func (h *Handler) rollbackIfItFixes(ctx context.Context, previous, updated storage.Route, failed routecheck.Result) (rolledBack bool, err error) {
	if _, err := h.store.UpdateRoute(ctx, previous); err != nil {
		return false, err
	}
	if err := h.caddy.ReloadFromStore(ctx); err != nil {
		// The previous version does not even load: back to the change.
		h.logger.Warn("route check: reload of the previous version failed; keeping the change", "err", err, "id", updated.ID)
		return false, h.reapply(ctx, updated)
	}
	if prev := h.checkRoute(ctx, previous); prev.Status == routecheck.StatusOK {
		h.logger.Warn("route check: the change broke a working route — rolled back",
			"id", updated.ID, "host", failed.Host, "status", failed.HTTPStatus, "detail", failed.Detail)
		return true, nil
	}
	return false, h.reapply(ctx, updated)
}

func (h *Handler) reapply(ctx context.Context, updated storage.Route) error {
	if _, err := h.store.UpdateRoute(ctx, updated); err != nil {
		return err
	}
	return h.caddy.ReloadFromStore(ctx)
}

// causeHealthCheck marks a rollback whose 503 came from the route's
// own active health check having just marked its upstreams down.
const causeHealthCheck = "health_check"

// causeMaybeHealthCheck: the upstreams are unavailable and this route
// has an active check, but the tracker has not recorded a verdict for
// them — so the probe is a candidate, not a conclusion.
//
// v2.45.1 — added because the confident branch missed the case it was
// built for. The operator pointed a probe at /toto, the route answered
// 503, and the message stayed generic: Arenet's tracker learns of a
// transition from a Caddy event, and the post-apply check can run
// before that event lands. Worse, on a freshly changed upstream the
// tracker has no history at all, by construction.
//
// Rather than widen the confident branch — which would have blamed
// the probe for a mistyped port — this names both places to look and
// says which is which.
const causeMaybeHealthCheck = "maybe_health_check"

// rollbackCause names what actually broke the route, so the operator
// is sent to the field that is wrong.
//
// v2.43.1 — a 503 on a route whose upstreams the active health check
// has just marked down is NOT an upstream-address mistake. The
// address is fine; the probe disagrees with the backend. Sending the
// operator to "fix the upstream address, port…" points them at the
// one screen where nothing is wrong. That is the wrong turn the
// 2026-09-24 session took, with the real cause — an expected-body
// regex that did not match the backend's JSON — three fields away.
//
// Why the change can look like the culprit when it is not: the fail
// counter lives on Caddy's pooled Host and survives config reloads
// (reverseproxy/hosts.go:176-181), while the unhealthy flag lives on
// Upstream and is rebuilt from JSON on every reload (hosts.go:65). A
// probe that was already failing before the change therefore starts
// from a nearly-full counter and can tip the upstream over on its
// very first run after it. The route genuinely answered before and
// genuinely stops after, and nothing about the change looks wrong.
func (h *Handler) rollbackCause(r storage.Route, failed routecheck.Result) string {
	if failed.HTTPStatus != http.StatusServiceUnavailable || !r.HealthCheck.Enabled {
		return ""
	}
	// h.hcStatus may be nil; computeRouteAggregateHealth treats that
	// as "unknown", which correctly declines to blame the probe.
	status, _, _ := computeRouteAggregateHealth(r, h.hcStatus)
	if status == routeStatusDown || status == routeStatusDegraded {
		return causeHealthCheck
	}
	// A 503 means reverse_proxy had no upstream to send to. With an
	// active check configured, the probe is the most common way that
	// happens — but the tracker may simply not have caught up, or the
	// upstream may have just changed and have no history. Both are
	// worth naming; neither is worth asserting.
	return causeMaybeHealthCheck
}

// writeRolledBack answers the 409 of an undone update and audits it.
func (h *Handler) writeRolledBack(w http.ResponseWriter, r *http.Request, previous, updated storage.Route, failed routecheck.Result) {
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteUpdateRolledBack,
		TargetType: "route",
		TargetID:   updated.ID,
		BeforeJSON: mustMarshalForAudit(routeForAudit(updated)),
		AfterJSON:  mustMarshalForAudit(routeForAudit(previous)),
		Message:    "status=" + string(failed.Status) + " detail=" + truncate(failed.Detail, 200),
	})
	details := map[string]any{"host": failed.Host, "httpStatus": failed.HTTPStatus, "detail": failed.Detail}
	message := "the change was undone: the route answered before and stopped answering after it (" + failed.Detail + ")"
	switch cause := h.rollbackCause(updated, failed); cause {
	case causeHealthCheck:
		details["cause"] = cause
		message += "; the active health check has marked the upstreams down — check its URI, " +
			"expected status and expected body rather than the upstream address"
	case causeMaybeHealthCheck:
		details["cause"] = cause
		message += "; no upstream was available. Check the backend itself, and this route's " +
			"active health check — a probe whose URI, expected status or expected body does " +
			"not match what the backend answers takes the route out of service even though " +
			"the backend is up"
	}
	writeErrorCode(w, http.StatusConflict, codeRouteCheckRolledBack, message, details)
}

// getRouteCheckConfig handles GET /settings/route-check.
func (h *Handler) getRouteCheckConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetRouteCheckConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the route check setting")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// putRouteCheckConfig handles PUT /settings/route-check.
func (h *Handler) putRouteCheckConfig(w http.ResponseWriter, r *http.Request) {
	var req storage.RouteCheckConfig
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	previous, _ := h.store.GetRouteCheckConfig(r.Context())
	if err := h.store.PutRouteCheckConfig(r.Context(), req); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save the route check setting")
		return
	}
	h.appendAudit(r, audit.Event{
		Action: audit.ActionRouteCheckUpdated, TargetType: "route_check", TargetID: "config",
		BeforeJSON: mustMarshalForAudit(previous), AfterJSON: mustMarshalForAudit(req),
	})
	writeJSON(w, http.StatusOK, req)
}
