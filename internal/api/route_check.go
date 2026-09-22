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
	writeErrorCode(w, http.StatusConflict, codeRouteCheckRolledBack,
		"the change was undone: the route answered before and stopped answering after it ("+failed.Detail+")",
		map[string]any{"host": failed.Host, "httpStatus": failed.HTTPStatus, "detail": failed.Detail})
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
