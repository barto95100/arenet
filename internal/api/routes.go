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
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// NewRouter builds the chi router for the admin API. When dev is true a
// permissive CORS middleware is mounted for http://localhost:5173.
//
// Step D wires the IP extractor near the top (after Recoverer) so
// every downstream handler reads the resolved IP from context. The
// /api/v1/auth/* subtree is then rate-limited per-IP; business
// endpoints under /api/v1 stay unrated (authenticated callers are
// trusted per spec §5.2).
//
// Step E adds the optional ws handler: when non-nil, it is mounted
// at GET /api/v1/ws/topology inside the hard-auth subgroup
// (spec §5.1 + §7.1). Tests that do not exercise the topology
// endpoint pass nil — the route is then simply not registered.
func NewRouter(h *Handler, dev bool, ipExtractor *auth.IPExtractor, ws *WSTopologyHandler) chi.Router {
	if ipExtractor == nil {
		panic("api.NewRouter: ipExtractor is nil")
	}
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(slogLogger(h.logger))
	r.Use(chimw.Recoverer)
	if dev {
		r.Use(devCORS("http://localhost:5173"))
	}
	r.Use(auth.IPExtractMiddleware(ipExtractor))

	// /healthz: mounted at the root (NOT /api/v1/...) so the probe
	// path stays stable across API versions. No auth wrapper because
	// orchestrator probes carry no credentials. No audit either —
	// audit is per-handler in Arenet, not a middleware, so /healthz
	// is implicitly silent. Step H.3 — see internal/api/health.go
	// for full design rationale. The middleware stack above does
	// apply (chi enforces "all middlewares before any route"), so
	// probe hits land in the structured log; that is an acceptable
	// trade-off for the homelab single-instance deployment target.
	r.Get("/healthz", h.healthz)

	r.Route("/api/v1", func(r chi.Router) {
		// Auth subtree: rate-limited per IP (spec §5.2).
		r.Route("/auth", func(r chi.Router) {
			r.Use(h.rateLimiter.Middleware())

			// No-auth subgroup: /setup, /login.
			r.Post("/setup", h.setup)
			r.Post("/login", h.login)

			// Soft-auth subgroup: /logout, /me, /unlock.
			r.Group(func(r chi.Router) {
				r.Use(auth.SoftAuthMiddleware(h.sessions, h.users, h.devMode))
				r.Post("/logout", h.logout)
				r.Get("/me", h.me)
				r.Post("/unlock", h.unlock)
			})

			// Hard-auth subgroup: /heartbeat, /sessions, DELETE /sessions/{id},
			// /me/password, /me/theme.
			r.Group(func(r chi.Router) {
				r.Use(auth.HardAuthMiddleware(h.sessions, h.users, h.devMode))
				r.Post("/heartbeat", h.heartbeat)
				r.Get("/sessions", h.listSessions)
				r.Delete("/sessions/{id}", h.deleteSession)
				r.Post("/me/password", h.changePassword)
				r.Post("/me/theme", h.updateTheme)
			})
		})

		// Business endpoints — hard-auth gated per spec §5.2.
		r.Group(func(r chi.Router) {
			r.Use(auth.HardAuthMiddleware(h.sessions, h.users, h.devMode))
			r.Get("/routes", h.listRoutes)
			r.Post("/routes", h.createRoute)
			r.Get("/routes/{id}", h.getRoute)
			r.Put("/routes/{id}", h.updateRoute)
			r.Delete("/routes/{id}", h.deleteRoute)
			r.Get("/audit", h.listAudit)
			// Step E: live-metrics WebSocket. HardAuthMiddleware
			// rejects the handshake (401 / 403) BEFORE the upgrade,
			// so an unauthorized peer never sees an open WS frame
			// — spec §5.1 + §7.1.
			if ws != nil {
				r.Get("/ws/topology", ws.ServeHTTP)
			}
		})
	})
	return r
}

func (h *Handler) listRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("list routes", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list routes")
		return
	}
	out := make([]routeResponse, 0, len(routes))
	for _, rt := range routes {
		out = append(out, toResponse(rt))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rt, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get route")
		return
	}
	writeJSON(w, http.StatusOK, toResponse(rt))
}

// validateAliasesStructural runs the same hostname rule used for the
// primary Host (RFC 1035 grammar + length) on every alias supplied
// by the user. It also enforces the two intra-route invariants from
// Step I.3 S3: no alias may duplicate the primary host, and no
// alias may duplicate another alias in the same request.
//
// Returns the first failure with a user-facing message. The
// duplicate checks here mirror the storage-layer defense in
// storage.Route.validate; the API copy gives a friendlier message
// (with the offending alias quoted) before the storage layer would
// reject it anonymously.
func validateAliasesStructural(host string, aliases []string) error {
	seen := make(map[string]struct{}, len(aliases))
	for _, a := range aliases {
		if a == "" {
			return errors.New("alias must not be empty")
		}
		if err := validateHost(a); err != nil {
			return fmt.Errorf("alias %q: %s", a, err.Error())
		}
		if a == host {
			return fmt.Errorf("alias %q duplicates the primary host", a)
		}
		if _, dup := seen[a]; dup {
			return fmt.Errorf("alias %q duplicates within the same route", a)
		}
		seen[a] = struct{}{}
	}
	return nil
}

// collectAllHostsExcept walks existing routes and returns a map from
// hostname to owning route ID, including every primary Host AND every
// alias. The excludeID, when non-empty, skips the route currently
// being updated (so it doesn't collide with its own existing aliases).
// Used by createRoute and updateRoute to enforce cross-route uniqueness
// across the union of (Host, Aliases) per Step I.3 Q1.
func collectAllHostsExcept(routes []storage.Route, excludeID string) map[string]string {
	owners := make(map[string]string, len(routes))
	for _, rt := range routes {
		if rt.ID == excludeID {
			continue
		}
		for _, h := range rt.AllHosts() {
			owners[h] = rt.ID
		}
	}
	return owners
}

// hostnamesEqual reports whether two hostname slices contain the same
// hosts in the same order. Used by updateRoute to short-circuit the
// uniqueness check when nothing changed (avoids a needless ListRoutes
// + map build on every PUT that flips, say, only WAFEnabled).
func hostnamesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (h *Handler) createRoute(w http.ResponseWriter, r *http.Request) {
	var req routeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateHost(req.Host); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateUpstreamURL(req.UpstreamURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateAliasesStructural(req.Host, req.Aliases); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Uniqueness check across the union of (Host ∪ Aliases) per
	// Step I.3 Q1. Caddy dispatches by host match, so any duplicate
	// hostname across two routes would yield non-deterministic
	// routing — reject at the API layer.
	//
	// NOTE: this is not atomic with the subsequent CreateRoute call —
	// two concurrent POSTs with the same host could both pass this
	// loop. Safe under the homelab single-writer assumption codified
	// in spec §3 Q3; revisit when real concurrency is introduced.
	existing, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("uniqueness list", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to verify uniqueness")
		return
	}
	owners := collectAllHostsExcept(existing, "")
	newRoute := storage.Route{
		Host:            req.Host,
		UpstreamURL:     req.UpstreamURL,
		TLSEnabled:      req.TLSEnabled,
		RedirectToHTTPS: req.RedirectToHTTPS,
		Aliases:         req.Aliases,
		WAFEnabled:      req.WAFEnabled,
	}
	for _, h := range newRoute.AllHosts() {
		if ownerID, taken := owners[h]; taken {
			writeError(w, http.StatusConflict, fmt.Sprintf("hostname %q already configured on route %s", h, ownerID))
			return
		}
	}

	created, err := h.store.CreateRoute(r.Context(), newRoute)
	if err != nil {
		h.logger.Error("create route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after create — rolling back", "err", err, "id", created.ID)
		if delErr := h.store.DeleteRoute(r.Context(), created.ID); delErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", delErr, "id", created.ID)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	// Emit route_created audit event AFTER the Caddy reload succeeds
	// (Plan §4.4 / D2). On reload failure the early return above skips
	// this emission. storage.Route holds no secrets (no PasswordHash,
	// no tokens) so passing it through mustMarshalForAudit is safe
	// per D3.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteCreated,
		TargetType: "route",
		TargetID:   created.ID,
		AfterJSON:  mustMarshalForAudit(created),
	})

	writeJSON(w, http.StatusCreated, toResponse(created))
}

func (h *Handler) updateRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req routeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateHost(req.Host); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateUpstreamURL(req.UpstreamURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateAliasesStructural(req.Host, req.Aliases); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}

	// Uniqueness check across (Host ∪ Aliases) when ANY hostname has
	// changed since the stored copy (Step I.3 Q1). The pre-Step-I.3
	// optimization that compared only Host is no longer sufficient —
	// adding a new alias must still trigger the cross-route check.
	newRoute := storage.Route{
		ID:              id,
		Host:            req.Host,
		UpstreamURL:     req.UpstreamURL,
		TLSEnabled:      req.TLSEnabled,
		RedirectToHTTPS: req.RedirectToHTTPS,
		Aliases:         req.Aliases,
		WAFEnabled:      req.WAFEnabled,
	}
	if !hostnamesEqual(newRoute.AllHosts(), previous.AllHosts()) {
		existing, err := h.store.ListRoutes(r.Context())
		if err != nil {
			h.logger.Error("uniqueness list (update)", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to verify uniqueness")
			return
		}
		owners := collectAllHostsExcept(existing, id)
		for _, h := range newRoute.AllHosts() {
			if ownerID, taken := owners[h]; taken {
				writeError(w, http.StatusConflict, fmt.Sprintf("hostname %q already configured on route %s", h, ownerID))
				return
			}
		}
	}

	updated, err := h.store.UpdateRoute(r.Context(), newRoute)
	if err != nil {
		h.logger.Error("update route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to update route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after update — rolling back", "err", err, "id", id)
		// UpdateRoute is used here (not RestoreRoute) per spec §9: RestoreRoute
		// is reserved for DELETE rollback. Side-effect: UpdatedAt reflects the
		// rollback time, not previous.UpdatedAt. Acceptable under single-writer.
		if _, rbErr := h.store.UpdateRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	// Emit route_updated audit event AFTER the Caddy reload succeeds
	// (Plan §4.4 / D2). storage.Route holds no secrets per D3, so
	// passing both Before and After through mustMarshalForAudit is safe.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteUpdated,
		TargetType: "route",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(previous),
		AfterJSON:  mustMarshalForAudit(updated),
	})

	writeJSON(w, http.StatusOK, toResponse(updated))
}

func (h *Handler) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}

	if err := h.store.DeleteRoute(r.Context(), id); err != nil {
		h.logger.Error("delete route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after delete — rolling back", "err", err, "id", id)
		if rbErr := h.store.RestoreRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	// Emit route_deleted audit event AFTER the Caddy reload succeeds
	// (Plan §4.4 / D2). BeforeJSON captures the deleted route's last
	// state; AfterJSON is intentionally nil. storage.Route holds no
	// secrets per D3.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteDeleted,
		TargetType: "route",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(previous),
	})

	w.WriteHeader(http.StatusNoContent)
}
