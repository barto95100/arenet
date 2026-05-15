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

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/barto95100/arenet/internal/storage"
)

// NewRouter builds the chi router for the admin API. When dev is true a
// permissive CORS middleware is mounted for http://localhost:5173.
func NewRouter(h *Handler, dev bool) chi.Router {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(slogLogger(h.logger))
	r.Use(chimw.Recoverer)
	if dev {
		r.Use(devCORS("http://localhost:5173"))
	}
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/routes", h.listRoutes)
		r.Post("/routes", h.createRoute)
		r.Get("/routes/{id}", h.getRoute)
		r.Put("/routes/{id}", h.updateRoute)
		r.Delete("/routes/{id}", h.deleteRoute)
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

func (h *Handler) createRoute(w http.ResponseWriter, r *http.Request) {
	var req routeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	// Uniqueness check. NOTE: this is not atomic with the subsequent
	// CreateRoute call — two concurrent POSTs with the same host could both
	// pass this loop. Safe under the homelab single-writer assumption
	// codified in spec §3 Q3; revisit when real concurrency is introduced.
	existing, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("uniqueness list", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to verify uniqueness")
		return
	}
	for _, rt := range existing {
		if rt.Host == req.Host {
			writeError(w, http.StatusConflict, "host already configured")
			return
		}
	}

	created, err := h.store.CreateRoute(r.Context(), storage.Route{
		Host:        req.Host,
		UpstreamURL: req.UpstreamURL,
		TLSEnabled:  req.TLSEnabled,
		WAFEnabled:  req.WAFEnabled,
	})
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

	writeJSON(w, http.StatusCreated, toResponse(created))
}

func (h *Handler) updateRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req routeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	// Host change must not collide with another route.
	if req.Host != previous.Host {
		existing, err := h.store.ListRoutes(r.Context())
		if err != nil {
			h.logger.Error("uniqueness list (update)", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to verify uniqueness")
			return
		}
		for _, rt := range existing {
			if rt.ID != id && rt.Host == req.Host {
				writeError(w, http.StatusConflict, "host already configured")
				return
			}
		}
	}

	updated, err := h.store.UpdateRoute(r.Context(), storage.Route{
		ID:          id,
		Host:        req.Host,
		UpstreamURL: req.UpstreamURL,
		TLSEnabled:  req.TLSEnabled,
		WAFEnabled:  req.WAFEnabled,
	})
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

	writeJSON(w, http.StatusOK, toResponse(updated))
}

// deleteRoute remains a 501 stub until Task 2.6.
func (h *Handler) deleteRoute(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not implemented yet")
}
