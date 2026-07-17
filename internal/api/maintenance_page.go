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
	"net/http"

	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/storage"
)

// Task 7 — global maintenance page GET/PUT handler.
//
// Surface :
//   GET /api/v1/settings/maintenance-page  (read, viewer-accessible)
//   PUT /api/v1/settings/maintenance-page  (write, admin-only)
//
// The maintenance page is a single global HTML template (storage's
// MaintenancePageConfig singleton) served on maintenance 503s for any
// route toggled into maintenance mode (see routes.go's
// /routes/{id}/maintenance endpoints). Empty HTML means "serve the
// branded default" (storage doc comment).
//
// PUT sanitizes the operator-supplied HTML through the same pipeline
// the error-pages surface uses (caddymgr.SanitizeErrorPageBody) before
// persisting, so a maintenance page can't be used to smuggle a <script>
// onto every route's 503 response. It then reloads Caddy so any live
// maintenance-mode routes pick up the new page immediately.

// maintenancePageRequest is the wire shape accepted by PUT.
type maintenancePageRequest struct {
	HTML string `json:"html"`
}

// maintenancePageResponse is the wire shape returned by GET (and echoed
// by PUT for symmetry with the error-templates handlers).
type maintenancePageResponse struct {
	HTML string `json:"html"`
}

func (h *Handler) getMaintenancePage(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetMaintenancePageConfig(r.Context())
	if err != nil {
		h.logger.Error("get maintenance_page config", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get maintenance page")
		return
	}
	writeJSON(w, http.StatusOK, maintenancePageResponse{HTML: cfg.HTML})
}

func (h *Handler) putMaintenancePage(w http.ResponseWriter, r *http.Request) {
	var req maintenancePageRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	sanitized := caddymgr.SanitizeErrorPageBody(req.HTML)

	if err := h.store.PutMaintenancePageConfig(r.Context(), storage.MaintenancePageConfig{HTML: sanitized}); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save maintenance page")
		return
	}

	// Reload Caddy so live maintenance-mode routes pick up the new
	// page content immediately, mirroring the error-templates
	// update handler's reload-after-write contract.
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Warn("maintenance_page: caddy reload after update failed", "err", err)
	}

	writeJSON(w, http.StatusOK, maintenancePageResponse{HTML: sanitized})
}
