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
	"strings"

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
//
// v2.18.0 — Message is the global operator maintenance message,
// substituted into the 503 body via {arenet.maintenance.message}. It
// is optional (a pre-v2.18.0 client omitting it still succeeds). It is
// stored as plain text (verbatim, only outer whitespace trimmed) and
// HTML-escaped at emission in caddymgr — NOT run through the HTML
// sanitizer here, because it is not HTML.
type maintenancePageRequest struct {
	HTML    string `json:"html"`
	Message string `json:"message"`
}

// maintenancePageResponse is the wire shape returned by GET (and echoed
// by PUT for symmetry with the error-templates handlers).
//
// v2.17.1 Item E — added IsDefault: GET previously returned an empty
// HTML string when the operator had never customized the page, which
// left the frontend editor looking blank with no visible starting
// point. Now GET returns the branded built-in default HTML (see
// caddymgr.DefaultMaintenancePageHTML) with IsDefault=true whenever
// the stored config is empty, so the frontend can show it labeled as
// "Arenet Default (built-in)" — mirroring the error-templates
// surface's virtual "arenet-default" builtin entry. PUT continues to
// echo exactly what was persisted (IsDefault=false unless the
// operator explicitly saves an empty string, which is the "reset"
// path — the NEXT GET will then report IsDefault=true again).
type maintenancePageResponse struct {
	HTML      string `json:"html"`
	IsDefault bool   `json:"isDefault"`
	// Message (v2.18.0) is the global maintenance message, echoed on
	// GET and PUT. Independent of IsDefault (which describes the HTML
	// buffer only) — the message can be set while the HTML is still
	// the built-in default.
	Message string `json:"message"`
}

func (h *Handler) getMaintenancePage(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetMaintenancePageConfig(r.Context())
	if err != nil {
		h.logger.Error("get maintenance_page config", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get maintenance page")
		return
	}
	if cfg.HTML == "" {
		writeJSON(w, http.StatusOK, maintenancePageResponse{
			HTML:      caddymgr.DefaultMaintenancePageHTML(),
			IsDefault: true,
			Message:   cfg.Message,
		})
		return
	}
	writeJSON(w, http.StatusOK, maintenancePageResponse{HTML: cfg.HTML, IsDefault: false, Message: cfg.Message})
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
	// Message is plain text: trim outer whitespace for tidiness but
	// keep inner content verbatim. It is NOT HTML-sanitized here — it
	// is HTML-escaped at emission in caddymgr (buildMaintenanceBody).
	message := strings.TrimSpace(req.Message)

	if err := h.store.PutMaintenancePageConfig(r.Context(), storage.MaintenancePageConfig{HTML: sanitized, Message: message}); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save maintenance page")
		return
	}

	// Reload Caddy so live maintenance-mode routes pick up the new
	// page content immediately, mirroring the error-templates
	// update handler's reload-after-write contract.
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Warn("maintenance_page: caddy reload after update failed", "err", err)
	}

	// Echo the same {html, isDefault} shape GET would return right
	// after this write: a "Reset to default" PUT (empty sanitized
	// HTML) reports the built-in default + IsDefault=true, matching
	// what the very next GET would produce, rather than echoing back
	// an empty string with IsDefault=false (a shape GET never emits).
	if sanitized == "" {
		writeJSON(w, http.StatusOK, maintenancePageResponse{
			HTML:      caddymgr.DefaultMaintenancePageHTML(),
			IsDefault: true,
			Message:   message,
		})
		return
	}
	writeJSON(w, http.StatusOK, maintenancePageResponse{HTML: sanitized, IsDefault: false, Message: message})
}
