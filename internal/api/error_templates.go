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
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// Step R — error-page templates CRUD handler.
//
// Surface :
//   GET    /api/v1/error-templates           (list, viewer-accessible)
//   GET    /api/v1/error-templates/{id}      (get, viewer-accessible)
//   POST   /api/v1/error-templates           (create, admin-only)
//   PUT    /api/v1/error-templates/{id}      (update, admin-only)
//   DELETE /api/v1/error-templates/{id}      (delete, admin-only)
//   GET    /api/v1/error-templates/{id}/preview?statusCode=X
//                                            (preview render, viewer-accessible)
//
// All admin mutations emit an audit event (created/updated/deleted)
// and trigger a Caddy reload via the manager's ReloadFromStore so
// the new template content reaches the running edge in <1 s.

// errorTemplateRequest is the wire shape accepted by POST/PUT.
// Mirrors the storage struct with camelCase JSON tags (API
// convention ; storage uses snake_case).
type errorTemplateRequest struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Pages       map[int]string `json:"pages,omitempty"`
}

// errorTemplateResponse is the wire shape returned by GET / list.
type errorTemplateResponse struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Pages       map[int]string `json:"pages"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
}

func errorTemplateToResponse(t storage.ErrorPageTemplate) errorTemplateResponse {
	pages := t.Pages
	if pages == nil {
		pages = map[int]string{}
	}
	return errorTemplateResponse{
		ID:          t.ID,
		Name:        t.Name,
		Description: t.Description,
		Pages:       pages,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
}

func (h *Handler) listErrorTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := h.store.ListErrorPageTemplates(r.Context())
	if err != nil {
		h.logger.Error("list error_templates", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list error templates")
		return
	}
	out := make([]errorTemplateResponse, 0, len(templates))
	for _, t := range templates {
		out = append(out, errorTemplateToResponse(t))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getErrorTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := h.store.GetErrorPageTemplate(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "error template not found")
			return
		}
		h.logger.Error("get error_template", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get error template")
		return
	}
	writeJSON(w, http.StatusOK, errorTemplateToResponse(t))
}

func (h *Handler) createErrorTemplate(w http.ResponseWriter, r *http.Request) {
	var req errorTemplateRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	t := storage.ErrorPageTemplate{
		Name:        req.Name,
		Description: req.Description,
		Pages:       req.Pages,
	}
	created, err := h.store.CreateErrorPageTemplate(r.Context(), t)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step R — reload Caddy so the new template lands on the
	// edge immediately. A template that's just created has no
	// route referencing it yet (the operator wires the ref via
	// the RouteForm in a separate PUT), so the reload here is
	// a no-op on the Caddy side — but the symmetry with
	// update/delete keeps the contract uniform.
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Warn("error_template: caddy reload after create failed", "id", created.ID, "err", err)
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionErrorTemplateCreated,
		TargetType: "error_template",
		TargetID:   created.ID,
		AfterJSON:  mustMarshalForAudit(created),
	})

	writeJSON(w, http.StatusCreated, errorTemplateToResponse(created))
}

func (h *Handler) updateErrorTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req errorTemplateRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	previous, err := h.store.GetErrorPageTemplate(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "error template not found")
			return
		}
		h.logger.Error("get error_template for update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load error template")
		return
	}

	t := storage.ErrorPageTemplate{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		Pages:       req.Pages,
	}
	updated, err := h.store.UpdateErrorPageTemplate(r.Context(), t)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step R — reload Caddy so updated template content reaches
	// the running edge. Routes referencing this template will
	// pick up the new bodies on the next request.
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Warn("error_template: caddy reload after update failed", "id", id, "err", err)
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionErrorTemplateUpdated,
		TargetType: "error_template",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(previous),
		AfterJSON:  mustMarshalForAudit(updated),
	})

	writeJSON(w, http.StatusOK, errorTemplateToResponse(updated))
}

func (h *Handler) deleteErrorTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	previous, err := h.store.GetErrorPageTemplate(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "error template not found")
			return
		}
		h.logger.Error("get error_template for delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load error template")
		return
	}

	if err := h.store.DeleteErrorPageTemplate(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Step R — reload Caddy. Routes referencing the deleted
	// template fall back to the built-in Arenet default at
	// emit time ; the caddymgr logs a warning per route with
	// a dangling ref so the operator can clean those up.
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Warn("error_template: caddy reload after delete failed", "id", id, "err", err)
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionErrorTemplateDeleted,
		TargetType: "error_template",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(previous),
	})

	w.WriteHeader(http.StatusNoContent)
}

// previewErrorTemplate renders one (template, statusCode) cell
// with mock placeholder values. Used by the /settings/error-pages
// editor's preview pane — the operator sees a representative
// rendering without having to deploy the template to a real route.
//
// The mock values match the Caddy runtime placeholders the
// static_response handler will expand at serve time. NOT a real
// expansion : we don't bind a real *http.Request, we just
// substring-replace each `{...}` with a fixture value. Operator
// sees the same SHAPE they'll see in prod ; the literal values
// (request ID, URI) come from the live request only.
//
// Returns the raw HTML body (Content-Type: text/html). Sandbox
// the iframe consumer-side to prevent template <script> from
// running in the editor page.
func (h *Handler) previewErrorTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	codeStr := r.URL.Query().Get("statusCode")
	if codeStr == "" {
		writeError(w, http.StatusBadRequest, "statusCode query parameter required")
		return
	}
	code, err := strconv.Atoi(codeStr)
	if err != nil || !storage.IsSupportedErrorStatusCode(code) {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("statusCode must be one of %v", storage.SupportedErrorStatusCodes))
		return
	}

	t, err := h.store.GetErrorPageTemplate(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "error template not found")
			return
		}
		h.logger.Error("get error_template for preview", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load error template")
		return
	}

	body, ok := t.Pages[code]
	if !ok || body == "" {
		writeError(w, http.StatusNotFound,
			fmt.Sprintf("template has no body for status code %d", code))
		return
	}

	rendered := previewSubstitute(body, code)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'")
	_, _ = w.Write([]byte(rendered))
}

// previewSubstitute does the {placeholder} → fixture substitution
// for the preview endpoint. Mirrors the Caddy runtime placeholders
// the static_response handler will expand at serve time. NOT a
// general-purpose template engine — every placeholder is a literal
// string replacement.
//
// Kept narrow + obvious so the operator can mentally model "what
// they'll see in the preview" matches "what they'll see in prod"
// for these specific tokens. Tokens we don't replace pass through
// untouched (operator sees the literal `{x}` in the preview, which
// signals "this won't expand in prod either").
func previewSubstitute(body string, code int) string {
	statusText := map[int]string{
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		429: "Too Many Requests",
		500: "Internal Server Error",
		502: "Bad Gateway",
		503: "Service Unavailable",
		504: "Gateway Timeout",
	}[code]
	replacements := map[string]string{
		"{http.error.status_code}": strconv.Itoa(code),
		"{http.error.status_text}": statusText,
		"{http.error.id}":          "preview-error-id-0000",
		"{http.error.message}":     statusText,
		"{http.request.method}":    "GET",
		"{http.request.host}":      "preview.example.com",
		"{http.request.uri}":       "/preview/path",
		"{http.request.uri.path}": "/preview/path",
		"{http.request.uuid}":      "00000000-0000-4000-8000-000000000000",
	}
	out := body
	for k, v := range replacements {
		out = strings.ReplaceAll(out, k, v)
	}
	return out
}
