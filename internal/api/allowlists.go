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
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/allowlist"
	"github.com/barto95100/arenet/internal/audit"
)

// AllowlistStore is the persistence seam for the #364 allowlist CRUD.
// Satisfied by *allowlist.Store in production; a test can substitute an
// in-memory store (allowlist.Open(ctx, ":memory:")).
type AllowlistStore interface {
	List(ctx context.Context) ([]allowlist.Allowlist, error)
	Get(ctx context.Context, slug string) (*allowlist.Allowlist, error)
	Create(ctx context.Context, in allowlist.Input) (*allowlist.Allowlist, error)
	Update(ctx context.Context, slug string, in allowlist.Input) (*allowlist.Allowlist, error)
	Delete(ctx context.Context, slug string) error
	// ReplaceAll is the backup-restore seam (#372): it lets the backup
	// handler pass the store as a backup.AllowlistSource (List) and
	// backup.AllowlistSink (ReplaceAll) without a second reference.
	ReplaceAll(ctx context.Context, lists []allowlist.Allowlist) error
}

// allowlistRequest is the create/update wire shape. The scope + enabled
// flags are pointers so an omitted field defaults to true (#364 spec:
// scopes are all checked by default), distinct from an explicit false.
type allowlistRequest struct {
	Name          string               `json:"name"`
	Description   string               `json:"description"`
	Enabled       *bool                `json:"enabled"`
	ScopeBlock    *bool                `json:"scopeBlock"`
	ScopeThrottle *bool                `json:"scopeThrottle"`
	ScopeAudit    *bool                `json:"scopeAudit"`
	Entries       []allowlistEntryWire `json:"entries"`
}

type allowlistEntryWire struct {
	CIDR string `json:"cidr"`
	Note string `json:"note"`
}

func boolOrTrue(p *bool) bool {
	if p == nil {
		return true
	}
	return *p
}

func (req allowlistRequest) toInput() allowlist.Input {
	entries := make([]allowlist.Entry, 0, len(req.Entries))
	for _, e := range req.Entries {
		entries = append(entries, allowlist.Entry{CIDR: e.CIDR, Note: e.Note})
	}
	return allowlist.Input{
		Name:          req.Name,
		Description:   req.Description,
		Enabled:       boolOrTrue(req.Enabled),
		ScopeBlock:    boolOrTrue(req.ScopeBlock),
		ScopeThrottle: boolOrTrue(req.ScopeThrottle),
		ScopeAudit:    boolOrTrue(req.ScopeAudit),
		Entries:       entries,
	}
}

// listAllowlists — GET /security/allowlists (viewer).
func (h *Handler) listAllowlists(w http.ResponseWriter, r *http.Request) {
	if h.allowlists == nil {
		writeError(w, http.StatusServiceUnavailable, "allowlist store unavailable")
		return
	}
	lists, err := h.allowlists.List(r.Context())
	if err != nil {
		h.logger.Error("allowlist: list", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list allowlists")
		return
	}
	if lists == nil {
		lists = []allowlist.Allowlist{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowlists": lists})
}

// getAllowlist — GET /security/allowlists/{slug} (viewer).
func (h *Handler) getAllowlist(w http.ResponseWriter, r *http.Request) {
	if h.allowlists == nil {
		writeError(w, http.StatusServiceUnavailable, "allowlist store unavailable")
		return
	}
	slug := chi.URLParam(r, "slug")
	a, err := h.allowlists.Get(r.Context(), slug)
	if errors.Is(err, allowlist.ErrNotFound) {
		writeError(w, http.StatusNotFound, "allowlist not found")
		return
	}
	if err != nil {
		h.logger.Error("allowlist: get", "err", err, "slug", slug)
		writeError(w, http.StatusInternalServerError, "failed to load allowlist")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// createAllowlist — POST /security/allowlists (admin).
func (h *Handler) createAllowlist(w http.ResponseWriter, r *http.Request) {
	if h.allowlists == nil {
		writeError(w, http.StatusServiceUnavailable, "allowlist store unavailable")
		return
	}
	var req allowlistRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	created, err := h.allowlists.Create(r.Context(), req.toInput())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	after, _ := json.Marshal(created)
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionAllowlistCreated,
		TargetType: "allowlist",
		TargetID:   created.Slug,
		AfterJSON:  after,
	})
	h.rebuildAllowlist(r.Context())
	writeJSON(w, http.StatusCreated, created)
}

// updateAllowlist — PUT /security/allowlists/{slug} (admin).
func (h *Handler) updateAllowlist(w http.ResponseWriter, r *http.Request) {
	if h.allowlists == nil {
		writeError(w, http.StatusServiceUnavailable, "allowlist store unavailable")
		return
	}
	slug := chi.URLParam(r, "slug")
	var req allowlistRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	ctx := r.Context()
	before, err := h.allowlists.Get(ctx, slug)
	if errors.Is(err, allowlist.ErrNotFound) {
		writeError(w, http.StatusNotFound, "allowlist not found")
		return
	}
	if err != nil {
		h.logger.Error("allowlist: load before update", "err", err, "slug", slug)
		writeError(w, http.StatusInternalServerError, "failed to load allowlist")
		return
	}
	updated, err := h.allowlists.Update(ctx, slug, req.toInput())
	if errors.Is(err, allowlist.ErrNotFound) {
		writeError(w, http.StatusNotFound, "allowlist not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(updated)
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionAllowlistUpdated,
		TargetType: "allowlist",
		TargetID:   slug,
		BeforeJSON: beforeJSON,
		AfterJSON:  afterJSON,
	})
	h.rebuildAllowlist(ctx)
	writeJSON(w, http.StatusOK, updated)
}

// deleteAllowlist — DELETE /security/allowlists/{slug} (admin).
func (h *Handler) deleteAllowlist(w http.ResponseWriter, r *http.Request) {
	if h.allowlists == nil {
		writeError(w, http.StatusServiceUnavailable, "allowlist store unavailable")
		return
	}
	slug := chi.URLParam(r, "slug")
	ctx := r.Context()
	before, err := h.allowlists.Get(ctx, slug)
	if errors.Is(err, allowlist.ErrNotFound) {
		writeError(w, http.StatusNotFound, "allowlist not found")
		return
	}
	if err != nil {
		h.logger.Error("allowlist: load before delete", "err", err, "slug", slug)
		writeError(w, http.StatusInternalServerError, "failed to load allowlist")
		return
	}
	if err := h.allowlists.Delete(ctx, slug); err != nil {
		if errors.Is(err, allowlist.ErrNotFound) {
			writeError(w, http.StatusNotFound, "allowlist not found")
			return
		}
		h.logger.Error("allowlist: delete", "err", err, "slug", slug)
		writeError(w, http.StatusInternalServerError, "failed to delete allowlist")
		return
	}
	beforeJSON, _ := json.Marshal(before)
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionAllowlistDeleted,
		TargetType: "allowlist",
		TargetID:   slug,
		BeforeJSON: beforeJSON,
	})
	h.rebuildAllowlist(ctx)
	w.WriteHeader(http.StatusNoContent)
}

// rebuildAllowlist invokes the resolver-rebuild hook (best-effort, nil-safe)
// so the live trigger picks up the mutation without a restart.
func (h *Handler) rebuildAllowlist(ctx context.Context) {
	if h.onAllowlistChange != nil {
		h.onAllowlistChange(ctx)
	}
}
