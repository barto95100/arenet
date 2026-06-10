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
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
)

// Step K.2 — admin Users management.
//
// Endpoints (hard-auth + admin role required):
//   - GET  /api/v1/admin/users               — list users
//   - POST /api/v1/admin/users/{id}/role     — elevate/demote
//
// PasswordHash + OIDCSub are NEVER on the wire: the response
// surface omits PasswordHash and surfaces OIDCSub only as a
// boolean indicator ("oidcLinked") rather than the raw value
// (the sub is operational metadata for the storage layer; the
// admin UI doesn't need it).

type adminUserResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	AuthSource  string `json:"authSource"`
	OIDCLinked  bool   `json:"oidcLinked"`
	Role        string `json:"role"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
	LastLoginAt string `json:"lastLoginAt,omitempty"`
}

func adminUserToResponse(u auth.User) adminUserResponse {
	out := adminUserResponse{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		AuthSource:  u.AuthSource,
		OIDCLinked:  u.OIDCSub != "",
		Role:        u.Role,
		CreatedAt:   u.CreatedAt.UTC().Format(timestampFormat),
		UpdatedAt:   u.UpdatedAt.UTC().Format(timestampFormat),
	}
	if !u.LastLoginAt.IsZero() {
		out.LastLoginAt = u.LastLoginAt.UTC().Format(timestampFormat)
	}
	return out
}

func (h *Handler) listAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.users.List(r.Context())
	if err != nil {
		h.logger.Error("admin: list users", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	out := make([]adminUserResponse, 0, len(users))
	for _, u := range users {
		out = append(out, adminUserToResponse(u))
	}
	writeJSON(w, http.StatusOK, out)
}

type updateUserRoleRequest struct {
	Role string `json:"role"`
}

// updateUserRole is POST /api/v1/admin/users/{id}/role. Elevates
// or demotes another user's role (Step K.2 §1.3 #12). Last-admin
// guard fires when demoting the last LOCAL admin (the break-
// glass channel). The acting user can demote themselves IF
// another local admin exists.
func (h *Handler) updateUserRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req updateUserRoleRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	req.Role = strings.TrimSpace(req.Role)
	if req.Role != auth.UserRoleViewer && req.Role != auth.UserRoleAdmin {
		writeError(w, http.StatusBadRequest, "role must be \"viewer\" or \"admin\"")
		return
	}

	previous, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("admin: get user for role update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	if err := h.users.UpdateRole(r.Context(), id, req.Role); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		// Last-admin guard fires here.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, _ := h.users.GetByID(r.Context(), id)

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionUserRoleChanged,
		TargetType: "user",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(adminUserToResponse(previous)),
		AfterJSON:  mustMarshalForAudit(adminUserToResponse(updated)),
	})

	writeJSON(w, http.StatusOK, adminUserToResponse(updated))
}
