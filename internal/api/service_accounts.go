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
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
)

// Phase 4 — service-account admin endpoints. All gated on the
// router-level RequireAdminMiddleware (see routes.go); a
// service-account viewer cannot create / rotate / delete
// service accounts.

// createServiceAccountRequest is the wire shape of POST
// /api/v1/admin/users/service-accounts. ExpiresAt is optional:
// nil → no-expiry token (homelab set-and-forget default).
type createServiceAccountRequest struct {
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// createServiceAccountResponse mirrors the create-user
// response, plus the plain token (shown ONCE — the frontend
// stages a "copy and close" modal so the operator commits it
// to their password manager / .env file before navigating
// away).
type createServiceAccountResponse struct {
	User  adminUserResponse `json:"user"`
	Token string            `json:"token"`
	// TokenID is surfaced so the rotation UI can correlate the
	// "rotate this exact one" intent — useful when audit log
	// references the token row by ID.
	TokenID string `json:"tokenId"`
	// ExpiresAt is echoed back (formatted) so the frontend can
	// render "valid until …" without re-parsing the request
	// body. Empty string when no expiry.
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// rotateTokenRequest carries an optional new expiry; nil →
// new token has no expiry (same default as create).
type rotateTokenRequest struct {
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// rotateTokenResponse echoes the new plain token + ID. The old
// token is revoked atomically with the new one's issuance.
type rotateTokenResponse struct {
	Token     string `json:"token"`
	TokenID   string `json:"tokenId"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// createServiceAccount handles POST /api/v1/admin/users/service-accounts.
// Creates a new service-account User row + an initial APIToken.
// Returns the plain token in the response body — this is the
// ONLY time it is ever surfaced.
func (h *Handler) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	if h.apiTokens == nil {
		writeError(w, http.StatusServiceUnavailable, "api token store not configured")
		return
	}

	var req createServiceAccountRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name must not be empty")
		return
	}
	switch req.Role {
	case auth.UserRoleViewer, auth.UserRoleAdmin:
	default:
		writeError(w, http.StatusBadRequest, "role must be 'admin' or 'viewer'")
		return
	}
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now().UTC()) {
		writeError(w, http.StatusBadRequest, "expiresAt must be in the future")
		return
	}

	user, err := h.users.CreateServiceAccount(r.Context(), name, req.Role)
	if err != nil {
		if errors.Is(err, auth.ErrUsernameTaken) {
			writeError(w, http.StatusConflict, "name already taken")
			return
		}
		if errors.Is(err, auth.ErrUsernameInvalid) {
			writeError(w, http.StatusBadRequest, "name must match [a-z0-9_-]{3,32}")
			return
		}
		h.logger.Error("create service account: store", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create service account")
		return
	}

	creatorID, _ := r.Context().Value(auth.UserIDKey).(string)
	plain, tokenRow, err := h.apiTokens.CreateToken(r.Context(), user.ID, name, creatorID, req.ExpiresAt)
	if err != nil {
		// User row was created but token issuance failed —
		// roll back so the operator doesn't see a half-baked
		// service account that can never authenticate.
		if delErr := h.users.Delete(r.Context(), user.ID); delErr != nil {
			h.logger.Error("create service account: failed to roll back orphan user",
				"err", delErr, "user_id", user.ID)
		}
		h.logger.Error("create service account: token issuance", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}

	resp := createServiceAccountResponse{
		User:    adminUserToResponse(user, auth.UserActivity{}),
		Token:   plain,
		TokenID: tokenRow.ID,
	}
	if tokenRow.ExpiresAt != nil {
		resp.ExpiresAt = tokenRow.ExpiresAt.UTC().Format(timestampFormat)
	}

	// Audit emission. Plain token is NEVER stored in the row.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionServiceAccountCreated,
		TargetType: "service_account",
		TargetID:   user.ID,
		AfterJSON:  mustMarshalForAudit(resp.User),
	})

	writeJSON(w, http.StatusCreated, resp)
}

// rotateServiceAccountToken handles POST
// /api/v1/admin/users/service-accounts/{id}/rotate-token.
// Atomic-ish: revoke the existing active token (if any), then
// issue a new one. A race window exists between revoke and
// create where neither is active — accept this (homelab UX
// favours simplicity; the operator rotates intentionally and
// pastes the new token before any client retries).
func (h *Handler) rotateServiceAccountToken(w http.ResponseWriter, r *http.Request) {
	if h.apiTokens == nil {
		writeError(w, http.StatusServiceUnavailable, "api token store not configured")
		return
	}
	id := chi.URLParam(r, "id")

	user, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "service account not found")
			return
		}
		h.logger.Error("rotate token: get user", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	if user.AuthSource != auth.UserAuthSourceService {
		writeError(w, http.StatusBadRequest, "user is not a service account")
		return
	}

	var req rotateTokenRequest
	if r.ContentLength > 0 {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, translateDecodeError(err))
			return
		}
	}
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now().UTC()) {
		writeError(w, http.StatusBadRequest, "expiresAt must be in the future")
		return
	}

	actorID, _ := r.Context().Value(auth.UserIDKey).(string)

	// Revoke whichever active token exists (if any). Idempotent
	// when there's no active token (FindActiveByUser returns
	// ErrAPITokenNotFound, which we treat as "nothing to revoke").
	if active, err := h.apiTokens.FindActiveByUser(r.Context(), user.ID); err == nil {
		if err := h.apiTokens.RevokeToken(r.Context(), active.ID, actorID); err != nil {
			h.logger.Error("rotate token: revoke active", "err", err, "user_id", user.ID)
			writeError(w, http.StatusInternalServerError, "failed to revoke existing token")
			return
		}
	}

	plain, tokenRow, err := h.apiTokens.CreateToken(r.Context(), user.ID, user.Username, actorID, req.ExpiresAt)
	if err != nil {
		h.logger.Error("rotate token: create new", "err", err, "user_id", user.ID)
		writeError(w, http.StatusInternalServerError, "failed to issue new token")
		return
	}

	resp := rotateTokenResponse{
		Token:   plain,
		TokenID: tokenRow.ID,
	}
	if tokenRow.ExpiresAt != nil {
		resp.ExpiresAt = tokenRow.ExpiresAt.UTC().Format(timestampFormat)
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionServiceAccountTokenRotated,
		TargetType: "service_account",
		TargetID:   user.ID,
		AfterJSON:  mustMarshalForAudit(adminUserToResponse(user, auth.UserActivity{})),
	})

	writeJSON(w, http.StatusOK, resp)
}

// deleteServiceAccount handles DELETE
// /api/v1/admin/users/service-accounts/{id}. Cascades: revokes
// every token owned by the user, then deletes the user row.
func (h *Handler) deleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	if h.apiTokens == nil {
		writeError(w, http.StatusServiceUnavailable, "api token store not configured")
		return
	}
	id := chi.URLParam(r, "id")

	user, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "service account not found")
			return
		}
		h.logger.Error("delete service account: get user", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	if user.AuthSource != auth.UserAuthSourceService {
		writeError(w, http.StatusBadRequest, "user is not a service account")
		return
	}

	actorID, _ := r.Context().Value(auth.UserIDKey).(string)

	// Revoke tokens FIRST so even if the user delete fails the
	// outstanding tokens cannot keep authenticating.
	if err := h.apiTokens.RevokeAllByUser(r.Context(), user.ID, actorID); err != nil {
		h.logger.Error("delete service account: revoke tokens", "err", err, "user_id", user.ID)
		writeError(w, http.StatusInternalServerError, "failed to revoke tokens")
		return
	}

	if err := h.users.Delete(r.Context(), user.ID); err != nil {
		h.logger.Error("delete service account: delete user", "err", err, "user_id", user.ID)
		writeError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionServiceAccountDeleted,
		TargetType: "service_account",
		TargetID:   user.ID,
		BeforeJSON: mustMarshalForAudit(adminUserToResponse(user, auth.UserActivity{})),
	})

	w.WriteHeader(http.StatusNoContent)
}
