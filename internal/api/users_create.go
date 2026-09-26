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

	"github.com/barto95100/arenet/internal/apierr"
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.48 — POST /admin/users, creating a local account.
//
// Arenet could list users, change a role, delete an account and create
// service accounts; it could not create a human. The only ways one
// came into existence were the boot-time setup flow and OIDC
// just-in-time provisioning.
//
// Design record:
// docs/superpowers/specs/2026-09-26-local-user-creation-design.md.

type createUserRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	// Password is optional. Empty means "generate one" — the default
	// path, and the safe one: an operator asked to invent a password
	// for somebody else reaches for something memorable, and nobody
	// needs to remember this one.
	Password string `json:"password,omitempty"`
}

type createUserResponse struct {
	User adminUserResponse `json:"user"`
	// GeneratedPassword is present ONLY when Arenet generated it, and
	// only in this response. Nothing returns it afterwards. When the
	// admin typed one they already have it, and echoing it back would
	// put it somewhere it does not need to be.
	GeneratedPassword string `json:"generatedPassword,omitempty"`
}

func (h *Handler) createAdminUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	if err := h.refuseIfOnOIDCAllowlist(r, req.Email); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	password := req.Password
	generated := ""
	if strings.TrimSpace(password) == "" {
		p, err := auth.GeneratePassword()
		if err != nil {
			h.logger.Error("create user: generate password", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to generate a password")
			return
		}
		password, generated = p, p
	}

	user, err := h.users.CreateManaged(r.Context(), auth.ManagedUserSpec{
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Email:       req.Email,
		Password:    password,
		Role:        req.Role,
	})
	if err != nil {
		h.writeCreateUserError(w, err)
		return
	}

	// The audit event names who did it and to whom, and carries no
	// password material — generated or typed. An audit trail that
	// holds credentials is a credential store.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionUserCreated,
		TargetType: "user",
		TargetID:   user.ID,
		Message:    "username=" + user.Username + " role=" + user.Role + " auth_source=" + user.AuthSource,
	})

	writeJSON(w, http.StatusCreated, createUserResponse{
		User:              adminUserToResponse(user, auth.UserActivity{}),
		GeneratedPassword: generated,
	})
}

// writeCreateUserError maps the store's refusals to coded HTTP errors,
// so the UI can say them in the operator's language (v2.46).
func (h *Handler) writeCreateUserError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrUsernameTaken):
		writeErrorFrom(w, http.StatusConflict,
			apierr.New("user_username_taken", nil, "auth: username already taken"))
	case errors.Is(err, auth.ErrUsernameInvalid):
		writeErrorFrom(w, http.StatusBadRequest,
			apierr.New("user_username_invalid", nil,
				"the username must be 3 to 32 characters of a-z, 0-9, _ or -"))
	case errors.Is(err, auth.ErrDisplayNameTooLong):
		writeErrorFrom(w, http.StatusBadRequest,
			apierr.New("user_display_name_too_long", nil, "the display name is too long"))
	case errors.Is(err, auth.ErrRoleInvalid):
		writeErrorFrom(w, http.StatusBadRequest,
			apierr.New("user_role_invalid", nil, "the role must be viewer or admin"))
	case errors.Is(err, auth.ErrPasswordTooShort):
		writeErrorFrom(w, http.StatusBadRequest,
			apierr.New("user_password_too_short", nil, "%s", err))
	case errors.Is(err, auth.ErrPasswordTooLong):
		writeErrorFrom(w, http.StatusBadRequest,
			apierr.New("user_password_too_long", nil, "%s", err))
	default:
		h.logger.Error("create user: store", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create the user")
	}
}

// refuseIfOnOIDCAllowlist rejects a local account for an address SSO
// already claims.
//
// Otherwise that person ends up with two identities — one
// password-based, one federated — and which one they land in depends
// on which button they happened to press. Arenet's own store already
// enforces that a user is local XOR OIDC; this catches the collision
// one layer earlier, where it can still be explained.
func (h *Handler) refuseIfOnOIDCAllowlist(r *http.Request, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil
	}
	cfg, err := h.store.GetOIDCConfig(r.Context())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil // no SSO configured, nothing to collide with
		}
		// Unreadable config is not a reason to refuse a legitimate
		// creation; the store's own XOR rule remains the backstop.
		h.logger.Warn("create user: could not read the oidc allowlist", "err", err)
		return nil
	}
	for _, ai := range cfg.AllowedIdentities {
		if strings.EqualFold(strings.TrimSpace(ai.Email), email) {
			return apierr.New("user_email_on_oidc_allowlist",
				map[string]string{"email": email},
				"an OIDC identity already exists for %s: that person would end up with two "+
					"accounts, one password-based and one federated", email)
		}
	}
	return nil
}
