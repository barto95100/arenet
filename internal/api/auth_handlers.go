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

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
)

// setupRequest is the wire shape accepted by POST /api/v1/auth/setup.
// Spec §4.2.
type setupRequest struct {
	SetupToken  string `json:"setupToken"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
}

// setupResponse is the wire shape returned on success. Notably omits
// PasswordHash and HIBP fields per spec §3.2 SECURITY note.
type setupResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	CreatedAt   string `json:"createdAt"`
}

// setup handles POST /api/v1/auth/setup (spec §4.2).
//
// Flow:
//  1. Verify the users bucket is empty (404 if not).
//  2. Verify the setup token matches the in-memory holder (403 if not).
//  3. Validate the password (length + top-10k + HIBP) via
//     auth.ValidatePasswordSync (400 on failure).
//  4. Create the user via UserStore.Create (400 on validation failure).
//  5. Set User.HIBPCheckStatus from the validation result.
//  6. Create a 24h session (no remember-me at setup) and set cookie.
//  7. Invalidate the setup token (single-use).
//  8. Emit setup_admin_created audit event (best-effort).
//  9. Return 201 with the user wire shape (sans PasswordHash).
func (h *Handler) setup(w http.ResponseWriter, r *http.Request) {
	// Step 1: users bucket empty?
	count, err := h.users.Count(r.Context())
	if err != nil {
		// Storage error (decision D11).
		h.logger.Error("setup: users count failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if count > 0 {
		// Per spec §4.2: 404 (not 403/409) is deliberate to avoid
		// confirming the endpoint exists past first-boot.
		writeError(w, http.StatusNotFound, "setup unavailable: an admin already exists")
		return
	}

	// Step 1.5: parse body.
	var req setupRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Step 2: token verification (constant-time inside Verify).
	if !h.setupToken.Verify(req.SetupToken) {
		writeError(w, http.StatusForbidden, "setup token invalid or expired")
		return
	}

	// Step 3: password validation (length + top-10k + HIBP).
	// Returns the HIBP status to persist on the user (clean/pending/skipped).
	hibpStatus, err := auth.ValidatePasswordSync(r.Context(), h.hibp, req.Password)
	if err != nil {
		// Map known sentinels to user-facing 400 messages per spec §4.2.
		switch {
		case errors.Is(err, auth.ErrPasswordTooShort):
			writeError(w, http.StatusBadRequest, "password must be at least 15 characters")
		case errors.Is(err, auth.ErrPasswordTooLong):
			writeError(w, http.StatusBadRequest, "password must be at most 128 characters")
		case errors.Is(err, auth.ErrPasswordCommon):
			writeError(w, http.StatusBadRequest, "password is in the list of common compromised passwords")
		default:
			h.logger.Error("setup: password validation unexpected error", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	// Step 4: create the user.
	user, err := h.users.Create(r.Context(), req.Username, req.DisplayName, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUsernameInvalid):
			writeError(w, http.StatusBadRequest, "username must be lowercase")
		case errors.Is(err, auth.ErrDisplayNameTooLong):
			writeError(w, http.StatusBadRequest, "displayName must be at most 64 characters")
		case errors.Is(err, auth.ErrUsernameTaken):
			// Should be impossible: Count was 0 at step 1. Treat as
			// concurrent setup attempt (race) → 404 like step 1.
			writeError(w, http.StatusNotFound, "setup unavailable: an admin already exists")
		case errors.Is(err, auth.ErrPasswordTooShort), errors.Is(err, auth.ErrPasswordTooLong):
			// Length should have failed at step 3; defensive.
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			h.logger.Error("setup: user create failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	// Step 5: align HIBP fields with the validation result (best-effort).
	// UserStore.Create defaults HIBPCheckStatus to "pending"; if
	// ValidatePasswordSync returned "clean" or "skipped" we update
	// in a follow-up call. Failure is logged but non-fatal — the user
	// is created either way; worst case the deferred re-check at next
	// login (spec §7.6) corrects the status.
	if hibpStatus != auth.HIBPStatusPending {
		if err := h.users.UpdateHIBPStatus(r.Context(), user.ID, hibpStatus, false); err != nil {
			h.logger.Warn("setup: UpdateHIBPStatus failed (non-fatal)", "err", err.Error(), "user_id", user.ID)
		} else {
			user.HIBPCheckStatus = hibpStatus
		}
	}

	// Step 6: create the session (24h, no remember-me at setup).
	ip := auth.ClientIPFromContext(r.Context())
	sess, err := h.sessions.Create(r.Context(), user.ID, false, ip, r.UserAgent())
	if err != nil {
		h.logger.Error("setup: session create failed", "err", err, "user_id", user.ID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	setSessionCookie(w, sess.ID, false, h.devMode)

	// Step 7: invalidate the setup token (single-use, spec §4.2).
	h.setupToken.Invalidate()

	// Step 8: emit audit event (best-effort, post-success per D2).
	// SECURITY: strip PasswordHash before serialization (decision D3:
	// no secrets in BeforeJSON/AfterJSON). We zero the field in-place
	// rather than define an intermediate "auditUser" type: the marshal
	// shape stays "User minus the secret value", which is exactly
	// what D3 mandates, and avoids the maintenance cost of a parallel
	// struct that must track every User field rename.
	user.PasswordHash = ""
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionSetupAdminCreated,
		TargetType: "user",
		TargetID:   user.ID,
		AfterJSON:  mustMarshalForAudit(user),
	})

	// Step 9: return the wire shape (omits PasswordHash, HIBP fields).
	writeJSON(w, http.StatusCreated, setupResponse{
		ID:          user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		CreatedAt:   user.CreatedAt.UTC().Format(timestampFormat),
	})
}
