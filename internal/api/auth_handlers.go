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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
)

// truncatedUsernameMaxLen bounds the username snapshot stored in
// audit events to prevent log injection of arbitrarily large
// attacker-controlled strings (spec §4.3 security notes).
const truncatedUsernameMaxLen = 32

// truncateUsername clamps an attempted username for audit storage.
func truncateUsername(s string) string {
	if len(s) > truncatedUsernameMaxLen {
		return s[:truncatedUsernameMaxLen]
	}
	return s
}

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
	// Setup creates a brand-new user with ThemePreference="" — normalized
	// to "dark" so the FOUC bootstrap has a useful value (spec §4.5).
	setThemeCookie(w, normalizeThemeForCookie(user.ThemePreference), h.devMode)

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

// --- POST /api/v1/auth/login -----------------------------------------------

// loginRequest is the wire shape for POST /api/v1/auth/login. Spec §4.3.
type loginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	RememberMe bool   `json:"rememberMe"`
}

// loginResponse is the success body per spec §4.3.
type loginResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
}

// login handles POST /api/v1/auth/login (spec §4.3).
//
// Security properties:
//   - Same 401 "invalid credentials" for "user not found" and "bad password"
//     to prevent username enumeration.
//   - argon2id.ComparePasswordAndHash is constant-time internally.
//   - Attempted username truncated before being stored in audit events.
//   - Failure increments the rate-limit counter (via the middleware's
//     401 observation); success calls rateLimiter.Reset.
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	// Record attempted username in context so the rate-limit middleware
	// can include it in Tier 2 Warn logs (spec §5.3).
	attempted := truncateUsername(req.Username)
	ctx := auth.SetAttemptedUsername(r.Context(), attempted)
	r = r.WithContext(ctx)

	user, err := h.users.GetByUsername(ctx, req.Username)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			h.emitLoginFailure(r, attempted, "user_not_found")
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		// Storage error (decision D11): 503.
		h.logger.Error("login: user lookup failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "authentication service temporarily unavailable")
		return
	}

	match, err := argon2id.ComparePasswordAndHash(req.Password, user.PasswordHash)
	if err != nil {
		// Malformed PHC string in storage; treat as internal failure.
		h.logger.Error("login: argon2id compare failed", "err", err, "user_id", user.ID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !match {
		h.emitLoginFailure(r, attempted, "bad_password")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Success: create session, set cookie, reset rate limit, audit.
	ip := auth.ClientIPFromContext(ctx)
	sess, err := h.sessions.Create(ctx, user.ID, req.RememberMe, ip, r.UserAgent())
	if err != nil {
		h.logger.Error("login: session create failed", "err", err, "user_id", user.ID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	setSessionCookie(w, sess.ID, req.RememberMe, h.devMode)
	// Also set the theme cookie so the FOUC bootstrap script picks up
	// the user's stored preference on the next paint (spec §4.5).
	setThemeCookie(w, normalizeThemeForCookie(user.ThemePreference), h.devMode)

	// Best-effort: record LastLoginAt; log warning on failure but
	// never fail the login response. Bounded by a 5-second timeout
	// so the goroutine cannot linger if the storage hangs (which
	// would also bound any goroutine leak on shutdown).
	go func(uid string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.users.RecordLogin(ctx, uid); err != nil {
			h.logger.Warn("login: RecordLogin failed (non-fatal)",
				"err", err.Error(), "user_id", uid)
		}
	}(user.ID)

	// Reset the per-IP failure counter on successful login (spec §5.3).
	h.rateLimiter.Reset(ip)

	// Audit success — populate ActorUserID directly because the soft-auth
	// context keys are not set on no-auth endpoints.
	h.appendAudit(r, audit.Event{
		Action:                audit.ActionLoginSuccess,
		ActorUserID:           user.ID,
		ActorUsernameSnapshot: user.Username,
	})

	writeJSON(w, http.StatusOK, loginResponse{
		ID:          user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
	})
}

// emitLoginFailure records a login_failure audit event. Used by both
// the "user not found" and "bad password" branches.
func (h *Handler) emitLoginFailure(r *http.Request, attemptedUsername, reason string) {
	h.appendAudit(r, audit.Event{
		Action:                audit.ActionLoginFailure,
		ActorUsernameSnapshot: attemptedUsername,
		Message:               reason,
	})
}

// --- POST /api/v1/auth/logout ----------------------------------------------

// logout handles POST /api/v1/auth/logout (spec §4.4). Group: soft-auth.
//
// Idempotent on the client side: a missing cookie returns 401 but the
// frontend treats that as success ("the user is now logged out").
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	sessionID := auth.SessionIDFromContext(r.Context())
	userID := auth.UserIDFromContext(r.Context())

	// Soft-auth middleware guarantees these are set if we got here.
	if err := h.sessions.Delete(r.Context(), sessionID); err != nil {
		h.logger.Warn("logout: session delete failed (non-fatal)", "err", err.Error(), "session_id", sessionID)
	}
	clearSessionCookieOnResponse(w, h.devMode)
	// Clear the theme cookie too — the "explicit logout" lifecycle path
	// in spec §4.5 clears both cookies. (Silent expirations leave the
	// theme cookie in place; only the explicit /logout call wipes it.)
	clearThemeCookieOnResponse(w, h.devMode)

	h.appendAudit(r, audit.Event{
		Action:                audit.ActionLogout,
		ActorUserID:           userID,
		ActorUsernameSnapshot: auth.UsernameFromContext(r.Context()),
		TargetType:            "session",
		TargetID:              sessionID,
		Message:               "manual",
	})

	w.WriteHeader(http.StatusNoContent)
}

// clearSessionCookieOnResponse is the api-layer counterpart of the
// auth-layer helper of the same name (which lives in middleware.go).
// Duplicated here so the api package does not need to reach into the
// auth package's private helpers. All cookie attributes match those
// of creation per spec §4.11.
func clearSessionCookieOnResponse(w http.ResponseWriter, devMode bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !devMode,
		SameSite: http.SameSiteStrictMode,
	})
}

// --- GET /api/v1/auth/me ---------------------------------------------------

// meResponse is the wire shape for GET /api/v1/auth/me. Spec §4.5
// (extended in Step F §3.3 to include ThemePreference).
type meResponse struct {
	ID                  string `json:"id"`
	Username            string `json:"username"`
	DisplayName         string `json:"displayName"`
	Locked              bool   `json:"locked"`
	PasswordCompromised bool   `json:"passwordCompromised"`
	HIBPCheckStatus     string `json:"hibpCheckStatus"`
	// ThemePreference is "dark", "light", or "" (legacy users who never
	// visited Settings). The frontend treats "" as "dark" per §4.2.
	ThemePreference string `json:"themePreference"`
}

// me handles GET /api/v1/auth/me (spec §4.5). Group: soft-auth.
//
// CRITICAL: this handler must NOT touch Session.LastActivity. The
// soft-auth middleware does not call Touch (spec §5.6), and the
// handler itself does not either. Polling /me must never extend
// the idle timer (otherwise the lock screen becomes unreachable).
//
// A regression test (TestMe_DoesNotTouchSession) protects this
// invariant.
func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := auth.UserIDFromContext(ctx)

	// The soft-auth middleware already loaded the User to populate
	// the context. We re-fetch here to get the live HIBP fields
	// (which the deferred re-check at login may have updated).
	user, err := h.users.GetByID(ctx, userID)
	if err != nil {
		h.logger.Error("me: user lookup failed", "err", err, "user_id", userID)
		writeError(w, http.StatusServiceUnavailable, "authentication service temporarily unavailable")
		return
	}

	writeJSON(w, http.StatusOK, meResponse{
		ID:                  user.ID,
		Username:            user.Username,
		DisplayName:         user.DisplayName,
		Locked:              auth.IsLockedFromContext(ctx),
		PasswordCompromised: user.PasswordCompromised,
		HIBPCheckStatus:     user.HIBPCheckStatus,
		ThemePreference:     user.ThemePreference,
	})
}

// --- POST /api/v1/auth/unlock ----------------------------------------------

// unlockRequest is the wire shape for POST /api/v1/auth/unlock. Spec §4.6.
type unlockRequest struct {
	Password string `json:"password"`
}

// unlockResponse is the success body.
type unlockResponse struct {
	Unlocked bool `json:"unlocked"`
}

// unlock handles POST /api/v1/auth/unlock (spec §4.6). Group: soft-auth.
//
// Re-authenticates an idle session by verifying the password. On
// success: Touch the session (lifting idle state), reset rate limit.
// On failure: audit + 401 + rate-limit counter increments via middleware.
func (h *Handler) unlock(w http.ResponseWriter, r *http.Request) {
	var req unlockRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	ctx := r.Context()
	userID := auth.UserIDFromContext(ctx)
	username := auth.UsernameFromContext(ctx)
	sessionID := auth.SessionIDFromContext(ctx)

	// Record the attempted username (we know it from soft-auth) so
	// the rate-limit middleware can include it in Tier 2 logs.
	ctx = auth.SetAttemptedUsername(ctx, username)
	r = r.WithContext(ctx)

	user, err := h.users.GetByID(ctx, userID)
	if err != nil {
		h.logger.Error("unlock: user lookup failed", "err", err, "user_id", userID)
		writeError(w, http.StatusServiceUnavailable, "authentication service temporarily unavailable")
		return
	}

	match, err := argon2id.ComparePasswordAndHash(req.Password, user.PasswordHash)
	if err != nil {
		h.logger.Error("unlock: argon2id compare failed", "err", err, "user_id", userID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !match {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionUnlockFailure,
			Message: "bad_password",
		})
		writeError(w, http.StatusUnauthorized, "invalid password")
		return
	}

	// Success: Touch the session to lift the idle state.
	if err := h.sessions.Touch(ctx, sessionID); err != nil {
		h.logger.Warn("unlock: session touch failed (non-fatal)", "err", err.Error(), "session_id", sessionID)
	}

	// Reset rate-limit counter for this IP (spec §5.3).
	h.rateLimiter.Reset(auth.ClientIPFromContext(ctx))

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionUnlockSuccess,
		TargetType: "session",
		TargetID:   sessionID,
	})

	writeJSON(w, http.StatusOK, unlockResponse{Unlocked: true})
}

// --- POST /api/v1/auth/heartbeat -------------------------------------------

// heartbeat handles POST /api/v1/auth/heartbeat (spec §4.7). Group: hard-auth.
//
// The hard-auth middleware has already called Touch by the time this
// handler runs; this body therefore just returns 204.
func (h *Handler) heartbeat(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// --- GET /api/v1/auth/sessions ---------------------------------------------

// sessionResponse is the wire shape for one session entry. Spec §4.8.
type sessionResponse struct {
	ID           string `json:"id"`
	IssuedAt     string `json:"issuedAt"`
	LastActivity string `json:"lastActivity"`
	ExpiresAt    string `json:"expiresAt"`
	IP           string `json:"ip"`
	UserAgent    string `json:"userAgent"`
	RememberMe   bool   `json:"rememberMe"`
	IsCurrent    bool   `json:"isCurrent"`
}

// listSessionsResponse wraps the session list per spec §4.8.
type listSessionsResponse struct {
	Sessions []sessionResponse `json:"sessions"`
}

// listSessions handles GET /api/v1/auth/sessions (spec §4.8). Group: hard-auth.
//
// Returns every non-expired session owned by the current user.
// `isCurrent` is true for the session whose ID matches the cookie of
// this request.
func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := auth.UserIDFromContext(ctx)
	currentSessionID := auth.SessionIDFromContext(ctx)

	all, err := h.sessions.ListForUser(ctx, userID)
	if err != nil {
		h.logger.Error("listSessions: failed", "err", err, "user_id", userID)
		writeError(w, http.StatusServiceUnavailable, "authentication service temporarily unavailable")
		return
	}

	now := time.Now().UTC()
	out := make([]sessionResponse, 0, len(all))
	for _, s := range all {
		// Filter expired sessions server-side per spec §4.8.
		if now.After(s.ExpiresAt) {
			continue
		}
		out = append(out, sessionResponse{
			ID:           s.ID,
			IssuedAt:     s.IssuedAt.UTC().Format(timestampFormat),
			LastActivity: s.LastActivity.UTC().Format(timestampFormat),
			ExpiresAt:    s.ExpiresAt.UTC().Format(timestampFormat),
			IP:           s.IP,
			UserAgent:    s.UserAgent,
			RememberMe:   s.RememberMe,
			IsCurrent:    s.ID == currentSessionID,
		})
	}

	writeJSON(w, http.StatusOK, listSessionsResponse{Sessions: out})
}

// --- DELETE /api/v1/auth/sessions/{id} -------------------------------------

// deleteSession handles DELETE /api/v1/auth/sessions/{id} (spec §4.9).
// Group: hard-auth.
//
// Security: returns 404 when the session belongs to another user (rather
// than 403) to prevent discovering which session IDs belong to which users
// by trial.
func (h *Handler) deleteSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	ctx := r.Context()
	currentUserID := auth.UserIDFromContext(ctx)

	sess, err := h.sessions.Get(ctx, id)
	if err != nil {
		if errors.Is(err, auth.ErrSessionNotFound) || errors.Is(err, auth.ErrSessionExpired) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		h.logger.Error("deleteSession: lookup failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "authentication service temporarily unavailable")
		return
	}
	if sess.UserID != currentUserID {
		// Foreign session: same 404 as not-found (anti-enumeration).
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	if err := h.sessions.Delete(ctx, id); err != nil {
		h.logger.Error("deleteSession: delete failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "authentication service temporarily unavailable")
		return
	}

	// Audit the revocation. BeforeJSON captures the revoked session
	// (sans secrets — Session has no PasswordHash field).
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionSessionRevoked,
		TargetType: "session",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(sess),
	})

	w.WriteHeader(http.StatusNoContent)
}

// --- POST /api/v1/auth/me/password -----------------------------------------

// changePasswordRequest is the wire shape for POST /api/v1/auth/me/password
// (spec §4.9bis).
type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// changePassword handles POST /api/v1/auth/me/password (spec §4.9bis).
// Group: hard-auth.
//
// Flow:
//  1. Verify currentPassword against the stored hash (401 on mismatch).
//  2. Validate the new password (length + top-10k + HIBP).
//  3. UserStore.UpdatePassword (resets HIBPCheckStatus, PasswordCompromised).
//  4. Revoke ALL OTHER sessions of this user (DeleteAllForUserExcept).
//  5. Audit password_changed (no BeforeJSON/AfterJSON — D3 forbids hash leaks).
//  6. Return 204.
//
// Security: a wrong currentPassword does NOT emit a login_failure-style
// audit event (the user is already authenticated; a typo is observability
// noise, not an authentication failure per spec §4.9bis). It is logged
// at Info level for operational visibility.
func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "currentPassword and newPassword are required")
		return
	}

	ctx := r.Context()
	userID := auth.UserIDFromContext(ctx)
	currentSessionID := auth.SessionIDFromContext(ctx)

	user, err := h.users.GetByID(ctx, userID)
	if err != nil {
		h.logger.Error("changePassword: user lookup failed", "err", err, "user_id", userID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	match, err := argon2id.ComparePasswordAndHash(req.CurrentPassword, user.PasswordHash)
	if err != nil {
		h.logger.Error("changePassword: argon2id compare failed", "err", err, "user_id", userID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !match {
		h.logger.Info("changePassword: currentPassword incorrect",
			"user_id", userID,
			"ip", auth.ClientIPFromContext(ctx),
		)
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	// Validate the new password BEFORE writing anything.
	if _, err := auth.ValidatePasswordSync(ctx, h.hibp, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, auth.ErrPasswordTooShort):
			writeError(w, http.StatusBadRequest, "password must be at least 15 characters")
		case errors.Is(err, auth.ErrPasswordTooLong):
			writeError(w, http.StatusBadRequest, "password must be at most 128 characters")
		case errors.Is(err, auth.ErrPasswordCommon):
			writeError(w, http.StatusBadRequest, "password is in the list of common compromised passwords")
		default:
			h.logger.Error("changePassword: validation unexpected error", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	// Persist the new password (UpdatePassword internally resets
	// HIBPCheckStatus to "pending", PasswordCompromised to false,
	// HIBPCheckedAt to zero, UpdatedAt to now — Chunk 1).
	if err := h.users.UpdatePassword(ctx, userID, req.NewPassword); err != nil {
		h.logger.Error("changePassword: UpdatePassword failed", "err", err, "user_id", userID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Revoke all OTHER sessions of this user. The current session
	// (whose cookie made this request) is preserved.
	revoked, err := h.sessions.DeleteAllForUserExcept(ctx, userID, currentSessionID)
	if err != nil {
		// Non-fatal: the password has already been changed. Log Warn
		// and continue. The other sessions will still get 401 at their
		// next request because PasswordHash mismatch is not the
		// invalidation channel (only session deletion is); but
		// pragmatically this is highly unlikely to fail in isolation
		// — the DB write before just succeeded.
		h.logger.Warn("changePassword: revoking other sessions failed (non-fatal)",
			"err", err.Error(), "user_id", userID)
	} else if revoked > 0 {
		h.logger.Info("changePassword: other sessions revoked",
			"user_id", userID, "revoked_count", revoked)
	}

	// Audit (post-success per D2). No BeforeJSON/AfterJSON: D3 forbids
	// PasswordHash in audit content, and the only changed field is the
	// hash. Action + ActorUserID + TargetID are sufficient.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionPasswordChanged,
		TargetType: "user",
		TargetID:   userID,
	})

	w.WriteHeader(http.StatusNoContent)
}

// --- POST /api/v1/auth/me/theme --------------------------------------------

// updateThemeRequest is the wire shape for POST /api/v1/auth/me/theme.
// Step F spec §3.3. Method is POST (not PATCH) for verb consistency
// with the analogous /me/password endpoint.
type updateThemeRequest struct {
	Theme string `json:"theme"` // "dark" or "light"
}

// updateTheme handles POST /api/v1/auth/me/theme (Step F §3.3).
// Group: hard-auth (same as /me/password).
//
// 204 on success, 400 on invalid body / invalid theme value,
// 401/403 via middleware, 500 on storage error.
//
// No audit emission: theme is a user-preference setting, not a
// security event (spec §3.4, brainstorm verbatim "c'est du
// paramétrage user, pas sécurité"). The D7 audit action set (15
// entries) is therefore unchanged.
func (h *Handler) updateTheme(w http.ResponseWriter, r *http.Request) {
	var req updateThemeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Theme != auth.ThemeDark && req.Theme != auth.ThemeLight {
		writeError(w, http.StatusBadRequest, "theme must be \"dark\" or \"light\"")
		return
	}

	ctx := r.Context()
	userID := auth.UserIDFromContext(ctx)

	if err := h.users.UpdateThemePreference(ctx, userID, req.Theme); err != nil {
		// ErrThemeInvalid here would mean the validation above passed but
		// the store rejected the value — should be unreachable, but map
		// it to 400 to stay consistent. Everything else is a 500.
		if errors.Is(err, auth.ErrThemeInvalid) {
			writeError(w, http.StatusBadRequest, "theme must be \"dark\" or \"light\"")
			return
		}
		h.logger.Error("updateTheme: UpdateThemePreference failed",
			"err", err, "user_id", userID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Refresh the arenet_theme cookie so the FOUC bootstrap on the
	// next paint reflects the new preference immediately (spec §4.5).
	// req.Theme is already validated to be exactly "dark" or "light"
	// at this point — no need to re-normalize.
	setThemeCookie(w, req.Theme, h.devMode)

	w.WriteHeader(http.StatusNoContent)
}

// --- GET /api/v1/audit ------------------------------------------------------

// auditEventWire is the wire shape for one event returned by /audit.
// Mirrors audit.Event but with camelCase JSON tags and parsed
// JSON for Before/After fields (not escaped strings) per spec §4.10.
type auditEventWire struct {
	ID                    string          `json:"id"`
	Timestamp             string          `json:"timestamp"`
	ActorUserID           string          `json:"actorUserId,omitempty"`
	ActorUsernameSnapshot string          `json:"actorUsernameSnapshot,omitempty"`
	Action                string          `json:"action"`
	TargetType            string          `json:"targetType,omitempty"`
	TargetID              string          `json:"targetId,omitempty"`
	BeforeJSON            json.RawMessage `json:"beforeJson"`
	AfterJSON             json.RawMessage `json:"afterJson"`
	Message               string          `json:"message,omitempty"`
	IP                    string          `json:"ip,omitempty"`
	UserAgent             string          `json:"userAgent,omitempty"`
}

// listAuditResponse wraps the events list with the pagination cursor.
type listAuditResponse struct {
	Events     []auditEventWire `json:"events"`
	NextCursor string           `json:"nextCursor"`
}

// listAudit handles GET /api/v1/audit (spec §4.10). Group: hard-auth.
//
// Parses query params into audit.Filter, fetches via audit.Store.List,
// converts to wire form (camelCase + parsed Before/After), and emits
// an `audit_viewed` event capturing the filters used (spec §4.10 +
// decision Q5 self-audit).
func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := audit.Filter{
		ActorUserID: q.Get("actor_user_id"),
		Action:      q.Get("action"),
		TargetType:  q.Get("target_type"),
		TargetID:    q.Get("target_id"),
		Cursor:      q.Get("cursor"),
	}

	if s := q.Get("from"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'from' timestamp")
			return
		}
		filter.From = t
	}
	if s := q.Get("to"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'to' timestamp")
			return
		}
		filter.To = t
	}
	if s := q.Get("limit"); s != "" {
		n, err := parseLimit(s)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'limit' parameter")
			return
		}
		filter.Limit = n
	}

	events, nextCursor, err := h.audit.List(r.Context(), filter)
	if err != nil {
		// Distinguish invalid cursor (user error → 400) from other
		// errors (server fault → 500).
		if strings.Contains(err.Error(), "invalid cursor") {
			writeError(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		h.logger.Error("listAudit: List failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	wire := make([]auditEventWire, 0, len(events))
	for _, e := range events {
		wire = append(wire, auditEventWire{
			ID:                    e.ID,
			Timestamp:             e.Timestamp.UTC().Format(timestampFormat),
			ActorUserID:           e.ActorUserID,
			ActorUsernameSnapshot: e.ActorUsernameSnapshot,
			Action:                e.Action,
			TargetType:            e.TargetType,
			TargetID:              e.TargetID,
			BeforeJSON:            e.BeforeJSON,
			AfterJSON:             e.AfterJSON,
			Message:               e.Message,
			IP:                    e.IP,
			UserAgent:             e.UserAgent,
		})
	}

	// Audit the audit query itself (self-audit per Q5).
	h.appendAudit(r, audit.Event{
		Action:  audit.ActionAuditViewed,
		Message: filterToString(filter),
	})

	writeJSON(w, http.StatusOK, listAuditResponse{
		Events:     wire,
		NextCursor: nextCursor,
	})
}

// parseLimit parses the limit query parameter and clamps it to the
// permitted range. Returns an error if the string is not an integer.
func parseLimit(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("negative limit")
	}
	return n, nil
}

// filterToString produces a compact human-readable representation of
// a Filter for inclusion in the audit_viewed event's Message field.
// Example: "action=login_failure&from=2026-05-01"
func filterToString(f audit.Filter) string {
	parts := []string{}
	if f.ActorUserID != "" {
		parts = append(parts, "actor_user_id="+f.ActorUserID)
	}
	if f.Action != "" {
		parts = append(parts, "action="+f.Action)
	}
	if f.TargetType != "" {
		parts = append(parts, "target_type="+f.TargetType)
	}
	if f.TargetID != "" {
		parts = append(parts, "target_id="+f.TargetID)
	}
	if !f.From.IsZero() {
		parts = append(parts, "from="+f.From.UTC().Format(time.RFC3339))
	}
	if !f.To.IsZero() {
		parts = append(parts, "to="+f.To.UTC().Format(time.RFC3339))
	}
	if f.Limit > 0 {
		parts = append(parts, fmt.Sprintf("limit=%d", f.Limit))
	}
	if f.Cursor != "" {
		parts = append(parts, "cursor=<set>")
	}
	return strings.Join(parts, "&")
}
