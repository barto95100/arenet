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

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// sessionCookieName is the cookie sent to and received from browsers.
// Spec §4.11.
const sessionCookieName = "arenet_session"

// SoftAuthMiddleware returns a chi-compatible middleware that
// validates the session cookie and populates the request context
// with user identity. It allows idle sessions (LastActivity outside
// the 15-min window) so that the lock screen flow can function
// (/me, /unlock).
//
// On failure, responds with HTTP 401 and clears the session cookie
// (Set-Cookie with Max-Age=0). On success, calls the next handler
// with the context enriched with UserIDKey, UsernameKey,
// SessionIDKey, and IsLockedKey.
//
// The middleware does NOT call sessionStore.Touch() — that would
// reset the idle timer on every /me call and make the lock screen
// unreachable. Touch is the hard-auth middleware's responsibility
// (spec §5.6, §5.7).
//
// devMode controls whether the Set-Cookie attributes include Secure
// (omitted in --dev for HTTP local). Spec §4.11.
func SoftAuthMiddleware(sessions sessionStore, users userStore, devMode bool) func(http.Handler) http.Handler {
	if sessions == nil {
		panic("auth.SoftAuthMiddleware: sessions is nil")
	}
	if users == nil {
		panic("auth.SoftAuthMiddleware: users is nil")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(sessionCookieName)
			if err != nil {
				writeAuthError(w, "no active session")
				return
			}

			session, err := sessions.Get(r.Context(), cookie.Value)
			if err != nil {
				// Both ErrSessionNotFound and ErrSessionExpired map to 401.
				// Distinguishing them is preserved at the storage layer
				// for observability (spec §3.3), but the user-visible
				// outcome is identical: drop the stale cookie and 401.
				clearSessionCookie(w, devMode)
				writeAuthError(w, "no active session")
				return
			}

			user, err := users.GetByID(r.Context(), session.UserID)
			if err != nil {
				if errors.Is(err, ErrUserNotFound) {
					// Session references a deleted user. Clean up and 401.
					_ = sessions.Delete(r.Context(), session.ID)
					clearSessionCookie(w, devMode)
					writeAuthError(w, "no active session")
					return
				}
				// Storage error (decision D11): 503.
				writeServiceUnavailable(w, "authentication service temporarily unavailable")
				return
			}

			// Compute is_locked once here for downstream consumers.
			// time.Since reads the wall clock; the session's
			// LastActivity is UTC (set by SessionStore.Create and
			// SessionStore.Touch).
			isLocked := time.Since(session.LastActivity) > SessionIdleTimeout

			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIDKey, user.ID)
			ctx = context.WithValue(ctx, UsernameKey, user.Username)
			ctx = context.WithValue(ctx, SessionIDKey, session.ID)
			ctx = context.WithValue(ctx, IsLockedKey, isLocked)
			// Step K.2: surface Role + AuthSource for the
			// RequireAdminMiddleware (role gate on business
			// endpoints) + the audit hooks (break-glass
			// emission, local-admin password rotation flag).
			ctx = context.WithValue(ctx, RoleKey, user.Role)
			ctx = context.WithValue(ctx, AuthSourceKey, user.AuthSource)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// HardAuthMiddleware returns a chi-compatible middleware that
// validates the session AND refuses idle sessions.
//
// Composition: HardAuthMiddleware WRAPS SoftAuthMiddleware rather
// than duplicating its logic. Any change to the session lookup
// happens in one place.
//
// SECURITY-CRITICAL ORDERING (spec §5.7, plan §7.3, sub-test #1):
// the Touch call MUST happen AFTER the idle check. If Touch ran
// first, LastActivity would be refreshed for a session that we are
// about to reject as idle, making the lock screen unreachable. The
// test TestHardAuthMiddleware_TouchAfterCheck verifies this ordering
// and will FAIL if Touch is moved before the check.
//
// devMode is propagated to the wrapped SoftAuthMiddleware for
// clearSessionCookie attribute consistency.
func HardAuthMiddleware(sessions sessionStore, users userStore, devMode bool) func(http.Handler) http.Handler {
	soft := SoftAuthMiddleware(sessions, users, devMode)
	return func(next http.Handler) http.Handler {
		// The chained handler runs AFTER soft-auth has populated the
		// context. We read IsLockedKey to decide whether to 403 or
		// proceed; if proceeding, we call Touch BEFORE the next
		// handler so it observes the refreshed LastActivity.
		hard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if locked, _ := r.Context().Value(IsLockedKey).(bool); locked {
				// CRITICAL: return BEFORE calling Touch.
				writeForbidden(w, "session locked")
				return
			}

			sessionID, _ := r.Context().Value(SessionIDKey).(string)
			if err := sessions.Touch(r.Context(), sessionID); err != nil {
				// Touch is best-effort. Log a warning but do not fail
				// the request: the user has already passed auth.
				slog.Default().Warn("auth: session touch failed",
					slog.String("err", err.Error()),
					slog.String("session_id", sessionID),
				)
			}

			next.ServeHTTP(w, r)
		})
		return soft(hard)
	}
}

// RequireAdminMiddleware returns a chi-compatible middleware that
// gates the wrapped handler on the authenticated user's role
// being "admin" (Step K.2 §1.3 decision 12). Returns 403 with
// {"error":"admin role required"} when the request is from a
// viewer (or, defensively, from any non-admin role).
//
// MUST be composed INSIDE the HardAuthMiddleware chain — it
// reads RoleKey populated by SoftAuth (transitively, via Hard).
// Composing it outside means the role check runs against an
// empty Role, which would deny by construction (the empty
// string never equals "admin"). That's safe but misleading;
// the explicit composition order is HardAuth → RequireAdmin →
// handler.
//
// Endpoints that DO NOT require admin (the viewer-accessible
// surfaces): GET /routes, GET /audit, GET /topology, GET /me,
// POST /me/password (self-rotate), POST /me/theme. All writes
// to routes / settings / users gate on admin.
func RequireAdminMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := RoleFromContext(r.Context())
			if role != UserRoleAdmin {
				writeForbidden(w, "admin role required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- HTTP response helpers (private to this package) ---------------------

// writeAuthError sends a 401 JSON response with the supplied message.
// The body follows the spec §4 error envelope: {"error": "<message>"}.
func writeAuthError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// writeForbidden sends a 403 JSON response. Used by HardAuthMiddleware
// when a session is in the idle lock state (spec §4.4 cookie attributes
// + spec §5.7).
func writeForbidden(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// writeServiceUnavailable sends a 503 JSON response. Used when a
// storage error prevents authentication from completing (decision D11).
func writeServiceUnavailable(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// clearSessionCookie sets a Set-Cookie header that instructs the
// browser to drop the arenet_session cookie. All cookie attributes
// match those used at creation (HttpOnly, SameSite=Strict, Path=/)
// so the browser correctly matches the cookie for deletion. Secure
// is omitted in dev mode (HTTP local) per spec §4.11.
func clearSessionCookie(w http.ResponseWriter, devMode bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // sentinel for "delete now"
		HttpOnly: true,
		Secure:   !devMode,
		SameSite: http.SameSiteStrictMode,
	})
}
