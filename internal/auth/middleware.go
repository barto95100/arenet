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
	"strings"
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
// Phase 4 — Bearer fallback. When the cookie is absent OR the
// cookie lookup fails (no session row, expired session row, deleted
// underlying user), the middleware then tries to authenticate via
// an Authorization: Bearer <token> header. The Bearer path is
// strictly a FALLBACK:
//   - Cookie present + session valid → use cookie. Bearer ignored
//     even if simultaneously sent (avoids "who am I?" confusion
//     when a human in DevTools sends a Bearer for a script test).
//   - Cookie absent OR cookie invalid → try Bearer.
//   - Bearer valid → attach the service-account user to the ctx;
//     SessionIDKey is empty and IsLockedKey is false (no
//     session, no idle window).
//   - Bearer absent / invalid in the fallback path → 401 (same as
//     pre-Phase-4 behaviour for cookie-less requests).
//
// The tokens parameter is OPTIONAL — pass nil to disable the
// Bearer path entirely (preserves the pre-Phase-4 surface for
// callers that don't wire APITokenStore).
//
// On failure, responds with HTTP 401 and clears the session cookie
// (Set-Cookie with Max-Age=0). On success, calls the next handler
// with the context enriched with UserIDKey, UsernameKey,
// SessionIDKey, IsLockedKey, RoleKey, and AuthSourceKey.
//
// The middleware does NOT call sessionStore.Touch() — that would
// reset the idle timer on every /me call and make the lock screen
// unreachable. Touch is the hard-auth middleware's responsibility
// (spec §5.6, §5.7).
//
// devMode controls whether the Set-Cookie attributes include Secure
// (omitted in --dev for HTTP local). Spec §4.11.
func SoftAuthMiddleware(sessions sessionStore, users userStore, tokens APITokenLookup, devMode bool) func(http.Handler) http.Handler {
	if sessions == nil {
		panic("auth.SoftAuthMiddleware: sessions is nil")
	}
	if users == nil {
		panic("auth.SoftAuthMiddleware: users is nil")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Cookie path — try first. If the cookie produces a
			// valid (user, session) pair, that wins; Bearer is
			// IGNORED on this request even if present.
			if cookie, err := r.Cookie(sessionCookieName); err == nil {
				if user, session, ok := resolveSessionCookie(w, r, sessions, users, cookie.Value); ok {
					isLocked := time.Since(session.LastActivity) > SessionIdleTimeout
					ctx := withAuthIdentity(r.Context(), user, session.ID, isLocked)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// Cookie was present but invalid; fall through to
				// Bearer. resolveSessionCookie already cleared the
				// stale cookie via Set-Cookie.
			}

			// 2. Bearer fallback — only when tokens store is wired
			// AND an Authorization header is present.
			if tokens != nil {
				if user, tok, ok := resolveBearerToken(r, tokens, users); ok {
					// Best-effort LastUsedAt update; never block
					// the request on a write contention.
					go func(id string) {
						_ = tokens.TouchLastUsed(context.Background(), id)
					}(tok.ID)
					ctx := withAuthIdentity(r.Context(), user, "", false)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// 3. Neither path produced an identity. 401 with the
			// same generic message — never leaks which path
			// failed (cookie miss vs Bearer miss).
			writeAuthError(w, "no active session")
		})
	}
}

// resolveSessionCookie looks up the cookie value, fetches the
// session + user, and returns them on success. On failure, the
// stale cookie is cleared on the response. The ok flag is false
// when either the session is gone/expired or the user is missing.
//
// Storage-level 503 errors short-circuit by returning ok=false
// AND writing the 503 directly; the caller treats that as a
// terminal failure and must not also try the Bearer fallback (the
// underlying bbolt is the same — Bearer would 503 too).
func resolveSessionCookie(
	w http.ResponseWriter,
	r *http.Request,
	sessions sessionStore,
	users userStore,
	cookieValue string,
) (User, Session, bool) {
	session, err := sessions.Get(r.Context(), cookieValue)
	if err != nil {
		// Both ErrSessionNotFound and ErrSessionExpired surface
		// as a cleared cookie and "fall through to Bearer". The
		// distinction is preserved at the storage layer for
		// observability (spec §3.3).
		clearSessionCookie(w, r)
		return User{}, Session{}, false
	}

	user, err := users.GetByID(r.Context(), session.UserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Session references a deleted user. Clean up and
			// fall through.
			_ = sessions.Delete(r.Context(), session.ID)
			clearSessionCookie(w, r)
			return User{}, Session{}, false
		}
		// Storage error (decision D11): 503 terminally — no
		// point trying Bearer since it would hit the same
		// bbolt.
		writeServiceUnavailable(w, "authentication service temporarily unavailable")
		return User{}, Session{}, false
	}

	return user, session, true
}

// resolveBearerToken parses Authorization: Bearer, validates the
// token, and resolves the owning user. Returns ok=false silently
// (no response written) so the caller can write the unified 401.
//
// Revoked / expired tokens come back as ok=false: leaking the
// reason via a distinct status would let an attacker probe whether
// a token ever existed.
func resolveBearerToken(
	r *http.Request,
	tokens APITokenLookup,
	users userStore,
) (User, APIToken, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return User{}, APIToken{}, false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return User{}, APIToken{}, false
	}
	plain := strings.TrimSpace(header[len(prefix):])
	if plain == "" {
		return User{}, APIToken{}, false
	}
	tok, err := tokens.LookupToken(r.Context(), plain)
	if err != nil {
		return User{}, APIToken{}, false
	}
	if tok.RevokedAt != nil {
		return User{}, APIToken{}, false
	}
	now := time.Now().UTC()
	if tok.ExpiresAt != nil && !tok.ExpiresAt.After(now) {
		return User{}, APIToken{}, false
	}
	user, err := users.GetByID(r.Context(), tok.UserID)
	if err != nil {
		return User{}, APIToken{}, false
	}
	return user, tok, true
}

// withAuthIdentity populates the ctx keys downstream middleware /
// handlers read. sessionID is "" for Bearer-authenticated
// requests; isLocked is always false on the Bearer path (no idle
// timer applies to service accounts).
func withAuthIdentity(ctx context.Context, user User, sessionID string, isLocked bool) context.Context {
	ctx = context.WithValue(ctx, UserIDKey, user.ID)
	ctx = context.WithValue(ctx, UsernameKey, user.Username)
	ctx = context.WithValue(ctx, SessionIDKey, sessionID)
	ctx = context.WithValue(ctx, IsLockedKey, isLocked)
	ctx = context.WithValue(ctx, RoleKey, user.Role)
	ctx = context.WithValue(ctx, AuthSourceKey, user.AuthSource)
	return ctx
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
func HardAuthMiddleware(sessions sessionStore, users userStore, tokens APITokenLookup, devMode bool) func(http.Handler) http.Handler {
	soft := SoftAuthMiddleware(sessions, users, tokens, devMode)
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

			// Bearer-authenticated requests carry an empty SessionID
			// (no session to touch). Skip the Touch call rather than
			// calling sessions.Touch("") which would either error or
			// silently no-op depending on the store implementation —
			// either way it's misleading in logs.
			sessionID, _ := r.Context().Value(SessionIDKey).(string)
			if sessionID != "" {
				if err := sessions.Touch(r.Context(), sessionID); err != nil {
					// Touch is best-effort. Log a warning but do not fail
					// the request: the user has already passed auth.
					slog.Default().Warn("auth: session touch failed",
						slog.String("err", err.Error()),
						slog.String("session_id", sessionID),
					)
				}
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
// so the browser correctly matches the cookie for deletion.
//
// Step #S-11: Secure is set based on the actual request scheme
// (TLS terminated by Arenet) rather than the devMode flag. Browsers
// silently drop Secure cookies on non-HTTPS (with localhost as the
// only exception), so a prod deployment accessed via LAN HTTP must
// not flag the cookie Secure or the browser will refuse to store it
// — breaking login despite a 200 response.
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // sentinel for "delete now"
		HttpOnly: true,
		Secure:   r != nil && r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}
