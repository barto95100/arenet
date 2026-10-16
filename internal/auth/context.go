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

// Context propagation primitives shared by the auth middlewares (Soft/
// Hard), the IP extractor (Section 8), the rate limiter (Section 5.3),
// and the audit helpers in internal/api (Section 5.9).
//
// Defining ctxKey as a package-private type prevents accidental
// collision with context keys used by other packages, per Go's standard
// library guidance. The accessors return zero values (empty string,
// false) on missing keys so handlers don't need defensive type
// assertions.

package auth

import "context"

// ctxKey is the unexported type used for all auth-related context
// keys. Using a distinct type avoids collisions across packages.
type ctxKey string

// Context keys populated by the auth middlewares.
const (
	// UserIDKey is the authenticated user's ID (UUID v4 string).
	// Populated by SoftAuthMiddleware on success.
	UserIDKey ctxKey = "auth.user_id"

	// UsernameKey is the authenticated user's username.
	// Populated by SoftAuthMiddleware on success.
	UsernameKey ctxKey = "auth.username"

	// TokenIDKey is the service-account API token's ID for a
	// Bearer-authenticated request, and empty for a cookie session
	// (v2.73). Added so a long-lived stream can re-check the TOKEN
	// that opened it, not merely the user behind it: revoking a token
	// leaves the service account in place, so a user-only re-check
	// would let a revoked token keep streaming.
	TokenIDKey ctxKey = "auth.token_id"

	// SessionIDKey is the current session ID (43-char base64url string).
	// Populated by SoftAuthMiddleware on success.
	SessionIDKey ctxKey = "auth.session_id"

	// IsLockedKey is true when the session is in the idle lock state
	// (LastActivity older than the idle timeout). Populated by
	// SoftAuthMiddleware; consumed by /me to populate its "locked"
	// response field, and by HardAuthMiddleware to reject the request
	// with 403.
	IsLockedKey ctxKey = "auth.is_locked"

	// ClientIPKey is the resolved client IP, X-Forwarded-For aware
	// when the immediate caller is in ARENET_TRUSTED_PROXIES.
	// Populated by IPExtractMiddleware near the top of the stack.
	ClientIPKey ctxKey = "auth.client_ip"

	// RequestSecureKey is true when the request reached Arenet over a
	// secure transport — either directly (r.TLS != nil) or through a
	// TLS-terminating proxy whose immediate hop is in the trusted set
	// (loopback ∪ ARENET_TRUSTED_PROXIES) that forwarded
	// X-Forwarded-Proto: https. Populated by IPExtractMiddleware;
	// consumed by the Set-Cookie helpers in internal/api to decide the
	// Secure attribute (F11). The trust gate matches ClientIPKey's:
	// X-Forwarded-Proto from an untrusted caller is ignored, so a
	// client cannot forge a secure context.
	RequestSecureKey ctxKey = "auth.request_secure"

	// RoleKey is the authenticated user's role ("viewer" or
	// "admin") populated by SoftAuthMiddleware on success.
	// Consumed by RequireAdminMiddleware to gate write
	// endpoints (Step K.2 §1.3 decision 12).
	RoleKey ctxKey = "auth.role"

	// AuthSourceKey is the authenticated user's auth source
	// ("local" or "oidc"). Populated by SoftAuthMiddleware on
	// success. Consumed by the local-admin password rotation
	// audit hook (Step K.2 AC #11) and by the break-glass audit
	// emission decision (AC #10).
	AuthSourceKey ctxKey = "auth.source"

	// MustChangePasswordKey is true when the authenticated account
	// must rotate its password before it may do anything else — an
	// admin-created local account still on its one-time initial
	// password. Populated by SoftAuthMiddleware; enforced server-side
	// by HardAuthMiddleware, which 403s every endpoint but the
	// password-change one (v2.73, F23). The SPA overlay is UX on top.
	MustChangePasswordKey ctxKey = "auth.must_change_password"

	// attemptedUsernameKey is the username submitted by an
	// unauthenticated /login or /unlock attempt. Stored by the
	// handler via SetAttemptedUsername so the rate-limit middleware
	// can include it in Tier 2 Warn logs. Unexported because callers
	// MUST use the typed accessors, never raw context.Value.
	attemptedUsernameKey ctxKey = "auth.attempted_username"
)

// UserIDFromContext returns the authenticated user's ID, or empty
// string if the request is not authenticated.
func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(UserIDKey).(string)
	return v
}

// UsernameFromContext returns the authenticated user's username, or
// empty string if the request is not authenticated.
func UsernameFromContext(ctx context.Context) string {
	v, _ := ctx.Value(UsernameKey).(string)
	return v
}

// SessionIDFromContext returns the current session ID, or empty
// string if the request is not authenticated.
func SessionIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(SessionIDKey).(string)
	return v
}

// TokenIDFromContext returns the API token's ID for a
// Bearer-authenticated request, or empty string for a cookie session
// or an unauthenticated request.
func TokenIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(TokenIDKey).(string)
	return v
}

// IsLockedFromContext returns true if the session is in the idle
// lock state. Only meaningful within soft-auth handlers; hard-auth
// handlers receive non-idle sessions by definition.
func IsLockedFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(IsLockedKey).(bool)
	return v
}

// ClientIPFromContext returns the resolved client IP, X-Forwarded-For
// aware. Returns empty string when the IP extractor has not run or
// when r.RemoteAddr was unparseable.
func ClientIPFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ClientIPKey).(string)
	return v
}

// RequestIsSecureFromContext reports whether the request reached
// Arenet over a secure transport (direct TLS, or a trusted proxy that
// forwarded X-Forwarded-Proto: https). Returns false when
// IPExtractMiddleware has not run, which is the safe default: a cookie
// without Secure is still stored, whereas a Secure cookie set over a
// genuinely plaintext context would be silently dropped by the browser.
func RequestIsSecureFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(RequestSecureKey).(bool)
	return v
}

// RoleFromContext returns the authenticated user's role
// ("viewer" or "admin"), or empty string when the request is
// unauthenticated. The empty case is safe: every callsite that
// matters (RequireAdminMiddleware, audit emission) gates on the
// explicit "admin" value, so an empty Role denies admin actions
// by construction.
func RoleFromContext(ctx context.Context) string {
	v, _ := ctx.Value(RoleKey).(string)
	return v
}

// AuthSourceFromContext returns the authenticated user's auth
// source ("local" or "oidc"), or empty string when the request
// is unauthenticated. Consumed by the local-admin password
// rotation audit hook + the break-glass audit emission.
func AuthSourceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(AuthSourceKey).(string)
	return v
}

// MustChangePasswordFromContext reports whether the authenticated
// account must rotate its password before it may do anything else.
func MustChangePasswordFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(MustChangePasswordKey).(bool)
	return v
}

// SetAttemptedUsername returns a new context carrying the username
// submitted by an unauthenticated /login or /unlock attempt. The
// rate-limit middleware reads this value after the handler runs to
// enrich Tier 2 Warn logs. Pattern: handlers call ctx = SetAttemptedUsername(ctx, username)
// and pass r.WithContext(ctx) to writers.
//
// The value is never used for authentication decisions; it is
// observability metadata only. A missing or empty value is OK.
func SetAttemptedUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, attemptedUsernameKey, username)
}

// AttemptedUsernameFromContext returns the username stored via
// SetAttemptedUsername, or empty string when the handler did not
// set one (e.g. malformed body, no /login or /unlock invocation).
func AttemptedUsernameFromContext(ctx context.Context) string {
	v, _ := ctx.Value(attemptedUsernameKey).(string)
	return v
}
