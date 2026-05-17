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
