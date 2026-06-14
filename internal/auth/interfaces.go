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

import "context"

// sessionStore is the subset of *SessionStore that SoftAuthMiddleware
// and HardAuthMiddleware depend on. Defined consumer-side (in this
// file rather than as the public surface of *SessionStore) so the
// middleware can be tested with hand-rolled mocks without booting
// bbolt.
//
// *SessionStore (sessionstore.go) naturally satisfies this interface;
// no adapter is needed. The interface is unexported because it is an
// implementation detail of this package — outside callers should use
// the concrete *SessionStore directly.
type sessionStore interface {
	// Get returns the session by ID, or ErrSessionNotFound /
	// ErrSessionExpired. Does NOT touch LastActivity (idle window
	// detection is the middleware's job).
	Get(ctx context.Context, id string) (Session, error)

	// Touch refreshes LastActivity and extends ExpiresAt by the
	// sliding TTL. Called by HardAuthMiddleware AFTER the idle check
	// succeeds — never before (sub-test security #1 in plan §4.2).
	Touch(ctx context.Context, id string) error

	// Delete removes the session. Called by SoftAuthMiddleware when
	// a session references a deleted user (clean-up of orphans).
	// Idempotent.
	Delete(ctx context.Context, id string) error
}

// userStore is the subset of *UserStore that the middleware depends on.
// Same rationale as sessionStore: consumer-side interface for mock
// injection, unexported because internal to this package.
type userStore interface {
	// GetByID returns the user by ID, or ErrUserNotFound.
	GetByID(ctx context.Context, id string) (User, error)
}

// APITokenLookup is the subset of *APITokenStore that SoftAuth
// depends on for the Bearer fallback (Phase 4). Defined as an
// exported interface so middleware tests can inject a fake without
// a real bbolt-backed token store.
//
// nil-injection is supported: SoftAuthMiddleware accepts a nil
// APITokenLookup when the caller wants cookie-only behaviour
// (existing tests, --no-api-tokens builds). When nil, Bearer headers
// are silently ignored and the cookie path runs unchanged.
//
// The interface is exported (capitalised) so the api.Handler can
// declare a field of this type and pass plain nil to the
// middleware without typed-nil-interface pitfalls — the api
// package never sees the concrete *APITokenStore type behind the
// interface, so `h.tokens == nil` works as expected.
type APITokenLookup interface {
	// LookupToken hashes the plain string and returns the matching
	// row (active OR not — caller inspects RevokedAt/ExpiresAt).
	// ErrAPITokenInvalid covers both wrong-prefix strings and hash
	// misses so the middleware can return a uniform 401 without
	// leaking whether a token ever existed.
	LookupToken(ctx context.Context, plain string) (APIToken, error)
	// TouchLastUsed updates the LastUsedAt timestamp. Best-effort —
	// the middleware fires it from a goroutine and ignores errors.
	TouchLastUsed(ctx context.Context, id string) error
}

// Compile-time assertions: the concrete stores from sessionstore.go
// and userstore.go satisfy the consumer-side interfaces above.
//
// These declarations have no runtime effect; the compiler verifies
// the interface conformance and emits an error if either type ever
// stops matching (e.g., a future refactor removes Touch from
// *SessionStore). They are the "single source of truth" for the
// auth middleware's dependency contract.
var (
	_ sessionStore   = (*SessionStore)(nil)
	_ userStore      = (*UserStore)(nil)
	_ APITokenLookup = (*APITokenStore)(nil)
)
