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

package api

import (
	"context"
	"errors"
	"time"

	"github.com/barto95100/arenet/internal/auth"
)

// A revoked session loses its stream (v2.73).
//
// The three streaming endpoints — /ws/geo-events, /ws/topology and
// /topology/stream — were authorized exactly once, by
// HardAuthMiddleware, before the upgrade. After that the handlers
// looped forever and never consulted the session, the user record or
// the role again. Neither sets a read deadline or a maximum lifetime
// either, so the CLIENT decided how long a stale grant lasted.
//
// Every session-termination control the product ships was therefore
// ineffective on these sockets: signing out, revoking the session from
// the Sessions page, deleting the account, demoting the role, and the
// 15-minute idle lock. The operator saw the revocation succeed, the
// audit log recorded it, every HTTP surface answered 401 — and the
// socket kept emitting one frame per request reaching the proxy, for
// as long as the peer held the TCP connection open.
//
// What those frames carry is why it matters: /ws/geo-events emits
// every source IP hitting the proxy with its country, route and block
// decision, and the topology streams emit per-route traffic rates,
// hostnames and upstream URLs.

// streamReauthInterval is how often a live stream re-checks its own
// authorization.
//
// 30 s is chosen against what it bounds: the idle lock is 15 minutes,
// so a third of a minute is negligible against the control it
// enforces, while a revocation an operator performs deliberately takes
// effect faster than they can switch windows to check. The cost is one
// bbolt read per stream per interval.
const streamReauthInterval = 30 * time.Second

// errStreamUnauthorized is returned when the stream must close. The
// specific reason is deliberately NOT carried to the peer: a client
// that can distinguish "revoked" from "locked" from "deleted" learns
// about the instance's state from a socket it no longer owns.
var errStreamUnauthorized = errors.New("stream authorization lapsed")

// streamReauthorizer re-checks a live stream's authorization. The
// stream handlers hold this interface rather than the stores, so a
// test can drive the revocation directly instead of racing a clock
// against a database.
type streamReauthorizer interface {
	// reauthorizeStream returns nil while the identity that opened the
	// stream may keep it, and an error once it may not.
	reauthorizeStream(ctx context.Context, sessionID, tokenID string) error
}

// reauthorizeStream implements streamReauthorizer against the
// handler's own stores, mirroring what SoftAuthMiddleware and
// HardAuthMiddleware check on an ordinary request.
//
// Both authentication paths are covered, because both can open a
// stream:
//
//   - a cookie session: the session must still exist, must not have
//     expired, and must not have gone idle past auth.SessionIdleTimeout
//     — which is what makes the idle lock apply to a socket at all;
//   - a service-account Bearer token: the token must still exist, must
//     not be revoked and must not have expired. The token is checked
//     by its own id and not merely through its user, because revoking
//     a token leaves the service account in place: a user-only
//     re-check would let a revoked token keep streaming.
//
// And in both cases the user must still exist and still hold a role.
// A deleted account cascades its sessions, so the session check would
// usually catch it first; the explicit user read covers a role
// demotion and the Bearer path, where there is no session to cascade.
func (h *Handler) reauthorizeStream(ctx context.Context, sessionID, tokenID string) error {
	switch {
	case sessionID != "":
		session, err := h.sessions.Get(ctx, sessionID)
		if err != nil {
			// Not found or expired — the store distinguishes them for
			// observability, and for this decision they are the same.
			return errStreamUnauthorized
		}
		// The idle lock, applied to a socket. HardAuthMiddleware
		// refuses a request past this point; a stream that outlived
		// it was the only authenticated surface that did not.
		if time.Since(session.LastActivity) > auth.SessionIdleTimeout {
			return errStreamUnauthorized
		}
		return h.streamUserStillValid(ctx, session.UserID)

	case tokenID != "":
		if h.apiTokens == nil {
			// No token store wired: nothing to re-check, and the
			// stream could not have been opened with a token either.
			return nil
		}
		tok, err := h.apiTokens.GetByID(ctx, tokenID)
		if err != nil {
			return errStreamUnauthorized
		}
		if tok.RevokedAt != nil {
			return errStreamUnauthorized
		}
		if tok.ExpiresAt != nil && !tok.ExpiresAt.After(time.Now().UTC()) {
			return errStreamUnauthorized
		}
		return h.streamUserStillValid(ctx, tok.UserID)
	}

	// Neither credential in the context. The stream passed hard auth
	// to get here, so this is a wiring error rather than an attack —
	// but a stream nobody can be held responsible for is exactly what
	// this function exists to close.
	return errStreamUnauthorized
}

// streamUserStillValid reports whether the identity behind a stream
// still exists and still holds a recognised role.
func (h *Handler) streamUserStillValid(ctx context.Context, userID string) error {
	user, err := h.users.GetByID(ctx, userID)
	if err != nil {
		return errStreamUnauthorized
	}
	// Any recognised role may hold these streams — they are
	// viewer-accessible by design. An unrecognised role is a user
	// whose grant no longer parses, which is not a grant.
	if user.Role != auth.UserRoleAdmin && user.Role != auth.UserRoleViewer {
		return errStreamUnauthorized
	}
	return nil
}

// streamCredentials pulls the session id and token id a stream was
// opened with out of the upgrade request's context, so the loop can
// re-check them without re-parsing a cookie or a header.
func streamCredentials(ctx context.Context) (sessionID, tokenID string) {
	return auth.SessionIDFromContext(ctx), auth.TokenIDFromContext(ctx)
}

// streamStillAuthorized reports whether a live stream may continue.
//
// A nil reauthorizer answers yes. NewRouter wires one into all three
// stream handlers unconditionally, and a test pins that, so nil means
// a handler built directly in a test — not a production path. Failing
// open there keeps those tests meaningful instead of closing every
// stream they open; failing closed in production is what the wiring
// test protects.
func streamStillAuthorized(ctx context.Context, ra streamReauthorizer, sessionID, tokenID string) bool {
	if ra == nil {
		return true
	}
	return ra.reauthorizeStream(ctx, sessionID, tokenID) == nil
}
