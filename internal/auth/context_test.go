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
	"testing"
)

func TestContextAccessors_EmptyContext(t *testing.T) {
	ctx := context.Background()
	if got := UserIDFromContext(ctx); got != "" {
		t.Errorf("UserID empty ctx: got %q, want \"\"", got)
	}
	if got := UsernameFromContext(ctx); got != "" {
		t.Errorf("Username empty ctx: got %q, want \"\"", got)
	}
	if got := SessionIDFromContext(ctx); got != "" {
		t.Errorf("SessionID empty ctx: got %q, want \"\"", got)
	}
	if got := IsLockedFromContext(ctx); got {
		t.Error("IsLocked empty ctx: got true, want false")
	}
	if got := ClientIPFromContext(ctx); got != "" {
		t.Errorf("ClientIP empty ctx: got %q, want \"\"", got)
	}
}

func TestContextAccessors_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, UserIDKey, "user-uuid-123")
	ctx = context.WithValue(ctx, UsernameKey, "admin")
	ctx = context.WithValue(ctx, SessionIDKey, "session-id-abc")
	ctx = context.WithValue(ctx, IsLockedKey, true)
	ctx = context.WithValue(ctx, ClientIPKey, "203.0.113.5")

	if got := UserIDFromContext(ctx); got != "user-uuid-123" {
		t.Errorf("UserID: got %q", got)
	}
	if got := UsernameFromContext(ctx); got != "admin" {
		t.Errorf("Username: got %q", got)
	}
	if got := SessionIDFromContext(ctx); got != "session-id-abc" {
		t.Errorf("SessionID: got %q", got)
	}
	if got := IsLockedFromContext(ctx); !got {
		t.Error("IsLocked: got false, want true")
	}
	if got := ClientIPFromContext(ctx); got != "203.0.113.5" {
		t.Errorf("ClientIP: got %q", got)
	}
}

// TestContextAccessors_WrongType verifies the accessors do not panic
// when a value of the wrong type is stored under one of the keys.
// Returning the zero value is the documented contract.
func TestContextAccessors_WrongType(t *testing.T) {
	ctx := context.Background()
	// Store an int where a string is expected, and vice versa.
	ctx = context.WithValue(ctx, UserIDKey, 42)
	ctx = context.WithValue(ctx, IsLockedKey, "not a bool")

	if got := UserIDFromContext(ctx); got != "" {
		t.Errorf("UserID wrong-type: got %q, want \"\"", got)
	}
	if got := IsLockedFromContext(ctx); got {
		t.Error("IsLocked wrong-type: got true, want false")
	}
}

// TestCtxKey_DistinctTypeIsolation verifies that the unexported ctxKey
// type isolates auth context values from accidental collision with
// plain-string keys used by other packages. Uses a string key
// intentionally to demonstrate the isolation; this is NOT a pattern
// to follow in production code.
func TestCtxKey_DistinctTypeIsolation(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, "auth.user_id", "leaked-from-string-key")
	if got := UserIDFromContext(ctx); got != "" {
		t.Errorf("ctxKey isolation broken: got %q via plain-string key", got)
	}
}

// TestAttemptedUsername_RoundTrip covers the handler→middleware
// observability channel used by the rate limiter (Commit B).
func TestAttemptedUsername_RoundTrip(t *testing.T) {
	ctx := context.Background()

	// Empty by default.
	if got := AttemptedUsernameFromContext(ctx); got != "" {
		t.Errorf("default: got %q, want \"\"", got)
	}

	ctx2 := SetAttemptedUsername(ctx, "admin")
	if got := AttemptedUsernameFromContext(ctx2); got != "admin" {
		t.Errorf("after Set: got %q, want \"admin\"", got)
	}

	// Original context unchanged (immutability invariant).
	if got := AttemptedUsernameFromContext(ctx); got != "" {
		t.Errorf("original ctx mutated: got %q, want \"\"", got)
	}

	// Overwrite.
	ctx3 := SetAttemptedUsername(ctx2, "other")
	if got := AttemptedUsernameFromContext(ctx3); got != "other" {
		t.Errorf("after overwrite: got %q, want \"other\"", got)
	}

	// Empty string is a valid value (signals "handler tried but no username available").
	ctx4 := SetAttemptedUsername(ctx, "")
	if got := AttemptedUsernameFromContext(ctx4); got != "" {
		t.Errorf("explicit empty: got %q, want \"\"", got)
	}
}
