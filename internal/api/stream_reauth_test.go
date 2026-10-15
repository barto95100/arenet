// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/api/topology"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/metrics"
)

// A revoked session loses its stream (v2.73).
//
// The three streaming endpoints were authorized exactly once, before
// the upgrade, and then looped forever without consulting the session,
// the user or the role again. Every session-termination control the
// product ships was ineffective on them: signing out, revoking from
// the Sessions page, deleting the account, demoting the role, and the
// 15-minute idle lock. The operator saw the revocation succeed and the
// socket kept emitting every source IP hitting the proxy.

func seedStreamUser(t *testing.T, env *testEnv, admin bool) auth.User {
	t.Helper()
	users := auth.NewUserStore(env.store.DB())
	ctx := context.Background()
	if admin {
		u, err := users.Create(ctx, "boss", "Boss", "", "a-long-enough-password-x")
		if err != nil {
			t.Fatalf("seed admin: %v", err)
		}
		return u
	}
	u, err := users.CreateOIDCUser(ctx, "watcher", "Watcher", "", "sub-watcher")
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	return u
}

func TestReauthorizeStream_LiveSessionIsAuthorized(t *testing.T) {
	env := newTestEnv(t, false)
	u := seedStreamUser(t, env, false)
	s, err := auth.NewSessionStore(env.store.DB()).Create(
		context.Background(), u.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	if err := env.handler.reauthorizeStream(context.Background(), s.ID, ""); err != nil {
		t.Fatalf("a live session must keep its stream: %v", err)
	}
}

// The case the finding describes: the operator revokes the session
// from the Sessions page, every HTTP surface answers 401, and the
// socket used to keep streaming.
func TestReauthorizeStream_RevokedSessionLosesIt(t *testing.T) {
	env := newTestEnv(t, false)
	u := seedStreamUser(t, env, false)
	sessions := auth.NewSessionStore(env.store.DB())
	ctx := context.Background()
	s, err := sessions.Create(ctx, u.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := sessions.Delete(ctx, s.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if err := env.handler.reauthorizeStream(ctx, s.ID, ""); err == nil {
		t.Error("a revoked session must lose its stream — this is the control the " +
			"operator used, and the socket outlived it")
	}
}

// Account deletion cascades the sessions, so the session check catches
// it; asserted explicitly because it is the second control the finding
// names and it must not depend on cascade ordering.
func TestReauthorizeStream_DeletedAccountLosesIt(t *testing.T) {
	env := newTestEnv(t, false)
	users := auth.NewUserStore(env.store.DB())
	u := seedStreamUser(t, env, false)
	ctx := context.Background()
	s, err := auth.NewSessionStore(env.store.DB()).Create(ctx, u.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := users.Delete(ctx, u.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	if err := env.handler.reauthorizeStream(ctx, s.ID, ""); err == nil {
		t.Error("a deleted account must lose its stream")
	}
}

// The idle lock, applied to a socket. HardAuthMiddleware refuses a
// request past auth.SessionIdleTimeout; a stream was the only
// authenticated surface that did not.
func TestReauthorizeStream_IdleLockClosesIt(t *testing.T) {
	env := newTestEnv(t, false)
	u := seedStreamUser(t, env, false)
	sessions := auth.NewSessionStore(env.store.DB())
	ctx := context.Background()
	s, err := sessions.Create(ctx, u.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// Age the session past the lock by rewriting LastActivity, which
	// is what the clock would do. Asserted against the real constant
	// rather than a literal, so a change to the timeout cannot leave
	// this test pinning a value the product no longer uses.
	stale := s
	stale.LastActivity = time.Now().Add(-auth.SessionIdleTimeout - time.Minute)
	if err := sessions.PutForTest(ctx, stale); err != nil {
		t.Fatalf("age the session: %v", err)
	}

	if err := env.handler.reauthorizeStream(ctx, s.ID, ""); err == nil {
		t.Error("an idle-locked session must lose its stream: the lock gates every other " +
			"authenticated surface")
	}
}

// Neither credential in the context is a wiring error, and a stream
// nobody can be held responsible for is what this closes.
func TestReauthorizeStream_NoCredentialIsRefused(t *testing.T) {
	env := newTestEnv(t, false)
	if err := env.handler.reauthorizeStream(context.Background(), "", ""); err == nil {
		t.Error("a stream with no identity in its context must be refused")
	}
}

// An unknown session id is refused, which also covers a client
// replaying an id it made up.
func TestReauthorizeStream_UnknownSessionIsRefused(t *testing.T) {
	env := newTestEnv(t, false)
	if err := env.handler.reauthorizeStream(context.Background(), "not-a-session", ""); err == nil {
		t.Error("an unknown session id must be refused")
	}
}

// The wiring is the part that makes all of the above reach production.
// A handler whose reauthorizer is nil answers "still authorized" by
// design, so an unwired handler silently restores the defect.
func TestNewRouter_WiresStreamReauthorization(t *testing.T) {
	env := newTestEnv(t, false)
	ipExtractor, err := auth.NewIPExtractor("")
	if err != nil {
		t.Fatalf("ip extractor: %v", err)
	}

	// Real dependencies: the constructors panic on nil, which is a
	// good thing and means this test exercises the production shape.
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	broadcaster := metrics.NewBroadcaster(logger)
	ws := NewWSTopologyHandler(broadcaster, false, logger)
	stream := NewStreamHandler(
		broadcaster, env.store, topology.NewSlidingWindow(), nil, 1000, false, logger,
	)
	// The geo handler accepts a nil bus by design (documented
	// degraded mode), so nil is the production shape here.
	geo := NewWSGeoEventsHandler(nil, false, nil)

	_ = NewRouter(env.handler, false, ipExtractor, ws, nil, stream, geo)

	if ws.reauth == nil {
		t.Error("/ws/topology has no reauthorizer: its stream would outlive a revocation")
	}
	if stream.reauth == nil {
		t.Error("/topology/stream has no reauthorizer")
	}
	if geo.reauth == nil {
		t.Error("/ws/geo-events has no reauthorizer")
	}
}
