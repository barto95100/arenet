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
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
)

// wsTestEnv wires the minimal API surface needed by the WS topology
// tests: a real router (so HardAuthMiddleware actually runs), a
// real metrics.Broadcaster, a bootstrapped admin session whose
// cookie value is exposed so tests can attach it to dial headers.
type wsTestEnv struct {
	srv         *httptest.Server
	broadcaster *metrics.Broadcaster
	sessionID   string
	userID      string
	sessions    *auth.SessionStore
}

// newWSTestEnv builds the env and the auth fixtures. Closes the
// httptest.Server in t.Cleanup.
func newWSTestEnv(t *testing.T) *wsTestEnv {
	t.Helper()

	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	caddy := &fakeReloader{}
	auditAppender := &fakeAuditAppender{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Setenv("ARENET_HIBP_DISABLED", "true")
	userStore := auth.NewUserStore(store.DB())
	sessionStore := auth.NewSessionStore(store.DB())
	hibpClient := auth.NewHIBPClient()
	rateLimiter := auth.NewRateLimiter(logger)
	setupTokenHolder := NewSetupTokenHolder()
	ipExtractor, _ := auth.NewIPExtractor("")

	h := NewHandler(store, caddy, auditAppender, userStore, sessionStore, hibpClient, rateLimiter, setupTokenHolder, false, logger)

	broadcaster := metrics.NewBroadcaster(logger)
	wsHandler := NewWSTopologyHandler(broadcaster, true /* dev allows empty Origin */, logger)

	router := NewRouter(h, true, ipExtractor, wsHandler)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// Bootstrap a real admin user + session so HardAuthMiddleware can
	// authenticate dials that present the cookie.
	ctx := context.Background()
	user, err := userStore.Create(ctx, "tester", "Tester", "test-password-15c-xx")
	if err != nil {
		t.Fatalf("bootstrap user: %v", err)
	}
	sess, err := sessionStore.Create(ctx, user.ID, false, "127.0.0.1", "ws-test/1")
	if err != nil {
		t.Fatalf("bootstrap session: %v", err)
	}

	return &wsTestEnv{
		srv:         srv,
		broadcaster: broadcaster,
		sessionID:   sess.ID,
		userID:      user.ID,
		sessions:    sessionStore,
	}
}

// wsURL converts the env's HTTP test-server URL into a ws:// URL for
// the topology endpoint.
func (e *wsTestEnv) wsURL(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(e.srv.URL)
	if err != nil {
		t.Fatalf("parse srv URL: %v", err)
	}
	u.Scheme = "ws"
	u.Path = "/api/v1/ws/topology"
	return u.String()
}

// authHeader returns the cookie header attaching the bootstrapped
// session to a WS dial.
func (e *wsTestEnv) authHeader() http.Header {
	return http.Header{
		"Cookie": []string{"arenet_session=" + e.sessionID},
	}
}

// --- Tests -----------------------------------------------------------------

func TestWS_Topology_RequiresAuth(t *testing.T) {
	env := newWSTestEnv(t)

	// Dial WITHOUT the session cookie. HardAuthMiddleware MUST reject
	// the handshake BEFORE the WebSocket upgrade happens. Spec §5.1.
	_, resp, err := websocket.DefaultDialer.Dial(env.wsURL(t), nil)
	if err == nil {
		t.Fatal("expected dial to fail without cookie")
	}
	if resp == nil {
		t.Fatalf("no HTTP response on rejected dial; err=%v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("handshake status=%d, want 401", resp.StatusCode)
	}
	// Spec §5.4: NO upgrade on auth failure. ErrBadHandshake confirms
	// the upgrade never completed.
	if !errors.Is(err, websocket.ErrBadHandshake) {
		t.Errorf("dial err=%v, want websocket.ErrBadHandshake", err)
	}
}

func TestWS_Topology_LockedSession_403(t *testing.T) {
	env := newWSTestEnv(t)

	// Backdate LastActivity past the idle threshold so the session is
	// "locked". HardAuthMiddleware must return 403 BEFORE the upgrade.
	sess, err := env.sessions.Get(context.Background(), env.sessionID)
	if err != nil {
		t.Fatalf("Get session: %v", err)
	}
	sess.LastActivity = time.Now().UTC().Add(-(auth.SessionIdleTimeout + time.Minute))
	if err := env.sessions.PutForTest(context.Background(), sess); err != nil {
		t.Fatalf("PutForTest backdated session: %v", err)
	}

	_, resp, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err == nil {
		t.Fatal("expected dial to fail on locked session")
	}
	if resp == nil {
		t.Fatalf("no HTTP response on rejected dial; err=%v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("handshake status=%d, want 403 (locked session)", resp.StatusCode)
	}
	if !errors.Is(err, websocket.ErrBadHandshake) {
		t.Errorf("dial err=%v, want websocket.ErrBadHandshake (no upgrade on 403)", err)
	}
}

func TestWS_Topology_Upgrades_AndStreams(t *testing.T) {
	env := newWSTestEnv(t)

	conn, resp, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer conn.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("handshake status=%d, want 101", resp.StatusCode)
	}

	// Publish a snapshot — the WS handler should forward it as a
	// JSON frame matching spec §5.2.
	want := metrics.Snapshot{
		T: time.Now().UTC(),
		Routes: []metrics.RouteSnapshot{
			{
				ID:         "rid-1",
				Host:       "app.example",
				Upstream:   "http://10.0.0.1:80",
				Reqs:       42,
				Errs:       1,
				ReqPerSec:  42,
				ErrRate5xx: 0.0238,
			},
		},
	}
	env.broadcaster.Publish(want)

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	msgType, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if msgType != websocket.TextMessage {
		t.Errorf("msgType=%d, want TextMessage", msgType)
	}

	var got metrics.Snapshot
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal frame: %v\npayload=%s", err, payload)
	}
	if len(got.Routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(got.Routes))
	}
	if got.Routes[0].ID != "rid-1" || got.Routes[0].Host != "app.example" {
		t.Errorf("route mismatch: %+v", got.Routes[0])
	}
	if got.Routes[0].Reqs != 42 || got.Routes[0].Errs != 1 {
		t.Errorf("counters mismatch: reqs=%d errs=%d", got.Routes[0].Reqs, got.Routes[0].Errs)
	}
}

func TestWS_Topology_SlowClient_DropsTicks(t *testing.T) {
	env := newWSTestEnv(t)

	// Two connections: one slow (never reads), one fast (reads every
	// frame). Slow's channel fills up; the broadcaster's non-blocking
	// publish (spec §5.6) drops its ticks. Fast must continue
	// receiving without delay.
	slowConn, _, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err != nil {
		t.Fatalf("dial slow: %v", err)
	}
	defer slowConn.Close()

	fastConn, _, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err != nil {
		t.Fatalf("dial fast: %v", err)
	}
	defer fastConn.Close()

	// Give the server time to register both subscriptions.
	// SubscriberCount is the cleanest barrier.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if env.broadcaster.SubscriberCount() == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := env.broadcaster.SubscriberCount(); got != 2 {
		t.Fatalf("SubscriberCount=%d, want 2 after both dials", got)
	}

	// Fire off many publishes. Slow never drains; fast drains
	// continuously.
	const N = 10
	go func() {
		// Drain fast in a tight loop so its channel never blocks.
		_ = fastConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for i := 0; i < N; i++ {
			if _, _, err := fastConn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for i := 0; i < N; i++ {
		env.broadcaster.Publish(metrics.Snapshot{
			T: time.Now().UTC(),
			Routes: []metrics.RouteSnapshot{
				{ID: "rid-1", Host: "h", Upstream: "u", Reqs: uint64(i)},
			},
		})
		time.Sleep(10 * time.Millisecond)
	}

	// If the slow subscriber had blocked Publish, fewer than N
	// frames would have been observable by fast. Confirm by reading
	// the count of frames "seen by the broadcaster": since fast
	// drains fully, the broadcaster's view should be that publishes
	// succeed for both (with drops on slow).
	//
	// The runnable proof here is: we reached this line. If the slow
	// client had blocked the publish, the per-publish call would
	// hang on the slow channel's blocked send. Since Publish uses
	// select+default (§5.6), it does not hang.
	//
	// Sub-assertion: SubscriberCount is still 2 (server didn't drop
	// the slow client just because it's slow).
	if got := env.broadcaster.SubscriberCount(); got != 2 {
		t.Errorf("SubscriberCount=%d after N publishes, want 2 (slow client kept)", got)
	}
}

func TestWS_Topology_ServerShutdown_Code1001(t *testing.T) {
	// httptest.Server.Close tears down TCP connections abruptly,
	// giving our handler no chance to send the close frame. We need
	// http.Server.Shutdown(ctx) which drains in-flight requests
	// gracefully. So this test builds its own server with a context
	// we control directly.

	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	caddy := &fakeReloader{}
	auditAppender := &fakeAuditAppender{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Setenv("ARENET_HIBP_DISABLED", "true")
	userStore := auth.NewUserStore(store.DB())
	sessionStore := auth.NewSessionStore(store.DB())
	hibpClient := auth.NewHIBPClient()
	rateLimiter := auth.NewRateLimiter(logger)
	setupTokenHolder := NewSetupTokenHolder()
	ipExtractor, _ := auth.NewIPExtractor("")

	h := NewHandler(store, caddy, auditAppender, userStore, sessionStore, hibpClient, rateLimiter, setupTokenHolder, false, logger)
	broadcaster := metrics.NewBroadcaster(logger)

	// Build a wsHandler bound to a context we can cancel. The
	// shutdown signal propagates to ServeHTTP via the request
	// context after we call http.Server.Shutdown.
	wsHandler := NewWSTopologyHandler(broadcaster, true, logger)
	router := NewRouter(h, true, ipExtractor, wsHandler)

	// Bootstrap an admin session.
	ctx := context.Background()
	user, err := userStore.Create(ctx, "tester", "Tester", "test-password-15c-xx")
	if err != nil {
		t.Fatalf("bootstrap user: %v", err)
	}
	sess, err := sessionStore.Create(ctx, user.ID, false, "127.0.0.1", "ws-test/1")
	if err != nil {
		t.Fatalf("bootstrap session: %v", err)
	}

	// Manually-managed server with a controllable BaseContext.
	// http.Server.Shutdown does not cancel request contexts of
	// hijacked connections (gorilla/websocket hijacks on upgrade),
	// so we wire our own cancellable base context that propagates
	// to r.Context() inside ServeHTTP. Cancelling it triggers our
	// ctx.Done() branch and emits the 1001 close frame.
	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()
	srv := &http.Server{
		Handler: router,
		BaseContext: func(_ net.Listener) context.Context {
			return srvCtx
		},
	}
	ln, err := newLocalListener(t)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	wsURL := "ws://" + ln.Addr().String() + "/api/v1/ws/topology"
	headers := http.Header{"Cookie": []string{"arenet_session=" + sess.ID}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Wait for the subscription to register.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if broadcaster.SubscriberCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := broadcaster.SubscriberCount(); got != 1 {
		t.Fatalf("SubscriberCount=%d, want 1", got)
	}

	// Generous read deadline so we observe the close frame before
	// the client's own timeout kicks in.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Cancel the BaseContext — this propagates through r.Context()
	// inside ServeHTTP's select loop (hijacked connection or not),
	// firing the ctx.Done() branch that writes the 1001 close frame.
	srvCancel()

	// ReadMessage should return a CloseError with code 1001.
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("expected ReadMessage to return an error after shutdown")
	}
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) {
		t.Fatalf("err is not *websocket.CloseError: %T %v", err, err)
	}
	if closeErr.Code != websocket.CloseGoingAway {
		t.Errorf("close code=%d, want %d (CloseGoingAway / 1001)", closeErr.Code, websocket.CloseGoingAway)
	}
}

// newLocalListener returns a TCP listener bound to an OS-chosen port
// on 127.0.0.1. Used by TestWS_Topology_ServerShutdown_Code1001 to
// build a manually-managed server.
func newLocalListener(t *testing.T) (net.Listener, error) {
	t.Helper()
	return net.Listen("tcp", "127.0.0.1:0")
}

// --- Constructor panic tests ----------------------------------------------

func TestNewWSTopologyHandler_NilBroadcaster_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil broadcaster")
		}
	}()
	NewWSTopologyHandler(nil, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestNewWSTopologyHandler_NilLogger_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil logger")
		}
	}()
	NewWSTopologyHandler(metrics.NewBroadcaster(slog.New(slog.NewTextHandler(io.Discard, nil))), false, nil)
}

// --- CheckOrigin behavior --------------------------------------------------

func TestWS_Topology_CheckOrigin_DevAllowsVite(t *testing.T) {
	env := newWSTestEnv(t)

	// httptest dial sets Origin to the test server's host by default
	// (e.g. http://127.0.0.1:PORT). In dev mode our CheckOrigin
	// tolerates empty Origin, but a Vite-like Origin header must
	// ALSO be accepted. Set it explicitly and confirm the dial
	// succeeds with a session cookie attached.
	headers := env.authHeader()
	headers.Set("Origin", "http://localhost:5173")
	conn, _, err := websocket.DefaultDialer.Dial(env.wsURL(t), headers)
	if err != nil {
		t.Fatalf("dial with Origin=:5173 in dev: %v", err)
	}
	_ = conn.Close()
}

func TestWS_Topology_CheckOrigin_DevRejectsForeign(t *testing.T) {
	env := newWSTestEnv(t)

	headers := env.authHeader()
	headers.Set("Origin", "http://evil.example")
	_, resp, err := websocket.DefaultDialer.Dial(env.wsURL(t), headers)
	if err == nil {
		t.Fatal("dial with foreign Origin should fail")
	}
	// gorilla rejects with 403 when CheckOrigin returns false.
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("status=%v, want 403", resp)
	}
	if !strings.Contains(err.Error(), "bad handshake") {
		// Acceptable; the precise error string is gorilla-internal.
		t.Logf("dial err (informational): %v", err)
	}
}
