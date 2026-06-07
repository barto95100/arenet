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
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/barto95100/arenet/internal/api/topology"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
)

// streamTestEnv mirrors wsTestEnv (ws_topology_test.go) but for the
// new /api/v1/topology/stream endpoint. It wires a real Router so
// HardAuthMiddleware actually runs, a real Broadcaster + Window +
// Store (with a single test route), and a bootstrapped admin
// session whose cookie is exposed for dial headers.
type streamTestEnv struct {
	srv         *httptest.Server
	broadcaster *metrics.Broadcaster
	window      *topology.SlidingWindow
	store       *storage.Store
	sessionID   string
}

func newStreamTestEnv(t *testing.T, tickMs int) *streamTestEnv {
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
	window := topology.NewSlidingWindow()
	streamHandler := NewStreamHandler(
		broadcaster, store, window, nil /* status: not exercised here */, tickMs, true, logger,
	)
	// Snapshot handler at /topology/snapshot isn't dialled by these
	// tests, but keeping it nil keeps NewRouter generic.

	router := NewRouter(h, true, ipExtractor, nil, nil, streamHandler, nil)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// Bootstrap an admin user + session for hard-auth.
	ctx := context.Background()
	user, err := userStore.Create(ctx, "tester", "Tester", "test-password-15c-xx")
	if err != nil {
		t.Fatalf("bootstrap user: %v", err)
	}
	sess, err := sessionStore.Create(ctx, user.ID, false, "127.0.0.1", "stream-test/1")
	if err != nil {
		t.Fatalf("bootstrap session: %v", err)
	}

	return &streamTestEnv{
		srv:         srv,
		broadcaster: broadcaster,
		window:      window,
		store:       store,
		sessionID:   sess.ID,
	}
}

func (e *streamTestEnv) wsURL(t *testing.T) string {
	t.Helper()
	u, _ := url.Parse(e.srv.URL)
	u.Scheme = "ws"
	u.Path = "/api/v1/topology/stream"
	return u.String()
}

func (e *streamTestEnv) authHeader() http.Header {
	return http.Header{"Cookie": []string{"arenet_session=" + e.sessionID}}
}

// readSnapshotFrame reads one JSON text frame from the WS conn
// and decodes it as a topology.SnapshotResponse. Sets a 2 s read
// deadline so a stuck server fails fast.
func readSnapshotFrame(t *testing.T, conn *websocket.Conn) topology.SnapshotResponse {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var resp topology.SnapshotResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode frame: %v\nraw: %s", err, raw)
	}
	return resp
}

// --- snap-up unit tests for the tickMs → emitEveryN conversion ---

func TestStreamHandler_EmitEveryN_SnapUp(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	broadcaster := metrics.NewBroadcaster(logger)
	store := &fakeRouteLister{}
	window := topology.NewSlidingWindow()

	cases := []struct {
		tickMs int
		want   int
	}{
		// Exact multiples — no snap.
		{1000, 1}, {2000, 2}, {3000, 3}, {60000, 60},
		// Non-multiples — snap UP.
		{1500, 2}, {2500, 3}, {2999, 3}, {3001, 4},
		// Non-positive — defaults to 2 s emit (2 source ticks).
		{0, 2}, {-1000, 2},
	}
	for _, c := range cases {
		h := NewStreamHandler(broadcaster, store, window, nil, c.tickMs, false, logger)
		if got := h.EmitEveryN(); got != c.want {
			t.Errorf("tickMs=%d: emitEveryN got %d, want %d", c.tickMs, got, c.want)
		}
	}
}

// --- HTTP / WS lifecycle tests against a real router ---

func TestStream_RequiresAuth(t *testing.T) {
	env := newStreamTestEnv(t, 1000) // 1s emit for fast tests

	_, resp, err := websocket.DefaultDialer.Dial(env.wsURL(t), nil)
	if err == nil {
		t.Fatal("expected dial to fail without cookie")
	}
	if resp == nil {
		t.Fatalf("no HTTP response on rejected dial; err=%v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", resp.StatusCode)
	}
	if !errors.Is(err, websocket.ErrBadHandshake) {
		t.Errorf("dial err=%v, want websocket.ErrBadHandshake", err)
	}
}

func TestStream_LockedSession_403(t *testing.T) {
	env := newStreamTestEnv(t, 1000)

	// Backdate session past idle threshold → HardAuth returns 403.
	sessionStore := auth.NewSessionStore(env.store.DB())
	sess, err := sessionStore.Get(context.Background(), env.sessionID)
	if err != nil {
		t.Fatalf("Get session: %v", err)
	}
	sess.LastActivity = time.Now().UTC().Add(-(auth.SessionIdleTimeout + time.Minute))
	if err := sessionStore.PutForTest(context.Background(), sess); err != nil {
		t.Fatalf("backdate session: %v", err)
	}

	_, resp, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err == nil {
		t.Fatal("expected dial to fail on locked session")
	}
	if resp == nil {
		t.Fatalf("no HTTP response; err=%v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status=%d, want 403", resp.StatusCode)
	}
}

func TestStream_InitialFrameOnConnect(t *testing.T) {
	env := newStreamTestEnv(t, 1000)

	// Seed one route via the store so BuildSnapshot has something
	// to project (an empty store would yield an empty-routes
	// payload — also valid, but a 1-route fixture makes the
	// wire-shape assertion meaningful).
	_, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:       "api.example",
		LBPolicy:   "round_robin",
		TLSEnabled: true,
		WAFMode:    "block",
		Upstreams:  []storage.Upstream{{URL: "http://10.0.0.1:80", Weight: 1}},
	})
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	conn, resp, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer conn.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("handshake status=%d, want 101", resp.StatusCode)
	}

	// Spec §5.2 of docs/api/topology.md: server sends current
	// snapshot IMMEDIATELY on connect. Verify by reading the
	// first frame with a 2 s deadline — if the server waited for
	// the first source tick we'd still get it within deadline,
	// but the assertion is "frame arrives without us publishing".
	frame := readSnapshotFrame(t, conn)
	if frame.GeneratedAt.IsZero() {
		t.Errorf("initial frame GeneratedAt: zero, want non-zero")
	}
	if len(frame.Routes) != 1 {
		t.Errorf("initial frame Routes: got %d, want 1", len(frame.Routes))
	}
	if len(frame.Routes) > 0 && frame.Routes[0].Host != "api.example" {
		t.Errorf("initial frame host: got %q, want api.example", frame.Routes[0].Host)
	}
}

func TestStream_AggregatesNTicks(t *testing.T) {
	// tickMs=3000 = emit every 3 source ticks. After the initial
	// connect-emit, publish 6 source ticks ONE AT A TIME (waiting
	// between each because SubscriberChanCap=1 — bursts drop).
	// Expect exactly 2 emitted frames (at tick 3 and tick 6).
	//
	// We count frames in a background reader goroutine and assert
	// the count after a quiet window. We can't use intermediate
	// short-deadline reads to assert "no frame here" because a
	// gorilla i/o-timeout on a WS conn poisons it — subsequent
	// reads also fail. The frame-counter approach avoids that.
	env := newStreamTestEnv(t, 3000)

	_, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "api.example",
		LBPolicy:  "round_robin",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.1:80", Weight: 1}},
	})
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	conn, _, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = readSnapshotFrame(t, conn) // consume initial connect-emit

	// Wait for subscription.
	deadline := time.Now().Add(time.Second)
	for env.broadcaster.SubscriberCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// Background reader counts post-initial frames until the
	// connection closes (which we do via t.Cleanup via defer).
	frameCount := make(chan int, 1)
	go func() {
		count := 0
		for {
			// No deadline — read until the connection closes.
			_, _, err := conn.ReadMessage()
			if err != nil {
				frameCount <- count
				return
			}
			count++
		}
	}()

	// Publish 6 source ticks; wait between each so each one
	// lands in the subscriber channel and gets drained.
	for i := 0; i < 6; i++ {
		env.broadcaster.Publish(metrics.Snapshot{
			T:      time.Now().UTC(),
			Routes: []metrics.RouteSnapshot{{ID: "rid", Reqs: 1, ReqPerSec: 1}},
		})
		time.Sleep(50 * time.Millisecond)
	}

	// Give the handler time to finish the last emit, then close
	// the connection to terminate the reader.
	time.Sleep(200 * time.Millisecond)
	_ = conn.Close()

	select {
	case got := <-frameCount:
		// emitEveryN=3, 6 publishes → 2 emits (at tick 3 and 6).
		if got != 2 {
			t.Errorf("frame count: got %d, want 2 (emitEveryN=3, 6 ticks → 2 emits)", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader goroutine did not return within 2s")
	}
}

func TestStream_PushesIntoWindow(t *testing.T) {
	// tickMs=1000 = emit every 1 source tick. Publish 3 ticks
	// with known reqs; the window's Aggregate for the route id
	// must reflect the mean.
	env := newStreamTestEnv(t, 1000)

	_, err := env.store.CreateRoute(context.Background(), storage.Route{
		ID:        "rid-pump", // ID is overwritten by storage; not useful here
		Host:      "api.example",
		LBPolicy:  "round_robin",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.1:80", Weight: 1}},
	})
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	conn, _, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = readSnapshotFrame(t, conn) // discard initial

	// Wait for subscription.
	deadline := time.Now().Add(time.Second)
	for env.broadcaster.SubscriberCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// Publish 3 ticks with reqs 10 / 20 / 30 for route id "r1"
	// — note this id is what the stream handler pushes into
	// the window, NOT the storage route's id. The two are
	// independent in the test (we're testing the window-push
	// behaviour, not the join).
	//
	// One-publish-one-read, because SubscriberChanCap=1: bursts
	// would drop ticks.
	for _, n := range []uint64{10, 20, 30} {
		env.broadcaster.Publish(metrics.Snapshot{
			T:      time.Now().UTC(),
			Routes: []metrics.RouteSnapshot{{ID: "r1", Reqs: n}},
		})
		// Read the corresponding frame so we know the handler
		// has processed the tick (the handler emits AFTER
		// pushing to the window, so a successful read is a
		// happens-after fence on the window mutation).
		_ = readSnapshotFrame(t, conn)
	}

	// Now interrogate the window directly — the handler pushed
	// reqs 10/20/30 over 3 ticks for "r1" → mean = 20.
	agg := env.window.Aggregate("r1")
	if agg.ReqPerSec != 20 {
		t.Errorf("window aggregate after 3 pushes: got %v, want 20", agg.ReqPerSec)
	}
}

func TestStream_ContextCancel_ClosesCleanly(t *testing.T) {
	env := newStreamTestEnv(t, 1000)
	conn, _, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Close the client side abruptly — the server's read pump
	// detects this and the handler returns cleanly. We don't
	// observe the close frame here (the client connection is
	// already gone); we assert the server doesn't hang by
	// confirming the broadcaster's subscriber count drops to 0.
	_ = conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for env.broadcaster.SubscriberCount() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if env.broadcaster.SubscriberCount() != 0 {
		t.Errorf("SubscriberCount after client disconnect: got %d, want 0", env.broadcaster.SubscriberCount())
	}
}

func TestNewStreamHandler_NilBroadcaster_Panics(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("nil broadcaster: want panic")
		}
	}()
	_ = NewStreamHandler(nil, &fakeRouteLister{}, topology.NewSlidingWindow(), nil, 1000, false, logger)
}

func TestNewStreamHandler_NilStore_Panics(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	broadcaster := metrics.NewBroadcaster(logger)
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("nil store: want panic")
		}
	}()
	_ = NewStreamHandler(broadcaster, nil, topology.NewSlidingWindow(), nil, 1000, false, logger)
}

func TestNewStreamHandler_NilWindow_Panics(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	broadcaster := metrics.NewBroadcaster(logger)
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("nil window: want panic")
		}
	}()
	_ = NewStreamHandler(broadcaster, &fakeRouteLister{}, nil, nil, 1000, false, logger)
}

func TestNewStreamHandler_NilLogger_Panics(t *testing.T) {
	broadcaster := metrics.NewBroadcaster(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("nil logger: want panic")
		}
	}()
	_ = NewStreamHandler(broadcaster, &fakeRouteLister{}, topology.NewSlidingWindow(), nil, 1000, false, nil)
}
