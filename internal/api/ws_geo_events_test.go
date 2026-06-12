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

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/geo"
	"github.com/barto95100/arenet/internal/storage"
)

// wsGeoEventsTestEnv mirrors wsTestEnv but wires a real
// *geo.Bus into the router instead of the metrics
// broadcaster. Each test gets a freshly-bootstrapped session
// so HardAuthMiddleware actually exercises (mirror of the
// ws_topology_test pattern).
type wsGeoEventsTestEnv struct {
	srv       *httptest.Server
	bus       *geo.Bus
	sessionID string
	userID    string
	sessions  *auth.SessionStore
}

func newWSGeoEventsTestEnv(t *testing.T) *wsGeoEventsTestEnv {
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

	bus := geo.NewBus(32)
	h.SetGeoBus(bus)
	wsHandler := NewWSGeoEventsHandler(bus, true /* dev allows empty Origin */, logger)

	router := NewRouter(h, true, ipExtractor, nil, nil, nil, wsHandler)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	ctx := context.Background()
	user, err := userStore.Create(ctx, "tester-geo", "Tester Geo", "", "test-password-15c-xx")
	if err != nil {
		t.Fatalf("bootstrap user: %v", err)
	}
	sess, err := sessionStore.Create(ctx, user.ID, false, "127.0.0.1", "ws-geo-test/1")
	if err != nil {
		t.Fatalf("bootstrap session: %v", err)
	}

	return &wsGeoEventsTestEnv{
		srv:       srv,
		bus:       bus,
		sessionID: sess.ID,
		userID:    user.ID,
		sessions:  sessionStore,
	}
}

func (e *wsGeoEventsTestEnv) wsURL(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(e.srv.URL)
	if err != nil {
		t.Fatalf("parse srv URL: %v", err)
	}
	u.Scheme = "ws"
	u.Path = "/api/v1/ws/geo-events"
	return u.String()
}

func (e *wsGeoEventsTestEnv) authHeader() http.Header {
	return http.Header{
		"Cookie": []string{"arenet_session=" + e.sessionID},
	}
}

// --- Tests -----------------------------------------------------------------

func TestWS_GeoEvents_RequiresAuth(t *testing.T) {
	env := newWSGeoEventsTestEnv(t)

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
	if !errors.Is(err, websocket.ErrBadHandshake) {
		t.Errorf("dial err=%v, want websocket.ErrBadHandshake", err)
	}
}

func TestWS_GeoEvents_Upgrades_AndReceivesEvent(t *testing.T) {
	env := newWSGeoEventsTestEnv(t)

	conn, resp, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer conn.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("handshake status=%d, want 101", resp.StatusCode)
	}

	// Give the server a moment to subscribe — the WS handler
	// calls bus.Subscribe inside ServeHTTP, which happens after
	// the upgrade. Without the barrier the Publish below races
	// the Subscribe and the event is dropped (bus delivers
	// only to subscribers present at publish time).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if env.bus.Stats().Subscribers == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := env.bus.Stats().Subscribers; got != 1 {
		t.Fatalf("Subscribers=%d, want 1 after dial", got)
	}

	want := geo.GeoEvent{
		Timestamp:     time.Now().UTC(),
		Category:      geo.CategoryWAF,
		SourceIP:      "1.2.3.4",
		SourceCountry: "FR",
		SourceCity:    "Paris",
		StatusCode:    403,
		Details:       "942100",
	}
	env.bus.Publish(want)

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

	var got geo.GeoEvent
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal frame: %v\npayload=%s", err, payload)
	}
	if got.SourceIP != want.SourceIP || got.Category != want.Category {
		t.Errorf("event mismatch: got %+v want %+v", got, want)
	}
	if got.SourceCountry != "FR" || got.SourceCity != "Paris" {
		t.Errorf("geo fields mismatch: %+v", got)
	}
}

func TestWS_GeoEvents_MultipleClients_AllReceive(t *testing.T) {
	env := newWSGeoEventsTestEnv(t)

	conn1, _, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err != nil {
		t.Fatalf("dial1: %v", err)
	}
	defer conn1.Close()
	conn2, _, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer conn2.Close()

	// Wait for both subscriptions to register.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if env.bus.Stats().Subscribers == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := env.bus.Stats().Subscribers; got != 2 {
		t.Fatalf("Subscribers=%d, want 2", got)
	}

	want := geo.GeoEvent{
		Timestamp: time.Now().UTC(),
		Category:  geo.CategoryAuth,
		SourceIP:  "9.9.9.9",
		Details:   "login_failure admin",
	}
	env.bus.Publish(want)

	for i, conn := range []*websocket.Conn{conn1, conn2} {
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("client %d SetReadDeadline: %v", i, err)
		}
		_, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("client %d ReadMessage: %v", i, err)
		}
		var got geo.GeoEvent
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("client %d unmarshal: %v", i, err)
		}
		if got.SourceIP != want.SourceIP {
			t.Errorf("client %d event mismatch: %+v", i, got)
		}
	}
}

func TestWS_GeoEvents_ClientDisconnect_UnsubscribesCleanly(t *testing.T) {
	env := newWSGeoEventsTestEnv(t)

	conn, _, err := websocket.DefaultDialer.Dial(env.wsURL(t), env.authHeader())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Wait for subscription.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if env.bus.Stats().Subscribers == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := env.bus.Stats().Subscribers; got != 1 {
		t.Fatalf("Subscribers=%d, want 1 after dial", got)
	}

	// Close from client side — read pump must observe EOF and
	// trigger the unsubscribe defer in ServeHTTP.
	_ = conn.Close()

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if env.bus.Stats().Subscribers == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("Subscribers=%d after client close, want 0 (unsubscribe leaked)", env.bus.Stats().Subscribers)
}

func TestWS_GeoEvents_NilBus_503(t *testing.T) {
	// Spin up a separate handler with a nil bus — the upgrade
	// must be rejected with 503. Doesn't need a full session
	// fixture because the rejection happens before any auth
	// dependence inside this handler (the route's middleware
	// chain still gates, but we test the handler directly).
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	wsHandler := NewWSGeoEventsHandler(nil, true, logger)

	srv := httptest.NewServer(wsHandler)
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	u.Scheme = "ws"

	_, resp, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err == nil {
		t.Fatal("expected dial to fail when bus is nil")
	}
	if resp == nil {
		t.Fatalf("no resp; err=%v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503 (nil bus)", resp.StatusCode)
	}
}
