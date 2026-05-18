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
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/barto95100/arenet/internal/metrics"
)

// closeWriteDeadline bounds the outbound CloseMessage frame we send
// on shutdown. We don't want to hang on a misbehaving client during
// server stop.
const closeWriteDeadline = 5 * time.Second

// WSTopologyHandler serves the live-metrics WebSocket endpoint
// /api/v1/ws/topology (spec §5). Hard-auth is applied by the router's
// middleware chain BEFORE this handler runs; here we assume an
// authenticated session and focus on the protocol.
//
// Each accepted connection subscribes to the metrics broadcaster and
// runs two coordinated goroutines:
//   - a read pump (so gorilla can handle control frames / pongs and
//     detect dropped clients);
//   - a write pump (drains the subscriber channel, encodes to JSON,
//     writes with metrics.WSWriteDeadline).
type WSTopologyHandler struct {
	broadcaster *metrics.Broadcaster
	upgrader    websocket.Upgrader
	logger      *slog.Logger
}

// NewWSTopologyHandler constructs the handler. The dev flag mirrors
// the Step D devCORS pattern: when true, the WebSocket Upgrader
// allows http://localhost:5173 (Vite dev server) as a cross-origin
// caller. When false, the default same-origin policy applies — the
// frontend embedded in the binary is served from the same origin as
// the admin API.
func NewWSTopologyHandler(broadcaster *metrics.Broadcaster, dev bool, logger *slog.Logger) *WSTopologyHandler {
	if broadcaster == nil {
		panic("api.NewWSTopologyHandler: broadcaster is nil")
	}
	if logger == nil {
		panic("api.NewWSTopologyHandler: logger is nil")
	}
	up := websocket.Upgrader{
		// Each tick is ~600 bytes for 10 routes (spec §9.1); 4 KB
		// buffers leave headroom without wasting per-conn memory.
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
	}
	if dev {
		// Cross-origin allowance for the Vite dev server. An empty
		// Origin (e.g. tools that don't send one, including the
		// httptest dial used by our test suite) is also accepted in
		// dev to keep the test surface simple.
		up.CheckOrigin = func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || origin == "http://localhost:5173"
		}
	}
	return &WSTopologyHandler{
		broadcaster: broadcaster,
		upgrader:    up,
		logger:      logger,
	}
}

// ServeHTTP upgrades the request to a WebSocket and runs the
// subscription/write loop until the connection drops or the request
// context is cancelled. Hard-auth is enforced by middleware upstream
// — by the time ServeHTTP runs, the session has already been
// resolved and touched (spec §7.1).
func (h *WSTopologyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// gorilla writes the HTTP error response itself; we log at
		// Debug because upgrade failures are typically client-side
		// (wrong Origin, non-WS GET) and would spam logs in prod.
		h.logger.Debug("ws topology: upgrade failed", slog.String("err", err.Error()))
		return
	}

	sub := h.broadcaster.Subscribe()
	defer h.broadcaster.Unsubscribe(sub)
	defer conn.Close()

	// done signals shutdown from any of three sources: ctx cancel,
	// read pump error (client disconnect / read timeout), or write
	// error in the pump. Closed at most once via sync.Once.
	done := make(chan struct{})
	var doneOnce sync.Once
	closeDone := func() { doneOnce.Do(func() { close(done) }) }

	// Read pump: never acts on the payload (unidirectional protocol
	// per spec §5.3) but MUST be running so gorilla can process
	// ping/pong frames and detect a dead peer. Any read error
	// (EOF, timeout, close frame) signals shutdown.
	go func() {
		defer closeDone()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			// Server shutdown or request cancellation. Close cleanly
			// with code 1001 (Going Away) so the client distinguishes
			// "server is going away" from a generic close. Spec §5.4.
			_ = conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, ""),
				time.Now().Add(closeWriteDeadline),
			)
			return

		case <-done:
			// Read pump exited (client disconnected). The TCP-side
			// close is already in flight; we just stop publishing.
			return

		case snap, ok := <-sub.Ch:
			if !ok {
				// Broadcaster closed our channel via Unsubscribe.
				// Shouldn't happen mid-lifetime (the defer above is
				// the only Unsubscribe path), but be defensive.
				return
			}
			deadline := time.Now().Add(metrics.WSWriteDeadline)
			if err := conn.SetWriteDeadline(deadline); err != nil {
				h.logger.Debug("ws topology: set write deadline failed",
					slog.String("err", err.Error()))
				closeDone()
				return
			}
			if err := writeJSONFrame(conn, snap); err != nil {
				// Write failed: client is too slow or disconnected.
				// Stop publishing; the defer closes the conn and
				// unsubscribes. The peer will observe an abnormal
				// closure (code 1006) — acceptable per spec §5.6
				// (slow clients drop, server does not retry).
				h.logger.Debug("ws topology: write failed",
					slog.String("err", err.Error()))
				closeDone()
				return
			}
		}
	}
}

// writeJSONFrame serializes snap and writes it as a single text
// frame on conn. Extracted from ServeHTTP for testability: a future
// test can stub or wrap it to inject write errors deterministically.
func writeJSONFrame(conn *websocket.Conn, snap metrics.Snapshot) error {
	w, err := conn.NextWriter(websocket.TextMessage)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(w).Encode(snap); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

// Compile-time check: WSTopologyHandler satisfies http.Handler.
var _ http.Handler = (*WSTopologyHandler)(nil)
