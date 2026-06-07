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

	"github.com/barto95100/arenet/internal/geo"
)

// wsGeoEventsSubscriberBuffer is the per-connection channel
// buffer the bus subscriber uses. 64 matches the ws_topology
// subscriber buffer (commit 30418ea pre-context); slow
// clients silently drop events past this point via the
// bus's non-blocking fan-out (counted in
// BusStats.DroppedToSlowSub for ops visibility).
const wsGeoEventsSubscriberBuffer = 64

// wsGeoEventsWriteDeadline bounds a single WS frame write.
// Same value as ws_topology — generous enough for a slow
// LAN client without leaving a wedged connection forever.
const wsGeoEventsWriteDeadline = 5 * time.Second

// GeoEventSubscriber is the WS handler's read surface on the
// bus. *geo.Bus satisfies this via Subscribe; declared as
// an interface so the WS handler tests can use a stub bus
// without spinning up the real implementation.
type GeoEventSubscriber interface {
	Subscribe(bufferSize int) (<-chan geo.GeoEvent, func())
}

// WSGeoEventsHandler serves the live geo-event WebSocket
// endpoint /api/v1/ws/geo-events (spec §5.5). Hard-auth is
// applied by the router middleware BEFORE this handler runs;
// here we assume an authenticated session and focus on the
// protocol.
//
// Each accepted connection subscribes to the bus and runs
// two coordinated goroutines per the ws_topology.go pattern:
//   - a read pump (so gorilla can handle control frames and
//     detect dropped clients);
//   - a write pump (drains the subscriber channel, encodes
//     each GeoEvent to JSON, writes with the deadline).
//
// Frame shape per spec §5.5: one JSON GeoEvent per WS
// message. No envelope wrapper (matches ws_topology's
// "snap-per-frame" pattern).
type WSGeoEventsHandler struct {
	bus      GeoEventSubscriber
	upgrader websocket.Upgrader
	logger   *slog.Logger
}

// NewWSGeoEventsHandler constructs the handler. The dev flag
// mirrors the Step D devCORS pattern: when true, the WebSocket
// upgrader allows http://localhost:5173 (Vite dev server) and
// empty-Origin requests (test harness) as cross-origin
// callers. When false, same-origin policy applies — the
// frontend embedded in the binary is served from the same
// origin as the admin API.
//
// A nil bus is a valid degraded-mode receiver: ServeHTTP
// rejects the upgrade with 503 so a slow boot doesn't expose
// a non-functional WS to clients.
func NewWSGeoEventsHandler(bus GeoEventSubscriber, dev bool, logger *slog.Logger) *WSGeoEventsHandler {
	if logger == nil {
		logger = slog.Default()
	}
	up := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
	}
	if dev {
		up.CheckOrigin = func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || origin == "http://localhost:5173"
		}
	}
	return &WSGeoEventsHandler{
		bus:      bus,
		upgrader: up,
		logger:   logger,
	}
}

// ServeHTTP upgrades the request to a WebSocket and runs the
// subscription/write loop until the connection drops or the
// request context is cancelled. Hard-auth is enforced
// upstream — by the time ServeHTTP runs, the session has
// already been resolved (spec §5.5 + §7.1 carried from
// ws_topology).
func (h *WSGeoEventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.bus == nil {
		// Degraded mode — bus not wired. Reject the upgrade
		// with 503 so the client doesn't think it has a
		// working WS that simply produces no events.
		writeError(w, http.StatusServiceUnavailable, "geo event bus unavailable")
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// gorilla writes the HTTP error response itself; we
		// log at Debug because upgrade failures are typically
		// client-side (wrong Origin, non-WS GET) and would
		// spam logs in prod.
		h.logger.Debug("ws geo-events: upgrade failed", slog.String("err", err.Error()))
		return
	}

	sub, unsubscribe := h.bus.Subscribe(wsGeoEventsSubscriberBuffer)
	defer unsubscribe()
	defer conn.Close()

	// done signals shutdown from any of three sources: ctx
	// cancel, read pump error (client disconnect / read
	// timeout), or write error in the pump. Closed at most
	// once via sync.Once.
	done := make(chan struct{})
	var doneOnce sync.Once
	closeDone := func() { doneOnce.Do(func() { close(done) }) }

	// Read pump — same shape as ws_topology. Never acts on
	// the payload (unidirectional protocol per spec §5.5)
	// but MUST be running so gorilla can process ping/pong
	// frames and detect a dead peer.
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
			// Server shutdown / request cancellation. Close
			// cleanly with code 1001 (Going Away) so the
			// client distinguishes "server is going away"
			// from a generic close.
			_ = conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, ""),
				time.Now().Add(wsGeoEventsWriteDeadline),
			)
			return

		case <-done:
			// Read pump exited (client disconnected). The
			// TCP-side close is already in flight; we just
			// stop publishing.
			return

		case ev, ok := <-sub:
			if !ok {
				// Bus closed our channel via the unsubscribe
				// path. Shouldn't happen mid-lifetime (the
				// defer above is the only unsubscribe path),
				// but be defensive.
				return
			}
			deadline := time.Now().Add(wsGeoEventsWriteDeadline)
			if err := conn.SetWriteDeadline(deadline); err != nil {
				h.logger.Debug("ws geo-events: set write deadline failed",
					slog.String("err", err.Error()))
				closeDone()
				return
			}
			if err := writeJSONGeoEventFrame(conn, ev); err != nil {
				// Write failed: client is too slow or
				// disconnected. Stop publishing; the defer
				// closes the conn and unsubscribes. The peer
				// will observe an abnormal closure (code
				// 1006) — acceptable per the ws_topology
				// pattern (slow clients drop, server does
				// not retry).
				h.logger.Debug("ws geo-events: write failed",
					slog.String("err", err.Error()))
				closeDone()
				return
			}
		}
	}
}

// writeJSONGeoEventFrame serializes ev as a single text
// frame on conn. Extracted from ServeHTTP for testability:
// a future test can stub or wrap it to inject write errors
// deterministically. Same shape as writeJSONFrame in
// ws_topology.go.
func writeJSONGeoEventFrame(conn *websocket.Conn, ev geo.GeoEvent) error {
	w, err := conn.NextWriter(websocket.TextMessage)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(w).Encode(ev); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

// Compile-time check: WSGeoEventsHandler satisfies http.Handler.
var _ http.Handler = (*WSGeoEventsHandler)(nil)
