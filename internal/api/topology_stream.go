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
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/barto95100/arenet/internal/api/topology"
	"github.com/barto95100/arenet/internal/metrics"
)

// StreamHandler serves /api/v1/topology/stream — the WebSocket
// counterpart to the C2 /snapshot endpoint. Subscribes to the
// shared metrics.Broadcaster, pushes each source tick into a
// SlidingWindow, and emits a topology.SnapshotResponse frame every
// N source ticks (N derived from ARENET_TOPOLOGY_TICK_MS, default
// 2 = 2 s emit cadence).
//
// Architecture mirrors the existing WSTopologyHandler (Step E):
//   - Broadcaster fan-out + buffered subscriber channels
//   - Slow-client drop (write deadline; on failure, the connection
//     is closed and the subscriber is unsubscribed)
//   - Read pump exists to process gorilla's control frames (ping/
//     pong / close) and detect dead peers, NEVER acts on payload
//   - Hard-auth middleware upstream of the upgrade — 401 / 403 is
//     a regular HTTP response BEFORE the upgrade, no in-WS close
//     codes (the spec mentioned 4401/4403, but the existing pattern
//     is the source of truth)
//
// The first emit happens IMMEDIATELY on connect (not after the
// first N-tick wait) — matches the spec's "server sends current
// snapshot immediately on connection" contract. Subsequent emits
// follow the N-tick aggregation cadence.
type StreamHandler struct {
	broadcaster *metrics.Broadcaster
	store       SnapshotRouteLister
	window      *topology.SlidingWindow
	status      topology.StatusLookup
	emitEveryN  int
	upgrader    websocket.Upgrader
	logger      *slog.Logger

	now func() time.Time
}

// NewStreamHandler constructs the stream handler. tickMs is the
// operator-configured emit cadence in milliseconds (typically
// ARENET_TOPOLOGY_TICK_MS); the handler snaps it UP to the
// nearest multiple of metrics.TickInterval to derive the
// per-source-tick aggregation count.
//
// Snapping UP ensures the operator's intent (slower emit) is
// respected even when the configured value isn't a clean multiple
// — a 2500 ms value snaps to 3 source ticks (3 s) rather than
// 2 (which would underrun the configured cadence and waste
// bandwidth).
//
// devMode mirrors the existing WSTopologyHandler — when true,
// http://localhost:5173 is allowed as a cross-origin caller
// (Vite dev server). Production same-origin enforcement is the
// default.
func NewStreamHandler(
	broadcaster *metrics.Broadcaster,
	store SnapshotRouteLister,
	window *topology.SlidingWindow,
	status topology.StatusLookup,
	tickMs int,
	devMode bool,
	logger *slog.Logger,
) *StreamHandler {
	if broadcaster == nil {
		panic("api.NewStreamHandler: broadcaster is nil")
	}
	if store == nil {
		panic("api.NewStreamHandler: store is nil")
	}
	if window == nil {
		panic("api.NewStreamHandler: window is nil")
	}
	if logger == nil {
		panic("api.NewStreamHandler: logger is nil")
	}

	// Snap tickMs UP to the next multiple of the source tick
	// interval. A non-positive value falls back to the spec
	// default (2 s emit = 2 source ticks @ 1 Hz). The config
	// layer rejects non-positive env values already; this is
	// defence-in-depth.
	srcMs := int(metrics.TickInterval / time.Millisecond)
	if srcMs <= 0 {
		srcMs = 1000
	}
	if tickMs <= 0 {
		tickMs = 2000
	}
	emitEveryN := (tickMs + srcMs - 1) / srcMs // ceil division
	if emitEveryN < 1 {
		emitEveryN = 1
	}

	up := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
	}
	if devMode {
		up.CheckOrigin = func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || origin == "http://localhost:5173"
		}
	}
	return &StreamHandler{
		broadcaster: broadcaster,
		store:       store,
		window:      window,
		status:      status,
		emitEveryN:  emitEveryN,
		upgrader:    up,
		logger:      logger,
		now:         time.Now,
	}
}

// EmitEveryN returns the per-source-tick aggregation count. Test
// helper — verifies the snap-UP behaviour for non-multiple tickMs
// without exposing the field directly.
func (h *StreamHandler) EmitEveryN() int { return h.emitEveryN }

// ServeHTTP upgrades the request to a WebSocket and runs the
// emit loop. Hard-auth is applied upstream by the router middleware
// chain; by the time ServeHTTP runs, the session is resolved.
func (h *StreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade failures are typically client-side (wrong
		// Origin, non-WS GET); gorilla writes the HTTP error
		// response. Debug-log only.
		h.logger.Debug("ws topology stream: upgrade failed",
			slog.String("err", err.Error()))
		return
	}

	sub := h.broadcaster.Subscribe()
	defer h.broadcaster.Unsubscribe(sub)
	defer conn.Close()

	done := make(chan struct{})
	var doneOnce sync.Once
	closeDone := func() { doneOnce.Do(func() { close(done) }) }

	// Read pump: gorilla needs an active reader for control frames
	// (ping/pong/close). Payload is ignored (unidirectional protocol).
	go func() {
		defer closeDone()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	// Spec: "server sends current snapshot immediately on
	// connection, then continues normal ticks". The window may
	// be empty on first connect (a fresh server with no traffic
	// yet) — that's fine, BuildSnapshot returns an idle response
	// and the client renders it.
	if err := h.emitOnce(conn); err != nil {
		h.logger.Debug("ws topology stream: initial emit failed",
			slog.String("err", err.Error()))
		return
	}

	// Per-connection counter: every source tick we push into the
	// SHARED SlidingWindow exactly once. This is wasteful when
	// multiple subscribers exist — N subscribers push N times
	// per tick instead of once. A future optimisation moves the
	// push to the Ticker / Broadcaster layer so the window is
	// updated centrally. For Phase 2 / Stage A and the homelab
	// concurrency target (1-3 admin browsers), the duplicated
	// push is cheap and the code stays local to this handler.
	tickCount := 0
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			_ = conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, ""),
				time.Now().Add(closeWriteDeadline),
			)
			return

		case <-done:
			return

		case snap, ok := <-sub.Ch:
			if !ok {
				return
			}
			// Push every source tick into the window — even
			// non-emit ticks contribute to the 60-slot history.
			h.pushSnap(snap)

			tickCount++
			if tickCount < h.emitEveryN {
				continue
			}
			tickCount = 0

			if err := h.emitOnce(conn); err != nil {
				h.logger.Debug("ws topology stream: emit failed",
					slog.String("err", err.Error()))
				closeDone()
				return
			}
		}
	}
}

// pushSnap forwards one source-tick metrics.Snapshot into the
// SlidingWindow. The Push contract is per-route reqs/errs/p95;
// metrics.RouteSnapshot carries reqs + errs natively but not
// per-tick p95 (Step L drops it from the wire shape). Stage A
// limitation acknowledged in the C1 ring docstring — we push 0
// for p95 here, which means the response's P99LatencyMs surfaces
// 0 for routes whose only metric path is the broadcaster.
//
// A follow-up could wire a metrics.TickConsumer alongside the
// broadcaster to feed real p95s into the ring — see #R-TOPO-
// upstream-metrics in the backlog for the broader Stage B
// instrumentation discussion.
func (h *StreamHandler) pushSnap(snap metrics.Snapshot) {
	for _, r := range snap.Routes {
		h.window.Push(r.ID, r.Reqs, r.Errs, 0)
	}
}

// emitOnce builds the snapshot from the current window + storage
// list + status cache and writes one JSON frame. Returns the
// underlying write error if any — the caller closes the connection.
func (h *StreamHandler) emitOnce(conn *websocket.Conn) error {
	// context.Background is used because:
	//   - storage.Store.ListRoutes is local-disk BoltDB; there's
	//     no I/O to cancel even if the request ctx fired (BoltDB
	//     ignores ctx).
	//   - using r.Context() here would cancel ListRoutes the
	//     instant the read pump exits (peer disconnect) — but the
	//     emit goroutine MAY still be mid-flight, and we'd then
	//     write an empty frame to a peer that's already gone.
	//     Distinguishing "real disconnect" from "slow disk" is
	//     not worth the complexity at homelab cardinality.
	routes, err := h.store.ListRoutes(context.Background())
	if err != nil {
		// On a storage error mid-stream, emit an empty-routes
		// frame rather than tearing down the connection. The
		// frontend renders an idle canvas, the operator sees
		// the issue in the server log, and the next tick will
		// retry. A torn-down WS would force a client reconnect
		// for a (typically transient) BoltDB lock contention.
		h.logger.Warn("ws topology stream: list routes failed (emitting empty frame)",
			slog.String("err", err.Error()))
		routes = nil
	}

	resp := topology.BuildSnapshot(routes, h.window, h.status, h.now())

	deadline := time.Now().Add(metrics.WSWriteDeadline)
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	w, err := conn.NextWriter(websocket.TextMessage)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

// Compile-time check: StreamHandler satisfies http.Handler.
var _ http.Handler = (*StreamHandler)(nil)
