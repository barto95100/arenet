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
	"net/http"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/geo"
	"github.com/barto95100/arenet/internal/storage"
)

// ServerPositionStore is the persistence seam the handlers
// use to load + save the operator's geographic-position
// choice. *storage.Store satisfies this via
// GetServerPosition / PutServerPosition; declared as an
// interface so tests can stub without spinning up BoltDB.
type ServerPositionStore interface {
	GetServerPosition(ctx context.Context) (storage.ServerPositionRecord, error)
	PutServerPosition(ctx context.Context, rec storage.ServerPositionRecord) error
}

// ServerPositionRedetector is the seam the POST redetect
// handler uses to re-run the V.1 ipify-then-GeoIP path.
// Declared as an interface so tests can substitute a stub
// detector without hitting the network. Production wires
// a thin closure in cmd/arenet/main.go around
// geo.DetectFromPublicIP.
type ServerPositionRedetector interface {
	Redetect() (*geo.ServerPosition, error)
}

// serverPositionResponse is the wire shape spec §5.1 locks
// for the three position endpoints. Field-for-field mirror
// of the spec — camelCase JSON tags matching the rest of
// the V API surface.
//
// Lat/Lon are 0.0 in the degraded shape (per spec §5.1
// "frontend renders a banner + falls back to a
// world-centered Mercator"). Country / City / SourceIP
// stay empty strings; DetectedAt stays nil-equivalent (the
// JSON encoder serializes a zero time.Time as "0001-...");
// the spec explicitly accepts that.
type serverPositionResponse struct {
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
	City       string  `json:"city"`
	Country    string  `json:"country"`
	Mode       string  `json:"mode"`
	SourceIP   string  `json:"sourceIp,omitempty"`
	DetectedAt string  `json:"detectedAt,omitempty"`
	Degraded   bool    `json:"degraded,omitempty"`
}

// putServerPositionRequest is the wire shape PUT accepts.
// `city` and `country` are operator-supplied display
// strings — empty allowed per spec §5.2. Lat/Lon validation
// runs at the handler.
type putServerPositionRequest struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	City    string  `json:"city"`
	Country string  `json:"country"`
}

// recordToResponse translates the storage-flat record into
// the wire response. Used by all three endpoints.
func recordToResponse(rec storage.ServerPositionRecord) serverPositionResponse {
	out := serverPositionResponse{
		Lat:      rec.Lat,
		Lon:      rec.Lon,
		City:     rec.City,
		Country:  rec.Country,
		Mode:     rec.Mode,
		SourceIP: rec.SourceIP,
	}
	if !rec.DetectedAt.IsZero() {
		out.DetectedAt = rec.DetectedAt.UTC().Format(timestampFormat)
	}
	return out
}

// degradedPositionResponse is the canonical empty-shape
// response per spec §5.1 ("returns the empty-shape with
// HTTP 200"). Used when no persisted row exists, no boot
// auto-detect succeeded, and the redetect (if asked) failed.
func degradedPositionResponse() serverPositionResponse {
	return serverPositionResponse{
		Mode:     geo.ServerPositionModeAuto,
		Degraded: true,
	}
}

// getServerPosition handles GET /api/v1/observability/
// server-position per spec §5.1. Resolution order:
//
//  1. Try the persisted store first (the operator's choice
//     wins across reboots).
//  2. If ErrNotFound and the boot-time auto-detect captured
//     a non-nil position, return that.
//  3. Otherwise return the degraded empty-shape.
//
// AC #13 degraded path: never returns 5xx. A store error
// (BoltDB hiccup) collapses to the degraded shape with the
// error logged.
func (h *Handler) getServerPosition(w http.ResponseWriter, r *http.Request) {
	if h.serverPositionStore == nil {
		// Store not wired (test harness or boot-failed
		// storage). Fall through to the boot-detected
		// position if any; otherwise degrade.
		if h.bootDetectedPosition != nil {
			writeJSON(w, http.StatusOK, recordToResponse(serverPositionToRecord(h.bootDetectedPosition)))
			return
		}
		writeJSON(w, http.StatusOK, degradedPositionResponse())
		return
	}

	rec, err := h.serverPositionStore.GetServerPosition(r.Context())
	if err == nil {
		writeJSON(w, http.StatusOK, recordToResponse(rec))
		return
	}
	if !errors.Is(err, storage.ErrNotFound) {
		h.logger.Warn("get server_position: store error; falling back to boot auto-detect",
			"err", err)
	}

	if h.bootDetectedPosition != nil {
		writeJSON(w, http.StatusOK, recordToResponse(serverPositionToRecord(h.bootDetectedPosition)))
		return
	}
	writeJSON(w, http.StatusOK, degradedPositionResponse())
}

// putServerPosition handles PUT /api/v1/observability/
// server-position per spec §5.2. Admin-auth gated at the
// route mount. Sets mode="manual", persists, and emits the
// ActionServerPositionUpdated audit event.
//
// Validation per spec §5.2:
//   - lat ∈ [-90, 90] (400 if out of range)
//   - lon ∈ [-180, 180] (400 if out of range)
//   - city / country are operator-supplied display strings;
//     empty allowed.
func (h *Handler) putServerPosition(w http.ResponseWriter, r *http.Request) {
	if h.serverPositionStore == nil {
		writeError(w, http.StatusServiceUnavailable, "server position store unavailable")
		return
	}

	var req putServerPositionRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	if req.Lat < -90 || req.Lat > 90 {
		writeError(w, http.StatusBadRequest, "lat must be in [-90, 90]")
		return
	}
	if req.Lon < -180 || req.Lon > 180 {
		writeError(w, http.StatusBadRequest, "lon must be in [-180, 180]")
		return
	}

	previous, prevErr := h.serverPositionStore.GetServerPosition(r.Context())
	if prevErr != nil && !errors.Is(prevErr, storage.ErrNotFound) {
		h.logger.Error("put server_position: load previous", "err", prevErr)
		writeError(w, http.StatusInternalServerError, "failed to load previous server position")
		return
	}

	now := time.Now().UTC()
	rec := storage.ServerPositionRecord{
		Lat:        req.Lat,
		Lon:        req.Lon,
		City:       req.City,
		Country:    req.Country,
		Mode:       geo.ServerPositionModeManual,
		SourceIP:   "", // manual override carries no public-IP provenance
		DetectedAt: now,
	}
	if err := h.serverPositionStore.PutServerPosition(r.Context(), rec); err != nil {
		h.logger.Error("put server_position: save", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to save server position")
		return
	}

	auditEvt := audit.Event{
		Action:     audit.ActionServerPositionUpdated,
		TargetType: "server_position",
		TargetID:   "default",
		AfterJSON:  mustMarshalForAudit(rec),
	}
	if !errors.Is(prevErr, storage.ErrNotFound) {
		auditEvt.BeforeJSON = mustMarshalForAudit(previous)
	}
	h.appendAudit(r, auditEvt)

	writeJSON(w, http.StatusOK, recordToResponse(rec))
}

// redetectServerPosition handles POST /api/v1/observability/
// server-position:redetect per spec §5.3. Admin-auth gated.
// Forces a re-run of the V.1 ipify-then-GeoIP path; on
// success persists with mode="auto" and returns the new
// position. On failure returns the degraded shape (per spec
// §5.3 "returns degraded if redetect fails") rather than
// 5xx — operator-facing endpoints surface degradation
// gracefully so the /map page can render an honest banner.
//
// Audit: emits ActionServerPositionRedetected with
// before/after JSON on the path that actually overwrites the
// row. A redetect that lands in degraded mode (network
// failure, MMDB absent) does NOT emit an audit row — no
// state changed.
func (h *Handler) redetectServerPosition(w http.ResponseWriter, r *http.Request) {
	if h.serverPositionStore == nil || h.serverPositionRedetector == nil {
		writeError(w, http.StatusServiceUnavailable, "server position redetect unavailable")
		return
	}

	pos, err := h.serverPositionRedetector.Redetect()
	if err != nil || pos == nil {
		if err != nil {
			h.logger.Warn("server_position:redetect failed", "err", err)
		}
		// Spec §5.3: return the degraded shape rather than
		// 5xx. The endpoint completes its work — the work
		// just yielded no usable position. Operator sees the
		// banner; no audit row because no state changed.
		writeJSON(w, http.StatusOK, degradedPositionResponse())
		return
	}

	previous, prevErr := h.serverPositionStore.GetServerPosition(r.Context())
	if prevErr != nil && !errors.Is(prevErr, storage.ErrNotFound) {
		h.logger.Warn("server_position:redetect: load previous; persisting new anyway",
			"err", prevErr)
	}

	rec := serverPositionToRecord(pos)
	if err := h.serverPositionStore.PutServerPosition(r.Context(), rec); err != nil {
		h.logger.Error("server_position:redetect: save", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to persist redetected server position")
		return
	}

	auditEvt := audit.Event{
		Action:     audit.ActionServerPositionRedetected,
		TargetType: "server_position",
		TargetID:   "default",
		AfterJSON:  mustMarshalForAudit(rec),
	}
	if !errors.Is(prevErr, storage.ErrNotFound) {
		auditEvt.BeforeJSON = mustMarshalForAudit(previous)
	}
	h.appendAudit(r, auditEvt)

	writeJSON(w, http.StatusOK, recordToResponse(rec))
}

// serverPositionToRecord translates a geo.ServerPosition
// into the storage-flat shape. Used at boot to persist the
// auto-detect result and by the redetect handler to save
// the re-run result.
func serverPositionToRecord(pos *geo.ServerPosition) storage.ServerPositionRecord {
	if pos == nil {
		return storage.ServerPositionRecord{}
	}
	return storage.ServerPositionRecord{
		Lat:        pos.Lat,
		Lon:        pos.Lon,
		City:       pos.City,
		Country:    pos.Country,
		Mode:       pos.Mode,
		SourceIP:   pos.SourceIP,
		DetectedAt: pos.DetectedAt,
	}
}
