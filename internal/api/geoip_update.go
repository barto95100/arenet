// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/barto95100/arenet/internal/geoipupdate"
	"github.com/barto95100/arenet/internal/storage"
)

// defaultGeoIPIntervalHours is the scheduler's default cadence (weekly)
// used for display when no override is stored, mirroring
// resolveGeoIPInterval's 168h default in cmd/arenet/main.go. MaxMind
// publishes GeoLite2 updates roughly weekly.
const defaultGeoIPIntervalHours = 168

// geoIPUpdateConfigResponse is the wire shape of GET/PUT
// /api/v1/system/geoip/update-config.
type geoIPUpdateConfigResponse struct {
	Enabled       bool `json:"enabled"`
	IntervalHours int  `json:"intervalHours"`
}

// intervalHoursFrom resolves a stored IntervalOverride (a Go-duration
// string, possibly empty or invalid) to a whole-hour count for display.
// An empty or unparseable override falls back to the weekly default —
// this mirrors resolveGeoIPInterval's own fallback so the UI never
// shows a nonsensical value even if the stored override is stale.
func intervalHoursFrom(override string) int {
	if override == "" {
		return defaultGeoIPIntervalHours
	}
	d, err := time.ParseDuration(override)
	if err != nil || d <= 0 {
		return defaultGeoIPIntervalHours
	}
	return int(d.Hours())
}

// getGeoIPUpdateConfig serves GET /api/v1/system/geoip/update-config.
// Fresh installs report enabled=false with the weekly default interval.
func (h *Handler) getGeoIPUpdateConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetGeoIPUpdateConfig(r.Context())
	if err != nil {
		h.logger.Error("read geoip update config", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to read geoip update config")
		return
	}
	writeJSON(w, http.StatusOK, geoIPUpdateConfigResponse{
		Enabled:       cfg.Enabled,
		IntervalHours: intervalHoursFrom(cfg.IntervalOverride),
	})
}

// geoIPUpdateConfigRequest is the decode shape for PUT
// /api/v1/system/geoip/update-config. IntervalHours is optional; zero
// (or omitted) means "use the scheduler's default cadence."
type geoIPUpdateConfigRequest struct {
	Enabled       bool `json:"enabled"`
	IntervalHours int  `json:"intervalHours"`
}

// putGeoIPUpdateConfig serves PUT /api/v1/system/geoip/update-config —
// toggles the opt-in + optional interval override, in hours. After
// persisting, the boot hook (if wired) starts/stops the scheduler loop
// to match, mirroring systemVersionConfig.
func (h *Handler) putGeoIPUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var req geoIPUpdateConfigRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	if req.IntervalHours < 0 {
		writeError(w, http.StatusBadRequest, "intervalHours must not be negative")
		return
	}

	var override string
	if req.IntervalHours > 0 {
		override = (time.Duration(req.IntervalHours) * time.Hour).String()
	}
	cfg := storage.GeoIPUpdateConfig{Enabled: req.Enabled, IntervalOverride: override}
	if err := h.store.PutGeoIPUpdateConfig(r.Context(), cfg); err != nil {
		h.logger.Error("persist geoip update config", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to persist geoip update config")
		return
	}
	if h.onGeoIPConfigChange != nil {
		h.onGeoIPConfigChange(cfg)
	}

	writeJSON(w, http.StatusOK, geoIPUpdateConfigResponse{
		Enabled:       cfg.Enabled,
		IntervalHours: intervalHoursFrom(cfg.IntervalOverride),
	})
}

// geoIPUpdateResultResponse is the wire shape of POST
// /api/v1/system/geoip/update.
type geoIPUpdateResultResponse struct {
	Status       string     `json:"status"`
	Error        string     `json:"error,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
}

// postGeoIPUpdate serves POST /api/v1/system/geoip/update — a manual,
// operator-triggered update that shares the exact same UpdateOnce call
// the scheduler loop uses. 409 when no updater is wired (build failed
// at boot, or MaxMind isn't configured in a way that builds an
// updater); otherwise always 200, even when the result itself is an
// error — the failure is reported in the body, not the status code.
func (h *Handler) postGeoIPUpdate(w http.ResponseWriter, r *http.Request) {
	if h.geoIPUpdater == nil {
		writeError(w, http.StatusConflict, "geoip updater not available")
		return
	}
	res := h.geoIPUpdater.UpdateOnce(r.Context())
	writeJSON(w, http.StatusOK, geoIPUpdateResultResponseFrom(res))
}

// geoIPStatusResponse is the wire shape of GET /api/v1/system/geoip/status.
type geoIPStatusResponse struct {
	LastStatus  string     `json:"lastStatus"`
	LastError   string     `json:"lastError,omitempty"`
	LastUpdated *time.Time `json:"lastUpdated,omitempty"`
}

// getGeoIPStatus serves GET /api/v1/system/geoip/status. nil-tolerant:
// with no updater wired it reports a zero-value snapshot (empty
// lastStatus, no timestamps).
func (h *Handler) getGeoIPStatus(w http.ResponseWriter, r *http.Request) {
	if h.geoIPUpdater == nil {
		writeJSON(w, http.StatusOK, geoIPStatusResponse{})
		return
	}
	st := h.geoIPUpdater.Status()
	resp := geoIPStatusResponse{LastStatus: st.Status, LastError: st.Error}
	if !st.At.IsZero() {
		at := st.At
		resp.LastUpdated = &at
	}
	writeJSON(w, http.StatusOK, resp)
}

// geoIPUpdateResultResponseFrom converts an UpdateResult to its wire
// shape. LastModified is only surfaced when non-zero (StatusUpdated).
func geoIPUpdateResultResponseFrom(res geoipupdate.UpdateResult) geoIPUpdateResultResponse {
	resp := geoIPUpdateResultResponse{Status: res.Status, Error: res.Error}
	if !res.LastModified.IsZero() {
		lm := res.LastModified
		resp.LastModified = &lm
	}
	return resp
}
