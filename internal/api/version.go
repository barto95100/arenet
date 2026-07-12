// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/internal/updatecheck"
)

// minUpdateInterval is the floor for a custom update-check cadence (D3).
// Values below this are rejected so an operator can't hammer GitHub.
const minUpdateInterval = time.Hour

// versionResponse is the wire shape of GET /api/v1/system/version. It
// carries no secrets — just the version state + the opt-in flag.
type versionResponse struct {
	Current         string    `json:"current"`
	Latest          string    `json:"latest"`
	UpdateAvailable bool      `json:"updateAvailable"`
	URL             string    `json:"url"`
	LastChecked     time.Time `json:"lastChecked"`
	LastError       string    `json:"lastError"`
	Enabled         bool      `json:"enabled"`
}

func (h *Handler) versionResponseFrom(st updatecheck.Status, enabled bool) versionResponse {
	return versionResponse{
		Current:         st.Current,
		Latest:          st.Latest,
		UpdateAvailable: st.UpdateAvailable,
		URL:             st.URL,
		LastChecked:     st.LastChecked,
		LastError:       st.LastError,
		Enabled:         enabled,
	}
}

// systemVersion serves GET /api/v1/system/version. nil-tolerant: with no
// checker wired it reports enabled=false / no update.
func (h *Handler) systemVersion(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetUpdateCheckConfig(r.Context())
	if err != nil {
		h.logger.Error("read update check config", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to read update config")
		return
	}
	if h.updateChecker == nil {
		writeJSON(w, http.StatusOK, versionResponse{Enabled: false})
		return
	}
	writeJSON(w, http.StatusOK, h.versionResponseFrom(h.updateChecker.Status(), cfg.Enabled))
}

// systemVersionCheck serves POST /api/v1/system/version/check — a manual
// check that bypasses the cadence. 409 when the checker isn't wired.
func (h *Handler) systemVersionCheck(w http.ResponseWriter, r *http.Request) {
	if h.updateChecker == nil {
		writeError(w, http.StatusConflict, "update checker not available")
		return
	}
	cfg, err := h.store.GetUpdateCheckConfig(r.Context())
	if err != nil {
		h.logger.Error("read update check config", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to read update config")
		return
	}
	st := h.updateChecker.Check(r.Context())
	writeJSON(w, http.StatusOK, h.versionResponseFrom(st, cfg.Enabled))
}

type versionConfigRequest struct {
	Enabled          bool   `json:"enabled"`
	IntervalOverride string `json:"intervalOverride"`
}

// systemVersionConfig serves PUT /api/v1/system/version/config — toggles
// the opt-in + optional interval override. A non-empty interval must
// parse and be ≥ 1h (D3). After persisting, the boot hook (if wired)
// starts/stops the poll loop to match.
func (h *Handler) systemVersionConfig(w http.ResponseWriter, r *http.Request) {
	var req versionConfigRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	if req.IntervalOverride != "" {
		d, err := time.ParseDuration(req.IntervalOverride)
		if err != nil {
			writeError(w, http.StatusBadRequest, "intervalOverride is not a valid duration (e.g. \"24h\")")
			return
		}
		if d < minUpdateInterval {
			writeError(w, http.StatusBadRequest, "intervalOverride must be at least 1h")
			return
		}
	}
	cfg := storage.UpdateCheckConfig{Enabled: req.Enabled, IntervalOverride: req.IntervalOverride}
	if err := h.store.PutUpdateCheckConfig(r.Context(), cfg); err != nil {
		h.logger.Error("persist update check config", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to persist update config")
		return
	}
	if h.onUpdateConfigChange != nil {
		h.onUpdateConfigChange(cfg)
	}

	var st updatecheck.Status
	if h.updateChecker != nil {
		st = h.updateChecker.Status()
	}
	writeJSON(w, http.StatusOK, h.versionResponseFrom(st, cfg.Enabled))
}
