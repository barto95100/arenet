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
	"errors"
	"net/http"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// Brick 2 Task 2 — MaxMind GeoIP account credentials admin
// settings.
//
// Endpoints (hard-auth admin, same subgroup as CrowdSec):
//   - GET    /api/v1/settings/maxmind — current row (secret redacted)
//   - PUT    /api/v1/settings/maxmind — persist
//   - DELETE /api/v1/settings/maxmind — wipe
//
// Secret redaction (mirror of crowdSecResponseFor / crowdSecConfigForAudit):
// LicenseKey is NEVER echoed by GET — the response carries no
// license key field at all, just a `configured: bool` flag. The
// UI uses `configured` to render a "•••• already saved"
// placeholder in the credential input and treats an empty
// submission on PUT as "keep the previously-stored value".
//
// The /test connection-probe endpoint is Task 3 — not added here.

// maxMindRequest is the wire shape accepted by PUT
// /api/v1/settings/maxmind. LicenseKey="" on PUT keeps the
// previously stored value (preserve-on-edit; same pattern as
// crowdSecRequest.APIKey).
type maxMindRequest struct {
	AccountID  int    `json:"accountId"`
	LicenseKey string `json:"licenseKey"`
	EditionID  string `json:"editionId,omitempty"`
}

// maxMindResponse is the wire shape returned by GET
// /api/v1/settings/maxmind. There is NO license key field at
// all — the UI binds `configured` to render the "secret already
// saved" affordance.
type maxMindResponse struct {
	AccountID  int    `json:"accountId"`
	EditionID  string `json:"editionId"`
	Configured bool   `json:"configured"`
}

// maxMindConfigForAudit returns a copy of c with the LicenseKey
// blanked. Mirror of crowdSecConfigForAudit: the audit row holds
// the account ID + edition + the fact a change happened, never
// the secret payload.
func maxMindConfigForAudit(c storage.MaxMindConfig) storage.MaxMindConfig {
	c.LicenseKey = ""
	return c
}

// maxMindResponseFor builds the GET/PUT/DELETE response shape
// from a stored row + an `everConfigured` boolean (true when a
// row exists). Configured is true only when both AccountID and
// LicenseKey are set — matching the storage layer's validation
// invariant that a persisted row always has both, but staying
// defensive against a zeroed/absent row.
func maxMindResponseFor(cfg storage.MaxMindConfig, everConfigured bool) maxMindResponse {
	if !everConfigured {
		return maxMindResponse{Configured: false}
	}
	return maxMindResponse{
		AccountID:  cfg.AccountID,
		EditionID:  cfg.EditionID,
		Configured: cfg.AccountID > 0 && cfg.LicenseKey != "",
	}
}

// getMaxMindSettings serves GET /api/v1/settings/maxmind.
// Returns 200 + configured=false on ErrNotFound (mirror of
// getCrowdSecSettings's no-row behaviour) — the lifecycle
// convention is "no 404 for absent settings; the operator PUTs
// to create".
func (h *Handler) getMaxMindSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetMaxMindConfig(r.Context())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusOK, maxMindResponseFor(storage.MaxMindConfig{}, false))
			return
		}
		h.logger.Error("get maxmind config", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get maxmind config")
		return
	}
	writeJSON(w, http.StatusOK, maxMindResponseFor(cfg, true))
}

// putMaxMindSettings serves PUT /api/v1/settings/maxmind.
// Persists the row via storage.PutMaxMindConfig.
//
// Preserve-on-edit: empty LicenseKey on the wire keeps the
// previously stored value (same convention as the CrowdSec API
// key). The storage layer itself already performs this
// preserve-merge (maxmind_config.go PutMaxMindConfig), but the
// handler pre-merges from its own GetPrevious read so the audit
// AfterJSON + response reflect the merged intent consistently
// with the CrowdSec handler shape.
func (h *Handler) putMaxMindSettings(w http.ResponseWriter, r *http.Request) {
	var req maxMindRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	previous, prevErr := h.store.GetMaxMindConfig(r.Context())
	if prevErr != nil && !errors.Is(prevErr, storage.ErrNotFound) {
		h.logger.Error("get maxmind config (update)", "err", prevErr)
		writeError(w, http.StatusInternalServerError, "failed to load maxmind config")
		return
	}

	// Preserve-on-edit merge for the secret.
	licenseKey := req.LicenseKey
	if licenseKey == "" {
		licenseKey = previous.LicenseKey
	}

	merged := storage.MaxMindConfig{
		AccountID:  req.AccountID,
		LicenseKey: licenseKey,
		EditionID:  req.EditionID,
		CreatedAt:  previous.CreatedAt,
	}

	if err := h.store.PutMaxMindConfig(r.Context(), merged); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Re-fetch for audit AfterJSON + response so both reflect the
	// storage-assigned UpdatedAt / defaulted EditionID rather than
	// the client-side merge struct (mirror of the CrowdSec
	// crowdsec_settings.go re-fetch at putCrowdSecSettings).
	persisted, refetchErr := h.store.GetMaxMindConfig(r.Context())
	if refetchErr != nil {
		h.logger.Warn("re-fetch maxmind config after put failed; audit + response will report client-side merge state",
			"err", refetchErr)
		persisted = merged
	}

	evt := audit.Event{
		Action:     audit.ActionMaxMindConfigUpdated,
		TargetType: "maxmind_config",
		TargetID:   "default",
		AfterJSON:  mustMarshalForAudit(maxMindConfigForAudit(persisted)),
	}
	if !errors.Is(prevErr, storage.ErrNotFound) {
		evt.BeforeJSON = mustMarshalForAudit(maxMindConfigForAudit(previous))
	}
	h.appendAudit(r, evt)

	writeJSON(w, http.StatusOK, maxMindResponseFor(persisted, true))
}

// deleteMaxMindSettings serves DELETE /api/v1/settings/maxmind.
// Wipes the persisted MaxMind config row. Mirrors
// deleteCrowdSecSettings, minus the Caddy hot-reload (MaxMind
// credentials feed the geoipupdate client, not the embedded
// Caddy config directly).
func (h *Handler) deleteMaxMindSettings(w http.ResponseWriter, r *http.Request) {
	previous, prevErr := h.store.GetMaxMindConfig(r.Context())
	if prevErr != nil && !errors.Is(prevErr, storage.ErrNotFound) {
		h.logger.Error("get maxmind config (delete)", "err", prevErr)
		writeError(w, http.StatusInternalServerError, "failed to load maxmind config")
		return
	}

	if err := h.store.DeleteMaxMindConfig(r.Context()); err != nil {
		h.logger.Error("delete maxmind config", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete maxmind config")
		return
	}

	if !errors.Is(prevErr, storage.ErrNotFound) {
		h.appendAudit(r, audit.Event{
			Action:     audit.ActionMaxMindConfigDeleted,
			TargetType: "maxmind_config",
			TargetID:   "default",
			BeforeJSON: mustMarshalForAudit(maxMindConfigForAudit(previous)),
			// AfterJSON intentionally nil — the row no longer exists.
		})
	}

	writeJSON(w, http.StatusOK, maxMindResponseFor(storage.MaxMindConfig{}, false))
}
