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
	"strings"
	"time"

	"github.com/maxmind/geoipupdate/v8/client"

	"github.com/barto95100/arenet/internal/storage"
)

// Brick 2 Task 3 — POST /api/v1/settings/maxmind/test.
//
// Validates the operator's MaxMind credentials by making a REAL
// authenticated request via geoipupdate/v8/client, WITHOUT
// downloading the ~60MB GeoIP database. Mirrors the CrowdSec /
// OIDC test-connection pattern: always 200 with a {reachable,
// error} body so the frontend can render a coherent toast for
// both outcomes — this is a diagnostic probe, never a hard
// failure.

// maxMindTestDeadline caps the whole probe. 12s: MaxMind's
// metadata endpoint is typically sub-second, but a homelab WAN
// cold-cache DNS + TLS handshake can eat a few seconds; matches
// the brief's budget.
const maxMindTestDeadline = 12 * time.Second

// maxMindTestRequest is the wire shape accepted by POST
// /api/v1/settings/maxmind/test.
type maxMindTestRequest struct {
	AccountID  int    `json:"accountId"`
	LicenseKey string `json:"licenseKey"`
	EditionID  string `json:"editionId"`
	UseStored  bool   `json:"useStored"`
}

// maxMindTestResponse is the wire shape returned to the frontend
// toast. Always 200 regardless of Reachable.
type maxMindTestResponse struct {
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

// maxMindProbe validates MaxMind credentials by attempting an
// authenticated request. It MUST NOT download the full database.
//
// Empirical verification (geoipupdate/v8 client @ v8.0.0):
// Client.Download first calls the unexported getMetadata, which
// performs a real Basic-Auth'd GET against
// {endpoint}/geoip/updates/metadata — a small JSON response
// (auth is proven here: a bad account/key yields a non-200,
// wrapped as *client.HTTPError). Only when the metadata MD5
// differs from the md5 argument does Download go on to call the
// actual /geoip/databases/.../download endpoint (the ~60MB
// payload). With any dummy md5 that doesn't match, that second
// call WILL fire — but net/http's Response.Body is streamed on
// demand (see net/http.Response.Body doc: "streamed on demand as
// the Body field is read"); Do() returns once headers arrive,
// and Download() itself only reads a small gzip-header + one tar
// header block before returning DownloadResponse.Reader
// unconsumed. As long as THIS seam never reads from
// resp.Reader (no io.ReadAll) and closes it immediately, the DB
// payload is never pulled off the wire. Verified by reading
// client/download.go (Do → gzip.NewReader → tarReader.Next(),
// none of which drain the mmdb payload) — no test harness could
// substitute for reading the real transport semantics here, but
// this is exactly the seam the task brief anticipated; Task 5
// should still confirm empirically against a real (or recorded)
// MaxMind response that byte counts stay small.
//
// Overridable in tests — NEVER hit the real API in unit tests.
var maxMindProbe = func(ctx context.Context, accountID int, licenseKey, editionID string) error {
	c, err := client.New(accountID, licenseKey,
		client.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}))
	if err != nil {
		return err
	}
	// Non-empty dummy md5: if the account happens to already have
	// this exact (impossible) hash the call short-circuits with an
	// empty in-memory Reader; otherwise Download proceeds to the
	// download endpoint but we close its Reader unread below — we
	// only care that auth succeeded (proven by getMetadata, called
	// internally before any of this).
	resp, err := c.Download(ctx, editionID, "00000000000000000000000000000000")
	if err != nil {
		return err
	}
	if resp.Reader != nil {
		_ = resp.Reader.Close() // do NOT io.ReadAll — must not pull ~60MB
	}
	return nil
}

// testMaxMindConnection is the chi handler for POST
// /api/v1/settings/maxmind/test. Admin-only via the router-level
// RequireAdminMiddleware (same subgroup as the CRUD endpoints).
//
// Resolves effective credentials mirroring
// testCrowdSecConnection: UseStored ignores wire fields entirely;
// otherwise wire fields fall back to the stored row on a
// per-field basis (a partial form is possible: operator changes
// the edition only and probes against the existing stored
// account/key).
func (h *Handler) testMaxMindConnection(w http.ResponseWriter, r *http.Request) {
	var req maxMindTestRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	stored, storedErr := h.store.GetMaxMindConfig(r.Context())
	if storedErr != nil && !errors.Is(storedErr, storage.ErrNotFound) {
		h.logger.Error("get maxmind config (test)", "err", storedErr)
		writeError(w, http.StatusInternalServerError, "failed to load maxmind config")
		return
	}

	var effAccountID int
	var effKey, effEdition string
	if req.UseStored {
		effAccountID = stored.AccountID
		effKey = stored.LicenseKey
		effEdition = stored.EditionID
	} else {
		effAccountID = req.AccountID
		if effAccountID <= 0 {
			effAccountID = stored.AccountID
		}
		effKey = strings.TrimSpace(req.LicenseKey)
		if effKey == "" {
			effKey = stored.LicenseKey
		}
		effEdition = strings.TrimSpace(req.EditionID)
		if effEdition == "" {
			effEdition = stored.EditionID
		}
	}
	if effEdition == "" {
		effEdition = "GeoLite2-City"
	}

	if effAccountID <= 0 || effKey == "" {
		writeJSON(w, http.StatusOK, maxMindTestResponse{
			Reachable: false,
			Error:     "no credentials",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), maxMindTestDeadline)
	defer cancel()

	err := maxMindProbe(ctx, effAccountID, effKey, effEdition)

	h.logger.Info("maxmind test probed",
		"account_id", effAccountID,
		"edition_id", effEdition,
		"reachable", err == nil)

	if err == nil {
		writeJSON(w, http.StatusOK, maxMindTestResponse{Reachable: true})
		return
	}

	var httpErr client.HTTPError
	if errors.As(err, &httpErr) {
		writeJSON(w, http.StatusOK, maxMindTestResponse{
			Reachable: false,
			Error:     "credentials rejected: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, maxMindTestResponse{
		Reachable: false,
		Error:     "could not reach MaxMind: " + err.Error(),
	})
}
