// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/go-chi/chi/v5"
)

// Undoing a manual ban (v2.72).
//
// A decision created through Arenet's UI could not be removed through
// Arenet: the router carried only GET and POST on
// /security/crowdsec/decisions, so the only way back was `cscli
// decisions delete` on the host. The codebase modelled it that way
// throughout — internal/automation/cooldown.go and rules.go both treat
// "the operator unbanned" as an event that happens elsewhere and has to
// be detected after the fact. A destructive action with no inverse is
// the defect; this is the inverse.
//
// LAPI facts, read in crowdsec@v1.6.3 rather than assumed:
//
//   - DELETE /v1/decisions/:decision_id is mounted ONLY in the machine
//     JWT group (pkg/apiserver/controllers/controller.go:127). The
//     bouncer API key group has GET and HEAD only (:134-137), so this
//     goes through the Security Automation credentials, exactly like the
//     manual ban.
//   - Success is 200 with {"nbDeleted":"<n>"} — the count is a STRING
//     (controllers/v1/decisions.go, strconv.Itoa on the way out).
//   - The decision is EXPIRED (until=now), not deleted
//     (pkg/database/decisions.go ExpireDecisionByID → ExpireDecisions).
//     The bouncer's stream then reports it as deleted.
//   - An unknown id answers 500, not 404: ExpireDecisionByID wraps
//     DeleteFail, and HandleDBErrors has no case for it, so it falls to
//     default (controllers/v1/errors.go). The upstream source even
//     carries "// XXX: do we want 500 or 404 here?" at that spot. We
//     therefore CANNOT tell "already expired" from a real LAPI failure,
//     and the error we return says so instead of guessing.
//   - A non-integer id answers 400 "decision_id must be valid integer".
//
// Security note on building the path. The id is interpolated into a URL
// path, and the sibling route DELETE /v1/decisions — the same verb with
// no id — expires decisions in BULK (controller.go:126). A crafted id
// containing path traversal would therefore be a way to turn "remove
// this one ban" into "remove every ban". The guard is twofold: the id
// must parse as an unsigned integer, and the path is then built from the
// PARSED NUMBER, never from the string the client sent.

// crowdSecDecisionDeleteResponse echoes what LAPI reported.
//
// NbDeleted is an int here even though LAPI sends a string: the wire
// shape an operator's tooling sees should be a number, and the decoding
// of LAPI's string happens in one place below.
type crowdSecDecisionDeleteResponse struct {
	ID        uint64 `json:"id"`
	NbDeleted int    `json:"nbDeleted"`
}

// lapiDeleteDecisionResponse is LAPI's own shape, with NbDeleted as the
// string it really is.
type lapiDeleteDecisionResponse struct {
	NbDeleted string `json:"nbDeleted"`
}

// parseDecisionID accepts only an unsigned decimal integer.
//
// Returning the number rather than the string is deliberate: every
// caller must build its LAPI path from this value, so no part of the
// client's input can reach the URL. See the security note above.
func parseDecisionID(raw string) (uint64, error) {
	if raw == "" {
		return 0, errors.New("decision id is required")
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid decision id %q (expected a positive integer)", raw)
	}
	if id == 0 {
		// LAPI ids start at 1; 0 is never a real decision and would
		// read oddly in the audit trail.
		return 0, errors.New("invalid decision id 0 (expected a positive integer)")
	}
	return id, nil
}

// deleteCrowdSecDecision expires one LAPI decision. Admin-only (the
// route sits inside the RequireAdminMiddleware group).
func (h *Handler) deleteCrowdSecDecision(w http.ResponseWriter, r *http.Request) {
	id, idErr := parseDecisionID(chi.URLParam(r, "id"))
	if idErr != nil {
		writeError(w, http.StatusBadRequest, idErr.Error())
		return
	}

	// Security Automation creds — same source and same 412 contract as
	// the manual ban, because it is the same JWT group on LAPI.
	creds, credsErr := h.store.GetWatcherCredentials(r.Context())
	if credsErr != nil && !errors.Is(credsErr, storage.ErrNotFound) {
		h.logger.Error("get watcher credentials (decision delete)", "err", credsErr)
		writeError(w, http.StatusInternalServerError, "failed to load automation credentials")
		return
	}
	if errors.Is(credsErr, storage.ErrNotFound) || !storage.WatcherCredentialsConfigured(creds) {
		writeError(w, http.StatusPreconditionFailed,
			"security automation not configured — set machine credentials in Settings → Security Automation to remove a decision")
		return
	}

	timeout := h.crowdSecLAPITimeout(r.Context())

	nbDeleted, err := h.deleteDecisionOnLAPI(r.Context(), creds, timeout, id)
	if err != nil {
		if errors.Is(err, errLAPIAuthRejected) {
			writeError(w, http.StatusBadGateway,
				"machine credentials rejected by LAPI — re-verify Settings → Security Automation")
			return
		}
		if errors.Is(err, errLAPIDecisionDeleteFailed) {
			// LAPI answers 500 both for "no such decision" and for a
			// genuine database failure, so this message names both
			// rather than asserting one. Guessing "not found" here
			// would tell the operator their ban is gone when it may
			// still be in force.
			writeError(w, http.StatusBadGateway,
				"LAPI refused to expire this decision — it may already have expired, or LAPI may be failing; "+
					"reload the list to see whether it is still active")
			return
		}
		writeError(w, http.StatusBadGateway, classifyProbeError(err, creds.Password))
		return
	}

	resp := crowdSecDecisionDeleteResponse{ID: id, NbDeleted: nbDeleted}

	// Audit AFTER LAPI accepts. BeforeJSON is nil: the decision's prior
	// shape is LAPI's, not ours, and re-fetching it would race the
	// expiry we just performed.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionCrowdSecDecisionDelete,
		TargetType: "crowdsec_decision",
		TargetID:   strconv.FormatUint(id, 10),
		AfterJSON:  mustMarshalForAudit(resp),
	})

	writeJSON(w, http.StatusOK, resp)
}

// crowdSecLAPITimeout is the per-request budget for a LAPI call,
// taken from the bouncer's configured timeout when there is one.
//
// Extracted here from addManualBan, which had it inline, so the two
// LAPI-facing handlers cannot drift apart on how long they wait.
func (h *Handler) crowdSecLAPITimeout(ctx context.Context) time.Duration {
	timeoutSec := defaultCrowdSecLAPITimeoutSeconds
	if cs, err := h.store.GetCrowdSecConfig(ctx); err == nil && cs.TimeoutSeconds > 0 {
		timeoutSec = cs.TimeoutSeconds
	}
	return time.Duration(timeoutSec) * time.Second
}

// defaultCrowdSecLAPITimeoutSeconds applies when the bouncer has no
// configured timeout of its own.
const defaultCrowdSecLAPITimeoutSeconds = 5

// errLAPIDecisionDeleteFailed marks the 500 LAPI returns both for an
// unknown id and for a real failure. Kept distinct from a transport
// error so the handler can explain the ambiguity.
var errLAPIDecisionDeleteFailed = errors.New("lapi refused to expire the decision")

// deleteDecisionOnLAPI sends the expiry and decodes the count.
//
// Retries once on an auth rejection with forceLogin, mirroring
// postManualBanToLAPI: the cached JWT can expire between calls.
func (h *Handler) deleteDecisionOnLAPI(
	ctx context.Context,
	creds storage.WatcherCredentials,
	timeout time.Duration,
	id uint64,
) (int, error) {
	// Built from the parsed integer: nothing the client sent can reach
	// this path. See the security note at the top of the file.
	path := "/v1/decisions/" + strconv.FormatUint(id, 10)

	body, status, err := h.lapiWithJWT(ctx, creds, timeout, http.MethodDelete, path, nil, false)
	if errors.Is(err, errLAPIAuthRejected) {
		body, status, err = h.lapiWithJWT(ctx, creds, timeout, http.MethodDelete, path, nil, true)
	}
	if err != nil {
		if status == http.StatusInternalServerError || status == http.StatusNotFound {
			return 0, errLAPIDecisionDeleteFailed
		}
		return 0, err
	}

	var decoded lapiDeleteDecisionResponse
	if len(body) > 0 {
		if jsonErr := json.Unmarshal(body, &decoded); jsonErr != nil {
			// The expiry already happened; only the count is unreadable.
			// Report zero rather than failing the request.
			h.logger.Warn("decision delete: unreadable LAPI response",
				"id", id, "err", jsonErr)
			return 0, nil
		}
	}
	nb, convErr := strconv.Atoi(decoded.NbDeleted)
	if convErr != nil {
		h.logger.Warn("decision delete: LAPI nbDeleted is not a number",
			"id", id, "value", decoded.NbDeleted)
		return 0, nil
	}
	return nb, nil
}
