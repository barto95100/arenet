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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/backup"
)

// Step K.3 — backup / restore HTTP surface.
//
// Endpoints (admin-only, wired in routes.go under RequireAdmin):
//   - GET  /api/v1/admin/backup    — export the live config as JSON.
//                                    Query: include-secrets=true → cleartext.
//                                    Header X-Arenet-Secrets-Included: bool
//                                    on the response, so a downstream tool
//                                    can read the flag without parsing the
//                                    body.
//   - POST /api/v1/admin/restore   — apply an uploaded JSON snapshot.
//                                    Body is the snapshot JSON.
//                                    Query: allow-incomplete-restore=true /
//                                    allow-empty-users=true → opt-in bypasses.
//
// Both endpoints emit audit events on success AND on failure
// (config_restored_rejected). Auditing on failure matters: a
// rejected restore is the kind of event an operator wants to trace
// post-mortem.

// arenetVersionForBackup is the version string baked into every
// export. The cmd/arenet/main.go const "version" is the source of
// truth; we shadow it here so the api package doesn't have to import
// cmd. The CLI export path passes its own version directly to
// backup.Export.
const arenetVersionForBackup = "v0.7.x"

// getBackup handles GET /admin/backup. Builds a Snapshot via
// internal/backup, writes it as a JSON download. On
// include-secrets=true, sets the X-Arenet-Secrets-Included header
// and the audit event flags secrets_included=true.
func (h *Handler) getBackup(w http.ResponseWriter, r *http.Request) {
	includeSecrets := r.URL.Query().Get("include-secrets") == "true"

	snap, err := backup.Export(r.Context(), h.store, h.users, arenetVersionForBackup, includeSecrets)
	if err != nil {
		h.logger.Error("backup: export failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to export configuration")
		return
	}

	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		h.logger.Error("backup: marshal failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to serialise configuration")
		return
	}

	// Audit BEFORE returning the body — operator's intent is
	// already a fact, audit it whether the download completes or
	// the client closes the connection mid-flight.
	h.appendAudit(r, audit.Event{
		Action: audit.ActionConfigExported,
		Message: fmt.Sprintf(
			"secrets_included=%t routes=%d users=%d dns_providers=%d forward_auth_providers=%d oidc_configured=%t",
			includeSecrets,
			len(snap.Routes),
			len(snap.Users),
			len(snap.DNSProviders),
			len(snap.ForwardAuthProviders),
			snap.OIDCConfig.IssuerURL != "" || snap.OIDCConfig.ClientID != "",
		),
	})

	filename := fmt.Sprintf("arenet-backup-%s.json", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	if includeSecrets {
		// Spec §5.3 surface (B clarification). Lets a downstream
		// archiver tag the file without reading it.
		w.Header().Set("X-Arenet-Secrets-Included", "true")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// postRestore handles POST /admin/restore. Reads the body as a
// Snapshot, computes its SHA-256 (for the audit trail), runs the
// full backup.Import pipeline, and on success calls ReloadFromStore
// (Q4 hot-apply per spec §5.3).
//
// SECURITY: this is the most destructive admin endpoint. Auth chain:
// hard-auth + RequireAdmin (enforced in routes.go). Audit on BOTH
// success and rejection — the operator needs to trace any restore
// attempt.
func (h *Handler) postRestore(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024*1024)) // 64 MiB ceiling
	if err != nil {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionConfigRestoredRejected,
			Message: "reason=read_body_failed",
		})
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])

	var snap backup.Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionConfigRestoredRejected,
			Message: fmt.Sprintf("reason=invalid_json source_sha256=%s err=%s", sha, truncate(err.Error(), 200)),
		})
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	q := r.URL.Query()
	opts := backup.ImportOptions{
		AllowIncompleteRestore: q.Get("allow-incomplete-restore") == "true",
		AllowEmptyUsers:        q.Get("allow-empty-users") == "true",
	}

	// Step K.3 Q4 rollback — snapshot the live state BEFORE the
	// import lands, so we can re-apply it if ReloadFromStore
	// fails after the BoltDB commit. We use Export(secrets=true)
	// because:
	//   - the live values are by definition non-sentinel (no
	//     resolution pass needed for the rollback re-apply),
	//   - the input survives in process memory only and is
	//     discarded before this handler returns.
	preSnapshot, err := backup.Export(r.Context(), h.store, h.users, arenetVersionForBackup, true)
	if err != nil {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionConfigRestoredRejected,
			Message: fmt.Sprintf("reason=preflight_snapshot_failed source_sha256=%s err=%s", sha, truncate(err.Error(), 200)),
		})
		writeError(w, http.StatusInternalServerError, "failed to snapshot pre-restore state for rollback safety: "+err.Error())
		return
	}
	rollbackInput, err := backup.BuildRestoreInputFromSnapshot(preSnapshot)
	if err != nil {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionConfigRestoredRejected,
			Message: fmt.Sprintf("reason=preflight_marshal_failed source_sha256=%s err=%s", sha, truncate(err.Error(), 200)),
		})
		writeError(w, http.StatusInternalServerError, "failed to marshal pre-restore snapshot: "+err.Error())
		return
	}

	// Build an ImportStorer adapter — the Handler.store is a
	// *storage.Store which already implements every method.
	report, err := backup.Import(r.Context(), h.store, h.users, &snap, opts)
	if err != nil {
		reason := classifyRestoreError(err)
		h.appendAudit(r, audit.Event{
			Action: audit.ActionConfigRestoredRejected,
			Message: fmt.Sprintf(
				"reason=%s source_sha256=%s schema_version=%s secrets_included_in_source=%t allow_incomplete_restore=%t allow_empty_users=%t",
				reason, sha, snap.SchemaVersion, snap.SecretsIncluded, opts.AllowIncompleteRestore, opts.AllowEmptyUsers,
			),
		})
		// Surface the actionable error verbatim on 400 — the
		// operator needs the "two paths forward" wording.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Hot-apply: rebuild Caddy config from the restored BoltDB.
	// Q4 arbitration: on reload failure, the BoltDB is rolled
	// back to the pre-restore state via the in-memory snapshot
	// taken above. We do NOT re-call ReloadFromStore after the
	// rollback — a failed reload leaves Caddy on the OLD config
	// in memory, so after re-applying the pre-restore BoltDB
	// the storage matches what Caddy is already serving.
	//
	// Edge irréductible: if the rollback re-apply ITSELF fails,
	// we stay loud (500 + audit) and don't attempt a rollback-of-
	// rollback. Re-applying a known-good state is the
	// incompressible edge.
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("backup: caddy reload after restore failed — rolling back BoltDB", "err", err)
		rollbackErr := h.store.RestoreSnapshot(r.Context(), rollbackInput)
		if rollbackErr != nil {
			// Edge incompressible — log + audit, no further attempt.
			h.logger.Error("backup: ROLLBACK FAILED after caddy reload failure", "rollback_err", rollbackErr, "reload_err", err)
			h.appendAudit(r, audit.Event{
				Action: audit.ActionConfigRestoredRejected,
				Message: fmt.Sprintf(
					"reason=rollback_failed source_sha256=%s reload_err=%s rollback_err=%s",
					sha, truncate(err.Error(), 120), truncate(rollbackErr.Error(), 120),
				),
			})
			writeError(w, http.StatusInternalServerError,
				"CRITICAL: Caddy reload failed AND rollback failed. BoltDB is in an indeterminate state. reload_err: "+err.Error()+"; rollback_err: "+rollbackErr.Error())
			return
		}
		h.appendAudit(r, audit.Event{
			Action: audit.ActionConfigRestoredRejected,
			Message: fmt.Sprintf(
				"reason=caddy_reload_failed_rolled_back source_sha256=%s schema_version=%s err=%s",
				sha, snap.SchemaVersion, truncate(err.Error(), 200),
			),
		})
		writeError(w, http.StatusInternalServerError, "restore applied but Caddy reload failed; BoltDB rolled back to pre-restore state: "+err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action: audit.ActionConfigRestored,
		Message: fmt.Sprintf(
			"source_sha256=%s schema_version=%s secrets_included_in_source=%t allow_incomplete_restore=%t routes_imported=%d users_imported=%d dns_providers_imported=%d forward_auth_providers_imported=%d oidc_config_imported=%t maxmind_config_imported=%t external_certificates_imported=%d sentinels_inherited_total=%d sentinels_unresolved_total=%d",
			sha,
			report.SchemaVersion,
			report.SecretsIncludedInSource,
			report.AllowIncompleteRestore,
			report.RoutesImported,
			report.UsersImported,
			report.DNSProvidersImported,
			report.ForwardAuthProvidersImported,
			report.OIDCConfigImported,
			report.MaxMindConfigImported,
			report.ExternalCertificatesImported,
			report.SentinelsInheritedTotal,
			report.SentinelsUnresolvedTotal,
		),
	})

	writeJSON(w, http.StatusOK, restoreResponse{
		RoutesImported:               report.RoutesImported,
		UsersImported:                report.UsersImported,
		DNSProvidersImported:         report.DNSProvidersImported,
		ForwardAuthProvidersImported: report.ForwardAuthProvidersImported,
		OIDCConfigImported:           report.OIDCConfigImported,
		MaxMindConfigImported:        report.MaxMindConfigImported,
		ExternalCertificatesImported: report.ExternalCertificatesImported,
		SentinelsInheritedTotal:      report.SentinelsInheritedTotal,
		SentinelsUnresolvedTotal:     report.SentinelsUnresolvedTotal,
		IncompleteRows:               len(report.IncompleteRows),
	})
}

type restoreResponse struct {
	RoutesImported               int  `json:"routesImported"`
	UsersImported                int  `json:"usersImported"`
	DNSProvidersImported         int  `json:"dnsProvidersImported"`
	ForwardAuthProvidersImported int  `json:"forwardAuthProvidersImported"`
	OIDCConfigImported           bool `json:"oidcConfigImported"`
	MaxMindConfigImported        bool `json:"maxmindConfigImported"`
	ExternalCertificatesImported int  `json:"externalCertificatesImported"`
	SentinelsInheritedTotal      int  `json:"sentinelsInheritedTotal"`
	SentinelsUnresolvedTotal     int  `json:"sentinelsUnresolvedTotal"`
	IncompleteRows               int  `json:"incompleteRows"`
}

// classifyRestoreError reduces a backup.Import error to a short
// audit token. Keeping the audit message compact while still
// surfacing the failure mode.
func classifyRestoreError(err error) string {
	switch {
	case errors.Is(err, backup.ErrPreflightDisasterRecovery):
		return "preflight_disaster_recovery"
	case errors.Is(err, backup.ErrEmptyUsers):
		return "empty_users"
	case backup.IsUnresolvedSentinelError(err):
		return "unresolved_sentinel"
	}
	var schemaErr *backup.ErrSchemaMajorMismatch
	if errors.As(err, &schemaErr) {
		return "schema_major_mismatch"
	}
	// Default — include a truncated form of the underlying
	// message so a post-mortem can read the wire.
	return "other:" + strings.ReplaceAll(truncate(err.Error(), 80), " ", "_")
}
