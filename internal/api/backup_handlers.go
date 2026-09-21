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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/automation"
	"github.com/barto95100/arenet/internal/backup"
	"github.com/barto95100/arenet/internal/storage"
)

// Step K.3 — backup / restore HTTP surface.
//
// Endpoints (admin-only, wired in routes.go under RequireAdmin):
//   - GET  /api/v1/admin/backup    — redacted export (sentinels).
//   - POST /api/v1/admin/backup    — export with secrets, encrypted
//                                    with {"passphrase": "…"} (v2.31).
//                                    Header X-Arenet-Secrets-Included: bool
//                                    on the response, so a downstream tool
//                                    can read the flag without parsing the
//                                    body.
//   - POST /api/v1/admin/restore   — apply an uploaded JSON snapshot.
//                                    Body is the snapshot JSON; an
//                                    encrypted one needs the header
//                                    X-Arenet-Backup-Passphrase
//                                    (base64 of the passphrase).
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

// Backup encryption wire (v2.31).
const (
	// headerBackupPassphrase carries the restore passphrase, base64
	// (UTF-8) so any character survives the HTTP header.
	headerBackupPassphrase = "X-Arenet-Backup-Passphrase"
	codePassphraseRequired = "passphrase_required"
	codePassphraseInvalid  = "passphrase_invalid"
	codePassphraseTooShort = "passphrase_too_short"
	// maxPassphraseBytes bounds the passphrase accepted by the API.
	maxPassphraseBytes = 1024
	// maxBackupRequestBytes bounds the POST /admin/backup body.
	maxBackupRequestBytes = 4096
)

// getBackup handles GET /admin/backup: the redacted export (secrets
// replaced by sentinels). An export WITH secrets must be encrypted —
// POST /admin/backup with a passphrase (v2.31); the former plaintext
// include-secrets=true is refused.
func (h *Handler) getBackup(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("include-secrets") == "true" {
		writeErrorCode(w, http.StatusBadRequest, codePassphraseRequired,
			"exports with secrets are encrypted: POST /api/v1/admin/backup with {\"passphrase\": \"…\"}", nil)
		return
	}
	snap, err := backup.Export(r.Context(), h.store, h.users, arenetVersionForBackup, false)
	if err != nil {
		h.logger.Error("backup: export failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to export configuration")
		return
	}
	h.writeBackup(w, r, snap)
}

// exportEncryptedRequest is the body of POST /admin/backup.
type exportEncryptedRequest struct {
	Passphrase string `json:"passphrase"`
}

// postBackup handles POST /admin/backup: the export with secrets,
// every secret sealed with a key derived from the passphrase.
func (h *Handler) postBackup(w http.ResponseWriter, r *http.Request) {
	var req exportEncryptedRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBackupRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	snap, err := backup.Export(r.Context(), h.store, h.users, arenetVersionForBackup, true)
	if err != nil {
		h.logger.Error("backup: export failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to export configuration")
		return
	}
	if err := backup.SealSnapshot(snap, req.Passphrase); err != nil {
		if errors.Is(err, backup.ErrPassphraseTooShort) {
			writeErrorCode(w, http.StatusBadRequest, codePassphraseTooShort, err.Error(),
				map[string]any{"min": backup.MinPassphraseLen})
			return
		}
		h.logger.Error("backup: encrypt failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to encrypt the export")
		return
	}
	h.writeBackup(w, r, snap)
}

// writeBackup audits the export and writes it as a JSON download.
func (h *Handler) writeBackup(w http.ResponseWriter, r *http.Request, snap *backup.Snapshot) {
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
			"secrets_included=%t encrypted=%t routes=%d users=%d dns_providers=%d forward_auth_providers=%d oidc_configured=%t",
			snap.SecretsIncluded,
			snap.IsEncrypted(),
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
	if snap.SecretsIncluded {
		// Spec §5.3 surface (B clarification). Lets a downstream
		// archiver tag the file without reading it.
		w.Header().Set("X-Arenet-Secrets-Included", "true")
		w.Header().Set("X-Arenet-Backup-Encrypted", fmt.Sprint(snap.IsEncrypted()))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// restorePassphrase decodes the base64 passphrase header ("" if absent).
func restorePassphrase(r *http.Request) (string, error) {
	raw := r.Header.Get(headerBackupPassphrase)
	if raw == "" {
		return "", nil
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(b) > maxPassphraseBytes {
		return "", errors.New("invalid " + headerBackupPassphrase + " header (base64 of the UTF-8 passphrase expected)")
	}
	return string(b), nil
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

	// v2.31: a passphrase-encrypted backup is decrypted first; the
	// rest of the pipeline sees a plain with-secrets snapshot.
	if snap.IsEncrypted() {
		passphrase, perr := restorePassphrase(r)
		if perr == nil {
			perr = backup.OpenSnapshot(&snap, passphrase)
		}
		if perr != nil {
			code, reason := codePassphraseInvalid, "passphrase_invalid"
			if errors.Is(perr, backup.ErrPassphraseRequired) {
				code, reason = codePassphraseRequired, "passphrase_required"
			}
			h.appendAudit(r, audit.Event{
				Action:  audit.ActionConfigRestoredRejected,
				Message: fmt.Sprintf("reason=%s source_sha256=%s", reason, sha),
			})
			writeErrorCode(w, http.StatusBadRequest, code, perr.Error(), nil)
			return
		}
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
	crowdSecSwapped, err := h.reloadAfterRestore(r.Context(), report.ExtrasImported)
	if err != nil {
		h.logger.Error("backup: caddy reload after restore failed — rolling back BoltDB", "err", err)
		rollbackErr := h.store.RestoreSnapshot(r.Context(), rollbackInput)
		if rollbackErr == nil && crowdSecSwapped {
			h.restoreCrowdSecAfterRollback(r.Context(), preSnapshot)
		}
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

	if report.ExtrasImported {
		h.applyRestoredSettings(r.Context())
	}

	h.appendAudit(r, audit.Event{
		Action: audit.ActionConfigRestored,
		Message: fmt.Sprintf(
			"source_sha256=%s schema_version=%s secrets_included_in_source=%t allow_incomplete_restore=%t routes_imported=%d users_imported=%d dns_providers_imported=%d forward_auth_providers_imported=%d oidc_config_imported=%t maxmind_config_imported=%t external_certificates_imported=%d extras_imported=%t managed_domains_imported=%d error_templates_imported=%d alert_channels_imported=%d alert_rules_imported=%d api_tokens_imported=%d sentinels_inherited_total=%d sentinels_unresolved_total=%d",
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
			report.ExtrasImported,
			report.ManagedDomainsImported,
			report.ErrorTemplatesImported,
			report.AlertChannelsImported,
			report.AlertRulesImported,
			report.APITokensImported,
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
		ExtrasImported:               report.ExtrasImported,
		ManagedDomainsImported:       report.ManagedDomainsImported,
		ErrorTemplatesImported:       report.ErrorTemplatesImported,
		AlertChannelsImported:        report.AlertChannelsImported,
		AlertRulesImported:           report.AlertRulesImported,
		APITokensImported:            report.APITokensImported,
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
	ExtrasImported               bool `json:"extrasImported"`
	ManagedDomainsImported       int  `json:"managedDomainsImported"`
	ErrorTemplatesImported       int  `json:"errorTemplatesImported"`
	AlertChannelsImported        int  `json:"alertChannelsImported"`
	AlertRulesImported           int  `json:"alertRulesImported"`
	APITokensImported            int  `json:"apiTokensImported"`
	SentinelsInheritedTotal      int  `json:"sentinelsInheritedTotal"`
	SentinelsUnresolvedTotal     int  `json:"sentinelsUnresolvedTotal"`
	IncompleteRows               int  `json:"incompleteRows"`
}

// reloadAfterRestore rebuilds the Caddy config from the restored
// store. When the backup carried the extras section and a CrowdSec
// row, the restored LAPI settings are swapped in with the same single
// reload (crowdSecSwapped reports it, so a rollback can swap back).
// A restore that deleted the CrowdSec row keeps the running settings
// until the next boot, which falls back to the env vars.
func (h *Handler) reloadAfterRestore(ctx context.Context, extras bool) (crowdSecSwapped bool, err error) {
	if extras && h.crowdsecApplier != nil {
		cs, csErr := h.store.GetCrowdSecConfig(ctx)
		switch {
		case csErr == nil:
			return true, h.crowdsecApplier.ApplyCrowdSecConfig(ctx, cs.LAPIURL, cs.APIKey)
		case !errors.Is(csErr, storage.ErrNotFound):
			return false, fmt.Errorf("read restored crowdsec config: %w", csErr)
		}
	}
	return false, h.caddy.ReloadFromStore(ctx)
}

// restoreCrowdSecAfterRollback puts the pre-restore CrowdSec settings
// back in the manager after a rolled-back restore. The BoltDB is
// already rolled back, so the reload this triggers serves the
// pre-restore config. Best effort: failures are logged.
func (h *Handler) restoreCrowdSecAfterRollback(ctx context.Context, pre *backup.Snapshot) {
	if pre.Extras == nil || pre.Extras.CrowdSecConfig == nil {
		h.logger.Warn("backup: rollback — CrowdSec settings were env-driven before the restore; restart Arenet to re-apply them")
		return
	}
	cs := pre.Extras.CrowdSecConfig
	if err := h.crowdsecApplier.ApplyCrowdSecConfig(ctx, cs.LAPIURL, cs.APIKey); err != nil {
		h.logger.Error("backup: rollback — re-applying pre-restore CrowdSec settings failed", "err", err)
	}
}

// applyRestoredSettings pushes the restored automation rules and
// credentials, update-check and GeoIP-update settings into the
// running services (the Caddy-facing areas were applied by the
// reload). Best effort: the store is the source of truth and the
// next boot re-reads it, so failures are logged, not returned.
func (h *Handler) applyRestoredSettings(ctx context.Context) {
	if mgr := automation.GetManager(); mgr != nil {
		rules, err := h.loadRules(ctx)
		if err != nil {
			h.logger.Warn("backup: reload restored automation rules failed; using defaults", "err", err)
			rules = automation.DefaultRuleSet()
		}
		mgr.SetRules(rules)
		creds, err := h.store.GetWatcherCredentials(ctx)
		switch {
		case err == nil && storage.WatcherCredentialsConfigured(creds):
			if err := mgr.SetCredentials(automation.WatcherConfig{
				LAPIURL: creds.LAPIURL, MachineID: creds.MachineID, Password: creds.Password,
			}); err != nil {
				h.logger.Warn("backup: restored watcher credentials rejected", "err", err)
				mgr.ClearCredentials()
			}
		case err == nil || errors.Is(err, storage.ErrNotFound):
			mgr.ClearCredentials()
		default:
			h.logger.Warn("backup: read restored watcher credentials failed", "err", err)
		}
	}
	if h.onUpdateConfigChange != nil {
		if cfg, err := h.store.GetUpdateCheckConfig(ctx); err == nil {
			h.onUpdateConfigChange(cfg)
		} else {
			h.logger.Warn("backup: read restored update-check config failed", "err", err)
		}
	}
	if h.onGeoIPConfigChange != nil {
		if cfg, err := h.store.GetGeoIPUpdateConfig(ctx); err == nil {
			h.onGeoIPConfigChange(cfg)
		} else {
			h.logger.Warn("backup: read restored geoip update config failed", "err", err)
		}
	}
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
