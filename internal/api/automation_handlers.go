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
	"net/http"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/automation"
	"github.com/barto95100/arenet/internal/storage"
)

// Step P.3 — auto-classify (Arenet → LAPI write-back) REST
// endpoints.
//
// Three operator-facing surfaces:
//
//   - GET    /api/v1/settings/automation             (viewer)
//   - PUT    /api/v1/settings/automation/rules       (admin)
//   - PUT    /api/v1/settings/automation/credentials (admin)
//   - DELETE /api/v1/settings/automation/credentials (admin)
//
// The GET response wraps both halves (the rule set + a
// credentials-configured boolean) into one object so the
// frontend loads the page state with a single request.

// automationResponse is the GET wire shape.
type automationResponse struct {
	// Rules is the current rule set (every Source pre-
	// populated with at least its disabled-default rule, so
	// the frontend always sees a known shape).
	Rules automation.RuleSet `json:"rules"`
	// Credentials surfaces the LAPI URL + machine-id +
	// `configured` boolean. Password is ALWAYS redacted.
	// Same J.4 secret discipline as the DNS provider GET.
	Credentials credentialsResponse `json:"credentials"`
	// EngineRunning says whether the trigger engine exists in this
	// process (v2.72).
	//
	// Rules are saved and audited whether it does or not, which is the
	// right call — they take effect at the next boot and refusing the
	// write would lose the operator's work. What was missing is any way
	// to know. wireAutomation failing at boot logs one WARN line and
	// Arenet keeps serving (cmd/arenet/main.go), so the rules page
	// showed a saved, audited rule set that nothing was evaluating.
	//
	// Note what this is NOT: `configured` above still means "watcher
	// credentials are stored and usable", which is a different fact and
	// one storage can answer on its own. Making it false here would
	// tell the operator to re-enter credentials that are already
	// correct. The missing fact gets its own field rather than
	// overloading that one.
	EngineRunning bool `json:"engineRunning"`
	// Health is the live auto-classify writer health (v2.83, point
	// 3(a)). Always present: zero/null when no manager is wired or the
	// writer is unconfigured — never omitted, so the frontend badge can
	// always read it without a nil check.
	Health automationHealth `json:"health"`
}

// automationHealth is the GET response's read-only health block. It
// surfaces the same facts as the /metrics endpoint (v2.83 point 3(b))
// so the dashboard badge can render without a scraper. Counters are
// cumulative; LastPushAt/LastPushError are the point-in-time view.
type automationHealth struct {
	// WriterHealthy is WriterConfigured && !WriterLoginFailed: the
	// writer is wired AND its last LAPI login was not rejected. False
	// whenever credentials are absent.
	WriterHealthy      bool   `json:"writerHealthy"`
	TotalPushSuccess   uint64 `json:"totalPushSuccess"`
	TotalPushPermanent uint64 `json:"totalPushPermanent"`
	TotalPushDropped   uint64 `json:"totalPushDropped"`
	// LastPushAt is the RFC3339 (UTC) time of the last successful push,
	// or nil when none has succeeded yet.
	LastPushAt *string `json:"lastPushAt"`
	// LastPushError is the message of the most recent failed push, or
	// nil (cleared on the next success — see automation.HealthSnapshot).
	LastPushError *string `json:"lastPushError"`
	// D11 (v2.84.0) ban-activity view for the in-UI "recent bans" line.
	// TotalBansIssued24h is an in-memory rolling count (resets on restart;
	// LAPI is the ledger). LastBanScenario/LastBanSrcIP are the most recent
	// ban's context, at the LastPushAt instant (which is also "last ban
	// issued at" — v1.3 only issues bans); nil when none issued yet.
	TotalBansIssued24h int     `json:"totalBansIssued24h"`
	LastBanScenario    *string `json:"lastBanScenario"`
	LastBanSrcIP       *string `json:"lastBanSrcIp"`
}

type credentialsResponse struct {
	LAPIURL    string `json:"lapiUrl"`
	MachineID  string `json:"machineId"`
	Configured bool   `json:"configured"`
}

// putRulesRequest is the wire shape for PUT
// /api/v1/settings/automation/rules. Mirrors
// automation.RuleSet's JSON tags.
type putRulesRequest struct {
	Rules automation.RuleSet `json:"rules"`
}

// putCredentialsRequest is the wire shape for PUT
// /api/v1/settings/automation/credentials. Empty Password
// triggers the preserve-on-edit path (the stored value is
// kept) — same J.4 pattern.
type putCredentialsRequest struct {
	LAPIURL   string `json:"lapiUrl"`
	MachineID string `json:"machineId"`
	Password  string `json:"password"`
}

// getAutomation serves GET /api/v1/settings/automation. Viewer-
// accessible per AC #20. Three combined reads:
//   - Rules from storage (or DefaultRuleSet on ErrNotFound).
//   - Credentials from storage (or zero-value on ErrNotFound).
//   - CredentialsConfigured from the running automation.Manager
//     (reflects the live writer state — may differ from storage
//     during a credential rotation that fails the LAPI handshake).
//
// AC #15 boot-degraded path: if no Manager is registered, the
// `configured` field still surfaces the storage-side state
// (the operator can see what's persisted even when the engine
// itself isn't running).
func (h *Handler) getAutomation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rules, err := h.loadRules(ctx)
	if err != nil {
		h.logger.Error("automation: load rules", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load automation rules")
		return
	}

	creds, err := h.store.GetWatcherCredentials(ctx)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		h.logger.Error("automation: load credentials", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load watcher credentials")
		return
	}

	configured := storage.WatcherCredentialsConfigured(creds)
	// Manager view trumps storage when available — reflects
	// the live writer state after a rotation.
	mgr := automation.GetManager()
	if mgr != nil {
		configured = mgr.CredentialsConfigured()
	}

	// v2.83 point 3(a) — live writer health. Zero/null when no manager
	// is wired (boot-degraded) or the manager is not a HealthReporter;
	// the block is always emitted so the badge reads it unconditionally.
	health := automationHealth{}
	if hr, ok := mgr.(automation.HealthReporter); ok {
		snap := hr.HealthSnapshot()
		health.WriterHealthy = snap.WriterConfigured && !snap.WriterLoginFailed
		health.TotalPushSuccess = snap.PushSuccess
		health.TotalPushPermanent = snap.PushPermanent
		health.TotalPushDropped = snap.PushDropped
		if snap.LastPushAt != nil {
			s := snap.LastPushAt.UTC().Format(time.RFC3339)
			health.LastPushAt = &s
		}
		health.LastPushError = snap.LastPushError
		health.TotalBansIssued24h = snap.TotalBansIssued24h
		health.LastBanScenario = snap.LastBanScenario
		health.LastBanSrcIP = snap.LastBanSrcIP
	}

	writeJSON(w, http.StatusOK, automationResponse{
		Rules: rules,
		Credentials: credentialsResponse{
			LAPIURL:    creds.LAPIURL,
			MachineID:  creds.MachineID,
			Configured: configured,
		},
		// v2.72 — nil manager means wireAutomation failed at boot and
		// nothing is evaluating these rules.
		EngineRunning: mgr != nil,
		Health:        health,
	})
}

// loadRules reads the persisted RuleSet, materialising
// DefaultRuleSet() on a fresh install (no row yet). The
// stored bytes are decoded into automation.RuleSet — a
// shape mismatch (future drift between storage blob format
// + RuleSet JSON tags) is surfaced as an error to the
// caller.
func (h *Handler) loadRules(ctx context.Context) (automation.RuleSet, error) {
	raw, err := h.store.GetAutomationRulesRaw(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return automation.DefaultRuleSet(), nil
		}
		return automation.RuleSet{}, err
	}
	// Wire shape is {"rules": {...}}, matching the GET
	// response (so PUT can echo back its own GET output
	// verbatim — round-trippable).
	var envelope putRulesRequest
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return automation.RuleSet{}, err
	}
	// Defensive: if the stored blob omits the rules map,
	// fall back to defaults. Operator visible: a corrupted
	// row reads as "default rules" rather than locking out
	// the UI.
	if envelope.Rules.Rules == nil {
		return automation.DefaultRuleSet(), nil
	}
	return envelope.Rules, nil
}

// putAutomationRules serves PUT /api/v1/settings/automation/
// rules. Admin-only. Validates the RuleSet, persists, swaps
// the live Engine's holder atomically. Audit emission carries
// before / after JSON.
//
// Per the P.2 commit-body checklist item #4: this handler
// calls automation.Manager.SetRules — the RuleSetHolder.Set
// path the Engine reads at each tick.
func (h *Handler) putAutomationRules(w http.ResponseWriter, r *http.Request) {
	var req putRulesRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	if err := req.Rules.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	previous, _ := h.loadRules(ctx) // best-effort for the audit before-JSON

	// Persist as opaque JSON. Re-marshal here (rather than
	// pass the request body bytes through) so we own the
	// shape: the stored blob is exactly what loadRules can
	// round-trip back.
	envelope := putRulesRequest{Rules: req.Rules}
	raw, err := json.Marshal(envelope)
	if err != nil {
		h.logger.Error("automation: marshal rules", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to marshal rules")
		return
	}
	if err := h.store.PutAutomationRulesRaw(ctx, raw); err != nil {
		h.logger.Error("automation: persist rules", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to persist rules")
		return
	}

	// Live swap on the running engine. AC #15 boot-degraded:
	// no Manager registered → rules persisted only, take
	// effect on next boot.
	if mgr := automation.GetManager(); mgr != nil {
		mgr.SetRules(req.Rules)
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionAutomationRuleChanged,
		TargetType: "automation_rules",
		BeforeJSON: mustMarshalForAudit(putRulesRequest{Rules: previous}),
		AfterJSON:  mustMarshalForAudit(envelope),
	})

	writeJSON(w, http.StatusOK, envelope)
}

// putAutomationCredentials serves PUT
// /api/v1/settings/automation/credentials. Admin-only.
// Implements the J.4 preserve-on-edit secret semantics
// (empty Password preserves the stored value).
//
// On successful storage write, recreates the underlying
// automation.WatcherClient + atomically swaps the engine's
// writer pointer (P.2 commit-body checklist item #3 /
// option b). Sticky loginFailed state on the previous client
// is discarded with the old client.
//
// Validation of the new credentials hits LAPI's
// /v1/watchers/login once via the recreated client — if it
// fails 401/403, we leave the BoltDB row alone and return 400
// with the LAPI error so the operator's bad creds don't
// land. Network / 5xx errors are NOT rejected at PUT time
// (the LAPI might be transiently down; we trust the operator
// + persist the row).
func (h *Handler) putAutomationCredentials(w http.ResponseWriter, r *http.Request) {
	var req putCredentialsRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	ctx := r.Context()
	previous, prevErr := h.store.GetWatcherCredentials(ctx)
	if prevErr != nil && !errors.Is(prevErr, storage.ErrNotFound) {
		h.logger.Error("automation: load credentials (update)", "err", prevErr)
		writeError(w, http.StatusInternalServerError, "failed to load credentials")
		return
	}

	// Erasure path: PUT with all three fields blank → erase
	// the row + tell the Manager to ClearCredentials. Mirror
	// of the J.4 DNS provider erasure shape.
	if req.LAPIURL == "" && req.MachineID == "" && req.Password == "" {
		if errors.Is(prevErr, storage.ErrNotFound) {
			writeJSON(w, http.StatusOK, credentialsResponse{})
			return
		}
		if err := h.store.DeleteWatcherCredentials(ctx); err != nil {
			h.logger.Error("automation: delete credentials", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to delete credentials")
			return
		}
		if mgr := automation.GetManager(); mgr != nil {
			mgr.ClearCredentials()
		}
		h.appendAudit(r, audit.Event{
			Action:     audit.ActionAutomationRuleChanged,
			TargetType: "automation_credentials",
			BeforeJSON: mustMarshalForAudit(watcherCredsForAudit(previous)),
			// AfterJSON nil — row erased.
		})
		writeJSON(w, http.StatusOK, credentialsResponse{})
		return
	}

	// Preserve-on-edit merge. Empty Password keeps the
	// previous value (a fresh install with an empty
	// previous Password is rejected by validate; the
	// operator must supply a password on first PUT).
	merged := storage.WatcherCredentials{
		LAPIURL:   req.LAPIURL,
		MachineID: req.MachineID,
		Password:  req.Password,
	}
	if merged.Password == "" {
		merged.Password = previous.Password
	}

	if err := h.store.PutWatcherCredentials(ctx, merged); err != nil {
		// storage.validate() rejects (missing field /
		// empty endpoint). Surface as 400.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Recreate-and-swap on the live Manager. Validates the
	// new creds shape (NewWatcherClient — same fields the
	// storage layer just accepted). DOES NOT yet hit LAPI
	// — the next intent's EnsureJWT does that. We accept
	// here that an operator who entered a wrong password
	// will see ErrLoginFailed surface in the metrics
	// + audit after the next event triggers, not at PUT
	// time.
	if mgr := automation.GetManager(); mgr != nil {
		if err := mgr.SetCredentials(automation.WatcherConfig{
			LAPIURL:   merged.LAPIURL,
			MachineID: merged.MachineID,
			Password:  merged.Password,
		}); err != nil {
			// Storage write succeeded but the Manager
			// rejected the shape — programming error
			// (storage + Manager validators should agree).
			h.logger.Error("automation: manager rejected after storage accepted",
				"err", err)
			writeError(w, http.StatusInternalServerError, "failed to wire credentials")
			return
		}
	}

	auditEvt := audit.Event{
		Action:     audit.ActionAutomationRuleChanged,
		TargetType: "automation_credentials",
		AfterJSON:  mustMarshalForAudit(watcherCredsForAudit(merged)),
	}
	if !errors.Is(prevErr, storage.ErrNotFound) {
		auditEvt.BeforeJSON = mustMarshalForAudit(watcherCredsForAudit(previous))
	}
	h.appendAudit(r, auditEvt)

	writeJSON(w, http.StatusOK, credentialsResponse{
		LAPIURL:    merged.LAPIURL,
		MachineID:  merged.MachineID,
		Configured: storage.WatcherCredentialsConfigured(merged),
	})
}

// deleteAutomationCredentials serves DELETE
// /api/v1/settings/automation/credentials — Step CS.3
// follow-up.
//
// Wipes the persisted Security Automation watcher row AND
// tells the in-memory automation.Manager to ClearCredentials
// so the auto-classify pipeline drops out of LAPI write
// immediately. Trigger rules are NOT touched — the operator
// may want to keep them for a later re-enable; mirrors the
// CS.2.C `crowdsec_reset` shape that explicitly preserves
// orthogonal config (Security Automation watcher creds
// during a CrowdSec bouncer reset, here trigger rules
// during a watcher reset).
//
// Idempotent: a fresh-install DELETE (no row to wipe) still
// runs the manager.ClearCredentials() so any straggler
// in-memory state clears cleanly. Returns 200 with the
// "not configured" response shape so the UI's badge flips
// without needing a separate GET round-trip.
//
// Audit: emits ActionAutomationReset (distinct from
// automation_rule_changed). BeforeJSON carries the wiped
// row (Password scrubbed). AfterJSON omitted (the row no
// longer exists). Skipped on fresh-install DELETE — a no-op
// shouldn't add audit noise. Same convention as
// deleteCrowdSecSettings.
//
// Unlike the CrowdSec reset, there's no rollback path here:
// the automation.Manager swap is in-process state, not a
// hot-reloadable Caddy config. If a future architecture
// makes ClearCredentials fallible, rollback semantics will
// need revisiting; today the call is infallible (idempotent
// pointer swap to nil).
func (h *Handler) deleteAutomationCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	previous, prevErr := h.store.GetWatcherCredentials(ctx)
	if prevErr != nil && !errors.Is(prevErr, storage.ErrNotFound) {
		h.logger.Error("automation: load credentials (reset)", "err", prevErr)
		writeError(w, http.StatusInternalServerError, "failed to load credentials")
		return
	}

	if !errors.Is(prevErr, storage.ErrNotFound) {
		if err := h.store.DeleteWatcherCredentials(ctx); err != nil {
			h.logger.Error("automation: delete credentials", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to delete credentials")
			return
		}
	}

	// Clear the in-memory writer regardless of storage state
	// so any straggler manager binding is dropped.
	if mgr := automation.GetManager(); mgr != nil {
		mgr.ClearCredentials()
	}

	// Audit AFTER storage + manager state are aligned.
	// Skip on fresh-install — no row existed, nothing to log.
	if !errors.Is(prevErr, storage.ErrNotFound) {
		h.appendAudit(r, audit.Event{
			Action:     audit.ActionAutomationReset,
			TargetType: "automation_credentials",
			TargetID:   "default",
			BeforeJSON: mustMarshalForAudit(watcherCredsForAudit(previous)),
			// AfterJSON intentionally nil — the row no longer
			// exists; the audit diff carries "was X, now gone".
		})
	}

	writeJSON(w, http.StatusOK, credentialsResponse{})
}

// watcherCredsForAudit returns a copy of c with the Password
// blanked. Mirrors dnsProviderForAudit (J.4). Apply to every
// storage.WatcherCredentials passed into mustMarshalForAudit's
// BeforeJSON / AfterJSON.
func watcherCredsForAudit(c storage.WatcherCredentials) storage.WatcherCredentials {
	c.Password = ""
	return c
}
