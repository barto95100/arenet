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
	"strconv"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/go-chi/chi/v5"
)

// Step O.3 — managed-domain CRUD endpoints + the route response's
// `effectiveCertSource` derived field.

// managedDomainRequest is the wire shape for POST
// /api/v1/settings/managed-domains. The Apex is normalised
// server-side (NormalizeApex: lowercase + trailing-dot stripped)
// before validation + persistence, so operator-supplied uppercase
// / trailing-dot variants land canonical. IncludeApex defaults to
// true at this layer per spec D2.C (most homelab operators have a
// landing page on the bare apex). Provider defaults to "ovh"
// since v1.2 has only the OVH provider value space (spec D3.B
// forward-compat enum); an explicit unknown value is rejected
// downstream.
type managedDomainRequest struct {
	Apex        string `json:"apex"`
	IncludeApex *bool  `json:"includeApex,omitempty"`
	Provider    string `json:"provider"`
}

// managedDomainResponse is the wire shape returned by GET / POST.
// Mirrors the storage struct verbatim; no secret fields (the OVH
// credentials live in DNSProviderConfig and are GET'd separately).
type managedDomainResponse struct {
	Apex        string `json:"apex"`
	IncludeApex bool   `json:"includeApex"`
	Provider    string `json:"provider"`
}

// listManagedDomainsResponse is the GET list wire shape: an object
// with a `domains` array. Wrapping in an object (vs returning a
// bare array) leaves room for future top-level fields (e.g. a
// `disabled` flag for AC #13 carry-forward, or pagination
// metadata) without breaking the wire contract.
type listManagedDomainsResponse struct {
	Domains []managedDomainResponse `json:"domains"`
}

// deleteManagedDomainResponse is returned by DELETE. The
// `mutatedRoutes` count lets the frontend display "N routes
// reverted to <revertTo>" in the post-action toast, and is
// the same number written to the audit event.
type deleteManagedDomainResponse struct {
	MutatedRoutes int `json:"mutatedRoutes"`
}

// toManagedDomainResponse maps storage → wire shape. Pure
// function; no normalisation.
func toManagedDomainResponse(md storage.ManagedDomain) managedDomainResponse {
	return managedDomainResponse{
		Apex:        md.Apex,
		IncludeApex: md.IncludeApex,
		Provider:    md.Provider,
	}
}

// listManagedDomains serves GET /api/v1/settings/managed-domains.
// Viewer-accessible per AC #20 (same posture as the DNS-provider
// GET). Empty list on a fresh install — never 404.
//
// AC #13 carry-forward: a storage read failure produces a 500
// rather than disabled=true here, mirroring listForwardAuthProviders
// behaviour. Boot-failed storage is the same as "no Arenet at
// all" — the operator never reaches this endpoint.
func (h *Handler) listManagedDomains(w http.ResponseWriter, r *http.Request) {
	mds, err := h.store.ListManagedDomains(r.Context())
	if err != nil {
		h.logger.Error("list managed domains", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list managed domains")
		return
	}
	out := make([]managedDomainResponse, 0, len(mds))
	for _, md := range mds {
		out = append(out, toManagedDomainResponse(md))
	}
	writeJSON(w, http.StatusOK, listManagedDomainsResponse{Domains: out})
}

// createManagedDomain serves POST /api/v1/settings/managed-domains.
// Admin-only (mounted under the RequireAdminMiddleware group).
//
// Validation + cross-rules:
//   - Apex is NormalizeApex'd (lowercase, trailing dot stripped),
//     then validated by storage.validate (RFC 1123 grammar,
//     no leading "*.", canonical form).
//   - Provider defaults to "ovh"; explicit unknown rejected.
//   - Overlap detection: reject 409 if any existing managed
//     domain's apex equals the new apex (uniqueness) OR if any
//     existing apex is itself covered by the new wildcard
//     (e.g. existing "app.example.com" when adding "example.com"
//     with IncludeApex=true) OR the inverse (new apex covered
//     by an existing wildcard). The §5 risks "multi-domain
//     overlap" row pins this.
//
// Once validation passes, the actual persistence + the route-
// migration (ACMEChallenge → "inherited" for newly-covered
// routes per spec D8.A) happen atomically inside
// store.PutManagedDomainWithRouteMigration. The coverage
// predicate is bound to the new managed domain and passed as
// a closure to keep storage independent of caddymgr.
//
// After the store write, ReloadFromStore picks up the new
// wildcard TLS policy. Reload failure → rollback (Delete the
// just-created managed domain) → 500. Same rollback pattern
// as routes / DNS-provider mutations.
func (h *Handler) createManagedDomain(w http.ResponseWriter, r *http.Request) {
	var req managedDomainRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	apex := storage.NormalizeApex(req.Apex)
	includeApex := true // D2.C default
	if req.IncludeApex != nil {
		includeApex = *req.IncludeApex
	}
	provider := req.Provider
	if provider == "" {
		provider = storage.ManagedDomainProviderOVH // D3.B default
	}

	md := storage.ManagedDomain{
		Apex:        apex,
		IncludeApex: includeApex,
		Provider:    provider,
	}

	// Overlap detection (§5 risks "multi-domain overlap").
	existing, err := h.store.ListManagedDomains(r.Context())
	if err != nil {
		h.logger.Error("list managed domains (overlap check)", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load managed domains")
		return
	}
	for _, e := range existing {
		if e.Apex == apex {
			writeError(w, http.StatusConflict, "managed domain "+apex+" already exists")
			return
		}
		// Does the new apex's wildcard cover the existing apex?
		// e.g. new "example.com" covers existing "app.example.com".
		// Reuse the predicate so the rule stays defined in ONE
		// place (caddymgr.IsHostCoveredByManagedDomain).
		if _, covered := caddymgr.IsHostCoveredByManagedDomain(e.Apex, []storage.ManagedDomain{md}); covered {
			writeError(w, http.StatusConflict, "managed domain "+apex+" would cover existing managed domain "+e.Apex)
			return
		}
		// Does the existing apex's wildcard cover the new apex?
		// Inverse direction — the operator can't add a sub-apex
		// when a covering wildcard already exists.
		if _, covered := caddymgr.IsHostCoveredByManagedDomain(apex, []storage.ManagedDomain{e}); covered {
			writeError(w, http.StatusConflict, "managed domain "+apex+" is already covered by existing managed domain "+e.Apex)
			return
		}
	}

	// Coverage predicate closure for the migration helper. Bound
	// to the new md so the storage layer doesn't need to import
	// caddymgr (preserves the spec §3.7 dependency direction).
	isCovered := func(host string) bool {
		_, ok := caddymgr.IsHostCoveredByManagedDomain(host, []storage.ManagedDomain{md})
		return ok
	}

	mutated, err := h.store.PutManagedDomainWithRouteMigration(r.Context(), md, isCovered)
	if err != nil {
		// storage.validate runs inside; bubble shape errors as
		// 400 (apex grammar, unknown provider). Any other error
		// is an I/O failure → 500.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Reload Caddy so the wildcard TLS policy lands in the
	// running config. On failure, rollback: delete the just-
	// created managed domain AND revert the route mutations
	// via the symmetric helper. The closure handles both sides.
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after managed domain create — rolling back", "err", err)
		if _, rbErr := h.store.DeleteManagedDomainWithRouteMigration(r.Context(), md.Apex, isCovered); rbErr != nil {
			h.logger.Error("rollback managed domain create failed", "err", rbErr)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	// Emit audit AFTER reload succeeds. The MutatedRoutes count
	// is captured in the message field so an operator scanning
	// the audit log sees the cross-cutting impact at a glance.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionManagedDomainCreated,
		TargetType: "managed_domain",
		TargetID:   md.Apex,
		AfterJSON:  mustMarshalForAudit(md),
		Message:    formatRouteMutationMessage(mutated),
	})

	writeJSON(w, http.StatusCreated, toManagedDomainResponse(md))
}

// deleteManagedDomain serves DELETE
// /api/v1/settings/managed-domains/{apex}?revertTo={"","http-01","dns-01"}.
// Admin-only. AC #21: revertTo lets the operator explicitly choose
// the post-revert ACMEChallenge value for the affected covered
// routes (the spec §3.8 convention surfaced where the operator
// makes the decision).
//
// revertTo value space:
//   - ""        → routes revert to "" (J-era default → HTTP-01
//     on next reload). N HTTP-01 challenges fire.
//   - "http-01" → routes set to "http-01" explicitly. Same
//     effect as "" but the route detail surfaces a
//     deliberate choice rather than the project
//     default. N HTTP-01 challenges fire.
//   - "dns-01"  → routes set to "dns-01". Requires the DNS
//     provider to remain configured; if not, the
//     caddymgr fallback kicks in and the route
//     effectively serves internal-CA cert until the
//     operator configures DNS.
//
// Unknown revertTo → 400. Missing revertTo → "" (the safe
// default, matches the storage layer's reverse-migration default).
//
// Atomic via store.DeleteManagedDomainWithRouteMigration. After
// the storage write, ReloadFromStore picks up the new shape.
// Reload failure → rollback (re-create the managed domain) →
// 500. The rollback re-runs the create migration so covered
// routes' ACMEChallenge values are restored to "inherited".
func (h *Handler) deleteManagedDomain(w http.ResponseWriter, r *http.Request) {
	apex := storage.NormalizeApex(chi.URLParam(r, "apex"))
	if apex == "" {
		writeError(w, http.StatusBadRequest, "apex path parameter is required")
		return
	}

	revertTo := r.URL.Query().Get("revertTo")
	switch revertTo {
	case "", storage.ACMEChallengeHTTP01, storage.ACMEChallengeDNS01:
	default:
		writeError(w, http.StatusBadRequest, `revertTo must be "", "http-01", or "dns-01"`)
		return
	}

	// Read the current row up front so we can rollback on
	// reload failure. ErrNotFound here → 404 (operator tried
	// to delete a non-existent managed domain).
	previous, err := h.store.GetManagedDomain(r.Context(), apex)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "managed domain "+apex+" not found")
			return
		}
		h.logger.Error("get managed domain (delete)", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load managed domain")
		return
	}

	// Coverage closure for the migration. Bound to the row
	// being deleted — same shape as the create path.
	isCovered := func(host string) bool {
		_, ok := caddymgr.IsHostCoveredByManagedDomain(host, []storage.ManagedDomain{previous})
		return ok
	}

	mutated, err := h.store.DeleteManagedDomainWithRouteMigrationRevertTo(
		r.Context(), apex, isCovered, revertTo,
	)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "managed domain "+apex+" not found")
			return
		}
		h.logger.Error("delete managed domain", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete managed domain")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after managed domain delete — rolling back", "err", err)
		// Rollback: re-create the managed domain + re-flip
		// covered routes to "inherited" via the create-side
		// migration helper.
		if _, rbErr := h.store.PutManagedDomainWithRouteMigration(r.Context(), previous, isCovered); rbErr != nil {
			h.logger.Error("rollback managed domain delete failed", "err", rbErr)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionManagedDomainDeleted,
		TargetType: "managed_domain",
		TargetID:   apex,
		BeforeJSON: mustMarshalForAudit(previous),
		Message:    formatRouteRevertMessage(mutated, revertTo),
	})

	// Purge tracker entries for the deleted apex. certmagic /
	// Caddy v2.11.3 emit no cert-removal event (verified during
	// the post-T.5 smoke), so OBTAIN_FAILED ghost rows for
	// *.<apex> (+ <apex> when includeApex was true) would linger
	// in /certs until an Arenet restart. The purge runs AFTER
	// the audit append so the audit row is the canonical record
	// of the user-initiated delete and the purge is a downstream
	// state-cleanup effect. Nil-tolerant: when SetCertInfoReader
	// was never called (e.g. test envs that skip the wiring) the
	// purge silently no-ops and the rest of the handler is
	// unaffected.
	if h.certInfo != nil {
		domainsToPurge := []string{"*." + apex}
		if previous.IncludeApex {
			domainsToPurge = append(domainsToPurge, apex)
		}
		purged := 0
		for _, d := range domainsToPurge {
			if h.certInfo.Remove(d) {
				purged++
			}
		}
		h.logger.Info("purged tracker entries for deleted apex",
			"apex", apex,
			"candidates", len(domainsToPurge),
			"purged", purged,
		)
	}

	writeJSON(w, http.StatusOK, deleteManagedDomainResponse{MutatedRoutes: mutated})
}

// formatRouteMutationMessage builds the audit `message` payload
// for managed_domain_created so the audit log carries the
// cross-cutting effect inline (vs requiring an operator to
// correlate two events).
func formatRouteMutationMessage(mutated int) string {
	if mutated == 0 {
		return "no covered routes to migrate"
	}
	if mutated == 1 {
		return "1 covered route migrated to acme_challenge=inherited"
	}
	return strconv.Itoa(mutated) + " covered routes migrated to acme_challenge=inherited"
}

// formatRouteRevertMessage is the symmetric message for the
// delete path. Includes the operator-chosen revertTo value so
// the audit log carries the AC #21 decision inline.
func formatRouteRevertMessage(mutated int, revertTo string) string {
	target := revertTo
	if target == "" {
		target = `""` // disambiguates the default in the log line
	}
	if mutated == 0 {
		return "no covered routes to revert (revertTo=" + target + ")"
	}
	if mutated == 1 {
		return "1 covered route reverted to acme_challenge=" + target
	}
	return strconv.Itoa(mutated) + " covered routes reverted to acme_challenge=" + target
}
