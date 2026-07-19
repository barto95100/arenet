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
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/certinfo"
	"github.com/barto95100/arenet/internal/storage"
)

// deleteCertificate handles DELETE /api/v1/certificates/{domain}. It
// removes an orphan certificate's on-disk material (across all
// issuers) and clears its /certs tracker entry. Orphans only: if any
// route (including disabled routes) or managed-domain coverage still
// references the domain, it responds 409 with the blocking hosts.
// Idempotent: a domain with no files on disk (a "ghost" tracker row)
// still returns 200 after purging the tracker. No ACME revocation is
// performed — this only removes local state.
func (h *Handler) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	rawDomain := chi.URLParam(r, "domain")
	// The frontend URL-encodes wildcard subjects ("*.example.com")
	// with url.PathEscape before issuing the request. Empirically
	// verified (TestDeleteCertificate_Wildcard_Routes, task-4-report.md):
	// net/http already decodes the escaped path into r.URL.Path
	// before chi's router matches it, so chi.URLParam returns "*.darro.ovh"
	// even without this call. Unescaping again here is a defensive
	// no-op for already-decoded input (PathUnescape is idempotent on
	// a string with no remaining %XX sequences) and guards against
	// any future routing layer that stops pre-decoding.
	domain, err := url.PathUnescape(rawDomain)
	if err != nil {
		domain = rawDomain
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}

	ctx := r.Context()

	// Orphan check (authoritative). Reference == route host/alias
	// equality (case-insensitive), INCLUDING disabled routes, OR
	// managed-domain coverage.
	routes, err := h.store.ListRoutes(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list routes: "+err.Error())
		return
	}
	mds, err := h.store.ListManagedDomains(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list managed domains: "+err.Error())
		return
	}
	// Known forward-auth provider names, so routeEmitsCertSubject can
	// detect the fail-closed deny path (a forward_auth route pointing at
	// an unknown provider emits its subject unconditionally).
	fwdAuthProviders, err := h.store.ListForwardAuthProviders(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list forward-auth providers: "+err.Error())
		return
	}
	knownFwdAuth := make(map[string]struct{}, len(fwdAuthProviders))
	for _, p := range fwdAuthProviders {
		knownFwdAuth[p.Name] = struct{}{}
	}

	var blocking []string
	for _, rt := range routes {
		// A route only "uses" (and re-issues) the cert for a host if it
		// actually EMITS that per-host cert subject. This must mirror the
		// emission condition in caddymgr (manager.go: a subject is emitted
		// only when r.TLSEnabled AND (r.UseDedicatedCert OR the host is not
		// covered by a managed-domain wildcard)). Blocking on host equality
		// alone wrongly held certs hostage to routes that don't serve them:
		//   - a route with TLS off emits no subject at all;
		//   - a TLS route covered by a *.apex wildcard (without opting into
		//     a dedicated cert) is served by the wildcard, so its leftover
		//     per-host cert is orphaned and must be deletable.
		if !routeEmitsCertSubject(rt, domain, mds, knownFwdAuth) {
			continue
		}
		blocking = append(blocking, rt.Host)
	}
	// NOTE: we deliberately do NOT block just because `domain` is a
	// sub-label covered by a wildcard (IsHostCoveredByManagedDomain).
	// The wildcard cert is a DIFFERENT disk entry (`*.<apex>`); a
	// leftover per-host cert for a now-wildcard-covered host is orphaned
	// (Caddy serves the wildcard at handshake and never re-issues the
	// per-host cert), so it must be deletable. Whether a route still
	// legitimately emits this per-host subject is decided by
	// routeEmitsCertSubject above (which accounts for UseDedicatedCert).
	// We still block deletion of the wildcard/apex SUBJECTS themselves,
	// below — those the managed domain does re-issue.
	//
	// IsHostCoveredByManagedDomain only handles sub-label coverage
	// (e.g. "sub.<apex>") — it bails on any "*."-prefixed host, so
	// it never catches the wildcard/apex subjects a managed domain
	// itself emits. A managed domain emits `*.<apex>` unconditionally
	// and `<apex>` when IncludeApex is set; deleting the cert for
	// either subject while the managed domain is live would just
	// make Caddy re-issue it (cert churn), so block those too.
	lowerDomain := strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, md := range mds {
		apex := strings.ToLower(md.Apex)
		if lowerDomain == "*."+apex {
			blocking = append(blocking, "*."+apex+" (managed domain)")
		} else if lowerDomain == apex && md.IncludeApex {
			blocking = append(blocking, apex+" (managed domain)")
		}
	}
	if len(blocking) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":          "certificate in use; delete or disable the referencing route(s) first",
			"blockingRoutes": blocking,
		})
		return
	}

	// Delete on-disk material across all issuers (idempotent: 0, nil
	// when nothing is present on disk for this domain).
	deleted := 0
	if h.certStorageDir != "" {
		n, derr := certinfo.DeleteCertFiles(h.certStorageDir, domain)
		if derr != nil {
			writeError(w, http.StatusInternalServerError, "delete cert files: "+derr.Error())
			return
		}
		deleted = n
	}

	// Purge the /certs tracker entry (ghost or real). Best-effort:
	// Remove is nil-tolerant on an absent entry.
	if h.certInfo != nil {
		h.certInfo.Remove(domain)
	}

	// Trigger the normal reload so Caddy's certmagic cache stays in
	// sync with the now-unreferenced domain. Best-effort: a reload
	// error is logged, not fatal to the delete (files are already
	// gone). Uses the same reload seam as toggleRouteDisabled.
	if rerr := h.caddy.ReloadFromStore(ctx); rerr != nil {
		h.logger.Error("cert delete: reload after delete failed", "domain", domain, "err", rerr)
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionCertDeleted,
		TargetType: "certificate",
		TargetID:   domain,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"domain":  domain,
		"deleted": deleted,
	})
}

// routeEmitsCertSubject reports whether the route would register a
// per-host ACME cert subject for `domain` (its Host or an alias). It is
// the delete-time mirror of caddymgr's emission gate (manager.go): a
// subject is emitted only when the route has TLS enabled AND either it
// opted into a dedicated cert OR the host is not already covered by a
// managed-domain wildcard. A route that does not emit the subject does
// not "use" the cert, so it must not block deletion. `mds` is the
// managed-domain list (passed in to avoid a per-route store read).
func routeEmitsCertSubject(rt storage.Route, domain string, mds []storage.ManagedDomain, knownFwdAuthProviders map[string]struct{}) bool {
	// TLS off → no subject emitted for any of its hosts.
	if !rt.TLSEnabled {
		return false
	}
	// Does this route reference the domain by Host or alias?
	matches := strings.EqualFold(rt.Host, domain)
	if !matches {
		for _, a := range rt.Aliases {
			if strings.EqualFold(a, domain) {
				matches = true
				break
			}
		}
	}
	if !matches {
		return false
	}
	// Forward-auth fail-closed deny path (manager.go: provider missing):
	// a forward_auth route referencing an UNKNOWN provider emits the deny
	// route AND registers its per-host subject UNCONDITIONALLY — there is
	// no managed-domain coverage skip on that path. Mirror it: such a
	// route always emits its subject, so it must block. (Reachable only
	// via a corrupted route state — the API enforces provider existence —
	// but the mirror must stay exact so an in-use cert never becomes
	// deletable.)
	if rt.AuthMode == storage.RouteAuthForwardAuth {
		if _, ok := knownFwdAuthProviders[rt.ForwardAuth.ProviderName]; !ok {
			return true
		}
	}
	// A dedicated-cert route always emits its own subject, even when
	// covered by a wildcard.
	if rt.UseDedicatedCert {
		return true
	}
	// Otherwise it emits its own subject only when NOT covered by a
	// managed-domain wildcard (a covered route is served by the wildcard
	// cert, leaving any prior per-host cert orphaned).
	_, covered := caddymgr.IsHostCoveredByManagedDomain(domain, mds)
	return !covered
}
