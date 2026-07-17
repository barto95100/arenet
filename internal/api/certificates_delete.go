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

	var blocking []string
	for _, rt := range routes {
		if strings.EqualFold(rt.Host, domain) {
			blocking = append(blocking, rt.Host)
			continue
		}
		for _, a := range rt.Aliases {
			if strings.EqualFold(a, domain) {
				blocking = append(blocking, rt.Host)
				break
			}
		}
	}
	if _, covered := caddymgr.IsHostCoveredByManagedDomain(domain, mds); covered {
		blocking = append(blocking, domain)
	}
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
