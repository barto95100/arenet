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
	"sort"
	"strings"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/go-chi/chi/v5"
)

// v2.11 — the pre-v2.11 singleton OVH DNS provider (GET/PUT
// /settings/dns-providers/ovh) became a UUID-keyed collection. This
// file serves the standard 5-verb collection API mirroring
// managed-domains. Secrets (ApplicationKey / ApplicationSecret /
// ConsumerKey) are NEVER serialized in any response or audit row.

// dnsProviderView is the wire shape returned by every read/write on the
// collection. The three OVH secret fields are DELIBERATELY absent from
// this struct — they can never leak over HTTP. `configured` is the
// single boolean the UI binds to (true when all three stored secrets
// are non-empty); `usedBy` lists the apexes of the managed domains that
// reference this provider (for the delete-in-use guard + UI badge).
type dnsProviderView struct {
	ID         string   `json:"id"`
	Label      string   `json:"label"`
	Type       string   `json:"type"`
	Endpoint   string   `json:"endpoint"`
	Configured bool     `json:"configured"`
	UsedBy     []string `json:"usedBy"`
}

// dnsProviderRequest is the wire shape accepted by POST and PUT. Empty
// secret fields on PUT trigger the storage preserve-on-edit path (the
// stored value is kept); non-empty secrets overwrite.
type dnsProviderRequest struct {
	Label             string `json:"label"`
	Type              string `json:"type"`
	Endpoint          string `json:"endpoint"`
	ApplicationKey    string `json:"applicationKey"`
	ApplicationSecret string `json:"applicationSecret"`
	ConsumerKey       string `json:"consumerKey"`
}

// dnsProviderComplete reports whether all four credential-bearing
// fields of an OVH DNS provider config are non-empty. Used by the
// route edit-time DNS-01 guard (createRoute / updateRoute) AND by the
// view's `configured` flag.
func dnsProviderComplete(c storage.DNSProviderConfig) bool {
	return c.Endpoint != "" &&
		c.ApplicationKey != "" &&
		c.ApplicationSecret != "" &&
		c.ConsumerKey != ""
}

// anyDNSProviderConfigured reports whether at least one fully-configured
// DNS provider exists. The route DNS-01 guard uses this: a dns-01 route
// is only accepted while a usable provider is present (which one is
// resolved at reload time by caddymgr, Task 1d).
func (h *Handler) anyDNSProviderConfigured(ctx context.Context) (bool, error) {
	list, err := h.store.ListDNSProviders(ctx)
	if err != nil {
		return false, err
	}
	for _, c := range list {
		if dnsProviderComplete(c) {
			return true, nil
		}
	}
	return false, nil
}

// dnsProviderForAudit returns a copy of c with the three secret fields
// blanked. Applied to every storage.DNSProviderConfig passed into an
// audit event's BeforeJSON / AfterJSON — the audit log holds the
// endpoint + label, never the secret payload.
func dnsProviderForAudit(c storage.DNSProviderConfig) storage.DNSProviderConfig {
	c.ApplicationKey = ""
	c.ApplicationSecret = ""
	c.ConsumerKey = ""
	return c
}

// toDNSProviderView maps a stored config + its usedBy apexes to the
// secret-free wire shape.
func toDNSProviderView(c storage.DNSProviderConfig, usedBy []string) dnsProviderView {
	if usedBy == nil {
		usedBy = []string{}
	}
	return dnsProviderView{
		ID:         c.ID,
		Label:      c.Label,
		Type:       c.Type,
		Endpoint:   c.Endpoint,
		Configured: dnsProviderComplete(c),
		UsedBy:     usedBy,
	}
}

// usedByIndex builds providerID -> [apex...] from the managed domains,
// so the list/get views and the delete-in-use guard share one source
// of truth for "which wildcards reference this provider".
func (h *Handler) usedByIndex(ctx context.Context) (map[string][]string, error) {
	mds, err := h.store.ListManagedDomains(ctx)
	if err != nil {
		return nil, err
	}
	idx := map[string][]string{}
	for _, md := range mds {
		if md.ProviderID != "" {
			idx[md.ProviderID] = append(idx[md.ProviderID], md.Apex)
		}
	}
	return idx, nil
}

// listDNSProviders serves GET /api/v1/settings/dns-providers. Returns
// the collection sorted by Label, each entry secret-free with its
// usedBy[] and configured flag. Empty list on a fresh install.
func (h *Handler) listDNSProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := h.store.ListDNSProviders(ctx)
	if err != nil {
		h.logger.Error("list dns providers", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list dns providers")
		return
	}
	idx, err := h.usedByIndex(ctx)
	if err != nil {
		h.logger.Error("list managed domains (usedBy)", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load managed domains")
		return
	}
	out := make([]dnsProviderView, 0, len(list))
	for _, c := range list {
		out = append(out, toDNSProviderView(c, idx[c.ID]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	writeJSON(w, http.StatusOK, out)
}

// getDNSProvider serves GET /api/v1/settings/dns-providers/{id}.
// 404 with code "provider_not_found" when the id is unknown.
func (h *Handler) getDNSProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	c, err := h.store.GetDNSProvider(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		writeErrorCode(w, http.StatusNotFound, "provider_not_found",
			"dns provider not found", map[string]any{"id": id})
		return
	}
	if err != nil {
		h.logger.Error("get dns provider", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get dns provider")
		return
	}
	idx, err := h.usedByIndex(r.Context())
	if err != nil {
		h.logger.Error("list managed domains (usedBy)", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load managed domains")
		return
	}
	writeJSON(w, http.StatusOK, toDNSProviderView(c, idx[c.ID]))
}

// createDNSProvider serves POST /api/v1/settings/dns-providers.
// 201 with the secret-free view on success; 400 with a structured
// validation code on a bad body. Emits dns_provider_created (no
// secrets in the audit row).
func (h *Handler) createDNSProvider(w http.ResponseWriter, r *http.Request) {
	var req dnsProviderRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	cfg := storage.DNSProviderConfig{
		Label:             strings.TrimSpace(req.Label),
		Type:              req.Type,
		Endpoint:          req.Endpoint,
		ApplicationKey:    req.ApplicationKey,
		ApplicationSecret: req.ApplicationSecret,
		ConsumerKey:       req.ConsumerKey,
	}
	created, err := h.store.CreateDNSProvider(r.Context(), cfg)
	if err != nil {
		writeDNSProviderValidationError(w, err)
		return
	}
	// Fix #1 (v2.12.2): reload so a newly-configured provider becomes
	// usable by dns-01 routes in the live config immediately.
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after dns provider create", "err", err)
		writeError(w, http.StatusInternalServerError, "provider created but caddy reload failed")
		return
	}
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionDNSProviderCreated,
		TargetType: "dns_provider",
		TargetID:   created.ID,
		AfterJSON:  mustMarshalForAudit(dnsProviderForAudit(created)),
	})
	writeJSON(w, http.StatusCreated, toDNSProviderView(created, nil))
}

// updateDNSProvider serves PUT /api/v1/settings/dns-providers/{id}.
// Preserve-on-edit: blank secret fields keep the stored value. 404
// with code "provider_not_found" for an unknown id; 400 for a bad
// body/validation. Emits dns_provider_updated (no secrets).
func (h *Handler) updateDNSProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req dnsProviderRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	previous, prevErr := h.store.GetDNSProvider(r.Context(), id)
	if errors.Is(prevErr, storage.ErrNotFound) {
		writeErrorCode(w, http.StatusNotFound, "provider_not_found",
			"dns provider not found", map[string]any{"id": id})
		return
	}
	if prevErr != nil {
		h.logger.Error("get dns provider (update)", "err", prevErr)
		writeError(w, http.StatusInternalServerError, "failed to load dns provider")
		return
	}
	cfg := storage.DNSProviderConfig{
		Label:             strings.TrimSpace(req.Label),
		Type:              req.Type,
		Endpoint:          req.Endpoint,
		ApplicationKey:    req.ApplicationKey,
		ApplicationSecret: req.ApplicationSecret,
		ConsumerKey:       req.ConsumerKey,
	}
	updated, err := h.store.UpdateDNSProvider(r.Context(), id, cfg)
	if errors.Is(err, storage.ErrNotFound) {
		writeErrorCode(w, http.StatusNotFound, "provider_not_found",
			"dns provider not found", map[string]any{"id": id})
		return
	}
	if err != nil {
		writeDNSProviderValidationError(w, err)
		return
	}
	// Fix #1 (v2.12.2): reload so credential/endpoint edits take effect
	// in the live config (otherwise Caddy keeps the old provider until
	// an unrelated reload — the operator's fix is silently ignored).
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after dns provider update", "err", err)
		writeError(w, http.StatusInternalServerError, "provider updated but caddy reload failed")
		return
	}
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionDNSProviderUpdated,
		TargetType: "dns_provider",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(dnsProviderForAudit(previous)),
		AfterJSON:  mustMarshalForAudit(dnsProviderForAudit(updated)),
	})
	writeJSON(w, http.StatusOK, toDNSProviderView(updated, nil))
}

// deleteDNSProvider serves DELETE /api/v1/settings/dns-providers/{id}.
// 204 on success; 409 with code "provider_in_use" (+ params.wildcards)
// when a managed domain still references it; 404 with code
// "provider_not_found" for an unknown id. Emits dns_provider_deleted.
func (h *Handler) deleteDNSProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Read the row up front so the audit event carries the deleted
	// endpoint/label (secret-scrubbed). ErrNotFound here → 404.
	previous, prevErr := h.store.GetDNSProvider(r.Context(), id)
	if errors.Is(prevErr, storage.ErrNotFound) {
		writeErrorCode(w, http.StatusNotFound, "provider_not_found",
			"dns provider not found", map[string]any{"id": id})
		return
	}
	if prevErr != nil {
		h.logger.Error("get dns provider (delete)", "err", prevErr)
		writeError(w, http.StatusInternalServerError, "failed to load dns provider")
		return
	}

	// Fix #3 (v2.12.2): block the delete when it would leave per-route
	// dns-01 routes with NO configured provider remaining. Per-route
	// DNS-01 has no per-route providerId (it uses the single default
	// provider from the collection), so ANY dns-01 route depends on
	// there being at least one configured provider. If removing THIS
	// provider drops the configured count to zero while dns-01 routes
	// exist, deleting would silently orphan them (Bug #1). Deleting a
	// spare while another configured provider remains is safe — the
	// default just shifts. Mirrors the managed-domain 409 posture.
	orphaned, orphErr := h.dns01RoutesOrphanedByProviderDelete(r.Context(), id)
	if orphErr != nil {
		h.logger.Error("check dns-01 route dependency (provider delete)", "err", orphErr)
		writeError(w, http.StatusInternalServerError, "failed to verify route dependencies")
		return
	}
	if len(orphaned) > 0 {
		writeErrorCode(w, http.StatusConflict, "provider_in_use_by_routes",
			"dns provider is the last one configured and is used by dns-01 routes: "+strings.Join(orphaned, ", "),
			map[string]any{"routes": orphaned})
		return
	}

	err := h.store.DeleteDNSProvider(r.Context(), id)
	switch {
	case errors.Is(err, storage.ErrProviderInUse):
		idx, ixErr := h.usedByIndex(r.Context())
		if ixErr != nil {
			h.logger.Error("list managed domains (in-use)", "err", ixErr)
			writeError(w, http.StatusInternalServerError, "failed to load managed domains")
			return
		}
		wildcards := idx[id]
		if wildcards == nil {
			wildcards = []string{}
		}
		// Structured error: the frontend (Plan 2) translates via
		// t('errors.provider_in_use', { wildcards }) — the message here
		// is an EN fallback only. code + params keep it i18n-able.
		writeErrorCode(w, http.StatusConflict, "provider_in_use",
			"dns provider is in use by: "+strings.Join(wildcards, ", "),
			map[string]any{"wildcards": wildcards})
		return
	case errors.Is(err, storage.ErrNotFound):
		writeErrorCode(w, http.StatusNotFound, "provider_not_found",
			"dns provider not found", map[string]any{"id": id})
		return
	case err != nil:
		h.logger.Error("delete dns provider", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete dns provider")
		return
	}

	// Fix #1 (v2.12.2): reload Caddy so the removed provider leaves the
	// live config. Without this the running config keeps referencing the
	// deleted provider until some other event reloads — at which point
	// dns-01 hosts silently fall through to the internal CA. Mirrors
	// forward_auth_provider.go. Storage is already mutated; a reload
	// error is logged + surfaced (no rollback — consistency with the
	// other settings handlers).
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after dns provider delete", "err", err)
		writeError(w, http.StatusInternalServerError, "provider deleted but caddy reload failed")
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionDNSProviderDeleted,
		TargetType: "dns_provider",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(dnsProviderForAudit(previous)),
	})
	w.WriteHeader(http.StatusNoContent)
}

// dns01RoutesOrphanedByProviderDelete returns the hosts of per-route
// dns-01 routes that would be left with no configured DNS provider if
// the provider `deleteID` were removed. Empty result → the delete is
// safe (either no dns-01 routes, or another configured provider would
// remain). Used by deleteDNSProvider to emit a 409 instead of silently
// orphaning dns-01 routes (Fix #3, v2.12.2).
func (h *Handler) dns01RoutesOrphanedByProviderDelete(ctx context.Context, deleteID string) ([]string, error) {
	providers, err := h.store.ListDNSProviders(ctx)
	if err != nil {
		return nil, err
	}
	// Would any configured provider survive the delete?
	survivingConfigured := false
	for _, p := range providers {
		if p.ID != deleteID && dnsProviderComplete(p) {
			survivingConfigured = true
			break
		}
	}
	if survivingConfigured {
		return nil, nil // the default just shifts; safe
	}
	// No configured provider would remain — collect dependent dns-01 routes.
	routes, err := h.store.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	var hosts []string
	for _, rt := range routes {
		if rt.ACMEChallenge == storage.ACMEChallengeDNS01 {
			hosts = append(hosts, rt.Host)
		}
	}
	return hosts, nil
}

// writeDNSProviderValidationError maps a storage.validate() error to a
// structured 400. storage.validate returns generic errors, so we detect
// the failing field cheaply by substring and pick the most specific
// code; the always-present EN `error` string is the fallback. The
// baseline code is "invalid_dns_provider" with a {reason} param.
func writeDNSProviderValidationError(w http.ResponseWriter, err error) {
	msg := err.Error()
	code := "invalid_dns_provider"
	switch {
	case strings.Contains(msg, "label"):
		code = "invalid_label"
	case strings.Contains(msg, "type"):
		code = "invalid_type"
	case strings.Contains(msg, "endpoint"):
		code = "invalid_endpoint"
	}
	writeErrorCode(w, http.StatusBadRequest, code, msg, map[string]any{"reason": msg})
}
