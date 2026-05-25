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

// dnsProviderRequest is the wire shape accepted by PUT
// /api/v1/settings/dns-providers/ovh (Step J.4 §5.4). Empty secret
// fields trigger the preserve-on-edit path (the stored value is
// kept); non-empty secrets overwrite.
type dnsProviderRequest struct {
	Endpoint          string `json:"endpoint"`
	ApplicationKey    string `json:"applicationKey"`
	ApplicationSecret string `json:"applicationSecret"`
	ConsumerKey       string `json:"consumerKey"`
}

// dnsProviderResponse is the wire shape returned by GET
// /api/v1/settings/dns-providers/ovh. The three secret fields are
// ALWAYS emitted as empty strings — same redaction policy as Step
// I.5's BasicAuthPasswordHash. Configured carries the single
// boolean status flag the UI binds to (true when all four stored
// fields are non-empty); the operator can't tell which secret is
// missing, deliberately.
type dnsProviderResponse struct {
	Endpoint string `json:"endpoint"`
	// ApplicationKey, ApplicationSecret, ConsumerKey are always
	// emitted as empty strings — redacted server-side.
	ApplicationKey    string `json:"applicationKey"`
	ApplicationSecret string `json:"applicationSecret"`
	ConsumerKey       string `json:"consumerKey"`
	// Configured is true when all four stored fields are non-empty,
	// false otherwise. Single source of truth for the UI's
	// "configured" / "not configured" badge.
	Configured bool `json:"configured"`
}

// dnsProviderComplete reports whether all four fields of an OVH
// DNS provider config are non-empty. Used by the route edit-time
// guard (createRoute / updateRoute) AND by the GET response's
// `configured` flag.
func dnsProviderComplete(c storage.DNSProviderConfig) bool {
	return c.Endpoint != "" &&
		c.ApplicationKey != "" &&
		c.ApplicationSecret != "" &&
		c.ConsumerKey != ""
}

// dnsProviderForAudit returns a copy of c with the three secret
// fields blanked. Mirrors routeForAudit (Step I.5) for the
// BasicAuthPasswordHash redaction. Apply to every
// storage.DNSProviderConfig passed into mustMarshalForAudit's
// BeforeJSON / AfterJSON.
func dnsProviderForAudit(c storage.DNSProviderConfig) storage.DNSProviderConfig {
	c.ApplicationKey = ""
	c.ApplicationSecret = ""
	c.ConsumerKey = ""
	return c
}

// getDNSProviderOVH serves GET
// /api/v1/settings/dns-providers/ovh. Always 200 on a successful
// read (including a fresh-install no-row case, which surfaces as
// `configured: false` with empty fields) — the lifecycle decision
// in §5.4 is "no delete, no 404 for absent config; the operator
// PUTs to create".
func (h *Handler) getDNSProviderOVH(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetDNSProviderOVH(r.Context())
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		h.logger.Error("get dns provider", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get dns provider")
		return
	}
	resp := dnsProviderResponse{
		Endpoint:          cfg.Endpoint,
		ApplicationKey:    "",
		ApplicationSecret: "",
		ConsumerKey:       "",
		Configured:        dnsProviderComplete(cfg),
	}
	writeJSON(w, http.StatusOK, resp)
}

// putDNSProviderOVH serves PUT
// /api/v1/settings/dns-providers/ovh. Implements the preserve-on-
// edit secret semantics (§5.4):
//   - Endpoint: round-trips normally; an empty endpoint on PUT is
//     a config error (rejected by the validator).
//   - ApplicationKey / ApplicationSecret / ConsumerKey: empty on
//     PUT preserves the previously stored value; non-empty
//     overwrites. The merged DNSProviderConfig is then handed to
//     storage.PutDNSProviderOVH which runs the strict last-line-
//     of-defence validate() (all four fields non-empty + endpoint
//     in the OVH enum).
//
// Audit: emits dns_provider_updated AFTER the storage write
// succeeds. Both BeforeJSON and AfterJSON are scrubbed of the
// three secret fields via dnsProviderForAudit — the audit log
// holds the endpoint + the fact a change happened, never the
// secret payload.
func (h *Handler) putDNSProviderOVH(w http.ResponseWriter, r *http.Request) {
	var req dnsProviderRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	previous, prevErr := h.store.GetDNSProviderOVH(r.Context())
	if prevErr != nil && !errors.Is(prevErr, storage.ErrNotFound) {
		h.logger.Error("get dns provider (update)", "err", prevErr)
		writeError(w, http.StatusInternalServerError, "failed to load dns provider")
		return
	}

	// Step J.4 erasure path: PUT with ALL FOUR fields blank means
	// "de-configure the provider". Without this branch the
	// preserve-on-edit merge below would carry the previous
	// secrets forward and the operator would have no way to
	// remove the OVH credentials from storage (the design intent
	// stated explicitly in the recon: delete = PUT all blank).
	// The cross-rule check above (no dns-01 route may exist
	// when erasing) defers to the Caddy reload below: an
	// erasure that leaves dns-01 routes orphaned fails caddy.Load
	// → the operator gets the 500 + the storage rollback restores
	// the previous credentials. Same single-rollback pattern as
	// /routes mutations.
	if req.Endpoint == "" &&
		req.ApplicationKey == "" &&
		req.ApplicationSecret == "" &&
		req.ConsumerKey == "" {
		if errors.Is(prevErr, storage.ErrNotFound) {
			// Nothing to erase — return the same "not configured"
			// response shape callers see on a fresh install.
			writeJSON(w, http.StatusOK, dnsProviderResponse{})
			return
		}
		if err := h.store.DeleteDNSProviderOVH(r.Context()); err != nil {
			h.logger.Error("delete dns provider", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to delete dns provider")
			return
		}
		if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
			h.logger.Error("caddy reload after dns provider erase — rolling back", "err", err)
			if rbErr := h.store.PutDNSProviderOVH(r.Context(), previous); rbErr != nil {
				h.logger.Error("rollback dns provider failed", "err", rbErr)
			}
			writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
			return
		}
		h.appendAudit(r, audit.Event{
			Action:     audit.ActionDNSProviderUpdated,
			TargetType: "dns_provider",
			TargetID:   "ovh",
			BeforeJSON: mustMarshalForAudit(dnsProviderForAudit(previous)),
			// AfterJSON intentionally nil — the row no longer
			// exists; the audit diff carries "was X, now gone".
		})
		writeJSON(w, http.StatusOK, dnsProviderResponse{})
		return
	}

	// Preserve-on-edit merge. Empty secret fields keep the previous
	// value; non-empty overwrite. Endpoint always takes the
	// supplied value — empty endpoint when not in the erasure
	// path is rejected by validate (a config error per §5.4).
	merged := storage.DNSProviderConfig{
		Endpoint:          req.Endpoint,
		ApplicationKey:    req.ApplicationKey,
		ApplicationSecret: req.ApplicationSecret,
		ConsumerKey:       req.ConsumerKey,
	}
	if merged.ApplicationKey == "" {
		merged.ApplicationKey = previous.ApplicationKey
	}
	if merged.ApplicationSecret == "" {
		merged.ApplicationSecret = previous.ApplicationSecret
	}
	if merged.ConsumerKey == "" {
		merged.ConsumerKey = previous.ConsumerKey
	}

	if err := h.store.PutDNSProviderOVH(r.Context(), merged); err != nil {
		// storage.validate() rejects with a user-friendly message
		// (endpoint enum, any secret blank). Bubble through as 400.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Reload Caddy so any existing dns-01 route picks up the new
	// credentials at the next renewal. Same rollback pattern as
	// /routes mutations: on failure, restore the previous row.
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after dns provider update — rolling back", "err", err)
		if errors.Is(prevErr, storage.ErrNotFound) {
			// No previous row to restore — leave the new write in
			// place. A fresh install whose first PUT fails the
			// reload would log here; the operator gets the 500
			// below and can re-PUT.
		} else {
			if rbErr := h.store.PutDNSProviderOVH(r.Context(), previous); rbErr != nil {
				h.logger.Error("rollback dns provider failed", "err", rbErr)
			}
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	// Emit dns_provider_updated AFTER the reload succeeds. Audit
	// payload is scrubbed of secrets — the endpoint and the
	// before/after `configured` flag are recoverable from the
	// blanked struct, the secrets are not.
	evt := audit.Event{
		Action:     audit.ActionDNSProviderUpdated,
		TargetType: "dns_provider",
		TargetID:   "ovh",
		AfterJSON:  mustMarshalForAudit(dnsProviderForAudit(merged)),
	}
	if !errors.Is(prevErr, storage.ErrNotFound) {
		evt.BeforeJSON = mustMarshalForAudit(dnsProviderForAudit(previous))
	}
	h.appendAudit(r, evt)

	// Response shape mirrors the GET — secrets redacted, configured
	// flag reflects the new state. The frontend receives the
	// truthful `configured: true` after a successful PUT and
	// updates its badge without a separate GET.
	resp := dnsProviderResponse{
		Endpoint:          merged.Endpoint,
		ApplicationKey:    "",
		ApplicationSecret: "",
		ConsumerKey:       "",
		Configured:        dnsProviderComplete(merged),
	}
	writeJSON(w, http.StatusOK, resp)
}
