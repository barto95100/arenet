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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/go-chi/chi/v5"
	"github.com/libdns/libdns"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.26 — POST /api/v1/settings/dns-providers/{id}/test.
//
// Validates a SAVED provider's credentials by listing the records of
// one zone through the provider's own Caddy module — the exact code
// path ACME DNS-01 uses, so a green test means Caddy can authenticate.
// Strictly read-only (libdns.RecordGetter): no record is created or
// changed. Always 200 with {ok, records, error} once the request is
// well-formed: this is a diagnostic probe, never a hard failure
// (same posture as the MaxMind / CrowdSec / OIDC tests).
//
// It exists because the maintainer can only live-test OVH: it lets
// every operator verify their own provider (spec 2026-09-21 §5).

// dnsProviderTestDeadline caps the whole probe (module provision +
// one listing call). Provider APIs answer sub-second; the margin
// covers a cold homelab DNS + TLS handshake and Route53's SDK
// credential chain.
const dnsProviderTestDeadline = 15 * time.Second

// dnsProviderTestRequest is the optional body of the test endpoint.
// An empty Zone defaults to the first managed domain using the
// provider.
type dnsProviderTestRequest struct {
	Zone string `json:"zone"`
}

// dnsProviderTestResponse is the wire shape of a completed probe.
type dnsProviderTestResponse struct {
	OK      bool   `json:"ok"`
	Zone    string `json:"zone"`
	Records int    `json:"records"`
	Error   string `json:"error,omitempty"`
}

// dnsProviderProbe instantiates the provider's dns.providers.<type>
// Caddy module from its stored credentials and lists the records of
// zone (FQDN, trailing dot). Returns the record count.
//
// Empirical basis (spec §Faits empiriques #4): after
// caddy.GetModule(...).New() + json.Unmarshal + Provision, all nine
// registry modules implement libdns.RecordGetter.
//
// Overridable in tests — NEVER hit a real provider API in unit tests.
var dnsProviderProbe = func(ctx context.Context, c storage.DNSProviderConfig, zone string) (int, error) {
	info, err := caddy.GetModule("dns.providers." + c.Type)
	if err != nil {
		return 0, fmt.Errorf("provider module unavailable: %w", err)
	}
	mod := info.New()
	raw, err := json.Marshal(c.Credentials)
	if err != nil {
		return 0, fmt.Errorf("encode credentials: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields() // same strictness as caddy.Load
	if err := dec.Decode(mod); err != nil {
		return 0, fmt.Errorf("decode provider config: %w", err)
	}
	cctx, cancel := caddy.NewContext(caddy.Context{Context: ctx})
	defer cancel()
	if p, ok := mod.(caddy.Provisioner); ok {
		if err := p.Provision(cctx); err != nil {
			return 0, fmt.Errorf("provision: %w", err)
		}
	}
	getter, ok := mod.(libdns.RecordGetter)
	if !ok {
		return 0, errors.New("provider module cannot list records")
	}
	recs, err := getter.GetRecords(ctx, zone)
	if err != nil {
		return 0, err
	}
	return len(recs), nil
}

// testDNSProvider is the chi handler for POST
// /api/v1/settings/dns-providers/{id}/test. Admin-only via the
// router-level RequireAdminMiddleware.
//
//   - 404 provider_not_found: unknown id.
//   - 400 provider_not_configured: a required credential is missing.
//   - 400 zone_required: no zone in the body and no managed domain
//     uses this provider.
//   - 400 invalid_zone: the zone is not a bare RFC 1123 domain.
//   - 200 {ok:false, error}: the provider rejected / could not be
//     reached; the error text is scrubbed of this provider's secrets.
func (h *Handler) testDNSProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req dnsProviderTestRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	prov, err := h.store.GetDNSProvider(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		writeErrorCode(w, http.StatusNotFound, "provider_not_found",
			"dns provider not found", map[string]any{"id": id})
		return
	}
	if err != nil {
		h.logger.Error("get dns provider (test)", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load dns provider")
		return
	}
	if !dnsProviderComplete(prov) {
		writeErrorCode(w, http.StatusBadRequest, "provider_not_configured",
			"dns provider is missing required credentials", map[string]any{"id": id})
		return
	}

	zone := storage.NormalizeApex(strings.TrimSpace(req.Zone))
	if zone == "" {
		idx, ixErr := h.usedByIndex(r.Context())
		if ixErr != nil {
			h.logger.Error("list managed domains (dns provider test)", "err", ixErr)
			writeError(w, http.StatusInternalServerError, "failed to load managed domains")
			return
		}
		if apexes := idx[id]; len(apexes) > 0 {
			zone = apexes[0]
		}
	}
	if zone == "" {
		writeErrorCode(w, http.StatusBadRequest, "zone_required",
			"no zone given and no managed domain uses this provider", nil)
		return
	}
	if err := storage.ValidateManagedDomain(storage.ManagedDomain{Apex: zone}); err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid_zone", err.Error(),
			map[string]any{"zone": zone})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dnsProviderTestDeadline)
	defer cancel()
	n, probeErr := dnsProviderProbe(ctx, prov, zone+".")

	h.logger.Info("dns provider test probed",
		"provider_id", id, "type", prov.Type, "zone", zone, "ok", probeErr == nil)

	if probeErr != nil {
		writeJSON(w, http.StatusOK, dnsProviderTestResponse{
			OK:    false,
			Zone:  zone,
			Error: storage.RedactDNSSecrets(probeErr.Error(), prov),
		})
		return
	}
	writeJSON(w, http.StatusOK, dnsProviderTestResponse{OK: true, Zone: zone, Records: n})
}
