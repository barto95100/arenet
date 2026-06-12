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
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Phase 2 Users-page refactor — POST /api/v1/settings/oidc/test.
// Admin-only operator-triggered probe that fetches the IdP's OIDC
// discovery document ({issuer}/.well-known/openid-configuration)
// and compares the discovery-advertised scopes against the
// operator's saved scope list.
//
// Mirrors the routes/test-upstream pattern: 5s hard deadline,
// admin-gated via the router subgroup, redirects NOT followed
// (a 301 from the discovery URL is a real signal — usually a
// misconfigured issuer), result always returned as 200 with
// {reachable:false, error} on failure (so the frontend can
// render a coherent toast in either case).

const (
	// oidcTestDeadline caps the whole probe. 5s matches the
	// test-upstream budget and covers DNS + TLS + JSON parse
	// for the discovery doc on a cold-cache homelab WAN.
	oidcTestDeadline = 5 * time.Second

	// oidcTestMaxBodyBytes caps the discovery doc read. The
	// canonical doc is ~1-3 KB; 64 KB protects against a
	// runaway IdP without rejecting reasonable extensions.
	oidcTestMaxBodyBytes = 64 * 1024
)

// oidcTestResponse is the wire shape returned to the frontend
// toast. Reachable=false carries Error; Reachable=true carries
// the discovery summary + scope comparison.
type oidcTestResponse struct {
	Reachable bool `json:"reachable"`
	// Issuer is the issuer URL returned by the discovery doc.
	// May differ from the saved IssuerURL — a mismatch is a
	// real IdP-misconfiguration signal worth surfacing.
	Issuer string `json:"issuer,omitempty"`
	// SupportedScopes is the scopes_supported array from the
	// discovery doc, sorted for stable diff rendering.
	SupportedScopes []string `json:"supportedScopes,omitempty"`
	// ScopesMatch is true when every scope in the saved config
	// is present in SupportedScopes. False otherwise (including
	// when the IdP doesn't advertise scopes_supported at all,
	// which is technically spec-permitted but operationally
	// unusual).
	ScopesMatch bool `json:"scopesMatch"`
	// MissingScopes lists scopes the operator saved but the
	// IdP doesn't advertise — populated only when ScopesMatch
	// is false. Drives the actionable toast message.
	MissingScopes []string `json:"missingScopes,omitempty"`
	// LatencyMs is the wall-clock duration of the discovery
	// fetch (DNS + TCP + TLS + body read).
	LatencyMs int64 `json:"latencyMs"`
	// Error is operator-readable text when Reachable=false.
	// Examples: "connection refused", "context deadline
	// exceeded", "discovery doc not JSON", "oidc not
	// configured".
	Error string `json:"error,omitempty"`
}

// discoveryDoc is the minimal subset of the OIDC discovery
// document we parse. The full schema has dozens of fields; we
// only surface issuer + scopes_supported to keep the response
// focused on what the toast renders.
type discoveryDoc struct {
	Issuer          string   `json:"issuer"`
	ScopesSupported []string `json:"scopes_supported"`
}

// testOIDCConnection is the chi handler for POST /api/v1/settings
// /oidc/test. Admin-only via the router-level RequireAdminMiddleware.
//
// No request body: the probe targets the saved OIDC config in
// storage. This avoids the SSRF-amplifier risk of letting the
// admin paste an arbitrary issuer URL — only the already-saved
// (already-admin-validated) issuer can be probed.
func (h *Handler) testOIDCConnection(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetOIDCConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load oidc config: "+err.Error())
		return
	}

	issuer := strings.TrimSpace(cfg.IssuerURL)
	if issuer == "" {
		writeJSON(w, http.StatusOK, oidcTestResponse{
			Reachable: false,
			Error:     "oidc not configured",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), oidcTestDeadline)
	defer cancel()

	resp := probeOIDCDiscovery(ctx, issuer, cfg.Scopes)

	h.logger.Info("oidc test probed",
		"issuer", issuer,
		"reachable", resp.Reachable,
		"scopes_match", resp.ScopesMatch,
		"latency_ms", resp.LatencyMs)

	writeJSON(w, http.StatusOK, resp)
}

// probeOIDCDiscovery fetches {issuer}/.well-known/openid-configuration
// and computes the scope comparison. Split from the handler so
// tests can drive it directly without a router.
func probeOIDCDiscovery(ctx context.Context, issuerURL string, savedScopes []string) oidcTestResponse {
	resp := oidcTestResponse{}

	parsed, err := url.Parse(issuerURL)
	if err != nil || parsed.Host == "" {
		resp.Error = "issuer url is malformed"
		return resp
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		resp.Error = "issuer url must use http or https scheme"
		return resp
	}

	// Build discovery URL: strip trailing slash on issuer per
	// OIDC Discovery §4 (RFC 8414 likewise) — many IdPs canonicalise
	// to no-trailing-slash and serve the well-known at the
	// no-slash form.
	discoveryURL := strings.TrimRight(parsed.String(), "/") + "/.well-known/openid-configuration"

	client := &http.Client{
		Timeout: oidcTestDeadline,
		// Don't follow redirects — a 301 from the discovery URL
		// is a real misconfiguration signal (issuer URL drift,
		// HTTP→HTTPS upgrade the operator hasn't updated).
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		resp.Error = "build discovery request: " + err.Error()
		return resp
	}
	req.Header.Set("Accept", "application/json")

	start := time.Now()
	httpResp, err := client.Do(req)
	resp.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		// Trim "Get \"...\": " stdlib prefix for a clean
		// operator-readable message.
		resp.Error = unwrapHTTPError(err)
		return resp
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		resp.Error = "discovery returned HTTP " + http.StatusText(httpResp.StatusCode)
		return resp
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, oidcTestMaxBodyBytes))
	if err != nil {
		resp.Error = "read discovery body: " + err.Error()
		return resp
	}

	var doc discoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		resp.Error = "discovery doc not JSON: " + err.Error()
		return resp
	}

	resp.Reachable = true
	resp.Issuer = doc.Issuer

	supported := append([]string(nil), doc.ScopesSupported...)
	sort.Strings(supported)
	resp.SupportedScopes = supported

	missing := scopesDiff(savedScopes, doc.ScopesSupported)
	resp.ScopesMatch = len(missing) == 0
	if !resp.ScopesMatch {
		resp.MissingScopes = missing
	}

	return resp
}

// scopesDiff returns the elements of saved that are not present
// in supported, sorted. Empty/missing supported list means
// "everything saved is missing" — the strictest interpretation,
// and the right one for an actionable warning.
func scopesDiff(saved, supported []string) []string {
	sup := make(map[string]struct{}, len(supported))
	for _, s := range supported {
		sup[s] = struct{}{}
	}
	var missing []string
	for _, s := range saved {
		if _, ok := sup[s]; !ok {
			missing = append(missing, s)
		}
	}
	sort.Strings(missing)
	return missing
}

// unwrapHTTPError trims the "Get \"url\":" prefix stdlib adds
// to net/url errors, leaving just the underlying cause for the
// operator-facing toast.
func unwrapHTTPError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}
