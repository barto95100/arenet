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
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// Step K.1 — forward-auth provider CRUD endpoints (§5.1, §3.3).
//
// The provider config is instance-level (one row per name, slug-
// shaped) and referenced by routes via `Route.ForwardAuth.
// ProviderName`. Routes' edit-time validation enforces "provider
// must exist" (validateForwardAuthProvider below); DELETE
// enforces the inverse "no route may reference this provider"
// (handleDeleteForwardAuthProvider).
//
// Secret discipline (§1.6 Δ6, AC #2bis): the ClientSecret is
// never echoed on the API GET path (returned as empty string with
// a ClientSecretSet bool), never appears in audit-log
// before/after payloads, never appears in slog output. Same
// posture as the J.4 OVH credentials and the I.5 Basic Auth
// hashes.

// forwardAuthProviderRequest is the wire shape on POST / PUT.
// ClientSecret is the IdP-issued credential, write-only:
// preserve-on-edit semantics on PUT (empty → keep previous).
type forwardAuthProviderRequest struct {
	Name           string   `json:"name"`
	Kind           string   `json:"kind"`
	VerifyURL      string   `json:"verifyUrl"`
	AuthRequestURI string   `json:"authRequestUri"`
	CopyHeaders    []string `json:"copyHeaders"`
	ClientSecret   string   `json:"clientSecret"`
	// AuthPassthroughPrefix (Step K.4, optional) — path prefix
	// served by the IdP itself on the application's external
	// host (e.g. "/outpost.goauthentik.io" for Authentik
	// embedded outpost, "/oauth2" for oauth2-proxy). Non-empty
	// emits a passthrough route bypassing the forward_auth gate
	// for that subtree. Empty = legacy K.1 behaviour.
	AuthPassthroughPrefix string `json:"authPassthroughPrefix,omitempty"`
}

// forwardAuthProviderResponse is the wire shape on GET. The
// ClientSecret is ALWAYS empty (server-side redaction); the
// ClientSecretSet bool tells the UI whether the row has a stored
// secret so it can render the "••• set" placeholder.
type forwardAuthProviderResponse struct {
	Name                  string   `json:"name"`
	Kind                  string   `json:"kind"`
	VerifyURL             string   `json:"verifyUrl"`
	AuthRequestURI        string   `json:"authRequestUri"`
	CopyHeaders           []string `json:"copyHeaders"`
	ClientSecret          string   `json:"clientSecret"`
	ClientSecretSet       bool     `json:"clientSecretSet"`
	AuthPassthroughPrefix string   `json:"authPassthroughPrefix"`
	CreatedAt             string   `json:"createdAt"`
	UpdatedAt             string   `json:"updatedAt"`
}

// forwardAuthProviderForAudit returns a copy of p with the
// ClientSecret blanked. Apply to every storage.ForwardAuthProvider
// passed into appendAudit's BeforeJSON / AfterJSON — mirrors the
// dnsProviderForAudit (J.4) and routeForAudit (I.5) patterns.
func forwardAuthProviderForAudit(p storage.ForwardAuthProvider) storage.ForwardAuthProvider {
	p.ClientSecret = ""
	return p
}

func forwardAuthProviderToResponse(p storage.ForwardAuthProvider) forwardAuthProviderResponse {
	copyHeaders := p.CopyHeaders
	if copyHeaders == nil {
		copyHeaders = []string{}
	}
	return forwardAuthProviderResponse{
		Name:                  p.Name,
		Kind:                  p.Kind,
		VerifyURL:             p.VerifyURL,
		AuthRequestURI:        p.AuthRequestURI,
		CopyHeaders:           copyHeaders,
		ClientSecret:          "",
		ClientSecretSet:       p.ClientSecret != "",
		AuthPassthroughPrefix: p.AuthPassthroughPrefix,
		CreatedAt:             p.CreatedAt.UTC().Format(timestampFormat),
		UpdatedAt:             p.UpdatedAt.UTC().Format(timestampFormat),
	}
}

// validateForwardAuthProviderRequest enforces API-layer shape
// rules with friendlier messages than storage.validate. Returns
// the first failure.
func validateForwardAuthProviderRequest(req forwardAuthProviderRequest) error {
	if req.Name == "" {
		return errors.New("name must not be empty")
	}
	// Kind enum check (storage will re-check; this surfaces the
	// API-layer message first).
	ok := false
	for _, k := range storage.ForwardAuthProviderKinds {
		if req.Kind == k {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("kind %q must be one of %v", req.Kind, storage.ForwardAuthProviderKinds)
	}
	if req.VerifyURL == "" {
		return errors.New("verifyUrl must not be empty")
	}
	u, err := url.Parse(req.VerifyURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("verifyUrl %q is not a valid URL", req.VerifyURL)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return errors.New("verifyUrl must use http or https scheme")
	}
	if req.AuthRequestURI == "" {
		return errors.New("authRequestUri must not be empty")
	}
	if req.AuthRequestURI[0] != '/' {
		return fmt.Errorf("authRequestUri %q must start with /", req.AuthRequestURI)
	}
	for i, h := range req.CopyHeaders {
		if err := validateHeaderName(h); err != nil {
			return fmt.Errorf("copyHeaders[%d]: %s", i, err.Error())
		}
	}
	// Step K.4 — passthrough prefix shape check (API-friendlier
	// wording; storage re-checks via validate()).
	if req.AuthPassthroughPrefix != "" {
		if req.AuthPassthroughPrefix[0] != '/' {
			return fmt.Errorf("authPassthroughPrefix %q must start with /", req.AuthPassthroughPrefix)
		}
		for _, r := range req.AuthPassthroughPrefix {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
				return fmt.Errorf("authPassthroughPrefix %q must not contain whitespace", req.AuthPassthroughPrefix)
			}
		}
		if len(req.AuthPassthroughPrefix) > 256 {
			return errors.New("authPassthroughPrefix must be ≤ 256 characters")
		}
	}
	return nil
}

// validateForwardAuthProvider is the cross-rule called by
// createRoute / updateRoute when AuthMode == "forward_auth":
// the referenced provider name MUST exist in the
// forward_auth_providers bucket. Mirrors the J.4 DNS-01 provider-
// exists check.
func (h *Handler) validateForwardAuthProvider(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("forwardAuth.providerName must not be empty when authMode is \"forward_auth\"")
	}
	_, err := h.store.GetForwardAuthProvider(ctx, name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("forwardAuth.providerName %q does not match any configured forward-auth provider — configure it under Settings", name)
		}
		// Storage error — surface as a 500 via the caller; we
		// return a wrapped error that the caller writes as 500.
		return fmt.Errorf("failed to verify forward-auth provider: %w", err)
	}
	return nil
}

func (h *Handler) listForwardAuthProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := h.store.ListForwardAuthProviders(r.Context())
	if err != nil {
		h.logger.Error("list forward_auth_providers", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list forward-auth providers")
		return
	}
	out := make([]forwardAuthProviderResponse, 0, len(providers))
	for _, p := range providers {
		out = append(out, forwardAuthProviderToResponse(p))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getForwardAuthProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	p, err := h.store.GetForwardAuthProvider(r.Context(), name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "forward-auth provider not found")
			return
		}
		h.logger.Error("get forward_auth_provider", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get forward-auth provider")
		return
	}
	writeJSON(w, http.StatusOK, forwardAuthProviderToResponse(p))
}

func (h *Handler) createForwardAuthProvider(w http.ResponseWriter, r *http.Request) {
	var req forwardAuthProviderRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateForwardAuthProviderRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	provider := storage.ForwardAuthProvider{
		Name:                  req.Name,
		Kind:                  req.Kind,
		VerifyURL:             req.VerifyURL,
		AuthRequestURI:        req.AuthRequestURI,
		CopyHeaders:           req.CopyHeaders,
		ClientSecret:          req.ClientSecret,
		AuthPassthroughPrefix: req.AuthPassthroughPrefix,
	}
	created, err := h.store.CreateForwardAuthProvider(r.Context(), provider)
	if err != nil {
		if errors.Is(err, storage.ErrConflict) {
			writeError(w, http.StatusConflict, fmt.Sprintf("forward-auth provider %q already exists", req.Name))
			return
		}
		// storage.validate failure surfaces here too — those are
		// 400s with a clear message.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after forward_auth_provider create — rolling back", "err", err, "name", created.Name)
		if delErr := h.store.DeleteForwardAuthProvider(r.Context(), created.Name); delErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", delErr, "name", created.Name)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionForwardAuthProviderUpdated,
		TargetType: "forward_auth_provider",
		TargetID:   created.Name,
		AfterJSON:  mustMarshalForAudit(forwardAuthProviderForAudit(created)),
	})

	writeJSON(w, http.StatusCreated, forwardAuthProviderToResponse(created))
}

func (h *Handler) updateForwardAuthProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var req forwardAuthProviderRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// The path name is authoritative; ignore Name in the body if
	// it disagrees (or enforce equality). We pick "path wins"
	// silently — same as the Route update endpoint pattern.
	req.Name = name
	if err := validateForwardAuthProviderRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	previous, err := h.store.GetForwardAuthProvider(r.Context(), name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "forward-auth provider not found")
			return
		}
		h.logger.Error("get forward_auth_provider for update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load forward-auth provider")
		return
	}

	// Preserve-on-edit secret semantics (Step J.4 pattern): an
	// empty ClientSecret on PUT keeps the previously stored
	// value. Mirrors the Step I.5 BasicAuth password preserve UX.
	clientSecret := req.ClientSecret
	if clientSecret == "" {
		clientSecret = previous.ClientSecret
	}

	updated, err := h.store.UpdateForwardAuthProvider(r.Context(), storage.ForwardAuthProvider{
		Name:                  req.Name,
		Kind:                  req.Kind,
		VerifyURL:             req.VerifyURL,
		AuthRequestURI:        req.AuthRequestURI,
		CopyHeaders:           req.CopyHeaders,
		ClientSecret:          clientSecret,
		AuthPassthroughPrefix: req.AuthPassthroughPrefix,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after forward_auth_provider update — rolling back", "err", err, "name", name)
		if _, rbErr := h.store.UpdateForwardAuthProvider(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "name", name)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionForwardAuthProviderUpdated,
		TargetType: "forward_auth_provider",
		TargetID:   updated.Name,
		BeforeJSON: mustMarshalForAudit(forwardAuthProviderForAudit(previous)),
		AfterJSON:  mustMarshalForAudit(forwardAuthProviderForAudit(updated)),
	})

	writeJSON(w, http.StatusOK, forwardAuthProviderToResponse(updated))
}

// handleDeleteForwardAuthProvider enforces the §1.3 decision 14
// reference-guarded delete: a provider referenced by ≥1 route's
// AuthMode == "forward_auth" cannot be deleted. The handler
// returns 409 with the offending route IDs in the response body
// so the operator can reconfigure those routes first.
func (h *Handler) deleteForwardAuthProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	previous, err := h.store.GetForwardAuthProvider(r.Context(), name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "forward-auth provider not found")
			return
		}
		h.logger.Error("get forward_auth_provider for delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load forward-auth provider")
		return
	}

	// Reference check: every route whose ForwardAuth.ProviderName
	// matches this name blocks the delete. Collect the IDs for the
	// 409 body — the operator sees exactly which routes to fix.
	routes, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("list routes for forward_auth_provider delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to verify provider references")
		return
	}
	var referencing []string
	for _, rt := range routes {
		if rt.AuthMode == storage.RouteAuthForwardAuth && rt.ForwardAuth.ProviderName == name {
			referencing = append(referencing, rt.ID)
		}
	}
	if len(referencing) > 0 {
		writeError(w, http.StatusConflict, fmt.Sprintf(
			"forward-auth provider %q is referenced by %d route(s) — reconfigure them first: %v",
			name, len(referencing), referencing))
		return
	}

	if err := h.store.DeleteForwardAuthProvider(r.Context(), name); err != nil {
		h.logger.Error("delete forward_auth_provider", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete forward-auth provider")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after forward_auth_provider delete — rolling back", "err", err, "name", name)
		if _, rbErr := h.store.CreateForwardAuthProvider(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "name", name)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionForwardAuthProviderDeleted,
		TargetType: "forward_auth_provider",
		TargetID:   name,
		BeforeJSON: mustMarshalForAudit(forwardAuthProviderForAudit(previous)),
	})

	w.WriteHeader(http.StatusNoContent)
}
