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
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/caddyimport"
	"github.com/barto95100/arenet/internal/storage"
)

// Caddyfile import (v2.40) — see
// docs/superpowers/specs/2026-09-22-caddyfile-import-design.md.

// caddyfileImportRequest is the body of both endpoints; Hosts and
// Replace are only read by the import.
type caddyfileImportRequest struct {
	Caddyfile string   `json:"caddyfile"`
	Hosts     []string `json:"hosts,omitempty"`
	Replace   []string `json:"replace,omitempty"`
}

// caddyfileCandidate is a preview row: the parsed candidate plus
// whether the host already exists in Arenet.
type caddyfileCandidate struct {
	caddyimport.Candidate
	Conflict bool `json:"conflict"`
}

// caddyfilePreviewResponse is what the preview returns.
type caddyfilePreviewResponse struct {
	GlobalWarnings []caddyimport.Warning `json:"globalWarnings"`
	Candidates     []caddyfileCandidate  `json:"candidates"`
}

// caddyfileImportResponse reports what the import did.
type caddyfileImportResponse struct {
	Created  []string              `json:"created"`
	Replaced []string              `json:"replaced"`
	Skipped  []caddyfileSkipped    `json:"skipped"`
	Warnings []caddyimport.Warning `json:"warnings"`
}

// caddyfileSkipped is one host left out, with the reason.
type caddyfileSkipped struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// parseImportBody decodes the request and parses the Caddyfile.
func (h *Handler) parseImportBody(w http.ResponseWriter, r *http.Request) (caddyfileImportRequest, caddyimport.Result, bool) {
	var req caddyfileImportRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return req, caddyimport.Result{}, false
	}
	if strings.TrimSpace(req.Caddyfile) == "" {
		writeError(w, http.StatusBadRequest, "caddyfile must not be empty")
		return req, caddyimport.Result{}, false
	}
	res, err := caddyimport.Parse(req.Caddyfile)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return req, caddyimport.Result{}, false
	}
	return req, res, true
}

// existingHosts maps every host and alias already configured to its
// route ID.
func (h *Handler) existingHosts(ctx context.Context) (map[string]string, error) {
	routes, err := h.store.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(routes)*2)
	for _, r := range routes {
		for _, host := range r.AllHosts() {
			out[strings.ToLower(host)] = r.ID
		}
	}
	return out, nil
}

// previewCaddyfileImport handles POST /routes/import/caddyfile/preview:
// parse only, nothing is written.
func (h *Handler) previewCaddyfileImport(w http.ResponseWriter, r *http.Request) {
	_, res, ok := h.parseImportBody(w, r)
	if !ok {
		return
	}
	existing, err := h.existingHosts(r.Context())
	if err != nil {
		h.logger.Error("caddyfile import: list routes", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load routes")
		return
	}
	resp := caddyfilePreviewResponse{GlobalWarnings: res.GlobalWarnings, Candidates: []caddyfileCandidate{}}
	if resp.GlobalWarnings == nil {
		resp.GlobalWarnings = []caddyimport.Warning{}
	}
	for _, c := range res.Candidates {
		row := caddyfileCandidate{Candidate: c}
		if c.Route != nil {
			for _, host := range append([]string{c.Route.Host}, c.Route.Aliases...) {
				if _, taken := existing[strings.ToLower(host)]; taken {
					row.Conflict = true
					break
				}
			}
		}
		resp.Candidates = append(resp.Candidates, row)
	}
	writeJSON(w, http.StatusOK, resp)
}

// importCaddyfile handles POST /routes/import/caddyfile: re-parses the
// Caddyfile, creates (or replaces) the requested hosts, reloads Caddy
// once and undoes everything if Caddy refuses the result.
func (h *Handler) importCaddyfile(w http.ResponseWriter, r *http.Request) {
	req, res, ok := h.parseImportBody(w, r)
	if !ok {
		return
	}
	if len(req.Hosts) == 0 {
		writeError(w, http.StatusBadRequest, "hosts must list at least one host to import")
		return
	}
	existing, err := h.existingHosts(r.Context())
	if err != nil {
		h.logger.Error("caddyfile import: list routes", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load routes")
		return
	}

	resp := caddyfileImportResponse{
		Created: []string{}, Replaced: []string{},
		Skipped: []caddyfileSkipped{}, Warnings: res.GlobalWarnings,
	}
	if resp.Warnings == nil {
		resp.Warnings = []caddyimport.Warning{}
	}
	// created / replaced routes, kept for the rollback.
	var created []storage.Route
	var replaced []storage.Route
	rollback := func(ctx context.Context) {
		for _, rt := range created {
			if err := h.store.DeleteRoute(ctx, rt.ID); err != nil {
				h.logger.Error("caddyfile import rollback: delete", "err", err, "id", rt.ID)
			}
		}
		for _, rt := range replaced {
			if _, err := h.store.UpdateRoute(ctx, rt); err != nil {
				h.logger.Error("caddyfile import rollback: restore", "err", err, "id", rt.ID)
			}
		}
	}

	for _, want := range req.Hosts {
		c := findCandidate(res.Candidates, want)
		switch {
		case c == nil:
			resp.Skipped = append(resp.Skipped, caddyfileSkipped{want, "not found in this Caddyfile"})
			continue
		case !c.Importable || c.Route == nil:
			// Give the parser's reason, not "not found".
			reason := c.Reason
			if reason == "" {
				reason = "nothing to import in this block"
			}
			resp.Skipped = append(resp.Skipped, caddyfileSkipped{want, reason})
			continue
		}
		route := routeFromCandidate(*c.Route)
		previousID, conflict := existing[strings.ToLower(route.Host)]
		if conflict && !slices.Contains(req.Replace, want) {
			resp.Skipped = append(resp.Skipped, caddyfileSkipped{want, "a route already serves this host"})
			continue
		}
		if err := storage.ValidateRoute(route); err != nil {
			resp.Skipped = append(resp.Skipped, caddyfileSkipped{want, err.Error()})
			continue
		}
		if conflict {
			previous, err := h.store.GetRoute(r.Context(), previousID)
			if err != nil {
				resp.Skipped = append(resp.Skipped, caddyfileSkipped{want, "failed to load the existing route"})
				continue
			}
			route.ID = previous.ID
			updated, err := h.store.UpdateRoute(r.Context(), route)
			if err != nil {
				resp.Skipped = append(resp.Skipped, caddyfileSkipped{want, err.Error()})
				continue
			}
			replaced = append(replaced, previous)
			resp.Replaced = append(resp.Replaced, route.Host)
			h.appendAudit(r, audit.Event{
				Action: audit.ActionRouteUpdated, TargetType: "route", TargetID: updated.ID,
				BeforeJSON: mustMarshalForAudit(routeForAudit(previous)),
				AfterJSON:  mustMarshalForAudit(routeForAudit(updated)),
			})
			continue
		}
		stored, err := h.store.CreateRoute(r.Context(), route)
		if err != nil {
			resp.Skipped = append(resp.Skipped, caddyfileSkipped{want, err.Error()})
			continue
		}
		created = append(created, stored)
		resp.Created = append(resp.Created, stored.Host)
		h.appendAudit(r, audit.Event{
			Action: audit.ActionRouteCreated, TargetType: "route", TargetID: stored.ID,
			AfterJSON: mustMarshalForAudit(routeForAudit(stored)),
		})
	}

	if len(created)+len(replaced) == 0 {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddyfile import: caddy reload failed — rolling back", "err", err)
		rollback(r.Context())
		if rbErr := h.caddy.ReloadFromStore(r.Context()); rbErr != nil {
			h.logger.Error("caddyfile import: reload after rollback failed", "err", rbErr)
		}
		writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("caddy refused the imported routes, nothing was kept: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// findCandidate returns the candidate for host (case-insensitive).
func findCandidate(candidates []caddyimport.Candidate, host string) *caddyimport.Candidate {
	for i := range candidates {
		if strings.EqualFold(candidates[i].Host, host) {
			return &candidates[i]
		}
	}
	return nil
}

// routeFromCandidate builds the storage route an import creates.
func routeFromCandidate(c caddyimport.Route) storage.Route {
	return storage.Route{
		Host:               c.Host,
		Aliases:            c.Aliases,
		Upstreams:          c.Upstreams,
		LBPolicy:           c.LBPolicy,
		TLSEnabled:         c.TLSEnabled,
		RedirectToHTTPS:    c.TLSEnabled,
		ACMEChallenge:      c.ACMEChallenge,
		AuthMode:           storage.RouteAuthNone,
		InsecureSkipVerify: c.InsecureSkipVerify,
		RequestHeaders:     c.RequestHeaders,
		ResponseHeaders:    c.ResponseHeaders,
		HealthCheck:        c.HealthCheck,
		PathRules:          c.PathRules,
		// Imported routes start with the WAF in detect mode: the
		// operator sees what the CRS would block before enforcing.
		WAFMode: "detect",
	}
}
