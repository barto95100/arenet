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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/internal/waf"
)

// v2.38 per-route SecLang — see
// docs/superpowers/specs/2026-09-22-waf-seclang-editor-design.md.

// codeSecLangInvalid is the error code of a refused SecLang; params.errors
// carries [{line, message}].
const codeSecLangInvalid = "seclang_invalid"

// wafTestMaxHeaders bounds the sample request of the WAF tester.
const wafTestMaxHeaders = 50

// secLangCheckError reports refused SecLang with its per-line problems.
type secLangCheckError struct{ errs []waf.SecLangError }

func (e secLangCheckError) Error() string {
	first := e.errs[0]
	return fmt.Sprintf("wafSecLang: line %d: %s", first.Line, first.Message)
}

// normalizeSecLang validates the route's SecLang (empty clears).
func normalizeSecLang(text string) (string, error) {
	if strings.TrimSpace(text) == "" {
		return "", nil
	}
	if _, errs := waf.CheckSecLang(text); len(errs) > 0 {
		return "", secLangCheckError{errs}
	}
	return text, nil
}

// writeSecLangError writes a 400 for a refused SecLang (structured when
// the error carries lines).
func writeSecLangError(w http.ResponseWriter, err error) {
	var se secLangCheckError
	if errors.As(err, &se) {
		writeErrorCode(w, http.StatusBadRequest, codeSecLangInvalid, se.Error(), map[string]any{"errors": se.errs})
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

// nextSecLangID is the first free ID after the rules found.
func nextSecLangID(rules []waf.SecLangRule) int {
	next := waf.SecLangMinID
	for _, r := range rules {
		if r.ID >= next {
			next = r.ID + 1
		}
	}
	return next
}

// secLangValidateRequest / Response — POST /waf/seclang/validate.
type secLangValidateRequest struct {
	SecLang string `json:"seclang"`
}

type secLangValidateResponse struct {
	Errors []waf.SecLangError `json:"errors"`
	NextID int                `json:"nextId"`
}

// validateSecLang handles POST /waf/seclang/validate: the editor's live
// check, plus the next free rule ID for templates.
func (h *Handler) validateSecLang(w http.ResponseWriter, r *http.Request) {
	var req secLangValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	rules, errs := waf.CheckSecLang(req.SecLang)
	if errs == nil {
		errs = []waf.SecLangError{}
	}
	writeJSON(w, http.StatusOK, secLangValidateResponse{Errors: errs, NextID: nextSecLangID(rules)})
}

// secLangFromGuidedRequest — POST /waf/seclang/from-guided.
type secLangFromGuidedRequest struct {
	Rule wafCustomRuleWire `json:"rule"`
	ID   int               `json:"id"`
}

// secLangFromGuided handles POST /waf/seclang/from-guided: the SecLang a
// guided rule compiles to, commented, with the given ID.
func (h *Handler) secLangFromGuided(w http.ResponseWriter, r *http.Request) {
	var req secLangFromGuidedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.ID < waf.SecLangMinID || req.ID > waf.SecLangMaxID {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("id must be between %d and %d", waf.SecLangMinID, waf.SecLangMaxID))
		return
	}
	rule, err := normalizeCustomRule(req.Rule)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"seclang": caddymgr.GuidedRuleSecLang(rule, req.ID)})
}

// wafTestRequest — POST /routes/{id}/waf-test.
type wafTestRequest struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Headers []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"headers"`
	Body string `json:"body"`
	// SecLang, when set, replaces the stored SecLang (unsaved draft).
	SecLang *string `json:"seclang,omitempty"`
}

type wafTestResponse struct {
	waf.DryRunResult
	// Mode is the route's WAF mode: in "detect" a blocked result is
	// only logged, in "off" nothing happens.
	Mode string `json:"mode"`
}

// testRouteWAF handles POST /routes/{id}/waf-test: runs a sample
// request through a WAF built like the route's (no traffic, no event).
func (h *Handler) testRouteWAF(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req wafTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if len(req.Headers) > wafTestMaxHeaders {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d headers", wafTestMaxHeaders))
		return
	}
	if len(req.Body) > waf.DryRunMaxBody {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("the body is limited to %d KiB", waf.DryRunMaxBody/1024))
		return
	}
	route, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for waf test", "err", err, "id", id)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}
	if req.SecLang != nil {
		if _, err := normalizeSecLang(*req.SecLang); err != nil {
			writeSecLangError(w, err)
			return
		}
	}
	directives, loadCRS := caddymgr.WAFDirectivesForRoute(route, req.SecLang)
	sample := waf.DryRunRequest{Method: req.Method, Path: req.Path, Host: route.Host, Body: req.Body}
	for _, hd := range req.Headers {
		sample.Headers = append(sample.Headers, [2]string{hd.Name, hd.Value})
	}
	res, err := waf.DryRun(directives, loadCRS, sample)
	if err != nil {
		h.logger.Error("waf test", "err", err, "id", id)
		writeError(w, http.StatusInternalServerError, "waf test failed: "+err.Error())
		return
	}
	mode := route.WAFMode
	if mode == "" {
		mode = "off"
	}
	writeJSON(w, http.StatusOK, wafTestResponse{DryRunResult: res, Mode: mode})
}
