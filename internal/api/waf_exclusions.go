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
	"slices"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.36 targeted WAF exclusions — see
// docs/superpowers/specs/2026-09-22-waf-targeted-exclusions-design.md.
const (
	// wafTargetedMaxCount caps the exclusions per route (one
	// directive each, evaluated on every request).
	wafTargetedMaxCount = 100
	// wafTargetKeyMaxLen bounds the field name of a target.
	wafTargetKeyMaxLen = 128
	// wafExclusionPathMaxLen bounds an exclusion path.
	wafExclusionPathMaxLen = 512
	// wafTargetForbiddenChars would break out of the ctl action or
	// the quoted directive (comma separates actions, semicolon
	// separates the ctl target, quotes end the action list).
	wafTargetForbiddenChars = " \t,;\"'\\|"
	// wafPathForbiddenChars would break out of the quoted operator.
	wafPathForbiddenChars = " \t\"'\\"
)

// wafTargetVariables are the collections a targeted exclusion may
// name: the keyed request collections CRS rules inspect.
var wafTargetVariables = []string{
	"ARGS", "ARGS_GET", "ARGS_POST", "ARGS_NAMES",
	"REQUEST_COOKIES", "REQUEST_COOKIES_NAMES",
	"REQUEST_HEADERS", "REQUEST_HEADERS_NAMES",
	"FILES", "FILES_NAMES",
}

// wafProtectedRuleFamilies are CRS rule families (ID / 1000) that must
// never be excluded: initialization (901), blocking evaluation (949,
// 959) and correlation (980) — excluding them disables the blocking
// itself, not one detection.
var wafProtectedRuleFamilies = []int{901, 949, 959, 980}

// isProtectedWAFRule reports whether id belongs to a protected family.
func isProtectedWAFRule(id int) bool {
	return slices.Contains(wafProtectedRuleFamilies, id/1000)
}

// wafTargetedExclusionWire is the API shape of a targeted exclusion.
type wafTargetedExclusionWire struct {
	RuleID     int    `json:"ruleId"`
	Target     string `json:"target"`
	Path       string `json:"path,omitempty"`
	PathPrefix bool   `json:"pathPrefix,omitempty"`
}

// toTargetedExclusionsWire converts storage exclusions for a response
// (never nil, so the JSON is always a list).
func toTargetedExclusionsWire(in []storage.WAFTargetedExclusion) []wafTargetedExclusionWire {
	out := make([]wafTargetedExclusionWire, 0, len(in))
	for _, e := range in {
		out = append(out, wafTargetedExclusionWire(e))
	}
	return out
}

// normalizeTargetedExclusions validates the wire list and returns its
// canonical stored form: trimmed, variable upper-cased, deduplicated,
// sorted by (rule, target, path, prefix). An empty input clears.
func normalizeTargetedExclusions(in []wafTargetedExclusionWire) ([]storage.WAFTargetedExclusion, error) {
	if len(in) > wafTargetedMaxCount {
		return nil, fmt.Errorf("wafTargetedExclusions: too many exclusions (%d); max %d per route", len(in), wafTargetedMaxCount)
	}
	out := make([]storage.WAFTargetedExclusion, 0, len(in))
	for _, w := range in {
		e, err := normalizeTargetedExclusion(w)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return targetedExclusionLess(out[i], out[j]) })
	return out, nil
}

// normalizeTargetedExclusion validates one exclusion.
func normalizeTargetedExclusion(w wafTargetedExclusionWire) (storage.WAFTargetedExclusion, error) {
	var zero storage.WAFTargetedExclusion
	if err := validateExcludableRuleID(w.RuleID); err != nil {
		return zero, fmt.Errorf("wafTargetedExclusions: %w", err)
	}
	target, err := normalizeWAFTarget(w.Target)
	if err != nil {
		return zero, fmt.Errorf("wafTargetedExclusions: %w", err)
	}
	path := strings.TrimSpace(w.Path)
	if path != "" {
		if !strings.HasPrefix(path, "/") {
			return zero, fmt.Errorf("wafTargetedExclusions: path %q must start with /", path)
		}
		if len(path) > wafExclusionPathMaxLen {
			return zero, fmt.Errorf("wafTargetedExclusions: path exceeds %d chars", wafExclusionPathMaxLen)
		}
		if strings.ContainsAny(path, wafPathForbiddenChars) || hasControlChar(path) {
			return zero, fmt.Errorf("wafTargetedExclusions: path %q contains a space, quote, backslash or control character", path)
		}
	}
	return storage.WAFTargetedExclusion{
		RuleID:     w.RuleID,
		Target:     target,
		Path:       path,
		PathPrefix: path != "" && w.PathPrefix,
	}, nil
}

// validateExcludableRuleID applies the WAFExcludeRules range and
// refuses the protected CRS families.
func validateExcludableRuleID(id int) error {
	if id < wafExcludeRuleMinID || id > wafExcludeRuleMaxID {
		return fmt.Errorf("rule ID %d is out of range (must be 6-digit, %d..%d)", id, wafExcludeRuleMinID, wafExcludeRuleMaxID)
	}
	if id <= wafExcludeRuleArenetReservedHi {
		return fmt.Errorf("rule ID %d is an Arenet rule (reserved range, must be > %d)", id, wafExcludeRuleArenetReservedHi)
	}
	if isProtectedWAFRule(id) {
		return fmt.Errorf("rule ID %d is a CRS initialization / blocking-evaluation rule and cannot be excluded — exclude the rule that matched instead", id)
	}
	return nil
}

// normalizeWAFTarget validates "VARIABLE:key" and upper-cases the
// variable (Coraza compares keys case-insensitively, the variable
// name is the canonical collection name).
func normalizeWAFTarget(raw string) (string, error) {
	variable, key, ok := strings.Cut(strings.TrimSpace(raw), ":")
	variable = strings.ToUpper(strings.TrimSpace(variable))
	key = strings.TrimSpace(key)
	if !ok || key == "" {
		return "", fmt.Errorf("target %q must be VARIABLE:name (e.g. ARGS:content)", raw)
	}
	if !slices.Contains(wafTargetVariables, variable) {
		return "", fmt.Errorf("target variable %q is not supported (one of %s)", variable, strings.Join(wafTargetVariables, ", "))
	}
	if len(key) > wafTargetKeyMaxLen {
		return "", fmt.Errorf("target name exceeds %d chars", wafTargetKeyMaxLen)
	}
	// A leading "/" would make Coraza read the name as a regex.
	if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("target name %q must not start with / (regular expressions are not supported)", key)
	}
	if strings.ContainsAny(key, wafTargetForbiddenChars) || hasControlChar(key) {
		return "", fmt.Errorf("target name %q contains a space, comma, semicolon, quote, backslash, pipe or control character", key)
	}
	return variable + ":" + key, nil
}

// hasControlChar reports any ASCII control character.
func hasControlChar(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

// targetedExclusionLess is the canonical order (mirrors caddymgr).
func targetedExclusionLess(a, b storage.WAFTargetedExclusion) bool {
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	if a.Target != b.Target {
		return a.Target < b.Target
	}
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	return !a.PathPrefix && b.PathPrefix
}

// addWAFExclusionRequest is the body of POST /routes/{id}/waf-exclusions.
// Without Target the rule is excluded on the whole route (added to
// WAFExcludeRules); with Target it becomes a targeted exclusion.
type addWAFExclusionRequest struct {
	RuleID     int    `json:"ruleId"`
	Target     string `json:"target,omitempty"`
	Path       string `json:"path,omitempty"`
	PathPrefix bool   `json:"pathPrefix,omitempty"`
}

// errWAFExclusionExists marks an exclusion already present.
var errWAFExclusionExists = errors.New("this exclusion already exists on the route")

// withWAFExclusion returns route with the exclusion added.
func withWAFExclusion(route storage.Route, req addWAFExclusionRequest) (storage.Route, error) {
	next := route
	if strings.TrimSpace(req.Target) == "" {
		if err := validateExcludableRuleID(req.RuleID); err != nil {
			return route, err
		}
		if slices.Contains(route.WAFExcludeRules, req.RuleID) {
			return route, errWAFExclusionExists
		}
		rules, err := normalizeExcludeRules(append(slices.Clone(route.WAFExcludeRules), req.RuleID))
		if err != nil {
			return route, err
		}
		next.WAFExcludeRules = rules
		return next, nil
	}
	e, err := normalizeTargetedExclusion(wafTargetedExclusionWire(req))
	if err != nil {
		return route, err
	}
	if slices.Contains(route.WAFTargetedExclusions, e) {
		return route, errWAFExclusionExists
	}
	wire := append(toTargetedExclusionsWire(route.WAFTargetedExclusions), wafTargetedExclusionWire(e))
	all, err := normalizeTargetedExclusions(wire)
	if err != nil {
		return route, err
	}
	next.WAFTargetedExclusions = all
	return next, nil
}

// addWAFExclusion handles POST /routes/{id}/waf-exclusions (v2.36):
// adds one exclusion — usually from a WAF event — with the update
// contract of the route endpoints (reload, rollback on Caddy refusal,
// route_updated audit). 409 when the exclusion already exists.
func (h *Handler) addWAFExclusion(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req addWAFExclusionRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for waf exclusion", "err", err, "id", id)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}
	next, err := withWAFExclusion(previous, req)
	if errors.Is(err, errWAFExclusionExists) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.store.UpdateRoute(r.Context(), next)
	if err != nil {
		h.logger.Error("add waf exclusion", "err", err, "id", id)
		writeError(w, http.StatusInternalServerError, "failed to update route")
		return
	}
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after waf exclusion — rolling back", "err", err, "id", id)
		if _, rbErr := h.store.UpdateRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteUpdated,
		TargetType: "route",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(routeForAudit(previous)),
		AfterJSON:  mustMarshalForAudit(routeForAudit(updated)),
	})
	writeJSON(w, http.StatusOK, toResponse(updated))
}
