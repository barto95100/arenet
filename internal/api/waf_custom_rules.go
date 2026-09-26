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
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/internal/waf"
)

// v2.37 guided WAF rules — see
// docs/superpowers/specs/2026-09-22-waf-guided-rules-design.md.
const (
	wafCustomRulesMaxCount   = 50
	wafCustomConditionsMax   = 8
	wafCustomNameMaxLen      = 64
	wafCustomValueMaxLen     = 256
	wafCustomValuesMax       = 20
	wafCustomMethodValuesMax = 10
	// wafCustomNameForbidden would break out of a quoted directive or
	// a single-quoted msg.
	wafCustomNameForbidden = "\"'\\"
	// wafCustomValueForbidden would break out of the quoted operator.
	wafCustomValueForbidden = "\"\\"
)

var (
	wafHeaderNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	wafMethodRe     = regexp.MustCompile(`^[A-Z]{1,16}$`)
)

// wafCustomOperators lists the operators each field accepts, and
// whether the operator takes values.
var wafCustomOperators = map[string]map[string]bool{
	storage.WAFFieldPath:      {storage.WAFOpIs: true, storage.WAFOpBeginsWith: true, storage.WAFOpContains: true},
	storage.WAFFieldMethod:    {storage.WAFOpIs: true, storage.WAFOpIsNot: true},
	storage.WAFFieldUserAgent: {storage.WAFOpContains: true, storage.WAFOpIs: true, storage.WAFOpMissing: false},
	storage.WAFFieldHeader:    {storage.WAFOpPresent: false, storage.WAFOpAbsent: false, storage.WAFOpContains: true, storage.WAFOpIs: true},
}

// wafCustomRuleWire is the API shape of a guided rule. ID 0 = new rule
// (an ID is allocated); an existing rule keeps its ID.
type wafCustomRuleWire struct {
	ID         int                    `json:"id"`
	Name       string                 `json:"name"`
	Disabled   bool                   `json:"disabled,omitempty"`
	Conditions []wafRuleConditionWire `json:"conditions"`
}

// wafRuleConditionWire is the API shape of one condition.
type wafRuleConditionWire struct {
	Field    string   `json:"field"`
	Header   string   `json:"header,omitempty"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// toCustomRulesWire converts stored rules for a response (never nil).
func toCustomRulesWire(in []storage.WAFCustomRule) []wafCustomRuleWire {
	out := make([]wafCustomRuleWire, 0, len(in))
	for _, r := range in {
		conds := make([]wafRuleConditionWire, 0, len(r.Conditions))
		for _, c := range r.Conditions {
			conds = append(conds, wafRuleConditionWire(c))
		}
		out = append(out, wafCustomRuleWire{ID: r.ID, Name: r.Name, Disabled: r.Disabled, Conditions: conds})
	}
	return out
}

// normalizeCustomRules validates the wire list and returns the stored
// form. Rules keep the IDs they were given; an ID must belong to
// previous (the route's stored rules) and appear once. New rules (ID
// 0) get the next free ID after the highest one ever seen on the route.
func normalizeCustomRules(in []wafCustomRuleWire, previous []storage.WAFCustomRule) ([]storage.WAFCustomRule, error) {
	if len(in) > wafCustomRulesMaxCount {
		return nil, fmt.Errorf("wafCustomRules: too many rules (%d); max %d per route", len(in), wafCustomRulesMaxCount)
	}
	known := make(map[int]bool, len(previous))
	next := waf.CustomRuleMinID
	for _, r := range previous {
		known[r.ID] = true
		if r.ID >= next {
			next = r.ID + 1
		}
	}
	seen := make(map[int]bool, len(in))
	out := make([]storage.WAFCustomRule, 0, len(in))
	for i, w := range in {
		r, err := normalizeCustomRule(w)
		if err != nil {
			return nil, fmt.Errorf("wafCustomRules[%d]: %w", i, err)
		}
		switch {
		case w.ID == 0:
			if next > waf.CustomRuleMaxID {
				return nil, fmt.Errorf("wafCustomRules[%d]: no rule ID left in %d..%d", i, waf.CustomRuleMinID, waf.CustomRuleMaxID)
			}
			r.ID = next
			next++
		case !known[w.ID]:
			return nil, fmt.Errorf("wafCustomRules[%d]: unknown rule id %d (send 0 for a new rule)", i, w.ID)
		case seen[w.ID]:
			return nil, fmt.Errorf("wafCustomRules[%d]: duplicate rule id %d", i, w.ID)
		default:
			r.ID = w.ID
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	return out, nil
}

// normalizeCustomRule validates one rule (without its ID).
func normalizeCustomRule(w wafCustomRuleWire) (storage.WAFCustomRule, error) {
	var zero storage.WAFCustomRule
	name := strings.TrimSpace(w.Name)
	if name == "" || len(name) > wafCustomNameMaxLen {
		return zero, fmt.Errorf("name must be 1..%d characters", wafCustomNameMaxLen)
	}
	if strings.ContainsAny(name, wafCustomNameForbidden) || hasControlChar(name) {
		return zero, fmt.Errorf("name %q contains a quote, backslash or control character", name)
	}
	if len(w.Conditions) == 0 || len(w.Conditions) > wafCustomConditionsMax {
		return zero, fmt.Errorf("a rule needs 1..%d conditions", wafCustomConditionsMax)
	}
	conds := make([]storage.WAFRuleCondition, 0, len(w.Conditions))
	for i, c := range w.Conditions {
		nc, err := normalizeCondition(c)
		if err != nil {
			return zero, fmt.Errorf("condition %d: %w", i+1, err)
		}
		conds = append(conds, nc)
	}
	return storage.WAFCustomRule{Name: name, Disabled: w.Disabled, Conditions: conds}, nil
}

// normalizeCondition validates one condition against its field.
func normalizeCondition(c wafRuleConditionWire) (storage.WAFRuleCondition, error) {
	var zero storage.WAFRuleCondition
	ops, ok := wafCustomOperators[c.Field]
	if !ok {
		return zero, fmt.Errorf("unknown field %q (path, method, user_agent, header)", c.Field)
	}
	takesValues, ok := ops[c.Operator]
	if !ok {
		return zero, fmt.Errorf("operator %q is not valid for %s", c.Operator, c.Field)
	}
	out := storage.WAFRuleCondition{Field: c.Field, Operator: c.Operator}
	if c.Field == storage.WAFFieldHeader {
		h := strings.TrimSpace(c.Header)
		if !wafHeaderNameRe.MatchString(h) {
			return zero, fmt.Errorf("header name %q must be 1..64 letters, digits, - or _", c.Header)
		}
		out.Header = h
	}
	if !takesValues {
		return out, nil
	}
	limit := wafCustomValuesMax
	if c.Field == storage.WAFFieldMethod {
		limit = wafCustomMethodValuesMax
	}
	if len(c.Values) == 0 || len(c.Values) > limit {
		return zero, fmt.Errorf("%s %s needs 1..%d values", c.Field, c.Operator, limit)
	}
	for _, raw := range c.Values {
		v := strings.TrimSpace(raw)
		if c.Field == storage.WAFFieldMethod {
			v = strings.ToUpper(v)
			if !wafMethodRe.MatchString(v) {
				return zero, fmt.Errorf("method %q must be letters only (e.g. POST)", raw)
			}
		}
		if v == "" || len(v) > wafCustomValueMaxLen {
			return zero, fmt.Errorf("values must be 1..%d characters", wafCustomValueMaxLen)
		}
		if strings.ContainsAny(v, wafCustomValueForbidden) || hasControlChar(v) {
			return zero, fmt.Errorf("value %q contains a double quote, backslash or control character", v)
		}
		if c.Field == storage.WAFFieldPath && c.Operator != storage.WAFOpContains && !strings.HasPrefix(v, "/") {
			return zero, fmt.Errorf("path %q must start with /", v)
		}
		out.Values = append(out.Values, v)
	}
	return out, nil
}

// customRuleNames resolves guided-rule names for WAF events, loading
// each route at most once per response.
type customRuleNames struct {
	h      *Handler
	byRule map[string]map[int]string // routeID → rule ID → name
}

// newCustomRuleNames returns an empty per-response resolver.
func (h *Handler) newCustomRuleNames() *customRuleNames {
	return &customRuleNames{h: h, byRule: map[string]map[int]string{}}
}

// lookup returns the name of rule ruleID on route routeID (guided rule
// name, or the msg of a SecLang rule), or "" when the ID is not a
// custom rule or the route / rule no longer exists.
func (n *customRuleNames) lookup(ctx context.Context, routeID, ruleID string) string {
	id, err := strconv.Atoi(ruleID)
	if err != nil || id < waf.CustomRuleMinID || id > waf.SecLangMaxID {
		return ""
	}
	names, ok := n.byRule[routeID]
	if !ok {
		names = map[int]string{}
		if route, err := n.h.store.GetRoute(ctx, routeID); err == nil {
			for _, r := range route.WAFCustomRules {
				names[r.ID] = r.Name
			}
			// v2.38 — SecLang rules are named by their msg.
			rules, _ := waf.CheckSecLang(route.WAFSecLang)
			for _, r := range rules {
				names[r.ID] = r.Msg
			}
		}
		n.byRule[routeID] = names
	}
	return names[id]
}
