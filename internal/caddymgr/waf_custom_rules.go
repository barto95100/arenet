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

package caddymgr

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/barto95100/arenet/internal/storage"
)

// customRuleActions are the disruptive actions of a guided rule's
// first link. severity:CRITICAL keeps the match visible in detect
// mode (onMatch reports severity <= WARNING); deny blocks in block
// mode (SecRuleEngine On) and only logs in detect mode
// (DetectionOnly).
const customRuleActions = "phase:1,deny,status:403,log,severity:CRITICAL,tag:arenet-custom"

// customRuleDirectives renders the enabled guided rules as chained
// SecRules, ordered by ID. Each condition is one link of the chain, so
// every condition must match (AND). Values are escaped with
// regexp.QuoteMeta; the API refused quotes, backslashes and control
// characters, so nothing can leave the quoted operator.
//
// See docs/superpowers/specs/2026-09-22-waf-guided-rules-design.md.
func customRuleDirectives(rules []storage.WAFCustomRule) []string {
	enabled := make([]storage.WAFCustomRule, 0, len(rules))
	for _, r := range rules {
		if !r.Disabled && len(r.Conditions) > 0 {
			enabled = append(enabled, r)
		}
	}
	sort.Slice(enabled, func(i, j int) bool { return enabled[i].ID < enabled[j].ID })

	out := make([]string, 0, len(enabled))
	for _, r := range enabled {
		links := make([]string, len(r.Conditions))
		for i, c := range r.Conditions {
			target, operator, transform := conditionParts(c)
			var actions []string
			if i == 0 {
				actions = append(actions, fmt.Sprintf("id:%d", r.ID), customRuleActions,
					fmt.Sprintf("msg:'Arenet custom rule %d'", r.ID))
			}
			actions = append(actions, transform)
			if i < len(r.Conditions)-1 {
				actions = append(actions, "chain")
			}
			links[i] = fmt.Sprintf(`SecRule %s "%s" "%s"`, target, operator, strings.Join(actions, ","))
		}
		out = append(out, strings.Join(links, "\n"))
	}
	return out
}

// conditionParts maps one condition to its SecRule target, operator
// and transformation.
func conditionParts(c storage.WAFRuleCondition) (target, operator, transform string) {
	transform = "t:none"
	switch c.Field {
	case storage.WAFFieldPath:
		target = "REQUEST_FILENAME"
	case storage.WAFFieldMethod:
		target = "REQUEST_METHOD"
	case storage.WAFFieldUserAgent:
		target = "REQUEST_HEADERS:User-Agent"
		transform = "t:none,t:lowercase"
	case storage.WAFFieldHeader:
		target = "REQUEST_HEADERS:" + c.Header
		transform = "t:none,t:lowercase"
	}

	switch c.Operator {
	case storage.WAFOpPresent:
		return "&" + target, "@gt 0", "t:none"
	case storage.WAFOpAbsent:
		return "&" + target, "@eq 0", "t:none"
	case storage.WAFOpMissing:
		// Absent (count 0) or present but empty: one rule over the
		// count and the value.
		return "&" + target + "|" + target, "@rx ^0?$", "t:none"
	}

	values := c.Values
	if transform != "t:none" {
		values = make([]string, len(c.Values))
		for i, v := range c.Values {
			values[i] = strings.ToLower(v)
		}
	}
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = regexp.QuoteMeta(v)
	}
	alt := "(?:" + strings.Join(quoted, "|") + ")"
	switch c.Operator {
	case storage.WAFOpIs:
		operator = "@rx ^" + alt + "$"
	case storage.WAFOpIsNot:
		operator = "!@rx ^" + alt + "$"
	case storage.WAFOpBeginsWith:
		operator = "@rx ^" + alt
	default: // contains
		operator = "@rx " + alt
	}
	return target, operator, transform
}

// WAFDirectivesForRoute returns the Coraza directives and CRS flag the
// route's WAF handler is built with, as if the WAF were on (the tester
// works on routes still in "off"). secLang replaces the stored SecLang
// (a draft from the editor); nil keeps the stored one.
func WAFDirectivesForRoute(r storage.Route, secLang *string) (directives string, loadCRS bool) {
	sl := r.WAFSecLang
	if secLang != nil {
		sl = *secLang
	}
	h := buildWAFHandler(r.ID, r.Host, "block", r.UploadStreamingMode, r.WAFDisableCRS,
		r.WAFExcludeRules, r.WAFExcludeTags, r.WAFTargetedExclusions, r.WAFCustomRules, sl)
	directives, _ = h["directives"].(string)
	loadCRS, _ = h["load_owasp_crs"].(bool)
	return directives, loadCRS
}

// GuidedRuleSecLang renders a guided rule as commented, indented
// SecLang with the given ID (v2.38 "convert to SecLang"): the same
// chain the rule compiles to, with msg set to the rule name so the WAF
// history keeps showing it.
func GuidedRuleSecLang(rule storage.WAFCustomRule, id int) string {
	rule.ID = id
	rule.Disabled = false
	d := customRuleDirectives([]storage.WAFCustomRule{rule})
	if len(d) == 0 {
		return ""
	}
	links := strings.Split(d[0], "\n")
	links[0] = strings.Replace(links[0], fmt.Sprintf("msg:'Arenet custom rule %d'", id),
		fmt.Sprintf("msg:'%s'", rule.Name), 1)
	for i := 1; i < len(links); i++ {
		links[i] = "    " + links[i]
	}
	return "# " + rule.Name + " (converted from a guided rule)\n" + strings.Join(links, "\n") + "\n"
}
