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

package storage

import (
	"strconv"
	"strings"

	"github.com/barto95100/arenet/internal/apierr"
	"github.com/barto95100/arenet/internal/seclang"
)

// The WAF fields are validated here because here is the only place
// every write path goes through (v2.73).
//
// Before this, each of them was checked in internal/api and nowhere
// else, so a route arriving through internal/backup's restore reached
// caddymgr's emitters and the Coraza compiler with whatever the
// snapshot contained. buildWAFHandler's comment said the SecLang was
// "validated by the API with waf.CheckSecLang", and that was true of
// one write path out of three.
//
// What it bought an attacker who could get an operator to restore a
// crafted snapshot: @inspectFile runs an arbitrary host program with
// an attacker-chosen argument on every matching request, and Include
// reads arbitrary host files with the first token echoed back in the
// reload error — both under the Arenet process account, which is root
// in the packaged Docker and systemd deployments.
//
// Validation runs whatever the route's WAFMode is. The fields are only
// emitted in detect and block mode, but a snapshot can set the mode in
// the same write, and a payload sitting at rest waiting for someone to
// switch the mode on is the same defect one step later.

// secLangUnsafe reports the first character of value that would break
// out of the SecLang construct caddymgr builds around it, or 0 when
// there is none.
//
// The quoting is not ours to trust: caddymgr writes
// fmt.Sprintf(`SecRule %s "%s" "%s"`, …), so a double quote ends the
// section early and a newline starts a whole new directive — and
// Coraza parses directives line by line, with # comments skipped, so
// an injected line loads cleanly and the reload succeeds.
//
// A control character is refused on its own account: it cannot be part
// of a legitimate header name, tag or match value, and it is the other
// half of the line-splitting problem.
func secLangUnsafe(value string, alsoRefuse string) rune {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return r
		}
		if strings.ContainsRune(alsoRefuse, r) {
			return r
		}
	}
	return 0
}

// refuseWAFChar builds the operator-facing refusal.
func refuseWAFChar(code, field, value string, bad rune) error {
	return apierr.New(code,
		map[string]string{"field": field, "value": value, "char": string(bad)},
		"%s: %q contains %q, which would break out of the SecLang directive "+
			"Arenet builds around it", field, value, string(bad))
}

// headerNameSafe reports whether s is a plain HTTP header name.
//
// Stricter than RFC 7230's token rule on purpose: this value is
// concatenated straight into "REQUEST_HEADERS:" + Header with no
// escaping at all (caddymgr/waf_custom_rules.go conditionParts), so it
// is held to the shape every real header name has rather than to the
// widest shape the grammar permits.
//
// The dot is allowed because some vendor headers carry one and it has
// no escaping power in a Coraza variable key. The other RFC 7230 token
// characters — ' ! # $ % & * + ^ ` | ~ — are refused: none appears in
// a real header name, and the single quote in particular is the one
// that matters elsewhere in this file.
func headerNameSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// validateWAFFields checks every operator-supplied string that reaches
// the Coraza directive text.
func (r *Route) validateWAFFields() error {
	// The expert SecLang, through the same allowlist internal/api has
	// always used. seclang.Check bars Include, SecRuleEngine and the
	// file-reading and program-running operators, and pins the rule-id
	// range; it is the security boundary, and the Coraza compile it
	// ends with is a syntax check on top.
	if _, errs := seclang.Check(r.WAFSecLang); len(errs) > 0 {
		return apierr.New("waf_seclang_invalid",
			map[string]string{"line": strconv.Itoa(errs[0].Line), "reason": errs[0].Message},
			"waf_seclang: line %d: %s", errs[0].Line, errs[0].Message)
	}

	for _, cr := range r.WAFCustomRules {
		// Name reaches msg:'%s' in GuidedRuleSecLang, so the single
		// quote matters here and nowhere else.
		if bad := secLangUnsafe(cr.Name, `'"\`); bad != 0 {
			return refuseWAFChar("waf_custom_rule_name_invalid", "waf_custom_rules[].name", cr.Name, bad)
		}
		for _, c := range cr.Conditions {
			if c.Field == WAFFieldHeader && !headerNameSafe(c.Header) {
				return apierr.New("waf_custom_rule_header_invalid",
					map[string]string{"header": c.Header},
					"waf_custom_rules[].conditions[].header: %q is not a header name — "+
						"letters, digits, - and _ only; it is concatenated into "+
						"REQUEST_HEADERS: with no escaping", c.Header)
			}
			for _, v := range c.Values {
				// caddymgr runs these through regexp.QuoteMeta, which
				// escapes regex metacharacters and nothing else: a
				// double quote and a newline pass straight through and
				// land inside "%s".
				if bad := secLangUnsafe(v, `"\`); bad != 0 {
					return refuseWAFChar("waf_custom_rule_value_invalid",
						"waf_custom_rules[].conditions[].values[]", v, bad)
				}
			}
		}
	}

	for _, ex := range r.WAFTargetedExclusions {
		if bad := secLangUnsafe(ex.Target, `"\`); bad != 0 {
			return refuseWAFChar("waf_exclusion_target_invalid",
				"waf_targeted_exclusions[].target", ex.Target, bad)
		}
		if bad := secLangUnsafe(ex.Path, `"\`); bad != 0 {
			return refuseWAFChar("waf_exclusion_path_invalid",
				"waf_targeted_exclusions[].path", ex.Path, bad)
		}
	}

	for _, tag := range r.WAFExcludeTags {
		// A tag lands in ctl:ruleRemoveByTag=%s inside a
		// comma-separated action list, so a space or a comma ends the
		// action as surely as a quote does.
		if bad := secLangUnsafe(tag, `"\ ,`); bad != 0 {
			return refuseWAFChar("waf_exclude_tag_invalid", "waf_exclude_tags[]", tag, bad)
		}
	}

	return nil
}
