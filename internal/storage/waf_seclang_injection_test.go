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
	"strings"
	"testing"
)

// The WAF fields are validated here because here is the only place
// every write path goes through (v2.73).
//
// waf.CheckSecLang existed and was reached from exactly one caller,
// internal/api's normalizeSecLang. Route.validate() had no reference to
// WAFSecLang at all, and internal/backup/import.go re-checks a restored
// snapshot only with storage.ValidateRoute — so routes[].waf_seclang,
// waf_custom_rules, waf_targeted_exclusions and waf_exclude_tags from an
// uploaded backup reached the Coraza compiler verbatim.
//
// buildWAFHandler's comment claimed the SecLang was "validated by the
// API with waf.CheckSecLang". That was true of one write path out of
// three, which is the shape of this whole defect.
//
// What an attacker got: @inspectFile runs an arbitrary host program
// with an attacker-chosen argument on every matching request, and
// Include reads arbitrary host files with the first token echoed back
// in the reload error. Both under the Arenet process account, root in
// the packaged deployments.

func routeWithWAF(mutate func(*Route)) Route {
	r := Route{
		ID: "r1", Host: "app.example.com",
		Upstreams: []Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		WAFMode:   "block",
	}
	mutate(&r)
	return r
}

// F3: the directive allowlist now runs on every write path, not just
// the API's.
func TestRoute_RefusesSecLangTheAllowlistBars(t *testing.T) {
	cases := []struct {
		name    string
		seclang string
	}{
		{
			"@inspectFile executes a host program",
			`SecRule REQUEST_HEADERS:X-Probe "@inspectFile /usr/bin/curl" "id:130001,phase:1,log,pass"`,
		},
		{
			"Include reads a host file",
			`Include /etc/shadow`,
		},
		{
			"SecRuleEngine can switch the engine off",
			`SecRuleEngine Off`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := routeWithWAF(func(r *Route) { r.WAFSecLang = tc.seclang })
			if err := r.validate(); err == nil {
				t.Fatalf("a restored snapshot carrying %q must be refused before it reaches the Coraza compiler", tc.seclang)
			}
		})
	}
}

// And SecLang the allowlist permits must still be accepted, or the
// feature is dead.
func TestRoute_AcceptsLegitimateSecLang(t *testing.T) {
	r := routeWithWAF(func(r *Route) {
		// 130000-139999 is the SecLang range; 120000-129999 belongs to
		// the guided rules. Using a guided-rule id here refused the
		// text for the wrong reason on the first attempt.
		r.WAFSecLang = `SecRule REQUEST_URI "@rx /wp-login" "id:130001,phase:1,deny,status:403,msg:'wp probe'"`
	})
	if err := r.validate(); err != nil {
		t.Fatalf("valid SecLang must stay valid: %v", err)
	}
}

// F7: the guided-rule fields are interpolated into a SecRule unescaped.
// This is the payload from the finding, which closed the quoted section
// and opened a second directive.
func TestRoute_RefusesAGuidedRuleThatInjectsADirective(t *testing.T) {
	injected := "X \"@rx z\" \"id:131001,phase:1,pass,nolog\"\n" +
		"SecRule REQUEST_HEADERS:X-P \"@inspectFile /usr/bin/env\" \"id:131002,phase:1,pass,nolog\"\n#"

	r := routeWithWAF(func(r *Route) {
		r.WAFCustomRules = []WAFCustomRule{{
			ID:   120001,
			Name: "x",
			Conditions: []WAFRuleCondition{{
				Field:    WAFFieldHeader,
				Header:   injected,
				Operator: WAFOpContains,
				Values:   []string{"foo"},
			}},
		}}
	})
	if err := r.validate(); err == nil {
		t.Fatal("a header name carrying a newline and quotes must be refused: " +
			"caddymgr interpolates it into \"REQUEST_HEADERS:\" + Header with no escaping")
	}
}

// The condition VALUES are injectable too, which the finding did not
// name. caddymgr runs them through regexp.QuoteMeta, and QuoteMeta
// escapes regex metacharacters only — a double quote and a newline pass
// through untouched, and the value lands inside "%s".
func TestRoute_RefusesAConditionValueThatInjectsADirective(t *testing.T) {
	for _, bad := range []string{
		`foo" "id:1,phase:1,pass" ` + "\n" + `SecRule ARGS "@inspectFile /bin/sh" "id:2,phase:1,pass"`,
		"plain\nnewline",
		`a"quote`,
	} {
		t.Run(strings.SplitN(bad, "\n", 2)[0], func(t *testing.T) {
			r := routeWithWAF(func(r *Route) {
				r.WAFCustomRules = []WAFCustomRule{{
					ID:   120001,
					Name: "x",
					Conditions: []WAFRuleCondition{{
						Field:    WAFFieldPath,
						Operator: WAFOpContains,
						Values:   []string{bad},
					}},
				}}
			})
			if err := r.validate(); err == nil {
				t.Errorf("condition value %q must be refused — QuoteMeta does not escape quotes or newlines", bad)
			}
		})
	}
}

// A guided rule an operator really writes must still pass.
func TestRoute_AcceptsAnOrdinaryGuidedRule(t *testing.T) {
	r := routeWithWAF(func(r *Route) {
		r.WAFCustomRules = []WAFCustomRule{{
			ID:   120001,
			Name: "block curl",
			Conditions: []WAFRuleCondition{{
				Field:    WAFFieldHeader,
				Header:   "X-Api-Key",
				Operator: WAFOpContains,
				Values:   []string{"curl/7.68", "python-requests"},
			}},
		}}
	})
	if err := r.validate(); err != nil {
		t.Fatalf("an ordinary guided rule must stay valid: %v", err)
	}
}

// The targeted exclusions land in ctl:ruleRemoveTargetById and in a
// chained SecRule path condition.
func TestRoute_RefusesATargetedExclusionThatInjects(t *testing.T) {
	r := routeWithWAF(func(r *Route) {
		r.WAFTargetedExclusions = []WAFTargetedExclusion{{
			RuleID: 942100,
			Target: "ARGS:x\"\nSecRule ARGS \"@inspectFile /bin/sh\" \"id:3,phase:1,pass\"",
		}}
	})
	if err := r.validate(); err == nil {
		t.Fatal("an exclusion target carrying a newline must be refused")
	}
}

// And the exclude tags, which land in ctl:ruleRemoveByTag=%s.
func TestRoute_RefusesAnExcludeTagThatInjects(t *testing.T) {
	r := routeWithWAF(func(r *Route) {
		r.WAFExcludeTags = []string{"attack-sqli\"\nInclude /etc/shadow\n#"}
	})
	if err := r.validate(); err == nil {
		t.Fatal("an exclude tag carrying a newline must be refused")
	}
}

func TestRoute_AcceptsAnOrdinaryExcludeTag(t *testing.T) {
	r := routeWithWAF(func(r *Route) {
		r.WAFExcludeTags = []string{"attack-sqli", "OWASP_CRS"}
	})
	if err := r.validate(); err != nil {
		t.Fatalf("an ordinary tag must stay valid: %v", err)
	}
}

// The WAF fields are only emitted when the mode is detect or block, but
// validation must not depend on the mode: a snapshot can set the mode
// in the same write, and a stored payload waiting for someone to switch
// the mode on is the same defect one step later.
func TestRoute_ValidatesWAFFieldsEvenWhenModeIsOff(t *testing.T) {
	r := routeWithWAF(func(r *Route) {
		r.WAFMode = "off"
		r.WAFSecLang = `Include /etc/shadow`
	})
	if err := r.validate(); err == nil {
		t.Fatal("the payload must be refused at rest, not only when the mode happens to be on")
	}
}
