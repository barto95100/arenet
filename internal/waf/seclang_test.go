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

package waf

import (
	"strings"
	"testing"
)

const validSecLang = `# Only JSON on the API
SecRule REQUEST_FILENAME "@beginsWith /api/" \
    "id:130000,phase:1,deny,status:415,log,msg:'API accepts JSON only',chain"
    SecRule REQUEST_METHOD "!@rx ^(?:GET|HEAD|DELETE)$" "chain"
    SecRule REQUEST_HEADERS:Content-Type "!@beginsWith application/json" "t:none,t:lowercase"

SecRule REMOTE_ADDR "!@ipMatch 192.168.1.0/24,10.0.0.0/8" "id:130001,phase:1,deny,msg:'Admin from LAN only',chain"
    SecRule REQUEST_FILENAME "@beginsWith /admin" "t:none"

SecAction "id:130002,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:content"
SecMarker END_ARENET
SecRule ARGS "@detectSQLi" "id:130003,phase:2,block,log,setvar:tx.custom_score=+5,t:none,t:urlDecodeUni"
`

func TestCheckSecLang_Valid(t *testing.T) {
	rules, errs := CheckSecLang(validSecLang)
	if len(errs) != 0 {
		t.Fatalf("valid SecLang refused: %+v", errs)
	}
	if len(rules) != 4 {
		t.Fatalf("rules = %+v, want 4", rules)
	}
	if rules[0].ID != 130000 || rules[0].Msg != "API accepts JSON only" || rules[0].Line != 2 {
		t.Errorf("first rule = %+v, want id 130000, msg, line 2", rules[0])
	}
	if rules[1].Line != 7 {
		t.Errorf("second rule line = %d, want 7", rules[1].Line)
	}
	if r, e := CheckSecLang("  \n# only a comment\n"); len(r) != 0 || len(e) != 0 {
		t.Errorf("empty text: rules %+v errs %+v", r, e)
	}
}

func TestCheckSecLang_Refuses(t *testing.T) {
	cases := map[string]string{
		"include":              `Include /etc/passwd`,
		"engine off":           `SecRuleEngine Off`,
		"audit log to disk":    `SecAuditLog /tmp/x`,
		"data dir":             `SecDataDir /tmp`,
		"body limit":           `SecRequestBodyLimit 1`,
		"inspectFile runs cmd": `SecRule ARGS "@inspectFile /bin/sh" "id:130000,phase:2,deny"`,
		"pmFromFile":           `SecRule ARGS "@pmFromFile /etc/shadow" "id:130000,phase:2,deny"`,
		"pmf alias":            `SecRule ARGS "@pmf /etc/shadow" "id:130000,phase:2,deny"`,
		"ipMatchFromFile":      `SecRule REMOTE_ADDR "@ipMatchFromFile /etc/hosts" "id:130000,phase:1,deny"`,
		"rbl":                  `SecRule REMOTE_ADDR "@rbl zen.spamhaus.org" "id:130000,phase:1,deny"`,
		"negated inspectFile":  `SecRule ARGS "!@inspectFile /bin/sh" "id:130000,phase:2,deny"`,
		"upper-case operator":  `SecRule ARGS "@INSPECTFILE /bin/sh" "id:130000,phase:2,deny"`,
		"exec":                 `SecRule ARGS "@rx x" "id:130000,phase:2,deny,exec:/bin/sh"`,
		"setenv":               `SecAction "id:130000,phase:1,pass,setenv:ARENET_DEV=true"`,
		"ctl ruleEngine":       `SecAction "id:130000,phase:1,pass,ctl:ruleEngine=Off"`,
		"ctl upper case":       `SecAction "id:130000,phase:1,pass,CTL:RULEENGINE=Off"`,
		"ctl body access":      `SecAction "id:130000,phase:1,pass,ctl:requestBodyAccess=Off"`,
		"ctl audit":            `SecAction "id:130000,phase:1,pass,ctl:auditEngine=On"`,
		"ENV collection":       `SecRule ENV:OVH_APPLICATION_SECRET "@rx ." "id:130000,phase:1,deny,logdata:%{MATCHED_VAR}"`,
		"ENV in a list":        `SecRule ARGS|!ENV:X|ENV "@rx ." "id:130000,phase:1,deny"`,
		"ENV macro":            `SecRule ARGS "@rx ." "id:130000,phase:1,deny,msg:'%{ENV.HOME}'"`,
		"no id":                `SecRule ARGS "@rx x" "phase:1,deny"`,
		"id below range":       `SecRule ARGS "@rx x" "id:120000,phase:1,deny"`,
		"id above range":       `SecRule ARGS "@rx x" "id:140000,phase:1,deny"`,
		"CRS id":               `SecRule ARGS "@rx x" "id:942100,phase:1,deny"`,
		"duplicate id":         "SecRule ARGS \"@rx x\" \"id:130000,phase:1,deny\"\nSecRule ARGS \"@rx y\" \"id:130000,phase:1,deny\"",
		"id in chained link":   "SecRule ARGS \"@rx x\" \"id:130000,phase:1,deny,chain\"\nSecRule ARGS \"@rx y\" \"id:130001\"",
		"deny in chained link": "SecRule ARGS \"@rx x\" \"id:130000,phase:1,deny,chain\"\nSecRule ARGS \"@rx y\" \"deny\"",
		"unclosed chain":       `SecRule ARGS "@rx x" "id:130000,phase:1,deny,chain"`,
		"backticks":            "SecAction `\nid:130000\n`",
		"unquoted operator":    `SecRule ARGS @rx "id:130000,phase:1,deny"`,
		"syntax (Coraza)":      `SecRule ARGS "@rx (" "id:130000,phase:1,deny"`,
		"unknown action":       `SecRule ARGS "@rx x" "id:130000,phase:1,deny,frobnicate"`,
		"too big":              "SecAction \"id:130000,phase:1,pass,msg:'" + strings.Repeat("a", SecLangMaxBytes) + "'\"",
	}
	for name, text := range cases {
		if _, errs := CheckSecLang(text); len(errs) == 0 {
			t.Errorf("%s: accepted, want a refusal", name)
		}
	}
}

func TestCheckSecLang_ErrorLines(t *testing.T) {
	text := "# header\nSecAction \"id:130000,phase:1,pass,nolog\"\n\nSecRuleEngine Off\nSecRule ARGS \"@rx x\" \\\n  \"id:120000,phase:1,deny\"\n"
	_, errs := CheckSecLang(text)
	if len(errs) != 2 || errs[0].Line != 4 || errs[1].Line != 5 {
		t.Fatalf("errs = %+v, want lines 4 (directive) and 5 (id range, continuation start)", errs)
	}
}

func TestCheckSecLang_CorazaErrorLine(t *testing.T) {
	text := "SecAction \"id:130000,phase:1,pass,nolog\"\n\nSecRule ARGS \"@rx (\" \"id:130001,phase:1,deny\"\n"
	_, errs := CheckSecLang(text)
	if len(errs) != 1 || errs[0].Line != 3 {
		t.Fatalf("errs = %+v, want one error on line 3", errs)
	}
}
