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

package waf

import "testing"

const dryRunCRS = crsAndExcludeBase

var browser = [][2]string{{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"}, {"Accept", "text/html"}}

func TestDryRun_BenignAccepted(t *testing.T) {
	res, err := DryRun(dryRunCRS, true, DryRunRequest{Method: "GET", Path: "/index.html", Host: "app.example.com", Headers: browser})
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if res.Blocked || len(res.Matches) != 0 {
		t.Fatalf("benign request: %+v, want accepted with no match", res)
	}
}

func TestDryRun_SQLiBlockedByCRS(t *testing.T) {
	res, err := DryRun(dryRunCRS, true, DryRunRequest{Path: "/search?q=1%27%20OR%20%271%27=%271", Host: "app.example.com", Headers: browser})
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if !res.Blocked || res.Status != 403 || res.BlockedBy != 949110 {
		t.Fatalf("SQLi: %+v, want blocked 403 by 949110", res)
	}
	found := false
	for _, m := range res.Matches {
		found = found || m.RuleID == 942100
	}
	if !found {
		t.Errorf("942100 missing from matches: %+v", res.Matches)
	}
}

func TestDryRun_SecLangRuleAndBody(t *testing.T) {
	sl := `SecRule ARGS_POST:role "@streq admin" "id:130000,phase:2,deny,status:401,msg:'No self-promotion'"`
	res, err := DryRun(sl+"\n"+dryRunCRS, true, DryRunRequest{
		Method: "POST", Path: "/profile", Host: "app.example.com",
		Headers: append([][2]string{{"Content-Type", "application/x-www-form-urlencoded"}}, browser...),
		Body:    "name=bob&role=admin",
	})
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if !res.Blocked || res.Status != 401 || res.BlockedBy != 130000 {
		t.Fatalf("SecLang body rule: %+v, want blocked 401 by 130000", res)
	}
	if len(res.Matches) == 0 || res.Matches[0].Message != "No self-promotion" {
		t.Errorf("matches = %+v", res.Matches)
	}
	res, _ = DryRun(sl+"\n"+dryRunCRS, true, DryRunRequest{
		Method: "POST", Path: "/profile", Host: "app.example.com",
		Headers: append([][2]string{{"Content-Type", "application/x-www-form-urlencoded"}}, browser...),
		Body:    "name=bob&role=user",
	})
	if res.Blocked {
		t.Errorf("role=user must pass: %+v", res)
	}
}

func TestDryRun_BuildError(t *testing.T) {
	if _, err := DryRun(`SecRule ARGS "@rx (" "id:130000,phase:1,deny"`, false, DryRunRequest{Path: "/"}); err == nil {
		t.Error("invalid directives must return an error")
	}
}
