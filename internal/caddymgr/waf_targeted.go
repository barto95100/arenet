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
	"sort"
	"strings"

	"github.com/barto95100/arenet/internal/storage"
)

// targetedExclusionBaseID is the first rule ID of the generated
// targeted-exclusion directives, inside the Arenet-reserved range
// [100000, 199999] (100001 is the admin-API guard).
const targetedExclusionBaseID = 110000

// targetedExclusionDirectives renders one phase-1 directive per
// targeted exclusion, in canonical order so the directives string —
// and so the WAF pool key — does not depend on input order:
//
//	no path:  SecAction "id:…,phase:1,pass,nolog,ctl:ruleRemoveTargetById=<rule>;<target>"
//	path:     SecRule REQUEST_FILENAME "@streq <path>" "id:…,phase:1,pass,nolog,t:none,ctl:…"
//	prefix:   @streq <path> + @beginsWith <path>/ — "below /api" is /api
//	          and /api/…, never /apix (@beginsWith is a raw string
//	          prefix; smoke-caught). A path ending in "/" needs only
//	          the @beginsWith.
//
// ctl:ruleRemoveTargetById must run before the rule it narrows, hence
// phase 1 and placement before the CRS Includes. Values are trusted:
// the API validated them (no quote, space, comma or semicolon).
func targetedExclusionDirectives(in []storage.WAFTargetedExclusion) []string {
	if len(in) == 0 {
		return nil
	}
	sorted := make([]storage.WAFTargetedExclusion, len(in))
	copy(sorted, in)
	sort.Slice(sorted, func(i, j int) bool { return targetedLess(sorted[i], sorted[j]) })

	out := make([]string, 0, len(sorted))
	id := targetedExclusionBaseID
	onPath := func(op, path, ctl string) {
		out = append(out, fmt.Sprintf(`SecRule REQUEST_FILENAME "%s %s" "id:%d,phase:1,pass,nolog,t:none,%s"`,
			op, path, id, ctl))
		id++
	}
	for _, e := range sorted {
		ctl := fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s", e.RuleID, e.Target)
		switch {
		case e.Path == "":
			out = append(out, fmt.Sprintf(`SecAction "id:%d,phase:1,pass,nolog,%s"`, id, ctl))
			id++
		case !e.PathPrefix:
			onPath("@streq", e.Path, ctl)
		case strings.HasSuffix(e.Path, "/"):
			onPath("@beginsWith", e.Path, ctl)
		default:
			onPath("@streq", e.Path, ctl)
			onPath("@beginsWith", e.Path+"/", ctl)
		}
	}
	return out
}

// targetedLess orders exclusions by rule, target, path, prefix flag.
func targetedLess(a, b storage.WAFTargetedExclusion) bool {
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
