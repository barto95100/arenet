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

// WAFTargetedExclusion (v2.36) stops one CRS rule from inspecting one
// request field, optionally only on one path — the OWASP-recommended
// way to silence a false positive while the rule keeps protecting
// every other field. Emitted as ctl:ruleRemoveTargetById before the
// CRS Includes (see caddymgr buildWAFHandler).
//
// See docs/superpowers/specs/2026-09-22-waf-targeted-exclusions-design.md.
type WAFTargetedExclusion struct {
	// RuleID is the CRS rule whose inspection is narrowed.
	RuleID int `json:"rule_id"`
	// Target is the field the rule no longer inspects, as
	// "VARIABLE:key" (e.g. "ARGS:content", "REQUEST_HEADERS:user-agent").
	Target string `json:"target"`
	// Path limits the exclusion to one request path; empty = every
	// path of the route.
	Path string `json:"path,omitempty"`
	// PathPrefix extends Path to everything below it.
	PathPrefix bool `json:"path_prefix,omitempty"`
}
