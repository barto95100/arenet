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

package storage

// WAFCustomRule (v2.37) is a guided WAF rule of a route: when every
// condition matches, the request is blocked (403 in block mode,
// logged in detect mode). Built from a form, emitted by caddymgr as a
// chained SecRule. See
// docs/superpowers/specs/2026-09-22-waf-guided-rules-design.md.
type WAFCustomRule struct {
	// ID is the Coraza rule ID, in the Arenet range [120000, 129999].
	// Stable across edits so WAF events keep pointing at the rule.
	ID int `json:"id"`
	// Name is the operator's label, shown in the route form and the
	// WAF history.
	Name string `json:"name"`
	// Disabled keeps the rule stored but not emitted.
	Disabled bool `json:"disabled,omitempty"`
	// Conditions must all match (AND).
	Conditions []WAFRuleCondition `json:"conditions"`
}

// WAFRuleCondition is one criterion of a WAFCustomRule. Values are
// alternatives: the condition matches when any of them does.
type WAFRuleCondition struct {
	// Field is "path", "method", "user_agent" or "header".
	Field string `json:"field"`
	// Header is the header name when Field is "header".
	Header string `json:"header,omitempty"`
	// Operator depends on Field: path is/begins_with/contains,
	// method is/is_not, user_agent contains/is/missing, header
	// present/absent/contains/is.
	Operator string `json:"operator"`
	// Values are the alternatives compared with the field.
	Values []string `json:"values,omitempty"`
}

// WAF custom-rule fields and operators.
const (
	WAFFieldPath      = "path"
	WAFFieldMethod    = "method"
	WAFFieldUserAgent = "user_agent"
	WAFFieldHeader    = "header"

	WAFOpIs         = "is"
	WAFOpIsNot      = "is_not"
	WAFOpBeginsWith = "begins_with"
	WAFOpContains   = "contains"
	WAFOpMissing    = "missing"
	WAFOpPresent    = "present"
	WAFOpAbsent     = "absent"
)
