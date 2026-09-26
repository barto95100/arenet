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
	"bufio"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

// Per-route SecLang (v2.38) — operator-written directives, checked
// against a strict allowlist before they reach Coraza. The WAF is
// built with the host filesystem mounted (CRS loading), and Coraza
// can read files (Include, *FromFile), run programs (@inspectFile),
// set process env (setenv) or query DNS (@rbl): none of that is
// allowed. See docs/superpowers/specs/2026-09-22-waf-seclang-editor-design.md.

// SecLang ID range and size limits.
const (
	SecLangMinID    = 130000
	SecLangMaxID    = 139999
	SecLangMaxBytes = 64 * 1024
	SecLangMaxRules = 200
)

var (
	secLangDirectives = []string{"secrule", "secaction", "secmarker"}
	secLangOperators  = []string{
		"rx", "streq", "beginswith", "endswith", "contains", "pm", "within",
		"eq", "ge", "gt", "le", "lt", "ipmatch", "detectsqli", "detectxss",
		"validatebyterange", "validateurlencoding", "validateutf8encoding",
		"strmatch", "unconditionalmatch", "nomatch",
	}
	secLangActions = []string{
		"id", "phase", "chain", "deny", "block", "drop", "pass", "allow",
		"status", "redirect", "log", "nolog", "auditlog", "noauditlog", "msg",
		"logdata", "tag", "severity", "rev", "ver", "maturity", "capture",
		"multimatch", "setvar", "expirevar", "skip", "skipafter", "t", "ctl",
	}
	secLangCtl = []string{
		"ruleremovebyid", "ruleremovebytag", "ruleremovebymsg",
		"ruleremovetargetbyid", "ruleremovetargetbytag", "ruleremovetargetbymsg",
		"requestbodyprocessor", "forcerequestbodyvariable",
	}
	// secLangDisruptive actions may not appear in a chained link.
	secLangDisruptive = []string{"deny", "block", "drop", "pass", "allow", "redirect"}
)

// SecLangError is one problem, with its 1-based line.
type SecLangError struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// SecLangRule is a rule (chain start or SecAction) found in the text.
type SecLangRule struct {
	ID   int
	Msg  string
	Line int
}

// secLangLine is one logical directive (continuations joined).
type secLangLine struct {
	text string
	line int // line where the directive starts
}

// splitSecLang mirrors Coraza's parser line handling
// (internal/seclang/parser.go parseString): trimmed lines, "#"
// comments skipped, trailing "\" joins the next line. Backticks
// (multi-line blocks) are refused.
func splitSecLang(text string) ([]secLangLine, []SecLangError) {
	var out []secLangLine
	var errs []SecLangError
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), SecLangMaxBytes+1)
	var buf strings.Builder
	start, n := 0, 0
	for scanner.Scan() {
		n++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if strings.Contains(line, "`") {
			errs = append(errs, SecLangError{n, "backticks are not supported"})
			continue
		}
		if buf.Len() == 0 {
			start = n
		}
		if strings.HasSuffix(line, "\\") {
			buf.WriteString(strings.TrimSuffix(line, "\\"))
			continue
		}
		buf.WriteString(line)
		out = append(out, secLangLine{buf.String(), start})
		buf.Reset()
	}
	if buf.Len() > 0 {
		out = append(out, secLangLine{buf.String(), start})
	}
	return out, errs
}

// CheckSecLang validates per-route SecLang: allowlist, rule IDs in
// [SecLangMinID, SecLangMaxID], unique, then a Coraza compile of the
// text alone (no filesystem). It returns the rules found and the
// problems, sorted by line; no problem means the text is accepted.
func CheckSecLang(text string) ([]SecLangRule, []SecLangError) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	if len(text) > SecLangMaxBytes {
		return nil, []SecLangError{{1, fmt.Sprintf("the SecLang is larger than %d KiB", SecLangMaxBytes/1024)}}
	}
	lines, errs := splitSecLang(text)
	var rules []SecLangRule
	var groups []secLangLine // one rule (with its chain) per entry, for error lines
	seen := map[int]int{}
	inChain := false
	for _, l := range lines {
		if inChain && len(groups) > 0 {
			groups[len(groups)-1].text += "\n" + l.text
		} else {
			groups = append(groups, l)
		}
		dir, opts, _ := strings.Cut(l.text, " ")
		dir = strings.ToLower(dir)
		if !slices.Contains(secLangDirectives, dir) {
			errs = append(errs, SecLangError{l.line, fmt.Sprintf("directive %q is not allowed (only SecRule, SecAction, SecMarker)", dir)})
			inChain = false
			continue
		}
		if dir == "secmarker" {
			if inChain {
				errs = append(errs, SecLangError{l.line, "a chain must end with a SecRule"})
			}
			inChain = false
			if strings.TrimSpace(opts) == "" {
				errs = append(errs, SecLangError{l.line, "SecMarker needs a name"})
			}
			continue
		}
		var actions string
		if dir == "secrule" {
			vars, op, acts, err := splitSecRule(opts)
			if err != nil {
				errs = append(errs, SecLangError{l.line, err.Error()})
				inChain = false
				continue
			}
			if msg := checkVariables(vars); msg != "" {
				errs = append(errs, SecLangError{l.line, msg})
			}
			if msg := checkOperator(op); msg != "" {
				errs = append(errs, SecLangError{l.line, msg})
			}
			actions = acts
		} else {
			if inChain {
				errs = append(errs, SecLangError{l.line, "a chain must end with a SecRule"})
			}
			actions = strings.Trim(strings.TrimSpace(opts), `"`)
		}
		parsed, msg := checkActions(actions)
		if msg != "" {
			errs = append(errs, SecLangError{l.line, msg})
		}
		if inChain {
			if parsed.id != "" {
				errs = append(errs, SecLangError{l.line, "a chained rule must not have an id"})
			}
			if parsed.disruptive {
				errs = append(errs, SecLangError{l.line, "a chained rule must not have a disruptive action (deny, block, pass…)"})
			}
		} else {
			id, err := strconv.Atoi(parsed.id)
			switch {
			case parsed.id == "":
				errs = append(errs, SecLangError{l.line, fmt.Sprintf("the rule needs an id between %d and %d", SecLangMinID, SecLangMaxID)})
			case err != nil || id < SecLangMinID || id > SecLangMaxID:
				errs = append(errs, SecLangError{l.line, fmt.Sprintf("id %s is outside %d..%d", parsed.id, SecLangMinID, SecLangMaxID)})
			case seen[id] != 0:
				errs = append(errs, SecLangError{l.line, fmt.Sprintf("id %d is already used on line %d", id, seen[id])})
			default:
				seen[id] = l.line
				rules = append(rules, SecLangRule{ID: id, Msg: parsed.msg, Line: l.line})
			}
		}
		inChain = dir == "secrule" && parsed.chain
	}
	if inChain && len(lines) > 0 {
		errs = append(errs, SecLangError{lines[len(lines)-1].line, "the last rule opens a chain that is never closed"})
	}
	if len(rules) > SecLangMaxRules {
		errs = append(errs, SecLangError{1, fmt.Sprintf("too many rules (%d); max %d", len(rules), SecLangMaxRules)})
	}
	if len(errs) == 0 {
		// Coraza compile of the text alone, without filesystem access.
		if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(text)); err != nil {
			errs = append(errs, SecLangError{failingGroupLine(groups), err.Error()})
		}
	}
	slices.SortStableFunc(errs, func(a, b SecLangError) int { return a.Line - b.Line })
	return rules, errs
}

// splitSecRule mirrors Coraza's parseActionOperator: variables up to
// the first space, a double-quoted operator, optional double-quoted
// actions.
func splitSecRule(opts string) (vars, op, actions string, err error) {
	data := strings.Trim(opts, " ")
	vars, rest, ok := strings.Cut(data, " ")
	if !ok {
		return "", "", "", fmt.Errorf("SecRule needs VARIABLES \"OPERATOR\" \"ACTIONS\"")
	}
	rest = strings.TrimLeft(rest, " ")
	if rest == "" || rest[0] != '"' {
		return "", "", "", fmt.Errorf("the operator must be in double quotes")
	}
	quoted, rest, ok := cutQuoted(rest)
	if !ok {
		return "", "", "", fmt.Errorf("the operator's closing quote is missing")
	}
	op = quoted[1 : len(quoted)-1]
	rest = strings.TrimLeft(rest, " ")
	if rest == "" {
		return vars, op, "", nil
	}
	if len(rest) < 2 || rest[0] != '"' || rest[len(rest)-1] != '"' {
		return "", "", "", fmt.Errorf("the actions must be in double quotes")
	}
	return vars, op, rest[1 : len(rest)-1], nil
}

// cutQuoted returns the leading double-quoted string (quotes kept)
// and the rest; a quote preceded by an odd number of backslashes is
// escaped (same rule as Coraza's cutQuotedString).
func cutQuoted(s string) (string, string, bool) {
	escapes := 0
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] == '\\':
			escapes++
		case s[i] == '"' && escapes%2 == 0:
			return s[:i+1], s[i+1:], true
		default:
			escapes = 0
		}
	}
	return "", "", false
}

// checkVariables refuses the ENV collection (process environment,
// where secrets such as DNS-provider keys may live).
func checkVariables(vars string) string {
	for _, v := range strings.Split(vars, "|") {
		name := strings.TrimLeft(v, "!&")
		name, _, _ = strings.Cut(name, ":")
		if strings.EqualFold(strings.TrimSpace(name), "ENV") {
			return "the ENV collection is not allowed"
		}
	}
	return ""
}

// checkOperator applies the operator allowlist (Coraza's defaulting:
// no "@" means @rx).
func checkOperator(op string) string {
	op = strings.TrimSpace(op)
	op = strings.TrimPrefix(op, "!")
	if !strings.HasPrefix(op, "@") {
		return ""
	}
	name, _, _ := strings.Cut(op[1:], " ")
	if !slices.Contains(secLangOperators, strings.ToLower(name)) {
		return fmt.Sprintf("operator @%s is not allowed", name)
	}
	return ""
}

// parsedActions is what the checks need from an action list.
type parsedActions struct {
	id         string
	msg        string
	chain      bool
	disruptive bool
}

// checkActions splits the action list like Coraza's parseActions
// (commas outside single quotes, "\" escapes the next character) and
// applies the action / ctl allowlists.
func checkActions(actions string) (parsedActions, string) {
	var p parsedActions
	if strings.Contains(strings.ToLower(actions), "%{env.") {
		return p, "the ENV collection is not allowed in macros"
	}
	for _, kv := range splitActions(actions) {
		key, val, _ := strings.Cut(kv, ":")
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.Trim(strings.TrimSpace(val), "'")
		if key == "" {
			continue
		}
		if !slices.Contains(secLangActions, key) {
			return p, fmt.Sprintf("action %q is not allowed", key)
		}
		switch key {
		case "id":
			p.id = val
		case "msg":
			p.msg = val
		case "chain":
			p.chain = true
		case "ctl":
			name, _, _ := strings.Cut(val, "=")
			if !slices.Contains(secLangCtl, strings.ToLower(strings.TrimSpace(name))) {
				return p, fmt.Sprintf("ctl:%s is not allowed", strings.TrimSpace(name))
			}
		}
		if slices.Contains(secLangDisruptive, key) {
			p.disruptive = true
		}
	}
	return p, ""
}

// splitActions splits on commas outside single quotes.
func splitActions(actions string) []string {
	var out []string
	inQuotes, start := false, 0
	for i := 0; i < len(actions); i++ {
		c := actions[i]
		if i > 0 && actions[i-1] == '\\' {
			continue
		}
		switch {
		case c == '\'':
			inQuotes = !inQuotes
		case c == ',' && !inQuotes:
			out = append(out, actions[start:i])
			start = i + 1
		}
	}
	return append(out, actions[start:])
}

// failingGroupLine locates a Coraza compile error (its messages carry
// no line): the first rule that does not compile on its own, else 1.
func failingGroupLine(groups []secLangLine) int {
	for _, g := range groups {
		if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(g.text)); err != nil {
			return g.line
		}
	}
	return 1
}
