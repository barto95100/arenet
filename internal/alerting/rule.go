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

package alerting

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// AL.2.a — AlertRule foundation. The rule row drives the
// AL.2.b watcher's polling loop: every CooldownSecs-bounded
// tick, the watcher reads the Source, asks the
// RuleEvaluator if the condition is met, and on fire,
// builds an AlertEvent + calls Dispatcher.Dispatch on the
// rule's Channels.
//
// This file ships the type + Validate only. The watcher,
// dedupe LRU, and CRUD endpoints live downstream:
//   - AL.2.b: watcher goroutine + polling loop + dedupe
//   - AL.3b: CRUD HTTP endpoints

// Rule kind constants. Drive the per-kind evaluator
// dispatch (see evaluator.go's EvaluatorFor).
const (
	// RuleKindThreshold compares a numeric SourceValue
	// against an operator + constant. Fires when the
	// inequality is satisfied at evaluation time. Example:
	// "WAF block rate on `registry` route > 50 over the
	// last 5 minutes".
	RuleKindThreshold = "threshold"
	// RuleKindState matches a string SourceValue against
	// a literal expected value. Fires when the source's
	// current state equals the expected token. Example:
	// "system.crowdsec component status == degraded".
	RuleKindState = "state"
)

// ruleKinds is the canonical set of supported rule kinds.
// Tests + Validate iterate this slice. V2 may append
// "event" (instantaneous fire on a single matching event)
// once the watcher learns push-driven sources.
var ruleKinds = []string{
	RuleKindThreshold,
	RuleKindState,
}

// Cooldown bounds, in seconds. The lower bound prevents an
// operator from configuring a rule that fires every tick
// (cooldown < polling interval is meaningless — the
// dedupe LRU would never clear). The upper bound prevents
// an effectively-permanent silence after a single fire
// (1 day cap; operators wanting longer should
// soft-disable the rule instead).
const (
	RuleCooldownSecsMin     = 30
	RuleCooldownSecsMax     = 86400
	RuleCooldownSecsDefault = 300
)

// ruleNameRE matches a slug-shaped rule name. Same shape
// as the channel name pattern; 64-char ceiling so
// operators can use descriptive labels (e.g.
// "waf-block-rate-registry").
var ruleNameRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// AlertRule is the persisted shape of one alerting rule.
//
// Field rationale:
//   - ID: UUID v4 generated at create time. Stable across
//     renames so AlertEvent.RuleID references survive
//     operator-facing Name changes.
//   - Enabled: soft-disable flag (operator pauses a
//     misbehaving rule without losing its config).
//   - Kind + EvalParams: the kind drives evaluator
//     selection; the typed params shape per kind lives
//     under evaluator.go.
//   - Source + SourceParams: the Source.Name() the
//     watcher reads each tick + the typed params for
//     that Source.
//   - Channels: list of Channel.ID values the watcher
//     dispatches to on fire. Order-stable per spec
//     (operators reading the rule UI see channels in the
//     order they were added).
//   - CooldownSecs: after a fire, the rule is silenced
//     for this many seconds before it can fire again
//     (D4 ADR — dedupe LRU keyed by RuleID).
//   - SubjectTemplate / BodyTemplate: optional; when
//     empty the watcher (AL.2.b) falls back to the
//     "[{{.Severity}}] {{.RuleName}} fired" defaults.
//   - LastFiredAt / LastEvalAt / LastError / LastErrorAt:
//     written by the watcher each tick. Operator-visible
//     "is this rule healthy?" telemetry. LastEvalAt
//     bumps on every tick (heartbeat); LastFiredAt only
//     bumps on actual fires.
type AlertRule struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Enabled       bool            `json:"enabled"`
	Kind          string          `json:"kind"`
	Severity      Severity        `json:"severity"`
	Category      string          `json:"category"`
	Source        string          `json:"source"`
	SourceParams  json.RawMessage `json:"source_params"`
	EvalParams    json.RawMessage `json:"eval_params"`
	Channels      []string        `json:"channels"`
	CooldownSecs  int             `json:"cooldown_secs"`
	SubjectTemplate string        `json:"subject_template,omitempty"`
	BodyTemplate    string        `json:"body_template,omitempty"`

	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastFiredAt *time.Time `json:"last_fired_at,omitempty"`
	LastEvalAt  *time.Time `json:"last_eval_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
}

// RuleValidationDeps bundles the lookup seams Validate
// needs to verify "Source exists in registry" + "every
// Channel ID exists in storage". The alerting package
// declares the interface here so the caller (CRUD layer
// in AL.3b) wires the concrete deps; the rule type
// itself doesn't take a hard dep on storage.
type RuleValidationDeps struct {
	// Sources looks up a Source by Name(). nil → skip the
	// "source exists" check (useful for tests that don't
	// wire a registry). The CRUD handler MUST supply a
	// non-nil registry in production.
	Sources SourceLookup
	// ChannelExists returns true iff the given channel ID
	// exists in storage. nil → skip the channel-existence
	// check (used by unit tests that exercise other
	// invariants in isolation).
	ChannelExists func(id string) bool
}

// SourceLookup is the read surface of the Source
// registry. Defined on the consumer side so Validate can
// take the registry without importing it in the rule
// type's package layout (same file, but the seam is
// explicit for the AL.3b CRUD wiring).
type SourceLookup interface {
	Get(name string) (Source, bool)
}

// Validate runs the AL.2.a D5 invariants on the rule. The
// deps argument carries the lookups Validate needs from
// outside the rule type; pass an empty struct to skip the
// cross-reference checks (template + intrinsic-field
// checks still run).
//
// Order matters: cheap intrinsic checks first so a
// malformed rule fails fast without consulting the
// registry / storage.
func (r AlertRule) Validate(deps RuleValidationDeps) error {
	if !ruleNameRE.MatchString(r.Name) {
		return fmt.Errorf("alert_rule: name %q must match %s",
			r.Name, ruleNameRE.String())
	}
	if !stringInSlice(r.Kind, ruleKinds) {
		return fmt.Errorf("alert_rule: kind %q must be one of %v",
			r.Kind, ruleKinds)
	}
	if int(r.Severity) < int(SeverityInfo) || int(r.Severity) > int(SeverityEmergency) {
		return fmt.Errorf("alert_rule: severity %d out of range [0,3]", r.Severity)
	}
	if r.Source == "" {
		return errors.New("alert_rule: source must not be empty")
	}
	if r.CooldownSecs < RuleCooldownSecsMin || r.CooldownSecs > RuleCooldownSecsMax {
		return fmt.Errorf("alert_rule: cooldown_secs %d out of range [%d, %d]",
			r.CooldownSecs, RuleCooldownSecsMin, RuleCooldownSecsMax)
	}
	if len(r.Channels) == 0 {
		return errors.New("alert_rule: channels must have at least one channel ID")
	}
	if len(r.SourceParams) == 0 {
		return errors.New("alert_rule: source_params must not be empty (use {} if the source takes no params)")
	}
	if len(r.EvalParams) == 0 {
		return errors.New("alert_rule: eval_params must not be empty")
	}

	// Source registry lookup. Skipped when Sources is nil
	// so unit tests can exercise template + kind checks
	// without a populated registry.
	if deps.Sources != nil {
		src, ok := deps.Sources.Get(r.Source)
		if !ok {
			return fmt.Errorf("alert_rule: source %q is not registered", r.Source)
		}
		// Source-side param shape check via ValidateParams.
		// Sources that opt out (ValidateParams returns nil
		// for any input) are tolerated — the watcher will
		// surface a runtime error on Read.
		if err := src.ValidateParams(r.SourceParams); err != nil {
			return fmt.Errorf("alert_rule: source_params invalid: %w", err)
		}
	}

	// Evaluator param shape check. The evaluator is the
	// authority on the EvalParams shape — Validate just
	// asks "would Evaluate accept this on a representative
	// SourceValue?" via the dedicated ValidateParams hook.
	ev, err := EvaluatorFor(r.Kind)
	if err != nil {
		return fmt.Errorf("alert_rule: evaluator: %w", err)
	}
	if err := ev.ValidateParams(r.EvalParams); err != nil {
		return fmt.Errorf("alert_rule: eval_params invalid: %w", err)
	}

	// Channel reference check. Skipped when ChannelExists
	// is nil (unit tests).
	if deps.ChannelExists != nil {
		for i, id := range r.Channels {
			if id == "" {
				return fmt.Errorf("alert_rule: channels[%d] is empty", i)
			}
			if !deps.ChannelExists(id) {
				return fmt.Errorf("alert_rule: channels[%d] = %q does not match any registered channel", i, id)
			}
		}
	}

	// Template compile checks. Empty templates use the
	// AL.2.b watcher's defaults; non-empty templates must
	// parse via the same sandboxed compileBodyTemplate
	// the senders use (text/template, missingkey=zero, no
	// sprig). Renders are dry — actual Execute against a
	// representative AlertEvent happens at watcher fire-
	// time.
	if r.SubjectTemplate != "" {
		if _, err := compileBodyTemplate(r.SubjectTemplate); err != nil {
			return fmt.Errorf("alert_rule: subject_template compile failed: %w", err)
		}
	}
	if r.BodyTemplate != "" {
		if _, err := compileBodyTemplate(r.BodyTemplate); err != nil {
			return fmt.Errorf("alert_rule: body_template compile failed: %w", err)
		}
	}
	return nil
}

// WithDefaults returns a copy of r with omitted fields
// filled in. Called by the CRUD layer before Validate so
// an operator who leaves CooldownSecs at zero gets the
// 5-minute default, not a "must be ≥30" rejection.
func (r AlertRule) WithDefaults() AlertRule {
	if r.CooldownSecs == 0 {
		r.CooldownSecs = RuleCooldownSecsDefault
	}
	return r
}

// stringInSlice is the standard small helper. Lives here
// (file-local) since the alerting package doesn't pull
// in slices.Contains uniformly.
func stringInSlice(want string, xs []string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
