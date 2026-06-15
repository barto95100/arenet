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
)

// AL.2.a — RuleEvaluator interface + two concrete
// implementations (threshold + state). The watcher
// (AL.2.b) looks up the evaluator by Kind, asks it to
// validate the rule's EvalParams at boot/edit time, then
// calls Evaluate per polling tick with the freshly-read
// SourceValue.

// RuleEvaluator is the seam the watcher calls per
// polling tick. Evaluate returns true when the rule
// condition is met (= fire). The evalParams are the
// rule's EvalParams blob; each evaluator owns its own
// param shape.
//
// Stateless by design: the watcher creates fresh
// evaluator instances per rule and never caches them
// across rule edits. The tradeoff is per-tick JSON
// unmarshal of EvalParams — measured at ~5µs on a
// homelab; the polling interval (30s default) dwarfs it.
type RuleEvaluator interface {
	// Kind returns the wire-shape token identifying the
	// evaluator (RuleKindThreshold, RuleKindState). Used
	// for symbolic dispatch; mirrors AlertSender.Kind().
	Kind() string

	// ValidateParams checks the EvalParams shape at
	// rule create/update time so a malformed config is
	// rejected at the CRUD layer instead of every 30s at
	// the watcher tick. Implementations must be cheap +
	// side-effect-free.
	ValidateParams(raw json.RawMessage) error

	// Evaluate returns (fired, error). fired=true means
	// the rule condition is currently met; the watcher
	// then runs cooldown + dedupe + dispatch. err != nil
	// means the evaluator could not decide (malformed
	// params at runtime, mismatched SourceValue type);
	// the watcher records LastError and skips dispatch.
	Evaluate(value SourceValue, raw json.RawMessage) (bool, error)
}

// EvaluatorFor returns the canonical evaluator instance
// for a rule kind. The instances are stateless so a
// package-level singleton is safe.
func EvaluatorFor(kind string) (RuleEvaluator, error) {
	switch kind {
	case RuleKindThreshold:
		return thresholdEvaluator, nil
	case RuleKindState:
		return stateEvaluator, nil
	default:
		return nil, fmt.Errorf("unsupported rule kind %q", kind)
	}
}

// thresholdEvaluator is the singleton instance returned
// by EvaluatorFor for RuleKindThreshold.
var thresholdEvaluator RuleEvaluator = &ThresholdEvaluator{}

// stateEvaluator is the singleton instance returned by
// EvaluatorFor for RuleKindState.
var stateEvaluator RuleEvaluator = &StateEvaluator{}

// ThresholdEvaluator compares SourceValue.Float against
// a constant using an operator. Used for rate-style
// rules ("WAF blocks > 50 over 5min", "cert expires in
// < 14 days").
type ThresholdEvaluator struct{}

// ThresholdParams is the EvalParams shape for
// ThresholdEvaluator.
type ThresholdParams struct {
	// Operator is one of [">", ">=", "<", "<=", "==", "!="].
	Operator string `json:"operator"`
	// Value is the right-hand side of the comparison.
	Value float64 `json:"value"`
}

// thresholdOperators is the closed set of supported
// comparison tokens. The watcher's per-tick path never
// allocates this slice; only ValidateParams uses it for
// the error message.
var thresholdOperators = []string{">", ">=", "<", "<=", "==", "!="}

func (e *ThresholdEvaluator) Kind() string { return RuleKindThreshold }

func (e *ThresholdEvaluator) ValidateParams(raw json.RawMessage) error {
	var p ThresholdParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("threshold: params not valid JSON: %w", err)
	}
	if !stringInSlice(p.Operator, thresholdOperators) {
		return fmt.Errorf("threshold: operator %q must be one of %v",
			p.Operator, thresholdOperators)
	}
	// Value=0 is allowed (operators may want "fire on any
	// nonzero count" via ">" 0). No range check.
	return nil
}

func (e *ThresholdEvaluator) Evaluate(value SourceValue, raw json.RawMessage) (bool, error) {
	var p ThresholdParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return false, fmt.Errorf("threshold: params decode: %w", err)
	}
	if value.Float == nil {
		return false, errors.New("threshold: source value missing Float (source returned non-numeric value)")
	}
	v := *value.Float
	switch p.Operator {
	case ">":
		return v > p.Value, nil
	case ">=":
		return v >= p.Value, nil
	case "<":
		return v < p.Value, nil
	case "<=":
		return v <= p.Value, nil
	case "==":
		return v == p.Value, nil
	case "!=":
		return v != p.Value, nil
	default:
		// Should never reach — ValidateParams gates this at
		// create time. Defensive in case a stored rule was
		// written by an older arenet with a wider operator
		// set.
		return false, fmt.Errorf("threshold: unsupported operator %q", p.Operator)
	}
}

// StateEvaluator matches SourceValue.String against a
// literal expected value. Used for status-style rules
// ("crowdsec component status == degraded").
type StateEvaluator struct{}

// StateParams is the EvalParams shape for StateEvaluator.
type StateParams struct {
	// Expected is the literal string the SourceValue.String
	// must match for the rule to fire. Case-sensitive
	// (sources return canonical lower-case tokens; an
	// operator typo at config time should surface as a
	// rule that never fires, NOT as a silent match against
	// a different status).
	Expected string `json:"expected"`
}

func (e *StateEvaluator) Kind() string { return RuleKindState }

func (e *StateEvaluator) ValidateParams(raw json.RawMessage) error {
	var p StateParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("state: params not valid JSON: %w", err)
	}
	if p.Expected == "" {
		return errors.New("state: expected must not be empty")
	}
	return nil
}

func (e *StateEvaluator) Evaluate(value SourceValue, raw json.RawMessage) (bool, error) {
	var p StateParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return false, fmt.Errorf("state: params decode: %w", err)
	}
	if value.String == nil {
		return false, errors.New("state: source value missing String (source returned non-string value)")
	}
	return *value.String == p.Expected, nil
}
