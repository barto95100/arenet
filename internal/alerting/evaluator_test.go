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
	"strings"
	"testing"
)

// AL.2.a — Evaluator pinning tests.
//
// Threshold: every operator × happy + edge + bad params.
// State: match + no-match + bad params.

func TestEvaluatorFor_UnknownKind(t *testing.T) {
	if _, err := EvaluatorFor("bogus"); err == nil {
		t.Errorf("EvaluatorFor bogus: nil err; want unsupported error")
	}
}

func TestThresholdEvaluator_AllOperators(t *testing.T) {
	cases := []struct {
		name     string
		operator string
		value    float64
		got      float64
		want     bool
	}{
		{"gt true", ">", 50, 51, true},
		{"gt false", ">", 50, 50, false},
		{"gte boundary", ">=", 50, 50, true},
		{"lt true", "<", 50, 49, true},
		{"lt false", "<", 50, 50, false},
		{"lte boundary", "<=", 50, 50, true},
		{"eq true", "==", 50, 50, true},
		{"eq false", "==", 50, 51, false},
		{"neq true", "!=", 50, 51, true},
		{"neq false", "!=", 50, 50, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(ThresholdParams{Operator: tc.operator, Value: tc.value})
			fired, err := thresholdEvaluator.Evaluate(FloatValue(tc.got), raw)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if fired != tc.want {
				t.Errorf("got=%v want=%v (got %.1f %s %.1f)",
					fired, tc.want, tc.got, tc.operator, tc.value)
			}
		})
	}
}

func TestThresholdEvaluator_ValidateParams_BadOperator(t *testing.T) {
	raw := json.RawMessage(`{"operator":"~","value":1}`)
	err := thresholdEvaluator.ValidateParams(raw)
	if err == nil || !strings.Contains(err.Error(), "operator") {
		t.Errorf("err = %v; want operator validation error", err)
	}
}

func TestThresholdEvaluator_ValidateParams_BadJSON(t *testing.T) {
	raw := json.RawMessage(`not json`)
	err := thresholdEvaluator.ValidateParams(raw)
	if err == nil {
		t.Errorf("nil err; want JSON decode error")
	}
}

func TestThresholdEvaluator_Evaluate_MissingFloat(t *testing.T) {
	raw, _ := json.Marshal(ThresholdParams{Operator: ">", Value: 1})
	fired, err := thresholdEvaluator.Evaluate(SourceValue{}, raw)
	if err == nil {
		t.Errorf("nil err; want missing-Float error")
	}
	if fired {
		t.Errorf("fired=true on error path; want false")
	}
}

func TestStateEvaluator_Match(t *testing.T) {
	raw, _ := json.Marshal(StateParams{Expected: "degraded"})
	fired, err := stateEvaluator.Evaluate(StringValue("degraded"), raw)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !fired {
		t.Errorf("fired=false; want true on match")
	}
}

func TestStateEvaluator_NoMatch(t *testing.T) {
	raw, _ := json.Marshal(StateParams{Expected: "degraded"})
	fired, err := stateEvaluator.Evaluate(StringValue("healthy"), raw)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if fired {
		t.Errorf("fired=true; want false on miss")
	}
}

func TestStateEvaluator_ValidateParams_EmptyExpected(t *testing.T) {
	raw := json.RawMessage(`{"expected":""}`)
	err := stateEvaluator.ValidateParams(raw)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("err = %v; want empty-expected error", err)
	}
}

func TestStateEvaluator_Evaluate_MissingString(t *testing.T) {
	raw, _ := json.Marshal(StateParams{Expected: "healthy"})
	_, err := stateEvaluator.Evaluate(SourceValue{}, raw)
	if err == nil {
		t.Errorf("nil err; want missing-String error")
	}
}
