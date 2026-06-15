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
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// AL.2.a — AlertRule.Validate pinning tests. Covers the
// D5 invariants: name slug, kind enum, source exists,
// channels non-empty + exist, cooldown range, evaluator
// params shape, template compile.

// stubSourceLookup is a SourceLookup backed by a static
// map. Tests register the names they need and assert
// Validate's "source exists" check fires for missing
// ones.
type stubSourceLookup struct {
	known map[string]Source
}

func (s *stubSourceLookup) Get(name string) (Source, bool) {
	src, ok := s.known[name]
	return src, ok
}

// passthroughSource accepts any params + always returns a
// canned value. Lets rule.Validate's source-side
// ValidateParams pass without setting up a real Source.
type passthroughSource struct {
	name    string
	wantErr error
}

func (p *passthroughSource) Name() string                              { return p.name }
func (p *passthroughSource) ValidateParams(_ json.RawMessage) error    { return p.wantErr }
func (p *passthroughSource) Read(_ context.Context, _ json.RawMessage) (SourceValue, error) {
	return FloatValue(0), nil
}

func validRule() AlertRule {
	return AlertRule{
		ID:           "11111111-1111-1111-1111-111111111111",
		Name:         "block-rate-high",
		Enabled:      true,
		Kind:         RuleKindThreshold,
		Severity:     SeverityWarning,
		Category:     "waf",
		Source:       "waf_event_rate",
		SourceParams: json.RawMessage(`{"windowSecs":300}`),
		EvalParams:   json.RawMessage(`{"operator":">","value":50}`),
		Channels:     []string{"ch-1"},
		CooldownSecs: 300,
	}
}

func validDeps() RuleValidationDeps {
	return RuleValidationDeps{
		Sources: &stubSourceLookup{known: map[string]Source{
			"waf_event_rate": &passthroughSource{name: "waf_event_rate"},
		}},
		ChannelExists: func(id string) bool { return id == "ch-1" },
	}
}

func TestAlertRule_Validate_Happy(t *testing.T) {
	if err := validRule().Validate(validDeps()); err != nil {
		t.Fatalf("Validate happy path: %v", err)
	}
}

func TestAlertRule_Validate_NameInvalid(t *testing.T) {
	r := validRule()
	r.Name = "Block Rate High!" // uppercase + space + bang
	err := r.Validate(validDeps())
	if err == nil || !strings.Contains(err.Error(), "name") {
		t.Errorf("err = %v; want name validation error", err)
	}
}

func TestAlertRule_Validate_KindInvalid(t *testing.T) {
	r := validRule()
	r.Kind = "bogus"
	err := r.Validate(validDeps())
	if err == nil || !strings.Contains(err.Error(), "kind") {
		t.Errorf("err = %v; want kind validation error", err)
	}
}

func TestAlertRule_Validate_SourceNotRegistered(t *testing.T) {
	r := validRule()
	r.Source = "ghost_source"
	err := r.Validate(validDeps())
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Errorf("err = %v; want 'not registered' error", err)
	}
}

func TestAlertRule_Validate_ChannelNotExists(t *testing.T) {
	r := validRule()
	r.Channels = []string{"ch-1", "ch-ghost"}
	err := r.Validate(validDeps())
	if err == nil || !strings.Contains(err.Error(), "ch-ghost") {
		t.Errorf("err = %v; want missing-channel error mentioning ch-ghost", err)
	}
}

func TestAlertRule_Validate_NoChannels(t *testing.T) {
	r := validRule()
	r.Channels = nil
	err := r.Validate(validDeps())
	if err == nil || !strings.Contains(err.Error(), "channels") {
		t.Errorf("err = %v; want channels-empty error", err)
	}
}

func TestAlertRule_Validate_CooldownTooLow(t *testing.T) {
	r := validRule()
	r.CooldownSecs = 5
	err := r.Validate(validDeps())
	if err == nil || !strings.Contains(err.Error(), "cooldown") {
		t.Errorf("err = %v; want cooldown range error", err)
	}
}

func TestAlertRule_Validate_CooldownTooHigh(t *testing.T) {
	r := validRule()
	r.CooldownSecs = 1_000_000
	err := r.Validate(validDeps())
	if err == nil || !strings.Contains(err.Error(), "cooldown") {
		t.Errorf("err = %v; want cooldown range error", err)
	}
}

func TestAlertRule_Validate_EvalParamsBadOperator(t *testing.T) {
	r := validRule()
	r.EvalParams = json.RawMessage(`{"operator":"~","value":50}`)
	err := r.Validate(validDeps())
	if err == nil || !strings.Contains(err.Error(), "operator") {
		t.Errorf("err = %v; want operator validation error", err)
	}
}

func TestAlertRule_Validate_TemplateInvalid(t *testing.T) {
	r := validRule()
	r.BodyTemplate = `{{.UnterminatedAction`
	err := r.Validate(validDeps())
	if err == nil || !strings.Contains(err.Error(), "body_template") {
		t.Errorf("err = %v; want body_template compile error", err)
	}
}

func TestAlertRule_Validate_SkipsRegistryWhenNil(t *testing.T) {
	// With nil Sources + nil ChannelExists, intrinsic
	// checks still pass — the cross-ref deps are tolerated
	// as absent. Used by tests asserting other invariants
	// without setting up the registry.
	r := validRule()
	if err := r.Validate(RuleValidationDeps{}); err != nil {
		t.Errorf("Validate with nil deps: %v", err)
	}
}

func TestAlertRule_WithDefaults_CooldownZero(t *testing.T) {
	r := AlertRule{CooldownSecs: 0}
	if got := r.WithDefaults().CooldownSecs; got != RuleCooldownSecsDefault {
		t.Errorf("CooldownSecs after defaults = %d; want %d", got, RuleCooldownSecsDefault)
	}
}
