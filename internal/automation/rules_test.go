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

package automation

import (
	"strings"
	"testing"
	"time"
)

func TestSource_Scenario_PrefixConvention(t *testing.T) {
	// Spec D3.3.A: scenario prefix MUST be "arenet/" so the
	// frontend filter `startsWith("arenet/")` correctly
	// identifies auto-classify decisions.
	for _, s := range AllSources() {
		got := s.Scenario()
		if !strings.HasPrefix(got, "arenet/") {
			t.Errorf("Scenario(%q) = %q, want arenet/* prefix", s, got)
		}
		if got != "arenet/"+string(s) {
			t.Errorf("Scenario(%q) = %q, want %q", s, got, "arenet/"+string(s))
		}
	}
}

func TestSource_IsKnown(t *testing.T) {
	for _, s := range AllSources() {
		if !s.IsKnown() {
			t.Errorf("AllSources entry %q reports IsKnown=false", s)
		}
	}
	for _, bad := range []Source{"", "waf-unknown", "auth-extra", "arenet/waf-sqli"} {
		if bad.IsKnown() {
			t.Errorf("unknown source %q reports IsKnown=true", bad)
		}
	}
}

func TestDefaultRuleSet_AllSourcesDisabled(t *testing.T) {
	rs := DefaultRuleSet()
	if len(rs.Rules) != len(AllSources()) {
		t.Fatalf("DefaultRuleSet has %d rules, want %d", len(rs.Rules), len(AllSources()))
	}
	for _, s := range AllSources() {
		r, ok := rs.Rules[s]
		if !ok {
			t.Errorf("DefaultRuleSet missing entry for %q", s)
			continue
		}
		if r.Enabled {
			t.Errorf("DefaultRuleSet[%q].Enabled = true, want false on fresh install", s)
		}
	}
	if rs.AnyEnabled() {
		t.Error("DefaultRuleSet.AnyEnabled() = true, want false")
	}
}

func TestDefaultRule_AsymmetricCooldownByCategory(t *testing.T) {
	// Spec §1.3 D5 rationale-of-record: cooldown defaults
	// encode the operator's mistake-distribution by category.
	// This test pins the asymmetry so a future refactor
	// can't quietly homogenise it.
	cases := []struct {
		s        Source
		wantCool time.Duration
		why      string
	}{
		{SourceAuthBurst, 7 * 24 * time.Hour, "operator unbans typically reflect real users"},
		{SourceWafSQLi, 24 * time.Hour, "false-positive suspicion, 24h investigation window"},
		{SourceWafRCE, 24 * time.Hour, "false-positive suspicion, 24h investigation window"},
		{SourceWafXSS, 24 * time.Hour, "false-positive suspicion, 24h investigation window"},
		{SourceWafLFI, 24 * time.Hour, "false-positive suspicion, 24h investigation window"},
		{SourceWafProtocol, 4 * time.Hour, "maintenance-action unbans, faster re-engagement"},
		{SourceWafOther, 4 * time.Hour, "maintenance-action unbans, faster re-engagement"},
		{SourceThrottleTier1, 4 * time.Hour, "maintenance-action unbans, faster re-engagement"},
		{SourceThrottleTier2, 4 * time.Hour, "maintenance-action unbans, faster re-engagement"},
	}
	for _, c := range cases {
		r := DefaultRule(c.s)
		if r.Cooldown != c.wantCool {
			t.Errorf("DefaultRule(%q).Cooldown = %s, want %s (%s)",
				c.s, r.Cooldown, c.wantCool, c.why)
		}
	}
}

func TestRule_Validate(t *testing.T) {
	cases := []struct {
		name    string
		r       Rule
		wantErr string
	}{
		{
			name: "disabled rule with zero fields OK",
			r:    Rule{Enabled: false},
		},
		{
			name: "enabled valid rule",
			r: Rule{
				Enabled:   true,
				Threshold: 2,
				Window:    60 * time.Second,
				Duration:  1 * time.Hour,
				Cooldown:  24 * time.Hour,
			},
		},
		{
			name:    "enabled threshold=0 rejected",
			r:       Rule{Enabled: true, Window: 1 * time.Second, Duration: 1 * time.Hour},
			wantErr: "threshold must be >= 1",
		},
		{
			name:    "enabled window=0 rejected",
			r:       Rule{Enabled: true, Threshold: 1, Duration: 1 * time.Hour},
			wantErr: "window must be > 0",
		},
		{
			name:    "enabled duration=0 rejected",
			r:       Rule{Enabled: true, Threshold: 1, Window: 1 * time.Second},
			wantErr: "duration must be > 0",
		},
		{
			name:    "enabled negative cooldown rejected",
			r:       Rule{Enabled: true, Threshold: 1, Window: 1 * time.Second, Duration: 1 * time.Hour, Cooldown: -1},
			wantErr: "cooldown must be >= 0",
		},
		{
			name: "enabled cooldown=0 allowed",
			r:    Rule{Enabled: true, Threshold: 1, Window: 1 * time.Second, Duration: 1 * time.Hour, Cooldown: 0},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.r.Validate(SourceWafSQLi)
			if c.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %q, want substring %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestRuleSet_Validate_RejectsUnknownSource(t *testing.T) {
	rs := RuleSet{Rules: map[Source]Rule{
		Source("bogus-source"): {Enabled: true, Threshold: 1, Window: 1 * time.Second, Duration: 1 * time.Hour},
	}}
	err := rs.Validate()
	if err == nil {
		t.Fatal("expected error on unknown source, got nil")
	}
	if !strings.Contains(err.Error(), "unknown source") {
		t.Errorf("err = %q, want substring 'unknown source'", err.Error())
	}
}

func TestRuleSet_AnyEnabled(t *testing.T) {
	if (RuleSet{}).AnyEnabled() {
		t.Error("zero-value RuleSet should report AnyEnabled=false")
	}
	rs := DefaultRuleSet()
	if rs.AnyEnabled() {
		t.Error("DefaultRuleSet should report AnyEnabled=false")
	}
	// Enable one rule → AnyEnabled true.
	r := rs.Rules[SourceWafSQLi]
	r.Enabled = true
	rs.Rules[SourceWafSQLi] = r
	if !rs.AnyEnabled() {
		t.Error("RuleSet with one enabled rule should report AnyEnabled=true")
	}
}
