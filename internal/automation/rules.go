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
	"errors"
	"fmt"
	"time"
)

// Source enumerates the auto-classify categories the trigger
// engine watches. Spec D2.3.A: per-category toggle, the
// operator opts in to each one independently. The string
// values double as the suffix of the LAPI decision scenario
// (e.g. "arenet/waf-sqli", per D3.3.A).
type Source string

const (
	// WAF categories — match observability.WafEvent.Category
	// (the OWASP enum from internal/waf/event.go).
	SourceWafSQLi     Source = "waf-sqli"
	SourceWafXSS      Source = "waf-xss"
	SourceWafRCE      Source = "waf-rce"
	SourceWafLFI      Source = "waf-lfi"
	SourceWafProtocol Source = "waf-protocol"
	SourceWafOther    Source = "waf-other"

	// Throttle tiers — match observability.ThrottleEvent.Tier
	// (the 1 / 2 enum from Step Q).
	SourceThrottleTier1 Source = "throttle-tier1"
	SourceThrottleTier2 Source = "throttle-tier2"

	// AuthBurst rolls up all auth-failure actions
	// (login_failure, unlock_failure, oidc_login_rejected,
	// oidc_callback_invalid) into one rule. Each individual
	// action's count contributes to the threshold; the
	// operator-facing knob is the aggregate.
	SourceAuthBurst Source = "auth-burst"
)

// AllSources lists every Source value. Used by the API layer
// to materialise default rules on PUT, and by validation to
// reject unknown source strings.
func AllSources() []Source {
	return []Source{
		SourceWafSQLi, SourceWafXSS, SourceWafRCE, SourceWafLFI,
		SourceWafProtocol, SourceWafOther,
		SourceThrottleTier1, SourceThrottleTier2,
		SourceAuthBurst,
	}
}

// Scenario returns the LAPI scenario string for a Source.
// Spec D3.3.A: prefix "arenet/" so frontend filters
// (scenario.startsWith("arenet/")) identify auto-classify
// decisions vs community-blocklist / cscli-added ones.
func (s Source) Scenario() string {
	return "arenet/" + string(s)
}

// IsKnown reports whether s is one of the AllSources values.
// Validation gate for the rule set on PUT.
func (s Source) IsKnown() bool {
	for _, k := range AllSources() {
		if s == k {
			return true
		}
	}
	return false
}

// Rule is the operator-facing configuration for one Source.
// Disabled rules are inert; the trigger engine skips them
// without querying the underlying event store (so a fresh-
// install Arenet with all rules disabled does zero query
// work per tick).
//
// Defaults per spec §1.3 D5 rationale (asymmetric cooldown
// by category, encoded in DefaultRule()).
type Rule struct {
	// Enabled is the per-category opt-in (D2.3.A). Default
	// false: a fresh boot has every rule off; the operator
	// explicitly enables each one in Settings.
	Enabled bool `json:"enabled"`

	// Threshold is the minimum event count from a single
	// src_ip within Window before the rule fires. D2.2.A
	// aggregated-window model — single-event false-positives
	// don't trigger.
	Threshold int `json:"threshold"`

	// Window is the sliding-window duration in which
	// Threshold events from the same src_ip must occur for
	// the rule to fire.
	Window time.Duration `json:"window_ns"`

	// Duration is the ban duration LAPI honours when the
	// rule fires. Spec D3.2.A — operator-configurable per
	// rule, defaults set by OWASP severity rough mapping.
	Duration time.Duration `json:"duration_ns"`

	// Cooldown is the operator-tombstone honour window per
	// (src_ip, scenario) (D5.A). When the operator manually
	// unbans an IP that auto-classify banned, no re-ban for
	// this duration. Defaults asymmetric by category (see
	// DefaultRule() rationale).
	Cooldown time.Duration `json:"cooldown_ns"`
}

// RuleSet maps every Source to its Rule. Persisted as a
// single BoltDB row keyed "rules" under bucketAutomation. The
// map shape (vs a flat list of typed fields) keeps the JSON
// round-trip operator-friendly: adding a new Source value in
// a future step doesn't break the wire shape.
type RuleSet struct {
	Rules map[Source]Rule `json:"rules"`
}

// DefaultRuleSet returns a fresh-install RuleSet with every
// Source disabled (Enabled=false). The Threshold / Window /
// Duration / Cooldown defaults per Source are pre-populated
// so an operator who flips Enabled=true on the UI gets
// sensible behaviour without configuring everything from
// zero.
func DefaultRuleSet() RuleSet {
	rs := RuleSet{Rules: make(map[Source]Rule, len(AllSources()))}
	for _, s := range AllSources() {
		rs.Rules[s] = DefaultRule(s)
	}
	return rs
}

// DefaultRule returns the (disabled-by-default) Rule for a
// Source with category-appropriate thresholds + durations +
// cooldowns. Documented inline so an operator reading the
// fresh-install state in Settings sees why each default is
// what it is.
//
// Cooldown asymmetry per spec §1.3 D5 rationale-of-record:
//   - AUTH 7 days: operator unbans typically reflect "real
//     user, please leave them alone" — trust longer.
//   - SQLi/RCE/XSS/LFI 24h: operator unbans typically reflect
//     false-positive suspicion — re-engage if the IP keeps
//     producing matches after the investigation window.
//   - PROTOCOL/OTHER/Throttle 4h: maintenance-action unbans
//     reasonably re-engage faster.
func DefaultRule(s Source) Rule {
	switch s {
	case SourceWafSQLi:
		// Severity-high attack. Aggregate 2 in 60s before
		// banning (single event = potential false positive
		// from a real user fumbling a query); ban 4h;
		// cooldown 24h on operator unban.
		return Rule{Enabled: false, Threshold: 2, Window: 60 * time.Second, Duration: 4 * time.Hour, Cooldown: 24 * time.Hour}
	case SourceWafRCE:
		// Unambiguous attack. Tight threshold (2/60s), long
		// ban (24h — RCE attempts justify a longer cooldown
		// at the attacker side), 24h operator-trust cooldown.
		return Rule{Enabled: false, Threshold: 2, Window: 60 * time.Second, Duration: 24 * time.Hour, Cooldown: 24 * time.Hour}
	case SourceWafXSS:
		// Severity-medium. 2/60s, 1h ban, 24h operator-trust.
		return Rule{Enabled: false, Threshold: 2, Window: 60 * time.Second, Duration: 1 * time.Hour, Cooldown: 24 * time.Hour}
	case SourceWafLFI:
		// Severity-medium-to-high. Like SQLi profile.
		return Rule{Enabled: false, Threshold: 2, Window: 60 * time.Second, Duration: 4 * time.Hour, Cooldown: 24 * time.Hour}
	case SourceWafProtocol:
		// Often noisy (broken clients, debugging tools). Higher
		// threshold + shorter ban + shorter cooldown so a
		// false-positive doesn't sit on a real user's IP.
		return Rule{Enabled: false, Threshold: 5, Window: 60 * time.Second, Duration: 15 * time.Minute, Cooldown: 4 * time.Hour}
	case SourceWafOther:
		// Catch-all bucket. Same shape as PROTOCOL.
		return Rule{Enabled: false, Threshold: 5, Window: 60 * time.Second, Duration: 15 * time.Minute, Cooldown: 4 * time.Hour}
	case SourceThrottleTier1:
		// Tier 1 = first-level rate-limit trip. Modest ban.
		return Rule{Enabled: false, Threshold: 1, Window: 60 * time.Second, Duration: 15 * time.Minute, Cooldown: 4 * time.Hour}
	case SourceThrottleTier2:
		// Tier 2 = escalated rate-limit trip. Heavier ban.
		return Rule{Enabled: false, Threshold: 1, Window: 60 * time.Second, Duration: 1 * time.Hour, Cooldown: 4 * time.Hour}
	case SourceAuthBurst:
		// Credential-stuffing signal. 10 failures in 5min is
		// the canonical pattern; ban 4h (long enough to deter
		// the script). Cooldown 7d on operator unban — see
		// §1.3 D5 rationale.
		return Rule{Enabled: false, Threshold: 10, Window: 5 * time.Minute, Duration: 4 * time.Hour, Cooldown: 7 * 24 * time.Hour}
	default:
		// Unknown source: zero-value rule (disabled, no
		// thresholds). The validator catches this on PUT;
		// this branch is defensive against future enum
		// extensions that forget to update the switch.
		return Rule{}
	}
}

// Validate runs strict shape checks. Called by the API layer
// before PUT-persisting a RuleSet, and by the storage layer
// as the last line of defence. Errors carry the offending
// source name so the operator's UI can highlight the field.
func (r Rule) Validate(source Source) error {
	if !r.Enabled {
		// Disabled rule: the other fields are inert. Don't
		// validate them — an operator who flips the toggle
		// off and ships a zero-valued rule should not be
		// blocked by "threshold must be >= 1".
		return nil
	}
	if r.Threshold < 1 {
		return fmt.Errorf("rule[%s]: threshold must be >= 1 when enabled, got %d", source, r.Threshold)
	}
	if r.Window <= 0 {
		return fmt.Errorf("rule[%s]: window must be > 0 when enabled, got %s", source, r.Window)
	}
	if r.Duration <= 0 {
		return fmt.Errorf("rule[%s]: duration must be > 0 when enabled, got %s", source, r.Duration)
	}
	if r.Cooldown < 0 {
		return fmt.Errorf("rule[%s]: cooldown must be >= 0 when enabled, got %s", source, r.Cooldown)
	}
	return nil
}

// Validate runs Rule.Validate on every entry + checks the map
// only contains known Source values. Empty map is accepted
// (treated as "every source disabled" by the engine).
func (rs RuleSet) Validate() error {
	if rs.Rules == nil {
		return nil
	}
	for s, r := range rs.Rules {
		if !s.IsKnown() {
			return fmt.Errorf("rule_set: unknown source %q", s)
		}
		if err := r.Validate(s); err != nil {
			return err
		}
	}
	return nil
}

// AnyEnabled reports whether at least one rule is enabled.
// Used by the engine's tick to short-circuit: when no rule
// is enabled, the tick does zero queries.
func (rs RuleSet) AnyEnabled() bool {
	for _, r := range rs.Rules {
		if r.Enabled {
			return true
		}
	}
	return false
}

// ErrUnknownSource is the sentinel returned by lookup paths
// when a Source string from a future enum extension doesn't
// match AllSources(). Callers (the API layer) translate it
// into a 400 with the offending name.
var ErrUnknownSource = errors.New("automation: unknown source")
