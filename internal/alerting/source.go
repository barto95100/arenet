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
	"errors"
	"fmt"
	"sort"
	"sync"
)

// AL.2.a — Source interface + SourceValue + Registry.
//
// A Source wraps an existing subsystem (observability,
// certinfo, systemhealth, ...) and exposes a uniform
// Read(params) interface to the watcher. The watcher
// (AL.2.b) does NOT understand the underlying subsystems
// — it only knows "here's a Source.Name() and a JSON
// params blob; give me a SourceValue".
//
// V1 sources (this file's siblings):
//   - source_waf_event_rate.go : counts waf_event rows in
//     a sliding window (Float).
//   - source_cert_expiry.go    : days until earliest /
//     queried-domain cert NotAfter (Float).
//   - source_system_health.go  : current Status of a
//     component or the global aggregator (String).
//
// V2 candidates: throttle_event_rate, decision_event_rate,
// auth_failure_rate, route_health_state. Each lands as a
// new file in this package + a Register call in
// cmd/arenet/main.go's wiring block.

// SourceValue is the typed result of a Source.Read. A
// source returns EITHER Float (for threshold-style rules)
// OR String (for state-style rules) — never both. Labels
// + Context propagate to the AlertEvent built by the
// watcher (AL.2.b) so notifications carry source-side
// drill-down data without the watcher knowing source
// internals.
type SourceValue struct {
	// Float is the numeric output for threshold sources.
	// nil → this Source emits string-only values (state
	// sources). ThresholdEvaluator returns an error when
	// nil — the rule kind / source pairing is the CRUD
	// layer's responsibility (the rule editor UI gates
	// source × kind compatibility).
	Float *float64
	// String is the string output for state sources. nil
	// for threshold sources. StateEvaluator returns an
	// error when nil.
	String *string
	// Labels propagate to AlertEvent.Labels — operator-
	// readable string→string pairs (e.g. "route_id"="..",
	// "host"="..", "component"="crowdsec"). The watcher
	// merges these with operator-configured rule labels
	// (V2; V1 has none on AlertRule).
	Labels map[string]string
	// Context propagates to AlertEvent.Context — structured
	// payload for downstream consumers (alertmanager-
	// compatible processors). Free-form; the source
	// decides what's useful.
	Context map[string]any
}

// FloatValue is a convenience constructor — sources
// emitting numeric results call this rather than wiring
// the Float pointer field by hand.
func FloatValue(v float64) SourceValue {
	return SourceValue{Float: &v}
}

// StringValue is a convenience constructor for state-
// emitting sources.
func StringValue(v string) SourceValue {
	return SourceValue{String: &v}
}

// Source is the seam the AL.2.b watcher reads through.
// Implementations bridge to an existing subsystem (the
// observability store, the cert tracker, the health
// checker, ...) and expose a uniform Read interface.
//
// Sources must honour ctx (deadline-aware Read). The
// watcher supplies a per-tick deadline (default 5s) so a
// stuck source doesn't pin the polling loop.
type Source interface {
	// Name returns the stable identifier the
	// AlertRule.Source field references. MUST be unique
	// across the registry. Convention: lowercase, snake-
	// case ("waf_event_rate", "cert_expiry").
	Name() string

	// ValidateParams checks the params shape at rule
	// create/update time so a malformed config is rejected
	// at CRUD. Cheap + side-effect-free; the watcher's
	// per-tick path skips it (Read does its own decoding).
	ValidateParams(raw json.RawMessage) error

	// Read returns the current SourceValue or an error.
	// Called per polling tick by the watcher.
	Read(ctx context.Context, raw json.RawMessage) (SourceValue, error)
}

// SourceRegistry is the lookup the watcher + the CRUD
// layer share. Sources are registered at boot in
// cmd/arenet/main.go after the dependencies they need
// are available; the registry is then passed into the
// watcher + injected into RuleValidationDeps for the
// CRUD layer.
//
// Concurrency: Register is intended for boot-time use
// (single goroutine, before the watcher starts). Get is
// concurrent-safe via the RWMutex so the watcher's
// goroutine doesn't race a hot-reload-style Register
// from a future operator-driven re-config.
type SourceRegistry struct {
	mu      sync.RWMutex
	sources map[string]Source
}

// NewSourceRegistry returns an empty registry.
func NewSourceRegistry() *SourceRegistry {
	return &SourceRegistry{sources: make(map[string]Source)}
}

// Register adds a source to the registry. Returns an
// error if the name collides with an already-registered
// source — collision is always a wiring bug (two sources
// claiming the same Name token), never an operator
// runtime condition.
func (r *SourceRegistry) Register(s Source) error {
	if s == nil {
		return errors.New("source registry: cannot register nil source")
	}
	name := s.Name()
	if name == "" {
		return errors.New("source registry: source has empty Name()")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.sources[name]; exists {
		return fmt.Errorf("source registry: source %q already registered", name)
	}
	r.sources[name] = s
	return nil
}

// Get looks up a source by Name. Returns (nil, false)
// when the source is not registered. Satisfies the
// SourceLookup interface declared in rule.go.
func (r *SourceRegistry) Get(name string) (Source, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sources[name]
	return s, ok
}

// Names returns the registered source names in sorted
// order. Used by the CRUD layer's "/sources" listing
// endpoint (AL.3b) and by integration tests asserting
// the boot-time registration set.
func (r *SourceRegistry) Names() []string {
	r.mu.RLock()
	out := make([]string, 0, len(r.sources))
	for name := range r.sources {
		out = append(out, name)
	}
	r.mu.RUnlock()
	sort.Strings(out)
	return out
}
