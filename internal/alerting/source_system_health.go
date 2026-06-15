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

	"github.com/barto95100/arenet/internal/systemhealth"
)

// AL.2.a — system_health Source.
//
// Reads the /system/health checker's Report and surfaces
// the global or per-component Status as a SourceValue.
// String. The Status enum values ("healthy" / "degraded"
// / "unhealthy") are stable wire tokens — a StateEvaluator
// rule reading {expected: "degraded"} fires when the
// component drops below healthy.
//
// Reader audit (commit body): *systemhealth.HealthChecker
// already exposes Run(ctx) Report. Report has both a
// global Status field and a Components []NamedReport slice
// for per-component lookup. No checker modification
// needed.

// SystemHealthParams is the Source.Read params shape.
type SystemHealthParams struct {
	// Component is the per-check name to look up
	// ("caddy", "boltdb", "metrics", "crowdsec",
	// "certmagic"). Empty = use the global Report.Status.
	Component string `json:"component,omitempty"`
}

// SystemHealthRunner is the seam the source reads through.
// *systemhealth.HealthChecker satisfies it via Run.
type SystemHealthRunner interface {
	Run(ctx context.Context) systemhealth.Report
}

// SystemHealthSource emits the current component or
// global health status as a String.
type SystemHealthSource struct {
	runner SystemHealthRunner
}

// NewSystemHealthSource constructs the source. runner
// may be nil — Read returns an error so the watcher
// records the boot-degraded state.
func NewSystemHealthSource(runner SystemHealthRunner) *SystemHealthSource {
	return &SystemHealthSource{runner: runner}
}

// Name implements Source.
func (s *SystemHealthSource) Name() string { return "system_health" }

// ValidateParams implements Source. Component is free-form
// (the systemhealth checker may add components in future
// releases); we don't gate the value here so a rule
// configured for a not-yet-implemented component surfaces
// the error at Read time with a clear "component not
// found" message rather than a CRUD-time rejection that
// would block forward-looking configs.
func (s *SystemHealthSource) ValidateParams(raw json.RawMessage) error {
	var p SystemHealthParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("system_health: params not valid JSON: %w", err)
	}
	return nil
}

// Read implements Source.
func (s *SystemHealthSource) Read(ctx context.Context, raw json.RawMessage) (SourceValue, error) {
	if s.runner == nil {
		return SourceValue{}, errors.New("system_health: health checker not wired (boot-degraded)")
	}
	var p SystemHealthParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return SourceValue{}, fmt.Errorf("system_health: params decode: %w", err)
	}

	report := s.runner.Run(ctx)
	if p.Component == "" {
		v := StringValue(string(report.Status))
		v.Labels = map[string]string{
			"scope": "global",
		}
		return v, nil
	}

	// Per-component lookup. Components is an ordered
	// slice (not a map) so order-of-checks stays stable
	// in the wire shape; here we iterate it linearly —
	// the slice length is ≤ 5 at the time of writing, so
	// a map index buys nothing.
	for _, c := range report.Components {
		if c.Name == p.Component {
			v := StringValue(string(c.Status))
			v.Labels = map[string]string{
				"scope":     "component",
				"component": c.Name,
			}
			if c.Message != "" {
				v.Context = map[string]any{
					"message":    c.Message,
					"latency_ms": c.LatencyMs,
				}
			}
			return v, nil
		}
	}
	return SourceValue{}, fmt.Errorf("system_health: component %q not found in report", p.Component)
}
