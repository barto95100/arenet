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

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Step V.1.3 — operator-facing env-var parsers for the
// normal-traffic monitoring feature (spec §5). Kept in a
// separate file so the parse rules + their tests are
// co-located and main.go stays readable.
//
// Validation philosophy: invalid SAMPLE_PCT / cooldown
// values are FATAL at boot per the spec §5 contract.
// Silent fallback (e.g. "garbage" → 0 → V.1 silently
// disabled) would mislead an operator who set the var
// thinking they enabled the feature. EXCLUDE_PATHS is
// the one parser that's forgiving: empty + extra commas +
// whitespace are all noise the operator's shell can
// produce accidentally and don't change the semantic
// (every prefix in the result is a valid prefix).

// defaultNormalTrafficCooldown is the spec §D9 default
// when ARENET_NORMAL_TRAFFIC_PER_IP_COOLDOWN is unset.
const defaultNormalTrafficCooldown = 30 * time.Second

// parseNormalTrafficSamplePct parses
// ARENET_NORMAL_TRAFFIC_SAMPLE_PCT. Empty input → 0 (V.1
// disabled — the canonical "feature off" state). Non-empty
// non-integer or out-of-range [0, 100] → error (FATAL at
// boot; the operator sees a clear message instead of a
// silently-disabled V.1).
func parseNormalTrafficSamplePct(raw string) (int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not an integer", raw)
	}
	if n < 0 || n > 100 {
		return 0, fmt.Errorf("%d out of range [0, 100]", n)
	}
	return n, nil
}

// parseNormalTrafficCooldown parses
// ARENET_NORMAL_TRAFFIC_PER_IP_COOLDOWN as a Go duration
// (e.g. "30s", "5m", "1h"). Empty input → default 30s
// (spec §D9). Invalid input → error (FATAL at boot).
//
// Negative durations are accepted as a special value: they
// disable the per-IP cooldown gate inside the sink (the
// sink treats cooldown <= 0 as "no cooldown"). A future
// hardening could reject negatives explicitly; for now we
// pass them through so the operator can experiment.
func parseNormalTrafficCooldown(raw string) (time.Duration, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return defaultNormalTrafficCooldown, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid Go duration (e.g. 30s, 5m): %w", raw, err)
	}
	return d, nil
}

// parseNormalTrafficExcludePaths parses
// ARENET_NORMAL_TRAFFIC_EXCLUDE_PATHS as a
// comma-separated list of path prefixes. Empty / unset
// input returns nil so the caddymgr emit-omitempty path
// preserves byte-equality with pre-V.1.3 configs.
//
// Forgiving parser: leading/trailing whitespace around
// each entry is stripped; empty entries (from a trailing
// comma or "a,,b") are dropped; duplicates are deduped
// while preserving the operator's input order (first
// occurrence wins). The hardcoded V.1.2 list is never
// merged in here — the middleware's eligibleForNormal
// applies hardcoded + configured as TWO sequential prefix
// loops (extension, not replacement).
func parseNormalTrafficExcludePaths(raw string) []string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	seen := make(map[string]bool, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
