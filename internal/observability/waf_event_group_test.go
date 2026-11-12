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

package observability

import (
	"context"
	"testing"
	"time"
)

// v2.80.x — the waf_event_rate alert now attaches a breakdown (top source
// IPs, CRS rules, paths) so an operator can act on the spike instead of
// only reading its count. TopWafEventGroups is that breakdown's exact
// SQL top-N. These guard the three things the feature promises: the
// counts are exact (GROUP BY, not the 100-row cap), the window/filter is
// honoured, and a blank value never surfaces as a row.

func wafGroupEvent(ts time.Time, ip, rule, path string) WafEvent {
	return WafEvent{
		Ts:            ts,
		RouteID:       "r1",
		RuleID:        rule,
		Category:      "anomaly",
		Severity:      2,
		SrcIP:         ip,
		RequestMethod: "GET",
		RequestPath:   path,
		Action:        WafActionBlock,
		StatusCode:    403,
	}
}

func TestTopWafEventGroups_RanksAndRespectsWindow(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now()
	in := func(mins int) time.Time { return now.Add(-time.Duration(mins) * time.Minute) }

	batch := []WafEvent{
		// Inside the 5-minute window.
		wafGroupEvent(in(1), "1.1.1.1", "942100", "/a"),
		wafGroupEvent(in(2), "1.1.1.1", "942100", "/a"),
		wafGroupEvent(in(3), "1.1.1.1", "930110", "/a"),
		wafGroupEvent(in(1), "3.3.3.3", "930110", "/a"),
		wafGroupEvent(in(2), "3.3.3.3", "942100", "/b"),
		wafGroupEvent(in(1), "2.2.2.2", "942100", "/b"),
		// A blank source IP must never surface as a breakdown row.
		wafGroupEvent(in(1), "", "942100", "/c"),
		// Outside the window — must be excluded from every grouping.
		wafGroupEvent(in(120), "9.9.9.9", "942100", "/a"),
	}
	if err := s.InsertWafEventBatch(ctx, batch); err != nil {
		t.Fatalf("InsertWafEventBatch: %v", err)
	}

	filter := WafEventFilter{From: now.Add(-5 * time.Minute), To: now.Add(time.Minute)}

	// By source IP: 1.1.1.1=3, 3.3.3.3=2, 2.2.2.2=1 (blank + out-of-window gone).
	got, err := s.TopWafEventGroups(ctx, filter, "src_ip", 5)
	if err != nil {
		t.Fatalf("TopWafEventGroups(src_ip): %v", err)
	}
	wantIPs := []WafEventGroup{{"1.1.1.1", 3}, {"3.3.3.3", 2}, {"2.2.2.2", 1}}
	assertGroups(t, "src_ip", got, wantIPs)

	// By rule: 942100 fired 5× (incl. the blank-IP row, which is excluded
	// from the IP breakdown but still a real rule hit), 930110 2×. The
	// out-of-window 9.9.9.9 942100 row is excluded.
	got, err = s.TopWafEventGroups(ctx, filter, "rule_id", 5)
	if err != nil {
		t.Fatalf("TopWafEventGroups(rule_id): %v", err)
	}
	assertGroups(t, "rule_id", got, []WafEventGroup{{"942100", 5}, {"930110", 2}})

	// limit clamps the number of groups returned.
	got, err = s.TopWafEventGroups(ctx, filter, "src_ip", 1)
	if err != nil {
		t.Fatalf("TopWafEventGroups(limit=1): %v", err)
	}
	assertGroups(t, "src_ip limit=1", got, []WafEventGroup{{"1.1.1.1", 3}})

	// A non-whitelisted column is rejected, never interpolated into SQL.
	if _, err := s.TopWafEventGroups(ctx, filter, "src_ip; DROP TABLE waf_event", 5); err == nil {
		t.Fatal("expected error for non-whitelisted column, got nil")
	}
}

func assertGroups(t *testing.T, label string, got, want []WafEventGroup) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d groups %v, want %d %v", label, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: group[%d] = %v, want %v (full: %v)", label, i, got[i], want[i], got)
		}
	}
}
