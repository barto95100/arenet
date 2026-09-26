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

// v2.36 — v12→v13 adds waf_event.matched_var.

func TestWafEvent_MatchedVar_RoundTrips(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	rows := []WafEvent{
		{Ts: time.Unix(1790000000, 0).UTC(), RouteID: "r", RuleID: "942100", Action: "BLOCK", StatusCode: 403, MatchedVar: "ARGS:content"},
		{Ts: time.Unix(1790000001, 0).UTC(), RouteID: "r", RuleID: "920350", Action: "DETECT"},
	}
	if err := s.InsertWafEventBatch(ctx, rows); err != nil {
		t.Fatalf("InsertWafEventBatch: %v", err)
	}
	got, err := s.QueryWafEvents(ctx, WafEventFilter{})
	if err != nil {
		t.Fatalf("QueryWafEvents: %v", err)
	}
	byRule := map[string]string{}
	for _, e := range got {
		byRule[e.RuleID] = e.MatchedVar
	}
	if byRule["942100"] != "ARGS:content" {
		t.Errorf("942100 MatchedVar = %q, want ARGS:content", byRule["942100"])
	}
	if byRule["920350"] != "" {
		t.Errorf("920350 MatchedVar = %q, want empty", byRule["920350"])
	}
}

// A row written without the column (as by a pre-v13 binary) reads
// back with an empty matched_var.
func TestMigrate_V12ToV13_LegacyRowDefaultsEmpty(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if _, err := s.db.ExecContext(ctx, `INSERT INTO waf_event
		(ts, route_id, rule_id, category, severity, src_ip, request_method, request_path, payload_sample, action, status_code)
		VALUES (1790000000, 'r', '942100', 'SQLI', 2, '', '', '/x', '', 'BLOCK', 403)`); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	got, err := s.QueryWafEvents(ctx, WafEventFilter{})
	if err != nil {
		t.Fatalf("QueryWafEvents: %v", err)
	}
	if len(got) != 1 || got[0].MatchedVar != "" {
		t.Fatalf("legacy row = %+v, want one row with empty MatchedVar", got)
	}
}
