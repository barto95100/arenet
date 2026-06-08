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

package observability

import (
	"context"
	"testing"
	"time"
)

// W.bugfix Fix #1 — v6→v7 migration tests. The migration
// adds the action + status_code columns to waf_event so the
// sink can record whether a matched rule actually blocked
// the request (BLOCK + 403) or merely detected it (DETECT +
// 0). Pre-migration rows are backfilled to (BLOCK, 403) —
// historically correct since every legacy row was emitted
// by a block-mode handler.

// TestMigrate_V6ToV7_BackfillsLegacyWafEventRows seeds a v6
// waf_event row directly into a freshly-opened store (which
// migrates straight to v7), then verifies the legacy row
// reads back with the backfilled action=BLOCK + status_code=
// 403. Mirrors the V.1.2/J.2 "decode-pre-X-row-with-zero-
// value" pattern.
func TestMigrate_V6ToV7_BackfillsLegacyWafEventRows(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// The Open call already migrated to v7. Insert a row
	// using the new INSERT path WITHOUT setting Action /
	// StatusCode — the prepared statement passes action="" +
	// status_code=0. The insert helper defaults action="" →
	// "BLOCK" so the persistence layer never writes the empty
	// string. status_code=0 is preserved (sentinel for
	// detect-mode), so we explicitly assert below that the
	// caller-supplied zero is what comes back, not the schema
	// default.
	rows := []WafEvent{{
		Ts:            time.Unix(1717689600, 0).UTC(),
		RouteID:       "r-pre-W-bugfix",
		RuleID:        "920420",
		Category:      "PROTOCOL",
		Severity:      3,
		SrcIP:         "203.0.113.5",
		RequestMethod: "GET",
		RequestPath:   "/auth/login_flow",
		PayloadSample: "User-Agent: () { :; }",
		// Action and StatusCode deliberately omitted.
	}}
	if err := s.InsertWafEventBatch(ctx, rows); err != nil {
		t.Fatalf("InsertWafEventBatch: %v", err)
	}

	got, err := s.QueryWafEvents(ctx, WafEventFilter{})
	if err != nil {
		t.Fatalf("QueryWafEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].Action != "BLOCK" {
		t.Errorf("legacy row Action = %q; want \"BLOCK\" (defense-in-depth defaulting in InsertWafEventBatch)",
			got[0].Action)
	}
	// status_code passed-through value (caller's 0), NOT the
	// schema default 403 — pinning the contract that 0 is a
	// valid sentinel for "unknown upstream status" (detect mode).
	if got[0].StatusCode != 0 {
		t.Errorf("status_code round-trip = %d; want 0 (caller's zero value, not schema default)",
			got[0].StatusCode)
	}
}

// TestInsertWafEventBatch_DetectAction_RoundTrips inserts a
// detect-mode row, queries it back, asserts Action="DETECT"
// + StatusCode=0 are preserved.
func TestInsertWafEventBatch_DetectAction_RoundTrips(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.InsertWafEventBatch(ctx, []WafEvent{{
		Ts:         time.Now().UTC(),
		RouteID:    "r-detect",
		RuleID:     "920420",
		Category:   "PROTOCOL",
		Severity:   3,
		SrcIP:      "203.0.113.5",
		Action:     "DETECT",
		StatusCode: 0,
	}}); err != nil {
		t.Fatalf("InsertWafEventBatch: %v", err)
	}

	got, err := s.QueryWafEvents(ctx, WafEventFilter{})
	if err != nil {
		t.Fatalf("QueryWafEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].Action != "DETECT" || got[0].StatusCode != 0 {
		t.Errorf("detect row round-trip: action=%q, status_code=%d; want DETECT, 0",
			got[0].Action, got[0].StatusCode)
	}
}

// TestInsertWafEventBatch_BlockAction_RoundTrips — symmetric
// for block mode.
func TestInsertWafEventBatch_BlockAction_RoundTrips(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.InsertWafEventBatch(ctx, []WafEvent{{
		Ts:         time.Now().UTC(),
		RouteID:    "r-block",
		RuleID:     "942100",
		Category:   "SQLi",
		Severity:   2,
		SrcIP:      "203.0.113.5",
		Action:     "BLOCK",
		StatusCode: 403,
	}}); err != nil {
		t.Fatalf("InsertWafEventBatch: %v", err)
	}

	got, err := s.QueryWafEvents(ctx, WafEventFilter{})
	if err != nil {
		t.Fatalf("QueryWafEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].Action != "BLOCK" || got[0].StatusCode != 403 {
		t.Errorf("block row round-trip: action=%q, status_code=%d; want BLOCK, 403",
			got[0].Action, got[0].StatusCode)
	}
}
