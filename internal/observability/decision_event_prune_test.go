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

// TestPruneDecisionEventsOlderThan_DeletesOlderRows pins the
// 30d retention horizon for decision_event rows (Step N spec
// D8.A). Backlog finding #N.5-1 surfaced this as a coverage
// gap: PruneDecisionEventsOlderThan was wired into the
// retention loop without a dedicated unit test.
//
// Uses an in-memory SQLite store + a synthetic clock (no wall-
// clock sleep). Mirrors TestStore_PruneOlderThan's shape.
//
// Coverage:
//  1. Pre-cutoff row deleted, post-cutoff row preserved.
//  2. Row count returned matches actual deletions.
//  3. Repeat-prune is idempotent (already-pruned rows
//     count as 0 deletions; survivors stay).
//  4. Soft-deleted rows (ExpiresAt updated by MarkDecisionExpired)
//     still prune by Ts, not by ExpiresAt — the retention
//     horizon is the OBSERVATION time, not the LAPI ban
//     duration. An operator investigating a 29d-old incident
//     finds the forensic row even if the decision was revoked
//     5 minutes after issuance.
func TestPruneDecisionEventsOlderThan_DeletesOlderRows(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-30 * 24 * time.Hour) // 30d retention horizon

	// Three rows:
	//   - oldRow @ now - 31d → should prune.
	//   - boundaryRow @ now - 30d → should prune (cutoff is strict `<`).
	//   - freshRow @ now - 29d → should survive.
	oldRow := DecisionEvent{
		UUID:            "uuid-old",
		Ts:              now.Add(-31 * 24 * time.Hour),
		Scope:           "ip",
		Value:           "10.0.0.1",
		Type:            "ban",
		Scenario:        "smoke/test",
		ExpiresAt:       now.Add(-30 * 24 * time.Hour),
		DurationSeconds: 86400,
	}
	boundaryRow := DecisionEvent{
		UUID:            "uuid-boundary",
		Ts:              cutoff.Add(-1 * time.Second),
		Scope:           "ip",
		Value:           "10.0.0.2",
		Type:            "ban",
		Scenario:        "smoke/test",
		ExpiresAt:       now,
		DurationSeconds: 86400,
	}
	freshRow := DecisionEvent{
		UUID:            "uuid-fresh",
		Ts:              now.Add(-29 * 24 * time.Hour),
		Scope:           "ip",
		Value:           "10.0.0.3",
		Type:            "ban",
		Scenario:        "smoke/test",
		ExpiresAt:       now,
		DurationSeconds: 86400,
	}
	if err := s.InsertDecisionEventBatch(ctx, []DecisionEvent{oldRow, boundaryRow, freshRow}); err != nil {
		t.Fatalf("InsertDecisionEventBatch: %v", err)
	}

	n, err := s.PruneDecisionEventsOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("PruneDecisionEventsOlderThan: %v", err)
	}
	if n != 2 {
		t.Errorf("pruned n=%d, want 2 (oldRow + boundaryRow)", n)
	}

	got, err := s.QueryDecisionEvents(ctx, DecisionEventFilter{})
	if err != nil {
		t.Fatalf("QueryDecisionEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("post-prune rows=%d, want 1 (freshRow only)", len(got))
	}
	if got[0].UUID != "uuid-fresh" {
		t.Errorf("survivor uuid=%q, want uuid-fresh", got[0].UUID)
	}

	// Idempotent re-run: same cutoff, no rows to prune.
	n2, err := s.PruneDecisionEventsOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("PruneDecisionEventsOlderThan repeat: %v", err)
	}
	if n2 != 0 {
		t.Errorf("repeat prune n=%d, want 0 (idempotent)", n2)
	}
}

// TestPruneDecisionEventsOlderThan_EmptyTable pins the no-op
// path: pruning an empty decision_event table returns 0 with
// no error. The retention loop hits this on a fresh install
// every hour for ~30d before any decisions land.
func TestPruneDecisionEventsOlderThan_EmptyTable(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	n, err := s.PruneDecisionEventsOlderThan(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("PruneDecisionEventsOlderThan: %v", err)
	}
	if n != 0 {
		t.Errorf("empty-table prune n=%d, want 0", n)
	}
}

// TestPruneDecisionEventsOlderThan_NilStore pins the AC #13
// degraded-mode contract: a closed / nil store returns an
// error rather than panicking. Mirrors WafEvent / Bucket prune
// nil-tolerance.
func TestPruneDecisionEventsOlderThan_NilStore(t *testing.T) {
	var s *Store
	_, err := s.PruneDecisionEventsOlderThan(context.Background(), time.Now())
	if err == nil {
		t.Error("nil store: expected error, got nil")
	}
}

// TestPruneDecisionEventsOlderThan_PrunesByTsNotByExpiresAt is
// the §N spec D8.A pin: retention is by OBSERVATION time, not
// by LAPI ban duration. A 31d-old short-lived decision (banned
// 31d ago, expired 30d50m ago) prunes; a 1d-old long-ban
// decision (banned 1d ago, expires in 5 years) survives. This
// matters because community blocklists can carry multi-year
// durations and we don't want them to crowd out the operator's
// forensic view of recent activity.
func TestPruneDecisionEventsOlderThan_PrunesByTsNotByExpiresAt(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-30 * 24 * time.Hour)

	// Old observation, short ban (expired long ago) — should prune.
	oldShort := DecisionEvent{
		UUID:            "uuid-old-short",
		Ts:              now.Add(-31 * 24 * time.Hour),
		Scope:           "ip",
		Value:           "10.0.0.10",
		Type:            "ban",
		Scenario:        "smoke/short",
		ExpiresAt:       now.Add(-30*24*time.Hour - 50*time.Minute),
		DurationSeconds: 3600,
	}
	// Recent observation, very long ban (years in the future) —
	// should survive. The retention horizon should NOT honor the
	// LAPI duration; otherwise community blocklists crowd out
	// recent events.
	recentLong := DecisionEvent{
		UUID:            "uuid-recent-long",
		Ts:              now.Add(-24 * time.Hour),
		Scope:           "range",
		Value:           "192.168.0.0/16",
		Type:            "ban",
		Scenario:        "crowdsecurity/community-blocklist",
		ExpiresAt:       now.Add(5 * 365 * 24 * time.Hour),
		DurationSeconds: 5 * 365 * 86400,
	}
	if err := s.InsertDecisionEventBatch(ctx, []DecisionEvent{oldShort, recentLong}); err != nil {
		t.Fatalf("InsertDecisionEventBatch: %v", err)
	}

	if _, err := s.PruneDecisionEventsOlderThan(ctx, cutoff); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	got, err := s.QueryDecisionEvents(ctx, DecisionEventFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].UUID != "uuid-recent-long" {
		t.Errorf("post-prune survivors=%+v, want only uuid-recent-long", got)
	}
}
