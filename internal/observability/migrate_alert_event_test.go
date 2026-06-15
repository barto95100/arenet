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
)

// Step AL.1.a — pin the alert_event table + indexes
// created by migrateV9toV10 land on a fresh install. The
// existing TestMigrate_FreshDB_LandsAtCurrentVersion test
// covers the SchemaVersion bump; this test pins the
// schema shape so a future migration drift (e.g. someone
// reuses the v10 step number for a different feature)
// surfaces here.

func TestMigrateV9toV10_AlertEventTableShape(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// Table existence + every expected column.
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(alert_event)`)
	if err != nil {
		t.Fatalf("PRAGMA table_info: %v", err)
	}
	defer rows.Close()
	gotCols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dfltValue any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		gotCols[name] = true
	}
	want := []string{
		"id", "event_id", "ts", "rule_id", "rule_name",
		"severity", "category", "subject", "body",
		"context_json", "labels_json",
		"channels_fired_json", "channels_failed_json",
	}
	for _, col := range want {
		if !gotCols[col] {
			t.Errorf("alert_event missing column %q", col)
		}
	}

	// Index existence — the activity log reader (AL.3b)
	// will rely on these for time-range + per-rule
	// drill-down queries.
	indexes := []string{
		"idx_alert_event_ts",
		"idx_alert_event_rule_ts",
		"idx_alert_event_severity_ts",
	}
	for _, idx := range indexes {
		var name string
		err := s.db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='index' AND name=?`,
			idx,
		).Scan(&name)
		if err != nil {
			t.Errorf("index %q not found: %v", idx, err)
		}
	}
}

func TestMigrateV9toV10_EventIDIsUnique(t *testing.T) {
	// The UNIQUE constraint on event_id is the dedupe gate
	// for watcher restarts: if the rule engine fires the
	// same trigger twice (re-evaluation after a sub-second
	// restart), the second INSERT must fail rather than
	// produce a duplicate row.
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	insert := `INSERT INTO alert_event
		(event_id, ts, rule_id, rule_name, severity, category, subject)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, insert,
		"evt-dup", 1, "r1", "rule one", 1, "system", "boot"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, insert,
		"evt-dup", 2, "r1", "rule one", 1, "system", "boot"); err == nil {
		t.Fatal("duplicate event_id insert succeeded; UNIQUE constraint missing")
	}
}
