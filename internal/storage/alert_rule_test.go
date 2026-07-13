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

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

// AL.2.a — AlertRule CRUD pinning tests on a real bolt
// store. Covers the happy round-trip + the ErrConflict /
// ErrNotFound paths the AL.2.b watcher relies on.

func newStoreForTest(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func sampleRule(id, name string) AlertRule {
	return AlertRule{
		ID:           id,
		Name:         name,
		Enabled:      true,
		Kind:         "threshold",
		Severity:     1,
		Category:     "waf",
		Source:       "waf_event_rate",
		SourceParams: json.RawMessage(`{"windowSecs":300}`),
		EvalParams:   json.RawMessage(`{"operator":">","value":50}`),
		Channels:     []string{"ch-1"},
		CooldownSecs: 300,
	}
}

func TestAlertRule_CreateGet(t *testing.T) {
	store := newStoreForTest(t)
	r := sampleRule("rule-1", "block-rate-high")
	created, err := store.CreateAlertRule(context.Background(), r)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.CreatedAt.IsZero() {
		t.Errorf("CreatedAt not stamped")
	}
	got, err := store.GetAlertRule(context.Background(), "rule-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "block-rate-high" {
		t.Errorf("Name = %q; want block-rate-high", got.Name)
	}
}

func TestAlertRule_Create_NameConflict(t *testing.T) {
	store := newStoreForTest(t)
	_, _ = store.CreateAlertRule(context.Background(), sampleRule("rule-1", "shared-name"))
	_, err := store.CreateAlertRule(context.Background(), sampleRule("rule-2", "shared-name"))
	if !errors.Is(err, ErrConflict) {
		t.Errorf("err = %v; want ErrConflict on duplicate Name", err)
	}
}

func TestAlertRule_Create_IDConflict(t *testing.T) {
	store := newStoreForTest(t)
	_, _ = store.CreateAlertRule(context.Background(), sampleRule("rule-1", "name-a"))
	_, err := store.CreateAlertRule(context.Background(), sampleRule("rule-1", "name-b"))
	if !errors.Is(err, ErrConflict) {
		t.Errorf("err = %v; want ErrConflict on duplicate ID", err)
	}
}

func TestAlertRule_Get_NotFound(t *testing.T) {
	store := newStoreForTest(t)
	_, err := store.GetAlertRule(context.Background(), "ghost")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v; want ErrNotFound", err)
	}
}

func TestAlertRule_List_SortedByCreated(t *testing.T) {
	store := newStoreForTest(t)
	_, _ = store.CreateAlertRule(context.Background(), sampleRule("rule-1", "first"))
	_, _ = store.CreateAlertRule(context.Background(), sampleRule("rule-2", "second"))
	out, err := store.ListAlertRules(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len = %d; want 2", len(out))
	}
	if out[0].Name != "first" || out[1].Name != "second" {
		t.Errorf("order = [%s, %s]; want [first, second]", out[0].Name, out[1].Name)
	}
}

func TestAlertRule_Update_PreservesWatcherFields(t *testing.T) {
	store := newStoreForTest(t)
	created, _ := store.CreateAlertRule(context.Background(), sampleRule("rule-1", "name"))
	// Simulate a watcher write: bump LastFiredAt + LastError.
	if err := store.MarkAlertRuleEval(context.Background(), "rule-1", true, errors.New("flaky source")); err != nil {
		t.Fatalf("MarkAlertRuleEval: %v", err)
	}
	withTelem, _ := store.GetAlertRule(context.Background(), "rule-1")
	if withTelem.LastFiredAt == nil {
		t.Fatalf("LastFiredAt not bumped after MarkAlertRuleEval")
	}

	// Now an API-layer PUT with zero LastFiredAt /
	// LastError: must preserve.
	updated := created
	updated.Name = "renamed"
	updated.Category = "system"
	// LastFiredAt / LastError NOT set → preserve.
	if _, err := store.UpdateAlertRule(context.Background(), updated); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := store.GetAlertRule(context.Background(), "rule-1")
	if got.Name != "renamed" {
		t.Errorf("Name = %q; want renamed", got.Name)
	}
	if got.LastFiredAt == nil {
		t.Errorf("LastFiredAt cleared by Update; want preserved")
	}
	if got.LastError != "flaky source" {
		t.Errorf("LastError = %q; want preserved 'flaky source'", got.LastError)
	}
}

func TestAlertRule_Update_NameConflict(t *testing.T) {
	store := newStoreForTest(t)
	_, _ = store.CreateAlertRule(context.Background(), sampleRule("rule-1", "name-a"))
	_, _ = store.CreateAlertRule(context.Background(), sampleRule("rule-2", "name-b"))
	r2 := sampleRule("rule-2", "name-a") // collides with rule-1
	_, err := store.UpdateAlertRule(context.Background(), r2)
	if !errors.Is(err, ErrConflict) {
		t.Errorf("err = %v; want ErrConflict on rename collision", err)
	}
}

func TestAlertRule_Delete(t *testing.T) {
	store := newStoreForTest(t)
	_, _ = store.CreateAlertRule(context.Background(), sampleRule("rule-1", "doomed"))
	if err := store.DeleteAlertRule(context.Background(), "rule-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := store.GetAlertRule(context.Background(), "rule-1")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err after Delete = %v; want ErrNotFound", err)
	}
}

func TestAlertRule_Delete_NotFound(t *testing.T) {
	store := newStoreForTest(t)
	if err := store.DeleteAlertRule(context.Background(), "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v; want ErrNotFound", err)
	}
}

func TestUpdateAlertRuleLastMatched_RoundTrip(t *testing.T) {
	store := newStoreForTest(t)
	created, err := store.CreateAlertRule(context.Background(), sampleRule("rule-1", "lm"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// default is false
	got, err := store.GetAlertRule(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.LastMatched {
		t.Fatalf("fresh rule LastMatched = true; want false")
	}
	// set true, read back
	if err := store.UpdateAlertRuleLastMatched(context.Background(), created.ID, true); err != nil {
		t.Fatalf("update last matched: %v", err)
	}
	got, _ = store.GetAlertRule(context.Background(), created.ID)
	if !got.LastMatched {
		t.Fatalf("LastMatched = false after set true")
	}
}

func TestUpdateAlertRule_PreservesLastMatched(t *testing.T) {
	store := newStoreForTest(t)
	created, _ := store.CreateAlertRule(context.Background(), sampleRule("rule-1", "lm"))
	if err := store.UpdateAlertRuleLastMatched(context.Background(), created.ID, true); err != nil {
		t.Fatalf("set last matched: %v", err)
	}
	// operator PUT that carries LastMatched=false (as the API layer would)
	edit := created
	edit.LastMatched = false
	edit.Name = "lm-edited"
	if _, err := store.UpdateAlertRule(context.Background(), edit); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	got, _ := store.GetAlertRule(context.Background(), created.ID)
	if !got.LastMatched {
		t.Fatalf("operator PUT reset LastMatched to false; want preserved true")
	}
}

func TestAlertRule_MarkEval_ErrorPath(t *testing.T) {
	store := newStoreForTest(t)
	_, _ = store.CreateAlertRule(context.Background(), sampleRule("rule-1", "name"))

	// Successful eval — fired=false, no error.
	if err := store.MarkAlertRuleEval(context.Background(), "rule-1", false, nil); err != nil {
		t.Fatalf("MarkAlertRuleEval ok: %v", err)
	}
	got, _ := store.GetAlertRule(context.Background(), "rule-1")
	if got.LastEvalAt == nil {
		t.Errorf("LastEvalAt nil after successful Mark")
	}
	if got.LastFiredAt != nil {
		t.Errorf("LastFiredAt non-nil on fired=false")
	}

	// Failed eval — sendErr != nil.
	if err := store.MarkAlertRuleEval(context.Background(), "rule-1", false, errors.New("timeout")); err != nil {
		t.Fatalf("MarkAlertRuleEval err: %v", err)
	}
	got, _ = store.GetAlertRule(context.Background(), "rule-1")
	if got.LastError != "timeout" {
		t.Errorf("LastError = %q; want timeout", got.LastError)
	}

	// Fired = true clears LastError on next non-error tick.
	if err := store.MarkAlertRuleEval(context.Background(), "rule-1", true, nil); err != nil {
		t.Fatalf("MarkAlertRuleEval clear: %v", err)
	}
	got, _ = store.GetAlertRule(context.Background(), "rule-1")
	if got.LastError != "" {
		t.Errorf("LastError = %q after clean tick; want empty", got.LastError)
	}
	if got.LastFiredAt == nil {
		t.Errorf("LastFiredAt nil after fired=true")
	}
}
