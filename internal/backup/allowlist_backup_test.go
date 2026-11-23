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

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/allowlist"
)

func newAllowlistStore(t *testing.T) *allowlist.Store {
	t.Helper()
	s, err := allowlist.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("allowlist.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedAllowlist(t *testing.T, s *allowlist.Store, name string, entry string) {
	t.Helper()
	if _, err := s.Create(context.Background(), allowlist.Input{
		Name: name, Enabled: true, ScopeBlock: true, ScopeThrottle: false, ScopeAudit: true,
		Entries: []allowlist.Entry{{CIDR: entry, Note: "seed"}},
	}); err != nil {
		t.Fatalf("seed allowlist %q: %v", name, err)
	}
}

// failingSink always errors — models security.db unavailable at restore.
type failingSink struct{}

func (failingSink) ReplaceAll(context.Context, []allowlist.Allowlist) error {
	return errors.New("security.db unavailable")
}

// exportImport runs a JSON-round-tripped export→import with the given
// allowlist source and sink and returns the restored store's contents.
func exportImport(t *testing.T, srcAL AllowlistSource, dstAL AllowlistSink) (*ImportReport, error) {
	t.Helper()
	ctx := context.Background()
	src, srcUsers := newTestStoreWithUserStore(t)
	snap, err := Export(ctx, src, srcUsers, "test", true, srcAL)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	body, _ := json.Marshal(snap)
	var decoded Snapshot
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	dst, dstUsers := newTestStoreWithUserStore(t)
	return Import(ctx, dst, dstUsers, &decoded, ImportOptions{AllowEmptyUsers: true}, dstAL)
}

// G_backup_allowlist_roundtrip
func TestBackupAllowlist_RoundTrip_G(t *testing.T) {
	ctx := context.Background()
	srcAL := newAllowlistStore(t)
	seedAllowlist(t, srcAL, "office", "10.0.0.0/24")
	seedAllowlist(t, srcAL, "probes", "203.0.113.9")
	dstAL := newAllowlistStore(t)

	if _, err := exportImport(t, srcAL, dstAL); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, err := dstAL.List(ctx)
	if err != nil {
		t.Fatalf("list restored: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("restored %d allowlists, want 2", len(got))
	}
	bySlug := map[string]allowlist.Allowlist{}
	for _, a := range got {
		bySlug[a.Slug] = a
	}
	office, ok := bySlug["office"]
	if !ok {
		t.Fatalf("office not restored; got %v", bySlug)
	}
	if !office.ScopeBlock || office.ScopeThrottle || !office.ScopeAudit {
		t.Errorf("office scope not preserved: %+v", office)
	}
	if len(office.Entries) != 1 || office.Entries[0].CIDR != "10.0.0.0/24" {
		t.Errorf("office entries not preserved: %+v", office.Entries)
	}
}

// G_backup_allowlist_replace — restore replaces, never merges.
func TestBackupAllowlist_ReplaceNotMerge_G(t *testing.T) {
	ctx := context.Background()
	srcAL := newAllowlistStore(t)
	seedAllowlist(t, srcAL, "new-list", "198.51.100.0/24")
	dstAL := newAllowlistStore(t)
	seedAllowlist(t, dstAL, "stale-list", "192.0.2.1") // pre-existing on target

	if _, err := exportImport(t, srcAL, dstAL); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, err := dstAL.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Slug != "new-list" {
		t.Fatalf("restore did not replace: got %+v, want only new-list", got)
	}
}

// G_backup_allowlist_degraded — a failing sink is a HARD error (D-RESTORE:
// stop net, non-zero, no silent partial/empty fallback).
func TestBackupAllowlist_SinkFailure_HardError_G(t *testing.T) {
	srcAL := newAllowlistStore(t)
	seedAllowlist(t, srcAL, "office", "10.0.0.0/24")
	if _, err := exportImport(t, srcAL, failingSink{}); err == nil {
		t.Fatal("import must return a hard error when the allowlist sink fails")
	}
}

// G_backup_allowlist_backcompat — a pre-v2.85.0 snapshot (no allowlists
// section) restores to a cleanly empty allowlist store, no error. Sibling.
func TestBackupAllowlist_BackCompat_NoSection_G(t *testing.T) {
	ctx := context.Background()
	src, srcUsers := newTestStoreWithUserStore(t)
	// Export WITHOUT an allowlist source → no allowlists section.
	snap, err := Export(ctx, src, srcUsers, "test", true)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if snap.Extras != nil && len(snap.Extras.Allowlists) != 0 {
		t.Fatalf("expected no allowlists section, got %d", len(snap.Extras.Allowlists))
	}
	// Simulate an older backup JSON with no "allowlists" key at all.
	body, _ := json.Marshal(snap)
	if strings.Contains(string(body), "\"allowlists\"") {
		t.Errorf("omitempty failed: allowlists key present in a no-allowlist export")
	}
	var decoded Snapshot
	_ = json.Unmarshal(body, &decoded)
	dst, dstUsers := newTestStoreWithUserStore(t)
	dstAL := newAllowlistStore(t)
	if _, err := Import(ctx, dst, dstUsers, &decoded, ImportOptions{AllowEmptyUsers: true}, dstAL); err != nil {
		t.Fatalf("import of pre-v2.85.0 backup: %v", err)
	}
	got, _ := dstAL.List(ctx)
	if len(got) != 0 {
		t.Errorf("expected empty allowlist store after back-compat restore, got %d", len(got))
	}
}

// G_backup_allowlist_nosecret — allowlist entries are cleartext in a
// no-secrets export (no sentinel/redaction). Sibling.
func TestBackupAllowlist_NoSecretRedaction_G(t *testing.T) {
	ctx := context.Background()
	srcAL := newAllowlistStore(t)
	seedAllowlist(t, srcAL, "office", "10.0.0.0/24")
	src, srcUsers := newTestStoreWithUserStore(t)
	snap, err := Export(ctx, src, srcUsers, "test", false /* no secrets */, srcAL)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	body, _ := json.Marshal(snap)
	if !strings.Contains(string(body), "10.0.0.0/24") {
		t.Errorf("allowlist CIDR should be cleartext in a no-secrets export; it is not a secret")
	}
}

// TestBackupAllowlist_RejectsMultipleSources_G guards the variadic
// optional-dependency contract (#372): the allowlist source/sink is
// zero-or-one. Passing more than one is a programmer error (ambiguous
// which wins) and must be rejected loudly, not silently resolved to [0].
func TestBackupAllowlist_RejectsMultipleSources_G(t *testing.T) {
	ctx := context.Background()
	src, srcUsers := newTestStoreWithUserStore(t)
	a1 := newAllowlistStore(t)
	a2 := newAllowlistStore(t)

	if _, err := Export(ctx, src, srcUsers, "test", true, a1, a2); err == nil {
		t.Error("Export must reject more than one allowlist source")
	}
	dst, dstUsers := newTestStoreWithUserStore(t)
	if _, err := Import(ctx, dst, dstUsers, &Snapshot{}, ImportOptions{AllowEmptyUsers: true}, a1, a2); err == nil {
		t.Error("Import must reject more than one allowlist sink")
	}
}
