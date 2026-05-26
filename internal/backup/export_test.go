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

package backup

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestExport_DefaultRedactsAllSecretFields pins AC #13: every field
// listed in spec §5.3 secret-scope table is replaced with the
// sentinel literal when --include-secrets is NOT set. The check
// runs against the marshalled JSON to catch any field the
// redactSnapshotInPlace pass would miss in a future refactor.
func TestExport_DefaultRedactsAllSecretFields(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	_ = seedLiveRoute(t, store, "redact-me.example.com")
	_ = seedLiveUser(t, us, "alice", "alice-password-15c-xx")

	snap, err := Export(context.Background(), store, us, "test", false /* includeSecrets */)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if snap.SecretsIncluded {
		t.Fatal("SecretsIncluded should be false on default export")
	}

	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jsonStr := string(body)

	// Pre-existing live secrets MUST NOT appear in the redacted export.
	if strings.Contains(jsonStr, "$argon2id$live-route-hash") {
		t.Error("REDACTION LEAK: route password hash leaked into default export")
	}
	// The sentinel literal SHOULD appear (every secret-bearing
	// row carries it).
	if !strings.Contains(jsonStr, SentinelLiteral) {
		t.Error("default export should contain the sentinel literal")
	}
	// Belt-and-braces: explicit per-field assertion on the struct.
	if snap.Routes[0].BasicAuth.PasswordHash != SentinelLiteral {
		t.Errorf("route password_hash not redacted: %q", snap.Routes[0].BasicAuth.PasswordHash)
	}
	if snap.Users[0].PasswordHash != SentinelLiteral {
		t.Errorf("user password_hash not redacted: %q", snap.Users[0].PasswordHash)
	}
}

func TestExport_IncludeSecrets_EmitsCleartext(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	_ = seedLiveRoute(t, store, "cleartext.example.com")
	_ = seedLiveUser(t, us, "alice", "alice-password-15c-xx")

	snap, err := Export(context.Background(), store, us, "test", true)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !snap.SecretsIncluded {
		t.Fatal("SecretsIncluded should be true on --include-secrets export")
	}
	if snap.Routes[0].BasicAuth.PasswordHash == SentinelLiteral {
		t.Error("--include-secrets export should NOT redact route hash")
	}
	if snap.Routes[0].BasicAuth.PasswordHash != "$argon2id$live-route-hash" {
		t.Errorf("route hash mangled: %q", snap.Routes[0].BasicAuth.PasswordHash)
	}
	if snap.Users[0].PasswordHash == SentinelLiteral || snap.Users[0].PasswordHash == "" {
		t.Errorf("user hash not preserved on --include-secrets export: %q", snap.Users[0].PasswordHash)
	}
}

// TestExport_SchemaVersion pins the exported schema version against
// SchemaVersion. A bump to SchemaVersion bumps this test
// deliberately — forces the conversation around backward-compat.
func TestExport_SchemaVersion(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	snap, err := Export(context.Background(), store, us, "test", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if snap.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %q; want %q", snap.SchemaVersion, SchemaVersion)
	}
	if snap.ArenetVersion != "test" {
		t.Errorf("ArenetVersion = %q; want %q", snap.ArenetVersion, "test")
	}
}
