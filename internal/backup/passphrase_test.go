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
	"errors"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/auth"
)

const testPassphrase = "correct horse battery staple"

// sealedFile exports the seeded store with secrets, encrypts it and
// returns the JSON file bytes.
func sealedFile(t *testing.T) ([]byte, seededExtras) {
	t.Helper()
	store, us := newTestStoreWithUserStore(t)
	seeded := seedExtras(t, store, us)
	snap, err := Export(context.Background(), store, us, "test", true)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := SealSnapshot(snap, testPassphrase); err != nil {
		t.Fatalf("SealSnapshot: %v", err)
	}
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body, seeded
}

func decodeFile(t *testing.T, body []byte) *Snapshot {
	t.Helper()
	var s Snapshot
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return &s
}

func TestPassphrase_RoundTripOntoFreshInstance(t *testing.T) {
	body, seeded := sealedFile(t)
	for _, secret := range []string{extSMTPPassword, extWebhookURL, extWebhookHeader, extCrowdSecKey, extWatcherPass, seeded.token.TokenHash, "cf-token"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("encrypted file leaks %q", secret)
		}
	}
	snap := decodeFile(t, body)
	if snap.SchemaVersion != SchemaVersionEncrypted || !snap.IsEncrypted() {
		t.Fatalf("schema %q encrypted=%t", snap.SchemaVersion, snap.IsEncrypted())
	}
	// Non-secret data stays readable.
	if !strings.Contains(string(body), "smtp.example.com") {
		t.Error("non-secret fields should stay in clear")
	}

	if err := OpenSnapshot(snap, testPassphrase); err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	if snap.IsEncrypted() || snap.SchemaVersion != SchemaVersion {
		t.Fatalf("opened snapshot still marked encrypted: %q", snap.SchemaVersion)
	}
	dst, dstUsers := newTestStoreWithUserStore(t)
	if _, err := Import(context.Background(), dst, dstUsers, snap, ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}
	if _, err := auth.NewAPITokenStore(dst.DB()).LookupToken(context.Background(), seeded.tokenPlain); err != nil {
		t.Errorf("service token lost: %v", err)
	}
	if cs, _ := dst.GetCrowdSecConfig(context.Background()); cs.APIKey != extCrowdSecKey {
		t.Errorf("crowdsec key %q", cs.APIKey)
	}
	ch, _ := dst.GetAlertChannel(context.Background(), seeded.webhookID)
	if !strings.Contains(string(ch.Config), extWebhookURL) || !json.Valid(ch.Config) {
		t.Errorf("webhook config %s", ch.Config)
	}
}

func TestPassphrase_Errors(t *testing.T) {
	body, _ := sealedFile(t)

	if err := OpenSnapshot(decodeFile(t, body), ""); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("no passphrase: %v", err)
	}
	if err := OpenSnapshot(decodeFile(t, body), "wrong passphrase!!"); !errors.Is(err, ErrPassphraseInvalid) {
		t.Errorf("wrong passphrase: %v", err)
	}
	store, us := newTestStoreWithUserStore(t)
	if _, err := Import(context.Background(), store, us, decodeFile(t, body), ImportOptions{}); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("import without opening: %v", err)
	}

	// Stripping the header leaves sealed values: rejected, never stored.
	stripped := decodeFile(t, body)
	stripped.Encryption = nil
	stripped.SchemaVersion = SchemaVersion
	if _, err := Import(context.Background(), store, us, stripped, ImportOptions{}); !errors.Is(err, ErrSealedWithoutHeader) {
		t.Errorf("header stripped: %v", err)
	}

	// A sealed value moved to another field does not open (path AAD).
	moved := decodeFile(t, body)
	moved.Extras.WatcherCredentials.Password = moved.Extras.CrowdSecConfig.APIKey
	if err := OpenSnapshot(moved, testPassphrase); !errors.Is(err, ErrPassphraseInvalid) {
		t.Errorf("moved value: %v", err)
	}

	// Crafted KDF cost is refused before any derivation.
	costly := decodeFile(t, body)
	costly.Encryption.MemoryKiB = kdfMaxMemoryKiB + 1
	if err := OpenSnapshot(costly, testPassphrase); err == nil || !strings.Contains(err.Error(), "out of bounds") {
		t.Errorf("KDF bounds: %v", err)
	}
}

func TestSealSnapshot_Preconditions(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	_ = seedLiveUser(t, us, "alice", "alice-password-15c-xx")
	redacted, _ := Export(context.Background(), store, us, "test", false)
	if err := SealSnapshot(redacted, testPassphrase); err == nil {
		t.Error("a redacted export must not be encrypted")
	}
	full, _ := Export(context.Background(), store, us, "test", true)
	if err := SealSnapshot(full, "short"); !errors.Is(err, ErrPassphraseTooShort) {
		t.Errorf("short passphrase: %v", err)
	}
	if err := SealSnapshot(full, strings.Repeat("é", MinPassphraseLen)); err != nil {
		t.Errorf("12 multi-byte characters must be accepted: %v", err)
	}
}
