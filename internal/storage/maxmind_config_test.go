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

package storage

import (
	"context"
	"errors"
	"testing"
)

func TestMaxMindConfig_GetFresh_ReturnsNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetMaxMindConfig(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("fresh GetMaxMindConfig err = %v; want ErrNotFound", err)
	}
}

func TestMaxMindConfig_PutGet_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	in := MaxMindConfig{AccountID: 12345, LicenseKey: "secretkey", EditionID: "GeoLite2-City"}
	if err := s.PutMaxMindConfig(context.Background(), in); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.GetMaxMindConfig(context.Background())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AccountID != 12345 || got.LicenseKey != "secretkey" || got.EditionID != "GeoLite2-City" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("timestamps not set: %+v", got)
	}
}

func TestMaxMindConfig_PutBlankKey_PreservesStored(t *testing.T) {
	s := newTestStore(t)
	_ = s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 1, LicenseKey: "orig", EditionID: "GeoLite2-City"})
	// update with blank key → inherit "orig"
	if err := s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 2, LicenseKey: ""}); err != nil {
		t.Fatalf("put update: %v", err)
	}
	got, _ := s.GetMaxMindConfig(context.Background())
	if got.LicenseKey != "orig" {
		t.Errorf("blank-key update dropped secret: %q; want 'orig'", got.LicenseKey)
	}
	if got.AccountID != 2 {
		t.Errorf("account id not updated: %d; want 2", got.AccountID)
	}
}

func TestMaxMindConfig_DefaultEdition(t *testing.T) {
	s := newTestStore(t)
	_ = s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 1, LicenseKey: "k"}) // no edition
	got, _ := s.GetMaxMindConfig(context.Background())
	if got.EditionID != "GeoLite2-City" {
		t.Errorf("default edition = %q; want GeoLite2-City", got.EditionID)
	}
}

func TestMaxMindConfig_RejectEmptyAfterMerge(t *testing.T) {
	s := newTestStore(t)
	// no prior config; blank key can't inherit → reject
	err := s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 1, LicenseKey: ""})
	if err == nil {
		t.Fatal("put with no key and nothing to inherit = nil; want error")
	}
	// account id <= 0 → reject
	if err := s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 0, LicenseKey: "k"}); err == nil {
		t.Fatal("put with AccountID<=0 = nil; want error")
	}
}

func TestMaxMindConfig_Delete(t *testing.T) {
	s := newTestStore(t)
	_ = s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 1, LicenseKey: "k"})
	if err := s.DeleteMaxMindConfig(context.Background()); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err := s.GetMaxMindConfig(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete Get err = %v; want ErrNotFound", err)
	}
}

func TestMaxMindConfig_EverConfigured(t *testing.T) {
	s := newTestStore(t)
	ever, _ := s.MaxMindConfigEverConfigured(context.Background())
	if ever {
		t.Fatal("fresh EverConfigured = true; want false")
	}
	_ = s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 1, LicenseKey: "k"})
	ever, _ = s.MaxMindConfigEverConfigured(context.Background())
	if !ever {
		t.Fatal("after put EverConfigured = false; want true")
	}
}

// v2.72 — a non-default edition survives a licence-key rotation.
//
// PutMaxMindConfig already preserved a blank LicenseKey from the stored
// row, and then reset a blank EditionID to the default instead of
// preserving it. The asymmetry WAS the bug: the GeoIP settings section
// sends accountId + licenseKey and nothing else, so rotating the key
// reverted a GeoLite2-ASN or GeoLite2-Country install to
// GeoLite2-City — after which geoipupdate downloads a different
// database than the operator chose, and its edition guard rejects the
// mismatch.
//
// TestMaxMindConfig_DefaultEdition above is the other half and still
// holds: with no stored row there is nothing to preserve, so the
// default applies. The two tests together say "preserve, else default",
// which is exactly what LicenseKey has always done.
func TestMaxMindConfig_PutBlankEdition_PreservesStored(t *testing.T) {
	s := newTestStore(t)
	if err := s.PutMaxMindConfig(context.Background(), MaxMindConfig{
		AccountID: 1, LicenseKey: "orig", EditionID: "GeoLite2-ASN",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// What the settings section sends: account + key, no edition.
	if err := s.PutMaxMindConfig(context.Background(), MaxMindConfig{
		AccountID: 1, LicenseKey: "rotated",
	}); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	got, _ := s.GetMaxMindConfig(context.Background())
	if got.EditionID != "GeoLite2-ASN" {
		t.Errorf("EditionID = %q, want %q — a blank edition must inherit the stored "+
			"one, not reset to the default", got.EditionID, "GeoLite2-ASN")
	}
	if got.LicenseKey != "rotated" {
		t.Errorf("LicenseKey = %q, want the rotated value", got.LicenseKey)
	}
}

// Changing the edition on purpose has to keep working, or the fix
// replaces a reset with a value nobody can move.
func TestMaxMindConfig_PutExplicitEdition_Replaces(t *testing.T) {
	s := newTestStore(t)
	_ = s.PutMaxMindConfig(context.Background(), MaxMindConfig{
		AccountID: 1, LicenseKey: "k", EditionID: "GeoLite2-ASN",
	})
	if err := s.PutMaxMindConfig(context.Background(), MaxMindConfig{
		AccountID: 1, LicenseKey: "k", EditionID: "GeoLite2-Country",
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, _ := s.GetMaxMindConfig(context.Background())
	if got.EditionID != "GeoLite2-Country" {
		t.Errorf("EditionID = %q, want the explicit value", got.EditionID)
	}
}
