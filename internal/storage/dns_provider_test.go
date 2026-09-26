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

// ovhTestCreds returns a complete, valid OVH credential set.
func ovhTestCreds() map[string]string {
	return map[string]string{
		"endpoint":           "ovh-eu",
		"application_key":    "ak",
		"application_secret": "as",
		"consumer_key":       "ck",
	}
}

func TestDNSProvider_CreateGetList(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	in := DNSProviderConfig{
		Label:       "OVH perso",
		Type:        DNSProviderTypeOVH,
		Credentials: ovhTestCreds(),
	}
	created, err := s.CreateDNSProvider(ctx, in)
	if err != nil {
		t.Fatalf("CreateDNSProvider: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateDNSProvider did not assign an ID")
	}
	if created.Label != "OVH perso" || created.Type != "ovh" {
		t.Errorf("round-trip mismatch: %+v", created)
	}

	got, err := s.GetDNSProvider(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetDNSProvider: %v", err)
	}
	if got.Credentials["application_key"] != "ak" {
		t.Errorf("secret not persisted: %+v", got)
	}

	list, err := s.ListDNSProviders(ctx)
	if err != nil {
		t.Fatalf("ListDNSProviders: %v", err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Errorf("list = %+v, want 1 entry with id %s", list, created.ID)
	}
}

func TestDNSProvider_GetMissing_ReturnsErrNotFound(t *testing.T) {
	s := newStoreForTest(t)
	if _, err := s.GetDNSProvider(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDNSProvider_UpdatePreservesBlankSecrets(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	created, err := s.CreateDNSProvider(ctx, DNSProviderConfig{
		Label: "OVH", Type: "ovh", Credentials: ovhTestCreds(),
	})
	if err != nil {
		t.Fatalf("CreateDNSProvider: %v", err)
	}
	// Edit label only; leave all secrets blank.
	updated, err := s.UpdateDNSProvider(ctx, created.ID, DNSProviderConfig{
		Label: "OVH renamed", Type: "ovh", Credentials: map[string]string{"endpoint": "ovh-eu"},
	})
	if err != nil {
		t.Fatalf("UpdateDNSProvider: %v", err)
	}
	if updated.Label != "OVH renamed" {
		t.Errorf("label = %q", updated.Label)
	}
	if updated.Credentials["application_key"] != "ak" || updated.Credentials["consumer_key"] != "ck" {
		t.Errorf("blank secrets were not preserved: %+v", updated)
	}
}

func TestDNSProvider_UpdateMissing_ReturnsErrNotFound(t *testing.T) {
	s := newStoreForTest(t)
	_, err := s.UpdateDNSProvider(context.Background(), "nope", DNSProviderConfig{
		Label: "OVH", Type: "ovh", Credentials: ovhTestCreds(),
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDNSProvider_DeleteInUse_ReturnsErrProviderInUse(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, err := s.CreateDNSProvider(ctx, DNSProviderConfig{
		Label: "OVH", Type: "ovh", Credentials: ovhTestCreds(),
	})
	if err != nil {
		t.Fatalf("CreateDNSProvider: %v", err)
	}
	if err := s.PutManagedDomain(ctx, ManagedDomain{Apex: "example.com", ProviderID: p.ID}); err != nil {
		t.Fatalf("PutManagedDomain: %v", err)
	}
	if err := s.DeleteDNSProvider(ctx, p.ID); !errors.Is(err, ErrProviderInUse) {
		t.Errorf("err = %v, want ErrProviderInUse", err)
	}
}

func TestDNSProvider_DeleteMissing_ReturnsErrNotFound(t *testing.T) {
	s := newStoreForTest(t)
	if err := s.DeleteDNSProvider(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDNSProvider_DeleteNotInUse_Succeeds(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, err := s.CreateDNSProvider(ctx, DNSProviderConfig{
		Label: "OVH", Type: "ovh", Credentials: ovhTestCreds(),
	})
	if err != nil {
		t.Fatalf("CreateDNSProvider: %v", err)
	}
	if err := s.DeleteDNSProvider(ctx, p.ID); err != nil {
		t.Fatalf("DeleteDNSProvider: %v", err)
	}
	if _, err := s.GetDNSProvider(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("provider still present after delete: %v", err)
	}
}

func TestDNSProvider_CreateRejectsBadType(t *testing.T) {
	s := newStoreForTest(t)
	_, err := s.CreateDNSProvider(context.Background(), DNSProviderConfig{
		Label: "X", Type: "bind9", Credentials: ovhTestCreds(),
	})
	if err == nil {
		t.Fatal("expected validation error for unknown type, got nil")
	}
}

func TestDNSProvider_CreateRejectsEmptyLabel(t *testing.T) {
	s := newStoreForTest(t)
	_, err := s.CreateDNSProvider(context.Background(), DNSProviderConfig{
		Label: "", Type: "ovh", Credentials: ovhTestCreds(),
	})
	if err == nil {
		t.Fatal("expected validation error for empty label, got nil")
	}
}
