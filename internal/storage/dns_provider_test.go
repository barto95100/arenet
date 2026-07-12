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
	"errors"
	"testing"
)

func TestDNSProvider_CreateGetList(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	in := DNSProviderConfig{
		Label:             "OVH perso",
		Type:              DNSProviderTypeOVH,
		Endpoint:          "ovh-eu",
		ApplicationKey:    "ak",
		ApplicationSecret: "as",
		ConsumerKey:       "ck",
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
	if got.ApplicationKey != "ak" {
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
		Label: "OVH", Type: "ovh", Endpoint: "ovh-eu",
		ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: "ck",
	})
	if err != nil {
		t.Fatalf("CreateDNSProvider: %v", err)
	}
	// Edit label only; leave all secrets blank.
	updated, err := s.UpdateDNSProvider(ctx, created.ID, DNSProviderConfig{
		Label: "OVH renamed", Type: "ovh", Endpoint: "ovh-eu",
	})
	if err != nil {
		t.Fatalf("UpdateDNSProvider: %v", err)
	}
	if updated.Label != "OVH renamed" {
		t.Errorf("label = %q", updated.Label)
	}
	if updated.ApplicationKey != "ak" || updated.ConsumerKey != "ck" {
		t.Errorf("blank secrets were not preserved: %+v", updated)
	}
}

func TestDNSProvider_UpdateMissing_ReturnsErrNotFound(t *testing.T) {
	s := newStoreForTest(t)
	_, err := s.UpdateDNSProvider(context.Background(), "nope", DNSProviderConfig{
		Label: "OVH", Type: "ovh", Endpoint: "ovh-eu",
		ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: "ck",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDNSProvider_DeleteInUse_ReturnsErrProviderInUse(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, err := s.CreateDNSProvider(ctx, DNSProviderConfig{
		Label: "OVH", Type: "ovh", Endpoint: "ovh-eu",
		ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: "ck",
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
		Label: "OVH", Type: "ovh", Endpoint: "ovh-eu",
		ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: "ck",
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
		Label: "X", Type: "cloudflare", Endpoint: "ovh-eu",
		ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: "ck",
	})
	if err == nil {
		t.Fatal("expected validation error for unknown type, got nil")
	}
}

func TestDNSProvider_CreateRejectsEmptyLabel(t *testing.T) {
	s := newStoreForTest(t)
	_, err := s.CreateDNSProvider(context.Background(), DNSProviderConfig{
		Label: "", Type: "ovh", Endpoint: "ovh-eu",
		ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: "ck",
	})
	if err == nil {
		t.Fatal("expected validation error for empty label, got nil")
	}
}
