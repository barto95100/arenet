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
	"testing"
)

func TestExternalCert_CreateRoundtrip(t *testing.T) {
	s := newTestStore(t)
	got, err := s.CreateExternalCertificate(context.Background(), ExternalCertificate{
		Name: "digicert-wildcard", CertPEM: "CERT", KeyPEM: "KEY", ChainPEM: "CHAIN",
		Issuer: "DigiCert", DNSNames: []string{"*.example.com"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.ID == "" {
		t.Error("ID not assigned by backend")
	}
	back, err := s.GetExternalCertificate(context.Background(), got.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if back.KeyPEM != "KEY" || back.CertPEM != "CERT" || back.ChainPEM != "CHAIN" {
		t.Errorf("PEM material not round-tripped: %+v", back)
	}
	if len(back.DNSNames) != 1 || back.DNSNames[0] != "*.example.com" {
		t.Errorf("DNSNames = %v", back.DNSNames)
	}
}

func TestExternalCert_Delete(t *testing.T) {
	s := newTestStore(t)
	c, _ := s.CreateExternalCertificate(context.Background(), ExternalCertificate{Name: "x", CertPEM: "C", KeyPEM: "K"})
	if err := s.DeleteExternalCertificate(context.Background(), c.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetExternalCertificate(context.Background(), c.ID); err != ErrNotFound {
		t.Errorf("get after delete err = %v; want ErrNotFound", err)
	}
}

func TestExternalCert_UpdatePreservesKeyWhenEmpty(t *testing.T) {
	s := newTestStore(t)
	c, _ := s.CreateExternalCertificate(context.Background(), ExternalCertificate{Name: "x", CertPEM: "C", KeyPEM: "SECRET"})
	// Update with empty KeyPEM must preserve the stored key.
	upd, err := s.UpdateExternalCertificate(context.Background(), c.ID, ExternalCertificate{Name: "x2", CertPEM: "C", KeyPEM: ""})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.KeyPEM != "SECRET" {
		t.Errorf("KeyPEM = %q; want preserved SECRET", upd.KeyPEM)
	}
	if upd.Name != "x2" {
		t.Errorf("Name = %q; want updated x2", upd.Name)
	}
}
