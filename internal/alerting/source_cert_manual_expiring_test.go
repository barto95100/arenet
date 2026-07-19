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

package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

type stubCertStore struct{ certs []storage.ExternalCertificate }

func (s stubCertStore) ListExternalCertificates(_ context.Context) ([]storage.ExternalCertificate, error) {
	return s.certs, nil
}

func TestCertManualExpiring_FiresWithinThreshold(t *testing.T) {
	now := time.Now()
	src := NewCertManualExpiringSource(stubCertStore{certs: []storage.ExternalCertificate{
		{ID: "a", Name: "soon", NotAfter: now.Add(10 * 24 * time.Hour), DNSNames: []string{"soon.example.com"}},
		{ID: "b", Name: "later", NotAfter: now.Add(90 * 24 * time.Hour)},
	}})
	v, err := src.Read(context.Background(), json.RawMessage(`{"thresholdDays":30}`))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if v.Float == nil || *v.Float != 1 {
		t.Errorf("count within threshold = %v; want 1", v.Float)
	}
	// Spec §7: the source attaches a context payload naming the
	// certs within the threshold plus the count.
	if v.Context == nil {
		t.Fatalf("expected Context payload, got nil")
	}
	if got := v.Context["count"]; got != 1 {
		t.Errorf("Context[count] = %v; want 1", got)
	}
	certsRaw, ok := v.Context["certs"].([]map[string]any)
	if !ok {
		t.Fatalf("Context[certs] is not []map[string]any: %T", v.Context["certs"])
	}
	if len(certsRaw) != 1 {
		t.Fatalf("Context[certs] len = %d; want 1", len(certsRaw))
	}
	c := certsRaw[0]
	if c["id"] != "a" {
		t.Errorf("cert id = %v; want a", c["id"])
	}
	if c["name"] != "soon" {
		t.Errorf("cert name = %v; want soon", c["name"])
	}
	if _, ok := c["daysLeft"]; !ok {
		t.Errorf("cert entry missing daysLeft: %v", c)
	}
	if _, ok := c["notAfter"]; !ok {
		t.Errorf("cert entry missing notAfter: %v", c)
	}
	if names, ok := c["dnsNames"].([]string); !ok || len(names) != 1 || names[0] != "soon.example.com" {
		t.Errorf("cert dnsNames = %v; want [soon.example.com]", c["dnsNames"])
	}
	// The later cert must NOT appear (outside threshold).
	if !strings.Contains(fmt.Sprint(certsRaw), "soon") || strings.Contains(fmt.Sprint(certsRaw), "later") {
		t.Errorf("context certs should contain only the within-threshold cert: %v", certsRaw)
	}
}

func TestCertManualExpiring_NoneWithinThreshold(t *testing.T) {
	now := time.Now()
	src := NewCertManualExpiringSource(stubCertStore{certs: []storage.ExternalCertificate{
		{ID: "b", Name: "later", NotAfter: now.Add(90 * 24 * time.Hour)},
	}})
	v, _ := src.Read(context.Background(), json.RawMessage(`{"thresholdDays":30}`))
	if v.Float == nil || *v.Float != 0 {
		t.Errorf("count = %v; want 0", v.Float)
	}
	// Context is still populated with a zero count and empty list.
	if v.Context == nil {
		t.Fatalf("expected Context payload even when count is 0, got nil")
	}
	if got := v.Context["count"]; got != 0 {
		t.Errorf("Context[count] = %v; want 0", got)
	}
	certsRaw, ok := v.Context["certs"].([]map[string]any)
	if !ok {
		t.Fatalf("Context[certs] is not []map[string]any: %T", v.Context["certs"])
	}
	if len(certsRaw) != 0 {
		t.Errorf("Context[certs] len = %d; want 0", len(certsRaw))
	}
}
