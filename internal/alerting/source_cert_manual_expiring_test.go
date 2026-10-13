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

// v2.72 — the threshold window has bounds, and Read honours it.
//
// ValidateParams accepted any valid JSON, so a rule could be stored
// with thresholdDays 0, -5 or 400 behind a success toast; Read then
// replaced anything <= 0 with 30, and the rule alerted on a window
// the form had never shown. The two tests above both pass
// thresholdDays:30 — the default — so a Read that ignored the param
// entirely would satisfy them; TestCertManualExpiring_HonoursNonDefaultThreshold
// is the one that pins it.
func TestCertManualExpiring_ValidateParamsBounds(t *testing.T) {
	src := NewCertManualExpiringSource(stubCertStore{})
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"absent", `{}`, false},
		{"null means default", `{"thresholdDays":null}`, false},
		{"zero means default", `{"thresholdDays":0}`, false},
		{"min", `{"thresholdDays":1}`, false},
		{"max", `{"thresholdDays":365}`, false},
		{"negative", `{"thresholdDays":-5}`, true},
		{"over max", `{"thresholdDays":400}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := src.ValidateParams(json.RawMessage(tc.raw))
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateParams(%s) = nil; want an out-of-range error", tc.raw)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateParams(%s) = %v; want nil", tc.raw, err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "out of range") {
				t.Errorf("error = %q; want it to name the range", err)
			}
		})
	}
}

func TestCertManualExpiring_HonoursNonDefaultThreshold(t *testing.T) {
	now := time.Now()
	src := NewCertManualExpiringSource(stubCertStore{certs: []storage.ExternalCertificate{
		{ID: "a", Name: "ten-days", NotAfter: now.Add(10 * 24 * time.Hour)},
	}})
	// A 7-day window excludes a cert that a 30-day window catches, so
	// the count separates "the param was read" from "the default was used".
	v, err := src.Read(context.Background(), json.RawMessage(`{"thresholdDays":7}`))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if v.Float == nil || *v.Float != 0 {
		t.Errorf("count within 7 days = %v; want 0 (the cert expires in 10)", v.Float)
	}
	v, err = src.Read(context.Background(), json.RawMessage(`{"thresholdDays":30}`))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if v.Float == nil || *v.Float != 1 {
		t.Errorf("count within 30 days = %v; want 1", v.Float)
	}
}
