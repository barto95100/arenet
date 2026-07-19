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
		{ID: "a", Name: "soon", NotAfter: now.Add(10 * 24 * time.Hour)},
		{ID: "b", Name: "later", NotAfter: now.Add(90 * 24 * time.Hour)},
	}})
	v, err := src.Read(context.Background(), json.RawMessage(`{"thresholdDays":30}`))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if v.Float == nil || *v.Float != 1 {
		t.Errorf("count within threshold = %v; want 1", v.Float)
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
}
