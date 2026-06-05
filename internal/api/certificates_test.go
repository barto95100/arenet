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

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/certinfo"
)

// stubCertInfoReader implements CertInfoReader with a canned list.
// Lives in this test file rather than the certinfo package so it
// doesn't bleed test-only types into production builds.
type stubCertInfoReader struct {
	items []*certinfo.CertRuntimeInfo
}

func (s *stubCertInfoReader) List() []*certinfo.CertRuntimeInfo {
	return s.items
}

// TestListCertificates_PopulatedTracker pins the happy path:
// SetCertInfoReader-attached tracker → GET /api/certificates →
// 200 OK with the wire-shape array.
func TestListCertificates_PopulatedTracker(t *testing.T) {
	env := newTestEnv(t, false)
	notAfter := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	env.handler.SetCertInfoReader(&stubCertInfoReader{
		items: []*certinfo.CertRuntimeInfo{
			{
				Domain:    "api.example.com",
				SANList:   []string{"api.example.com"},
				Issuer:    "Let's Encrypt",
				NotBefore: notAfter.Add(-90 * 24 * time.Hour),
				NotAfter:  notAfter,
				Status:    certinfo.StatusValid,
				Source:    certinfo.SourceSpecific,
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got []certinfo.CertRuntimeInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
	}
	if len(got) != 1 {
		t.Fatalf("len=%d want=1; body=%s", len(got), rec.Body.String())
	}
	if got[0].Domain != "api.example.com" {
		t.Fatalf("Domain=%q want=api.example.com", got[0].Domain)
	}
	if got[0].Status != certinfo.StatusValid {
		t.Fatalf("Status=%q want=VALID", got[0].Status)
	}
}

// TestListCertificates_NilReader_Degraded pins the AC #13 degraded
// path: no SetCertInfoReader call → empty array, NOT 500.
func TestListCertificates_NilReader_Degraded(t *testing.T) {
	env := newTestEnv(t, false)
	// Intentionally NOT calling SetCertInfoReader.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=200 (degraded); body=%s", rec.Code, rec.Body.String())
	}
	var got []certinfo.CertRuntimeInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
	}
	if len(got) != 0 {
		t.Fatalf("len=%d want=0", len(got))
	}
}

// TestListCertificates_EmptyTracker pins the empty-list path:
// reader attached, returns nil — the handler coerces to []
// rather than letting `null` ship on the wire.
func TestListCertificates_EmptyTracker(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetCertInfoReader(&stubCertInfoReader{items: nil})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	// Pin the wire-level "always an array" invariant by checking
	// the raw body — JSON null is silently absorbed by []T
	// unmarshal, so a unmarshaled-len check alone is insufficient.
	body := rec.Body.String()
	if body == "null\n" || body == "null" {
		t.Fatalf("body=%q — handler must coerce nil to []", body)
	}
}
