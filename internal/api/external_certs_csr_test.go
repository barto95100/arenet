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
	"strings"
	"testing"
)

// TestCreateExternalCertCSR_RSA drives the happy path: a valid subject
// generates a key + CSR and stores a pending_csr row. The response must
// redact KeyPEM (secret) but ride CSRPEM through unredacted (public,
// re-downloadable — spec §5.1).
func TestCreateExternalCertCSR_RSA(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"name":"DigiCert app","description":"primary","csrSubject":{` +
		`"commonName":"app.corp.local","sans":["app.corp.local"],` +
		`"organization":"Corp","country":"FR","keyAlgorithm":"rsa_4096"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/external/csr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "pending_csr" {
		t.Fatalf("status = %v, want pending_csr", resp["status"])
	}
	if resp["keyPEM"] != "" {
		t.Fatalf("keyPEM must be redacted, got %v", resp["keyPEM"])
	}
	csrPEM, _ := resp["csrPEM"].(string)
	if csrPEM == "" {
		t.Fatalf("csrPEM must be present in the response, got %v", resp["csrPEM"])
	}
	if !strings.Contains(csrPEM, "CERTIFICATE REQUEST") {
		t.Errorf("csrPEM does not look like a PEM CSR: %q", csrPEM)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Errorf("response leaked key material: %s", rec.Body.String())
	}

	id, _ := resp["id"].(string)
	if id == "" {
		t.Fatalf("response has no id: %v", resp)
	}

	// Read the full stored row in-process — the private key must have
	// actually been persisted even though it's redacted on the wire.
	stored, err := env.store.GetExternalCertificate(t.Context(), id)
	if err != nil {
		t.Fatalf("get stored: %v", err)
	}
	if stored.KeyPEM == "" {
		t.Error("stored KeyPEM is empty; want the generated private key persisted")
	}
	if !strings.Contains(stored.KeyPEM, "PRIVATE KEY") {
		t.Errorf("stored KeyPEM does not look like a PEM key: %q", stored.KeyPEM)
	}
	if stored.CSRPEM == "" {
		t.Error("stored CSRPEM is empty; want the generated CSR persisted")
	}
	if stored.Status != "pending_csr" {
		t.Errorf("stored Status = %q, want pending_csr", stored.Status)
	}
}

// TestCreateExternalCertCSR_CNRequired asserts a missing commonName
// surfaces the storage sentinel's actionable code (cn_required) as a
// 400, not a 500 or silent success.
func TestCreateExternalCertCSR_CNRequired(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"name":"x","csrSubject":{"keyAlgorithm":"rsa_4096"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/external/csr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "cn_required") {
		t.Errorf("want cn_required error; body=%s", rec.Body.String())
	}
}

// TestCreateExternalCertCSR_InvalidKeyAlgorithm pins the third storage
// sentinel (invalid_key_algorithm) surfacing as 400.
func TestCreateExternalCertCSR_InvalidKeyAlgorithm(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"name":"x","csrSubject":{"commonName":"app.corp.local","keyAlgorithm":"dsa_1024"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/external/csr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_key_algorithm") {
		t.Errorf("want invalid_key_algorithm error; body=%s", rec.Body.String())
	}
}

// TestDownloadExternalCertCSR drives the download endpoint end to end:
// generate a CSR via POST, then GET the download route and assert the
// body is a downloadable CSR PEM. SECURITY: the response must never
// contain the private key.
func TestDownloadExternalCertCSR(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"name":"x","csrSubject":{"commonName":"app.corp.local","keyAlgorithm":"rsa_4096"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/external/csr", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("create response has no id: %v", created)
	}

	dreq := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/external/"+id+"/csr", nil)
	drec := httptest.NewRecorder()
	env.router.ServeHTTP(drec, dreq)

	if drec.Code != http.StatusOK {
		t.Fatalf("download status = %d, body %s", drec.Code, drec.Body.String())
	}
	if ct := drec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain; charset=utf-8", ct)
	}
	if cd := drec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".csr") {
		t.Errorf("Content-Disposition = %q, want attachment with .csr filename", cd)
	}
	if !strings.Contains(drec.Body.String(), "CERTIFICATE REQUEST") {
		t.Fatalf("body is not a CSR PEM: %s", drec.Body.String())
	}
	if strings.Contains(drec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("CSR download leaked the private key")
	}
}

// TestDownloadExternalCertCSR_NotFound covers the unknown-id 404 case
// (storage.ErrNotFound). See TestDownloadExternalCertCSR_ExistingRowNoCSR
// for the distinct existing-row-without-CSR 404 case.
func TestDownloadExternalCertCSR_NotFound(t *testing.T) {
	env := newTestEnv(t, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/external/does-not-exist/csr", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body %s", rec.Code, rec.Body.String())
	}
}

// TestDownloadExternalCertCSR_ExistingRowNoCSR covers the second, distinct
// 404 branch: the row exists (found in storage) but was created via the
// plain-upload path (SOCLE bring-your-own-cert), so CSRPEM == "". This
// guards against a refactor silently turning that branch into a
// 200-with-empty-body.
func TestDownloadExternalCertCSR_ExistingRowNoCSR(t *testing.T) {
	env := newTestEnv(t, false)

	certPEM, keyPEM := genSelfSignedAPI(t, "app.example.com", []string{"app.example.com"})
	rec := postExternalCert(t, env, "socle-upload", certPEM, keyPEM, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == "" {
		t.Fatalf("create response has no id: %s", rec.Body.String())
	}

	dreq := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/external/"+created.ID+"/csr", nil)
	drec := httptest.NewRecorder()
	env.router.ServeHTTP(drec, dreq)

	if drec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (existing row, no CSR), body %s", drec.Code, drec.Body.String())
	}
}
