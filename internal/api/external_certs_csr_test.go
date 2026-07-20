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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// signLeafForStoredKey simulates the CA step of the CSR workflow: it
// reads the pending row's stored private key directly from the store
// (in-process — the API never echoes it back), derives its public key,
// and mints a self-signed leaf for the given CN/SANs against that same
// key pair. Only the public key needs to match the stored private key
// for tls.X509KeyPair (ParseExternalCert's mandatory gate) to accept it
// — a real CA-issued cert would satisfy the same constraint.
func signLeafForStoredKey(t *testing.T, env *testEnv, id, cn string, sans []string) string {
	t.Helper()
	stored, err := env.store.GetExternalCertificate(t.Context(), id)
	if err != nil {
		t.Fatalf("get stored row for signing: %v", err)
	}
	block, _ := pem.Decode([]byte(stored.KeyPEM))
	if block == nil {
		t.Fatalf("stored KeyPEM did not PEM-decode: %q", stored.KeyPEM)
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse stored PKCS8 key: %v", err)
	}
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("stored key is not RSA (got %T); test only covers rsa_4096 CSRs", priv)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		DNSNames:     sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaPriv.PublicKey, rsaPriv)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestReimportSignedCert_FlipsStatusAndWarns drives the core CSR
// workflow: generate a pending CSR, "sign" a leaf for the stored key
// with a rewritten CN and a dropped SAN (simulating a CA that doesn't
// return exactly what was requested — spec §Q4), then PUT it back with
// an empty keyPEM (preserve-on-edit). The row must flip from
// pending_csr to active (status "") and the response must surface both
// the CN-rewritten and SANs-missing warnings.
func TestReimportSignedCert_FlipsStatusAndWarns(t *testing.T) {
	env := newTestEnv(t, false)

	gen := `{"name":"x","csrSubject":{"commonName":"app.corp.local",` +
		`"sans":["app.corp.local","www.corp.local"],"keyAlgorithm":"rsa_4096"}}`
	greq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/external/csr", strings.NewReader(gen))
	greq.Header.Set("Content-Type", "application/json")
	grec := httptest.NewRecorder()
	env.router.ServeHTTP(grec, greq)
	if grec.Code != http.StatusCreated {
		t.Fatalf("CSR create status = %d, body %s", grec.Code, grec.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(grec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("create response has no id: %v", created)
	}

	// The CA signs: CN rewritten, one requested SAN dropped.
	signedPEM := signLeafForStoredKey(t, env, id, "app.corp.internal", []string{"app.corp.local"})

	putBody := `{"name":"x","certPEM":` + jsonStr(signedPEM) + `,"keyPEM":""}`
	preq := httptest.NewRequest(http.MethodPut, "/api/v1/certificates/external/"+id, strings.NewReader(putBody))
	preq.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	env.router.ServeHTTP(prec, preq)
	if prec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body %s", prec.Code, prec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(prec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	// Status has `omitempty`: an active (cleared) status is absent from
	// the JSON entirely, not present as "".
	if v, present := resp["status"]; present {
		t.Fatalf("status should be cleared to active (omitted from JSON), got %v", v)
	}
	ws, _ := resp["warnings"].([]any)
	found := map[string]bool{}
	for _, w := range ws {
		found[w.(map[string]any)["code"].(string)] = true
	}
	if !found["subject_cn_rewritten"] || !found["sans_missing"] {
		t.Fatalf("expected subject_cn_rewritten + sans_missing warnings, got %v", ws)
	}

	// Confirm the row is actually persisted as active, not just the
	// response shape.
	stored, err := env.store.GetExternalCertificate(t.Context(), id)
	if err != nil {
		t.Fatalf("get stored after PUT: %v", err)
	}
	if stored.Status != "" {
		t.Fatalf("stored Status = %q, want cleared to active", stored.Status)
	}
}

// TestReimportSignedCert_KeyMismatch pins that ParseExternalCert's
// mandatory public-key gate (tls.X509KeyPair) still blocks BEFORE any
// status flip: a cert whose key does NOT match the stored private key
// must 400 with key_does_not_match_cert, and the row must remain
// pending_csr (not flipped, not warned).
func TestReimportSignedCert_KeyMismatch(t *testing.T) {
	env := newTestEnv(t, false)

	gen := `{"name":"x","csrSubject":{"commonName":"app.corp.local",` +
		`"sans":["app.corp.local"],"keyAlgorithm":"rsa_4096"}}`
	greq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/external/csr", strings.NewReader(gen))
	greq.Header.Set("Content-Type", "application/json")
	grec := httptest.NewRecorder()
	env.router.ServeHTTP(grec, greq)
	if grec.Code != http.StatusCreated {
		t.Fatalf("CSR create status = %d, body %s", grec.Code, grec.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(grec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("create response has no id: %v", created)
	}

	// A cert signed against a completely different, freshly generated
	// key — its public key will NOT match the stored private key.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "app.corp.local"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		DNSNames:     []string{"app.corp.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatalf("create mismatched leaf: %v", err)
	}
	mismatchedPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	putBody := `{"name":"x","certPEM":` + jsonStr(mismatchedPEM) + `,"keyPEM":""}`
	preq := httptest.NewRequest(http.MethodPut, "/api/v1/certificates/external/"+id, strings.NewReader(putBody))
	preq.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	env.router.ServeHTTP(prec, preq)
	if prec.Code != http.StatusBadRequest {
		t.Fatalf("PUT status = %d, want 400, body %s", prec.Code, prec.Body.String())
	}
	if !strings.Contains(prec.Body.String(), "key_does_not_match_cert") {
		t.Errorf("want key_does_not_match_cert error; body=%s", prec.Body.String())
	}

	stored, err := env.store.GetExternalCertificate(t.Context(), id)
	if err != nil {
		t.Fatalf("get stored after failed PUT: %v", err)
	}
	if stored.Status != "pending_csr" {
		t.Fatalf("stored Status = %q, want unchanged pending_csr after a rejected PUT", stored.Status)
	}
}

// TestReimportSignedCert_NameOnlyEditDoesNotFlipStatus pins the
// critical negative case: a PUT that supplies NO new cert (empty
// req.CertPEM — the preserve-on-edit path) on a pending_csr row must
// NEVER flip it to active, under any outcome. A pending row has no
// leaf yet (CertPEM is empty), so flipping it here would produce an
// invalid "active" row with no certificate — exactly the state Task 7
// guards against.
//
// A pending row's stored CertPEM is empty, and updateExternalCert
// unconditionally re-validates the *effective* leaf/key on every PUT
// (pre-existing SOCLE contract, not something Task 5 changes) — so a
// name-only edit on a still-pending row 400s on invalid_cert_pem
// before ever reaching the clearPending gate. That rejection is
// correct and is itself proof the gate cannot spuriously fire: the
// row must be confirmed unchanged (still pending_csr) afterwards.
func TestReimportSignedCert_NameOnlyEditDoesNotFlipStatus(t *testing.T) {
	env := newTestEnv(t, false)

	gen := `{"name":"x","csrSubject":{"commonName":"app.corp.local",` +
		`"sans":["app.corp.local"],"keyAlgorithm":"rsa_4096"}}`
	greq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/external/csr", strings.NewReader(gen))
	greq.Header.Set("Content-Type", "application/json")
	grec := httptest.NewRecorder()
	env.router.ServeHTTP(grec, greq)
	if grec.Code != http.StatusCreated {
		t.Fatalf("CSR create status = %d, body %s", grec.Code, grec.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(grec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("create response has no id: %v", created)
	}

	// Name-only edit: certPEM and keyPEM both empty. A pending row has
	// no stored leaf, so the effective-leaf re-validation 400s — this
	// is pre-existing SOCLE behavior, not a Task 5 regression.
	putBody := `{"name":"renamed","certPEM":"","keyPEM":""}`
	preq := httptest.NewRequest(http.MethodPut, "/api/v1/certificates/external/"+id, strings.NewReader(putBody))
	preq.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	env.router.ServeHTTP(prec, preq)
	if prec.Code != http.StatusBadRequest {
		t.Fatalf("PUT status = %d, want 400 (pending row has no leaf to re-validate), body %s", prec.Code, prec.Body.String())
	}

	// Whatever the outcome, the row must remain untouched: still
	// pending_csr, name unchanged. This is the load-bearing assertion —
	// the status-flip gate must never fire without a new cert.
	stored, err := env.store.GetExternalCertificate(t.Context(), id)
	if err != nil {
		t.Fatalf("get stored after PUT: %v", err)
	}
	if stored.Status != "pending_csr" {
		t.Fatalf("stored Status = %q, want unchanged pending_csr", stored.Status)
	}
	if stored.Name != "x" {
		t.Errorf("name was unexpectedly changed on a rejected PUT: %q", stored.Name)
	}
}

// TestDeletePendingCSR_NoConflict proves the existing SOCLE DELETE
// handler already deletes a pending_csr row cleanly (200, not 409): the
// delete-guard blocks only when a TLS route references the cert, and a
// pending row (empty CertPEM, no leaf yet) can never be servably
// route-referenced. Regression test only — no production code change.
func TestDeletePendingCSR_NoConflict(t *testing.T) {
	env := newTestEnv(t, false)

	gen := `{"name":"x","csrSubject":{"commonName":"app.corp.local","keyAlgorithm":"rsa_4096"}}`
	greq := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/external/csr", strings.NewReader(gen))
	greq.Header.Set("Content-Type", "application/json")
	grec := httptest.NewRecorder()
	env.router.ServeHTTP(grec, greq)
	if grec.Code != http.StatusCreated {
		t.Fatalf("CSR create status = %d, body %s", grec.Code, grec.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(grec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("create response has no id: %v", created)
	}

	dreq := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/external/"+id, nil)
	drec := httptest.NewRecorder()
	env.router.ServeHTTP(drec, dreq)
	if drec.Code != http.StatusOK {
		t.Fatalf("delete pending = %d, want 200 (a pending row is never route-referenced)", drec.Code)
	}
}
