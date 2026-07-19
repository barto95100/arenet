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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// genSelfSignedAPI mirrors storage's genSelfSigned test helper (kept
// local to the api package so this test file is self-contained). Emits
// a PKCS#8 ECDSA key + a self-signed leaf valid for one year.
func genSelfSignedAPI(t *testing.T, cn string, dns []string) (certPEM, keyPEM string) {
	t.Helper()
	now := time.Now()
	return genSelfSignedAPIRange(t, cn, now.Add(-time.Hour), now.Add(365*24*time.Hour), dns)
}

// genSelfSignedExpiredAPI emits a leaf whose validity window is entirely
// in the past, so ParseExternalCert returns a cert_expired warning (but
// no blocking error).
func genSelfSignedExpiredAPI(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	now := time.Now()
	return genSelfSignedAPIRange(t, cn, now.Add(-48*time.Hour), now.Add(-24*time.Hour), []string{cn})
}

func genSelfSignedAPIRange(t *testing.T, cn string, notBefore, notAfter time.Time, dns []string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore, NotAfter: notAfter,
		DNSNames: dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// jsonStr JSON-encodes a string so it can be embedded verbatim in a
// hand-built request body (handles the PEM newlines).
func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func postExternalCert(t *testing.T, env *testEnv, name, certPEM, keyPEM, chainPEM string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"name":` + jsonStr(name) + `,"certPEM":` + jsonStr(certPEM) + `,"keyPEM":` + jsonStr(keyPEM) + `,"chainPEM":` + jsonStr(chainPEM) + `}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/external", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

// TestExternalCert_Upload_RedactsKeyOnGet asserts the private key is
// never echoed back — not in the POST response, not in a later GET.
func TestExternalCert_Upload_RedactsKeyOnGet(t *testing.T) {
	env := newTestEnv(t, false)
	certPEM, keyPEM := genSelfSignedAPI(t, "app.example.com", []string{"app.example.com"})
	rec := postExternalCert(t, env, "c1", certPEM, keyPEM, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Errorf("POST leaked key material: %s", rec.Body)
	}
	var created struct {
		ID     string `json:"id"`
		KeyPEM string `json:"keyPEM"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&created)
	if created.KeyPEM != "" {
		t.Errorf("keyPEM leaked in POST response: %q", created.KeyPEM)
	}
	if created.ID == "" {
		t.Fatal("POST response has no id")
	}

	// GET detail must also redact.
	gr := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/external/"+created.ID, nil)
	grec := httptest.NewRecorder()
	env.router.ServeHTTP(grec, gr)
	if grec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", grec.Code, grec.Body)
	}
	if strings.Contains(grec.Body.String(), "PRIVATE KEY") {
		t.Errorf("GET leaked key material: %s", grec.Body)
	}
}

// TestExternalCert_Upload_ExpiredReturnsWarning pins that an expired
// cert is persisted (201) with a cert_expired warning, not rejected.
func TestExternalCert_Upload_ExpiredReturnsWarning(t *testing.T) {
	env := newTestEnv(t, false)
	certPEM, keyPEM := genSelfSignedExpiredAPI(t, "old.example.com")
	rec := postExternalCert(t, env, "old", certPEM, keyPEM, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s; expired cert must persist with a warning", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "cert_expired") {
		t.Errorf("want cert_expired warning; body=%s", rec.Body)
	}
}

// TestExternalCert_Upload_InvalidCertRejected asserts a blocking parse
// error (garbage PEM) returns 400, not 201.
func TestExternalCert_Upload_InvalidCertRejected(t *testing.T) {
	env := newTestEnv(t, false)
	rec := postExternalCert(t, env, "bad", "not a pem", "not a key", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; garbage cert must be rejected 400", rec.Code, rec.Body)
	}
}

// TestExternalCert_Upload_EmptyKeyReturnsKeyRequired pins spec §3.6:
// an empty keyPEM on create is a distinct, actionable error
// (key_required, 400) — NOT the generic key_does_not_match_cert that
// tls.X509KeyPair would otherwise surface when handed an empty key.
func TestExternalCert_Upload_EmptyKeyReturnsKeyRequired(t *testing.T) {
	env := newTestEnv(t, false)
	certPEM, _ := genSelfSignedAPI(t, "app.example.com", []string{"app.example.com"})
	rec := postExternalCert(t, env, "nokey", certPEM, "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; empty key on create must be 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "key_required") {
		t.Errorf("want key_required error; body=%s", rec.Body)
	}
}

// TestExternalCert_Upload_EmptyCertReturnsCertRequired mirrors the
// key_required guard for the leaf certificate PEM.
func TestExternalCert_Upload_EmptyCertReturnsCertRequired(t *testing.T) {
	env := newTestEnv(t, false)
	_, keyPEM := genSelfSignedAPI(t, "app.example.com", []string{"app.example.com"})
	rec := postExternalCert(t, env, "nocert", "", keyPEM, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; empty cert on create must be 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "cert_required") {
		t.Errorf("want cert_required error; body=%s", rec.Body)
	}
}

// v2.19.1 — a "fullchain" pasted into the Certificate field (leaf +
// intermediate concatenated) is split: the stored CertPEM is the leaf,
// the intermediate moves to ChainPEM. Common CA download format,
// vendor-agnostic.
func TestExternalCert_Upload_FullchainSplit(t *testing.T) {
	env := newTestEnv(t, false)
	leaf, keyPEM := genSelfSignedAPI(t, "app.example.com", []string{"app.example.com"})
	inter, _ := genSelfSignedAPI(t, "Intermediate CA", nil)
	fullchain := leaf + inter

	rec := postExternalCert(t, env, "fullchain", fullchain, keyPEM, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s; fullchain upload must succeed", rec.Code, rec.Body)
	}
	stored, _ := env.store.ListExternalCertificates(context.Background())
	if len(stored) != 1 {
		t.Fatalf("want 1 stored cert; got %d", len(stored))
	}
	if strings.Count(stored[0].CertPEM, "BEGIN CERTIFICATE") != 1 {
		t.Errorf("stored CertPEM should hold only the leaf; got %d blocks", strings.Count(stored[0].CertPEM, "BEGIN CERTIFICATE"))
	}
	if strings.Count(stored[0].ChainPEM, "BEGIN CERTIFICATE") != 1 {
		t.Errorf("stored ChainPEM should hold the intermediate; got %d blocks", strings.Count(stored[0].ChainPEM, "BEGIN CERTIFICATE"))
	}
}

// A chain supplied in BOTH the Certificate field (fullchain) AND the
// Chain field is ambiguous → 400.
func TestExternalCert_Upload_ChainSpecifiedTwice_400(t *testing.T) {
	env := newTestEnv(t, false)
	leaf, keyPEM := genSelfSignedAPI(t, "app.example.com", []string{"app.example.com"})
	inter, _ := genSelfSignedAPI(t, "Intermediate CA", nil)
	fullchain := leaf + inter

	rec := postExternalCert(t, env, "twice", fullchain, keyPEM, inter)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; chain in two places must be 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "chain_specified_twice") {
		t.Errorf("want chain_specified_twice error; body=%s", rec.Body)
	}
}

// TestExternalCert_List_SortedByExpiry asserts the list is ordered by
// NotAfter ascending (soonest-expiring first) regardless of insert
// order.
func TestExternalCert_List_SortedByExpiry(t *testing.T) {
	env := newTestEnv(t, false)
	now := time.Now()

	// Insert in a deliberately unsorted order: far, soon, mid.
	farCert, farKey := genSelfSignedAPIRange(t, "far", now.Add(-time.Hour), now.Add(300*24*time.Hour), []string{"far"})
	soonCert, soonKey := genSelfSignedAPIRange(t, "soon", now.Add(-time.Hour), now.Add(10*24*time.Hour), []string{"soon"})
	midCert, midKey := genSelfSignedAPIRange(t, "mid", now.Add(-time.Hour), now.Add(100*24*time.Hour), []string{"mid"})

	if rec := postExternalCert(t, env, "far", farCert, farKey, ""); rec.Code != http.StatusCreated {
		t.Fatalf("post far: %d %s", rec.Code, rec.Body)
	}
	if rec := postExternalCert(t, env, "soon", soonCert, soonKey, ""); rec.Code != http.StatusCreated {
		t.Fatalf("post soon: %d %s", rec.Code, rec.Body)
	}
	if rec := postExternalCert(t, env, "mid", midCert, midKey, ""); rec.Code != http.StatusCreated {
		t.Fatalf("post mid: %d %s", rec.Code, rec.Body)
	}

	lr := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/external", nil)
	lrec := httptest.NewRecorder()
	env.router.ServeHTTP(lrec, lr)
	if lrec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", lrec.Code, lrec.Body)
	}
	var list []struct {
		Name     string    `json:"name"`
		NotAfter time.Time `json:"notAfter"`
	}
	if err := json.NewDecoder(lrec.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("list len=%d; want 3", len(list))
	}
	wantOrder := []string{"soon", "mid", "far"}
	for i, w := range wantOrder {
		if list[i].Name != w {
			t.Errorf("list[%d].Name=%q; want %q (sort by NotAfter asc). Full order: %v", i, list[i].Name, w, list)
		}
	}
}

// TestExternalCert_Update_ReparsesMetadataOnCertChange pins spec §3.6:
// when a new CertPEM is supplied on PUT, the metadata (NotAfter, DNS
// names, ...) is re-parsed from the new cert, not left stale.
func TestExternalCert_Update_ReparsesMetadataOnCertChange(t *testing.T) {
	env := newTestEnv(t, false)
	now := time.Now()

	aCert, aKey := genSelfSignedAPIRange(t, "a.example.com", now.Add(-time.Hour), now.Add(30*24*time.Hour), []string{"a.example.com"})
	rec := postExternalCert(t, env, "cert", aCert, aKey, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("post A: %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ID       string    `json:"id"`
		NotAfter time.Time `json:"notAfter"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&created)

	// New cert B with a clearly different NotAfter + SAN.
	bCert, bKey := genSelfSignedAPIRange(t, "b.example.com", now.Add(-time.Hour), now.Add(200*24*time.Hour), []string{"b.example.com"})
	putBody := `{"name":"cert","certPEM":` + jsonStr(bCert) + `,"keyPEM":` + jsonStr(bKey) + `}`
	pr := httptest.NewRequest(http.MethodPut, "/api/v1/certificates/external/"+created.ID, strings.NewReader(putBody))
	pr.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	env.router.ServeHTTP(prec, pr)
	if prec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", prec.Code, prec.Body)
	}

	// GET back and confirm metadata reflects cert B.
	gr := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/external/"+created.ID, nil)
	grec := httptest.NewRecorder()
	env.router.ServeHTTP(grec, gr)
	var got struct {
		NotAfter time.Time `json:"notAfter"`
		DNSNames []string  `json:"dnsNames"`
	}
	if err := json.NewDecoder(grec.Body).Decode(&got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if got.NotAfter.Equal(created.NotAfter) {
		t.Errorf("NotAfter not re-parsed after cert change: still %v", got.NotAfter)
	}
	if len(got.DNSNames) != 1 || got.DNSNames[0] != "b.example.com" {
		t.Errorf("DNSNames not re-parsed: %v; want [b.example.com]", got.DNSNames)
	}
}

// TestExternalCert_Update_PreservesKeyWhenEmpty pins the secret
// preserve-on-edit contract: a PUT with an empty KeyPEM must keep the
// stored key (and still succeed, since the stored key still matches the
// unchanged cert).
func TestExternalCert_Update_PreservesKeyWhenEmpty(t *testing.T) {
	env := newTestEnv(t, false)
	certPEM, keyPEM := genSelfSignedAPI(t, "keep.example.com", []string{"keep.example.com"})
	rec := postExternalCert(t, env, "keep", certPEM, keyPEM, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("post: %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&created)

	// PUT only a description change, no cert/key material.
	putBody := `{"name":"keep","description":"renamed","certPEM":"","keyPEM":""}`
	pr := httptest.NewRequest(http.MethodPut, "/api/v1/certificates/external/"+created.ID, strings.NewReader(putBody))
	pr.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	env.router.ServeHTTP(prec, pr)
	if prec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", prec.Code, prec.Body)
	}
	// Stored key must still be present (verify via storage, not the
	// redacted API).
	stored, err := env.store.GetExternalCertificate(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("get stored: %v", err)
	}
	if stored.KeyPEM == "" {
		t.Error("stored KeyPEM was wiped by an empty-key PUT; want preserved")
	}
	if stored.Description != "renamed" {
		t.Errorf("description not updated: %q", stored.Description)
	}
}

// TestExternalCert_Delete_ReloadsAndReturns200 asserts delete removes
// the row, triggers a Caddy reload, and 200s; a second delete is a 404.
func TestExternalCert_Delete_ReloadsAndReturns200(t *testing.T) {
	env := newTestEnv(t, false)
	certPEM, keyPEM := genSelfSignedAPI(t, "del.example.com", []string{"del.example.com"})
	rec := postExternalCert(t, env, "del", certPEM, keyPEM, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("post: %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&created)

	before := env.caddy.CallCount()
	dr := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/external/"+created.ID, nil)
	drec := httptest.NewRecorder()
	env.router.ServeHTTP(drec, dr)
	if drec.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", drec.Code, drec.Body)
	}
	if env.caddy.CallCount() <= before {
		t.Errorf("expected Caddy reload after delete; CallCount before=%d after=%d", before, env.caddy.CallCount())
	}

	// Second delete → 404 (row gone).
	dr2 := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/external/"+created.ID, nil)
	drec2 := httptest.NewRecorder()
	env.router.ServeHTTP(drec2, dr2)
	if drec2.Code != http.StatusNotFound {
		t.Errorf("second DELETE status=%d; want 404", drec2.Code)
	}
}

// TestExternalCert_Get_NotFound asserts a missing id is a 404.
func TestExternalCert_Get_NotFound(t *testing.T) {
	env := newTestEnv(t, false)
	gr := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/external/does-not-exist", nil)
	grec := httptest.NewRecorder()
	env.router.ServeHTTP(grec, gr)
	if grec.Code != http.StatusNotFound {
		t.Errorf("GET missing status=%d; want 404", grec.Code)
	}
}
