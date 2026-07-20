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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// seedExternalCert inserts an ExternalCertificate directly into the
// store with the chosen DNSNames, returning its generated ID. This is
// simpler than round-tripping a real PEM through the parse layer when
// the test only cares about the SAN coverage cross-check.
func seedExternalCert(t *testing.T, env *testEnv, name string, dnsNames []string) string {
	t.Helper()
	created, err := env.store.CreateExternalCertificate(context.Background(), storage.ExternalCertificate{
		Name:     name,
		CertPEM:  "-----BEGIN CERTIFICATE-----\nseed\n-----END CERTIFICATE-----\n",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nseed\n-----END PRIVATE KEY-----\n",
		DNSNames: dnsNames,
	})
	if err != nil {
		t.Fatalf("seed external cert: %v", err)
	}
	return created.ID
}

// seedPendingExternalCert inserts a pending_csr ExternalCertificate
// (empty CertPEM, as createExternalCertCSR leaves it) directly into the
// store with the chosen DNSNames, returning its generated ID. Used to
// pin the v2.20.0 cert_not_ready guard: a pending row must never be
// bindable to a route (empty leaf → silently-broken HTTPS).
func seedPendingExternalCert(t *testing.T, env *testEnv, name string, dnsNames []string) string {
	t.Helper()
	created, err := env.store.CreateExternalCertificate(context.Background(), storage.ExternalCertificate{
		Name:     name,
		Status:   storage.StatusPendingCSR,
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nseed\n-----END PRIVATE KEY-----\n",
		DNSNames: dnsNames,
	})
	if err != nil {
		t.Fatalf("seed pending external cert: %v", err)
	}
	return created.ID
}

// jsonBodyManualCert builds a route POST/PUT body selecting the manual
// cert source referencing certID.
func jsonBodyManualCert(host, certID string) string {
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"http://10.0.0.20:8080","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":true,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"off","cert_source":"manual","cert_id":%q}`,
		host, certID,
	)
}

// TestCreateRoute_ManualCert_CoveringSAN_RoundTrips pins the happy
// path: a manual route whose host is covered by the cert SANs is
// created (201) and a GET echoes certSource:"manual" + certId (the
// wire-field response-serialization half).
func TestCreateRoute_ManualCert_CoveringSAN_RoundTrips(t *testing.T) {
	env := newTestEnv(t, false)
	certID := seedExternalCert(t, env, "wild", []string{"*.example.com"})

	body := jsonBodyManualCert("app.example.com", certID)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s; want 201", rec.Code, rec.Body)
	}

	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.CertSource != "manual" {
		t.Errorf("POST response CertSource=%q; want manual", created.CertSource)
	}
	if created.CertID != certID {
		t.Errorf("POST response CertID=%q; want %q", created.CertID, certID)
	}

	// GET must echo the same two fields (the v2.17.1-class missing
	// response-field regression guard).
	gr := httptest.NewRequest(http.MethodGet, "/api/v1/routes/"+created.ID, nil)
	grec := httptest.NewRecorder()
	env.router.ServeHTTP(grec, gr)
	if grec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", grec.Code, grec.Body)
	}
	var got routeResponse
	if err := json.Unmarshal(grec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if got.CertSource != "manual" || got.CertID != certID {
		t.Errorf("GET echo CertSource=%q CertID=%q; want manual + %q", got.CertSource, got.CertID, certID)
	}

	// Storage carries the two fields too.
	stored, err := env.store.GetRoute(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get stored route: %v", err)
	}
	if stored.CertSource != storage.RouteCertSourceManual || stored.CertID != certID {
		t.Errorf("stored CertSource=%q CertID=%q; want manual + %q", stored.CertSource, stored.CertID, certID)
	}
}

// TestCreateRoute_ManualCert_HostNotCovered rejects a manual route
// whose host is not present in the referenced cert's SANs with a 400
// host_not_covered_by_cert.
func TestCreateRoute_ManualCert_HostNotCovered(t *testing.T) {
	env := newTestEnv(t, false)
	certID := seedExternalCert(t, env, "narrow", []string{"only.other.com"})

	body := jsonBodyManualCert("app.example.com", certID)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "host_not_covered_by_cert") {
		t.Errorf("want host_not_covered_by_cert; body=%s", rec.Body)
	}
}

// TestCreateRoute_ManualCert_UnknownCertID rejects a manual route that
// references a non-existent cert with a 400 cert_not_found.
func TestCreateRoute_ManualCert_UnknownCertID(t *testing.T) {
	env := newTestEnv(t, false)

	body := jsonBodyManualCert("app.example.com", "does-not-exist")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "cert_not_found") {
		t.Errorf("want cert_not_found; body=%s", rec.Body)
	}
}

// TestCreateRoute_ManualCert_PendingCSR_Rejected pins the v2.20.0
// finding: a manual route referencing a pending_csr cert (no signed
// leaf yet) is rejected with 400 cert_not_ready, even though the
// pending row's SANs cover the route host. Without this guard the
// route would be created TLS-enabled but serve NO certificate (the
// empty leaf is skipped at Caddy-config emission).
func TestCreateRoute_ManualCert_PendingCSR_Rejected(t *testing.T) {
	env := newTestEnv(t, false)
	certID := seedPendingExternalCert(t, env, "pending", []string{"app.example.com"})

	body := jsonBodyManualCert("app.example.com", certID)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "cert_not_ready") {
		t.Errorf("want cert_not_ready; body=%s", rec.Body)
	}
}

// TestDeleteExternalCert_ReferencedByRoute_409 pins the DELETE
// 409-guard: a cert referenced by a manual route cannot be deleted; the
// response lists the blocking route host.
func TestDeleteExternalCert_ReferencedByRoute_409(t *testing.T) {
	env := newTestEnv(t, false)
	certID := seedExternalCert(t, env, "inuse", []string{"*.example.com"})

	body := jsonBodyManualCert("app.example.com", certID)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create route status=%d body=%s", rec.Code, rec.Body)
	}

	dr := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/external/"+certID, nil)
	drec := httptest.NewRecorder()
	env.router.ServeHTTP(drec, dr)
	if drec.Code != http.StatusConflict {
		t.Fatalf("DELETE status=%d body=%s; want 409", drec.Code, drec.Body)
	}
	var resp struct {
		Error          string   `json:"error"`
		BlockingRoutes []string `json:"blockingRoutes"`
	}
	if err := json.Unmarshal(drec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 409 body: %v", err)
	}
	foundHost := false
	for _, h := range resp.BlockingRoutes {
		if h == "app.example.com" {
			foundHost = true
		}
	}
	if !foundHost {
		t.Errorf("blockingRoutes=%v; want it to contain app.example.com", resp.BlockingRoutes)
	}

	// Cert must still exist (delete was blocked).
	if _, err := env.store.GetExternalCertificate(context.Background(), certID); err != nil {
		t.Errorf("cert should survive a blocked delete: %v", err)
	}
}

// v2.19.1 — a manual route WITHOUT TLS enabled does NOT actually serve
// the cert (buildLoadPemList only emits for TLS routes), so it must NOT
// block deletion. Mirrors the v2.18.2 ACME cert-delete fix: the block
// must mirror the emission condition, not host/CertID equality alone.
func TestDeleteExternalCert_ReferencedByNonTLSRoute_200(t *testing.T) {
	env := newTestEnv(t, false)
	certID := seedExternalCert(t, env, "notls", []string{"*.example.com"})

	// Seed the route directly with TLSEnabled=false + manual/CertID
	// (the API create path would apply the SAN cross-check; we want the
	// specific non-TLS-manual state that a route could reach by toggling
	// TLS off after linking a cert).
	if _, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:       "notls.example.com",
		Upstreams:  []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
		TLSEnabled: false,
		CertSource: storage.RouteCertSourceManual,
		CertID:     certID,
	}); err != nil {
		t.Fatalf("seed non-TLS manual route: %v", err)
	}

	dr := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/external/"+certID, nil)
	drec := httptest.NewRecorder()
	env.router.ServeHTTP(drec, dr)
	if drec.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s; want 200 (non-TLS route must not block)", drec.Code, drec.Body)
	}
}
