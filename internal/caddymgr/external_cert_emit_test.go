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

package caddymgr

import (
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// TestBuildConfigJSON_ManualCert_EmitsLoadPemAndSkip is the Task 5
// structural gate for the external-certificates SOCLE: a route with
// CertSource="manual" + CertID referencing an ExternalCertificate must
//   - EMIT the cert via apps.tls.certificates.load_pem (cert + key PEM),
//   - add the host to automatic_https.skip_certificates (so auto-HTTPS
//     does not manage / ACME-issue it),
//   - NOT emit any ACME automation policy for that host.
//
// We deliberately do NOT call caddy.Validate or metrics.SetRegistry in
// THIS file: it sorts alphabetically BEFORE manager_test.go, and either
// call would leak Caddy admin-endpoint / metrics-registry global state
// into the alphabetically-later TestSyncRegistry_NotCalledOnReload
// Failure and break it — the exact cross-test poisoning documented at
// maintenance_test.go:26-53. Structural string assertions only; the
// real caddy.Validate coverage lives in TestBuildConfigJSON_LoadsCleanly
// (manager_test.go), which runs safely after the sync-registry test.
func TestBuildConfigJSON_ManualCert_EmitsLoadPemAndSkip(t *testing.T) {
	routes := []storage.Route{{
		ID: "m1", Host: "app.example.com", TLSEnabled: true,
		CertSource: "manual", CertID: "cert-uuid",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}
	opts := buildOpts{DevMode: true, ExternalCerts: map[string]storage.ExternalCertificate{
		"cert-uuid": {ID: "cert-uuid", CertPEM: "CERTPEM", KeyPEM: "KEYPEM", DNSNames: []string{"app.example.com"}},
	}}
	cfgJSON, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	compact := strings.Join(strings.Fields(string(cfgJSON)), "")
	if !strings.Contains(compact, `"load_pem"`) {
		t.Error("no load_pem block emitted for manual cert route")
	}
	if !strings.Contains(compact, "CERTPEM") || !strings.Contains(compact, "KEYPEM") {
		t.Error("cert/key PEM not in load_pem block")
	}
	if !strings.Contains(compact, `"skip_certificates"`) || !strings.Contains(compact, "app.example.com") {
		t.Error("manual host not added to skip_certificates")
	}
	// Must NOT emit an ACME automation policy for this host.
	if strings.Contains(compact, `"module":"acme"`) {
		t.Error("manual route wrongly emitted an ACME policy")
	}
}
