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
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func codes(ws []CertWarning) map[string]bool {
	m := map[string]bool{}
	for _, w := range ws {
		m[w.Code] = true
	}
	return m
}

func TestCompareCSRAndCert_ExactMatch(t *testing.T) {
	want := CSRSubject{CommonName: "app.corp.local", SANs: []string{"app.corp.local"}, Organization: "Corp", Country: "FR"}
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "app.corp.local", Organization: []string{"Corp"}, Country: []string{"FR"}},
		DNSNames: []string{"app.corp.local"},
	}
	if ws := CompareCSRAndCert(want, cert); len(ws) != 0 {
		t.Fatalf("expected no warnings, got %v", ws)
	}
}

func TestCompareCSRAndCert_CNRewritten(t *testing.T) {
	want := CSRSubject{CommonName: "app.corp.local", SANs: []string{"app.corp.local"}}
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "app.corp.internal"}, DNSNames: []string{"app.corp.local"}}
	if !codes(CompareCSRAndCert(want, cert))[CertWarnSubjectCNRewritten] {
		t.Fatalf("expected subject_cn_rewritten")
	}
}

func TestCompareCSRAndCert_SANsMissing(t *testing.T) {
	want := CSRSubject{CommonName: "app.corp.local", SANs: []string{"app.corp.local", "www.corp.local"}}
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "app.corp.local"}, DNSNames: []string{"app.corp.local"}}
	ws := CompareCSRAndCert(want, cert)
	if !codes(ws)[CertWarnSANsMissing] {
		t.Fatalf("expected sans_missing, got %v", ws)
	}
}

func TestCompareCSRAndCert_OrgRewrittenAndSANsExtra(t *testing.T) {
	want := CSRSubject{CommonName: "app.corp.local", SANs: []string{"app.corp.local"}, Organization: "Corp"}
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "app.corp.local", Organization: []string{"Corp Policy Ltd"}},
		DNSNames: []string{"app.corp.local", "extra.corp.local"},
	}
	c := codes(CompareCSRAndCert(want, cert))
	if !c[CertWarnSubjectOrgRewritten] || !c[CertWarnSANsExtra] {
		t.Fatalf("expected org_rewritten + sans_extra, got %v", c)
	}
}
