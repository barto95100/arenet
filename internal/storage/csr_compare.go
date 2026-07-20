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

import "crypto/x509"

// New non-blocking warning codes for the CSR re-import diff (spec §5.3).
// Extend the CertWarn* set in external_cert_parse.go.
const (
	CertWarnSubjectCNRewritten      = "subject_cn_rewritten"
	CertWarnSubjectOrgRewritten     = "subject_org_rewritten"
	CertWarnSubjectCountryRewritten = "subject_country_rewritten"
	CertWarnSANsMissing             = "sans_missing"
	CertWarnSANsExtra               = "sans_extra"
)

// CompareCSRAndCert reports non-blocking divergences between what the
// operator requested (the stored CSR subject) and what the CA actually
// issued. CAs legitimately rewrite the subject and filter/add SANs
// (spec §Q4); none of these block the import — they inform the operator.
func CompareCSRAndCert(want CSRSubject, cert *x509.Certificate) []CertWarning {
	var out []CertWarning

	if want.CommonName != "" && cert.Subject.CommonName != want.CommonName {
		out = append(out, CertWarning{CertWarnSubjectCNRewritten,
			"CA issued CN " + cert.Subject.CommonName + " (requested " + want.CommonName + ")"})
	}
	if want.Organization != "" && !containsString(cert.Subject.Organization, want.Organization) {
		out = append(out, CertWarning{CertWarnSubjectOrgRewritten,
			"CA rewrote the Organization (requested " + want.Organization + ")"})
	}
	if want.Country != "" && !containsString(cert.Subject.Country, want.Country) {
		out = append(out, CertWarning{CertWarnSubjectCountryRewritten,
			"CA rewrote the Country (requested " + want.Country + ")"})
	}

	// The requested SAN baseline must mirror what GenerateKeyAndCSR
	// actually put on the wire, not the raw operator input: the CSR
	// generator auto-adds the CN to the SAN list when absent (a bare-CN
	// cert with no matching SAN is rejected by modern clients — see
	// csr.go). Without this fold, a CSR requested with empty/CN-less
	// SANs but an issued cert whose SAN list (correctly) includes the
	// CN would report a false-positive sans_extra.
	wantSANs := want.SANs
	if want.CommonName != "" && !containsString(wantSANs, want.CommonName) {
		wantSANs = append([]string{want.CommonName}, wantSANs...)
	}

	issued := map[string]bool{}
	for _, s := range cert.DNSNames {
		issued[s] = true
	}
	requested := map[string]bool{}
	for _, s := range wantSANs {
		requested[s] = true
	}
	var missing []string
	for _, s := range wantSANs {
		if !issued[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		out = append(out, CertWarning{CertWarnSANsMissing,
			"requested SAN(s) not in the issued cert: " + joinComma(missing)})
	}
	var extra []string
	for _, s := range cert.DNSNames {
		if !requested[s] {
			extra = append(extra, s)
		}
	}
	if len(extra) > 0 {
		out = append(out, CertWarning{CertWarnSANsExtra,
			"issued cert has SAN(s) not requested: " + joinComma(extra)})
	}
	return out
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
