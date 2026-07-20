# External Certificates — CSR Generation (v2.20.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator generate a private key + CSR inside Arenet, download the CSR for signing by an external CA, then re-import the signed certificate — validated against the key Arenet already holds — all without the private key ever leaving the box.

**Architecture:** A CSR request is a `pending_csr` row in the *existing* `ExternalCertificate` collection (`KeyPEM` + `CSRPEM` filled, `CertPEM` empty). Generation is stdlib crypto (`crypto/x509.CreateCertificateRequest`), no new dependency. Re-import reuses the *existing* SOCLE `PUT` handler (preserve-on-edit keeps the stored key; `tls.X509KeyPair` is the mandatory public-key gate); the PUT gains a status flip + subject/SANs warnings. A pending row is inert but a defensive empty-leaf skip is added to `buildLoadPemList` because emission today is NOT guarded on an empty leaf.

**Tech Stack:** Go 1.25 (`crypto/rsa`, `crypto/ecdsa`, `crypto/x509`, `crypto/x509/pkix`, `encoding/pem`), BoltDB (bbolt), chi router, SvelteKit (Svelte 5, TS), Vitest, Tailwind.

## Global Constraints

- **AGPL header** verbatim at the top of every new Go and TS file (see CLAUDE.md).
- **Go**: `gofmt -s` clean, `go vet ./...` clean, `staticcheck ./...` clean. Errors wrapped `fmt.Errorf("context: %w", err)`. No `panic` outside `main`. `slog` for logs, never `fmt.Println`. I/O funcs take `ctx context.Context` first.
- **Secret discipline (inherited):** `KeyPEM` is a SECRET — redact-on-GET (every response through `toExternalCertResponse`), preserve-on-edit (empty `KeyPEM` on PUT keeps the stored key), never logged, excluded from backup unless `--include-secrets`. `CSRPEM`/`CSRSubject` are PUBLIC — returned in full, always in backup.
- **Migration-free:** new struct fields are `omitempty`; a pre-v2.20.0 row with no `Status` unmarshals as active (`Status == ""`).
- **Wire-field gap checklist (RECURRING BUG — see memory):** any new `ExternalCertificate` field surfaced over the API must be added to the request struct, the create path, the update path, AND the response, or `DisallowUnknownFields` yields a 400. This plan uses a NEW request struct for `/csr`, so the gap applies there, not to `externalCertRequest`.
- **Key algorithms:** exactly two — `rsa_4096` (default) and `ecdsa_p256`. No others.
- **Private key PEM format:** PKCS#8 (`-----BEGIN PRIVATE KEY-----`), matching the SOCLE test fixtures (`external_cert_parse_test.go:49` uses `MarshalPKCS8PrivateKey`) so `tls.X509KeyPair` accepts it on re-import.
- **i18n parity:** every new UI string added to BOTH `en.json` and `fr.json` under `certs.externalCerts.*`; the parity guard test must pass.
- **Branch:** `feature/external-certs-csr` (already created, spec committed `ecd4b41`).
- **Process weight (LIGHT):** implementer per task + controller-inline reviews; DEDICATED reviewer on Task 1 (crypto) and Task 7 (emission-skip invariant); ONE final opus whole-branch review before PR.

---

### Task 1: CSR + keypair generation (`storage.GenerateKeyAndCSR`) — DEDICATED REVIEW

**Files:**
- Create: `internal/storage/csr.go`
- Test: `internal/storage/csr_test.go`

**Interfaces:**
- Consumes: nothing (leaf task).
- Produces:
  - `type CSRSubject struct { CommonName string; SANs []string; Organization string; OrgUnit string; Country string; Locality string; State string; KeyAlgorithm string }` (JSON tags per spec §4).
  - Const `CSRAlgorithmRSA4096 = "rsa_4096"`, `CSRAlgorithmECDSAP256 = "ecdsa_p256"`.
  - `func GenerateKeyAndCSR(subject CSRSubject) (keyPEM string, csrPEM string, err error)` — reads `subject.KeyAlgorithm`; returns PKCS#8 `PRIVATE KEY` PEM + `CERTIFICATE REQUEST` PEM.
  - Error sentinels (plain `errors.New`, actionable codes): `ErrCSRCNRequired = errors.New("cn_required")`, `ErrCSRInvalidCountry = errors.New("invalid_country")`, `ErrCSRInvalidKeyAlgorithm = errors.New("invalid_key_algorithm")`.

- [ ] **Step 1: Write failing tests**

```go
// internal/storage/csr_test.go  (AGPL header above package)
package storage

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func parseCSRPEM(t *testing.T, csrPEM string) *x509.CertificateRequest {
	t.Helper()
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("csr PEM did not decode to a CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr signature invalid: %v", err)
	}
	return csr
}

func parseKeyPEM(t *testing.T, keyPEM string) any {
	t.Helper()
	b, _ := pem.Decode([]byte(keyPEM))
	if b == nil || b.Type != "PRIVATE KEY" {
		t.Fatalf("key PEM did not decode to a PKCS#8 PRIVATE KEY")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		t.Fatalf("parse pkcs8 key: %v", err)
	}
	return k
}

func TestGenerateKeyAndCSR_RSA4096(t *testing.T) {
	subj := CSRSubject{CommonName: "app.corp.local", SANs: []string{"app.corp.local"},
		Organization: "Corp", Country: "FR", KeyAlgorithm: CSRAlgorithmRSA4096}
	keyPEM, csrPEM, err := GenerateKeyAndCSR(subj)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	k := parseKeyPEM(t, keyPEM)
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", k)
	}
	if rk.N.BitLen() != 4096 {
		t.Fatalf("expected 4096-bit key, got %d", rk.N.BitLen())
	}
	csr := parseCSRPEM(t, csrPEM)
	if csr.Subject.CommonName != "app.corp.local" {
		t.Fatalf("CN = %q", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "app.corp.local" {
		t.Fatalf("SANs = %v", csr.DNSNames)
	}
}

func TestGenerateKeyAndCSR_ECDSAP256(t *testing.T) {
	subj := CSRSubject{CommonName: "api.corp.local", KeyAlgorithm: CSRAlgorithmECDSAP256}
	keyPEM, csrPEM, err := GenerateKeyAndCSR(subj)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, ok := parseKeyPEM(t, keyPEM).(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey")
	}
	csr := parseCSRPEM(t, csrPEM)
	// CN auto-added to SANs when SANs empty.
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "api.corp.local" {
		t.Fatalf("expected CN auto-added to SANs, got %v", csr.DNSNames)
	}
}

func TestGenerateKeyAndCSR_Validation(t *testing.T) {
	if _, _, err := GenerateKeyAndCSR(CSRSubject{KeyAlgorithm: CSRAlgorithmRSA4096}); err != ErrCSRCNRequired {
		t.Fatalf("empty CN: want ErrCSRCNRequired, got %v", err)
	}
	if _, _, err := GenerateKeyAndCSR(CSRSubject{CommonName: "x", Country: "FRA", KeyAlgorithm: CSRAlgorithmRSA4096}); err != ErrCSRInvalidCountry {
		t.Fatalf("3-letter country: want ErrCSRInvalidCountry, got %v", err)
	}
	if _, _, err := GenerateKeyAndCSR(CSRSubject{CommonName: "x", KeyAlgorithm: "ed25519"}); err != ErrCSRInvalidKeyAlgorithm {
		t.Fatalf("bad algo: want ErrCSRInvalidKeyAlgorithm, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run TestGenerateKeyAndCSR -v`
Expected: FAIL — `undefined: GenerateKeyAndCSR` / `CSRSubject`.

- [ ] **Step 3: Write the implementation**

```go
// internal/storage/csr.go  (AGPL header above package)
package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
)

// Key-algorithm identifiers accepted by GenerateKeyAndCSR (spec §Q3).
const (
	CSRAlgorithmRSA4096   = "rsa_4096"
	CSRAlgorithmECDSAP256 = "ecdsa_p256"
)

// Blocking validation errors — the API layer surfaces .Error() as the
// actionable code (cn_required, invalid_country, invalid_key_algorithm).
var (
	ErrCSRCNRequired          = errors.New("cn_required")
	ErrCSRInvalidCountry      = errors.New("invalid_country")
	ErrCSRInvalidKeyAlgorithm = errors.New("invalid_key_algorithm")
)

// CSRSubject is the operator-supplied PKCS#10 subject + SANs + chosen
// key algorithm. Stored on the pending ExternalCertificate row for
// display and for the re-import subject/SANs diff.
type CSRSubject struct {
	CommonName   string   `json:"commonName"`
	SANs         []string `json:"sans,omitempty"`
	Organization string   `json:"organization,omitempty"`
	OrgUnit      string   `json:"orgUnit,omitempty"`
	Country      string   `json:"country,omitempty"`
	Locality     string   `json:"locality,omitempty"`
	State        string   `json:"state,omitempty"`
	KeyAlgorithm string   `json:"keyAlgorithm"`
}

// GenerateKeyAndCSR builds a fresh private key and a CSR for the given
// subject. The key is PKCS#8-encoded (matches the SOCLE key format so
// tls.X509KeyPair accepts it on re-import); the CSR is PEM
// CERTIFICATE REQUEST. The CN is auto-added to the SAN list when absent
// (a bare-CN cert with no matching SAN is rejected by modern clients).
func GenerateKeyAndCSR(subject CSRSubject) (keyPEM string, csrPEM string, err error) {
	if subject.CommonName == "" {
		return "", "", ErrCSRCNRequired
	}
	if subject.Country != "" && len(subject.Country) != 2 {
		return "", "", ErrCSRInvalidCountry
	}

	var priv any
	var sigAlgo x509.SignatureAlgorithm
	switch subject.KeyAlgorithm {
	case CSRAlgorithmRSA4096:
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
		sigAlgo = x509.SHA256WithRSA
	case CSRAlgorithmECDSAP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sigAlgo = x509.ECDSAWithSHA256
	default:
		return "", "", ErrCSRInvalidKeyAlgorithm
	}
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	sans := subject.SANs
	if !containsString(sans, subject.CommonName) {
		sans = append([]string{subject.CommonName}, sans...)
	}

	name := pkix.Name{CommonName: subject.CommonName}
	if subject.Organization != "" {
		name.Organization = []string{subject.Organization}
	}
	if subject.OrgUnit != "" {
		name.OrganizationalUnit = []string{subject.OrgUnit}
	}
	if subject.Country != "" {
		name.Country = []string{subject.Country}
	}
	if subject.Locality != "" {
		name.Locality = []string{subject.Locality}
	}
	if subject.State != "" {
		name.Province = []string{subject.State}
	}

	tmpl := &x509.CertificateRequest{
		Subject:            name,
		DNSNames:           sans,
		SignatureAlgorithm: sigAlgo,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return "", "", fmt.Errorf("create csr: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}

	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	return keyPEM, csrPEM, nil
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests + vet + staticcheck**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run TestGenerateKeyAndCSR -v && go vet ./internal/storage/ && gofmt -l internal/storage/csr.go`
Expected: PASS (all 3 tests), no vet output, `gofmt -l` prints nothing.

- [ ] **Step 5: Commit**

```bash
git add internal/storage/csr.go internal/storage/csr_test.go
git commit -m "feat(external-certs): CSR + keypair generation (RSA4096/ECDSA-P256)"
```

---

### Task 2: Storage struct extension + subject/SANs compare helper

**Files:**
- Modify: `internal/storage/external_cert.go:34-54` (add 3 fields to `ExternalCertificate`)
- Create: `internal/storage/csr_compare.go`
- Test: `internal/storage/csr_compare_test.go`

**Interfaces:**
- Consumes: `CSRSubject` (Task 1), `CertWarning` (existing, `external_cert_parse.go:34`).
- Produces:
  - `ExternalCertificate.Status string` (`json:"status,omitempty"`), `.CSRPEM string` (`json:"csrPEM,omitempty"`), `.CSRSubject CSRSubject` (`json:"csrSubject,omitempty"`).
  - Const `StatusPendingCSR = "pending_csr"` (active is `""`).
  - New warning codes: `CertWarnSubjectCNRewritten = "subject_cn_rewritten"`, `CertWarnSubjectOrgRewritten = "subject_org_rewritten"`, `CertWarnSubjectCountryRewritten = "subject_country_rewritten"`, `CertWarnSANsMissing = "sans_missing"`, `CertWarnSANsExtra = "sans_extra"`.
  - `func CompareCSRAndCert(want CSRSubject, cert *x509.Certificate) []CertWarning`.

- [ ] **Step 1: Add the struct fields + status const**

In `internal/storage/external_cert.go`, after the existing `DNSNames []string` field (before `CreatedAt`), add:

```go
	// v2.20.0 CSR generation. Empty on every SOCLE-uploaded cert.
	Status     string     `json:"status,omitempty"`    // "" = active | "pending_csr"
	CSRPEM     string     `json:"csrPEM,omitempty"`     // PUBLIC — re-downloadable
	CSRSubject CSRSubject `json:"csrSubject,omitempty"` // requested subject (display + diff)
```

And near the top of the file, after the imports/type doc, add:

```go
// StatusPendingCSR marks a row that carries a generated key + CSR and is
// awaiting its signed certificate. Such a row has an empty CertPEM and is
// never emitted as load_pem (Task 7). Active certs have Status == "".
const StatusPendingCSR = "pending_csr"
```

- [ ] **Step 2: Write failing compare tests**

```go
// internal/storage/csr_compare_test.go  (AGPL header)
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run TestCompareCSRAndCert -v`
Expected: FAIL — `undefined: CompareCSRAndCert` and the warning-code consts.

- [ ] **Step 4: Write the implementation**

```go
// internal/storage/csr_compare.go  (AGPL header)
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

	issued := map[string]bool{}
	for _, s := range cert.DNSNames {
		issued[s] = true
	}
	requested := map[string]bool{}
	for _, s := range want.SANs {
		requested[s] = true
	}
	var missing []string
	for _, s := range want.SANs {
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
```

- [ ] **Step 5: Run tests + vet**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run 'TestCompareCSRAndCert|TestGenerateKeyAndCSR' -v && go vet ./internal/storage/`
Expected: PASS, no vet output.

- [ ] **Step 6: Commit**

```bash
git add internal/storage/external_cert.go internal/storage/csr_compare.go internal/storage/csr_compare_test.go
git commit -m "feat(external-certs): pending_csr fields + CSR/cert subject-SANs diff"
```

---

> **API test harness (Tasks 3–6) — use the REAL helpers, verified in `internal/api/external_certs_test.go`.** The skeletons below use shorthand (`newTestHandler(t)`, `withAdminSession`, `h.Router()`) — those names DO NOT exist. Map them to the actual harness before writing:
> - `env := newTestEnv(t, false)` builds the handler + wired router + store. There is no separate admin-session wrapper — `env.router` already serves the admin routes in tests.
> - Drive requests with `env.router.ServeHTTP(rec, req)` (NOT `h.Router()`), `rec := httptest.NewRecorder()`.
> - Read the full stored row (incl. `KeyPEM`) in-process via `env.store.GetExternalCertificate(t.Context(), id)`.
> - Build request bodies with the existing `jsonStr(...)` helper for PEM strings; set `req.Header.Set("Content-Type","application/json")`.
> - For Task 5's `signLeafForStoredKey`, reuse the existing `genSelfSignedAPIRange(t, cn, notBefore, notAfter, dns)` pattern but sign with the key read back from `env.store` (self-signed is fine — only the public key must match the stored private key).
> Read `external_certs_test.go` top-to-bottom before Task 3 and mirror it exactly.

### Task 3: API — generate endpoint `POST /certificates/external/csr`

**Files:**
- Modify: `internal/api/external_certs.go` (add `createExternalCertCSR` handler + request struct)
- Modify: `internal/api/routes.go:369` (register the admin route)
- Modify: `internal/audit/actions.go:254-256,324-326` (add the audit action)
- Test: `internal/api/external_certs_csr_test.go`

**Interfaces:**
- Consumes: `storage.GenerateKeyAndCSR` (Task 1), `storage.CSRSubject`, `storage.StatusPendingCSR`, `storage.CreateExternalCertificate` (existing), `toExternalCertResponse` (existing, `external_certs.go:66`).
- Produces: `POST /api/v1/certificates/external/csr` → `201` with `externalCertResponse` (keyPEM redacted, `csrPEM` populated).

- [ ] **Step 1: Add the audit action**

In `internal/audit/actions.go`, add after `ActionExternalCertDeleted` (line 256):

```go
	ActionExternalCertCSRGenerated = "external_cert_csr_generated"
```

And add `ActionExternalCertCSRGenerated,` to the slice around line 326 (next to the other three).

- [ ] **Step 2: Write the failing test**

```go
// internal/api/external_certs_csr_test.go  (AGPL header)
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestHandler + admin session helpers already exist in the api test
// suite (see external_certs_test.go). Reuse them here.
func TestCreateExternalCertCSR_RSA(t *testing.T) {
	h, cleanup := newTestHandler(t) // existing helper
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"name": "DigiCert app", "description": "primary",
		"csrSubject": map[string]any{
			"commonName": "app.corp.local", "sans": []string{"app.corp.local"},
			"organization": "Corp", "country": "FR", "keyAlgorithm": "rsa_4096",
		},
	})
	req := httptest.NewRequest("POST", "/api/v1/certificates/external/csr", bytes.NewReader(body))
	withAdminSession(t, req, h) // existing helper
	rec := httptest.NewRecorder()
	h.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "pending_csr" {
		t.Fatalf("status = %v", resp["status"])
	}
	if resp["keyPEM"] != "" {
		t.Fatalf("keyPEM must be redacted, got %v", resp["keyPEM"])
	}
	if s, _ := resp["csrPEM"].(string); s == "" {
		t.Fatalf("csrPEM must be present")
	}
}

func TestCreateExternalCertCSR_CNRequired(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()
	body, _ := json.Marshal(map[string]any{"name": "x", "csrSubject": map[string]any{"keyAlgorithm": "rsa_4096"}})
	req := httptest.NewRequest("POST", "/api/v1/certificates/external/csr", bytes.NewReader(body))
	withAdminSession(t, req, h)
	rec := httptest.NewRecorder()
	h.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
```

> Per the harness note above: replace `newTestHandler(t)`→`newTestEnv(t, false)`, `h.Router()`→`env.router`, drop `withAdminSession`. Build the body via `jsonStr` if it contains PEM.

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run TestCreateExternalCertCSR -v`
Expected: FAIL — 404 (route unregistered).

- [ ] **Step 4: Add the handler**

Append to `internal/api/external_certs.go`:

```go
// externalCertCSRRequest is the wire shape for POST …/external/csr.
type externalCertCSRRequest struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	CSRSubject  storage.CSRSubject `json:"csrSubject"`
}

// createExternalCertCSR generates a key + CSR and stores a pending_csr
// row (spec §5.1). The private key is stored (redacted on the echo); the
// CSR is returned so the UI can offer immediate download.
func (h *Handler) createExternalCertCSR(w http.ResponseWriter, r *http.Request) {
	var req externalCertCSRRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	keyPEM, csrPEM, err := storage.GenerateKeyAndCSR(req.CSRSubject)
	if err != nil {
		// storage sentinels carry actionable codes as their message.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rec := storage.ExternalCertificate{
		Name:        req.Name,
		Description: req.Description,
		Status:      storage.StatusPendingCSR,
		KeyPEM:      keyPEM,
		CSRPEM:      csrPEM,
		CSRSubject:  req.CSRSubject,
		DNSNames:    req.CSRSubject.SANs,
	}
	created, err := h.store.CreateExternalCertificate(r.Context(), rec)
	if err != nil {
		h.logger.Error("create external cert csr", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to save CSR request")
		return
	}
	h.appendAudit(r, audit.Event{Action: audit.ActionExternalCertCSRGenerated, TargetType: "external_certificate", TargetID: created.ID})
	writeJSON(w, http.StatusCreated, toExternalCertResponse(created, nil))
}
```

> Confirm `toExternalCertResponse` does NOT blank `csrPEM` — it only blanks `KeyPEM` (`external_certs.go:66-69`). `CSRPEM` rides through the embedded struct. Add an explicit assertion in the test if unsure.

- [ ] **Step 5: Register the route**

In `internal/api/routes.go`, in the admin block (near line 369), add:

```go
				r.Post("/certificates/external/csr", h.createExternalCertCSR)
```

> Place it BEFORE `r.Put("/certificates/external/{id}", …)` is irrelevant for chi (distinct methods/paths), but keep it grouped with the other `certificates/external` mutations for readability.

- [ ] **Step 6: Run tests + vet**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run TestCreateExternalCertCSR -v && go vet ./internal/api/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/api/external_certs.go internal/api/routes.go internal/audit/actions.go internal/api/external_certs_csr_test.go
git commit -m "feat(external-certs): POST /certificates/external/csr generate endpoint"
```

---

### Task 4: API — download CSR `GET /certificates/external/{id}/csr`

**Files:**
- Modify: `internal/api/external_certs.go` (add `downloadExternalCertCSR`)
- Modify: `internal/api/routes.go:178` (register viewer route)
- Test: `internal/api/external_certs_csr_test.go` (append)

**Interfaces:**
- Consumes: `storage.GetExternalCertificate` (existing).
- Produces: `GET /api/v1/certificates/external/{id}/csr` → `200 text/plain` PEM (CSR only, never the key); `404` if the row has no CSR.

- [ ] **Step 1: Write the failing test**

```go
func TestDownloadExternalCertCSR(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()
	// generate one first
	body, _ := json.Marshal(map[string]any{"name": "x",
		"csrSubject": map[string]any{"commonName": "app.corp.local", "keyAlgorithm": "rsa_4096"}})
	req := httptest.NewRequest("POST", "/api/v1/certificates/external/csr", bytes.NewReader(body))
	withAdminSession(t, req, h)
	rec := httptest.NewRecorder()
	h.Router().ServeHTTP(rec, req)
	var created map[string]any
	json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)

	dreq := httptest.NewRequest("GET", "/api/v1/certificates/external/"+id+"/csr", nil)
	withAdminSession(t, dreq, h)
	drec := httptest.NewRecorder()
	h.Router().ServeHTTP(drec, dreq)
	if drec.Code != http.StatusOK {
		t.Fatalf("status = %d", drec.Code)
	}
	if !bytes.Contains(drec.Body.Bytes(), []byte("CERTIFICATE REQUEST")) {
		t.Fatalf("body is not a CSR PEM: %s", drec.Body.String())
	}
	if bytes.Contains(drec.Body.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatalf("CSR download leaked the private key")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run TestDownloadExternalCertCSR -v`
Expected: FAIL — 404.

- [ ] **Step 3: Add the handler**

```go
// downloadExternalCertCSR returns the stored CSR as a downloadable PEM
// (spec §5.2). The CSR is public; the private key is never served here.
func (h *Handler) downloadExternalCertCSR(w http.ResponseWriter, r *http.Request) {
	c, err := h.store.GetExternalCertificate(r.Context(), chi.URLParam(r, "id"))
	if err == storage.ErrNotFound {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	if err != nil {
		h.logger.Error("get external cert for csr download", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load certificate")
		return
	}
	if c.CSRPEM == "" {
		writeError(w, http.StatusNotFound, "no CSR for this certificate")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(c.Name)+`.csr"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(c.CSRPEM))
}

// sanitizeFilename keeps a Content-Disposition filename to a safe subset.
func sanitizeFilename(name string) string {
	if name == "" {
		return "certificate"
	}
	out := make([]rune, 0, len(name))
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}
```

- [ ] **Step 4: Register the viewer route**

In `internal/api/routes.go`, after line 178 (the viewer GET-by-id):

```go
			r.Get("/certificates/external/{id}/csr", h.downloadExternalCertCSR)
```

- [ ] **Step 5: Run tests + vet**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run 'TestDownloadExternalCertCSR|TestCreateExternalCertCSR' -v && go vet ./internal/api/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/api/external_certs.go internal/api/routes.go internal/api/external_certs_csr_test.go
git commit -m "feat(external-certs): GET /certificates/external/{id}/csr download"
```

---

### Task 5: API — PUT re-import: status flip + subject/SANs warnings

**Files:**
- Modify: `internal/api/external_certs.go:164-274` (`updateExternalCert`)
- Test: `internal/api/external_certs_csr_test.go` (append)

**Interfaces:**
- Consumes: `storage.StatusPendingCSR`, `storage.CompareCSRAndCert` (Task 2), `storage.ParseExternalCert` (existing — its `tls.X509KeyPair` is the mandatory public-key gate, already `key_does_not_match_cert`).
- Produces: PUT on a `pending_csr` row with a matching signed cert → `Status` cleared to `""`, response `warnings` include subject/SANs diff.

- [ ] **Step 1: Write the failing test**

Generate a pending CSR, then self-sign a cert FOR THE STORED KEY to simulate the CA. Because the test cannot read the redacted key back over the API, sign at the storage layer via a helper: read the row directly from the store (`h.store.GetExternalCertificate` returns the full row incl. KeyPEM in-process) and build a leaf with `x509.CreateCertificate` using that key.

```go
func TestReimportSignedCert_FlipsStatusAndWarns(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	// 1. generate pending CSR (RSA)
	gen, _ := json.Marshal(map[string]any{"name": "x",
		"csrSubject": map[string]any{"commonName": "app.corp.local", "sans": []string{"app.corp.local", "www.corp.local"}, "keyAlgorithm": "rsa_4096"}})
	greq := httptest.NewRequest("POST", "/api/v1/certificates/external/csr", bytes.NewReader(gen))
	withAdminSession(t, greq, h)
	grec := httptest.NewRecorder()
	h.Router().ServeHTTP(grec, greq)
	var created map[string]any
	json.Unmarshal(grec.Body.Bytes(), &created)
	id := created["id"].(string)

	// 2. the CA signs: read full row (KeyPEM present in-process), mint a
	//    leaf whose CN was rewritten and one SAN dropped.
	signedPEM := signLeafForStoredKey(t, h, id, "app.corp.internal", []string{"app.corp.local"})

	// 3. PUT the signed cert with empty keyPEM (preserve-on-edit)
	put, _ := json.Marshal(map[string]any{"name": "x", "certPEM": signedPEM})
	preq := httptest.NewRequest("PUT", "/api/v1/certificates/external/"+id, bytes.NewReader(put))
	withAdminSession(t, preq, h)
	prec := httptest.NewRecorder()
	h.Router().ServeHTTP(prec, preq)
	if prec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", prec.Code, prec.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(prec.Body.Bytes(), &resp)
	if resp["status"] != "" {
		t.Fatalf("status should be cleared to active, got %v", resp["status"])
	}
	ws, _ := resp["warnings"].([]any)
	found := map[string]bool{}
	for _, w := range ws {
		found[w.(map[string]any)["code"].(string)] = true
	}
	if !found["subject_cn_rewritten"] || !found["sans_missing"] {
		t.Fatalf("expected cn_rewritten + sans_missing, got %v", ws)
	}
}
```

> `signLeafForStoredKey(t, h, id, cn, sans)` is a test helper in this file: it calls `h.store.GetExternalCertificate(ctx, id)`, `pem.Decode`+`x509.ParsePKCS8PrivateKey` on `.KeyPEM`, builds an `x509.Certificate` template with the given CN/SANs, `x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)` (self-signed is fine — only the public key must match), and returns the leaf PEM. Write it in the test file.

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run TestReimportSignedCert -v`
Expected: FAIL — status not cleared / warnings absent (current PUT ignores pending).

- [ ] **Step 3: Modify `updateExternalCert`**

After the existing `meta, warnings, err := storage.ParseExternalCert(...)` block (around line 231) and BEFORE building `rec`, add the pending-transition handling. When the row was pending and a new cert was supplied, append the CSR diff to `warnings` and clear the status:

```go
	// v2.20.0: re-import onto a pending_csr row. ParseExternalCert already
	// enforced the mandatory public-key match (tls.X509KeyPair →
	// key_does_not_match_cert). Add the non-blocking subject/SANs diff and
	// flip the row to active.
	clearPending := false
	if existing.Status == storage.StatusPendingCSR && req.CertPEM != "" {
		if block, _ := pem.Decode([]byte(certPEM)); block != nil {
			if leaf, perr := x509.ParseCertificate(block.Bytes); perr == nil {
				warnings = append(warnings, storage.CompareCSRAndCert(existing.CSRSubject, leaf)...)
			}
		}
		clearPending = true
	}
```

Then after `rec := existing` and the field assignments, add:

```go
	if clearPending {
		rec.Status = "" // now active and servable
	}
```

Add `"crypto/x509"` and `"encoding/pem"` to the file's imports if not present.

- [ ] **Step 4: Run tests + vet**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run 'TestReimport|TestCreateExternalCertCSR|TestDownloadExternalCertCSR' -v && go vet ./internal/api/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/external_certs.go internal/api/external_certs_csr_test.go
git commit -m "feat(external-certs): re-import flips pending_csr to active + subject/SANs warnings"
```

---

### Task 6: Verify delete-pending needs no change (regression test only)

**Files:**
- Test: `internal/api/external_certs_csr_test.go` (append)

**Interfaces:** Consumes existing `DELETE` handler.

- [ ] **Step 1: Write the test asserting a pending row deletes cleanly (no 409)**

```go
func TestDeletePendingCSR_NoConflict(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()
	gen, _ := json.Marshal(map[string]any{"name": "x",
		"csrSubject": map[string]any{"commonName": "app.corp.local", "keyAlgorithm": "rsa_4096"}})
	greq := httptest.NewRequest("POST", "/api/v1/certificates/external/csr", bytes.NewReader(gen))
	withAdminSession(t, greq, h)
	grec := httptest.NewRecorder()
	h.Router().ServeHTTP(grec, greq)
	var created map[string]any
	json.Unmarshal(grec.Body.Bytes(), &created)
	id := created["id"].(string)

	dreq := httptest.NewRequest("DELETE", "/api/v1/certificates/external/"+id, nil)
	withAdminSession(t, dreq, h)
	drec := httptest.NewRecorder()
	h.Router().ServeHTTP(drec, dreq)
	if drec.Code != http.StatusOK {
		t.Fatalf("delete pending = %d, want 200 (a pending row is never route-referenced)", drec.Code)
	}
}
```

- [ ] **Step 2: Run — expected PASS immediately** (proves the delete-guard already handles pending correctly; no code change).

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run TestDeletePendingCSR -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/api/external_certs_csr_test.go
git commit -m "test(external-certs): delete-guard already handles pending_csr rows"
```

---

### Task 7: caddymgr — empty-leaf emission skip — DEDICATED REVIEW

**Files:**
- Modify: `internal/caddymgr/manager.go:2591` (inside `buildLoadPemList`)
- Test: `internal/caddymgr/external_cert_emit_test.go` (append)

**Interfaces:** Consumes `storage.ExternalCertificate` with empty `CertPEM`.

- [ ] **Step 1: Write the failing empirical test**

```go
// append to internal/caddymgr/external_cert_emit_test.go
func TestBuildLoadPemList_SkipsPendingEmptyLeaf(t *testing.T) {
	routes := []storage.Route{{
		Host: "app.corp.local", CertSource: storage.RouteCertSourceManual,
		CertID: "pending-1", TLSEnabled: true,
	}}
	ext := map[string]storage.ExternalCertificate{
		"pending-1": {ID: "pending-1", Status: storage.StatusPendingCSR, CertPEM: "", KeyPEM: "irrelevant"},
	}
	got := buildLoadPemList(routes, ext)
	if got != nil {
		t.Fatalf("a pending (empty-leaf) row must not be emitted, got %v", got)
	}
}
```

> If a full build-and-validate test harness exists (`TestBuildConfigJSON_LoadsCleanly`), also add a case wiring a route to a pending cert and assert the emitted JSON still `caddy.Validate()`s and contains no `load_pem`. Follow the existing harness signature in the file.

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ -run TestBuildLoadPemList_SkipsPendingEmptyLeaf -v`
Expected: FAIL — the row IS emitted with `"certificate": ""`.

- [ ] **Step 3: Add the skip**

In `internal/caddymgr/manager.go`, inside `buildLoadPemList`, immediately after `cert, ok := ext[route.CertID]` / the dangling-`ok` check and BEFORE `seen[route.CertID] = struct{}{}` (around line 2589-2590):

```go
		if cert.CertPEM == "" {
			// A pending_csr row (or any cert missing its leaf) is not
			// servable — emitting {"certificate":"", ...} yields invalid
			// Caddy JSON. Skip it defensively; emission is NOT otherwise
			// guarded on an empty leaf (verified manager.go:2591, v2.20.0).
			continue
		}
```

- [ ] **Step 4: Run tests + vet + the broader caddymgr suite**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ -run 'TestBuildLoadPemList|TestBuildConfigJSON' -v && go vet ./internal/caddymgr/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/caddymgr/manager.go internal/caddymgr/external_cert_emit_test.go
git commit -m "fix(external-certs): skip empty-leaf (pending_csr) rows in load_pem emission"
```

---

### Task 8: Frontend API client + types

**Files:**
- Modify: `web/frontend/src/lib/api/types.ts:1004-1060` (extend `ExternalCertificate`, add `CSRSubject`, `GenerateCSRRequest`, new warning codes doc)
- Modify: `web/frontend/src/lib/api/external-certs.ts` (add `generateCSR`, `csrDownloadUrl`)
- Test: `web/frontend/src/lib/api/external-certs.test.ts` (append)

**Interfaces:**
- Produces: `externalCertsApi.generateCSR(req: GenerateCSRRequest): Promise<ExternalCertificate>`; `externalCertsApi.csrDownloadUrl(id: string): string`.

- [ ] **Step 1: Extend the types**

In `types.ts`, add to `ExternalCertificate`:

```ts
	status?: '' | 'pending_csr';
	csrPEM?: string;
	csrSubject?: CSRSubject;
```

And add:

```ts
export interface CSRSubject {
	commonName: string;
	sans?: string[];
	organization?: string;
	orgUnit?: string;
	country?: string;
	locality?: string;
	state?: string;
	keyAlgorithm: 'rsa_4096' | 'ecdsa_p256';
}

export interface GenerateCSRRequest {
	name: string;
	description?: string;
	csrSubject: CSRSubject;
}
```

- [ ] **Step 2: Write the failing client test**

```ts
// append to external-certs.test.ts — mirror the existing request() mock style
it('generateCSR POSTs to /certificates/external/csr', async () => {
	const spy = mockRequestReturning({ id: 'c1', status: 'pending_csr', csrPEM: '---CSR---' });
	const res = await externalCertsApi.generateCSR({
		name: 'x', csrSubject: { commonName: 'app.corp.local', keyAlgorithm: 'rsa_4096' }
	});
	expect(spy).toHaveBeenCalledWith('POST', '/certificates/external/csr', expect.any(Object));
	expect(res.status).toBe('pending_csr');
});

it('csrDownloadUrl builds the download path', () => {
	expect(externalCertsApi.csrDownloadUrl('c1')).toContain('/certificates/external/c1/csr');
});
```

> Match the existing mock helper names in the test file — read it first.

- [ ] **Step 3: Run to verify it fails**

Run: `cd web/frontend && npx vitest run src/lib/api/external-certs.test.ts`
Expected: FAIL — `generateCSR is not a function`.

- [ ] **Step 4: Add the client methods**

In `external-certs.ts`, inside `externalCertsApi`:

```ts
	/**
	 * POST /api/v1/certificates/external/csr — generate a key + CSR and
	 * create a pending_csr row. Returns 201 with csrPEM populated (keyPEM
	 * redacted). Backend: internal/api/external_certs.go createExternalCertCSR.
	 */
	generateCSR(req: GenerateCSRRequest): Promise<ExternalCertificate> {
		return request<ExternalCertificate>('POST', '/certificates/external/csr', req);
	},

	/**
	 * Download URL for the stored CSR PEM (text/plain attachment). The CSR
	 * is public; the private key is never served. Anchor the <a href> at
	 * this URL rather than fetching, so the browser handles the download.
	 */
	csrDownloadUrl(id: string): string {
		return `${BASE}/api/v1/certificates/external/${encodeURIComponent(id)}/csr`;
	}
```

Add `CSRSubject`, `GenerateCSRRequest` to the type imports + re-exports at the top.

- [ ] **Step 5: Run tests**

Run: `cd web/frontend && npx vitest run src/lib/api/external-certs.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add web/frontend/src/lib/api/types.ts web/frontend/src/lib/api/external-certs.ts web/frontend/src/lib/api/external-certs.test.ts
git commit -m "feat(external-certs): frontend generateCSR + csrDownloadUrl client"
```

---

### Task 9: Frontend — Generate CSR form component

**Files:**
- Create: `web/frontend/src/lib/components/certs/GenerateCSRForm.svelte`
- Test: `web/frontend/src/lib/components/certs/GenerateCSRForm.test.ts`

**Interfaces:**
- Consumes: `externalCertsApi.generateCSR`, `externalCertsApi.csrDownloadUrl`, `t()` i18n.
- Produces: emits `created` event with the new cert; on success triggers CSR download via a synthesized `<a>` at `csrDownloadUrl(id)`.

- [ ] **Step 1: Write the failing component test** (validation + submit path)

```ts
// GenerateCSRForm.test.ts — mirror ExternalCertsPanel.test.ts render style
import { render, fireEvent } from '@testing-library/svelte';
import { vi } from 'vitest';
import GenerateCSRForm from './GenerateCSRForm.svelte';
import { externalCertsApi } from '$lib/api/external-certs';

it('rejects submit with empty CN', async () => {
	const spy = vi.spyOn(externalCertsApi, 'generateCSR');
	const { getByRole, getByText } = render(GenerateCSRForm);
	await fireEvent.click(getByRole('button', { name: /generate/i }));
	expect(spy).not.toHaveBeenCalled(); // client-side CN-required guard
});

it('submits with CN + default RSA algorithm', async () => {
	const spy = vi.spyOn(externalCertsApi, 'generateCSR')
		.mockResolvedValue({ id: 'c1', status: 'pending_csr', csrPEM: 'x' } as never);
	const { getByLabelText, getByRole } = render(GenerateCSRForm);
	await fireEvent.input(getByLabelText(/common name/i), { target: { value: 'app.corp.local' } });
	await fireEvent.click(getByRole('button', { name: /generate/i }));
	expect(spy).toHaveBeenCalled();
	expect(spy.mock.calls[0][0].csrSubject.keyAlgorithm).toBe('rsa_4096');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd web/frontend && npx vitest run src/lib/components/certs/GenerateCSRForm.test.ts`
Expected: FAIL — component does not exist.

- [ ] **Step 3: Write the component**

Build `GenerateCSRForm.svelte` (AGPL header comment). Fields: Name, Description, CommonName (required), SANs (comma/chip input), Organization, OrgUnit, Country (2-letter), Locality, State, and a Key algorithm radio group (`rsa_4096` default / `ecdsa_p256`) with the two helper texts (§7). On submit: guard non-empty CN client-side; call `externalCertsApi.generateCSR({name, description, csrSubject:{...}})`; on success create a transient `<a href={csrDownloadUrl(id)} download>` and click it to download the CSR; dispatch `created`. All labels wired with `for`/`id` and ARIA per project a11y rule. All copy through `t('certs.externalCerts.generate.*')`.

- [ ] **Step 4: Run tests**

Run: `cd web/frontend && npx vitest run src/lib/components/certs/GenerateCSRForm.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/components/certs/GenerateCSRForm.svelte web/frontend/src/lib/components/certs/GenerateCSRForm.test.ts
git commit -m "feat(external-certs): Generate CSR form component"
```

---

### Task 10: Frontend — Pending CSR tab in `ExternalCertsPanel`

**Files:**
- Modify: `web/frontend/src/lib/components/certs/ExternalCertsPanel.svelte`
- Test: `web/frontend/src/lib/components/certs/ExternalCertsPanel.test.ts` (append)

**Interfaces:**
- Consumes: `externalCertsApi.list` (rows now carry `status`), `csrDownloadUrl`, `GenerateCSRForm` (Task 9), the existing edit/upload form (for cert-only re-import), `externalCertsApi.remove`.

- [ ] **Step 1: Write the failing test** — the panel splits rows by status and renders an age badge.

```ts
it('splits active and pending_csr rows into tabs', async () => {
	vi.spyOn(externalCertsApi, 'list').mockResolvedValue([
		{ id: 'a', name: 'Active', status: '', notAfter: '2027-01-01T00:00:00Z' },
		{ id: 'p', name: 'Pending', status: 'pending_csr', createdAt: '2026-07-01T00:00:00Z' }
	] as never);
	const { findByRole, getByText } = render(ExternalCertsPanel);
	// pending tab exists and shows the pending row
	(await findByRole('tab', { name: /pending/i })).click();
	expect(getByText('Pending')).toBeTruthy();
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd web/frontend && npx vitest run src/lib/components/certs/ExternalCertsPanel.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

Add a tab control (Active / Pending CSR) that filters `certs` on `status`. Active tab = the existing table unchanged. Pending tab: per row show name, requested CN/SANs (from `csrSubject`), a created-age label + threshold badge (neutral <4d, info 4–14d, warning 15–30d, attention 30d+; compute from `createdAt` in a pure helper `csrAgeBadge(createdAt): 'recent'|'waiting'|'old'|'stale'` — unit-test it), and actions: Download CSR (`<a href={csrDownloadUrl(id)}>`), Upload signed cert (opens the existing edit form in cert-only mode → PUT), Delete (opens the key-destruction confirm — Task 11 copy). Wire the `GenerateCSRForm` behind a "Generate CSR" button; on its `created` event, refresh the list and switch to the Pending tab. All copy through `t()`.

- [ ] **Step 4: Run tests**

Run: `cd web/frontend && npx vitest run src/lib/components/certs/ExternalCertsPanel.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/components/certs/ExternalCertsPanel.svelte web/frontend/src/lib/components/certs/ExternalCertsPanel.test.ts
git commit -m "feat(external-certs): Pending CSR tab + age badge + re-import wiring"
```

---

### Task 11: i18n — EN + FR keys (parity guard)

**Files:**
- Modify: `web/frontend/src/lib/i18n/locales/en.json` (under `certs.externalCerts`)
- Modify: `web/frontend/src/lib/i18n/locales/fr.json` (same paths)

**Interfaces:** Consumes: every `t('certs.externalCerts.generate.*' | '.pending.*' | '.warnings.*')` key referenced in Tasks 9–10.

- [ ] **Step 1: Add the EN keys**

Under `certs.externalCerts` (en.json, sibling to `upload`/`delete`), add a `generate`, `pending`, and `warnings` block. Include at minimum: `generate.title`, `.cnLabel`, `.cnHelp`, `.sansLabel`, `.orgLabel`, `.countryLabel`, `.keyAlgoLabel`, `.keyAlgoRSA`, `.keyAlgoRSAHelp` ("Compatible with all CAs including legacy PKI (Windows AD CS)."), `.keyAlgoECDSA`, `.keyAlgoECDSAHelp` ("Faster handshakes, smaller key. Some legacy CAs reject ECDSA — verify support first."), `.submit`, `.cnRequired`, `.success`; `pending.tab`, `.downloadCSR`, `.uploadSigned`, `.ageRecent`, `.ageWaiting`, `.ageOld`, `.ageStale`, `.deleteConfirmTitle`, `.deleteConfirmText` ("This permanently deletes the generated private key. If your CA signs the certificate later you will NOT be able to import it — you'll need to generate a new CSR."), `.multiplePendingHint`; `warnings.subject_cn_rewritten`, `.subject_org_rewritten`, `.subject_country_rewritten`, `.sans_missing`, `.sans_extra`.

- [ ] **Step 2: Add the matching FR keys** — same paths, French copy.

- [ ] **Step 3: Run the parity guard + i18n tests**

Run: `cd web/frontend && npx vitest run src/lib/i18n/index.test.ts`
Expected: PASS (no missing-key / parity failures).

- [ ] **Step 4: Commit**

```bash
git add web/frontend/src/lib/i18n/locales/en.json web/frontend/src/lib/i18n/locales/fr.json
git commit -m "i18n(external-certs): CSR generate/pending/warnings keys EN+FR"
```

---

### Task 12: Full build + empirical live-serve smoke

**Files:** none (verification task). Produces `docs/smoke-test-csr-generation.md`.

- [ ] **Step 1: Full backend build + all tests + static analysis**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go build ./... && go test ./... && go vet ./... && staticcheck ./...`
Expected: build OK, all tests PASS, no vet/staticcheck output.

- [ ] **Step 2: Frontend build + tests**

Run: `cd web/frontend && npm run build && npx vitest run`
Expected: build OK (static output for embed), all tests PASS.

- [ ] **Step 3: Empirical smoke against a running binary** (per CLAUDE.md §Empirical verification). Document each in `docs/smoke-test-csr-generation.md`:
  1. Generate CSR (RSA 4096) → row `pending_csr`, `keyPEM` stored+redacted, `csrPEM` present.
  2. Generate CSR (ECDSA P-256) → same.
  3. Download CSR → PEM file, contains `CERTIFICATE REQUEST`, NOT `PRIVATE KEY`.
  4. Sign the CSR with a test CA (openssl), PUT the signed cert (empty keyPEM) → `status` cleared to active, subject/SANs warnings surfaced.
  5. PUT a cert NOT matching the stored key → `400 key_does_not_match_cert`.
  6. Point a TLS route at the now-active cert → Caddy serves it (curl `https://` with the test CA trusted → 200).
  7. Generate a second pending CSR for the same hostname → two distinct rows, no error.
  8. Delete a pending row → 200, no 409.
  9. Restart the binary → pending rows survive (BoltDB persistence).
  10. Point a TLS route at a PENDING cert → emitted config still `caddy.Validate()`s, no `load_pem` for it (Task 7 backstop).

- [ ] **Step 4: Commit the smoke doc**

```bash
git add docs/smoke-test-csr-generation.md
git commit -m "docs(external-certs): CSR generation live-serve smoke results"
```

---

## Post-plan (outside task loop)

- **Docs/Wiki** (`Certificates` EN+FR): add a "Generate a CSR" section (3 phases: generate → wait → re-import), cross-ref backup + expiry alerting. Ship as a follow-up docs PR (mirrors the SOCLE docs cadence).
- **Final opus whole-branch review** (non-negotiable keeper) BEFORE the PR — fix findings via subagent, then PR `feature/external-certs-csr` → main, merge, tag `v2.20.0`.
- **Backlog:** alerting source `cert_pending_csr_stale`; topbar expiry badge (still deferred from SOCLE).
