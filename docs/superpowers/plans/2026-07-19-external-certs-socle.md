# External Certificates SOCLE (v2.19.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator upload an externally-issued TLS certificate (leaf + chain + key) and serve it on a route via an explicit `Route.CertID` reference, without ACME; with manual renewal and an expiry-alert source.

**Architecture:** New BoltDB collection `external_certificates` (UUID-keyed, DNS-provider pattern). Admin-only CRUD API. Route gains `CertSource`/`CertID`; caddymgr emits `apps.tls.certificates.load_pem` for manual routes + adds the host to `skip_certificates`. A dedicated alerting source reads the store for expiry. All secret handling mirrors MaxMind.

**Tech Stack:** Go 1.25, bbolt, `crypto/x509` + `crypto/tls`, embedded Caddy v2.11.3, SvelteKit/Svelte 5, vitest.

## Global Constraints

- AGPL header on every new Go and TS file (verbatim from CLAUDE.md).
- `gofmt -s` clean, `go vet ./...` clean; every shell command prefixed `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH`.
- Secret regime for `KeyPEM`: redact-on-GET, preserve-on-edit (empty/absent = keep), never logged, excluded from backup unless `--include-secrets`. Reference: `internal/storage/dns_provider.go` (secret fields) + `internal/storage/maxmind_config.go`.
- Bucket name: `external_certificates` (snake_case plural — matches every existing bucket).
- UUID generated backend-side in the storage layer at create (`uuid.NewString()`), never from the frontend.
- `DisallowUnknownFields` on every JSON request decoder — every accepted field must be on the request struct.
- Wire-field discipline: a new `storage.Route` field requires struct + `routeRequest` + create-map + update-map + `routeResponse` + a round-trip test (else 400 / silent drop).
- caddymgr changes MUST keep `TestBuildConfigJSON_LoadsCleanly` green (`caddy.Validate`), and the load-bearing `auto_https`/`skip_certificates` behaviour MUST be proven with a live-serve smoke (Task 11) — `caddy.Validate` provisions but does not serve.
- No-goals (do NOT build): CSR generation (v2.20.0), renewal 3-options (v2.21.0), PKCS12/JKS, external managed-domain, CRL/OCSP revocation, at-rest key encryption, topbar expiry badge, list search/filter, on-demand cert loading.

---

### Task 1: Storage — `ExternalCertificate` collection + bucket

**Files:**
- Create: `internal/storage/external_cert.go`
- Create: `internal/storage/external_cert_test.go`
- Modify: `internal/storage/storage.go` (add bucket const ~line 114 area + register in the CreateBucketIfNotExists loop ~line 184)

**Interfaces:**
- Produces: `type ExternalCertificate struct {...}`; `(s *Store) CreateExternalCertificate(ctx, ExternalCertificate) (ExternalCertificate, error)`; `GetExternalCertificate(ctx, id) (ExternalCertificate, error)`; `ListExternalCertificates(ctx) ([]ExternalCertificate, error)`; `UpdateExternalCertificate(ctx, id, ExternalCertificate) (ExternalCertificate, error)`; `DeleteExternalCertificate(ctx, id) error`. Const `bucketExternalCertificates = "external_certificates"`.
- Consumes: nothing (Task 2 adds the parse/validate helper this task's Create/Update will call — Task 1 stores WITHOUT parsing; the metadata fields are set by the caller in tests until Task 2 wires parsing. To keep Task 1 self-contained, Create/Update persist the struct as given and only assign ID/timestamps.)

- [ ] **Step 1: Write the failing test** in `internal/storage/external_cert_test.go` (AGPL header first)

```go
package storage

import (
	"context"
	"testing"
)

func TestExternalCert_CreateRoundtrip(t *testing.T) {
	s := newTestStore(t)
	got, err := s.CreateExternalCertificate(context.Background(), ExternalCertificate{
		Name: "digicert-wildcard", CertPEM: "CERT", KeyPEM: "KEY", ChainPEM: "CHAIN",
		Issuer: "DigiCert", DNSNames: []string{"*.example.com"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.ID == "" {
		t.Error("ID not assigned by backend")
	}
	back, err := s.GetExternalCertificate(context.Background(), got.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if back.KeyPEM != "KEY" || back.CertPEM != "CERT" || back.ChainPEM != "CHAIN" {
		t.Errorf("PEM material not round-tripped: %+v", back)
	}
	if len(back.DNSNames) != 1 || back.DNSNames[0] != "*.example.com" {
		t.Errorf("DNSNames = %v", back.DNSNames)
	}
}

func TestExternalCert_Delete(t *testing.T) {
	s := newTestStore(t)
	c, _ := s.CreateExternalCertificate(context.Background(), ExternalCertificate{Name: "x", CertPEM: "C", KeyPEM: "K"})
	if err := s.DeleteExternalCertificate(context.Background(), c.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetExternalCertificate(context.Background(), c.ID); err != ErrNotFound {
		t.Errorf("get after delete err = %v; want ErrNotFound", err)
	}
}

func TestExternalCert_UpdatePreservesKeyWhenEmpty(t *testing.T) {
	s := newTestStore(t)
	c, _ := s.CreateExternalCertificate(context.Background(), ExternalCertificate{Name: "x", CertPEM: "C", KeyPEM: "SECRET"})
	// Update with empty KeyPEM must preserve the stored key.
	upd, err := s.UpdateExternalCertificate(context.Background(), c.ID, ExternalCertificate{Name: "x2", CertPEM: "C", KeyPEM: ""})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.KeyPEM != "SECRET" {
		t.Errorf("KeyPEM = %q; want preserved SECRET", upd.KeyPEM)
	}
	if upd.Name != "x2" {
		t.Errorf("Name = %q; want updated x2", upd.Name)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/storage/ -run TestExternalCert 2>&1 | tail`
Expected: FAIL — `undefined: ExternalCertificate` / `CreateExternalCertificate`.

- [ ] **Step 3: Add the bucket const + registration** in `internal/storage/storage.go`

After the `bucketMaintenancePage = "maintenance_page"` const (~line 114), add:
```go
	bucketExternalCertificates = "external_certificates"
```
In the CreateBucketIfNotExists loop (after `[]byte(bucketMaintenancePage),`), add:
```go
			[]byte(bucketExternalCertificates), // v2.19.0
```

- [ ] **Step 4: Create `internal/storage/external_cert.go`** (AGPL header first), modelled on `dns_provider.go`:

```go
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// ExternalCertificate is an operator-uploaded TLS cert served on a
// route via load_pem (v2.19.0). KeyPEM is a SECRET — redact-on-GET at
// the API layer, preserve-on-edit here (empty KeyPEM on update keeps
// the stored one), never logged, excluded from backup unless
// --include-secrets. Mirrors the DNSProviderConfig secret discipline.
type ExternalCertificate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	CertPEM  string `json:"certPEM"`  // leaf (public)
	KeyPEM   string `json:"keyPEM"`   // SECRET
	ChainPEM string `json:"chainPEM"` // intermediates (public)

	Issuer             string    `json:"issuer"`
	Subject            string    `json:"subject"`
	SerialNumber       string    `json:"serialNumber"`
	KeyAlgorithm       string    `json:"keyAlgorithm"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	DNSNames           []string  `json:"dnsNames"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (s *Store) ListExternalCertificates(ctx context.Context) ([]ExternalCertificate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	out := []ExternalCertificate{}
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketExternalCertificates)).ForEach(func(_, raw []byte) error {
			var c ExternalCertificate
			if err := json.Unmarshal(raw, &c); err != nil {
				return fmt.Errorf("unmarshal external cert: %w", err)
			}
			out = append(out, c)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) GetExternalCertificate(ctx context.Context, id string) (ExternalCertificate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	var out ExternalCertificate
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketExternalCertificates)).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return ExternalCertificate{}, err
	}
	return out, nil
}

func (s *Store) CreateExternalCertificate(ctx context.Context, c ExternalCertificate) (ExternalCertificate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	c.ID = uuid.NewString()
	now := time.Now().UTC()
	c.CreatedAt = now
	c.UpdatedAt = now
	buf, err := json.Marshal(c)
	if err != nil {
		return ExternalCertificate{}, fmt.Errorf("marshal external cert: %w", err)
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketExternalCertificates)).Put([]byte(c.ID), buf)
	})
	if err != nil {
		return ExternalCertificate{}, err
	}
	return c, nil
}

// UpdateExternalCertificate merges c over the stored row: empty KeyPEM
// preserves the stored key (secret preserve-on-edit); empty CertPEM /
// ChainPEM also preserve. Callers that re-parse metadata (API layer)
// overwrite the metadata fields before calling this. Returns ErrNotFound.
func (s *Store) UpdateExternalCertificate(ctx context.Context, id string, c ExternalCertificate) (ExternalCertificate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	var out ExternalCertificate
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketExternalCertificates))
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var existing ExternalCertificate
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("unmarshal external cert: %w", err)
		}
		merged := c
		merged.ID = id
		merged.CreatedAt = existing.CreatedAt
		merged.UpdatedAt = time.Now().UTC()
		if merged.KeyPEM == "" {
			merged.KeyPEM = existing.KeyPEM
		}
		if merged.CertPEM == "" {
			merged.CertPEM = existing.CertPEM
		}
		buf, err := json.Marshal(merged)
		if err != nil {
			return fmt.Errorf("marshal external cert: %w", err)
		}
		out = merged
		return b.Put([]byte(id), buf)
	})
	if err != nil {
		return ExternalCertificate{}, err
	}
	return out, nil
}

func (s *Store) DeleteExternalCertificate(ctx context.Context, id string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketExternalCertificates))
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}
```

Note on ChainPEM clear-via-null (spec §3.5): the `null`-clears-ChainPEM semantic is an API-layer concern (Task 3 decodes into a `*string` and decides keep vs clear before calling Update). Storage `Update` keeps ChainPEM as-passed — so the API passes the resolved value.

- [ ] **Step 5: Run to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/storage/ -run TestExternalCert 2>&1 | tail`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add internal/storage/external_cert.go internal/storage/external_cert_test.go internal/storage/storage.go
git commit -m "feat(storage): external_certificates collection + bucket"
```

---

### Task 2: X.509 parse + validate helper (metadata + warnings)

**Files:**
- Create: `internal/storage/external_cert_parse.go`
- Create: `internal/storage/external_cert_parse_test.go`

**Interfaces:**
- Produces: `func ParseExternalCert(certPEM, keyPEM, chainPEM string) (ExternalCertificate, []CertWarning, error)` — returns a partially-filled `ExternalCertificate` (metadata fields only: Issuer/Subject/Serial/KeyAlgorithm/SignatureAlgorithm/NotBefore/NotAfter/DNSNames), the non-blocking warnings, or a blocking error. Also `type CertWarning struct { Code, Message string }` and exported codes.
- Consumes: `ExternalCertificate` (Task 1).

- [ ] **Step 1: Write the failing test** `internal/storage/external_cert_parse_test.go` (AGPL header first). It generates a self-signed cert in-test so there's no fixture dependency:

```go
package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func genSelfSigned(t *testing.T, cn string, notBefore, notAfter time.Time, dns []string) (certPEM, keyPEM string) {
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

func TestParseExternalCert_Valid(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := genSelfSigned(t, "app.example.com", now.Add(-time.Hour), now.Add(365*24*time.Hour), []string{"app.example.com", "*.example.com"})
	meta, warnings, err := ParseExternalCert(certPEM, keyPEM, "")
	if err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %+v", warnings)
	}
	if len(meta.DNSNames) != 2 {
		t.Errorf("DNSNames = %v", meta.DNSNames)
	}
	if meta.NotAfter.IsZero() {
		t.Error("NotAfter not parsed")
	}
}

func TestParseExternalCert_KeyMismatch(t *testing.T) {
	certPEM, _ := genSelfSigned(t, "a", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []string{"a"})
	_, otherKey := genSelfSigned(t, "b", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []string{"b"})
	if _, _, err := ParseExternalCert(certPEM, otherKey, ""); err == nil {
		t.Error("want error for key not matching cert")
	}
}

func TestParseExternalCert_ExpiredWarns(t *testing.T) {
	certPEM, keyPEM := genSelfSigned(t, "old", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), []string{"old"})
	_, warnings, err := ParseExternalCert(certPEM, keyPEM, "")
	if err != nil {
		t.Fatalf("expired cert must warn not error: %v", err)
	}
	found := false
	for _, w := range warnings {
		if w.Code == CertWarnExpired {
			found = true
		}
	}
	if !found {
		t.Errorf("want cert_expired warning; got %+v", warnings)
	}
}

func TestParseExternalCert_CRLFNormalized(t *testing.T) {
	certPEM, keyPEM := genSelfSigned(t, "crlf", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []string{"crlf"})
	crlf := strings.ReplaceAll(certPEM, "\n", "\r\n")
	if _, _, err := ParseExternalCert(crlf, keyPEM, ""); err != nil {
		t.Errorf("CRLF PEM should parse after normalization: %v", err)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/storage/ -run TestParseExternalCert 2>&1 | tail`
Expected: FAIL — `undefined: ParseExternalCert`.

- [ ] **Step 3: Create `internal/storage/external_cert_parse.go`** (AGPL header first):

```go
package storage

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

type CertWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

const (
	CertWarnExpired     = "cert_expired"
	CertWarnNotYetValid = "cert_not_yet_valid"
	CertWarnWeakSigAlgo = "signature_algorithm_weak"
	CertWarnChainIncomplete = "chain_incomplete"
)

func normalizePEM(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// ParseExternalCert validates the leaf/key (blocking) and returns
// parsed metadata + non-blocking warnings. It does NOT verify the
// chain up to a system root (private CAs are the target audience).
func ParseExternalCert(certPEM, keyPEM, chainPEM string) (ExternalCertificate, []CertWarning, error) {
	certPEM = normalizePEM(certPEM)
	keyPEM = normalizePEM(keyPEM)
	chainPEM = normalizePEM(chainPEM)

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ExternalCertificate{}, nil, errors.New("invalid_cert_pem: leaf PEM does not decode")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ExternalCertificate{}, nil, fmt.Errorf("invalid_cert_pem: %w", err)
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return ExternalCertificate{}, nil, fmt.Errorf("key_does_not_match_cert: %w", err)
	}
	if chainPEM != "" {
		if b, _ := pem.Decode([]byte(chainPEM)); b == nil {
			return ExternalCertificate{}, nil, errors.New("invalid_chain_pem: chain PEM does not decode")
		}
	}

	meta := ExternalCertificate{
		Issuer:             leaf.Issuer.String(),
		Subject:            leaf.Subject.String(),
		SerialNumber:       leaf.SerialNumber.String(),
		KeyAlgorithm:       leaf.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		NotBefore:          leaf.NotBefore,
		NotAfter:           leaf.NotAfter,
		DNSNames:           leaf.DNSNames,
	}

	var warnings []CertWarning
	now := time.Now()
	if now.After(leaf.NotAfter) {
		warnings = append(warnings, CertWarning{CertWarnExpired, "certificate has expired (" + leaf.NotAfter.Format(time.RFC3339) + ")"})
	}
	if now.Before(leaf.NotBefore) {
		warnings = append(warnings, CertWarning{CertWarnNotYetValid, "certificate is not valid until " + leaf.NotBefore.Format(time.RFC3339)})
	}
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1, x509.MD5WithRSA:
		warnings = append(warnings, CertWarning{CertWarnWeakSigAlgo, "weak signature algorithm: " + leaf.SignatureAlgorithm.String()})
	}
	return meta, warnings, nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/storage/ -run TestParseExternalCert 2>&1 | tail`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/storage/external_cert_parse.go internal/storage/external_cert_parse_test.go
git commit -m "feat(storage): X.509 parse + validate helper for external certs"
```

---

### Task 3: API CRUD handlers

**Files:**
- Create: `internal/api/external_certs.go`
- Create: `internal/api/external_certs_test.go`
- Modify: `internal/api/routes.go` (register routes — GET in viewer group, POST/PUT/DELETE in admin group; mirror the maintenance-page registration at `routes.go:171` / `:358`)
- Modify: `internal/audit/actions.go` + `internal/audit/actions_test.go` (Task 7 owns the audit constants — this task USES them; if Task 7 runs after, use literal strings temporarily. To avoid ordering coupling, this plan puts audit constants in THIS task's commit — see Step 3.)

**Interfaces:**
- Consumes: storage CRUD (Task 1), `ParseExternalCert` (Task 2).
- Produces: `POST/GET/PUT/DELETE /api/v1/certificates/external[/{id}]`. Response redacts `keyPEM`.

- [ ] **Step 1: Write the failing test** `internal/api/external_certs_test.go` (AGPL header first). Reuse the self-signed generator idea via storage's exported `ParseExternalCert` is not enough — generate PEM inline (copy `genSelfSigned` into a test helper here, or add a small helper). Minimal set:

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	// plus crypto imports for a local genSelfSigned identical to Task 2's
)

func TestExternalCert_Upload_RedactsKeyOnGet(t *testing.T) {
	env := newTestEnv(t, false)
	certPEM, keyPEM := genSelfSignedAPI(t, "app.example.com", []string{"app.example.com"})
	body := `{"name":"c1","certPEM":` + jsonStr(certPEM) + `,"keyPEM":` + jsonStr(keyPEM) + `,"chainPEM":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/external", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s", rec.Code, rec.Body)
	}
	var created struct {
		ID     string `json:"id"`
		KeyPEM string `json:"keyPEM"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&created)
	if created.KeyPEM != "" {
		t.Errorf("keyPEM leaked in POST response: %q", created.KeyPEM)
	}
	// GET detail must also redact.
	gr := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/external/"+created.ID, nil)
	grec := httptest.NewRecorder()
	env.router.ServeHTTP(grec, gr)
	if strings.Contains(grec.Body.String(), "PRIVATE KEY") {
		t.Errorf("GET leaked key material: %s", grec.Body)
	}
}

func TestExternalCert_Upload_ExpiredReturnsWarning(t *testing.T) {
	env := newTestEnv(t, false)
	certPEM, keyPEM := genSelfSignedExpiredAPI(t, "old.example.com")
	body := `{"name":"old","certPEM":` + jsonStr(certPEM) + `,"keyPEM":` + jsonStr(keyPEM) + `,"chainPEM":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/external", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s; expired cert must persist with a warning", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "cert_expired") {
		t.Errorf("want cert_expired warning; body=%s", rec.Body)
	}
}
```

(Helpers `genSelfSignedAPI`, `genSelfSignedExpiredAPI`, `jsonStr` live in the test file — `jsonStr` = `func jsonStr(s string) string { b,_ := json.Marshal(s); return string(b) }`.)

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/api/ -run TestExternalCert_Upload 2>&1 | tail`
Expected: FAIL — route not registered / 404.

- [ ] **Step 3: Create `internal/api/external_certs.go`** (AGPL header first):

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

type externalCertRequest struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	CertPEM     string  `json:"certPEM"`
	KeyPEM      string  `json:"keyPEM"`
	ChainPEM    *string `json:"chainPEM"` // pointer: nil=keep(create:empty), ""=keep(update), value=set/clear-on-null handled below
}

type externalCertResponse struct {
	storage.ExternalCertificate
	KeyPEM   string                  `json:"keyPEM"`   // always redacted (empty)
	Warnings []storage.CertWarning   `json:"warnings,omitempty"`
}

func toExternalCertResponse(c storage.ExternalCertificate, warnings []storage.CertWarning) externalCertResponse {
	c.KeyPEM = "" // redact
	return externalCertResponse{ExternalCertificate: c, KeyPEM: "", Warnings: warnings}
}

func (h *Handler) listExternalCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := h.store.ListExternalCertificates(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list external certs")
		return
	}
	// Sort by NotAfter ascending (soonest-expiring first).
	sortExternalCertsByExpiry(certs)
	out := make([]externalCertResponse, 0, len(certs))
	for _, c := range certs {
		out = append(out, toExternalCertResponse(c, nil))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getExternalCert(w http.ResponseWriter, r *http.Request) {
	c, err := h.store.GetExternalCertificate(r.Context(), chi.URLParam(r, "id"))
	if err == storage.ErrNotFound {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get external cert")
		return
	}
	writeJSON(w, http.StatusOK, toExternalCertResponse(c, nil))
}

func (h *Handler) createExternalCert(w http.ResponseWriter, r *http.Request) {
	var req externalCertRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	chain := ""
	if req.ChainPEM != nil {
		chain = *req.ChainPEM
	}
	meta, warnings, err := storage.ParseExternalCert(req.CertPEM, req.KeyPEM, chain)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rec := meta // metadata fields set
	rec.Name = req.Name
	rec.Description = req.Description
	rec.CertPEM = req.CertPEM
	rec.KeyPEM = req.KeyPEM
	rec.ChainPEM = chain
	created, err := h.store.CreateExternalCertificate(r.Context(), rec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "save external cert")
		return
	}
	h.appendAudit(r, audit.Event{Action: audit.ActionExternalCertUploaded, TargetType: "external_certificate", TargetID: created.ID})
	writeJSON(w, http.StatusCreated, toExternalCertResponse(created, warnings))
}

func (h *Handler) deleteExternalCert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	routes, err := h.store.ListRoutes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list routes")
		return
	}
	var blocking []string
	for _, rt := range routes {
		if rt.CertSource == "manual" && rt.CertID == id {
			blocking = append(blocking, rt.Host)
		}
	}
	if len(blocking) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":          "certificate in use; change or remove the referencing route(s) first",
			"blockingRoutes": blocking,
		})
		return
	}
	if err := h.store.DeleteExternalCertificate(r.Context(), id); err == storage.ErrNotFound {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "delete external cert")
		return
	}
	if rerr := h.caddy.ReloadFromStore(r.Context()); rerr != nil {
		h.logger.Warn("external cert delete: reload failed", "err", rerr)
	}
	h.appendAudit(r, audit.Event{Action: audit.ActionExternalCertDeleted, TargetType: "external_certificate", TargetID: id})
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}
```

Add `sortExternalCertsByExpiry` (a tiny `sort.Slice` by `NotAfter`) in this file. The PUT handler (preserve-on-edit + re-parse §3.6 + `null`-clears-ChainPEM) follows the same shape — include it with a test asserting the re-parse gate (upload A, PUT cert B, GET NotAfter=B).

- [ ] **Step 3b: Add audit constants** in `internal/audit/actions.go` — after `ActionRouteMaintenanceOff` add:
```go
	// External certificates (3) — v2.19.0
	ActionExternalCertUploaded = "external_cert_uploaded"
	ActionExternalCertUpdated  = "external_cert_updated"
	ActionExternalCertDeleted  = "external_cert_deleted"
```
Add the same three to the `allActions` slice, and bump the count comment + expected count in `actions_test.go`'s `TestAllActions_ExactSet`.

- [ ] **Step 3c: Register routes** in `internal/api/routes.go`: GET (viewer) near `routes.go:171`:
```go
			r.Get("/certificates/external", h.listExternalCerts)
			r.Get("/certificates/external/{id}", h.getExternalCert)
```
POST/PUT/DELETE (admin) near `routes.go:358`:
```go
				r.Post("/certificates/external", h.createExternalCert)
				r.Put("/certificates/external/{id}", h.updateExternalCert)
				r.Delete("/certificates/external/{id}", h.deleteExternalCert)
```

- [ ] **Step 4: Run to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/api/ -run 'TestExternalCert|TestAllActions' 2>&1 | tail`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/external_certs.go internal/api/external_certs_test.go internal/api/routes.go internal/audit/actions.go internal/audit/actions_test.go
git commit -m "feat(api): external cert CRUD + audit actions"
```

---

### Task 4: Route model — `CertSource` + `CertID` + SAN validation

**Files:**
- Modify: `internal/storage/routes.go` (struct fields + validate + SAN match helper)
- Modify: `internal/api/handler.go` (routeRequest + routeResponse + computeEffectiveCertSource)
- Modify: `internal/api/routes.go` (create-map + update-map)
- Test: `internal/storage/routes_external_cert_test.go` (new), `internal/api/routes_external_cert_test.go` (new)

**Interfaces:**
- Consumes: `storage.ExternalCertificate.DNSNames` (Task 1).
- Produces: `Route.CertSource string`, `Route.CertID string`; `func HostMatchesSAN(host string, sans []string) bool` (exported for the API cross-check).

- [ ] **Step 1: Write the failing test** `internal/storage/routes_external_cert_test.go` (AGPL header):

```go
package storage

import "testing"

func TestHostMatchesSAN(t *testing.T) {
	cases := []struct {
		host string
		sans []string
		want bool
	}{
		{"app.example.com", []string{"app.example.com"}, true},
		{"app.example.com", []string{"*.example.com"}, true},
		{"sub.app.example.com", []string{"*.example.com"}, false}, // wildcard = 1 label
		{"example.com", []string{"*.example.com"}, false},         // apex not covered by *.
		{"APP.example.com", []string{"app.example.com"}, true},    // case-insensitive
		{"other.com", []string{"app.example.com"}, false},
	}
	for _, c := range cases {
		if got := HostMatchesSAN(c.host, c.sans); got != c.want {
			t.Errorf("HostMatchesSAN(%q,%v)=%v want %v", c.host, c.sans, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/storage/ -run TestHostMatchesSAN 2>&1 | tail`
Expected: FAIL — `undefined: HostMatchesSAN`.

- [ ] **Step 3: Add fields + helper** in `internal/storage/routes.go`. In the `Route` struct add:
```go
	// CertSource (v2.19.0) selects the cert provider: "" or "acme"
	// (ACME, default), "internal" (self-signed), "manual" (external
	// uploaded cert referenced by CertID). Zero value = acme
	// (migration-free).
	CertSource string `json:"cert_source,omitempty"`
	// CertID references an ExternalCertificate.ID; required when
	// CertSource == "manual".
	CertID string `json:"cert_id,omitempty"`
```
Add the helper + constant:
```go
const RouteCertSourceManual = "manual"

// HostMatchesSAN reports whether host is covered by any SAN, with
// RFC 6125 single-label wildcard semantics ("*.example.com" covers
// "app.example.com" but not "sub.app.example.com" nor "example.com").
// Case-insensitive.
func HostMatchesSAN(host string, sans []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, san := range sans {
		san = strings.ToLower(strings.TrimSuffix(san, "."))
		if san == host {
			return true
		}
		if strings.HasPrefix(san, "*.") {
			suffix := san[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) {
				label := host[:len(host)-len(suffix)]
				if label != "" && !strings.Contains(label, ".") {
					return true
				}
			}
		}
	}
	return false
}
```
(`strings` is already imported in routes.go.)

- [ ] **Step 4: Run to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/storage/ -run TestHostMatchesSAN 2>&1 | tail`
Expected: PASS.

- [ ] **Step 5: Wire the API** (wire-field discipline). In `internal/api/handler.go`: add `CertSource string \`json:"cert_source"\`` + `CertID string \`json:"cert_id"\`` to BOTH `routeRequest` and `routeResponse`; set them in `toResponse`. In `internal/api/routes.go` create-map + update-map: `CertSource: req.CertSource, CertID: req.CertID`. In `computeEffectiveCertSource` add: when `r.CertSource == "manual"` return `"per-route-manual"`.
  Add the manual-mode cross-check: on create/update, if `CertSource=="manual"`, load the cert (404→400 `cert_not_found`) and reject with 400 `host_not_covered_by_cert` if `!storage.HostMatchesSAN(r.Host, cert.DNSNames)`.

- [ ] **Step 6: Write + run the API round-trip test** `internal/api/routes_external_cert_test.go`: create a manual route referencing an uploaded cert whose SAN covers the host → 201, GET echoes `cert_source:"manual"` + `cert_id`; a manual route whose host is NOT in the SANs → 400 `host_not_covered_by_cert`; a manual route with unknown CertID → 400.

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/api/ -run 'TestRoute.*ExternalCert|TestRoute.*Manual' 2>&1 | tail`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/storage/routes.go internal/api/handler.go internal/api/routes.go internal/storage/routes_external_cert_test.go internal/api/routes_external_cert_test.go
git commit -m "feat(routes): CertSource/CertID + RFC6125 SAN validation"
```

---

### Task 5: caddymgr emission — `load_pem` + `skip_certificates` (LOAD-BEARING)

**Files:**
- Modify: `internal/caddymgr/manager.go` (`buildOpts` gains `ExternalCerts map[string]storage.ExternalCertificate`; `applyLocked` reads them; `buildTLSApp` emits `load_pem`; `buildSkipList` adds manual hosts; the per-route emission loop skips ACME/internal for manual routes)
- Test: `internal/caddymgr/external_cert_emit_test.go` (new)

**Interfaces:**
- Consumes: `Route.CertSource`/`CertID` (Task 4), `storage.ExternalCertificate` (Task 1).
- Produces: manual-cert emission in the Caddy JSON.

- [ ] **Step 1: Write the failing test** `internal/caddymgr/external_cert_emit_test.go` (AGPL header). Structural assertions on `buildConfigJSON` (no caddy.Validate here — this file sorts before manager_test.go; the Validate coverage is added to `TestBuildConfigJSON_LoadsCleanly` in Step 4):

```go
package caddymgr

import (
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

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
```

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/caddymgr/ -run TestBuildConfigJSON_ManualCert 2>&1 | tail`
Expected: FAIL.

- [ ] **Step 3: Implement.** In `manager.go`:
  1. Add to `buildOpts`: `ExternalCerts map[string]storage.ExternalCertificate`.
  2. In `applyLocked`: read `certs, _ := m.store.ListExternalCertificates(ctx)`, build the map keyed by ID, pass as `ExternalCerts`.
  3. In the ACME partition builder / per-route loop: a route with `CertSource=="manual"` (and `TLSEnabled`) is EXCLUDED from `partition.HTTP01`/`DNS01` (no ACME policy) — add a guard `if r.CertSource == storage.RouteCertSourceManual { /* skip ACME add */ }`.
  4. In `buildSkipList`: also append `route.Host` + aliases when `route.CertSource == storage.RouteCertSourceManual`.
  5. In `buildTLSApp`: collect `load_pem` entries from routes whose `CertSource=="manual"`, looking up `opts.ExternalCerts[route.CertID]`, and set:
```go
	loadPem := buildLoadPemList(routesForTLS, opts.ExternalCerts)
	if len(loadPem) > 0 {
		certs, _ := tls["certificates"].(map[string]any)
		if certs == nil {
			certs = map[string]any{}
		}
		certs["load_pem"] = loadPem
		tls["certificates"] = certs
	}
```
  where `buildLoadPemList` returns `[]map[string]any{{"certificate": pem, "key": key}}` (dedup by CertID so a multi-route shared cert emits once). PEM = `cert.CertPEM + "\n" + cert.ChainPEM` when chain present. `buildTLSApp` needs the routes slice — thread it through (it currently takes `acme, opts`; add `routes []storage.Route`).

- [ ] **Step 4: Run to verify it passes + extend the Validate fixture**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/caddymgr/ -run TestBuildConfigJSON_ManualCert 2>&1 | tail`
Expected: PASS.
Then add a manual-cert route (with a REAL self-signed PEM generated in-test) to the `TestBuildConfigJSON_LoadsCleanly` fixture so `caddy.Validate` exercises the load_pem shape, and run:
`export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/caddymgr/ -run TestBuildConfigJSON_LoadsCleanly 2>&1 | tail`
Expected: PASS.

- [ ] **Step 5: Run the full caddymgr suite** (cross-test poisoning guard):

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/caddymgr/ 2>&1 | tail`
Expected: ok.

- [ ] **Step 6: Commit**

```bash
git add internal/caddymgr/manager.go internal/caddymgr/external_cert_emit_test.go
git commit -m "feat(caddymgr): emit load_pem + skip_certificates for manual-cert routes"
```

---

### Task 6: Alerting source `cert_manual_expiring`

**Files:**
- Create: `internal/alerting/source_cert_manual_expiring.go`
- Create: `internal/alerting/source_cert_manual_expiring_test.go`
- Modify: `cmd/arenet/main.go` (register after line ~1594, alongside the other sources)

**Interfaces:**
- Consumes: `store.ListExternalCertificates` (Task 1) via a `CertStore` seam interface.
- Produces: a `Source` named `cert_manual_expiring`.

- [ ] **Step 1: Write the failing test** `internal/alerting/source_cert_manual_expiring_test.go` (AGPL header). Use a stub store:

```go
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/alerting/ -run TestCertManualExpiring 2>&1 | tail`
Expected: FAIL — `undefined: NewCertManualExpiringSource`.

- [ ] **Step 3: Create `internal/alerting/source_cert_manual_expiring.go`** (AGPL header):

```go
package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// CertStore is the seam this source reads through (*storage.Store satisfies it).
type CertStore interface {
	ListExternalCertificates(ctx context.Context) ([]storage.ExternalCertificate, error)
}

type CertManualExpiringParams struct {
	ThresholdDays int `json:"thresholdDays"`
}

type CertManualExpiringSource struct {
	store CertStore
	now   func() time.Time
}

func NewCertManualExpiringSource(store CertStore) *CertManualExpiringSource {
	return &CertManualExpiringSource{store: store, now: time.Now}
}

func (s *CertManualExpiringSource) Name() string { return "cert_manual_expiring" }

func (s *CertManualExpiringSource) ValidateParams(raw json.RawMessage) error {
	var p CertManualExpiringParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("cert_manual_expiring: params not valid JSON: %w", err)
	}
	return nil
}

func (s *CertManualExpiringSource) Read(ctx context.Context, raw json.RawMessage) (SourceValue, error) {
	if s.store == nil {
		return SourceValue{}, fmt.Errorf("cert_manual_expiring: store not wired (boot-degraded)")
	}
	p := CertManualExpiringParams{ThresholdDays: 30}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return SourceValue{}, fmt.Errorf("cert_manual_expiring: params decode: %w", err)
		}
	}
	if p.ThresholdDays <= 0 {
		p.ThresholdDays = 30
	}
	certs, err := s.store.ListExternalCertificates(ctx)
	if err != nil {
		return SourceValue{}, fmt.Errorf("cert_manual_expiring: list: %w", err)
	}
	cutoff := s.now().Add(time.Duration(p.ThresholdDays) * 24 * time.Hour)
	count := 0
	for _, c := range certs {
		if !c.NotAfter.IsZero() && c.NotAfter.Before(cutoff) {
			count++
		}
	}
	return FloatValue(float64(count)), nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go test ./internal/alerting/ -run TestCertManualExpiring 2>&1 | tail`
Expected: PASS.

- [ ] **Step 5: Register at boot** in `cmd/arenet/main.go` (after the `NewUpdateAvailableSource` register ~line 1594):
```go
	if err := alertingRegistry.Register(alerting.NewCertManualExpiringSource(store)); err != nil {
		return fmt.Errorf("register cert_manual_expiring source: %w", err)
	}
```
(Use whatever the local `*storage.Store` variable is named at that point.)

- [ ] **Step 6: Build + commit**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go build ./... 2>&1 | tail && echo OK`
```bash
git add internal/alerting/source_cert_manual_expiring.go internal/alerting/source_cert_manual_expiring_test.go cmd/arenet/main.go
git commit -m "feat(alerting): cert_manual_expiring source"
```

---

### Task 7: Frontend — API client + types + upload panel & list

**Files:**
- Create: `web/frontend/src/lib/api/external-certs.ts` (+ types in `types.ts`)
- Create/Modify: `web/frontend/src/routes/settings/certificates/` — an "External" tab with upload (paste cert/chain/key) + list (metadata + expiry badges, sorted soonest-first) + delete dialog ("Delete ≠ Revoke")
- Test: co-located `*.test.ts`

**Interfaces:**
- Consumes: `POST/GET/DELETE /api/v1/certificates/external`.

- [ ] **Step 1** Write a failing vitest for the API client `listExternalCerts()`/`uploadExternalCert()`/`deleteExternalCert()` shape (mock fetch, assert method+path+redacted-key-not-sent-back). Run, see it fail.
- [ ] **Step 2** Implement `external-certs.ts` (mirror `error-templates.ts` request pattern) + the types. Run, green.
- [ ] **Step 3** Build the External tab UI (upload form: name + 3 textareas cert/chain/key; list table sorted by expiry with orange <30d / red <7d badges + warnings; delete confirm dialog with the "does NOT revoke" copy). Add a component test that the list renders sorted + the delete dialog shows the revoke warning.
- [ ] **Step 4** `npm run check` (0 errors) + `npx vitest run` on the new tests. Green.
- [ ] **Step 5** Commit `feat(frontend): external cert upload panel + list`.

---

### Task 8: Frontend — Route form CertSource dropdown + filtered picker

**Files:**
- Modify: `web/frontend/src/routes/routes/+page.svelte` (CertSource dropdown: ACME / Internal / Manual; Manual → cert picker filtered to certs whose SAN covers the route host, RFC 6125; warning + upload link when none eligible)
- Modify: `web/frontend/src/lib/api/types.ts` (Route `certSource`/`certID` + MaintenanceConfig-style wire fields)
- Test: `web/frontend/src/routes/routes/page.test.ts`

- [ ] **Step 1** Failing test: opening a route in Manual mode shows only certs covering the host; picking one ships `certSource:"manual"` + `certID` in the payload. Run, fail.
- [ ] **Step 2** Implement the dropdown + filtered picker + payload wiring (ship `certSource`/`certID` only when relevant; keep the active-route-flip discipline — don't synthesize manual mode on an ACME route). Run, green.
- [ ] **Step 3** `npm run check` + vitest. Commit `feat(frontend): route CertSource picker for manual certs`.

---

### Task 9: i18n EN + FR

**Files:**
- Modify: `web/frontend/src/lib/i18n/locales/en.json` + `fr.json` (keys for the External tab, upload form, warnings, route CertSource options, delete-≠-revoke dialog)
- Modify: `web/frontend/.../RuleModal` source list — add `cert_manual_expiring` (the hardcoded-dropdown backlog: a new source is invisible otherwise)

- [ ] **Step 1** Add all new `certificates.external.*` + `routes.form.certSource.*` keys to EN, then FR twins.
- [ ] **Step 2** Add `cert_manual_expiring` to the RuleModal Source options + its i18n label.
- [ ] **Step 3** Run the i18n parity guard: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; cd web/frontend && npx vitest run src/lib/i18n/index.test.ts`. Green.
- [ ] **Step 4** Commit `i18n(external-certs): EN+FR keys + alerting source`.

---

### Task 10: Docs — Certificates + Routes wiki (EN + FR)

**Files:**
- Modify: `docs/wiki-seed/Certificates.md` + `Certificates-FR.md` — how to upload, that renewal is MANUAL, the expiry alert, wildcard external vs ACME wildcard distinction.
- Modify: `docs/wiki-seed/Routes.md` + `Routes-FR.md` — the CertSource picker + manual mode.
- Create: `docs/smoke-test-external-certs.md` — the Task 11 procedure.

- [ ] **Step 1** Write the Certificates sections (EN then FR twin), Routes sections (EN+FR), and the smoke doc. No shell command in the docs that hasn't been run against the binary (doc-commands-must-be-run).
- [ ] **Step 2** Commit `docs(external-certs): Certificates + Routes wiki EN+FR + smoke doc`.

---

### Task 11: Live-serve smoke (MANDATORY — the load-bearing gate)

**Files:** none (procedure + evidence). Follows `docs/smoke-test-external-certs.md` (Task 10).

Run against a real binary built from the branch. A self-signed test cert stands in for the external cert.

- [ ] **Step 1** Build: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH; go build -o /tmp/arenet ./cmd/arenet`. Boot dev-mode (`ARENET_HTTP_PORT=:8080 ARENET_HTTPS_PORT=:8443 ... --dev --admin-port 127.0.0.1:8001`). Setup admin.
- [ ] **Step 2** Upload a self-signed cert for `manual.local` via `POST /certificates/external`. Create an ACME baseline route + a manual route (`certSource:manual`, its CertID) for `manual.local`.
- [ ] **Step 3** Inspect the live Caddy config via the admin API: `manual.local` in routing ✓; its PEM in `apps.tls.certificates.load_pem` ✓; `manual.local` NOT in `apps.tls.automation.policies` ✓; `manual.local` in `skip_certificates` ✓.
- [ ] **Step 4** HTTPS handshake: `curl -vk --resolve manual.local:8443:127.0.0.1 https://manual.local:8443/` → served the uploaded cert (match serial/subject), NO ACME request logged for that host.
- [ ] **Step 5** Non-regression: the ACME route still serves; no `skip_certificates` leak onto it.
- [ ] **Step 6** maintenance+manual: put the manual route into maintenance → `curl -vk` → TLS handshake succeeds (manual cert) AND HTTP 503 (maintenance handler). Proves handshake-before-503.
- [ ] **Step 7** Restart persistence: restart the binary → config re-emitted → manual cert still served, no new ACME challenge for `manual.local`.
- [ ] **Step 8** Record the evidence (config excerpts + curl outputs) in the smoke doc. If any assertion fails → STOP and revisit Task 5 (the auto_https interaction is the whole risk).

---

## Self-Review notes

- **Spec coverage:** §3 storage → Tasks 1-2; §3.5/§3.6 preserve/re-parse → Tasks 1 (preserve) + 3 (re-parse gate); §4 API → Task 3; §5 route model + emission → Tasks 4-5; §5.4 maintenance+manual → Task 11 Step 6; §6 wildcard → Task 4 SAN helper; §7 alerting → Task 6; §8 tests+smoke → each task's tests + Task 11; §9 file map → all tasks. Docs → Task 10.
- **Non-goals** honored: no CSR, no renewal UI, no PKCS12, no external managed-domain, no revocation, no key encryption, no topbar badge, no search.
- **Type consistency:** `CertSource`/`CertID` (storage snake_case json `cert_source`/`cert_id`; frontend `certSource`/`certID`), `RouteCertSourceManual = "manual"`, `HostMatchesSAN`, `ParseExternalCert`, `NewCertManualExpiringSource`, audit `ActionExternalCert{Uploaded,Updated,Deleted}` — used consistently across tasks.
- **Ordering note:** Task 3 owns the audit constants (Step 3b) so it's self-contained; Task 7 (audit) in the user's sketch is folded here. The plan has 11 tasks; the frontend/i18n/docs are Tasks 7-10, smoke is 11.
