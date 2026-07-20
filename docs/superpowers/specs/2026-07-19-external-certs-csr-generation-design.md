# External certificates — CSR generation (v2.20.0) Design

**Status:** design brainstormed with user 2026-07-19, 6 decisions locked
(Q1–Q6). Awaiting written-spec review. Feature = minor bump.
Second of three incremental sub-projects
(v2.19.0 SOCLE ✅ → **v2.20.0 CSR generation** → v2.21.0 renewal).

**One-line:** Let an operator **generate a private key + CSR inside Arenet**,
download the CSR to get it signed by an external CA (DigiCert, corporate
PKI / AD CS), then **re-import the signed certificate** — which is validated
against the key Arenet already holds. The private key never leaves the box.

Builds directly on the SOCLE (`2026-07-19-external-certs-socle-design.md`):
same `ExternalCertificate` collection, same secret discipline, same
`load_pem` emission, same delete-guard. This spec adds a *generation* entry
point and a *pending* lifecycle to that collection.

---

## 1. Motivation

The SOCLE (v2.19.0) lets an operator **upload** a cert they already hold —
but it assumes they generated the key + CSR themselves (openssl, an external
tool) and are custodians of the private key. For a homelab/enterprise
operator that is friction and a security hazard: the private key is created
and stored outside Arenet, copy-pasted around, and can leak.

CSR generation closes that gap. Arenet generates the keypair, emits a CSR for
signing, and keeps the private key under the SAME secret regime as every
other secret (clear in BoltDB, data-dir `0700`, redacted from API + backup).
The operator only ever handles **public** material (the CSR, the signed cert).

This is a config/UX gap, not an engine limitation — Go's stdlib
(`crypto/x509.CreateCertificateRequest`) does all the cryptography; no new
dependency.

## 2. Non-goals (explicit, locked)

- ❌ **Renewal 3-options workflow** (reuse CSR / regen same details / new
  details, auto-rotate `Route.CertID` at cutover) → v2.21.0. This spec ships
  generation + re-import only; rotation is a manual PUT + manual route swap.
- ❌ **Auto-submission to the CA** (ACME-style protocol handshake). External
  enterprise CAs have no automatic submission channel — the operator carries
  the CSR to the CA portal by hand. Arenet generates and re-imports; it does
  not talk to the CA.
- ❌ **Auto-cleanup of pending CSRs** — a pending row holds a private key;
  destroying it automatically risks discarding the key before a slow CA
  returns the signed cert (Q5). Deletion is always an explicit operator gesture.
- ❌ **Uniqueness constraint per hostname** — multiple pending CSRs for the
  same CN/SAN are allowed without friction (Q6): testing two CAs in parallel,
  regenerating after a CA rejection, planned rotation are all legitimate.
- ❌ **Alerting source `cert_pending_csr_stale`** → backlog. The age badge
  (§7) covers the awareness need in-UI; add an alerting source later only if
  dogfooding shows pending CSRs actually get forgotten.
- ❌ **Encryption at rest** for the generated key — same GLOBAL decision as the
  SOCLE, out of scope here.
- ❌ **Key algorithms beyond RSA 4096 / ECDSA P-256** — no RSA 2048 (NIST
  SP 800-131A recommends ≥3072), no P-384 (marginal legacy-CA compat loss),
  no Ed25519 (thin enterprise-CA support). Two options only (Q3).
- ❌ **PKCS#10 attributes beyond subject + SANs** (challenge password, custom
  extensions, key usage requests) — enterprise CAs impose their own policy and
  ignore most requested extensions. Subject (CN/O/OU/C/L/ST) + DNS SANs only.
- ❌ **A new re-import endpoint** — re-import reuses the existing SOCLE `PUT`
  (§5.3). This is the "architectural gift" the SOCLE's preserve-on-edit KeyPEM
  already grants.

## 3. Locked decisions (brainstorm Q1–Q6)

| # | Decision | Rationale (short) |
|---|----------|-------------------|
| Q1 | **Pending state = a row in `ExternalCertificate`** with `Status="pending_csr"`, `KeyPEM` filled, `CertPEM` empty. Not a separate entity. | Reuses the collection, secret discipline, backup pipeline, and one lifecycle. Re-import = a PUT that fills `CertPEM`. |
| Q2 | **Pending rows are included in backup** (same regime as active). | Consistency; the operator can migrate mid-request. Key redacted unless `--include-secrets`, exactly like active rows. |
| Q3 | **Key algorithm = UI choice: RSA 4096 (default) or ECDSA P-256.** | RSA 4096 = 100% CA compat incl. legacy AD CS; ECDSA P-256 = modern, faster handshake. Helper text warns ECDSA may be rejected by old CAs. |
| Q4 | **Re-import validation:** public-key match = **blocking**; subject/SANs divergence = **non-blocking warnings**. | CAs legitimately rewrite subject (AD CS imposes O=, filters SANs). Blocking would break the real workflow. Public-key mismatch = unusable cert → reject. |
| Q5 | **No auto-delete of pending; UI age badge.** Delete is explicit, behind a confirm dialog warning the key is destroyed. | Never destroy crypto material automatically; CA turnaround is unpredictable (J+40 for a J+30-purged key = broken). |
| Q6 | **Multiple pending per hostname allowed, no friction.** | Row-based model → distinct ID/CertID, no collision. Legitimate: 2-CA test, regen-after-failure, rotation. |

---

## 4. Storage — extend `ExternalCertificate` (Brick A)

No new bucket. Three additive fields on the existing struct
(`internal/storage/external_cert.go`), all `omitempty` so pre-v2.20.0 rows
unmarshal unchanged (migration-free — a row with no `Status` reads as active).

```go
type ExternalCertificate struct {
    // ... all existing v2.19.0 fields (ID, Name, CertPEM, KeyPEM, ChainPEM,
    //     Issuer, Subject, NotAfter, DNSNames, CreatedAt, ...) unchanged.

    // v2.20.0 — CSR generation. Empty on every uploaded (SOCLE) cert.
    Status     string     `json:"status,omitempty"`     // "" = active | "pending_csr"
    CSRPEM     string     `json:"csrPEM,omitempty"`      // PUBLIC — the generated CSR, re-downloadable
    CSRSubject CSRSubject `json:"csrSubject,omitempty"`  // what was requested (display + re-import diff)
}

type CSRSubject struct {
    CommonName   string   `json:"commonName"`
    SANs         []string `json:"sans,omitempty"`
    Organization string   `json:"organization,omitempty"`
    OrgUnit      string   `json:"orgUnit,omitempty"`
    Country      string   `json:"country,omitempty"`      // 2-letter ISO
    Locality     string   `json:"locality,omitempty"`
    State        string   `json:"state,omitempty"`
    KeyAlgorithm string   `json:"keyAlgorithm"`           // "rsa_4096" | "ecdsa_p256"
}
```

**Status semantics — the single source of truth for "servable".**

- `Status == "pending_csr"`: `CertPEM` is empty. The row is **inert in
  practice** — no route legitimately references it, so it is never emitted as
  `load_pem`. It only carries the key + CSR while waiting.
- `Status == ""` (active): behaves exactly like a v2.19.0 uploaded cert.

**Secret discipline (inherited, unchanged):** `KeyPEM` stays redact-on-GET,
preserve-on-edit, never logged, excluded from backup unless `--include-secrets`.
`CSRPEM` and `CSRSubject` are **public** (a CSR carries only the public key) —
returned in full by the API, included in backup unconditionally.

**Guard the transition invariant — this is a NECESSARY check, not redundant.**
Verified against the current code (`buildLoadPemList`,
`internal/caddymgr/manager.go:2572`): emission is gated only on
`CertSource==manual && TLSEnabled && CertID resolves` — there is **no** guard on
an empty leaf today. So if an operator points a TLS route at a pending row,
`buildLoadPemList` would emit `{"certificate": "", "key": <priv>}` → invalid
Caddy JSON. Add an explicit `if cert.CertPEM == "" { continue }` skip in
`buildLoadPemList`. Empirically assert (per CLAUDE.md §Empirical verification):
a `pending_csr` row referenced by a TLS route emits **no** `load_pem` and the
emitted config still `caddy.Validate()`s.

## 5. API (Brick B)

### 5.1 Generate — `POST /api/v1/certificates/external/csr`

Admin-only (mutation), mirrors the SOCLE create split.

Request:
```json
{ "name": "DigiCert app.corp.local",
  "description": "primary, 2026 rotation",
  "csrSubject": {
    "commonName": "app.corp.local",
    "sans": ["app.corp.local", "www.corp.local"],
    "organization": "Corp Inc", "country": "FR",
    "keyAlgorithm": "rsa_4096" } }
```

Backend (`storage.GenerateKeyAndCSR(algo, subject)` — new, in a new
`internal/storage/csr.go`):
1. Generate the private key (`rsa.GenerateKey(rand.Reader, 4096)` or
   `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`).
2. Build `x509.CertificateRequest{Subject: pkix.Name{...}, DNSNames: sans,
   SignatureAlgorithm: <SHA256WithRSA | ECDSAWithSHA256>}` and
   `x509.CreateCertificateRequest`.
3. PEM-encode key (`PKCS#8`, `PRIVATE KEY`) + CSR (`CERTIFICATE REQUEST`).
4. Create the row: `Status="pending_csr"`, `KeyPEM`, `CSRPEM`, `CSRSubject`
   set; `CertPEM`/`ChainPEM` empty; `KeyAlgorithm` metadata populated.

Validation (blocking, 400 with actionable codes):
`cn_required` (CN empty) · `invalid_country` (not 2-letter) ·
`invalid_key_algorithm` (not one of the two) · `invalid_san` (a SAN that is
not a hostname). CN is auto-added to SANs if absent (standard practice — a
bare-CN cert without a matching SAN is rejected by modern clients).

Response `201`: the redacted row (KeyPEM blanked, as always) **including
`csrPEM`** so the UI can offer immediate download.

### 5.2 Download CSR — `GET /api/v1/certificates/external/{id}/csr`

Viewer-accessible (the CSR is public). Returns `text/plain` PEM
(`Content-Disposition: attachment; filename="<name>.csr"`). 404 if the row has
no CSR (an uploaded SOCLE cert). Never returns the key.

### 5.3 Re-import — the **existing** SOCLE `PUT /api/v1/certificates/external/{id}`

**No new endpoint.** The operator PUTs the signed cert with an empty `keyPEM`
(preserve-on-edit keeps the stored generated key — the SOCLE gift). The PUT
handler (`internal/api/external_certs.go`) gains three deltas:

1. **Public-key match is already enforced** — `ParseExternalCert` runs
   `tls.X509KeyPair(certPEM, keyPEM)` → the existing `key_does_not_match_cert`
   (400) IS the Q4 blocking check. No new code for the mandatory gate.
2. **Subject/SANs warnings** — when the edited row `Status == "pending_csr"`,
   call new `storage.CompareCSRAndCert(existing.CSRSubject, leaf)` and append
   its `[]CertWarning` to the response (reusing the SOCLE warning channel).
3. **Clear the pending flag** — on a successful cert set, `Status = ""`. The
   row becomes active and servable; the next `ReloadFromStore` (already called
   by PUT) makes any route referencing it start serving.

New non-blocking warning codes (extend the SOCLE `CertWarn*` set):
`subject_cn_rewritten` · `subject_org_rewritten` · `subject_country_rewritten` ·
`sans_missing` (with the missing list) · `sans_extra`. Message carries a
requested-vs-issued detail so the UI can show a before/after.

### 5.4 Delete pending — the **existing** SOCLE `DELETE`

Already correct: a pending row has empty `CertPEM`, so the SOCLE delete-guard
(block only when a TLS route references it — impossible for an inert pending)
never blocks it. No backend change. The UI adds the key-destruction confirm
copy (§7).

## 6. Route wiring (Brick C) — nothing new

A pending row is inert (§4). Once re-import flips it to active, it is an
ordinary `CertSource=manual` cert; the operator points a route at it via the
existing `Route.CertID`. The route dropdown lists pending rows disabled
(greyed, non-selectable) so an operator cannot accidentally wire a route to an
unservable cert — and the §4 empty-leaf skip is the backend backstop if one
somehow does.

## 7. Frontend (Brick D)

`/settings/certificates/external` (the SOCLE page) gains a tab split:

- **Active** (`Status == ""`) — the SOCLE list, servable, sort-by-expiry.
- **Pending CSR** (`Status == "pending_csr"`) — waiting rows. Per row:
  Download CSR · Upload signed cert (opens the existing edit form,
  cert-only) · Delete. Each row shows a **created-age** with a threshold
  badge: neutral <4d, info 4–14d, warning 15–30d, attention 30d+. The badge
  is computed client-side from `CreatedAt` — no new storage field.

**Generate CSR** button → form: Name, Description, CN, SANs (chips),
Organization, OrgUnit, Country, Locality, State, and a **Key algorithm**
radio (RSA 4096 default / ECDSA P-256) with helper text:
- RSA 4096 — "Compatible with all CAs including legacy PKI (Windows AD CS)."
- ECDSA P-256 — "Faster handshakes, smaller key. Some legacy CAs reject ECDSA — verify support first."
On submit → `POST …/csr` → immediately trigger the CSR download → land on the
Pending tab.

**Delete-pending confirm dialog** copy (Q5): "This permanently deletes the
generated private key. If your CA signs the certificate later you will NOT be
able to import it — you'll need to generate a new CSR." — `[Cancel]` /
`[Delete pending CSR]`.

**Re-import result** — the edit form, on success, surfaces the returned
warnings inline (subject-rewrite / SANs-missing), each with a
requested-vs-issued detail and an "informational — the cert is valid and in
use" note.

i18n: all new strings EN + FR (parity guard, per the multi-DNS lesson).

## 8. Backup / audit

- **Backup**: pending rows flow through the SOCLE backup pipeline unchanged
  (Q2). `CSRPEM`/`CSRSubject` are public → always included; `KeyPEM` redacted
  unless `--include-secrets`. Restore re-creates pending rows verbatim.
- **Audit**: new action `external_cert_csr_generated` (on POST …/csr). The
  existing `external_cert_updated` covers re-import; `external_cert_deleted`
  covers delete-pending. Follows `internal/audit/actions.go`.

## 9. Testing (empirical gates, per CLAUDE.md)

Storage/crypto: generate RSA 4096 + ECDSA P-256 → key PEM parses, CSR parses,
CSR subject/SANs round-trip. `CompareCSRAndCert`: exact match → no warnings;
CN rewritten → `subject_cn_rewritten`; SAN filtered → `sans_missing` with the
list; O added → `subject_org_rewritten`.

API: POST …/csr → row with `Status=pending_csr` + KeyPEM + CSRPEM stored,
response redacts KeyPEM but includes CSRPEM. GET …/{id}/csr → PEM, no key.
PUT signed-cert-matching-key on a pending row → `Status=""`, warnings on
subject drift. PUT cert-not-matching-key → 400 `key_does_not_match_cert`.
DELETE pending → 200, no 409. Restart → pending row survives (real-BoltDB).

Caddy emission (the load-bearing invariant): a `pending_csr` row referenced by
a route emits **no** `load_pem`; emitted JSON `caddy.Validate()`s and all
handler IDs resolve (the `TestBuildConfigJSON_LoadsCleanly` +
`…HandlersAllResolvable` pattern from CLAUDE.md §Empirical verification).

Frontend: tab split filters on `Status`; age-badge thresholds; generate form
validation; delete-confirm copy; warning rendering on re-import.

## 10. Process weight

LIGHT mode (per the process-weight-calibration memory): implementer per task +
controller-inline reviews, with **dedicated reviewers on the two load-bearing
tasks** — the crypto generation (`GenerateKeyAndCSR`, key material) and the
emission-skip invariant (a pending row must never be servable). ONE final opus
whole-branch review before PR (non-negotiable keeper). Then live-serve smoke
on AreNET-test, PR, merge, tag `v2.20.0`.
