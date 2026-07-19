# External certificates — SOCLE (v2.19.0) Design

**Status:** design approved by user 2026-07-19. Feature = minor bump.
First of three incremental sub-projects (SOCLE → v2.20.0 CSR generation →
v2.21.0 renewal 3-options).

**One-line:** Let an operator **upload** a TLS certificate issued by an
external CA (DigiCert, corporate PKI) — leaf + chain + private key — and serve
it on a route via an explicit `Route.CertID` reference, without ACME.
Renewal is manual; an alerting source warns before expiry.

Supersedes the backlog note `docs/backlog-external-certs.md` (which sketched
all 4 bricks). This spec is the SOCLE only.

---

## 1. Motivation

Today Arenet obtains certs two ways only (`internal/caddymgr/manager.go`):
ACME (`buildACMEPolicy`, http-01/dns-01) and internal self-signed
(`{"module":"internal"}`). The route TLS model is a closed set —
`Route.TLSEnabled` + `Route.ACMEChallenge` enum. There is no way to serve a
cert the operator already holds (compliance, corporate PKI, a non-ACME CA,
air-gapped issuance). This blocks a real class of user.

Caddy v2.11.3 already ships the loader modules (`tls.certificates.load_pem`,
`load_files`); this is a product gap in Arenet's config generation, not an
engine limitation.

## 2. Non-goals (explicit, locked)

- ❌ **CSR generation** (operator generates key + CSR inside Arenet) → v2.20.0.
- ❌ **Renewal 3-options workflow** (reuse CSR / regen same / new details) → v2.21.0.
- ❌ **Import PKCS12/JKS** → backlog V2.
- ❌ **External managed-domain** (a wildcard external cert auto-covering
  subdomains, like ACME managed domains) → backlog if a real need emerges.
  In the SOCLE a wildcard external cert is just a cert with a wildcard SAN,
  referenced explicitly per route (§6).
- ❌ **CRL/OCSP revocation** on delete (revocation is the operator's action at
  the CA portal — consistent with today's ACME delete, which also doesn't revoke).
- ❌ **Encryption at rest** for the private key — it follows the SAME regime as
  every other secret (clear in BoltDB, data-dir 0700, redacted from API + backup).
  At-rest encryption is a separate GLOBAL decision for all secrets, not this feature.
- ❌ **Topbar expiry badge** → backlog v2.20.0 (the alerting source is the safety
  net; a frontend badge re-introduces the SourceRegistry-frontend coupling that
  caused the `update_available` miss — do it properly later).
- ❌ **Search / advanced filter** in the cert list → backlog. SOCLE ships a
  sort-by-expiry default only.
- ❌ **On-demand cert loading** — SOCLE uses static `load_pem` (mirrors ACME
  preload). On-demand is a future optimization if scale demands.

## 3. Storage — `ExternalCertificate` collection (Brick A)

New BoltDB bucket **`external_certificates`** (snake_case plural — verified
against every existing bucket: `dns_providers`, `error_templates`,
`managed_domains`, `forward_auth_providers`, …). UUID-keyed, mirroring
`internal/storage/dns_provider.go`.

```go
type ExternalCertificate struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    Description string    `json:"description,omitempty"`

    // PEM material.
    CertPEM  string `json:"certPEM"`  // leaf (public)
    KeyPEM   string `json:"keyPEM"`   // SECRET — redacted on GET, preserve-on-edit
    ChainPEM string `json:"chainPEM"` // intermediates (public)

    // Metadata parsed at upload (cached for the UI, re-parsed when CertPEM changes).
    Issuer             string    `json:"issuer"`
    Subject            string    `json:"subject"`
    SerialNumber       string    `json:"serialNumber"`
    KeyAlgorithm       string    `json:"keyAlgorithm"`       // RSA / ECDSA / Ed25519
    SignatureAlgorithm string    `json:"signatureAlgorithm"`
    NotBefore          time.Time `json:"notBefore"`
    NotAfter           time.Time `json:"notAfter"`
    DNSNames           []string  `json:"dnsNames"`

    CreatedAt time.Time `json:"createdAt"`
    UpdatedAt time.Time `json:"updatedAt"`
}
```

### 3.1 UUID generation (clarification #4)
**Backend generates the UUID** in the storage layer at create time —
`c.ID = uuid.NewString()` — exactly as `dns_provider.go:189`. The frontend
never supplies an ID.

### 3.2 Secret regime (Q1 — locked)
`KeyPEM` follows the **exact MaxMind pattern** (reference:
`internal/storage/maxmind_config.go` license-key handling):
- **redact-on-GET**: API GET never returns `KeyPEM` (redacted / omitted).
- **preserve-on-edit**: an empty/absent `KeyPEM` on PUT keeps the stored one.
- **never logged**: no log statement includes key material.
- **backup**: `KeyPEM` excluded from the snapshot unless `--include-secrets`;
  `CertPEM` / `ChainPEM` / metadata are public and always included.

Rationale: Arenet already stores other secrets in the clear (MaxMind key, OVH
creds, argon2id hashes); the data-dir is 0700 (v2.15.1). Encrypting only this
one key would be inconsistent security theater — see non-goals.

### 3.3 Validation at write time (Q2 — locked)
Blocking (400) — reject the write:
- `invalid_cert_pem` — leaf PEM does not parse.
- `invalid_chain_pem` — chain PEM supplied but does not parse.
- `key_does_not_match_cert` — `tls.X509KeyPair(cert, key)` fails.

Non-blocking (persist, return `warnings[]`):
- `cert_expired` — `NotAfter < now`.
- `cert_not_yet_valid` — `NotBefore > now` (staging a cert ahead of cutover).
- `signature_algorithm_weak` — SHA-1 (obsolete) / MD5 (critical).
- `chain_incomplete` — heuristic (leaf's issuer not found in the supplied chain).

**No trust-chain validation to a system root** — the target audience is
private/corporate CAs whose root is not in the trust store. Validating to a
root would reject exactly the intended users.

### 3.4 PEM normalization (bonus 2 — in SOCLE)
Normalize CRLF→LF on ingest (`strings.ReplaceAll(pem, "\r\n", "\n")`) before
parsing, so a PEM pasted from a Windows tool parses cleanly. Empirical gate:
a CRLF PEM uploads without a spurious `invalid_cert_pem`.

### 3.5 Preserve-vs-clear on edit (clarification #2)
The PUT body distinguishes three states per PEM field (JSON: absent /
`""` / `null`):

| Field | absent | `""` (empty string) | `null` (explicit) | non-empty value |
|-------|--------|---------------------|-------------------|-----------------|
| `KeyPEM`   | keep existing | keep existing | **400 `key_required`** | replace (+ X.509 validate) |
| `ChainPEM` | keep existing | keep existing | **clear** | replace |
| `CertPEM`  | keep existing | keep existing | **400 `cert_required`** | replace (+ re-parse §3.6) |

The `null`-clears-ChainPEM path is the one intentional asymmetry; document it
in the API section and the wiki. (Distinguishing absent vs `null` requires
`*string` fields or a raw-map decode in the request struct — implementer's
choice, but the behavior above is the contract.)

### 3.6 Metadata re-parse on cert change (clarification #3)
On `UpdateExternalCertificate`, **if `CertPEM` changes**, re-parse and
overwrite ALL derived metadata (Issuer/Subject/SerialNumber/DNSNames/
NotBefore/NotAfter/KeyAlgorithm/SignatureAlgorithm). If `CertPEM` is preserved,
metadata is untouched. **Test-gate:** upload cert A (NotAfter=2027-01-01) →
update with cert B (NotAfter=2028-01-01) → GET reflects B, not A.

## 4. API (Brick B) — `internal/api/external_certs.go`, admin-only

- `POST /api/v1/certificates/external` — upload. Body: name, description,
  certPEM, chainPEM, keyPEM. Backend generates UUID, validates (§3.3),
  persists, returns `{id, <metadata>, warnings:[{code,message}]}`.
- `GET /api/v1/certificates/external` — list (metadata only, KeyPEM redacted),
  **sorted by NotAfter ascending** (bonus 3 — soonest-expiring first).
- `GET /api/v1/certificates/external/{id}` — detail (KeyPEM redacted).
- `PUT /api/v1/certificates/external/{id}` — edit (preserve-on-edit §3.5,
  re-parse §3.6).
- `DELETE /api/v1/certificates/external/{id}` — **409 if a route in `manual`
  mode references this cert** (list the blocking route hosts), mirroring the
  ACME cert-delete guard just shipped in v2.18.2 (`routeEmitsCertSubject`
  posture). Otherwise: delete from store → `ReloadFromStore` →
  rollback-on-reload-fail (the v2.12.2 lesson: reload is mandatory in CRUD
  handlers; roll the store back if reload fails). Response dialog copy makes
  "delete ≠ revoke" explicit.

Audit actions as typed constants + bump `TestAllActions_ExactSet`
(`internal/audit/actions_test.go`): `external_cert_uploaded`,
`external_cert_updated`, `external_cert_deleted`.

`DisallowUnknownFields` on the decoder (project convention) — the request
struct must carry every accepted field.

## 5. Route model + caddymgr emission (Brick C) — the load-bearing part

### 5.1 Route model
Add to `internal/storage/routes.go`:
- `CertSource string` — `"acme" | "internal" | "manual"`. Zero value `""`
  means acme (migration-free; existing routes keep behaving as today).
- `CertID string \`json:"certID,omitempty"\`` — required when
  `CertSource=="manual"`, references an `ExternalCertificate.ID`.

**Wire-field discipline** (the recurring 400 / silent-drop class): both new
fields go on `routeRequest` + create-map + update-map + `routeResponse` + a
round-trip test.

**Validation at route create/edit** (`Route.validate` + API cross-check):
when `CertSource=="manual"` — `CertID` non-empty AND references an existing
cert AND `Route.Host` matches one of the cert's SANs (`host_not_covered_by_cert`
otherwise). SAN match = exact OR wildcard (RFC 6125: `*.example.com` matches
`app.example.com`, ONE label only — NOT `sub.app.example.com`), case-insensitive.

### 5.2 The 5 CertSource cases (documented)
| CertSource | Other field | Effective source |
|------------|-------------|------------------|
| `acme`     | DNSProviderID="" | HTTP-01 ACME |
| `acme`     | DNSProviderID set | DNS-01 ACME |
| `internal` | — | Caddy internal self-signed |
| `manual`   | CertID set | external cert via `load_pem` |
| `""` (legacy) | — | defaults to acme (backward compatible) |

`computeEffectiveCertSource` (`internal/api/handler.go`) gains a
`per-route-manual` / `manual:<label>` value.

### 5.3 Emission
In `buildTLSPolicies` / `buildTLSApp` (`internal/caddymgr/manager.go`): for a
route with `CertSource=="manual"`:
- Emit the stored PEM under `apps.tls.certificates.load_pem` (static — key +
  cert + chain inline).
- Emit **NO** ACME/internal automation policy for that host.
- Add the host to `skip_certificates` (`buildSkipList`) so Caddy's `auto_https`
  does not also try to ACME-issue it. **⚠️ This is the load-bearing empirical
  assumption — see §8 smoke.**

Guard the emitted JSON with `caddy.Validate` (`TestBuildConfigJSON_LoadsCleanly`
fixture gains a manual-cert route).

### 5.4 Interaction with the 3 route states
- `active` + manual → the manual cert is served at handshake, proxy runs.
- `disabled` + manual → route filtered before buildConfigJSON (404 catch-all);
  no cert emitted (nothing to serve).
- `maintenance` + manual → the route stays emitted; **the manual cert MUST be
  served for the TLS handshake so the 503 handler can respond at all** (no
  handshake → no 503). `buildTLSPolicies` must include the manual cert for a
  maintenance route exactly as for an active one. Dedicated smoke (§8).

## 6. Wildcard external certs (Q7 — locked)
No special handling. A wildcard external cert is a cert whose SAN list includes
`*.apex`; a route references it explicitly (§5.1) and the SAN match accepts the
wildcard per RFC 6125. Multiple routes may reference the same multi-SAN /
wildcard cert. No external managed-domain concept (non-goal).

## 7. Alerting — `cert_manual_expiring` source (Brick D, Q8 — locked)
**Empirical finding:** the existing `cert_expiry` source
(`internal/alerting/source_cert_expiry.go`) reads through `CertLister` =
`*certinfo.Tracker`, the **runtime** cert tracker fed by Caddy handshake
events — it does NOT see BoltDB-stored external certs. So a dedicated source
reading the store is the clean, decoupled choice (not wiring external certs
into the runtime tracker).

New `internal/alerting/source_cert_manual_expiring.go`:
- `Name() == "cert_manual_expiring"`, registered in the `SourceRegistry`.
- `Read` lists `store.ListExternalCertificates()`, computes days-until-NotAfter,
  returns the count of certs within the threshold (configurable via rule params,
  default 30 days) + a context payload (id, name, dnsNames, notAfter, daysLeft).
- Edge-triggered via the existing `AlertRule.LastMatched` mechanism (the
  `alerting_state_rules_edge_triggered` fix), so it fires once per transition,
  not every poll.
- Routes to Discord/webhook/email like every other source.

Also register the source name so `GET /alerting/sources` (if/when it exists)
and the rule editor can surface it — note the known
`alerting_sources_hardcoded_frontend` backlog: the RuleModal Source dropdown is
hardcoded, so this new source must be added there too or it's invisible.

## 8. Tests

Unit / integration:
- **storage**: create round-trip; GET redacts KeyPEM; preserve-on-edit (Key
  absent/empty keeps, Chain null clears); re-parse-on-cert-change gate (§3.6);
  X.509 validation (blocking + warnings); CRLF normalization.
- **api**: upload returns warnings for expired/not-yet-valid; GET redacts key;
  DELETE 409 when a manual route references it, 200 + reload otherwise;
  audit ExactSet bumped.
- **caddymgr**: `TestBuildConfigJSON_LoadsCleanly` passes with a manual-cert
  route (`caddy.Validate`); a manual route emits `load_pem` and NOT an ACME
  policy; the host appears in `skip_certificates`.
- **route validation**: manual + unknown CertID → 400; manual + host not in
  SANs → 400; wildcard SAN covers one label, not two.

**Live-serve smoke (mandatory — caddy.Validate provisions but does not serve):**
model on `docs/smoke-test-maintenance.md`. A self-signed test cert stands in
for the external cert.
1. Route ACME baseline + route manual (uploaded self-signed) → inspect the live
   Caddy config via the admin API: manual host in routing ✓, PEM in
   `load_pem` ✓, manual host NOT in `automation.policies` ✓, manual host in
   `skip_certificates` ✓.
2. HTTPS handshake: `curl -v --resolve` the manual host → served the manual cert
   (not the internal fallback), NO ACME request logged for that host.
3. Non-regression: the ACME route still works; no `skip_certificates` leak onto
   ACME hosts.
4. **maintenance + manual**: a manual route in maintenance → TLS handshake
   succeeds (manual cert served) AND HTTP response is 503 (maintenance handler
   active). Proves the handshake-before-503 ordering.
5. Restart persistence: restart Arenet → config re-emitted → manual cert still
   served, no new ACME challenge for the manual host.

## 9. File map (implementation targets)
- `internal/storage/external_cert.go` (+ `_test.go`) — collection, validation,
  parse-metadata helper, bucket registration in the storage.go creation loop.
- `internal/storage/routes.go` — `CertSource` + `CertID` fields + validate.
- `internal/api/external_certs.go` (+ `_test.go`) — CRUD handlers + routes
  registration (admin group).
- `internal/api/handler.go` — routeRequest/response wire fields +
  `computeEffectiveCertSource` manual value.
- `internal/api/routes.go` — create/update maps carry CertSource/CertID.
- `internal/caddymgr/manager.go` — manual-cert branch in buildTLSPolicies /
  buildTLSApp / buildSkipList; buildOpts carries the external-cert set read
  in applyLocked.
- `internal/audit/actions.go` (+ actions_test.go) — 3 new actions + ExactSet.
- `internal/alerting/source_cert_manual_expiring.go` (+ `_test.go`) +
  registry registration.
- `web/frontend/src/lib/api/` — external-certs client + types.
- `web/frontend/src/routes/settings/certificates/` (or the existing certs
  surface) — upload panel + list (sort by expiry).
- `web/frontend/src/routes/routes/+page.svelte` — CertSource dropdown +
  filtered CertID picker.
- `web/frontend/src/lib/i18n/locales/{en,fr}.json` — twins + parity guard.
- `web/frontend/.../RuleModal` — add `cert_manual_expiring` to the Source list.
- `docs/wiki-seed/Certificates.md` + `-FR.md`, `Routes.md` + `-FR.md`,
  `Alerting.md` if present — upload flow, manual renewal, expiry alert,
  the CertSource picker.
- `docs/smoke-test-external-certs.md` — the §8 live-serve procedure.
