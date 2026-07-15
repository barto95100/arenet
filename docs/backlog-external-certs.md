# Backlog — External / operator-supplied TLS certificates (bring-your-own-cert)

**Status:** Not started. Backlog note (2026-07-15). Feasibility confirmed
against code + vendored Caddy v2.11.3.

**One-line:** Let an operator upload and serve a TLS certificate issued by
an external CA (DigiCert, a corporate/enterprise PKI, etc.) instead of
Arenet auto-issuing via ACME or the internal self-signed CA.

---

## 1. Why

Today Arenet can only obtain a certificate two ways
(`internal/caddymgr/manager.go` — the only functions touching `apps.tls`):

- **ACME** — `buildACMEPolicy` (manager.go:2415) emits `{"module":"acme",...}`
  for HTTP-01 (default) or DNS-01 (OVH wildcard).
- **Internal self-signed** — the `{"module":"internal"}` literal
  (manager.go:2167), catch-all + fallback when a managed domain has no
  DNS provider.

The route TLS model is a closed set: `Route.TLSEnabled bool` +
`Route.ACMEChallenge` enum (`"", "http-01", "dns-01", "inherited"`,
constants at `internal/storage/routes.go:65-67`). The API's
`computeEffectiveCertSource` (`internal/api/handler.go:1744`) derives a
5-value closed enum — `""`, `managed-domain:<apex>`, `per-route-acme:dns-01`,
`per-route-acme:http-01`, `per-route-internal`. **There is no `manual` /
`uploaded` / `external` variant anywhere.**

This blocks a real class of user: anyone who already holds a cert from a
commercial/enterprise CA (compliance requirement, corporate PKI, EV cert,
a CA that isn't ACME-capable, or an air-gapped/offline issuance workflow)
cannot use it in Arenet. They are forced onto Let's Encrypt / ZeroSSL or
a self-signed cert the browser rejects.

This is already logged as deliberately-deferred, not an oversight:
- `docs/backlog-step-j.md:271-277` — "manual cert upload — feature Arenet
  does NOT support today, separate sub-feature with its own design surface
  (where to store, how to renew warnings, key confidentiality, etc.)."
- `docs/superpowers/specs/2026-05-30-step-o-wildcards.md:354` — listed under
  "Out of scope (for v1.2): Manual cert upload (operator pastes PEM)."

This note promotes it to a scoped backlog item.

## 2. Feasibility — the embedded engine already supports it

Caddy has standard, registered manual-cert loader modules (vendored
`caddy/v2@v2.11.3/modules/caddytls/`):

- `tls.certificates.load_pem` — `pemloader.go:55` (cert + key as inline PEM)
- `tls.certificates.load_files` — `fileloader.go:56` (cert + key file paths)
- `tls.certificates.load_folders` — `folderloader.go:42`

A cert loaded this way goes under `apps.tls.certificates.load_pem`
(or `load_files`) in the JSON and is matched to a host at handshake via
the standard SNI cert selection — no ACME automation policy for that host.
**This is a product gap in Arenet's config generation, not an engine
limitation.** Arenet already fully controls the emitted `apps.tls` JSON,
so adding a manual-cert branch is a bounded change.

## 3. Proposed shape (brick decomposition, mirrors the GeoIP/DNS-provider work)

Not a spec — a sketch of the design surface so the eventual spec-per-brick
has a starting point.

### Brick A — storage: uploaded-cert collection
- New BoltDB bucket, UUID-keyed collection (mirror the multi-config DNS
  provider pattern in `internal/storage/dns_provider.go`), each record:
  cert chain (PEM), private key (PEM), label, parsed metadata (subjects/SANs,
  not-before/not-after, issuer) extracted at upload with `x509.ParseCertificate`.
- **Private key is a secret**: same write-only discipline as MaxMind/OVH —
  never returned by GET, never logged, redacted from the backup snapshot
  (sentinel pattern). See [[route_basic_auth_hash_cache]]-era secret rules
  and the MaxMind license-key handling as the reference.
- Validation at store time: key matches cert (`tls.X509KeyPair`), chain
  parses, not-yet-expired (warn, don't hard-reject an expired one — operator
  may be staging).

### Brick B — API: upload + CRUD + validation
- `POST /certs/uploaded` (PEM cert+chain+key), `GET` (metadata only, no key),
  `DELETE`. Structured x509 validation errors (key/cert mismatch, unparseable,
  SAN list) surfaced like the DNS-provider `/test` errors.
- Audit actions as typed constants (the pattern enforced for MaxMind/DNS —
  `internal/audit/actions.go` + `TestAllActions_ExactSet`).

### Brick C — route model + caddymgr emission
- Extend the TLS model. Cleanest: add a TLS "mode" so the closed enum
  becomes `acme (http-01|dns-01) | internal | manual`, with a
  `Route.CertID` (or managed-domain-level) reference to a Brick-A record.
  Touches `internal/storage/routes.go` (new field + validate), the API's
  `computeEffectiveCertSource` (new `per-route-manual` / `manual:<label>`
  value), and the frontend cert-source display.
- `buildTLSPolicies` (manager.go:2166): for a manual-cert route, emit NO
  ACME/internal automation policy for that host; instead emit
  `apps.tls.certificates.load_pem` with the stored PEM (written to a temp
  file or inline) + a `tls_connection_policy` that resolves it by SNI.
  Guard with `caddy.Validate` on the emitted JSON (the mandated pattern —
  `TestBuildConfigJSON_LoadsCleanly`) so a bad manual-cert config can't
  reach `caddy.Load`.
- **Interaction with `auto_https`**: a host with a manual cert must be added
  to the auto-HTTPS skip list (`buildSkipList`, manager.go) so Caddy doesn't
  also try to ACME-issue it. Verify empirically (CLAUDE.md §Empirical
  verification) — this is exactly the class of Caddy-behaviour assumption
  that must be proven, not inferred.

### Brick D — UI + expiry alerting + docs
- Upload panel (drag PEM or paste) in `/certs` or `/settings`, cert-source
  picker on the route editor (mode = manual → pick an uploaded cert).
- **No auto-renewal** for manual certs — so an expiry alert is essential:
  reuse the alerting `SourceRegistry` (a new `cert_manual_expiring` source,
  mirroring `cert_renewal_failed`, see [[cert_renewal_failed_source]]) that
  fires N days before not-after. The certinfo dashboard (`internal/certinfo`,
  currently ACME-only, read-only) should surface manual certs too.
- Docs: Certificates page (EN+FR) — how to upload, that renewal is manual,
  the expiry-alert behaviour.

## 4. Hard parts / open questions (the "design surface" the specs flagged)

- **Renewal is the operator's job.** Unlike ACME, nothing auto-renews. The
  expiry-alert (Brick D) is not optional polish — it's the safety net that
  makes the feature responsible to ship. Decide lead time + channel.
- **Key confidentiality on disk.** `load_pem` inline keeps the key in the
  Caddy JSON (in memory); `load_files` needs the key written to disk where
  Caddy reads it. Either way the key sits in the data dir — decide whether
  to encrypt at rest in BoltDB (the store already holds other secrets in
  the clear today, so this may be a broader decision).
- **Chain / intermediate handling.** Operators often have leaf + intermediates
  in separate files; the upload must accept and correctly order the chain.
- **OCSP stapling / must-staple** — Caddy handles OCSP for loaded certs;
  confirm behaviour, surface staple status in the dashboard (already noted as
  a follow-up widget in step-o spec:140).
- **Related but distinct: ACME EAB** (External Account Binding) for private
  ACME CAs — also backlog (`step-o-wildcards.md:357`). Different mechanism
  (still ACME, just authenticated to a private directory), not covered here,
  but the same class of "enterprise CA" user may want it. Worth deciding
  whether BYO-cert or EAB is the higher-value first step.

## 5. Rough sizing

Comparable to the multi-DNS-provider workstream (storage + API + caddymgr +
UI + i18n + docs, ~4 bricks). The caddymgr emission + auto_https-skip
interaction is the load-bearing risk and needs an empirical Caddy smoke
(emit → `caddy.Validate` → real handshake with a self-signed test cert)
before it's considered settled. The expiry-alert + secret-redaction pieces
reuse existing patterns and are low-risk.
