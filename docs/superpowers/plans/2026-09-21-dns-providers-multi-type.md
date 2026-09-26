<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# DNS Providers Multi-Type — Implementation Plan

**Spec:** `docs/superpowers/specs/2026-09-21-dns-providers-multi-type-design.md`

**Goal:** Replace the OVH-hardwired `DNSProviderConfig` (3 flat secret
fields) with a type registry + generic `Credentials map[string]string`, ship
9 provider types, redact secrets from Caddy load errors, and add a read-only
"test connection" endpoint + UI button.

**Tech:** Go 1.25+, Caddy v2.11.4 (bump from 2.11.3, required by
`caddy-dns/scaleway`), 8 new `caddy-dns/*` modules, SvelteKit 5 + Vitest.

## Global constraints

- AGPL header on every new Go / TS / Svelte file.
- **OVH non-regression:** an existing OVH provider emits Caddy JSON
  byte-identical to v2.25.1 (golden assertion).
- **Backward compatibility:** legacy flat keys (`endpoint`,
  `application_key`, `application_secret`, `consumer_key`) decode into
  `Credentials` via `DNSProviderConfig.UnmarshalJSON` — covers BoltDB rows,
  old backups, and the legacy singleton migration. The API still accepts the
  camelCase OVH fields.
- **Secrets never leave the server:** not in API views, audit rows, backup
  exports (sentinel), slog lines, or error strings (redaction).
- **`caddy.Validate` placement:** new Validate-based tests go in
  `internal/caddymgr/manager_test.go` after the `TestSyncRegistry` tests, no
  active health check in the fixture (known Caddy-internal race under
  `-race`).
- i18n EN + FR parity for every new string.
- Version v2.26.0; no tag until operator go-ahead.

---

### Task 1 — Registry + storage model + migration

**Files:** `internal/storage/dns_provider_types.go` (new),
`internal/storage/dns_provider.go`, `internal/storage/migrate.go` (register
boot migration), tests `dns_provider_types_test.go` (new),
`dns_provider_test.go`.

- Registry types `DNSProviderField` / `DNSProviderType`, 9 entries with the
  field table from spec §Faits empiriques #2 and provider docs URLs.
- `DNSProviderTypeByName`, `DNSProviderTypesList` (OVH first, then
  alphabetical), `ProviderConfigured(c)`, `SecretValues(c)`,
  `SecretKeys(type)`.
- `DNSProviderConfig{ID, Label, Type, Credentials}` + `UnmarshalJSON`
  folding legacy keys; `Type == ""` → `ovh`.
- `validate()`: known type, required non-empty, enum membership, no unknown
  keys; empty optional values dropped.
- `UpdateDNSProvider`: generic preserve-on-edit for secret keys when the type
  is unchanged; type change preserves nothing.
- Boot migration `migrateDNSProviderCredentialsMap` (idempotent rewrite).
- Tests: registry sanity (unique types/keys, enum defaults valid), legacy
  decode, validate matrix, preserve-on-edit, type change, migration
  idempotence.

### Task 2 — Caddy emission, module imports, redaction

**Files:** `internal/caddymgr/manager.go`, `internal/caddymgr/dns_redact.go`
(new) + test, `internal/caddymgr/manager_test.go`, `cmd/arenet/main.go`,
`go.mod` / `go.sum`.

- `go get` the 8 modules (bumps Caddy to v2.11.4); blank imports in
  `main.go` and `manager_test.go`.
- `buildACMEPolicy`: `provider = {"name": Type} ∪ non-empty Credentials`.
  Replace `dnsProviderConfigured` with `storage.ProviderConfigured`.
- `redactSecrets(err, providers)` applied in `applyLocked` on `caddy.Load`
  failure (values ≥ 4 chars → `[REDACTED]`).
- Tests: OVH golden JSON (byte-identical provider block), new
  `TestBuildConfigJSON_LoadsCleanly_AllDNSProviderTypes` (one managed domain
  per registry type, all fields filled → single `caddy.Validate`), redaction
  unit tests (incl. real Cloudflare Provision error shape).
- `cmd/arenet/main.go:1936` → `storage.ProviderConfigured`.

### Task 3 — API: generic wire, `/types`, `/test`

**Files:** `internal/api/dns_provider.go`, `internal/api/dns_provider_test.go`
(new file `dns_provider_test_connection.go` + test), `internal/api/routes.go`,
places using `dnsProviderComplete`.

- Request `{label, type, credentials}` + OVH camelCase fold-in.
- View `{id, label, type, configured, fields, secretsSet, usedBy, endpoint}`.
- Audit copies with secret keys blanked (`dnsProviderForAudit` generic).
- `GET /settings/dns-providers/types` (viewer+).
- `POST /settings/dns-providers/{id}/test` (admin): zone from body or first
  linked managed domain, else 400 `zone_required`; instantiate
  `dns.providers.<type>` via `caddy.GetModule`, Provision, `GetRecords`
  with 15 s timeout; `{ok, records}` / `{ok:false, error}` redacted.
  Provider instantiation behind a small interface so tests inject a fake.
- Tests: CRUD per type, legacy OVH body, secrets absent from views/audit,
  `/types` shape, `/test` success/failure/zone_required/RBAC/redaction.

### Task 4 — Backup / restore

**Files:** `internal/backup/sentinel.go`, `import.go`, `validate.go` + tests.

- Sentinel per secret key; resolve per key with live fallback only when the
  live provider has the same id **and** type; placeholders per cleared key.
- Tests: export sentinelises all secret keys (Cloudflare + OVH), round-trip,
  pre-v2.26 flat-field snapshot fixture imports correctly.

### Task 5 — Frontend

**Files:** `web/frontend/src/lib/api/types.ts`, `settings.ts` (+ tests),
`lib/components/settings/DNSProvidersSection.svelte` (+ test),
`lib/i18n/locales/{en,fr}.json`.

- Load types once; type selector on create (read-only on edit); fields
  generated from registry (password inputs for secrets, "unchanged"
  placeholder when `secretsSet[key]`, select for enums, required markers),
  docs link.
- "Test connection" button with zone input (prefilled from `usedBy[0]`),
  inline result.
- i18n keys with registry-label fallback; parity test passes.

### Task 6 — Docs, version

- `docs/wiki-seed/DNS-Providers.md` + `-FR.md`: supported types table, token
  scopes per provider, "validated automatically, not live-tested by the
  maintainer" note, test button.
- `docs/smoke-test-dns-providers.md`: real OVH smoke (operator) + automated
  validation evidence for the others.
- README feature line; roadmap backlog update; binary size before/after in
  the PR description.

## Verification gates (before PR)

```bash
go build ./... && go vet ./...
go test -race -count=1 ./internal/storage/... ./internal/caddymgr/... ./internal/api/... ./internal/backup/...
cd web/frontend && npm run check && npm test && npm run build
go build -o /tmp/arenet ./cmd/arenet   # size comparison
```
