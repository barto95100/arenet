# GeoIP Auto-Update — Brick 2: MaxMind Credentials — Design

**Date:** 2026-07-13
**Status:** Approved (design validated by operator)

## Context

Brick 2 of the GeoIP auto-update feature. Brick 1 (swappable reader) is
done. This brick lets the operator store MaxMind credentials
(`account_id` + `license_key`) so Brick 3 can download the database. It
adds: BoltDB storage, a redacting CRUD API, a **test-connection** endpoint
(real MaxMind call), backup/restore participation, and the storage/API
surface the settings UI (Brick 4) will consume.

**Pattern to mirror: CrowdSec config** (`internal/storage/crowdsec_config.go`
+ `internal/api/crowdsec_settings.go`). MaxMind creds are structurally
identical to the CrowdSec bouncer config: a single record keyed `"default"`,
one secret field, GET/PUT/DELETE + test-connection, redaction via a
`configured` flag, preserve-secret-on-update. CrowdSec is the copy target
for storage + API; DNS/OIDC are the copy targets for the backup wiring
(CrowdSec itself is not in the backup snapshot — a gap we do NOT replicate).

## Decisions (from brainstorming)

1. **In the backup snapshot** (redacted via sentinel, like DNS/OIDC), so a
   restore preserves the license_key. Requires the 4 `internal/backup/`
   edits.
2. **Test-connection button** (real MaxMind API call) so the operator
   validates creds before enabling auto-update.
3. **Pull `github.com/maxmind/geoipupdate/v8/client` in this brick** — the
   test-connection uses `client.Download` for a real auth check; Brick 3
   reuses the same client for the actual download.

## Storage: `internal/storage/maxmind_config.go` (NEW)

Mirror `crowdsec_config.go`. Single-record, bucket keyed `"default"`.

```go
// MaxMindConfig holds the operator's MaxMind account credentials for
// GeoIP database auto-update. Single record (one MaxMind account).
type MaxMindConfig struct {
	// AccountID is the MaxMind account ID (an integer, stored as such).
	AccountID int `json:"account_id"`
	// LicenseKey is the MaxMind license key. SECRET — never echoed by
	// the API GET path (redacted like OVH/CrowdSec secrets; at-rest
	// threat model is the BoltDB file's 0o600 perms, same boundary).
	LicenseKey string `json:"license_key"`
	// EditionID is the database edition to download. Defaults to
	// "GeoLite2-City" (what internal/geo opens). Stored so a future
	// operator could switch editions without a code change.
	EditionID string `json:"edition_id"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
```

Bucket constant `bucketMaxMind = "maxmind_config"` in `storage.go`; single
key `maxMindConfigKey = "default"`.

CRUD (mirror CrowdSec):
- `GetMaxMindConfig(ctx) (MaxMindConfig, error)` — `ErrNotFound` on a fresh
  install.
- `PutMaxMindConfig(ctx, cfg) error` — upsert; preserves `CreatedAt`; trims
  string fields; **preserve-secret-on-update**: if `cfg.LicenseKey == ""`,
  inherit `existing.LicenseKey`. Default `EditionID` to `"GeoLite2-City"`
  when empty.
- `DeleteMaxMindConfig(ctx) error` — removes the record (operator clears
  their creds).
- `MaxMindConfigEverConfigured(ctx) (bool, error)` — for diagnostics / UI.

Validation (storage last-line): `AccountID > 0` and `LicenseKey != ""` on a
non-preserve write (a Put that ends with an empty license key after the
merge is rejected — you can't store half-credentials).

## API: `internal/api/maxmind_settings.go` (NEW)

Mirror `crowdsec_settings.go`. Admin-gated (the settings subgroup).

**Wire shapes:**
```go
type maxMindRequest struct {
	AccountID  int    `json:"accountId"`
	LicenseKey string `json:"licenseKey"` // "" on edit = keep stored
	EditionID  string `json:"editionId,omitempty"`
}
type maxMindResponse struct {
	AccountID  int    `json:"accountId"`
	EditionID  string `json:"editionId"`
	Configured bool   `json:"configured"` // AccountID>0 && LicenseKey set
	// LicenseKey intentionally omitted (never echoed).
}
```

**Redaction:** `maxMindResponseFor(cfg)` sets `Configured = cfg.AccountID > 0
&& cfg.LicenseKey != ""`, never includes the key. Audit scrub
`maxMindConfigForAudit` blanks the key before BeforeJSON/AfterJSON.

**Handlers:**
- `getMaxMindSettings` — `GET /api/v1/settings/maxmind` → `maxMindResponse`
  (redacted). `ErrNotFound` → return a zeroed response with
  `Configured:false` (not a 404 — the UI wants an empty form, matching
  CrowdSec/OIDC behavior; confirm against the CrowdSec GET handler and
  follow whichever it does).
- `putMaxMindSettings` — `PUT /api/v1/settings/maxmind`. Preserve-secret
  merge at the handler level (blank `licenseKey` → inherit stored, mirror
  `putCrowdSecSettings:167-169`), then `PutMaxMindConfig`. 200 + audit
  `maxmind_config_updated`.
- `deleteMaxMindSettings` — `DELETE /api/v1/settings/maxmind`. 200 + audit
  `maxmind_config_deleted`.
- `testMaxMindConnection` — `POST /api/v1/settings/maxmind/test`. See below.

**Routes** (`internal/api/routes.go`, in the admin subgroup near the
CrowdSec routes ~`:446-449`):
```
r.Get("/settings/maxmind", h.getMaxMindSettings)
r.Put("/settings/maxmind", h.putMaxMindSettings)
r.Delete("/settings/maxmind", h.deleteMaxMindSettings)
r.Post("/settings/maxmind/test", h.testMaxMindConnection)
```

## Test-connection: `internal/api/maxmind_test_connection.go` (NEW)

Mirror `oidc_test_connection.go` / `testCrowdSecConnection` — always 200
with a `{reachable bool, error string}` body (never a 4xx/5xx for a failed
test; the failure is data, not an HTTP error).

**Behavior:**
- Read the request body OR the stored config for creds. Support **testing
  unsaved creds**: the request may carry `accountId` + `licenseKey`; if
  `licenseKey` is blank, fall back to the stored key (so the operator can
  test a saved config via its `configured` state without re-typing). If no
  usable creds → `{reachable:false, error:"no credentials"}`.
- Build the client: `client.New(accountID, licenseKey)` (add
  `client.WithHTTPClient` with a ~10s-timeout http.Client).
- Validate via a real request: `client.Download(ctx, editionID, "someMd5")`
  under a short `context.WithTimeout` (e.g. 10s). **Do not read the body.**
  MaxMind authenticates on the response headers, so:
  - `err == nil` (with `UpdateAvailable` either way) → creds valid.
    Immediately `resp.Reader.Close()` **without** `io.ReadAll` — we must not
    pull the ~60 MB DB just to test auth.
  - `errors.As(err, &httpErr)` (a `client.HTTPError`) → creds invalid /
    access problem → `{reachable:false, error:<status + message>}`.
  - other error (network/timeout) → `{reachable:false, error:"could not
    reach MaxMind: <err>"}`.
- Pass a non-empty dummy md5 (or the last-known md5 once Brick 3 stores it)
  so a valid-creds test that finds no update returns quickly without a
  body; if `UpdateAvailable` is true, still just close the Reader unread.

  > Implementation note (empirical, verify at build): `Download` with a
  > non-empty md5 that doesn't match returns `UpdateAvailable:true` and a
  > Reader for the new DB. We close it unread — auth is already proven by
  > the 200. If MaxMind's client insists on the caller consuming the body,
  > fall back to an empty md5 + `ctx` cancel right after the first read, or
  > a `HEAD`-style check; pick whatever the vendored client supports
  > without downloading 60 MB. The invariant to preserve: **the test must
  > not download the full database.**

## Backup participation (4 edits in `internal/backup/`)

Per the redaction discipline at `sentinel.go:31-35` (a new secret field
elsewhere REQUIRES a matching redaction entry or the export leaks it):

1. `types.go` — add `MaxMind *storage.MaxMindConfig` (or value + presence
   flag, matching how OIDC single-record config is embedded) to `Snapshot`.
2. `sentinel.go` `redactSnapshotInPlace` — replace `MaxMind.LicenseKey`
   with `SentinelLiteral` in the redacted (no-secrets) export.
3. `import.go` `resolveSentinels` — add a `resolve(...)` block for MaxMind
   keyed `"default"` (mirror the OIDC block at `import.go:350-359`).
4. `import.go` `readLive` — capture live MaxMind state (does a config exist,
   what's its stored key) so a sentinel can inherit on restore; add the
   `identityKey` label.

`account_id` and `edition_id` are non-secret → travel verbatim; only
`license_key` is sentinel-redacted.

## Frontend (API client + types only in this brick)

The settings UI **panel** is Brick 4. Brick 2 ships the client + types so
Brick 4 (and manual testing) can call the API:
- `web/frontend/src/lib/api/settings.ts` — `getMaxMind`, `putMaxMind`,
  `deleteMaxMind`, `testMaxMind` (mirror the CrowdSec/OIDC client methods).
- `web/frontend/src/lib/api/types.ts` — `MaxMindConfig` (`accountId`,
  `editionId`, `configured`; no secret), `MaxMindRequest` (`accountId`,
  `licenseKey`, `editionId?`), `MaxMindTestResult` (`reachable`, `error`).

The i18n parity guard applies to any new keys added; Brick 2 adds none if
it ships no component (client/types carry no user-facing strings). If a
key is needed, add to both en/fr.

## Testing

- **Storage** (`maxmind_config_test.go`, mirror `crowdsec_config_test.go`):
  Get on fresh install → `ErrNotFound`; Put→Get round-trip; preserve
  license_key on blank-key update; default EditionID; delete; reject a Put
  that resolves to empty license key or `AccountID<=0`.
- **API** (`maxmind_settings_test.go`, mirror the CrowdSec settings test):
  GET redacts (no `licenseKey` in JSON, `configured` correct); PUT with
  blank key preserves stored; DELETE; admin-gating (viewer → 403); audit
  scrub blanks the key.
- **Test-connection:** unit-test the handler with a **mock/stub** at the
  client seam — inject a fake that returns (a) success, (b) an
  `HTTPError`, (c) a network error, and assert the `{reachable,error}`
  mapping. Do NOT hit the real MaxMind API in unit tests. (Structure the
  handler so the `client.Download` call is behind a small interface/func
  var that tests can substitute — the same seam Brick 3's updater will
  use.)
- **Backup:** extend the backup redaction/resolution tests to cover the
  MaxMind license_key sentinel round-trip (redacted export → restore
  inherits from live) — mirror the existing OIDC sentinel test.

## Runtime verification

- `go build ./...` clean with the new `geoipupdate/v8/client` dep (`go get`
  it; `go mod tidy`).
- `caddy`/config unaffected.
- Manual/operator (has real MaxMind creds): PUT creds → GET shows
  `configured:true`, no key leaked → POST /test with valid creds →
  `reachable:true`; with a wrong key → `reachable:false`. The full
  end-to-end (test does NOT download 60 MB) is confirmed by watching the
  response latency + no large transfer. Deferred parts (actual scheduled
  download + reload) are Brick 3.

## Non-goals (YAGNI)

- No scheduler, no actual DB download, no reload wiring (Brick 3).
- No settings UI panel/component (Brick 4) — only client + types here.
- No at-rest encryption of the license_key (same boundary as OVH/CrowdSec
  secrets: BoltDB 0o600).
- No multi-account support (single record, like CrowdSec/OIDC).

## Files summary

| Action | File |
| --- | --- |
| Create | `internal/storage/maxmind_config.go` (struct + CRUD) |
| Create | `internal/storage/maxmind_config_test.go` |
| Modify | `internal/storage/storage.go` (bucket constant + registration) |
| Create | `internal/api/maxmind_settings.go` (handlers + redaction + audit scrub) |
| Create | `internal/api/maxmind_settings_test.go` |
| Create | `internal/api/maxmind_test_connection.go` (test handler + client seam) |
| Modify | `internal/api/routes.go` (4 admin-gated routes) |
| Modify | `internal/backup/types.go` (Snapshot field) |
| Modify | `internal/backup/sentinel.go` (redact license_key) |
| Modify | `internal/backup/import.go` (resolve + readLive + identityKey) |
| Modify | backup tests (sentinel round-trip for MaxMind) |
| Modify | `web/frontend/src/lib/api/settings.ts` (4 client methods) |
| Modify | `web/frontend/src/lib/api/types.ts` (MaxMind types) |
| Modify | `go.mod` / `go.sum` (add `geoipupdate/v8`) |

## Global constraints (from CLAUDE.md)

- `gofmt -s`/`go vet`/`staticcheck` clean; `ctx` first arg on I/O; wrap
  errors `%w`; `slog`; no panic; AGPL header on new files.
- Match the CrowdSec storage/API pattern; match DNS/OIDC backup wiring.
- Secret never echoed on GET; audit scrubs it; preserve-on-blank-update.
- New dependency `geoipupdate/v8` is Apache/MIT (AGPL-compatible — verified
  in Brick-1 research).
