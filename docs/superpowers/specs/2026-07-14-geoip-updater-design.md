# GeoIP Auto-Update — Brick 3: The Updater (download → reload) — Design

**Date:** 2026-07-14
**Status:** Approved (design validated by operator)

## Context

Brick 3 of the GeoIP auto-update feature — the piece that ties Brick 1
(swappable `*geo.Lookup.Reload`) and Brick 2 (MaxMind credentials) together
into a working auto-updater: it downloads the GeoIP database from MaxMind,
writes it atomically to disk, and hot-reloads it so the **country-block
(geoblock)**, geo enrichment, server-position, and batch-lookup features
immediately use the new database — **without an Arenet restart**.

### Verified end-to-end premise (the operator's key concern)

Confirmed by empirical trace (file:line): there is exactly ONE `*geo.Lookup`
(created at `cmd/arenet/main.go:506`), shared by pointer with every
consumer — country-block (`main.go:534` via the `countryBlockGeoLookup`
adapter), enricher (`main.go:632`), server-position (`main.go:586`/`:1411`),
batch-lookup (`main.go:1392`). None caches the reader or the resolved
`Location` — each calls `LookupIP` fresh. Brick 1's `Reload` mutates the
reader **in place** via the internal `atomic.Pointer` (`Lookup.Reload`,
receiver `*Lookup`, `l.reader.Swap(nr)` — verified on branch
`feature/geoip-swappable-reader`). Therefore after `geoLookup.Reload(path)`:
**all consumers use the new DB automatically, with NO re-wiring** (the
country-block `SetGlobalLookup` need NOT be re-called — its adapter wraps
the same self-swapping pointer). This is the correctness guarantee the whole
feature rests on, and it holds.

## Decisions (from brainstorming)

1. **Trigger:** opt-in periodic scheduler (weekly default) + a manual
   "update now" endpoint.
2. **Bootstrap:** on boot, if MaxMind creds are configured and NO local DB
   exists, download one (so geoblock works with zero manual `scp`).
3. **Atomic write:** download to `<path>.tmp`, `os.Rename` to `<path>`,
   then `Reload` — the geoblock never sees a half-written file.
4. **MD5 state:** computed from the on-disk `.mmdb` each check (empty if
   absent). No persisted MD5 — the file is the source of truth, no drift.
5. **Config:** a SEPARATE `GeoIPUpdateConfig{Enabled, IntervalOverride}`
   record — do NOT extend `MaxMindConfig` (keeps the secret record clean;
   lets the scheduler toggle independently of credential validation).
6. **Edition guard (operator-flagged):** Arenet's reader calls
   `reader.City(ip)` (`lookup.go:122`), which requires a **City-type**
   MMDB. The download must install ONLY a City database — never Country
   or ASN. See the dedicated guard below.

### Edition guard — must be a City database, never Country/ASN

Arenet uses **GeoLite2-City** (not Country) because it needs both the
country (for geoblock) AND city/lat-lon (for the **world map** — the Step V
geographic threat map at `/map` / `WorldMap.svelte` — and server position);
City contains both, Country does not. (The topology view is the D3 route
graph and does not use geo.) The `MaxMindConfig.
EditionID` is operator-configurable, so a mistake (`GeoLite2-Country`,
`GeoLite2-ASN`, `GeoLite2-City`'s ASN sibling) is possible.

Verified against `geoip2-golang@v1.9.0`: `reader.City(ip)` checks the DB
type (`reader.go:331` — `isCity & databaseType == 0 →
InvalidMethodError`). So a Country/ASN DB does NOT panic, but every
`LookupIP` returns `Found:false` — a **silent fail-open**: the geoblock
would stop matching and enrichment would go blank. That is the exact
failure the operator wants prevented.

**Guard:** after writing the downloaded file to the temp path (before the
`os.Rename` + `Reload`), open it with `geoip2.Open(tmp)` and confirm it is a
City database — either by checking `reader.Metadata().DatabaseType` contains
`"City"`, or by calling `reader.City(<a known public IP>)` and rejecting on
`InvalidMethodError`. If it is not a City DB → **abort the install**: remove
the temp file, do NOT rename, do NOT Reload, return `{Status:"error",
Error:"downloaded edition <X> is not a City database; Arenet requires a
GeoLite2-City / GeoIP2-City edition"}`, and log it. The existing on-disk DB
(if any) stays untouched. This makes a mis-set `EditionID` a loud, safe
failure instead of a silent geoblock outage.

(Belt-and-suspenders: the config layer could also warn if `EditionID`
doesn't contain "City", but the download-time guard is the authoritative
check since it inspects the actual downloaded bytes.)

### Empirical facts (verified against geoipupdate/v8@v8.0.0)

- `DownloadResponse` = `{LastModified time.Time, MD5 string, Reader
  io.ReadCloser, UpdateAvailable bool}` (`client/download.go:26`).
- **The `Reader` yields the already-extracted `.mmdb` bytes** — the library
  handles gzip + tar internally and positions on the `.mmdb` entry
  (`download.go:143-176`). So we just `io.Copy(tmpFile, resp.Reader)` — no
  tar/gzip handling on our side. The doc mandates: read to completion +
  close.
- `client.New(accountID int, licenseKey string, ...Option)`,
  `Download(ctx, editionID, md5) (DownloadResponse, error)`,
  `client.WithHTTPClient`, `client.HTTPError` (value-type alias) — same
  client Brick 2 uses.

---

## Section 1 — The downloader (new package `internal/geoipupdate`)

A self-contained, dependency-injected updater (structural template:
`internal/alerting/watcher.go`). NOTE: the package name `geoipupdate` is
Arenet's internal package; the MaxMind client is imported as
`github.com/maxmind/geoipupdate/v8/client` — no collision (different import
paths; alias the vendored one if the bare name clashes at a call site).

### Config / constructor (DI)

```go
type Config struct {
	Store       CredStore        // reads MaxMind creds each run (GetMaxMindConfig)
	Lookup      *geo.Lookup      // Reload target (Brick 1)
	MMDBPath    string           // resolved ARENET_GEOIP_MMDB / default
	HTTPClient  *http.Client     // injected (timeout)
	Download    DownloadFunc     // the seam (default = real client; tests stub)
	Logger      *slog.Logger
	Now         func() time.Time // testable clock (optional)
}
```

- `CredStore` is a small interface (`GetMaxMindConfig(ctx) (storage.MaxMindConfig, error)`) so tests inject a fake — same seam style as the watcher's `AlertRuleStore`.
- `DownloadFunc` is the download seam — **distinct from Brick 2's
  `maxMindProbe`** because this one READS the body (temp+rename), whereas
  the test-connection closes it unread:
  ```go
  type DownloadFunc func(ctx context.Context, accountID int, licenseKey, editionID, currentMD5 string) (client.DownloadResponse, error)
  ```
  Default impl: `client.New(...).Download(ctx, editionID, currentMD5)`.
  Tests substitute a fake returning a canned `DownloadResponse` (with an
  in-memory Reader) — no real MaxMind call.

### `UpdateOnce(ctx) UpdateResult` — the one-shot, shared by loop + manual endpoint

```go
type UpdateResult struct {
	Status       string    // "updated" | "up_to_date" | "no_credentials" | "error"
	Error        string    // set when Status=="error"
	LastModified time.Time // set when Status=="updated"
	At           time.Time // when this run completed
}
```

Flow:
1. `cfg := store.GetMaxMindConfig(ctx)`. On `ErrNotFound` or `AccountID<=0`
   or empty `LicenseKey` → `{Status:"no_credentials"}` (not an error — a
   normal "not configured yet" state).
2. Compute `currentMD5` = md5 hex of the on-disk `MMDBPath` file, or `""`
   if the file is absent (bootstrap). Read failure other than not-exist →
   `{Status:"error"}`.
3. `resp, err := Download(ctx, cfg.AccountID, cfg.LicenseKey, cfg.EditionID, currentMD5)`.
   - `err` → classify like Brick 2 (HTTPError → "credentials rejected: …";
     else "download failed: …"); `{Status:"error", Error:…}`.
4. `if !resp.UpdateAvailable` → close `resp.Reader` (if non-nil),
   `{Status:"up_to_date"}`.
5. **Atomic install (with edition guard):**
   - Create `MMDBPath + ".tmp"` (same dir → same filesystem, so rename is
     atomic). `defer` a cleanup that removes the tmp if it still exists
     (so a mid-write error — or a rejected edition — leaves no partial file).
   - `io.Copy(tmp, resp.Reader)` (the extracted .mmdb bytes), close
     `resp.Reader`, `tmp.Sync()`, `tmp.Close()`.
   - **Edition guard:** `geoip2.Open(tmp)` and verify it is a City database
     (see "Edition guard" above). If not → return `{Status:"error",
     Error:"downloaded edition … is not a City database …"}`; the defer
     removes the tmp; the existing DB is untouched; do NOT rename/Reload.
   - `os.Rename(tmp, MMDBPath)` — atomic replace.
   - `cfg.Lookup.Reload(MMDBPath)` — hot-swap. If Reload errors (corrupt
     download), the file is on disk but the reader stayed old (Brick 1
     preserves the current reader on open error) → `{Status:"error"}`
     surfacing the reload failure, and log it. (The bad file remains; next
     run's MD5 differs so it re-downloads. Acceptable.)
   - Success → `{Status:"updated", LastModified: resp.LastModified}`.
6. Never panics; the tmp cleanup defer guarantees no partial `.mmdb`.

`UpdateOnce` also updates the updater's in-memory `Status()` snapshot
(last result + timestamp + error), mutex-guarded, mirroring
`updatecheck.Checker.Status()` — for the `GET /status` endpoint.

## Section 2 — Scheduler + config + bootstrap

### `GeoIPUpdateConfig` storage (mirror `update_check_config.go`)

`internal/storage/geoip_update_config.go` (NEW):
```go
type GeoIPUpdateConfig struct {
	Enabled          bool   `json:"enabled"`
	IntervalOverride string `json:"intervalOverride"` // optional Go-duration
}
```
Own bucket `geoip_update`, fixed key `"config"`. `GetGeoIPUpdateConfig` →
zero-value (Enabled:false) on fresh install, nil error (no ErrNotFound
special-casing — same as UpdateCheckConfig). `PutGeoIPUpdateConfig` upsert.
No secret → no redaction, no audit-scrub concern.

### The loop (mirror the update-checker's `startUpdateLoop` in main.go)

- `Updater.Run(ctx)` / `Done()` skeleton from `alerting/watcher.go`:
  ctx-driven, `time.NewTicker(interval)`, resilient (a failed run logs and
  continues — network downloads fail transiently), `defer close(done)`.
- **Interval:** stored `IntervalOverride` → env
  `ARENET_GEOIP_UPDATE_INTERVAL` → **default 168h (weekly)**, 1h floor,
  bad/too-short → default with a warning. Resolver mirrors
  `resolveUpdateInterval` (`main.go:2048`).
- **Warmup:** ~30s delay before the first run (don't hit MaxMind at boot),
  like the update-checker.
- **Restart hook:** `onGeoIPConfigChange func(GeoIPUpdateConfig)` — cancels
  the prior loop then conditionally restarts (enable→start, disable→stop,
  interval→restart), no reboot. Mirror `startUpdateLoop`
  (`main.go:1504-1540`) + `SetUpdateConfigHook`.

### Bootstrap (boot-time)

At boot, after wiring: if `MaxMindConfigEverConfigured` (creds present) AND
the `MMDBPath` file does not exist → run one `UpdateOnce` (respecting the
warmup) even if the periodic loop's first tick would also do it — the point
is the geoblock becomes functional on first launch without a manual file.
If the scheduler is enabled, its immediate-first-tick already covers this;
the explicit bootstrap covers "creds present, file absent" regardless of
enabled state? **Decision: bootstrap only fires when the loop is enabled**
(don't download behind the operator's back if they haven't opted in).
Enabled + creds + no file → download. This keeps opt-in honest.

## Section 3 — API + wiring + frontend

### API (admin-gated, mirror `/system/version/*`)

`internal/api/geoip_update.go` (NEW):
- `GET /api/v1/system/geoip/update-config` → `{enabled bool, intervalHours int}`.
- `PUT /api/v1/system/geoip/update-config` → persist + fire `onGeoIPConfigChange`; 200.
- `POST /api/v1/system/geoip/update` → calls the SAME `UpdateOnce` the loop
  uses (like `systemVersionCheck` reuses `Check`); returns the
  `UpdateResult` as `{status, error?, lastModified?}`; always 200. 409 if the
  updater isn't wired.
- `GET /api/v1/system/geoip/status` → `Status()` snapshot `{lastStatus,
  lastError, lastUpdated}`.

Routes registered in the admin subgroup near `/system/version/*`
(`routes.go` ~:366). The handler holds the updater behind a small interface
(`UpdateOnce`, `Status`) so tests inject a fake, mirroring how the
version handler holds `updateChecker`.

### main.go wiring

- Resolve `mmdbPath` (already done, `main.go:502-504`).
- Build the `Updater` (DI: `store`, the `geoLookup` from `main.go:506`,
  `mmdbPath`, an `*http.Client{Timeout: ~5min}` — a full DB download needs
  a generous timeout, unlike the 10s test-connection).
- `apiHandler.SetGeoIPUpdater(updater)` + `apiHandler.SetGeoIPConfigHook(startGeoIPLoop)`.
- Boot: read `GetGeoIPUpdateConfig`, `startGeoIPLoop(cfg)`, run bootstrap.

### Frontend (client + types only; UI panel is Brick 4)

`api/settings.ts` + `api/types.ts`: `getGeoIPUpdateConfig`,
`putGeoIPUpdateConfig`, `triggerGeoIPUpdate`, `getGeoIPStatus`; types
`GeoIPUpdateConfig{enabled, intervalHours}`, `GeoIPUpdateResult{status,
error?, lastModified?}`, `GeoIPStatus{lastStatus, lastError, lastUpdated}`.

## Testing (TDD)

- **Downloader (`internal/geoipupdate`), seam + store mocked (no real MaxMind):**
  1. no_credentials (store returns ErrNotFound / incomplete).
  2. up_to_date (Download returns `UpdateAvailable:false` — assert NO file
     written, NO Reload).
  3. updated (Download returns a canned Reader with fake bytes + a temp
     MMDBPath — assert: file at MMDBPath now contains the bytes, `.tmp`
     gone, `Reload` called). Use a real `*geo.Lookup` pointed at the temp
     path OR a tiny seam to assert Reload was invoked.
  4. error/atomicity: Download's Reader errors mid-copy → assert MMDBPath is
     UNCHANGED (old file intact) and NO `.tmp` left behind (cleanup defer).
  5. bootstrap: MMDBPath absent → `currentMD5 == ""` passed to Download.
  6. **edition guard: a non-City DB is rejected.** Download returns a
     Reader whose bytes are a Country (or ASN) MMDB → assert `UpdateOnce`
     returns `{Status:"error", ...}`, MMDBPath is NOT written/replaced, no
     `.tmp` remains, and `Reload` is NOT called. (Fixture: a tiny real
     Country-type MMDB, or — since building one is hard — assert the guard
     via a seam that reports the opened DB's type; prefer a real minimal
     City vs Country fixture if the test-data is obtainable, else document
     the guard is covered by the type-check unit + runtime verification.)
- **Atomic-write guard:** an interrupted copy never leaves a corrupt
  MMDBPath (the pre-existing file, if any, is byte-identical after a failed
  run).
- **Config storage:** `GeoIPUpdateConfig` round-trip; Get-fresh → disabled.
- **API:** the 4 endpoints; admin-gating (viewer→403); the manual POST
  invokes `UpdateOnce`; GET config/status shapes.
- **Scheduler restart hook:** enable→starts, disable→stops, interval→restart
  (testable like the update-checker loop; assert via a fake updater's
  call-count under a fast interval + ctx cancel).

## Runtime verification

The end-to-end proof (real download → geoblock uses new DB) needs the
operator's real MaxMind creds on their VM — **hand-off**:
1. Configure creds (Brick 2) + enable auto-update; `POST /system/geoip/update`.
2. Confirm the `.mmdb` appears/updates at `MMDBPath`, `GET /status` shows
   `updated`, and — the key check — a country-block rule immediately
   reflects the new DB (block/allow a country whose data is in the fresh DB)
   **without restarting Arenet**.
3. **Edition guard:** set `EditionID` to `GeoLite2-Country` (or ASN) and
   trigger an update → confirm it is REJECTED (`GET /status` shows the
   "not a City database" error), the existing City DB is untouched, and the
   geoblock keeps working on the old DB. Then set it back to
   `GeoLite2-City` → update succeeds.
In-workspace (no creds): the seam-mocked tests prove the download→temp→
rename→Reload flow and the atomicity guarantee; `go build ./...` + `-race`
on the updater's loop.

## Non-goals (YAGNI)

- No settings UI panel (Brick 4) — client + types only here.
- No multi-edition / multi-DB (single GeoLite2-City, per Brick 2's edition).
- No persisted MD5/last-modified (file-on-disk is the source of truth).
- No signature/GPG verification of the download (MaxMind's TLS + the
  library's own handling is the boundary; matches the manual-download
  status quo).

## Files summary

| Action | File |
| --- | --- |
| Create | `internal/geoipupdate/updater.go` (Config, UpdateOnce, Run/Done, Status, the default DownloadFunc) |
| Create | `internal/geoipupdate/updater_test.go` |
| Create | `internal/storage/geoip_update_config.go` (GeoIPUpdateConfig + CRUD) |
| Create | `internal/storage/geoip_update_config_test.go` |
| Modify | `internal/storage/storage.go` (bucket `geoip_update`) |
| Create | `internal/api/geoip_update.go` (4 handlers + interface seam) |
| Create | `internal/api/geoip_update_test.go` |
| Modify | `internal/api/routes.go` (4 admin-gated routes) |
| Modify | `internal/api/handler.go` (SetGeoIPUpdater + SetGeoIPConfigHook) |
| Modify | `cmd/arenet/main.go` (build updater, wire hook, boot loop + bootstrap) |
| Modify | `web/frontend/src/lib/api/settings.ts` + `types.ts` (client + types) |

## Global constraints (from CLAUDE.md)

- Base branch = Brick 1 (+ Brick 2) — `Reload` and `GetMaxMindConfig` must
  be present. Set up the branch accordingly.
- `gofmt -s`/`vet`/`staticcheck` clean; `ctx` first arg; `%w`; `slog`
  (NEVER log the license key); no panic; AGPL header on new files.
- Structural template: `internal/alerting/watcher.go` (Config/Run/Done);
  config/hook/manual-endpoint template: `internal/updatecheck` + the
  `startUpdateLoop` wiring.
- The updater's `*http.Client` timeout must accommodate a full DB download
  (~minutes), separate from the 10s test-connection client.
