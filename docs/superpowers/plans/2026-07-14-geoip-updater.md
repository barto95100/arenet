# GeoIP Updater (Brick 3) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A GeoIP database auto-updater that reads MaxMind creds, downloads the DB (only if changed), writes it atomically, and hot-reloads it — so geoblock / enrichment / world-map / server-position use the new DB with no restart. Opt-in weekly scheduler + manual endpoint + boot bootstrap. An edition guard rejects any non-City database.

**Architecture:** A DI'd `internal/geoipupdate.Updater` (watcher-style `Run`/`Done`) whose `UpdateOnce` does read-creds → md5-of-disk → `client.Download` → temp-write → **City-edition guard** → atomic rename → `geo.Lookup.Reload`. A separate `GeoIPUpdateConfig` storage record drives an opt-in loop with a PUT-hook restart (mirroring the update-checker). Admin API: config GET/PUT, manual update POST (shares `UpdateOnce`), status GET.

**Tech Stack:** Go 1.25, BoltDB, `github.com/maxmind/geoipupdate/v8/client` (already a dep from Brick 2), `github.com/oschwald/geoip2-golang` (edition-type check).

**Spec:** `docs/superpowers/specs/2026-07-14-geoip-updater-design.md`

## Global Constraints

- Base branch already combines Brick 1 (`geo.Lookup.Reload`, `atomic.Pointer` reader) + Brick 2 (`storage.MaxMindConfig` + `GetMaxMindConfig`, the `geoipupdate/v8/client` dep).
- **Single edition, singular API.** We use the client's `Download(ctx, editionID, md5)` — ONE edition per call (NOT the CLI's plural `EditionIDs`). Arenet needs only `GeoLite2-City`; `cfg.EditionID` (default "GeoLite2-City") is passed through. The edition guard (Task 2) is what protects against a mis-set Country/ASN edition.
- `gofmt -s`/`vet`/`staticcheck` clean; `ctx` first arg; `%w`; `slog` (NEVER log the license key); no panic; AGPL header on new files.
- Structural templates: `cmd/arenet/main.go:1504-1552` (`startUpdateLoop` + hook + boot kickoff), `resolveUpdateInterval` (`main.go:2048`), `internal/alerting/watcher.go` (Config/Run/Done), `internal/storage/update_check_config.go` (single-row config), `internal/api/version.go` (manual endpoint reuses the poll fn).
- Backend: `go build ./...`, `go test ./internal/geoipupdate/ ./internal/storage/ ./internal/api/`. Frontend: `cd web/frontend && npm run check`.

---

### Task 1: The downloader core (`internal/geoipupdate.Updater` + `UpdateOnce`, no scheduler yet)

**Files:**
- Create: `internal/geoipupdate/updater.go`
- Create: `internal/geoipupdate/updater_test.go`

**Interfaces:**
- Produces (consumed by Tasks 3-5):
  - `type CredStore interface { GetMaxMindConfig(ctx context.Context) (storage.MaxMindConfig, error) }`
  - `type DownloadFunc func(ctx context.Context, accountID int, licenseKey, editionID, currentMD5 string) (client.DownloadResponse, error)`
  - `type Config struct { Store CredStore; Lookup *geo.Lookup; MMDBPath string; HTTPClient *http.Client; Download DownloadFunc; Logger *slog.Logger }`
  - `func New(cfg Config) (*Updater, error)` (validate required deps, default Download to the real client, default Logger)
  - `func (u *Updater) UpdateOnce(ctx context.Context) UpdateResult`
  - `func (u *Updater) Status() UpdateStatus` (thread-safe snapshot)
  - `type UpdateResult struct { Status string; Error string; LastModified time.Time; At time.Time }` with status consts `StatusUpdated="updated"`, `StatusUpToDate="up_to_date"`, `StatusNoCreds="no_credentials"`, `StatusError="error"`.

- [ ] **Step 1: Write the failing tests (seam + store mocked — NO real MaxMind)**

`internal/geoipupdate/updater_test.go`. Build an `Updater` with a fake `CredStore` and a fake `DownloadFunc` returning a canned `client.DownloadResponse` (in-memory `io.NopCloser(bytes.NewReader(...))` Reader). Use `t.TempDir()` for `MMDBPath`.

```go
func newTestUpdater(t *testing.T, store CredStore, dl DownloadFunc, mmdbPath string) *Updater {
	t.Helper()
	u, err := New(Config{Store: store, Lookup: &geo.Lookup{}, MMDBPath: mmdbPath, Download: dl, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil { t.Fatalf("New: %v", err) }
	return u
}

func TestUpdateOnce_NoCredentials(t *testing.T) {
	store := fakeStore{err: storage.ErrNotFound}
	u := newTestUpdater(t, store, failDownload(t), filepath.Join(t.TempDir(), "db.mmdb"))
	r := u.UpdateOnce(context.Background())
	if r.Status != StatusNoCreds { t.Fatalf("status=%q want no_credentials", r.Status) }
}

func TestUpdateOnce_UpToDate_NoWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.mmdb")
	// down returns UpdateAvailable:false
	dl := func(_ context.Context, _ int, _, _, _ string) (client.DownloadResponse, error) {
		return client.DownloadResponse{UpdateAvailable: false, Reader: io.NopCloser(bytes.NewReader(nil))}, nil
	}
	u := newTestUpdater(t, okStore(), dl, path)
	r := u.UpdateOnce(context.Background())
	if r.Status != StatusUpToDate { t.Fatalf("status=%q want up_to_date", r.Status) }
	if _, err := os.Stat(path); !os.IsNotExist(err) { t.Fatalf("up_to_date must not write a file") }
}

func TestUpdateOnce_DownloadError_PreservesExisting(t *testing.T) {
	dir := t.TempDir(); path := filepath.Join(dir, "db.mmdb")
	os.WriteFile(path, []byte("OLD-DB"), 0o644)
	dl := func(_ context.Context, _ int, _, _, _ string) (client.DownloadResponse, error) {
		return client.DownloadResponse{}, errors.New("network boom")
	}
	u := newTestUpdater(t, okStore(), dl, path)
	r := u.UpdateOnce(context.Background())
	if r.Status != StatusError { t.Fatalf("status=%q want error", r.Status) }
	b, _ := os.ReadFile(path)
	if string(b) != "OLD-DB" { t.Fatalf("existing DB was clobbered: %q", b) }
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) { t.Fatalf(".tmp left behind") }
}

func TestUpdateOnce_Bootstrap_PassesEmptyMD5(t *testing.T) {
	dir := t.TempDir(); path := filepath.Join(dir, "db.mmdb") // absent
	var gotMD5 string
	dl := func(_ context.Context, _ int, _, _, md5 string) (client.DownloadResponse, error) {
		gotMD5 = md5
		return client.DownloadResponse{UpdateAvailable: false, Reader: io.NopCloser(bytes.NewReader(nil))}, nil
	}
	u := newTestUpdater(t, okStore(), dl, path)
	u.UpdateOnce(context.Background())
	if gotMD5 != "" { t.Fatalf("bootstrap md5=%q want empty", gotMD5) }
}
```

(Provide the small `fakeStore`, `okStore()`, `failDownload(t)` helpers in the test file. `okStore()` returns `storage.MaxMindConfig{AccountID:1, LicenseKey:"k", EditionID:"GeoLite2-City"}`.)

The **"updated" happy-path test** (writes file, calls Reload) and the **edition-guard test** are added in Task 2 (they need the guard + a way to assert Reload). This task covers no-creds / up-to-date / download-error-atomicity / bootstrap-md5.

- [ ] **Step 2: Run → RED**

Run: `go test ./internal/geoipupdate/ -v`
Expected: compile error (package/types undefined).

- [ ] **Step 3: Implement `updater.go` (UpdateOnce WITHOUT the edition guard yet — guard is Task 2)**

Full implementation of `New`, `UpdateOnce` (steps 1-5 from the spec MINUS the edition guard — leave a clearly-marked `// EDITION GUARD (Task 2)` insertion point right after the temp file is fully written and before `os.Rename`), `Status`, the default `DownloadFunc` (`client.New(accountID, licenseKey, client.WithHTTPClient(u.httpClient)).Download(ctx, editionID, md5)`), and the `md5OfFile(path) (string, error)` helper (returns "" if not-exist). Mutex-guarded `status` field updated at the end of `UpdateOnce`. NEVER log `LicenseKey`.

- [ ] **Step 4: Run → GREEN**

Run: `go test ./internal/geoipupdate/ -v` → the 4 tests PASS. Then `go test ./internal/geoipupdate/` → PASS.

- [ ] **Step 5: gofmt + vet + commit**

```bash
gofmt -s -w internal/geoipupdate/updater.go internal/geoipupdate/updater_test.go
go vet ./internal/geoipupdate/
git add internal/geoipupdate/
git commit -m "feat(geoipupdate): downloader core UpdateOnce (no scheduler, no guard yet)

Reads MaxMind creds, computes the on-disk MMDB md5 (empty=bootstrap),
downloads via the geoipupdate/v8 client seam only if changed, and installs
atomically (temp write + rename) then Reloads the shared *geo.Lookup. A
failed download leaves the existing DB untouched and no .tmp behind. Edition
guard + the updated/Reload happy-path land in the next task."
```

---

### Task 2: The City-edition guard (+ the "updated" happy path)

**Files:**
- Modify: `internal/geoipupdate/updater.go` (insert the guard)
- Modify: `internal/geoipupdate/updater_test.go`

**Interfaces:** unchanged (the guard is internal to `UpdateOnce`).

- [ ] **Step 1: Write the failing tests**

Add to `updater_test.go`:
- **Updated happy path:** a `DownloadFunc` returns `UpdateAvailable:true` + a Reader containing the bytes of a **real minimal City MMDB fixture** (see fixture note). Assert: after `UpdateOnce`, `MMDBPath` exists with those bytes, no `.tmp`, `Status==StatusUpdated`, and the injected `*geo.Lookup` now serves from the new file (assert `Lookup.Path()==MMDBPath` after, or a successful `LookupIP` on a known IP if the fixture has data).
- **Edition guard rejects a non-City DB:** a `DownloadFunc` returns a Reader containing a **Country-type** MMDB fixture (or a byte blob the guard will reject). Assert: `Status==StatusError`, error mentions "not a City database", `MMDBPath` is NOT created/changed, no `.tmp`, and the `*geo.Lookup` reader is unchanged (Reload NOT called).

**Fixture note:** building a valid MMDB by hand is impractical. Options, in order of preference: (1) check whether the vendored `oschwald/maxminddb-golang` test-data ships tiny `GeoLite2-City-Test.mmdb` / `GeoLite2-Country-Test.mmdb` files that can be copied into `internal/geoipupdate/testdata/`; (2) if not available, gate these two tests behind a fixture-present check (`testdata/city.mmdb`, `testdata/country.mmdb`) with `t.Skip` when absent, AND add a focused unit test of the guard's type-check logic (`isCityDB(reader) bool`) that can be exercised by opening whatever real MMDB is present at `ARENET_TEST_MMDB`. Document which path was taken. The guard's real end-to-end proof is the Task-6 runtime verification with a real download.

- [ ] **Step 2: Run → RED**

Run: `go test ./internal/geoipupdate/ -run 'Updated|EditionGuard' -v`
Expected: FAIL (the guard doesn't exist; the happy path may write a non-validated file).

- [ ] **Step 3: Implement the guard**

At the `// EDITION GUARD (Task 2)` insertion point (temp file written, before `os.Rename`):
```go
// Edition guard: Arenet's reader calls reader.City(), which requires a
// City-type MMDB. A Country/ASN DB would silently fail-open (every
// LookupIP -> Found:false), disabling geoblock + blanking the world map.
// Verify the freshly-downloaded file is a City database before installing.
if err := verifyCityMMDB(tmpPath); err != nil {
	// defer already removes tmpPath; do NOT rename/Reload.
	return u.fail(fmt.Sprintf("downloaded edition %q is not a City database: %v", editionID, err))
}
```
And the helper:
```go
// verifyCityMMDB opens the MMDB and confirms it is a City-type database
// (the type Arenet's reader.City() requires). Returns an error for
// Country/ASN/other editions.
func verifyCityMMDB(path string) error {
	r, err := geoip2.Open(path)
	if err != nil {
		return fmt.Errorf("open downloaded mmdb: %w", err)
	}
	defer r.Close()
	dbType := r.Metadata().DatabaseType // e.g. "GeoLite2-City", "GeoLite2-Country"
	if !strings.Contains(dbType, "City") {
		return fmt.Errorf("database type %q is not a City edition", dbType)
	}
	return nil
}
```
(`u.fail(msg)` sets `status` + returns `UpdateResult{Status:StatusError, Error:msg, At: now}`. Confirm `Metadata().DatabaseType` is the right field name against the vendored geoip2 — the reader exposes `Metadata()` with a `DatabaseType string`; the strings.Contains "City" check matches "GeoLite2-City" and "GeoIP2-City" but not "GeoLite2-Country"/"GeoLite2-ASN".)

- [ ] **Step 4: Run → GREEN + package + -race on UpdateOnce**

Run: `go test ./internal/geoipupdate/ -v` → all PASS (or the two fixture tests skip cleanly with the guard-logic unit passing). Then `go test -race ./internal/geoipupdate/`.

- [ ] **Step 5: gofmt + vet + commit**

```bash
gofmt -s -w internal/geoipupdate/updater.go internal/geoipupdate/updater_test.go
go vet ./internal/geoipupdate/
git add internal/geoipupdate/
git commit -m "feat(geoipupdate): City-edition guard + updated happy path

reader.City() requires a City-type MMDB; a Country/ASN DB silently
fails-open (LookupIP -> Found:false), disabling geoblock and blanking the
world map. After writing the temp file, verify via
geoip2.Metadata().DatabaseType that it's a City edition; reject (no rename,
no Reload, existing DB intact) otherwise. Adds the updated/Reload happy
path with an atomic install."
```

---

### Task 3: `GeoIPUpdateConfig` storage

**Files:**
- Create: `internal/storage/geoip_update_config.go`
- Create: `internal/storage/geoip_update_config_test.go`
- Modify: `internal/storage/storage.go` (bucket `geoip_update`)

**Interfaces:**
- Produces: `GeoIPUpdateConfig{Enabled bool json:"enabled"; IntervalOverride string json:"intervalOverride"}`; `GetGeoIPUpdateConfig(ctx) (GeoIPUpdateConfig, error)` (zero-value on fresh, nil err); `PutGeoIPUpdateConfig(ctx, cfg) error`.

- [ ] **Step 1: Write failing tests** (mirror `update_check_config_test.go`): Get-fresh → `{Enabled:false}`, nil err; Put→Get round-trip; toggle enabled + set interval.

- [ ] **Step 2: RED** — `go test ./internal/storage/ -run 'GeoIPUpdateConfig' -v` → compile error.

- [ ] **Step 3: Implement** — mirror `update_check_config.go` exactly (bucket `bucketGeoIPUpdate = "geoip_update"` in storage.go + registration; key `"config"`; Get returns zero-value on missing key with nil error; Put upsert). AGPL header.

- [ ] **Step 4: GREEN** — `-run 'GeoIPUpdateConfig'` passes, then `go test ./internal/storage/`.

- [ ] **Step 5: gofmt + vet + commit**

```bash
gofmt -s -w internal/storage/geoip_update_config.go internal/storage/geoip_update_config_test.go internal/storage/storage.go
go vet ./internal/storage/
git add internal/storage/geoip_update_config.go internal/storage/geoip_update_config_test.go internal/storage/storage.go
git commit -m "feat(storage): GeoIPUpdateConfig single-record (enabled + interval)

Separate opt-in scheduler config for GeoIP auto-update, mirroring
UpdateCheckConfig. Own bucket, disabled on fresh install. Kept separate
from MaxMindConfig so the scheduler toggles independently of the secret."
```

---

### Task 4: Scheduler loop + main.go wiring + bootstrap

**Files:**
- Modify: `internal/geoipupdate/updater.go` (add `Run(ctx)` / `Done()`)
- Modify: `internal/geoipupdate/updater_test.go` (loop test)
- Modify: `cmd/arenet/main.go` (build updater, hook, boot loop, bootstrap, resolveGeoIPInterval)

**Interfaces:**
- Produces: `func (u *Updater) Run(ctx context.Context, interval time.Duration)` (ticker loop, warmup, ctx-cancel, immediate-ish first run after warmup, resilient), `func (u *Updater) Done() <-chan struct{}`. main.go `startGeoIPLoop(cfg storage.GeoIPUpdateConfig)` + `resolveGeoIPInterval(override, logger)`.

- [ ] **Step 1: Write the loop test** — with a fast interval + a counting fake `DownloadFunc`, assert `Run` invokes `UpdateOnce` repeatedly and stops on ctx cancel (mirror how the watcher loop is tested; use a tiny warmup for the test or make warmup a Config field defaulting to 30s so the test can set it to 0).

- [ ] **Step 2: RED** — `go test ./internal/geoipupdate/ -run 'Run|Loop' -v`.

- [ ] **Step 3: Implement `Run`/`Done`** (watcher-style: `defer close(u.done)`, warmup `select` on ctx / `time.After(warmup)`, one `UpdateOnce`, then `time.NewTicker(interval)` loop, ctx-cancel exits). Then wire `main.go`:
  - `resolveGeoIPInterval(override, logger)` — mirror `resolveUpdateInterval` but default **168h**, 1h floor, env `ARENET_GEOIP_UPDATE_INTERVAL`.
  - Build the updater: `geoipupdate.New(geoipupdate.Config{Store: store, Lookup: geoLookup, MMDBPath: geoMMDBPath, HTTPClient: &http.Client{Timeout: 5*time.Minute}, Logger: logger})`.
  - `startGeoIPLoop(cfg)` mirroring `startUpdateLoop` (cancel-then-restart under a mutex, `!cfg.Enabled` → stop + log, else `Run` with the resolved interval in a cancelable ctx).
  - `apiHandler.SetGeoIPConfigHook(startGeoIPLoop)` (added in Task 5's handler wiring — sequence so this compiles; if Task 5 isn't merged yet, add the setter here as part of the handler surface).
  - Boot kickoff: `GetGeoIPUpdateConfig` → `startGeoIPLoop(cfg)`.
  - **Bootstrap:** after kickoff, if `cfg.Enabled` AND `MaxMindConfigEverConfigured` AND the `geoMMDBPath` file is absent → the loop's warmup+first-run already covers it (enabled path runs `UpdateOnce` after warmup). So the bootstrap is implicit in the enabled loop; no separate call needed. (Document this: bootstrap == the enabled loop's first run; nothing extra to wire.)

- [ ] **Step 4: GREEN + build + -race** — `go test ./internal/geoipupdate/`, `go build ./...`, `go test -race ./internal/geoipupdate/`.

- [ ] **Step 5: gofmt + vet + commit**

```bash
gofmt -s -w internal/geoipupdate/updater.go internal/geoipupdate/updater_test.go cmd/arenet/main.go
go vet ./internal/geoipupdate/ ./cmd/arenet/
git add internal/geoipupdate/ cmd/arenet/main.go
git commit -m "feat(geoipupdate,main): opt-in weekly scheduler + boot wiring + bootstrap

Updater.Run/Done watcher-style loop (warmup, resilient, ctx-cancel).
main.go builds the updater (5min HTTP timeout for a full DB download),
resolves the interval (168h default / env / floor), and wires
startGeoIPLoop with a cancel-then-restart PUT hook. Bootstrap is implicit:
an enabled loop's first run downloads when creds exist and no DB is on disk."
```

---

### Task 5: API endpoints + handler wiring + frontend client

**Files:**
- Create: `internal/api/geoip_update.go` (4 handlers + the updater/hook interface seams)
- Create: `internal/api/geoip_update_test.go`
- Modify: `internal/api/routes.go` (4 admin routes)
- Modify: `internal/api/handler.go` (`SetGeoIPUpdater` + `SetGeoIPConfigHook` + the interface fields)
- Modify: `web/frontend/src/lib/api/settings.ts` + `types.ts`

**Interfaces:**
- Consumes: the updater (`UpdateOnce`, `Status`) via a small interface; `Get/PutGeoIPUpdateConfig`.
- Produces: `GET/PUT /system/geoip/update-config`, `POST /system/geoip/update`, `GET /system/geoip/status`.

- [ ] **Step 1: Write failing API tests** (mirror `version_test.go`/the update-checker handler tests): GET config (fresh → `{enabled:false}`); PUT config persists + fires the hook (assert a fake hook was called); POST update calls a fake updater's `UpdateOnce` and returns its result; GET status returns the snapshot; admin-gating (viewer → 403 on all).

- [ ] **Step 2: RED** — `go test ./internal/api/ -run 'GeoIP' -v` → compile error.

- [ ] **Step 3: Implement handlers + wiring**:
  - `handler.go`: add `geoIPUpdater` (interface `{ UpdateOnce(ctx) geoipupdate.UpdateResult; Status() geoipupdate.UpdateStatus }`) + `onGeoIPConfigChange func(storage.GeoIPUpdateConfig)`, with `SetGeoIPUpdater` / `SetGeoIPConfigHook` setters (mirror `SetUpdateChecker`/`SetUpdateConfigHook`).
  - `geoip_update.go`: the 4 handlers. `getGeoIPUpdateConfig` → `{enabled, intervalHours}` (resolve interval to hours for display). `putGeoIPUpdateConfig` → decode, persist, fire hook, 200. `postGeoIPUpdate` → 409 if updater nil, else `res := updater.UpdateOnce(ctx)`, return `{status, error?, lastModified?}`, always 200. `getGeoIPStatus` → the `Status()` snapshot.
  - `routes.go`: 4 admin-gated routes near `/system/version/*`.
  - main.go: `apiHandler.SetGeoIPUpdater(updater)` (Task 4 already added `SetGeoIPConfigHook`).

- [ ] **Step 4: GREEN + package** — `-run 'GeoIP'` passes, then `go test ./internal/api/`.

- [ ] **Step 5: Frontend client + types** — `types.ts`: `GeoIPUpdateConfig{enabled:boolean; intervalHours:number}`, `GeoIPUpdateResult{status:string; error?:string; lastModified?:string}`, `GeoIPStatus{lastStatus:string; lastError?:string; lastUpdated?:string}`. `settings.ts`: `getGeoIPUpdateConfig`/`putGeoIPUpdateConfig`/`triggerGeoIPUpdate`/`getGeoIPStatus` (match the neighboring `request(...)` signature). `npm run check` → 0 errors.

- [ ] **Step 6: gofmt + vet + typecheck + commit**

```bash
gofmt -s -w internal/api/geoip_update.go internal/api/geoip_update_test.go internal/api/routes.go internal/api/handler.go cmd/arenet/main.go
go vet ./internal/api/
(cd web/frontend && npm run check)
git add internal/api/ cmd/arenet/main.go web/frontend/src/lib/api/settings.ts web/frontend/src/lib/api/types.ts
git commit -m "feat(api,web): GeoIP update config/trigger/status endpoints + client

Admin-gated GET/PUT /system/geoip/update-config (opt-in + interval, PUT
fires the scheduler restart hook), POST /system/geoip/update (manual,
shares UpdateOnce), GET /system/geoip/status. Frontend API client + types.
The settings UI panel is brick 4."
```

---

### Task 6: Runtime verification

**Files:** none (observation only).

- [ ] **Step 1: Build** — `go build ./... && cd web/frontend && npm run build && cd ../.. && go build -o arenet ./cmd/arenet`.

- [ ] **Step 2: In-workspace surface checks** — run the binary; confirm the 4 `/system/geoip/*` routes are mounted + admin-gated (401 not 404); boot log clean (no geoip updater error).

- [ ] **Step 3: Operator hand-off (real MaxMind creds + real DB)** — per the spec's Runtime verification: (1) configure creds + enable + `POST /system/geoip/update` → `.mmdb` appears/updates, `GET /status` = `updated`, and a country-block rule reflects the new DB **without restart**; (2) **edition guard:** set `EditionID=GeoLite2-Country` → update REJECTED, old DB intact, geoblock still works; set back to `GeoLite2-City` → succeeds.

- [ ] **Step 4: Report PASS/FAIL** (in-workspace parts) + hand the operator the real-creds checklist.

---

## Self-Review

**Spec coverage:** downloader UpdateOnce (creds/md5/download/atomic) → Task 1. Edition guard → Task 2. Config storage → Task 3. Scheduler loop + wiring + bootstrap → Task 4. API + frontend → Task 5. Runtime → Task 6. The single-edition/singular-Download clarification is in Global Constraints. End-to-end reload-uses-new-DB is the spec's verified premise + Task 6 operator check. All spec sections covered.

**Placeholder scan:** No TBD/TODO. The one genuinely open item — MMDB test fixtures for the guard/happy-path — is handled with an explicit preference order + a skip-with-unit-fallback, not a placeholder. Every code step shows the code.

**Type consistency:** `DownloadFunc(ctx, int, string, string, string) (client.DownloadResponse, error)` identical in Config, default impl, and tests. `UpdateResult`/`UpdateStatus` + status consts shared across updater (Tasks 1-2), loop (Task 4), API (Task 5). `GeoIPUpdateConfig{Enabled, IntervalOverride}` identical across storage (Task 3), main.go loop (Task 4), API (Task 5). Routes registered once each. `verifyCityMMDB` checks `geoip2.Metadata().DatabaseType` (confirmed field). The interval default is 168h (Task 4) vs the update-checker's 24h — intentionally different, noted.
