# GeoIP MaxMind Credentials (Brick 2) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store MaxMind credentials (account_id + license_key) with a redacting CRUD API, a real test-connection endpoint, backup participation, and the frontend client/types — mirroring the CrowdSec config pattern.

**Architecture:** Single-record BoltDB config keyed `"default"` (like CrowdSec/OIDC). Secret redacted on GET via a `configured` flag; preserve-on-blank-update; admin-gated routes. Test-connection uses `github.com/maxmind/geoipupdate/v8/client` behind a substitutable seam (reused by Brick 3). license_key participates in the backup sentinel mechanism.

**Tech Stack:** Go 1.25, BoltDB, `geoipupdate/v8/client` (Apache/MIT), SvelteKit (client + types only in this brick).

**Spec:** `docs/superpowers/specs/2026-07-13-geoip-maxmind-credentials-design.md`

## Global Constraints

- Mirror the CrowdSec templates: storage `internal/storage/crowdsec_config.go`, API `internal/api/crowdsec_settings.go`, routes `routes.go:446-449`.
- `gofmt -s`/`go vet`/`staticcheck` clean; `ctx` first arg; `%w` wrapping; `slog`; no panic; AGPL header on new files.
- Secret never echoed on GET; audit scrubs it; preserve-on-blank-update.
- `EditionID` defaults to `"GeoLite2-City"`.
- Backend: `go build ./...`, `go test ./internal/storage/ ./internal/api/ ./internal/backup/`. Frontend: `cd web/frontend && npm run check`.

---

### Task 1: Dependency + storage (`MaxMindConfig` CRUD)

**Files:**
- Modify: `go.mod` / `go.sum` (add `geoipupdate/v8`)
- Create: `internal/storage/maxmind_config.go`
- Create: `internal/storage/maxmind_config_test.go`
- Modify: `internal/storage/storage.go` (bucket constant + registration)

**Interfaces:**
- Produces (consumed by Tasks 2-4): `storage.MaxMindConfig{AccountID int, LicenseKey string, EditionID string, CreatedAt, UpdatedAt time.Time}`; `Store.GetMaxMindConfig(ctx) (MaxMindConfig, error)`, `PutMaxMindConfig(ctx, MaxMindConfig) error`, `DeleteMaxMindConfig(ctx) error`, `MaxMindConfigEverConfigured(ctx) (bool, error)`.

- [ ] **Step 1: Add the dependency**

Run: `go get github.com/maxmind/geoipupdate/v8/client && go mod tidy`
Expected: `go.mod` gains `github.com/maxmind/geoipupdate/v8`; `go build ./...` still works (no code uses it yet — that's fine, `go mod tidy` keeps it because Task 3 will; if tidy drops it, add a blank import temporarily OR sequence the dep with Task 3 — but adding it here is intended). If `go mod tidy` removes it for lack of use, defer the `go get` to Task 3 Step 1 and note it here as done-in-task-3.

- [ ] **Step 2: Write the failing storage tests**

`internal/storage/maxmind_config_test.go` (mirror `crowdsec_config_test.go` setup — `newStoreForTest(t)` or the equivalent helper in that file):

```go
func TestMaxMindConfig_GetFresh_ReturnsNotFound(t *testing.T) {
	s := newStoreForTest(t)
	_, err := s.GetMaxMindConfig(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("fresh GetMaxMindConfig err = %v; want ErrNotFound", err)
	}
}

func TestMaxMindConfig_PutGet_RoundTrip(t *testing.T) {
	s := newStoreForTest(t)
	in := MaxMindConfig{AccountID: 12345, LicenseKey: "secretkey", EditionID: "GeoLite2-City"}
	if err := s.PutMaxMindConfig(context.Background(), in); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.GetMaxMindConfig(context.Background())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AccountID != 12345 || got.LicenseKey != "secretkey" || got.EditionID != "GeoLite2-City" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("timestamps not set: %+v", got)
	}
}

func TestMaxMindConfig_PutBlankKey_PreservesStored(t *testing.T) {
	s := newStoreForTest(t)
	_ = s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 1, LicenseKey: "orig", EditionID: "GeoLite2-City"})
	// update with blank key → inherit "orig"
	if err := s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 2, LicenseKey: ""}); err != nil {
		t.Fatalf("put update: %v", err)
	}
	got, _ := s.GetMaxMindConfig(context.Background())
	if got.LicenseKey != "orig" {
		t.Errorf("blank-key update dropped secret: %q; want 'orig'", got.LicenseKey)
	}
	if got.AccountID != 2 {
		t.Errorf("account id not updated: %d; want 2", got.AccountID)
	}
}

func TestMaxMindConfig_DefaultEdition(t *testing.T) {
	s := newStoreForTest(t)
	_ = s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 1, LicenseKey: "k"}) // no edition
	got, _ := s.GetMaxMindConfig(context.Background())
	if got.EditionID != "GeoLite2-City" {
		t.Errorf("default edition = %q; want GeoLite2-City", got.EditionID)
	}
}

func TestMaxMindConfig_RejectEmptyAfterMerge(t *testing.T) {
	s := newStoreForTest(t)
	// no prior config; blank key can't inherit → reject
	err := s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 1, LicenseKey: ""})
	if err == nil {
		t.Fatal("put with no key and nothing to inherit = nil; want error")
	}
	// account id <= 0 → reject
	if err := s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 0, LicenseKey: "k"}); err == nil {
		t.Fatal("put with AccountID<=0 = nil; want error")
	}
}

func TestMaxMindConfig_Delete(t *testing.T) {
	s := newStoreForTest(t)
	_ = s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 1, LicenseKey: "k"})
	if err := s.DeleteMaxMindConfig(context.Background()); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err := s.GetMaxMindConfig(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete Get err = %v; want ErrNotFound", err)
	}
}

func TestMaxMindConfig_EverConfigured(t *testing.T) {
	s := newStoreForTest(t)
	ever, _ := s.MaxMindConfigEverConfigured(context.Background())
	if ever {
		t.Fatal("fresh EverConfigured = true; want false")
	}
	_ = s.PutMaxMindConfig(context.Background(), MaxMindConfig{AccountID: 1, LicenseKey: "k"})
	ever, _ = s.MaxMindConfigEverConfigured(context.Background())
	if !ever {
		t.Fatal("after put EverConfigured = false; want true")
	}
}
```

Use the exact test-store helper name from `crowdsec_config_test.go` (likely `newStoreForTest`); substitute if different.

- [ ] **Step 3: Run tests → RED**

Run: `go test ./internal/storage/ -run 'MaxMindConfig' -v`
Expected: compile error (types/methods undefined).

- [ ] **Step 4: Implement storage**

`internal/storage/storage.go`: add `bucketMaxMindConfig = "maxmind_config"` near `bucketCrowdSecConfig` (~`:70`), and add it to the bucket-creation list (~`:147`).

`internal/storage/maxmind_config.go` (mirror `crowdsec_config.go` structure — `withTimeout`, bbolt Get/Update, `ErrNotFound`, `%w`):
- `const maxMindConfigKey = "default"`.
- `const defaultMaxMindEdition = "GeoLite2-City"`.
- The `MaxMindConfig` struct (from the spec, with doc comments + AGPL header).
- `GetMaxMindConfig`: read key, `ErrNotFound` if nil, unmarshal.
- `PutMaxMindConfig`: within a bbolt Update — read existing; **preserve**: `if c.LicenseKey == "" { c.LicenseKey = existing.LicenseKey }`; default `if c.EditionID == "" { c.EditionID = defaultMaxMindEdition }`; **validate after merge**: `if c.AccountID <= 0 { return error }`, `if c.LicenseKey == "" { return error }`; preserve `CreatedAt` (from existing if present, else now); set `UpdatedAt = now`; marshal + Put.
- `DeleteMaxMindConfig`: delete the key (no error if absent, mirror CrowdSec Delete).
- `MaxMindConfigEverConfigured`: true if the key exists.

- [ ] **Step 5: Run tests → GREEN + package**

Run: `go test ./internal/storage/ -run 'MaxMindConfig' -v` → PASS. Then `go test ./internal/storage/` → PASS (no regression).

- [ ] **Step 6: gofmt + vet + commit**

```bash
gofmt -s -w internal/storage/maxmind_config.go internal/storage/maxmind_config_test.go internal/storage/storage.go
go vet ./internal/storage/
git add go.mod go.sum internal/storage/maxmind_config.go internal/storage/maxmind_config_test.go internal/storage/storage.go
git commit -m "feat(storage): MaxMindConfig single-record CRUD (brick 2)

MaxMind GeoIP credentials (account_id + license_key + edition_id) stored
as a single record keyed 'default', mirroring CrowdSecConfig. Preserve-
secret-on-blank-update, default edition GeoLite2-City, validate account_id>0
and non-empty key after merge. Adds geoipupdate/v8 dependency (used by the
test-connection in a later task)."
```

---

### Task 2: API CRUD + redaction (GET / PUT / DELETE)

**Files:**
- Create: `internal/api/maxmind_settings.go`
- Create: `internal/api/maxmind_settings_test.go`
- Modify: `internal/api/routes.go` (3 routes now; the /test route in Task 3)

**Interfaces:**
- Consumes: the storage CRUD from Task 1.
- Produces: `GET/PUT/DELETE /api/v1/settings/maxmind`; wire types `maxMindRequest` / `maxMindResponse`; helpers `maxMindResponseFor`, `maxMindConfigForAudit`.

- [ ] **Step 1: Write the failing API tests**

`internal/api/maxmind_settings_test.go` (mirror the CrowdSec settings test harness — the test env/handler builder in that file):
1. **GET redacts:** put a config with a key via the store, GET → 200, body has `configured:true`, `accountId`, `editionId`, and **no** `licenseKey` field (assert the raw JSON does not contain the secret string).
2. **GET fresh:** no config → 200 with `configured:false` (not 404), matching CrowdSec's GET-fresh behavior (verify what CrowdSec's GET does on ErrNotFound and mirror it exactly).
3. **PUT blank key preserves:** PUT `{accountId:2, licenseKey:""}` after a stored key → the stored key is preserved (GET still `configured:true`; re-read store shows old key).
4. **PUT sets key:** PUT `{accountId:1, licenseKey:"newkey"}` → stored.
5. **DELETE:** removes config → subsequent GET `configured:false`.
6. **Admin-gating:** a viewer session → 403 on PUT/DELETE (mirror the CrowdSec gating test).
7. **Audit scrub:** the audit BeforeJSON/AfterJSON for a PUT does not contain the license key (assert via the audit capture the CrowdSec test uses).

- [ ] **Step 2: Run tests → RED**

Run: `go test ./internal/api/ -run 'MaxMind' -v`
Expected: compile error (handlers/types undefined).

- [ ] **Step 3: Implement the handlers**

`internal/api/maxmind_settings.go` (mirror `crowdsec_settings.go`, AGPL header):
- `maxMindRequest{AccountID int `json:"accountId"`; LicenseKey string `json:"licenseKey"`; EditionID string `json:"editionId,omitempty"`}`.
- `maxMindResponse{AccountID int `json:"accountId"`; EditionID string `json:"editionId"`; Configured bool `json:"configured"`}` (no license key).
- `maxMindResponseFor(cfg storage.MaxMindConfig, everConfigured bool) maxMindResponse` — `Configured = cfg.AccountID > 0 && cfg.LicenseKey != ""`.
- `maxMindConfigForAudit(cfg storage.MaxMindConfig) storage.MaxMindConfig` — returns cfg with `LicenseKey = ""`.
- `getMaxMindSettings`: `GetMaxMindConfig`; on `ErrNotFound` return a zeroed `maxMindResponse{Configured:false}` with 200 (mirror CrowdSec GET-fresh).
- `putMaxMindSettings`: decode (DisallowUnknownFields); GetPrevious (tolerate ErrNotFound); preserve-merge the key (`if req.LicenseKey=="" { key = previous.LicenseKey }`); `PutMaxMindConfig(merged)`; re-fetch for audit AfterJSON + response (mirror the CrowdSec re-fetch at `crowdsec_settings.go:198`); audit `maxmind_config_updated` using `maxMindConfigForAudit`; 200 + redacted response.
- `deleteMaxMindSettings`: `DeleteMaxMindConfig`; audit `maxmind_config_deleted`; 200.

`internal/api/routes.go`: in the admin subgroup near CrowdSec (`:446`):
```go
r.Get("/settings/maxmind", h.getMaxMindSettings)
r.Put("/settings/maxmind", h.putMaxMindSettings)
r.Delete("/settings/maxmind", h.deleteMaxMindSettings)
```
(the `/test` POST route is added in Task 3.)

- [ ] **Step 4: Run tests → GREEN + package**

Run: `go test ./internal/api/ -run 'MaxMind' -v` → PASS. Then `go test ./internal/api/` → PASS.

- [ ] **Step 5: gofmt + vet + commit**

```bash
gofmt -s -w internal/api/maxmind_settings.go internal/api/maxmind_settings_test.go internal/api/routes.go
go vet ./internal/api/
git add internal/api/maxmind_settings.go internal/api/maxmind_settings_test.go internal/api/routes.go
git commit -m "feat(api): MaxMind credentials CRUD, secret-redacted (brick 2)

GET/PUT/DELETE /settings/maxmind, admin-gated, mirroring CrowdSec. GET
never echoes the license key (configured flag only); PUT preserves the
stored key on a blank field; audit scrubs the key. Test-connection route
added in the next task."
```

---

### Task 3: Test-connection (real MaxMind client behind a seam)

**Files:**
- Create: `internal/api/maxmind_test_connection.go`
- Modify: `internal/api/maxmind_settings_test.go` (test-connection cases with a stub seam)
- Modify: `internal/api/routes.go` (the `/test` route)

**Interfaces:**
- Consumes: storage CRUD (Task 1), `geoipupdate/v8/client`.
- Produces: `POST /api/v1/settings/maxmind/test` → `{reachable bool, error string}`; a substitutable download-seam (func var or small interface) that Brick 3 reuses.

- [ ] **Step 1: Write the failing test-connection tests (stubbed seam)**

Add to `internal/api/maxmind_settings_test.go`. The handler must call MaxMind behind a package-level func var (e.g. `maxMindProbe func(ctx, accountID int, licenseKey, editionID string) error`) so tests substitute it — NEVER hit the real API in unit tests.

```go
func TestMaxMindTest_ValidCreds_Reachable(t *testing.T) {
	// stub probe returns nil (auth ok)
	orig := maxMindProbe
	maxMindProbe = func(ctx context.Context, id int, key, edition string) error { return nil }
	defer func() { maxMindProbe = orig }()
	// ... build handler env, store a config, POST /test with UseStored ...
	// assert 200 + {reachable:true, error:""}
}

func TestMaxMindTest_BadCreds_NotReachable(t *testing.T) {
	orig := maxMindProbe
	maxMindProbe = func(ctx context.Context, id int, key, edition string) error {
		return errors.New("401 invalid credentials")
	}
	defer func() { maxMindProbe = orig }()
	// ... POST /test ... assert 200 + {reachable:false, error contains "401"}
}

func TestMaxMindTest_NoCreds_NotReachable(t *testing.T) {
	// no stored config, request carries no key → {reachable:false, error:"no credentials"}
}
```

- [ ] **Step 2: Run tests → RED**

Run: `go test ./internal/api/ -run 'MaxMindTest' -v`
Expected: compile error (handler + `maxMindProbe` undefined).

- [ ] **Step 3: Implement the test-connection**

`internal/api/maxmind_test_connection.go` (mirror `oidc_test_connection.go` — always 200 with a data body):
- Wire types: `maxMindTestRequest{AccountID int; LicenseKey string; EditionID string; UseStored bool}` and `maxMindTestResponse{Reachable bool `json:"reachable"`; Error string `json:"error,omitempty"`}`.
- **The seam** (package-level, so tests + Brick 3 substitute it):

```go
// maxMindProbe validates MaxMind credentials by attempting an
// authenticated request. It MUST NOT download the full database — it
// closes the response body unread; auth is proven by the response
// headers (a non-2xx yields an *client.HTTPError). Overridable in tests.
var maxMindProbe = func(ctx context.Context, accountID int, licenseKey, editionID string) error {
	c, err := client.New(accountID, licenseKey,
		client.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}))
	if err != nil {
		return err
	}
	// Non-empty dummy md5 so a "no update" answer returns without a body;
	// if an update IS available we still close the Reader unread — we only
	// care that auth succeeded.
	resp, err := c.Download(ctx, editionID, "00000000000000000000000000000000")
	if err != nil {
		return err
	}
	if resp.Reader != nil {
		_ = resp.Reader.Close() // do NOT io.ReadAll — must not pull ~60MB
	}
	return nil
}
```

  > Build-time verification (spec invariant): confirm this does not download
  > the full DB. If the vendored client requires consuming the body before
  > Close, adjust (empty md5 + immediate ctx-cancel, or the smallest edition)
  > — but the test MUST NOT transfer ~60MB. Keep the seam signature stable.

- `testMaxMindConnection` handler:
  - decode request; resolve effective creds (UseStored → stored; else wire fields falling back to stored per-field, mirror `testCrowdSecConnection:403-422`); default edition.
  - if `accountID <= 0 || licenseKey == ""` → 200 `{reachable:false, error:"no credentials"}`.
  - `ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second); defer cancel()`.
  - `err := maxMindProbe(ctx, accountID, licenseKey, editionID)`.
  - `err == nil` → `{reachable:true}`. Else classify: if `errors.As(err, &client.HTTPError{})` (or the exported type) → `{reachable:false, error: "credentials rejected: "+err.Error()}`; else → `{reachable:false, error:"could not reach MaxMind: "+err.Error()}`. Always 200.

`routes.go`: add `r.Post("/settings/maxmind/test", h.testMaxMindConnection)` after the DELETE route.

- [ ] **Step 4: Run tests → GREEN + package**

Run: `go test ./internal/api/ -run 'MaxMind' -v` → PASS (all CRUD + test cases). Then `go test ./internal/api/` → PASS.

- [ ] **Step 5: gofmt + vet + commit**

```bash
gofmt -s -w internal/api/maxmind_test_connection.go internal/api/maxmind_settings_test.go internal/api/routes.go
go vet ./internal/api/
git add internal/api/maxmind_test_connection.go internal/api/maxmind_settings_test.go internal/api/routes.go
git commit -m "feat(api): MaxMind test-connection via real client, no DB download (brick 2)

POST /settings/maxmind/test validates creds with a real
geoipupdate/v8/client Download call behind a substitutable seam
(maxMindProbe, reused by brick 3). Auth is proven on the response headers;
the body Reader is closed unread so a test never pulls the ~60MB database.
Always 200 with {reachable,error}; HTTPError → creds rejected, other → not
reachable. Unit-tested with a stubbed seam (no real API calls)."
```

---

### Task 4: Backup sentinel + frontend client/types

**Files:**
- Modify: `internal/backup/types.go` (Snapshot field)
- Modify: `internal/backup/sentinel.go` (redact license_key)
- Modify: `internal/backup/import.go` (resolve + readLive + identityKey)
- Modify: `internal/backup/<the sentinel round-trip test file>`
- Modify: `web/frontend/src/lib/api/settings.ts` (4 client methods)
- Modify: `web/frontend/src/lib/api/types.ts` (MaxMind TS types)

**Interfaces:**
- Consumes: storage `MaxMindConfig` (Task 1) + the API routes (Tasks 2-3).

- [ ] **Step 1: Write the failing backup test**

In the backup test file that covers OIDC/DNS sentinel round-trips, add a MaxMind case (mirror the OIDC sentinel test): a snapshot with a MaxMind config → redacted export replaces `license_key` with the sentinel → import against live state inherits the stored key. Assert the redacted export does NOT contain the plaintext key, and the resolved import restores it.

- [ ] **Step 2: Run → RED**

Run: `go test ./internal/backup/ -run 'MaxMind|Sentinel' -v`
Expected: FAIL/compile error (Snapshot has no MaxMind field / redaction absent).

- [ ] **Step 3: Wire the 4 backup sites**

Following the OIDC single-record pattern (spec §backup):
1. `internal/backup/types.go`: add the MaxMind config to `Snapshot` (match how OIDC is embedded — value + presence, or pointer).
2. `internal/backup/sentinel.go` `redactSnapshotInPlace`: replace `MaxMind.LicenseKey` with `SentinelLiteral` (heed the discipline comment at `sentinel.go:31-35`).
3. `internal/backup/import.go` `resolveSentinels`: add a `resolve(...)` block for MaxMind keyed `"default"` (mirror OIDC at `import.go:350-359`).
4. `internal/backup/import.go` `readLive`: capture live MaxMind state (exists? stored key) for inheritance; add the `identityKey` label in `sentinel.go:99`.

`account_id` / `edition_id` travel verbatim; only `license_key` is redacted.

- [ ] **Step 4: Run backup tests → GREEN + package**

Run: `go test ./internal/backup/ -run 'MaxMind|Sentinel' -v` → PASS. Then `go test ./internal/backup/` → PASS.

- [ ] **Step 5: Frontend client + types**

`web/frontend/src/lib/api/types.ts` (mirror the CrowdSec/OIDC types):
```ts
export interface MaxMindConfig { accountId: number; editionId: string; configured: boolean; }
export interface MaxMindRequest { accountId: number; licenseKey: string; editionId?: string; }
export interface MaxMindTestResult { reachable: boolean; error?: string; }
```

`web/frontend/src/lib/api/settings.ts` (mirror the CrowdSec/OIDC client methods):
```ts
getMaxMind: (): Promise<MaxMindConfig> => request('GET', '/settings/maxmind'),
putMaxMind: (body: MaxMindRequest): Promise<MaxMindConfig> => request('PUT', '/settings/maxmind', body),
deleteMaxMind: (): Promise<void> => request('DELETE', '/settings/maxmind'),
testMaxMind: (body: MaxMindRequest & { useStored?: boolean }): Promise<MaxMindTestResult> => request('POST', '/settings/maxmind/test', body),
```
(match the exact `request(...)` signature used by the neighboring methods.)

- [ ] **Step 6: Typecheck + commit**

Run: `cd web/frontend && npm run check` → 0 errors. `cd ../.. && go build ./...` → clean.

```bash
gofmt -s -w internal/backup/*.go
git add internal/backup/ web/frontend/src/lib/api/settings.ts web/frontend/src/lib/api/types.ts
git commit -m "feat(backup,web): MaxMind creds in backup snapshot + frontend client (brick 2)

license_key participates in the backup sentinel mechanism (redacted in
no-secrets exports, inherited on restore) like DNS/OIDC; account_id and
edition_id travel verbatim. Add the frontend API client methods + TS types
(getMaxMind/putMaxMind/deleteMaxMind/testMaxMind). The settings UI panel is
brick 4."
```

---

### Task 5: Runtime verification

**Files:** none (observation only).

- [ ] **Step 1: Build**

Run: `go build ./... && cd web/frontend && npm run build && cd ../.. && go build -o arenet ./cmd/arenet`
Expected: clean.

- [ ] **Step 2: Drive the API (verify skill)**

Run the binary; with an admin session (curl against the admin API):
- `PUT /api/v1/settings/maxmind` `{accountId, licenseKey}` → 200; `GET` → `configured:true`, response contains NO license key (grep the body).
- `POST /api/v1/settings/maxmind/test` with valid operator creds → `{reachable:true}` **quickly** (confirm no ~60MB transfer — watch latency/network); with a wrong key → `{reachable:false, error:...}`.
- `DELETE` → `GET` shows `configured:false`.
- Backup export (redacted) → confirm the JSON has the sentinel, not the plaintext license key.

The valid-creds test needs the operator's real MaxMind account (hand-off). The redaction, gating, and no-key-leak checks run without real creds.

- [ ] **Step 3: Capture evidence + report PASS/FAIL** per the verify skill.

---

## Self-Review

**Spec coverage:** storage struct + CRUD + preserve + validate → Task 1. Redacting API GET/PUT/DELETE + audit scrub → Task 2. Test-connection real-client-no-download behind a seam → Task 3. Backup sentinel (4 sites) + frontend client/types → Task 4. Runtime → Task 5. Dependency → Task 1. All spec sections covered.

**Placeholder scan:** No TBD/TODO; storage/API/test code is concrete. The two "verify the exact helper name / CrowdSec GET-fresh behavior" notes are real mirror-the-template instructions, not placeholders — they name the template location. The "must-not-download-60MB" invariant is called out with a build-time verification step and a fallback.

**Type consistency:** `MaxMindConfig` fields (AccountID int, LicenseKey, EditionID, timestamps) identical across storage (Task 1), API mapping (Task 2), backup (Task 4). `maxMindProbe(ctx, int, string, string) error` seam signature identical in Task 3 impl + tests. Wire JSON keys (`accountId`, `licenseKey`, `editionId`, `configured`, `reachable`) consistent between Go structs (Tasks 2-3) and TS types (Task 4). Routes registered once each (GET/PUT/DELETE in Task 2, POST /test in Task 3).
