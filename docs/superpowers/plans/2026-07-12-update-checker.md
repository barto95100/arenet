# Update checker (v2.12.3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An opt-in checker that polls GitHub for a newer stable Arenet release and surfaces it as an alerting source + topbar badge + /settings mini-card — no auto-update.

**Architecture:** A standalone `internal/updatecheck` package holds the poll/compare logic (unit-testable). Main wires a boot+24h loop when enabled. A new `update_available` alerting source (mirroring `cert_renewal_failed`) reads the checker's status. `GET/POST /api/v1/system/version` exposes/triggers it. Frontend adds a discreet topbar badge + a settings card, all i18n EN/FR.

**Tech Stack:** Go 1.25 (`net/http`, `time.Ticker`, `log/slog`, bbolt), the existing `internal/alerting` Source registry, SvelteKit (Svelte 5 runes) + vitest, i18n `t()` bundles.

## Global Constraints

- AGPL header on every new Go/TS/Svelte file.
- `gofmt -s`, `go vet ./...`, `staticcheck ./...` clean.
- Every I/O func takes `ctx context.Context` first; wrap errors `%w`; no `panic` outside main.
- ALL user-facing strings via `t()`, EN + FR, parity guard (v2.12.1) must stay green. Version identifiers / "GitHub" / semver strings stay untranslated.
- Opt-in: no external HTTP call unless the operator enabled the check (D1).
- No secrets involved; nothing new to redact.

## Locked decisions (from spec)

D1 opt-in (OFF default) · D2 boot+30s then 24h + manual · D3 interval configurable via `ARENET_UPDATE_CHECK_INTERVAL` (min 1h, default 24h) · D4 severity always Info · D5 failures silent (lastChecked/lastError, no alert) · D6 stable only (`/releases/latest`) · D7 discreet topbar badge.

---

## File Structure

- `internal/updatecheck/checker.go` — Checker + Status + semver compare (CREATE).
- `internal/updatecheck/checker_test.go` — unit tests (CREATE).
- `internal/storage/update_check_config.go` — `UpdateCheckConfig{Enabled, IntervalOverride}` + Get/Put (CREATE) + bucket const in `storage.go` (MODIFY).
- `internal/alerting/source_update_available.go` — new Source (CREATE).
- `internal/api/version.go` — `GET /system/version` + `POST /system/version/check` (CREATE).
- `internal/api/routes.go` — 2 routes (MODIFY).
- `cmd/arenet/main.go` — construct Checker, register source, start loop when enabled (MODIFY).
- `web/frontend/src/lib/api/system.ts` (or extend an existing client) — `getSystemVersion` / `triggerVersionCheck` (CREATE/MODIFY).
- `web/frontend/src/lib/components/UpdateBadge.svelte` — topbar bell (CREATE) + mount in the topbar component (MODIFY).
- `web/frontend/src/lib/components/settings/UpdatesSection.svelte` — settings mini-card (CREATE) + mount in /settings (MODIFY).
- `web/frontend/src/lib/i18n/locales/{en,fr}.json` — new keys (MODIFY).

---

### Task 1: Storage — update_check config singleton

**Files:**
- Modify: `internal/storage/storage.go` (bucket const)
- Create: `internal/storage/update_check_config.go`
- Test: `internal/storage/update_check_config_test.go`

**Interfaces:**
- Produces: `type UpdateCheckConfig struct { Enabled bool; IntervalOverride string }`; `func (s *Store) GetUpdateCheckConfig(ctx) (UpdateCheckConfig, error)` (returns zero-value {Enabled:false} + nil on a fresh install — NOT ErrNotFound, so the boot path reads "disabled" cleanly); `func (s *Store) PutUpdateCheckConfig(ctx, UpdateCheckConfig) error`.
- Consumes: bbolt, `withTimeout`, mirrors `crowdsec_config.go`.

- [ ] **Step 1: Add the bucket constant**

In `internal/storage/storage.go`, next to the other bucket consts:
```go
	bucketUpdateCheck = "update_check"
```
Ensure it's created in the `NewStore` bucket-init loop (grep `CreateBucketIfNotExists` — add `bucketUpdateCheck` to the same list the others use).

- [ ] **Step 2: Write the failing test**

Create `internal/storage/update_check_config_test.go`:
```go
package storage

import (
	"context"
	"testing"
)

func TestUpdateCheckConfig_DefaultDisabled(t *testing.T) {
	s := newStoreForTest(t)
	got, err := s.GetUpdateCheckConfig(context.Background())
	if err != nil {
		t.Fatalf("GetUpdateCheckConfig on fresh store: %v", err)
	}
	if got.Enabled {
		t.Error("fresh install must default to Enabled=false (opt-in)")
	}
}

func TestUpdateCheckConfig_Roundtrip(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	if err := s.PutUpdateCheckConfig(ctx, UpdateCheckConfig{Enabled: true, IntervalOverride: "12h"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetUpdateCheckConfig(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Enabled || got.IntervalOverride != "12h" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}
```

- [ ] **Step 3: Run → verify fail**

Run: `go test ./internal/storage/ -run TestUpdateCheckConfig -v`
Expected: FAIL (`GetUpdateCheckConfig` undefined).

- [ ] **Step 4: Implement the config**

Create `internal/storage/update_check_config.go` (AGPL header), mirroring `crowdsec_config.go`'s Get/Put:
```go
package storage

import (
	"context"
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// UpdateCheckConfig is the opt-in update-checker settings row (singleton
// under a fixed key). Enabled defaults to false (D1: no external call
// without consent). IntervalOverride is an optional Go-duration string;
// empty → use the default/env cadence.
type UpdateCheckConfig struct {
	Enabled          bool   `json:"enabled"`
	IntervalOverride string `json:"intervalOverride"`
}

const updateCheckKey = "config"

// GetUpdateCheckConfig returns the persisted config, or a zero-value
// (Enabled=false) config with nil error on a fresh install.
func (s *Store) GetUpdateCheckConfig(ctx context.Context) (UpdateCheckConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out UpdateCheckConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketUpdateCheck)).Get([]byte(updateCheckKey))
		if raw == nil {
			return nil // fresh install → zero value (disabled)
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return UpdateCheckConfig{}, err
	}
	return out, nil
}

// PutUpdateCheckConfig upserts the singleton config.
func (s *Store) PutUpdateCheckConfig(ctx context.Context, c UpdateCheckConfig) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal update check config: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketUpdateCheck)).Put([]byte(updateCheckKey), buf)
	})
}
```

- [ ] **Step 5: Run → verify pass + whole package**

Run: `go test ./internal/storage/ -run TestUpdateCheckConfig -v && go test ./internal/storage/ 2>&1 | tail -3`
Expected: PASS.

- [ ] **Step 6: Commit**
```bash
git add internal/storage/storage.go internal/storage/update_check_config.go internal/storage/update_check_config_test.go
git commit -m "feat(storage): update_check config singleton (opt-in default off)"
```

---

### Task 2: updatecheck package — Checker + semver compare

**Files:**
- Create: `internal/updatecheck/checker.go`
- Test: `internal/updatecheck/checker_test.go`

**Interfaces:**
- Produces:
  - `type Status struct { Current, Latest, URL string; UpdateAvailable bool; LastChecked time.Time; LastError string }`
  - `type Checker struct { ... }` with `func New(current string, httpClient *http.Client) *Checker`
  - `func (c *Checker) Check(ctx context.Context) Status` — performs the HTTP GET (Etag-cached), updates + returns a snapshot. Never returns an error value; failures land in `Status.LastError`.
  - `func (c *Checker) Status() Status` — current snapshot (thread-safe).
  - `func compareSemver(current, latest string) (updateAvailable bool)` (unexported; tested via Check or exported-for-test).
- Consumes: `net/http`, `encoding/json`, `sync`, `time`.

- [ ] **Step 1: Write failing semver tests**

Create `internal/updatecheck/checker_test.go`:
```go
package updatecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
	}{
		{"v2.12.3", "v2.12.4", true},   // patch ahead
		{"v2.12.3", "v2.13.0", true},   // minor ahead
		{"v2.12.3", "v3.0.0", true},    // major ahead
		{"v2.12.3", "v2.12.3", false},  // equal
		{"v2.12.4", "v2.12.3", false},  // latest older
		{"2.12.3", "v2.12.4", true},    // tolerate missing leading v
		{"DEV", "v2.12.4", false},      // dev build never reports update
	}
	for _, c := range cases {
		if got := compareSemver(c.current, c.latest); got != c.want {
			t.Errorf("compareSemver(%q,%q)=%v want %v", c.current, c.latest, got, c.want)
		}
	}
}

func TestCheck_NewRelease_SetsUpdateAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Etag", `"abc"`)
		_, _ = w.Write([]byte(`{"tag_name":"v2.12.4","html_url":"https://github.com/x/releases/v2.12.4"}`))
	}))
	defer srv.Close()

	c := New("v2.12.3", srv.Client())
	c.releasesURL = srv.URL // test seam (see impl)
	st := c.Check(context.Background())
	if !st.UpdateAvailable || st.Latest != "v2.12.4" {
		t.Errorf("status=%+v; want UpdateAvailable=true Latest=v2.12.4", st)
	}
	if st.URL == "" || st.LastError != "" {
		t.Errorf("status=%+v; want URL set, no error", st)
	}
}

func TestCheck_NotModified_KeepsLatest(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("If-None-Match") == `"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Etag", `"abc"`)
		_, _ = w.Write([]byte(`{"tag_name":"v2.12.4","html_url":"u"}`))
	}))
	defer srv.Close()
	c := New("v2.12.3", srv.Client())
	c.releasesURL = srv.URL
	_ = c.Check(context.Background())          // 200, stores Etag
	st := c.Check(context.Background())         // 304
	if st.Latest != "v2.12.4" {
		t.Errorf("304 path dropped Latest: %+v", st)
	}
	if calls != 2 {
		t.Errorf("calls=%d want 2", calls)
	}
}

func TestCheck_Failure_SetsLastError_NoAlarm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New("v2.12.3", srv.Client())
	c.releasesURL = srv.URL
	st := c.Check(context.Background())
	if st.LastError == "" {
		t.Error("expected LastError on 500")
	}
	if st.UpdateAvailable {
		t.Error("failed check must not report an update")
	}
}
```

- [ ] **Step 2: Run → verify fail**

Run: `go test ./internal/updatecheck/ -v`
Expected: FAIL (package/symbols undefined).

- [ ] **Step 3: Implement the checker**

Create `internal/updatecheck/checker.go` (AGPL header):
```go
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultReleasesURL is the GitHub "latest stable release" endpoint.
// /releases/latest excludes prereleases by GitHub convention (D6).
const defaultReleasesURL = "https://api.github.com/repos/barto95100/arenet/releases/latest"

// Status is a snapshot of the checker state, safe to copy.
type Status struct {
	Current         string    `json:"current"`
	Latest          string    `json:"latest"`
	URL             string    `json:"url"`
	UpdateAvailable bool      `json:"updateAvailable"`
	LastChecked     time.Time `json:"lastChecked"`
	LastError       string    `json:"lastError"`
}

type Checker struct {
	current     string
	client      *http.Client
	releasesURL string

	mu   sync.Mutex
	etag string
	st   Status
}

func New(current string, client *http.Client) *Checker {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Checker{
		current:     current,
		client:      client,
		releasesURL: defaultReleasesURL,
		st:          Status{Current: current},
	}
}

// Status returns the current snapshot.
func (c *Checker) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}

type releaseResp struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

// Check performs one poll. Failures never bubble up as an error — they
// land in Status.LastError (D5). LastChecked is always refreshed.
func (c *Checker) Check(ctx context.Context) Status {
	c.mu.Lock()
	etag := c.etag
	st := c.st
	c.mu.Unlock()

	st.LastChecked = time.Now().UTC()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.releasesURL, nil)
	if err != nil {
		st.LastError = err.Error()
		return c.store(st, etag)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		st.LastError = err.Error()
		return c.store(st, etag)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotModified:
		st.LastError = ""
		return c.store(st, etag) // keep prior Latest/URL/etag
	case http.StatusOK:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var rr releaseResp
		if jerr := json.Unmarshal(body, &rr); jerr != nil {
			st.LastError = fmt.Sprintf("parse release: %v", jerr)
			return c.store(st, etag)
		}
		st.Latest = rr.TagName
		st.URL = rr.HTMLURL
		st.UpdateAvailable = compareSemver(c.current, rr.TagName)
		st.LastError = ""
		return c.store(st, resp.Header.Get("Etag"))
	default:
		st.LastError = fmt.Sprintf("github returned %d", resp.StatusCode)
		return c.store(st, etag)
	}
}

func (c *Checker) store(st Status, etag string) Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.st = st
	c.etag = etag
	return st
}

// compareSemver reports whether latest is strictly newer than current.
// Tolerates a leading "v". A non-semver current (e.g. "DEV") never
// reports an update.
func compareSemver(current, latest string) bool {
	cur, ok1 := parseSemver(current)
	lat, ok2 := parseSemver(latest)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if lat[i] != cur[i] {
			return lat[i] > cur[i]
		}
	}
	return false
}

func parseSemver(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		// tolerate a pre-release/build suffix on patch (e.g. 3-rc1)
		p = strings.FieldsFunc(p, func(r rune) bool { return r == '-' || r == '+' })[0]
		n, err := strconv.Atoi(p)
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}
```

- [ ] **Step 4: Run → verify pass**

Run: `go test ./internal/updatecheck/ -v`
Expected: PASS (semver table + 200/304/500 paths).

- [ ] **Step 5: Commit**
```bash
git add internal/updatecheck/
git commit -m "feat(updatecheck): GitHub releases checker + semver compare"
```

---

### Task 3: Alerting source `update_available`

**Files:**
- Create: `internal/alerting/source_update_available.go`
- Test: `internal/alerting/source_update_available_test.go`

**Interfaces:**
- Produces: `type UpdateAvailableSource struct{...}`; `func NewUpdateAvailableSource(statusFn func() updatecheck.Status) *UpdateAvailableSource`; implements `Name()`/`ValidateParams`/`Read`. `Name()=="update_available"`. `Read` returns `StringValue("available")` with `Context{current,latest,url}` when `UpdateAvailable`, else `StringValue("up_to_date")`. It's a STATE source (String), evaluated by a rule `state == "available"` → Info.
- Consumes: `internal/updatecheck.Status`, the alerting `Source` interface (`Name`/`ValidateParams`/`Read` + `StringValue`).

- [ ] **Step 1: Write failing test**

Create `internal/alerting/source_update_available_test.go`:
```go
package alerting

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/barto95100/arenet/internal/updatecheck"
)

func TestUpdateAvailableSource_ReadsStatus(t *testing.T) {
	src := NewUpdateAvailableSource(func() updatecheck.Status {
		return updatecheck.Status{UpdateAvailable: true, Latest: "v2.12.4", URL: "u", Current: "v2.12.3"}
	})
	if src.Name() != "update_available" {
		t.Fatalf("name=%q", src.Name())
	}
	v, err := src.Read(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v.String == nil || *v.String != "available" {
		t.Errorf("value=%+v; want state 'available'", v)
	}
	if v.Context["latest"] != "v2.12.4" {
		t.Errorf("context=%v; want latest v2.12.4", v.Context)
	}
}

func TestUpdateAvailableSource_UpToDate(t *testing.T) {
	src := NewUpdateAvailableSource(func() updatecheck.Status {
		return updatecheck.Status{UpdateAvailable: false}
	})
	v, _ := src.Read(context.Background(), json.RawMessage(`{}`))
	if v.String == nil || *v.String != "up_to_date" {
		t.Errorf("value=%+v; want 'up_to_date'", v)
	}
}
```

- [ ] **Step 2: Run → verify fail** — `go test ./internal/alerting/ -run TestUpdateAvailableSource -v` → FAIL.

- [ ] **Step 3: Implement the source**

Create `internal/alerting/source_update_available.go` (AGPL header):
```go
package alerting

import (
	"context"
	"encoding/json"

	"github.com/barto95100/arenet/internal/updatecheck"
)

// UpdateAvailableSource is a STATE source: it emits "available" when a
// newer stable release exists, "up_to_date" otherwise. A rule of kind
// state (expected="available") at severity Info surfaces the update.
// It reads a live snapshot via statusFn so it stays decoupled from the
// checker's goroutine.
type UpdateAvailableSource struct {
	statusFn func() updatecheck.Status
}

func NewUpdateAvailableSource(statusFn func() updatecheck.Status) *UpdateAvailableSource {
	return &UpdateAvailableSource{statusFn: statusFn}
}

func (s *UpdateAvailableSource) Name() string { return "update_available" }

// ValidateParams accepts an empty object — this source takes no params.
func (s *UpdateAvailableSource) ValidateParams(raw json.RawMessage) error {
	return nil
}

func (s *UpdateAvailableSource) Read(_ context.Context, _ json.RawMessage) (SourceValue, error) {
	st := s.statusFn()
	if st.UpdateAvailable {
		v := StringValue("available")
		v.Context = map[string]any{"current": st.Current, "latest": st.Latest, "url": st.URL}
		return v, nil
	}
	return StringValue("up_to_date"), nil
}
```

- [ ] **Step 4: Run → verify pass** — `go test ./internal/alerting/ -run TestUpdateAvailableSource -v` → PASS. Then `go test ./internal/alerting/ 2>&1 | tail -3`.

- [ ] **Step 5: Commit**
```bash
git add internal/alerting/source_update_available.go internal/alerting/source_update_available_test.go
git commit -m "feat(alerting): update_available state source (Info)"
```

---

### Task 4: API — `/system/version` (+ manual check) + main wiring

**Files:**
- Create: `internal/api/version.go`
- Test: `internal/api/version_test.go`
- Modify: `internal/api/routes.go`, `internal/api/handler.go` (hold the checker + status), `cmd/arenet/main.go`

**Interfaces:**
- Produces:
  - `GET /api/v1/system/version` → `{current, latest, updateAvailable, url, lastChecked, lastError, enabled}`.
  - `POST /api/v1/system/version/check` → runs `Check` synchronously (admin-only), returns the refreshed body.
  - `PUT /api/v1/system/version/config` → `{enabled, intervalOverride}` toggles the opt-in, persists via `PutUpdateCheckConfig`, (re)starts/stops the loop.
- Consumes: the `*updatecheck.Checker` (injected into `Handler`), `store.Get/PutUpdateCheckConfig`.

- [ ] **Step 1: Wire the checker into Handler**

In `internal/api/handler.go`, add an `updateChecker *updatecheck.Checker` field (nil-tolerant, like other optional deps) + a setter `SetUpdateChecker(c *updatecheck.Checker)`; and a `getUpdateEnabled func(ctx) (bool, error)` (or read the store directly). Keep it nil-safe: when nil, the endpoint reports `enabled:false, updateAvailable:false`.

- [ ] **Step 2: Write failing API test**

Create `internal/api/version_test.go`:
```go
func TestSystemVersion_ReportsStatus(t *testing.T) {
	env := newTestEnv(t, false)
	// inject a checker whose status says an update is available
	chk := updatecheck.New("v2.12.3", nil)
	// seed a status via a manual field or a test hook — simplest: point
	// it at an httptest server returning v2.12.4 and Check once.
	env.handler.SetUpdateChecker(chk) // adapt to the real setter name
	// enable it in the store so enabled:true
	_ = env.store.PutUpdateCheckConfig(context.Background(), storage.UpdateCheckConfig{Enabled: true})

	rec := getRec(t, env, "/api/v1/system/version")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["current"] != "v2.12.3" {
		t.Errorf("current=%v", body["current"])
	}
	if _, ok := body["enabled"]; !ok {
		t.Error("missing enabled field")
	}
}
```
> Adapt to real helpers (`newTestEnv`, `getRec` — confirmed present in `internal/api/*_test.go`). If seeding a concrete Status needs a test hook, add a small `SetStatusForTest` on Checker guarded to `_test` usage, OR drive `Check` against an httptest server.

- [ ] **Step 3: Run → verify fail** — route 404 / handler undefined.

- [ ] **Step 4: Implement the handlers + routes**

Create `internal/api/version.go` with `systemVersion` (GET), `systemVersionCheck` (POST), `systemVersionConfig` (PUT). GET builds the body from `h.updateChecker.Status()` (or zero when nil) + the stored `enabled`. POST calls `h.updateChecker.Check(ctx)` and returns the new status (503/409 when nil/disabled — pick one; document). PUT decodes `{enabled, intervalOverride}`, validates the interval (≥1h if non-empty, D3), persists, and toggles the loop (via a callback the main wiring registers, or by having the loop poll the store — simplest: a `func(UpdateCheckConfig)` hook set from main).

In `routes.go`, INSIDE the `/api/v1` subtree under the admin group
(NOT at the root next to `/system/health` — that one is deliberately
public for scrapers; `/system/version` carries operator-relevant state
and is admin-only). Register at the same nesting as the other admin
settings routes, e.g. `/api/v1/system/version`:
```go
	r.Get("/system/version", h.systemVersion)
	r.Post("/system/version/check", h.systemVersionCheck)
	r.Put("/system/version/config", h.systemVersionConfig)
```
> Grep how an existing admin-gated `/api/v1/...` settings route is nested (e.g. the dns-providers routes under `RequireAdminMiddleware`) and mirror that placement. Do NOT mount alongside the public root `/system/health`.

- [ ] **Step 5: Wire main.go**

In `cmd/arenet/main.go`:
1. Construct `chk := updatecheck.New(version, nil)`.
2. Register the source: `alertingRegistry.Register(alerting.NewUpdateAvailableSource(chk.Status))` next to the other `Register` calls (~1465).
3. Inject into the handler: `handler.SetUpdateChecker(chk)`.
4. Read `store.GetUpdateCheckConfig`; if `Enabled`, start the loop goroutine: first tick after 30s, then `time.NewTicker(interval)` where interval = env `ARENET_UPDATE_CHECK_INTERVAL` (parsed, clamped ≥1h) or config override or 24h default. The PUT-config hook starts/stops this goroutine (use a small supervisor with a `context.CancelFunc`).

- [ ] **Step 6: Run → verify pass + package + build**

Run: `go test ./internal/api/ -run TestSystemVersion -v && go build ./... && go vet ./...`
Expected: PASS, build+vet clean.

- [ ] **Step 7: Commit**
```bash
git add internal/api/version.go internal/api/version_test.go internal/api/routes.go internal/api/handler.go cmd/arenet/main.go
git commit -m "feat(api): /system/version endpoint + update checker wiring"
```

---

### Task 5: Frontend — client, topbar badge, settings card, i18n

**Files:**
- Create/modify: `web/frontend/src/lib/api/system.ts` (client methods)
- Create: `web/frontend/src/lib/components/UpdateBadge.svelte` + mount in the topbar
- Create: `web/frontend/src/lib/components/settings/UpdatesSection.svelte` + mount in /settings
- Modify: `web/frontend/src/lib/i18n/locales/{en,fr}.json`
- Test: co-located `*.test.ts`

**Interfaces:**
- Consumes: `GET /system/version`, `POST /system/version/check`, `PUT /system/version/config`.
- Produces: `SystemVersion` type `{current, latest, updateAvailable, url, lastChecked, lastError, enabled}`.

- [ ] **Step 1: Client + type + failing test**

Add to the system API client (grep for an existing `system` client or create `system.ts`):
```ts
export interface SystemVersion {
	current: string; latest: string; updateAvailable: boolean;
	url: string; lastChecked: string; lastError: string; enabled: boolean;
}
export const systemApi = {
	getVersion: (): Promise<SystemVersion> => request<SystemVersion>('GET', '/system/version'),
	checkVersion: (): Promise<SystemVersion> => request<SystemVersion>('POST', '/system/version/check'),
	setVersionConfig: (b: { enabled: boolean; intervalOverride?: string }): Promise<SystemVersion> =>
		request<SystemVersion>('PUT', '/system/version/config', b),
};
```
Write a client test asserting method+path+body (mirror `settings.test.ts`). Run → fail → implement → pass.

- [ ] **Step 2: UpdateBadge — failing test then impl**

Test: renders nothing when `updateAvailable:false`; renders a bell + links to `url` when true; tooltip names `latest`.
Implement `UpdateBadge.svelte` (fetch `getVersion` on mount; render only when `updateAvailable`; `<a href={url} target="_blank">` bell icon; `aria-label`/tooltip via `t('topbar.updateAvailable', { version: latest })`). Mount in the topbar component (grep the existing topbar/header component).

- [ ] **Step 3: UpdatesSection — failing test then impl**

Test: shows current/latest, the enable toggle calls `setVersionConfig`, "Check now" calls `checkVersion`, `lastError` renders when non-empty.
Implement `UpdatesSection.svelte` (current + latest/"up to date"; toggle bound to `enabled` → `setVersionConfig`; "Check now" button → `checkVersion` + refresh; `lastChecked` relative time via `relativeTime`; `lastError` line; link to `url`). Mount in `/settings`. All strings via `t()`.

- [ ] **Step 4: i18n EN + FR**

Add to both bundles: `topbar.updateAvailable`; `settings.updates.{title, subtitle, current, latest, upToDate, enableToggle, checkNow, checking, lastChecked, lastErrorLabel, viewRelease}`; `alerting.sources.updateAvailable` (source display name). Values: EN natural, FR natural; version strings / "GitHub" untranslated.

- [ ] **Step 5: Full gates**

Run:
```bash
cd web/frontend && npx vitest run && npm run check 2>&1 | tail -3 && npm run build 2>&1 | tail -3
```
Expected: all tests pass (incl. the i18n parity guard), svelte-check 0/0, build OK.

- [ ] **Step 6: Commit**
```bash
git add web/frontend/src/lib/api/system.ts web/frontend/src/lib/components/UpdateBadge.svelte web/frontend/src/lib/components/settings/UpdatesSection.svelte web/frontend/src/lib/i18n/locales/en.json web/frontend/src/lib/i18n/locales/fr.json <topbar+settings mounts + tests>
git commit -m "feat(web): update badge + settings updates section + i18n"
```

---

### Task 6: Empirical smoke (real binary)

**Files:** none.

- [ ] **Step 1** Build + run; complete /setup.
- [ ] **Step 2** Default OFF: `GET /api/v1/system/version` → `enabled:false, updateAvailable:false`; confirm NO outbound GitHub call happened (check logs). This pins D1.
- [ ] **Step 3** Enable via `PUT /system/version/config {enabled:true}`; `POST /system/version/check` → status refreshes with the real latest release (or lastError if offline — both acceptable, note which).
- [ ] **Step 4** Simulate "update available": point the checker at a local httptest-style stub OR temporarily build the binary with an older `-X main.version=v0.0.1` so the real latest is newer → badge + alerting rule fire. Verify the topbar badge appears and `GET /system/version` reports `updateAvailable:true`.
- [ ] **Step 5** Failure path: block the network / bad URL → `lastError` populated, no alert, service healthy.
- [ ] **Step 6** Non-regression: existing alerting rules + /settings unaffected. Clean up.
- [ ] **Step 7** Record results in the PR description. Do NOT tag (tag v2.12.3 after merge).

---

## Self-Review

- **Spec coverage**: D1 opt-in → Task 1 (default off) + Task 4 (enabled gating) + Task 6 Step 2; D2 boot+30s/24h + manual → Task 4 Step 5 + POST check; D3 configurable interval → Task 4 (env + config, ≥1h); D4 Info → Task 3 (state source, rule severity Info); D5 silent failure → Task 2 (LastError, no error return) + Task 5 (lastError UI); D6 stable-only → Task 2 (`/releases/latest`); D7 badge → Task 5. Endpoint `/system/version` → Task 4. ✓
- **Placeholder scan**: code present in every step; the "confirm helper/mount point" notes are verification instructions (test-helper + topbar-component names vary), not code placeholders. ✓
- **Type consistency**: `updatecheck.Status`/`Checker.New`/`Check`/`Status()`, `compareSemver`, `UpdateCheckConfig{Enabled,IntervalOverride}`, `Get/PutUpdateCheckConfig`, `NewUpdateAvailableSource(statusFn)`, `SystemVersion` — used identically across tasks. ✓
- **Ambiguity**: the loop start/stop on toggle is a supervisor with a CancelFunc set from main (Task 4 Step 5) — made explicit. The source is STATE (String "available"/"up_to_date"), evaluated by a state rule — explicit in Task 3.
