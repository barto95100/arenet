# Routes UI + Maintenance Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a third route state "Maintenance" (503 + global custom page + Retry-After + per-route IP bypass) alongside Active/Disabled, driven by one inline 3-state segmented control on the Routes list.

**Architecture:** A new nilable `MaintenanceConfig` field on Route (nil = not in maintenance). caddymgr emits a maintenance route as a subroute with a `client_ip` bypass route (→ real proxy) + a catch-all `static_response` 503; priority Disabled(filtered→404) > Maintenance(503) > Active. A global maintenance page is stored as a singleton setting (GeoIPUpdateConfig pattern) with a branded default, editable in a Settings→Error Pages tab. A new `RouteStateControl.svelte` replaces the old enable/disable button.

**Tech Stack:** Go 1.25 (bbolt, chi router, embedded Caddy v2.11.3 `static_response`/`client_ip`), SvelteKit 5 runes, vitest, i18n JSON bundles.

## Global Constraints

- **AGPL header** on every new Go and TS/Svelte file (`//` block).
- **Target v2.17.0** (feature = minor bump; verify git-state at tag with `git rev-parse`).
- **Emit priority (locked):** `Disabled=true` → filtered → 404 (wins) ; else `MaintenanceConfig!=nil` → 503 ; else active proxy.
- **Clear-on-off (locked):** `MaintenanceConfig!=nil` IS the maintenance signal. Exiting maintenance sets it `nil` (config cleared). Entering with no config → defaults `{RetryAfterSeconds:300, BypassIPs:nil}`.
- **Last-HTTPS warning = Disabled ONLY.** A maintenance route stays emitted and serves 503 over TLS, so `:443` survives. Do NOT fire the warning on the maintenance transition (all HTTPS predicates test `TLSEnabled && !Disabled`, none reference maintenance).
- **Wire-field lesson (MANDATORY):** any new Route field must be added to `routeRequest` (handler.go) + mapped in createRoute AND updateRoute + added to `routeResponse` + covered by a `routes_maintenance_test.go`, else create/edit 400s with "unknown field".
- **Caddy JSON (verified):** `static_response` = `{"handler":"static_response","status_code":503,"body":"<html>","headers":{"Retry-After":["300"],"Content-Type":["text/html; charset=utf-8"]}}`. `client_ip` matcher = `{"client_ip":{"ranges":["1.2.3.4/32"]}}` (NOT `remote_ip`). Bypass route `terminal:true` first, 503 catch-all second.
- **Reuse, don't reinvent:** storage singleton = `GeoIPUpdateConfig` pattern (geoip_update_config.go); maintenance emission = `buildForwardAuthDenyHandler` deny-path precedent (manager.go:1663-1692, 3272-3290); state endpoints = `toggleRouteDisabled` pattern (routes.go:1978-2057); HTML sanitize = `SanitizeErrorPageBody` (error_pages.go:201).
- **Empirically verified sites:** per-route handler loop `manager.go:1176`, handlers slice init `:1508`, proxy append `:1709`, `wrapInSubroute` `:1725`; HasHTTPSServer `:3403`; filterDisabledRoutes `:544`; audit count currently 59.

---

### Task 1: Storage — `MaintenanceConfig` field on Route

**Files:**
- Modify: `internal/storage/routes.go` (Route struct; validate function)
- Test: `internal/storage/routes_maintenance_test.go` (create)

**Interfaces:**
- Produces: `storage.MaintenanceConfig{RetryAfterSeconds int, BypassIPs []string}` and `Route.MaintenanceConfig *MaintenanceConfig`.

- [ ] **Step 1: Write the failing test**

```go
// internal/storage/routes_maintenance_test.go
package storage

import (
	"context"
	"testing"
)

func TestRoute_MaintenanceConfig_Roundtrip(t *testing.T) {
	s := newTestStore(t)
	r := minimalRoute("m.example.com", "http://u:1")
	r.MaintenanceConfig = &MaintenanceConfig{RetryAfterSeconds: 300, BypassIPs: []string{"192.168.1.0/24", "10.0.0.5"}}
	created, err := s.CreateRoute(context.Background(), r)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetRoute(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.MaintenanceConfig == nil {
		t.Fatal("MaintenanceConfig nil after roundtrip; want non-nil")
	}
	if got.MaintenanceConfig.RetryAfterSeconds != 300 {
		t.Errorf("RetryAfterSeconds = %d; want 300", got.MaintenanceConfig.RetryAfterSeconds)
	}
	if len(got.MaintenanceConfig.BypassIPs) != 2 {
		t.Errorf("BypassIPs len = %d; want 2", len(got.MaintenanceConfig.BypassIPs))
	}
}

func TestRoute_MaintenanceConfig_NilByDefault(t *testing.T) {
	s := newTestStore(t)
	created, _ := s.CreateRoute(context.Background(), minimalRoute("plain.example.com", "http://u:1"))
	got, _ := s.GetRoute(context.Background(), created.ID)
	if got.MaintenanceConfig != nil {
		t.Errorf("MaintenanceConfig = %+v; want nil (zero value)", got.MaintenanceConfig)
	}
}

func TestMaintenanceConfig_Validate_BadIP(t *testing.T) {
	if err := (&MaintenanceConfig{BypassIPs: []string{"not-an-ip"}}).Validate(); err == nil {
		t.Error("want error for junk bypass IP")
	}
	if err := (&MaintenanceConfig{BypassIPs: []string{"10.0.0.0/8", "1.2.3.4"}}).Validate(); err != nil {
		t.Errorf("valid CIDR + IP rejected: %v", err)
	}
	if err := (&MaintenanceConfig{RetryAfterSeconds: -1}).Validate(); err == nil {
		t.Error("want error for negative RetryAfterSeconds")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run 'TestRoute_MaintenanceConfig|TestMaintenanceConfig' -v`
Expected: FAIL — `MaintenanceConfig` undefined.

- [ ] **Step 3: Add the struct + field + Validate**

In `internal/storage/routes.go`, add near the Route struct's other option types:
```go
// MaintenanceConfig, when non-nil (and Disabled=false), puts the route
// in maintenance mode: Caddy serves 503 + the global maintenance page +
// Retry-After, except BypassIPs which reach the real upstream. Nil =
// not in maintenance (zero value, migration-free). Exiting maintenance
// sets this back to nil (clear-on-off).
type MaintenanceConfig struct {
	// RetryAfterSeconds is sent as the 503 Retry-After header and
	// substituted into the maintenance page. 0 = omit the header.
	RetryAfterSeconds int `json:"retryAfterSeconds,omitempty"`
	// BypassIPs is an IP/CIDR allow-list; matching clients reach the
	// real upstream instead of the 503.
	BypassIPs []string `json:"bypassIps,omitempty"`
}

// Validate rejects a negative Retry-After and any bypass entry that is
// neither a bare IP nor a CIDR.
func (m *MaintenanceConfig) Validate() error {
	if m == nil {
		return nil
	}
	if m.RetryAfterSeconds < 0 {
		return fmt.Errorf("maintenance: retryAfterSeconds must be >= 0, got %d", m.RetryAfterSeconds)
	}
	for _, e := range m.BypassIPs {
		if _, _, err := net.ParseCIDR(e); err == nil {
			continue
		}
		if net.ParseIP(e) != nil {
			continue
		}
		return fmt.Errorf("maintenance: bypass entry %q is not an IP or CIDR", e)
	}
	return nil
}
```
Add the field to the `Route` struct (near `Disabled bool`):
```go
	MaintenanceConfig *MaintenanceConfig `json:"maintenanceConfig,omitempty"`
```
Ensure `"net"` and `"fmt"` are imported in routes.go (fmt already is; add net if missing). If the Route has a `validate()` method that runs on Create/Update, call `r.MaintenanceConfig.Validate()` there and return the error.

- [ ] **Step 4: Run test to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run 'TestRoute_MaintenanceConfig|TestMaintenanceConfig' -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/storage/routes.go internal/storage/routes_maintenance_test.go
git commit -m "feat(storage): MaintenanceConfig field on Route (nilable, validated)"
```

---

### Task 2: Storage — global maintenance page singleton

**Files:**
- Create: `internal/storage/maintenance_page_config.go`
- Modify: `internal/storage/storage.go` (bucket const + register in the bucket-creation loop ~168-178)
- Test: `internal/storage/maintenance_page_config_test.go` (create)

**Interfaces:**
- Produces: `storage.MaintenancePageConfig{HTML string}`, `(*Store).GetMaintenancePageConfig(ctx) (MaintenancePageConfig, error)` (zero value + nil err when absent), `(*Store).PutMaintenancePageConfig(ctx, MaintenancePageConfig) error`.

- [ ] **Step 1: Write the failing test**

```go
// internal/storage/maintenance_page_config_test.go
package storage

import (
	"context"
	"testing"
)

func TestMaintenancePageConfig_AbsentReturnsZero(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetMaintenancePageConfig(context.Background())
	if err != nil {
		t.Fatalf("get on fresh store: %v", err)
	}
	if got.HTML != "" {
		t.Errorf("HTML = %q; want empty (serve branded default)", got.HTML)
	}
}

func TestMaintenancePageConfig_Roundtrip(t *testing.T) {
	s := newTestStore(t)
	if err := s.PutMaintenancePageConfig(context.Background(), MaintenancePageConfig{HTML: "<h1>Back soon</h1>"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.GetMaintenancePageConfig(context.Background())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.HTML != "<h1>Back soon</h1>" {
		t.Errorf("HTML = %q; want the stored value", got.HTML)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run TestMaintenancePageConfig -v`
Expected: FAIL — `GetMaintenancePageConfig` undefined / bucket missing.

- [ ] **Step 3: Implement (mirror GeoIPUpdateConfig verbatim)**

Create `internal/storage/maintenance_page_config.go`:
```go
// <AGPL header>
package storage

import (
	"context"
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// MaintenancePageConfig is the single global HTML template served on
// maintenance 503s. Empty HTML = serve the branded default. Singleton,
// same convention as GeoIPUpdateConfig / update_check_config.
type MaintenancePageConfig struct {
	HTML string `json:"html,omitempty"`
}

const maintenancePageKey = "config"

// GetMaintenancePageConfig returns the persisted page, or a zero value
// (empty HTML) with nil error on a fresh install — callers serve the
// branded default when HTML is empty.
func (s *Store) GetMaintenancePageConfig(ctx context.Context) (MaintenancePageConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	var out MaintenancePageConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketMaintenancePage)).Get([]byte(maintenancePageKey))
		if raw == nil {
			return nil // fresh install → zero value (default)
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return MaintenancePageConfig{}, err
	}
	return out, nil
}

// PutMaintenancePageConfig upserts the singleton page.
func (s *Store) PutMaintenancePageConfig(ctx context.Context, c MaintenancePageConfig) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal maintenance page config: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketMaintenancePage)).Put([]byte(maintenancePageKey), buf)
	})
}
```
In `internal/storage/storage.go`: add `bucketMaintenancePage = "maintenance_page"` next to the other bucket consts, and add `[]byte(bucketMaintenancePage)` to the bucket-creation loop (~168-178, the same loop that creates bucketGeoIPUpdate). Confirm the exact loop shape by reading it first.

- [ ] **Step 4: Run test to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run TestMaintenancePageConfig -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/storage/maintenance_page_config.go internal/storage/storage.go internal/storage/maintenance_page_config_test.go
git commit -m "feat(storage): global maintenance-page singleton (GeoIPUpdateConfig pattern)"
```

---

### Task 3: Audit actions `route_maintenance_on` / `route_maintenance_off`

**Files:**
- Modify: `internal/audit/actions.go` (const ~60, allActions ~262)
- Modify: `internal/audit/actions_test.go:28` (wantCount 59 → 61)

**Interfaces:**
- Produces: `audit.ActionRouteMaintenanceOn = "route_maintenance_on"`, `audit.ActionRouteMaintenanceOff = "route_maintenance_off"`.

- [ ] **Step 1: Bump the count test to fail first**

In `internal/audit/actions_test.go`, change `const wantCount = 59` to `const wantCount = 61` and append `+ route-maintenance=2)` to the drift message.

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/audit/ -run TestAllActions -v`
Expected: FAIL — count drift 59 vs 61 + ExactSet missing.

- [ ] **Step 3: Add the constants + register**

In `internal/audit/actions.go`, after `ActionCertDeleted = "cert_deleted"` (line ~60):
```go
	ActionRouteMaintenanceOn  = "route_maintenance_on"
	ActionRouteMaintenanceOff = "route_maintenance_off"
```
In `allActions` after `ActionCertDeleted,` (~line 262):
```go
	ActionRouteMaintenanceOn,
	ActionRouteMaintenanceOff,
```
If `TestAllActions_ExactSet` enumerates the set, add both there.

- [ ] **Step 4: Run to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/audit/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/actions.go internal/audit/actions_test.go
git commit -m "feat(audit): route_maintenance_on/off actions (59->61)"
```

---

### Task 4: caddymgr — emit the maintenance subroute (503 + client_ip bypass)

**Files:**
- Modify: `internal/caddymgr/manager.go` (per-route loop ~1176; branch before the normal proxy assembly ~1508-1725)
- Create: `internal/caddymgr/maintenance.go` (the body-builder helper + the subroute builder)
- Test: `internal/caddymgr/maintenance_test.go` (create)

**Interfaces:**
- Consumes: `storage.MaintenanceConfig` (Task 1); `storage.MaintenancePageConfig` HTML (Task 2, passed via the manager's store access — confirm how the manager reads settings; if it takes the HTML via buildOpts, thread it through, mirroring how error-page templates reach the emitter).
- Produces: the maintenance branch inside `buildConfigJSON` + `buildMaintenanceBody(html string, retryAfter int) string` + `buildMaintenanceRoute(...)`.

**Note:** This is the load-bearing task. Mirror the forward-auth deny path (`manager.go:1663-1692`) which appends a terminal `static_response` after metrics, wraps, and `continue`s past the normal proxy. But maintenance needs a DISTINCT subroute shape (a matcher-bearing bypass inner route), so build a subroute with two inner routes.

- [ ] **Step 1: Write the failing test (config-gen + caddy.Validate)**

```go
// internal/caddymgr/maintenance_test.go
package caddymgr

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/barto95100/arenet/internal/storage"
)

// Build a config with one maintenance route and assert: it validates,
// the emitted route carries a static_response 503 with Retry-After +
// the maintenance body, and a client_ip bypass route.
func TestBuildConfigJSON_MaintenanceRoute(t *testing.T) {
	routes := []storage.Route{{
		ID: "r1", Host: "maint.example.com", TLSEnabled: true,
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		MaintenanceConfig: &storage.MaintenanceConfig{
			RetryAfterSeconds: 300, BypassIPs: []string{"192.168.1.0/24"},
		},
	}}
	// Use the same buildConfigJSON entrypoint the other tests use
	// (copy the harness from manager_test.go TestBuildConfigJSON_LoadsCleanly:
	// build opts, call buildConfigJSON, unmarshal to caddy.Config, Validate).
	cfgJSON := mustBuildConfigJSONForTest(t, routes) // helper defined in manager_test.go or inline per that test's shape

	// 1. It validates against a real Caddy binary.
	var cfg caddy.Config
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("caddy.Validate: %v", err)
	}

	s := string(cfgJSON)
	// 2. static_response 503 present.
	if !strings.Contains(s, `"static_response"`) || !strings.Contains(s, `"status_code":503`) {
		t.Error("no static_response 503 emitted for maintenance route")
	}
	// 3. Retry-After header present.
	if !strings.Contains(s, `"Retry-After"`) || !strings.Contains(s, `"300"`) {
		t.Error("no Retry-After: 300 header emitted")
	}
	// 4. client_ip bypass with the CIDR (NOT remote_ip).
	if !strings.Contains(s, `"client_ip"`) || !strings.Contains(s, `"192.168.1.0/24"`) {
		t.Error("no client_ip bypass with the CIDR")
	}
	if strings.Contains(s, `"remote_ip"`) {
		t.Error("used remote_ip; want client_ip")
	}
}
```
IMPLEMENTER: read `manager_test.go` `TestBuildConfigJSON_LoadsCleanly` (~1082-1255) FIRST and copy its exact harness for building `cfgJSON` from routes (opts construction + buildConfigJSON call). Replace `mustBuildConfigJSONForTest` with that real harness inline. Do NOT invent a helper that doesn't exist.

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ -run TestBuildConfigJSON_MaintenanceRoute -v`
Expected: FAIL — no static_response emitted (maintenance branch doesn't exist yet).

- [ ] **Step 3: Implement the maintenance body helper**

Create `internal/caddymgr/maintenance.go`:
```go
// <AGPL header>
package caddymgr

import (
	"strconv"
	"strings"
)

// maintenanceRetryAfterSentinel is replaced at emission time with the
// route's Retry-After value inside the maintenance page body.
const maintenanceRetryAfterSentinel = "{arenet.maintenance.retry_after}"

// buildMaintenanceBody returns the maintenance HTML with the per-route
// Retry-After substituted in. `html` is the operator's page (already
// sanitized upstream) or the branded default. retryAfter is seconds.
func buildMaintenanceBody(html string, retryAfter int) string {
	return strings.ReplaceAll(html, maintenanceRetryAfterSentinel, strconv.Itoa(retryAfter))
}

// arenetDefaultMaintenancePage is the branded default served when the
// operator has not customized the maintenance page. Styled to match
// arenetDefaultErrorPages. (IMPLEMENTER: mirror the structure/branding
// of arenetDefaultErrorPages in error_pages.go — same <style>, colors,
// logo treatment — with a blue/info "Back soon" message and a line
// showing "Retry in {arenet.maintenance.retry_after}s".)
const arenetDefaultMaintenancePage = `<!doctype html>...`
```

- [ ] **Step 4: Implement the maintenance branch in buildConfigJSON**

Read `manager.go:1508-1725` (the handlers slice from `metricsHandler` to `wrapInSubroute`) and the deny-path precedent at `:1663-1692`. Insert a maintenance branch BEFORE the normal gate/proxy assembly: when `route.MaintenanceConfig != nil && !route.Disabled`, build a subroute with two inner routes and `continue` (like the deny path), keeping `metricsHandler` first in the 503 inner route so it's counted, and copying the deny path's cert-subject registration block (`:1676-1689`) so the host still issues a cert and `:443` stays alive.

The subroute (adapt map-building to the file's existing `map[string]any` style):
```go
// bypass inner route: listed IPs → the normal proxy subroute.
bypassRoute := map[string]any{
	"match":    []map[string]any{{"client_ip": map[string]any{"ranges": route.MaintenanceConfig.BypassIPs}}},
	"handle":   []map[string]any{ /* the normal proxy handler subroute — reuse the same proxyHandler built at :1254/:1709 */ },
	"terminal": true,
}
// 503 inner route: everyone else. metrics first so the 503 is metered.
body := buildMaintenanceBody(maintenanceHTML, route.MaintenanceConfig.RetryAfterSeconds)
staticResp := map[string]any{
	"handler":     "static_response",
	"status_code": 503,
	"body":        body,
	"headers": map[string]any{
		"Content-Type": []string{"text/html; charset=utf-8"},
	},
}
if route.MaintenanceConfig.RetryAfterSeconds > 0 {
	staticResp["headers"].(map[string]any)["Retry-After"] = []string{strconv.Itoa(route.MaintenanceConfig.RetryAfterSeconds)}
}
maintRoute := map[string]any{"handle": []map[string]any{metricsHandler, staticResp}}
// wrap the two inner routes in a subroute as the terminal handler for this host route
```
Only emit the bypass route when `len(BypassIPs) > 0` (an empty ranges list is a no-op matcher; simplest is to omit the bypass inner route entirely when there are no bypass IPs, so all traffic hits the 503). `maintenanceHTML` = the stored page HTML if non-empty else `arenetDefaultMaintenancePage`; thread the stored HTML into the emitter the same way error-page bodies reach it (IMPLEMENTER: confirm whether the manager reads `GetMaintenancePageConfig` directly or receives it via buildOpts — mirror the error-template path).

- [ ] **Step 5: Run to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ -run TestBuildConfigJSON_MaintenanceRoute -v`
Expected: PASS.

- [ ] **Step 6: Run the existing caddymgr suite (no regression)**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ 2>&1 | tail -5`
Expected: all pass (the existing LoadsCleanly / ForwardAuth / etc. still green).

- [ ] **Step 7: Commit**

```bash
git add internal/caddymgr/manager.go internal/caddymgr/maintenance.go internal/caddymgr/maintenance_test.go
git commit -m "feat(caddymgr): emit maintenance route (503 static_response + client_ip bypass)"
```

---

### Task 5: caddymgr — thread the stored maintenance HTML into emission

**Files:**
- Modify: `internal/caddymgr/manager.go` (where the manager reads settings before building config)
- Modify: `internal/caddymgr/maintenance.go` if a sanitize call is needed
- Test: extend `internal/caddymgr/maintenance_test.go`

**Interfaces:**
- Consumes: `(*Store).GetMaintenancePageConfig` (Task 2); `SanitizeErrorPageBody` (error_pages.go:201).
- Produces: the emitter uses the operator's stored HTML (sanitized) when present, else the branded default.

**Note:** ONLY do this task if Task 4 stubbed the HTML source (e.g. hardcoded the default). If Task 4 already threaded the real stored HTML, fold this into Task 4 and skip. The implementer of Task 4 should report which; the controller decides whether Task 5 is needed.

- [ ] **Step 1: Write the failing test**

```go
func TestBuildConfigJSON_MaintenanceUsesStoredPage(t *testing.T) {
	// Store a custom page, build config for a maintenance route,
	// assert the custom HTML (post-sanitize) appears in the 503 body
	// and the {arenet.maintenance.retry_after} sentinel is replaced by 300.
	// (IMPLEMENTER: use the same buildConfigJSON harness; set the stored
	// page via the same seam the emitter reads — GetMaintenancePageConfig
	// or buildOpts.MaintenanceHTML.)
	// custom page contains: <p>Retry in {arenet.maintenance.retry_after}s</p>
	// assert body contains "Retry in 300s" and NOT the raw sentinel.
}
```

- [ ] **Step 2-5:** Run-fail, implement the sanitize+substitute wiring (`SanitizeErrorPageBody(stored.HTML)` then `buildMaintenanceBody`), run-pass, commit `feat(caddymgr): serve the operator's stored maintenance page`.

---

### Task 6: API — maintenance state endpoints + wire-field

**Files:**
- Modify: `internal/api/routes.go` (register 2 endpoints ~338; add `toggleRouteMaintenance` mirroring `toggleRouteDisabled` ~1978; map MaintenanceConfig in createRoute + updateRoute)
- Modify: `internal/api/handler.go` (routeRequest struct + routeResponse)
- Test: `internal/api/routes_maintenance_test.go` (create)

**Interfaces:**
- Consumes: `storage.MaintenanceConfig` (Task 1); `audit.ActionRouteMaintenanceOn/Off` (Task 3).
- Produces: `POST /routes/{id}/maintenance`, `POST /routes/{id}/maintenance/off`; `routeRequest.MaintenanceConfig`; `routeResponse.MaintenanceConfig`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/api/routes_maintenance_test.go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

func maintBody(host, extra string) string {
	return `{"host":"` + host + `","upstreams":[{"url":"http://u:1","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"off"` + extra + `}`
}

// The exact create-with-maintenance payload the frontend sends must NOT 400.
func TestCreateRoute_WithMaintenanceConfig(t *testing.T) {
	env := newTestEnv(t, false)
	body := maintBody("m.example.com", `,"maintenanceConfig":{"retryAfterSeconds":300,"bypassIps":["10.0.0.5"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s; want 201 (maintenanceConfig must be accepted)", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].MaintenanceConfig == nil || got[0].MaintenanceConfig.RetryAfterSeconds != 300 {
		t.Errorf("stored MaintenanceConfig = %+v; want RetryAfterSeconds 300", got[0].MaintenanceConfig)
	}
}

func TestMaintenanceEndpoint_On_SetsConfig(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "on.example.com", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+created.ID+"/maintenance", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.MaintenanceConfig == nil {
		t.Fatal("MaintenanceConfig nil after /maintenance; want defaults set")
	}
	if got.MaintenanceConfig.RetryAfterSeconds != 300 {
		t.Errorf("default RetryAfterSeconds = %d; want 300", got.MaintenanceConfig.RetryAfterSeconds)
	}
}

func TestMaintenanceEndpoint_Off_ClearsConfig(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "off.example.com", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
		MaintenanceConfig: &storage.MaintenanceConfig{RetryAfterSeconds: 300},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+created.ID+"/maintenance/off", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.MaintenanceConfig != nil {
		t.Errorf("MaintenanceConfig = %+v after /off; want nil (clear-on-off)", got.MaintenanceConfig)
	}
}

func TestUpdateRoute_PreservesMaintenanceOnEdit(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "edit.example.com", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
		MaintenanceConfig: &storage.MaintenanceConfig{RetryAfterSeconds: 120, BypassIPs: []string{"10.0.0.1"}},
	})
	body := maintBody("edit.example.com", `,"maintenanceConfig":{"retryAfterSeconds":120,"bypassIps":["10.0.0.1"]}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.MaintenanceConfig == nil || got.MaintenanceConfig.RetryAfterSeconds != 120 {
		t.Errorf("MaintenanceConfig after edit = %+v; want RetryAfterSeconds 120", got.MaintenanceConfig)
	}
	_ = json.Marshal // keep import
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run 'TestCreateRoute_WithMaintenance|TestMaintenanceEndpoint|TestUpdateRoute_PreservesMaintenance' -v`
Expected: FAIL — 400 "unknown field maintenanceConfig" (wire gap) + endpoints 404.

- [ ] **Step 3: Add the wire field**

In `internal/api/handler.go`, add to `routeRequest` (near `Disabled bool`):
```go
	MaintenanceConfig *storage.MaintenanceConfig `json:"maintenanceConfig,omitempty"`
```
And to `routeResponse`:
```go
	MaintenanceConfig *storage.MaintenanceConfig `json:"maintenanceConfig,omitempty"`
```
(Confirm `storage` is imported in handler.go; it is, per CertInfoReader. If routeResponse is built by `toResponse`, populate `MaintenanceConfig: r.MaintenanceConfig` there.)

- [ ] **Step 4: Map it in createRoute + updateRoute**

In `internal/api/routes.go`, in BOTH the createRoute `newRoute := storage.Route{...}` (~1403) and updateRoute `newRoute := storage.Route{...}` (~1881), add:
```go
		MaintenanceConfig: req.MaintenanceConfig,
```

- [ ] **Step 5: Add the endpoints + toggle helper**

In `internal/api/routes.go`, register in the admin group (after the enable route ~339):
```go
				r.Post("/routes/{id}/maintenance", h.enterMaintenance)
				r.Post("/routes/{id}/maintenance/off", h.exitMaintenance)
```
Add, mirroring `toggleRouteDisabled` (read it at ~1978-2057 for the exact GetRoute→mutate→UpdateRoute→ReloadFromStore→rollback→appendAudit shape; use the REAL helper names `writeJSON`/`h.appendAudit`/`h.caddy.ReloadFromStore` confirmed in the cert-delete work — NOT writeJSONWithHint for a plain 200):
```go
// toggleRouteMaintenance enters (on=true) or exits (on=false) maintenance.
// Enter with no prior config applies defaults; exit clears the config
// (clear-on-off). Mirrors toggleRouteDisabled: mutate, reload, roll back
// on reload failure, audit. Does NOT compute a last-HTTPS hint — a
// maintenance route stays emitted so :443 survives.
func (h *Handler) toggleRouteMaintenance(w http.ResponseWriter, r *http.Request, on bool) {
	id := chi.URLParam(r, "id")
	// GetRoute → previous; build next: on ? (reuse previous.MaintenanceConfig if non-nil else &storage.MaintenanceConfig{RetryAfterSeconds:300}) : nil
	// UpdateRoute(next); ReloadFromStore; on failure UpdateRoute(previous) and 500;
	// appendAudit(on ? ActionRouteMaintenanceOn : ActionRouteMaintenanceOff);
	// writeJSON(w, http.StatusOK, routeResponse-for-next)
}
func (h *Handler) enterMaintenance(w http.ResponseWriter, r *http.Request) { h.toggleRouteMaintenance(w, r, true) }
func (h *Handler) exitMaintenance(w http.ResponseWriter, r *http.Request)  { h.toggleRouteMaintenance(w, r, false) }
```
IMPLEMENTER: fill the body by copying `toggleRouteDisabled` verbatim and swapping the mutation (Disabled → MaintenanceConfig) + the audit action + dropping the last-HTTPS hint. Confirm every helper name against `toggleRouteDisabled` before finalizing.

- [ ] **Step 6: Run to verify they pass**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run 'TestCreateRoute_WithMaintenance|TestMaintenanceEndpoint|TestUpdateRoute_PreservesMaintenance' -v`
Expected: PASS (4 tests).

- [ ] **Step 7: Commit**

```bash
git add internal/api/routes.go internal/api/handler.go internal/api/routes_maintenance_test.go
git commit -m "feat(api): maintenance state endpoints + MaintenanceConfig wire-field"
```

---

### Task 7: API — global maintenance page GET/PUT

**Files:**
- Modify: `internal/api/routes.go` (register GET viewer ~164 + PUT admin ~345)
- Create: `internal/api/maintenance_page.go` (handlers)
- Test: `internal/api/maintenance_page_test.go` (create)

**Interfaces:**
- Consumes: `(*Store).GetMaintenancePageConfig` / `PutMaintenancePageConfig` (Task 2); `SanitizeErrorPageBody`.
- Produces: `GET /api/v1/settings/maintenance-page` → `{html}`; `PUT /api/v1/settings/maintenance-page` (admin) accepts `{html}`, sanitizes, persists.

- [ ] **Step 1: Write failing tests** — GET on fresh store returns `{"html":""}` (200); PUT admin persists + GET echoes; PUT sanitizes a `<script>` out; PUT non-admin → 403. (Mirror the error-templates handler tests in `internal/api/error_templates_test.go` for the harness.)

- [ ] **Step 2-5:** Run-fail; implement handlers (GET reads config; PUT decodes `{html}`, runs `SanitizeErrorPageBody`, `PutMaintenancePageConfig`, then `ReloadFromStore` so live maintenance routes pick up the new page); register routes (GET in the viewer group, PUT in the admin group); run-pass; commit `feat(api): global maintenance-page GET/PUT endpoints`.

---

### Task 8: Frontend — `RouteStateControl.svelte` component

**Files:**
- Create: `web/frontend/src/lib/components/RouteStateControl.svelte`
- Modify: `web/frontend/src/lib/api/client.ts` (or the routes client): add `enterMaintenance(id)`, `exitMaintenance(id)` calling the 2 endpoints
- Modify: `web/frontend/src/lib/i18n/locales/{en,fr}.json` (3 state labels)
- Test: `web/frontend/src/lib/components/RouteStateControl.test.ts` (create)

**Interfaces:**
- Produces: `<RouteStateControl value={"active"|"maintenance"|"disabled"} onchange={(next)=>...} />` — a 3-segment radiogroup, filled semantic color + icon per state.

- [ ] **Step 1: Write the failing test** — render with `value="active"`, assert 3 radio segments with the state labels and the active one `aria-checked="true"`; click the "maintenance" segment → `onchange("maintenance")` fires. (Reuse the vitest+@testing-library/svelte pattern from `Toggle`'s neighbors.)

- [ ] **Step 2-5:** Run-fail; implement the component (mirror `Toggle.svelte`'s controlled `value` + `onchange` + `role="radiogroup"`/`role="radio"` + keyboard nav, but 3 FIXED states with per-state icon play/wrench/power and semantic fill `--status-up`/`--status-warn`/`--status-down` — do NOT import/extend Toggle); add the client methods; add i18n `routes.state.{active,maintenance,disabled}` EN+FR (parity guard); run-pass; `npm run build`; commit `feat(web): RouteStateControl 3-state segmented control`.

---

### Task 9: Frontend — wire the control into /routes + maintenance form section

**Files:**
- Modify: `web/frontend/src/routes/routes/+page.svelte` (replace the enable/disable ghost button with `<RouteStateControl>`; add a "Maintenance" section to the edit form; strengthen the disabled badge; visible column header; keep last-HTTPS warning for Disabled ONLY)
- Modify: `web/frontend/src/lib/i18n/locales/{en,fr}.json` (maintenance form labels)
- Test: `web/frontend/src/routes/routes/page.test.ts` (extend)

**Interfaces:**
- Consumes: `RouteStateControl` (Task 8); `enterMaintenance`/`exitMaintenance`/`disableRoute`/`enableRoute` clients; `maintenanceConfig` on the form model.

- [ ] **Step 1: Write failing tests** — (a) a route renders `RouteStateControl` reflecting its state (active/maintenance/disabled derived from `disabled` + `maintenanceConfig`); (b) selecting "maintenance" calls `enterMaintenance` and refreshes; (c) selecting "active" from maintenance calls `exitMaintenance`; (d) the edit form shows a Maintenance section (Retry-After input + bypass IP list) seeded from `route.maintenanceConfig`; (e) switching the LAST TLS route to Disabled shows the last-HTTPS warning, switching it to Maintenance does NOT.

- [ ] **Step 2-5:** Run-fail; implement (derive state = `disabled ? 'disabled' : maintenanceConfig ? 'maintenance' : 'active'`; onchange routes to the right endpoint; edit-form Maintenance section binds `formData.maintenanceConfig` with `{retryAfterSeconds, bypassIps[]}`, seeded in openEdit and shipped in the payload — WIRE-FIELD: the form must send `maintenanceConfig`; the disabled-only warning gate); strengthen badge (amber/red variant); visible "State" column header; run-pass; `npm run build`; commit `feat(web): 3-state control + maintenance form on the routes page`.

---

### Task 10: Frontend — Settings → Error Pages "Maintenance" tab

**Files:**
- Modify: `web/frontend/src/routes/settings/error-pages/+page.svelte` (add a Maintenance tab/section editing the global page)
- Modify: `web/frontend/src/lib/api/error-templates.ts` (or a new client): `getMaintenancePage()`, `putMaintenancePage(html)`
- Modify: `web/frontend/src/lib/i18n/locales/{en,fr}.json` (tab + editor labels)
- Test: `web/frontend/src/routes/settings/error-pages/page.test.ts` (extend, if present)

**Interfaces:**
- Consumes: `GET/PUT /settings/maintenance-page` (Task 7); the existing `HtmlEditor.svelte`.

- [ ] **Step 1: Write failing test** — the Error Pages settings page shows a "Maintenance" tab; it loads the current page HTML; editing + save calls `putMaintenancePage`; a "reset to default" clears to empty (branded default). (Reuse the settings error-pages test harness if one exists; else a minimal render+interaction test.)

- [ ] **Step 2-5:** Run-fail; implement (a Maintenance tab reusing `HtmlEditor.svelte` + a preview, bound to `getMaintenancePage`/`putMaintenancePage`; document the `{arenet.maintenance.retry_after}` placeholder in the editor help); i18n EN+FR; run-pass; `npm run build`; commit `feat(web): Settings maintenance-page editor tab`.

---

### Task 11: Smoke (verification-only, no commit) + manual live-serve doc

**Files:**
- Create: `docs/smoke-test-maintenance.md` (the manual curl-2-IPs procedure)

- [ ] **Step 1: Backend gates**

Run:
```
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET
go vet ./...
go build ./...
go test -race ./internal/storage/ ./internal/audit/ ./internal/caddymgr/ ./internal/api/
```
Expected: all clean/green (internal/api -race may be slow; note in ledger if left to CI).

- [ ] **Step 2: Frontend gates**

Run:
```
cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend
npx vitest run src/lib/components/RouteStateControl.test.ts src/routes/routes/page.test.ts src/lib/i18n/index.test.ts
npm run build
```
Expected: pass + build clean.

- [ ] **Step 3: Write the manual live-serve smoke doc**

Create `docs/smoke-test-maintenance.md` modeled on `docs/smoke-test-step-i.md`: build the real binary, boot `--dev` with a real upstream, create a maintenance route with a bypass CIDR, then `curl` asserting (a) from a NON-listed IP → `503` + `Retry-After: 300` + the maintenance HTML body; (b) from a listed IP (bypass CIDR) → the real upstream 200; (c) `:443` still handshakes for the maintenance host (cert issued). Mark it as the mandatory CLAUDE.md live-serve check (caddy.Validate provisions but does not serve).

- [ ] **Step 4: Commit the doc**

```bash
git add docs/smoke-test-maintenance.md
git commit -m "docs: manual live-serve smoke for maintenance mode"
```

---

## Self-Review

**1. Spec coverage:** MaintenanceConfig field (T1) ✓; global page singleton (T2) ✓; audit actions (T3) ✓; Caddy emission 503+client_ip bypass, priority, metrics-first, cert-subject (T4) ✓; stored page + sanitize + Retry-After substitution (T5, foldable into T4) ✓; state endpoints + wire-field + clear-on-off + defaults + disabled-only warning (T6) ✓; global page GET/PUT + sanitize (T7) ✓; RouteStateControl 3-state (T8) ✓; routes page wiring + maintenance form + badge + warning gate (T9) ✓; settings maintenance tab (T10) ✓; smoke incl. mandatory live-serve (T11) ✓. No ACME revocation concept here; N/A. No enum refactor of Disabled (two fields) ✓.

**2. Placeholder scan:** T4/T5/T7/T8/T9/T10 carry explicit "IMPLEMENTER: read X first / confirm helper names against toggleRouteDisabled / mirror the error-templates harness" directives rather than inventing helper names — intentional (the cert-delete work proved the plan's guessed names — writeJSONWithHint — were wrong; every Go handler task must confirm against the real code). `arenetDefaultMaintenancePage` HTML body is left for the implementer to author mirroring `arenetDefaultErrorPages` (a branded-page authoring task, not a placeholder — the structure to copy is named). These are directed scaffolding, not TBDs.

**3. Type consistency:** `MaintenanceConfig{RetryAfterSeconds int, BypassIPs []string}` used identically in T1 (def), T4 (emit), T6 (API). `maintenanceConfig` JSON key consistent Go↔TS (T1/T6/T8/T9). `GetMaintenancePageConfig`/`PutMaintenancePageConfig` consistent T2/T5/T7. `enterMaintenance`/`exitMaintenance` (Go handlers T6) vs client `enterMaintenance`/`exitMaintenance` (TS T8) — same names, intentional. Audit `ActionRouteMaintenanceOn/Off` T3→T6.

**Known adaptation points (flagged for implementers, not gaps):** the exact API helper names (`writeJSON`/`h.appendAudit`/`h.caddy.ReloadFromStore`) and test-env fields (`env.store`/`env.router`) must be confirmed against the live package per task (established real in cert-delete work); the maintenance-HTML→emitter seam (direct store read vs buildOpts) must be confirmed in T4/T5; whether T5 is separate or folded into T4 is the controller's call based on T4's report.
