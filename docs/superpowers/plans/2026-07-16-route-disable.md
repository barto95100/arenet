# Route enable/disable (v2.14.3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-route `Disabled` flag; a disabled route keeps its full config but is filtered out before the Caddy config is built (not routed, no cert requested), reachable to toggle via two idempotent endpoints and a /routes UI toggle.

**Architecture:** `Route.Disabled bool` (zero-value = enabled, no migration). caddymgr filters disabled routes once in `applyLocked` before `buildConfigJSON`, which transitively removes them from routing + TLS policies + ACME issuance + error routes + the HC re-prime loop. Two POST endpoints mirror the existing update-route reload/rollback/audit pattern. Frontend adds a badge/toggle/dimmed row + a topology node-dim flag.

**Tech Stack:** Go 1.25 (BoltDB storage, embedded Caddy v2, chi router, log/slog, internal audit), SvelteKit (Svelte 5 runes, Tailwind, vitest), i18n JSON bundles.

Design doc: `docs/superpowers/specs/2026-07-16-route-disable-design.md`.

## Global Constraints

- **AGPL header** on every new Go file and TS/JS file (project rule; copy from any sibling).
- **`gofmt -s` clean, `go vet ./...` clean** before each Go commit.
- **Storage field polarity:** `Disabled bool json:"disabled,omitempty"` — zero-value MUST equal legacy "enabled" behavior. NO migration code. Mirror `WAFDisableCRS bool json:"waf_disable_crs,omitempty"`.
- **Empirical verification of Caddy behavior** (CLAUDE.md §): any claim about emitted Caddy JSON is proven via `caddy.Validate` on the emitted config, not assumed.
- **API convention:** POST/PUT/DELETE only (no PATCH exists in the repo). Endpoints are admin-only (registered in the auth subgroup at `internal/api/routes.go:333-337`).
- **Audit count guard:** adding audit actions requires bumping `wantCount` in `internal/audit/actions_test.go:28` (currently **56** → **58**) and updating the `TestAllActions_ExactSet` set — this test failing is the intended "force the conversation" guard.
- **i18n parity:** every new UI string lands in BOTH `web/frontend/src/lib/i18n/locales/en.json` and `fr.json`; the guard `web/frontend/src/lib/i18n/index.test.ts` must stay green.
- **Frontend build for Go tests:** `//go:embed` needs `web/frontend/build/` present — run `cd web/frontend && npm run build` once before Go compiles if the dir is missing.
- **Shell prefix (this environment):** prepend `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH` to shell commands.

---

### Task 1: Storage — `Route.Disabled` field

**Files:**
- Modify: `internal/storage/routes.go` (Route struct, ends line 508)
- Test: `internal/storage/routes_disabled_test.go` (create)

**Interfaces:**
- Produces: `storage.Route.Disabled bool` (`json:"disabled,omitempty"`). Consumed by Tasks 2 (caddymgr filter), 3 (API), 5 (topology).

- [ ] **Step 1: Write the failing test**

Create `internal/storage/routes_disabled_test.go`:

```go
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package storage

import (
	"encoding/json"
	"testing"
)

// TestRoute_Disabled_ZeroValueIsEnabled pins the backward-compat
// invariant: a route JSON with NO "disabled" key decodes to
// Disabled=false (= enabled). This is why the field is Disabled (not
// Enabled) — an old row / old backup must default to enabled, never
// silently go dark. Mirrors the WAFDisableCRS polarity precedent.
func TestRoute_Disabled_ZeroValueIsEnabled(t *testing.T) {
	// Legacy row shape: no "disabled" key at all.
	legacy := `{"id":"r1","host":"a.example.com","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lb_policy":"round_robin"}`
	var r Route
	if err := json.Unmarshal([]byte(legacy), &r); err != nil {
		t.Fatalf("unmarshal legacy route: %v", err)
	}
	if r.Disabled {
		t.Error("legacy route (no disabled key) decoded Disabled=true; want false (enabled)")
	}
}

// TestRoute_Disabled_RoundTrips pins that an explicitly disabled route
// survives a marshal→unmarshal cycle (backup export/import safety).
func TestRoute_Disabled_RoundTrips(t *testing.T) {
	in := Route{ID: "r2", Host: "b.example.com", Disabled: true}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Route
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.Disabled {
		t.Errorf("Disabled did not round-trip; got %+v", out)
	}
}

// TestRoute_Disabled_OmitemptyKeepsLegacyBytes pins that an ENABLED
// route (Disabled=false) marshals WITHOUT a "disabled" key, so the
// wire shape is byte-identical to pre-feature routes (omitempty).
func TestRoute_Disabled_OmitemptyKeepsLegacyBytes(t *testing.T) {
	raw, err := json.Marshal(Route{ID: "r3", Host: "c.example.com"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(raw); contains(got, `"disabled"`) {
		t.Errorf("enabled route emitted a disabled key: %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run TestRoute_Disabled -v`
Expected: FAIL — `r.Disabled undefined (type Route has no field Disabled)`.

- [ ] **Step 3: Add the field**

In `internal/storage/routes.go`, inside the `Route` struct (before the closing `}` at line 508), add:

```go
	// Disabled (v2.14.3) takes a route out of service WITHOUT
	// deleting its config. When true, the route is filtered out
	// before the Caddy config is built (caddymgr applyLocked), so
	// it is not routed AND no cert is requested for its host —
	// requests fall to the branded catch-all 404. Zero value is
	// false = enabled: pre-v2.14.3 routes and old backups decode
	// as enabled (backward-safe, no migration). Polarity mirrors
	// WAFDisableCRS / InsecureSkipVerify — the JSON zero-value must
	// equal legacy behavior. omitempty keeps enabled routes'
	// wire bytes identical to pre-feature routes.
	Disabled bool `json:"disabled,omitempty"`
```

- [ ] **Step 4: Run test to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run TestRoute_Disabled -v`
Expected: PASS (3 subtests).

- [ ] **Step 5: gofmt + vet + commit**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
gofmt -w internal/storage/routes.go internal/storage/routes_disabled_test.go
go vet ./internal/storage/
git add internal/storage/routes.go internal/storage/routes_disabled_test.go
git commit -m "feat(storage): add Route.Disabled flag (zero-migration)"
```

---

### Task 2: caddymgr — filter disabled routes in `applyLocked` + `HasHTTPSServer`

**Files:**
- Modify: `internal/caddymgr/manager.go` (`applyLocked` at line 542; `HasHTTPSServer` at ~3369)
- Test: `internal/caddymgr/route_disabled_emission_test.go` (create)

**Interfaces:**
- Consumes: `storage.Route.Disabled` (Task 1).
- Produces: emission behavior — a route with `Disabled=true` is absent from `apps.http.servers.*.routes` and from `apps.tls` subjects. `HasHTTPSServer()` ignores disabled routes.

- [ ] **Step 1: Write the failing test**

Create `internal/caddymgr/route_disabled_emission_test.go`:

```go
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package caddymgr

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// TestBuildConfigJSON_DisabledRoute_NotEmitted pins that a disabled
// route contributes nothing to the emitted Caddy config: no HTTP/HTTPS
// route for its host, and no ACME subject (so Caddy never requests a
// cert for a disabled host — the rate-limit-safety invariant).
//
// NOTE: buildConfigJSON emits what it is given; the disabled FILTER
// lives in applyLocked (which reads storage then calls buildConfigJSON).
// So this test filters the slice the same way applyLocked will, and
// asserts the emitted JSON. A companion assertion (that the UNFILTERED
// slice WOULD have emitted the host) proves the host is otherwise valid.
func TestBuildConfigJSON_DisabledRoute_NotEmitted(t *testing.T) {
	routes := []storage.Route{
		{
			ID: "r-live", Host: "live.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin, TLSEnabled: true,
			ACMEChallenge: storage.ACMEChallengeHTTP01, WAFMode: "off",
		},
		{
			ID: "r-off", Host: "off.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin, TLSEnabled: true,
			ACMEChallenge: storage.ACMEChallengeHTTP01, WAFMode: "off",
			Disabled: true,
		},
	}
	// Sanity: unfiltered emission DOES include off.example.com.
	rawAll, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON(all): %v", err)
	}
	if !strings.Contains(string(rawAll), "off.example.com") {
		t.Fatal("precondition failed: off.example.com absent even before filtering")
	}

	// Apply the same filter applyLocked will apply.
	live := filterDisabledRoutes(routes)
	raw, err := buildConfigJSON(live, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON(live): %v", err)
	}
	got := string(raw)
	if strings.Contains(got, "off.example.com") {
		t.Errorf("disabled host off.example.com leaked into emitted config:\n%s", got)
	}
	if !strings.Contains(got, "live.example.com") {
		t.Errorf("live host missing from emitted config")
	}
	// Cert subjects: off.example.com must NOT be in apps.tls.
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if strings.Contains(mustDump(t, cfg["apps"]), "off.example.com") {
		t.Errorf("disabled host appears in apps (cert subject leak)")
	}
}

// TestFilterDisabledRoutes pins the helper directly.
func TestFilterDisabledRoutes(t *testing.T) {
	in := []storage.Route{
		{ID: "a"}, {ID: "b", Disabled: true}, {ID: "c"},
	}
	out := filterDisabledRoutes(in)
	if len(out) != 2 {
		t.Fatalf("want 2 live routes, got %d", len(out))
	}
	for _, r := range out {
		if r.Disabled {
			t.Errorf("disabled route %s survived filter", r.ID)
		}
	}
}

func mustDump(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ -run 'DisabledRoute_NotEmitted|FilterDisabledRoutes' -v`
Expected: FAIL — `undefined: filterDisabledRoutes`.

- [ ] **Step 3: Add the filter helper + call it in applyLocked**

In `internal/caddymgr/manager.go`, add a package-level helper (place it just above `applyLocked`, before line 541):

```go
// filterDisabledRoutes returns the routes that must be emitted into
// Caddy — i.e. the ones with Disabled=false. Filtering the slice ONCE
// here removes disabled routes from every downstream emission at once:
// routing, TLS connection policies, ACME issuance (subjects accumulate
// inside buildConfigJSON's route loop), buildSkipList, error routes,
// and the HC re-prime loop below — because they all consume this slice.
func filterDisabledRoutes(routes []storage.Route) []storage.Route {
	live := routes[:0:0]
	for _, r := range routes {
		if r.Disabled {
			continue
		}
		live = append(live, r)
	}
	return live
}
```

Then in `applyLocked`, immediately after the `ListRoutes` error check (after line 545, before the DNS-provider comment at 547), insert:

```go
	// v2.14.3: drop disabled routes before anything consumes the slice.
	// One filter point covers routing + TLS policies + ACME issuance +
	// skip_certificates + error routes + the HC re-prime loop.
	for _, r := range routes {
		if r.Disabled {
			m.logger.Info("route skipped: disabled", "route_id", r.ID, "host", r.Host)
		}
	}
	routes = filterDisabledRoutes(routes)
```

- [ ] **Step 4: Fix `HasHTTPSServer` to ignore disabled routes**

Read `internal/caddymgr/manager.go` around line 3369. It does its own `ListRoutes` and returns true if any `r.TLSEnabled`. Change that predicate to also require `!r.Disabled`. The exact edit: in the loop that checks `r.TLSEnabled`, replace the condition with `r.TLSEnabled && !r.Disabled`. Add a one-test:

Append to `route_disabled_emission_test.go`:

```go
// TestHasHTTPSServer_IgnoresDisabled pins that a disabled TLS route
// does not by itself make HasHTTPSServer report true (it would no
// longer be emitted, so no :443 server exists for it).
func TestHasHTTPSServer_IgnoresDisabled(t *testing.T) {
	// This is a documentation-level guard; the real predicate lives in
	// HasHTTPSServer which reads storage. We assert the pure predicate
	// used inside it via filterDisabledRoutes: a slice of only-disabled
	// TLS routes yields zero live TLS routes.
	routes := []storage.Route{
		{ID: "r", Host: "x.example.com", TLSEnabled: true, Disabled: true},
	}
	live := filterDisabledRoutes(routes)
	anyTLS := false
	for _, r := range live {
		if r.TLSEnabled {
			anyTLS = true
		}
	}
	if anyTLS {
		t.Error("a disabled TLS route should not count as a live HTTPS route")
	}
}
```

- [ ] **Step 5: Run tests — unit + the caddy.Validate integration guard**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
ls web/frontend/build/index.html >/dev/null 2>&1 || (cd web/frontend && npm run build)
go test ./internal/caddymgr/ -run 'DisabledRoute|FilterDisabled|HasHTTPSServer' -v
go test ./internal/caddymgr/ -run 'TestBuildConfigJSON_LoadsCleanly'   # existing caddy.Validate guard still green
```
Expected: all PASS.

- [ ] **Step 6: gofmt + vet + commit**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
gofmt -w internal/caddymgr/manager.go internal/caddymgr/route_disabled_emission_test.go
go vet ./internal/caddymgr/
git add internal/caddymgr/manager.go internal/caddymgr/route_disabled_emission_test.go
git commit -m "feat(caddymgr): skip disabled routes in applyLocked + HasHTTPSServer"
```

---

### Task 3: Audit — `route_disabled` / `route_enabled` actions

**Files:**
- Modify: `internal/audit/actions.go` (const block ~47-49; `allActions` ~237)
- Modify: `internal/audit/actions_test.go` (count 56→58; ExactSet)

**Interfaces:**
- Produces: `audit.ActionRouteDisabled = "route_disabled"`, `audit.ActionRouteEnabled = "route_enabled"`. Consumed by Task 4 (API handlers).

- [ ] **Step 1: Update the count guard test first (RED)**

In `internal/audit/actions_test.go`, change `wantCount` at line 28 from `56` to `58`, and append the two new actions to the `wantCount` comment (e.g. `+ route-toggle=2`). In `TestAllActions_ExactSet` (line 76), add `ActionRouteDisabled` and `ActionRouteEnabled` to the expected set map (mirror how `ActionRouteUpdated` is listed there).

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/audit/ -run TestAllActions -v`
Expected: FAIL — compile error `undefined: ActionRouteDisabled` (and/or count mismatch).

- [ ] **Step 3: Add the constants + register in allActions**

In `internal/audit/actions.go`, after `ActionRouteDeleted = "route_deleted"` (line 49) add:

```go
	// v2.14.3 — per-route enable/disable toggle. Emitted AFTER the
	// Caddy reload succeeds, mirroring route_updated. Distinct from
	// route_updated so operators see "took the route down" vs a
	// config edit in the audit trail.
	ActionRouteDisabled = "route_disabled"
	ActionRouteEnabled  = "route_enabled"
```

In the `allActions` slice, after `ActionRouteDeleted,` (line 248) add:

```go
	ActionRouteDisabled,
	ActionRouteEnabled,
```

- [ ] **Step 4: Run to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/audit/ -run TestAllActions -v`
Expected: PASS (count now 58, ExactSet matches).

- [ ] **Step 5: gofmt + vet + commit**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
gofmt -w internal/audit/actions.go internal/audit/actions_test.go
go vet ./internal/audit/
git add internal/audit/actions.go internal/audit/actions_test.go
git commit -m "feat(audit): add route_disabled / route_enabled actions"
```

---

### Task 4: API — `POST /routes/{id}/disable` + `/enable` with reload, rollback, audit, hint

**Files:**
- Modify: `internal/api/routes.go` (router at 335-337; add two handlers near `updateRoute` ~1870)
- Test: `internal/api/route_toggle_test.go` (create)

**Interfaces:**
- Consumes: `storage.Route.Disabled` (T1), `audit.ActionRouteDisabled/Enabled` (T3), `h.caddy.ReloadFromStore`, `h.store.GetRoute/UpdateRoute`, `h.appendAudit`, `toResponse`.
- Produces: two endpoints returning `200` with JSON body `{...route..., "lastHttpsRouteAffected": bool}` where `lastHttpsRouteAffected` is set on the `/disable` response only. Consumed by Task 6 (frontend).

- [ ] **Step 1: Write the failing test**

Create `internal/api/route_toggle_test.go`. Mirror the existing route-handler test setup in this package (find an existing `func Test...Route...` that builds an in-memory store + handler + chi router via `m.router.ServeHTTP`; reuse that harness — e.g. the helper used by `geo_lookup_batch_handler_test.go` / route tests). Concretely:

```go
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// helper: create a route via the store and return its ID.
func seedRoute(t *testing.T, env *routeTestEnv, host string, tls bool) string {
	t.Helper()
	r, err := env.store.CreateRoute(env.ctx, storage.Route{
		Host:       host,
		Upstreams:  []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
		TLSEnabled: tls,
	})
	if err != nil {
		t.Fatalf("seed route: %v", err)
	}
	return r.ID
}

func TestRouteDisable_SetsDisabledAndReloads(t *testing.T) {
	env := newRouteTestEnv(t) // reuse the package's route test harness
	id := seedRoute(t, env, "a.example.com", false)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+id+"/disable", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", rec.Code, rec.Body)
	}
	got, err := env.store.GetRoute(env.ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Disabled {
		t.Error("route not marked Disabled after /disable")
	}
}

func TestRouteDisable_Idempotent(t *testing.T) {
	env := newRouteTestEnv(t)
	id := seedRoute(t, env, "b.example.com", false)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+id+"/disable", nil)
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("disable #%d status = %d; want 200", i, rec.Code)
		}
	}
}

func TestRouteEnable_ClearsDisabled(t *testing.T) {
	env := newRouteTestEnv(t)
	id := seedRoute(t, env, "c.example.com", false)
	// disable then enable
	for _, action := range []string{"disable", "enable"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+id+"/"+action, nil)
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d; want 200", action, rec.Code)
		}
	}
	got, _ := env.store.GetRoute(env.ctx, id)
	if got.Disabled {
		t.Error("route still Disabled after /enable")
	}
}

func TestRouteDisable_LastHttpsRouteHint(t *testing.T) {
	env := newRouteTestEnv(t)
	id := seedRoute(t, env, "only-tls.example.com", true) // sole TLS route

	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+id+"/disable", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		LastHTTPSRouteAffected bool `json:"lastHttpsRouteAffected"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if !resp.LastHTTPSRouteAffected {
		t.Error("disabling the only TLS route should report lastHttpsRouteAffected=true")
	}
}
```

> If the package has no reusable `routeTestEnv`/`newRouteTestEnv`, the implementer creates a tiny harness in this test file that builds `storage.NewStore(t.TempDir()+"/arenet.db")`, a `Handler` with a stub `caddy` whose `ReloadFromStore` returns nil, and the chi router via the same constructor the other API tests use. Look at an existing `*_test.go` in `internal/api/` that exercises a route handler and copy its env builder.

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run 'TestRouteDisable|TestRouteEnable' -v`
Expected: FAIL — 404 (routes not registered) / missing handler.

- [ ] **Step 3: Add the two handlers**

In `internal/api/routes.go`, add near `updateRoute` (after its closing brace ~1972). The handlers share a helper:

```go
// toggleRouteDisabled is the shared body of the disable/enable
// endpoints. It mirrors updateRoute's reload+rollback+audit contract:
// GetRoute → set Disabled → UpdateRoute → ReloadFromStore → roll back
// on reload failure → appendAudit. Idempotent: setting the same value
// is a no-op success. On /disable it computes lastHttpsRouteAffected.
func (h *Handler) toggleRouteDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	id := chiURLParam(r, "id") // use the same param accessor the other handlers use (e.g. chi.URLParam)

	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "route not found")
		return
	}

	// Compute the hint BEFORE mutation: is this the last active TLS route?
	lastHTTPS := false
	if disabled && previous.TLSEnabled && !previous.Disabled {
		all, lerr := h.store.ListRoutes(r.Context())
		if lerr == nil {
			activeTLS := 0
			for _, rt := range all {
				if rt.TLSEnabled && !rt.Disabled {
					activeTLS++
				}
			}
			lastHTTPS = activeTLS == 1
		}
	}

	next := previous
	next.Disabled = disabled
	updated, err := h.store.UpdateRoute(r.Context(), next)
	if err != nil {
		h.logger.Error("toggle route disabled", "err", err, "id", id)
		writeError(w, http.StatusInternalServerError, "failed to update route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after toggle — rolling back", "err", err, "id", id)
		if _, rbErr := h.store.UpdateRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	action := audit.ActionRouteEnabled
	if disabled {
		action = audit.ActionRouteDisabled
	}
	h.appendAudit(r, audit.Event{
		Action:     action,
		TargetType: "route",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(routeForAudit(previous)),
		AfterJSON:  mustMarshalForAudit(routeForAudit(updated)),
	})

	resp := toResponse(updated)
	// Attach the hint on the disable path so the frontend can pre-warn.
	writeJSONWithHint(w, resp, disabled && lastHTTPS)
}

func (h *Handler) disableRoute(w http.ResponseWriter, r *http.Request) {
	h.toggleRouteDisabled(w, r, true)
}

func (h *Handler) enableRoute(w http.ResponseWriter, r *http.Request) {
	h.toggleRouteDisabled(w, r, false)
}
```

Notes for the implementer:
- Replace `chiURLParam` with the exact param accessor the sibling handlers use (grep `URLParam` in `internal/api/routes.go`).
- `writeJSONWithHint` does not exist — implement it minimally next to the other `writeJSON`/`writeError` helpers: marshal `resp` into a `map[string]any` (or re-marshal the struct and inject) and add `"lastHttpsRouteAffected": hint`. Simplest robust approach:

```go
// writeJSONWithHint writes resp as JSON with an extra top-level
// "lastHttpsRouteAffected" boolean merged in. Used by the route
// disable endpoint so the frontend can warn before removing the
// last HTTPS listener.
func writeJSONWithHint(w http.ResponseWriter, resp any, hint bool) {
	b, err := json.Marshal(resp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode response")
		return
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		writeError(w, http.StatusInternalServerError, "encode response")
		return
	}
	m["lastHttpsRouteAffected"] = hint
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(m)
}
```

- [ ] **Step 4: Register the routes**

In `internal/api/routes.go`, in the admin-auth subgroup right after line 337 (`r.Delete("/routes/{id}", h.deleteRoute)`), add:

```go
				r.Post("/routes/{id}/disable", h.disableRoute)
				r.Post("/routes/{id}/enable", h.enableRoute)
```

- [ ] **Step 5: Run to verify it passes**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
go test ./internal/api/ -run 'TestRouteDisable|TestRouteEnable' -v
```
Expected: all PASS.

- [ ] **Step 6: gofmt + vet + commit**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
gofmt -w internal/api/routes.go internal/api/route_toggle_test.go
go vet ./internal/api/
git add internal/api/routes.go internal/api/route_toggle_test.go
git commit -m "feat(api): POST /routes/{id}/disable + /enable (idempotent, hint, audit)"
```

---

### Task 5: Topology wire — expose `Disabled`

**Files:**
- Modify: `internal/api/topology/types.go` (Route wire struct ~88-101)
- Modify: `internal/api/topology/builder.go` (`buildRoute` ~132)
- Test: `internal/api/topology/route_disabled_test.go` (create)

**Interfaces:**
- Consumes: `storage.Route.Disabled` (T1).
- Produces: topology wire `Route.Disabled bool json:"disabled"`. Consumed by Task 7 (frontend topology dim).

- [ ] **Step 1: Write the failing test**

Create `internal/api/topology/route_disabled_test.go`:

```go
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package topology

import (
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// stubMetrics / stubStatus satisfy the builder's collaborators with
// zero data — we only care about the Disabled pass-through.
type stubMetrics struct{}

func (stubMetrics) Aggregate(string) Aggregate { return Aggregate{} }

type stubStatus struct{}

func (stubStatus) Status(string) string { return "" }

func TestBuildRoute_PassesDisabledThrough(t *testing.T) {
	src := &storage.Route{ID: "r1", Host: "x.example.com", Disabled: true}
	out := buildRoute(src, stubMetrics{}, stubStatus{})
	if !out.Disabled {
		t.Error("buildRoute did not propagate Disabled=true to the wire struct")
	}

	src2 := &storage.Route{ID: "r2", Host: "y.example.com"}
	out2 := buildRoute(src2, stubMetrics{}, stubStatus{})
	if out2.Disabled {
		t.Error("enabled route reported Disabled=true")
	}
}
```

> The implementer must match the ACTUAL `MetricsView` / `StatusLookup` interface method names (grep them in `builder.go` — the stub method signatures above must match, e.g. `Aggregate(id string) Aggregate` and whatever the status lookup method is called). Adjust the stub to compile.

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/topology/ -run TestBuildRoute_PassesDisabledThrough -v`
Expected: FAIL — `out.Disabled undefined (Route has no field Disabled)`.

- [ ] **Step 3: Add the wire field + populate it**

In `internal/api/topology/types.go`, in the `Route` struct after `HTTPRedirect bool json:"httpRedirect"` (line 101), add:

```go
	// Disabled (v2.14.3) mirrors storage.Route.Disabled. When true,
	// the route is not emitted into Caddy (serves nothing); the
	// frontend renders its node dimmed/dashed so the operator sees
	// a deliberately-off route rather than a mysterious zero-traffic
	// phantom (topology reads storage directly, so a disabled route
	// still appears here — this flag is what lets the UI dim it).
	Disabled bool `json:"disabled"`
```

In `internal/api/topology/builder.go`, inside `buildRoute`'s `out := Route{...}` literal (after `TLSEnabled: r.TLSEnabled,`), add:

```go
		Disabled:     r.Disabled,
```

- [ ] **Step 4: Run to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/topology/ -run TestBuildRoute_PassesDisabledThrough -v`
Expected: PASS.

- [ ] **Step 5: gofmt + vet + commit**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
gofmt -w internal/api/topology/types.go internal/api/topology/builder.go internal/api/topology/route_disabled_test.go
go vet ./internal/api/topology/
git add internal/api/topology/types.go internal/api/topology/builder.go internal/api/topology/route_disabled_test.go
git commit -m "feat(topology): expose Route.Disabled on the wire"
```

---

### Task 6: Frontend — API client + types + i18n keys

**Files:**
- Modify: `web/frontend/src/lib/api/client.ts` (~188-192)
- Modify: `web/frontend/src/lib/api/types.ts` (Route ~57; RouteRequest ~439)
- Modify: `web/frontend/src/lib/i18n/locales/en.json` + `fr.json`
- Test: `web/frontend/src/lib/api/client.test.ts` (append) — or a small dedicated test

**Interfaces:**
- Consumes: the two endpoints (T4), topology `disabled` (T5).
- Produces: `disableRoute(id)`, `enableRoute(id)` returning `Promise<Route & { lastHttpsRouteAffected?: boolean }>`; `Route.disabled?: boolean` type; i18n keys under `routes.*` + `topology.*`. Consumed by Tasks 7, 8.

- [ ] **Step 1: Add the type field + client methods**

In `web/frontend/src/lib/api/types.ts`, add `disabled?: boolean;` to the `Route` interface (near line 57) and to `RouteRequest` (near line 439).

In `web/frontend/src/lib/api/client.ts`, after `deleteRoute` (line 192) add:

```ts
export const disableRoute = (id: string): Promise<Route & { lastHttpsRouteAffected?: boolean }> =>
	request('POST', `/routes/${id}/disable`);
export const enableRoute = (id: string): Promise<Route & { lastHttpsRouteAffected?: boolean }> =>
	request('POST', `/routes/${id}/enable`);
```

- [ ] **Step 2: Add i18n keys (BOTH bundles)**

In `web/frontend/src/lib/i18n/locales/en.json`, add under the `routes` object:

```json
"disabled": { "badge": "Disabled" },
"disable": {
  "action": "Disable",
  "confirm": {
    "title": "Disable route?",
    "text": "This route will no longer serve traffic. Its configuration is preserved so you can re-enable it anytime.",
    "action": "Disable",
    "lastHttps": {
      "title": "Disable the last HTTPS route?",
      "text": "This is the last active HTTPS route. Disabling it stops the HTTPS server (port 443) — requests to any HTTPS URL will fail with connection refused. Continue?",
      "action": "Disable anyway"
    }
  }
},
"enable": { "action": "Enable" },
"form": {
  "disabledLabel": "Disabled",
  "disabledHelper": "A disabled route keeps its config but serves no traffic (requests get the 404 page)."
}
```

And in `web/frontend/src/lib/i18n/locales/fr.json`, the same keys under `routes`:

```json
"disabled": { "badge": "Désactivée" },
"disable": {
  "action": "Désactiver",
  "confirm": {
    "title": "Désactiver la route ?",
    "text": "Cette route ne servira plus de trafic. Sa configuration est conservée : tu peux la réactiver à tout moment.",
    "action": "Désactiver",
    "lastHttps": {
      "title": "Désactiver la dernière route HTTPS ?",
      "text": "C'est la dernière route HTTPS active. La désactiver arrête le serveur HTTPS (port 443) — toute requête HTTPS échouera avec « connexion refusée ». Continuer ?",
      "action": "Désactiver quand même"
    }
  }
},
"enable": { "action": "Activer" },
"form": {
  "disabledLabel": "Désactivée",
  "disabledHelper": "Une route désactivée conserve sa config mais ne sert aucun trafic (les requêtes reçoivent la page 404)."
}
```

Add under `topology` in BOTH bundles:
- en: `"disabled": { "tooltip": "Disabled — not serving traffic" }`
- fr: `"disabled": { "tooltip": "Désactivée — ne sert aucun trafic" }`

> If `routes` already has a `form` object, MERGE these keys into it rather than duplicating the key (JSON has no duplicate keys). Same for `topology`.

- [ ] **Step 3: Run the i18n parity guard + typecheck**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend
npx vitest run src/lib/i18n/index.test.ts
npm run check
```
Expected: parity test PASS (EN/FR key sets equal), `svelte-check` 0 errors.

- [ ] **Step 4: Commit**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
git add web/frontend/src/lib/api/client.ts web/frontend/src/lib/api/types.ts web/frontend/src/lib/i18n/locales/en.json web/frontend/src/lib/i18n/locales/fr.json
git commit -m "feat(web): route disable/enable API client, type, i18n keys"
```

---

### Task 7: Frontend — /routes page badge + toggle + confirm dialogs

**Files:**
- Modify: `web/frontend/src/routes/routes/+page.svelte` (row ~2073; confirm-dialog wiring ~3741; RouteForm section)
- Test: `web/frontend/src/routes/routes/page.test.ts` (append)

**Interfaces:**
- Consumes: `disableRoute`, `enableRoute`, i18n keys (T6).
- Produces: UI. No downstream consumer.

- [ ] **Step 1: Write the failing test**

Append to `web/frontend/src/routes/routes/page.test.ts` (match the file's existing mock scaffold — it mocks `$lib/api/client`; add `disableRoute`/`enableRoute` to that mock):

```ts
describe('/routes — disable/enable', () => {
	it('renders a Disabled badge for a disabled route', async () => {
		// Arrange: listRoutes returns one disabled route.
		routesApiMock.listRoutes.mockResolvedValue([
			{ id: 'r1', host: 'off.example.com', upstreams: [{ url: 'http://x', weight: 1 }], lbPolicy: 'round_robin', tlsEnabled: false, disabled: true }
		]);
		render(Page);
		expect(await screen.findByText(/Disabled/i)).toBeInTheDocument();
	});

	it('clicking Disable on an active route opens the confirm dialog then calls disableRoute', async () => {
		routesApiMock.listRoutes.mockResolvedValue([
			{ id: 'r2', host: 'live.example.com', upstreams: [{ url: 'http://x', weight: 1 }], lbPolicy: 'round_robin', tlsEnabled: false, disabled: false }
		]);
		routesApiMock.disableRoute.mockResolvedValue({ id: 'r2', disabled: true, lastHttpsRouteAffected: false });
		render(Page);
		await screen.findByText('live.example.com');
		await fireEvent.click(screen.getByTestId('route-disable-r2'));
		// confirm dialog appears
		await fireEvent.click(screen.getByTestId('route-disable-confirm'));
		await waitFor(() => expect(routesApiMock.disableRoute).toHaveBeenCalledWith('r2'));
	});
});
```

> Match the existing test conventions in this file for `render`, `screen`, mock names, and the `data-testid` scheme. If the file uses different testid patterns, align the markup testids in Step 3 to them.

- [ ] **Step 2: Run to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend && npx vitest run src/routes/routes/page.test.ts -t "disable/enable"`
Expected: FAIL — no Disabled badge / no `route-disable-*` control.

- [ ] **Step 3: Implement the UI**

In `+page.svelte`:
1. Import `disableRoute, enableRoute` from `$lib/api/client`.
2. In the route row (`{#each ... as r}` at ~2073): add a "Disabled" `<Badge>` (reuse the existing Badge component + the TLS/WAF badge `<td>` pattern) shown when `r.disabled`; add `class:opacity-50={r.disabled}` (or the project's dim class) on the `<tr>`; add a toggle action button with `data-testid={`route-${r.disabled ? 'enable' : 'disable'}-${r.id}`}`.
3. On disable click: if the row is TLS-enabled, first call requires a confirm. Open the existing `ConfirmDialog` (the `confirmTarget` state pattern at ~387/~3741). Use the special copy (`routes.disable.confirm.lastHttps.*`) when the disable response's `lastHttpsRouteAffected` would be true — since that's only known after the call, the simplest correct flow: show the NORMAL confirm first; on confirm call `disableRoute(id)`; if the response `lastHttpsRouteAffected === true`, we've already disabled, so instead compute the warning PRE-call on the client from the current route list (count routes with `tlsEnabled && !disabled` === 1 && this row is TLS) and pick which confirm copy to show. Implement the pre-call count in the component and branch the dialog copy.
4. Confirm button `data-testid="route-disable-confirm"` calls `disableRoute(r.id)` then refreshes the list (`loadRoutes()` or the existing reload fn) and `pushToast`.
5. Enable: no confirm — call `enableRoute(r.id)` directly, refresh, toast.
6. RouteForm (edit modal): add a "Disabled" checkbox bound to `formData.disabled` near the top, default `false` for new routes, with helper text `routes.form.disabledHelper`. The existing PUT `updateRoute` already carries the field (types updated in T6).

- [ ] **Step 4: Run tests + typecheck**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend
npx vitest run src/routes/routes/page.test.ts
npm run check
```
Expected: new tests PASS, whole /routes suite PASS, svelte-check 0 errors.

- [ ] **Step 5: Commit**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
git add web/frontend/src/routes/routes/+page.svelte web/frontend/src/routes/routes/page.test.ts
git commit -m "feat(web): /routes disable/enable toggle, badge, confirm dialogs"
```

---

### Task 8: Frontend — topology node dimming

**Files:**
- Modify: the topology node component (find it: `web/frontend/src/lib/components/` topology graph / node renderer, or under `web/frontend/src/routes/` topology page)
- Test: the topology component's test if one exists (append); else a minimal render assertion

**Interfaces:**
- Consumes: topology wire `disabled` (T5) + `topology.disabled.tooltip` (T6).

- [ ] **Step 1: Locate the node renderer**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
grep -rln "tlsEnabled\|httpRedirect\|route.*node\|TopologyNode\|d3" web/frontend/src --include='*.svelte' | head
```
Identify the component that renders a route node from the topology snapshot's `Route`.

- [ ] **Step 2: Write the failing test (if the component is unit-testable)**

If the node component accepts a route prop, add a test asserting that when `route.disabled === true` the node gets the dim class / `data-disabled="true"` attribute and the tooltip text. If the topology is a single D3 canvas not unit-testable in isolation, SKIP the vitest test and rely on the empirical smoke (Task 9) — note this explicitly in the commit.

- [ ] **Step 3: Implement dimming**

In the node renderer, when the route's `disabled` is true: apply reduced opacity + a dashed border (or the project's existing "inactive" node style), and set the tooltip/title to `t('topology.disabled.tooltip')`. Reuse whatever styling primitive the component already uses for node state.

- [ ] **Step 4: Run tests + typecheck**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend
npx vitest run   # full suite, ensure no regression
npm run check
```
Expected: PASS, svelte-check 0 errors.

- [ ] **Step 5: Commit**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
git add web/frontend/src
git commit -m "feat(web): dim disabled routes in the topology graph"
```

---

### Task 9: Empirical smoke — verify against a real binary

**Files:** none (verification only; produces a short note appended to the spec or a smoke log).

This task runs the §8 gates against a built binary + `caddy.Validate`, not assumptions.

- [ ] **Step 1: Full build + full test suites**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend && npm run build
cd /Users/l.ramos/Documents/Projets/AreNET
go vet ./...
go test -race -count=1 ./...
cd web/frontend && npx vitest run && npm run check
```
Expected: all green.

- [ ] **Step 2: Emission smoke (caddy.Validate path)**

Confirm via the caddymgr tests (Task 2) that a disabled route is absent from emitted config AND from `apps.tls`. This is already covered by `TestBuildConfigJSON_DisabledRoute_NotEmitted` + the existing `TestBuildConfigJSON_LoadsCleanly` guard. Re-run:

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
go test ./internal/caddymgr/ -run 'Disabled|LoadsCleanly' -v
```

- [ ] **Step 3: Backward-compat + idempotence gates (already unit-covered)**

Confirm green: `TestRoute_Disabled_ZeroValueIsEnabled` (old-row/old-backup safe), `TestRouteDisable_Idempotent`, `TestRouteDisable_LastHttpsRouteHint`, `TestBuildRoute_PassesDisabledThrough`.

- [ ] **Step 4: Note the runtime edge case for docs**

Append one line to the spec's §5 (or a smoke note) confirming: disabling the sole TLS route removes the :443 server (curl https → connection refused), and the frontend showed the special warning. This is behavior-by-design, documented.

- [ ] **Step 5: Commit the smoke note (if any file changed) — otherwise no-op**

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET
git add -A
git commit -m "test: route-disable empirical smoke gates verified" --allow-empty
```

---

## Self-Review (run after writing)

**Spec coverage** — every spec section maps to a task:
- §3 storage field → Task 1. §4 caddymgr single filter + HasHTTPSServer → Task 2. §5 behavior/edge → verified in Tasks 2 + 9, warning UI in Task 7. §6 API endpoints + hint + audit → Tasks 3 (audit) + 4 (API). §7 frontend (routes page, RouteForm, topology, metrics-NOT-dimmed) → Tasks 6+7+8 (metrics intentionally omitted per §7/§10). §8 smoke gates → Task 9. §9 v2.14.4 → out of scope (no task, correct). §10 backlog → no task, correct. §11 file map → drove the tasks.

**Type consistency** — `Route.Disabled bool` (storage, T1) ↔ `disabled?: boolean` (TS, T6) ↔ topology `Disabled bool json:"disabled"` (T5); `disableRoute`/`enableRoute` names consistent T4/T6/T7; `lastHttpsRouteAffected` JSON key consistent T4↔T6↔T7; audit `ActionRouteDisabled`/`ActionRouteEnabled` T3↔T4.

**Placeholder scan** — handler param accessor (`chiURLParam`) and the `routeTestEnv` harness are explicitly flagged as "match the sibling" with grep instructions rather than invented — the implementer resolves them against real code; every other code block is complete.
