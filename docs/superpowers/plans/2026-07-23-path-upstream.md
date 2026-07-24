# Per-Path Upstream Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a `PathRule` optionally route its matched sub-path to its own upstream pool (URLs + LB policy + health-check) instead of the route's shared pool, turning path-rules from protection-only into routing+protection.

**Architecture:** Add 3 optional fields to `storage.PathRule` (Upstreams/LBPolicy/HealthCheck, all omitempty → migration-free). Extract the monolithic `reverse_proxy` handler builder in `caddymgr/manager.go` into a reusable `buildReverseProxyHandler` that the route and each path-rule call with their own pool; the error-branding `handle_response` is built once and shared. Wire the 3 fields through the API path-rule mapper (`handler.go`) with the same preserve-on-empty discipline as basic-auth. Add a collapsed "Upstream spécifique" disclosure to `PathRulesSection.svelte` (lean fields, no upstream-testing machinery).

**Tech Stack:** Go 1.25 (caddymgr emission, BoltDB storage, net/http API), Caddy v2.11.3 (embedded), SvelteKit/Svelte 5 + TypeScript frontend, Vitest.

## Global Constraints

- **AGPL header** on every new Go and TS/Svelte file (see CLAUDE.md).
- **Migration-free:** the 3 new `PathRule` fields are `omitempty`; a route with no per-path upstream stores byte-identically to v2.22.0.
- **Byte-identical Caddy JSON (§3.1, NON-NEGOTIABLE):** routes without per-path upstream must emit JSON byte-identical to pre-refactor. A dedicated golden test guards this.
- **`go test -race ./internal/caddymgr/` before PR** ([[caddymgr_race_test_gate]]): the active-HC × nested-subroute combo races inside Caddy v2.11.3. In the single canonical `TestBuildConfigJSON_LoadsCleanly` fixture (one `caddy.Validate` per package — never add a 2nd), keep an active-HC route and a subroute-heavy (path-rule) route SEPARATE — never active-HC-per-path on a route that already has nested subroutes.
- **Wire-field-gap** ([[route_wire_field_gap_regression]]): each new PathRule field must traverse the path-rule wire mapper's request struct + create/update map + response, or `DisallowUnknownFields` 400s the request.
- **Validation model (Q3):** a path-rule is valid if it declares at least ONE of {basic-auth, active IP-filter, non-empty upstream pool}. Pure routing (`/v1 → pool`, no protection) is valid.
- **Transport per pool (Q2):** a path pool's scheme (`http`/`https`) is independent of the route's; the transport `tls` block is deduced per pool from its own URLs. A pool must be same-scheme internally (reuse `validateSameSchemePool`).
- **Secrets:** path-rule basic-auth password is hashed server-side via `auth.HashRoutePassword`; the response never echoes password or hash. Upstream URLs / LB / HC are NOT secret and DO round-trip in the response.
- **i18n EN+FR parity** for every new UI string.
- **Version:** v2.23.0 (minor). No tag until operator go-ahead.

**Key existing types (verbatim from the codebase):**
- `storage.Upstream{ URL string; Weight int }` (routes.go:187)
- `storage.HealthCheck{ Enabled bool; URI, Method, Interval, Timeout string; ExpectStatus int; ExpectBody string; Passes, Fails int }` (routes.go:210) — NOTE the type is `HealthCheck`, not `HealthCheckConfig`.
- `storage.PathRule{ PathPrefix string; BasicAuth *BasicAuthRouteConfig; IPFilter *IPFilter }` (routes.go:99)
- `storage.validateSameSchemePool(pool []Upstream) error` (routes.go:741)
- Wire mirrors in `internal/api/handler.go`: `upstreamReq{URL,Weight}` (1072), `healthCheckReq{...}` (1544), `ipFilterReq{Mode,CIDRs,StatusCode}` (1113), `pathRuleReq{PathPrefix,BasicAuth,IPFilter}` (1151), `pathRuleBasicAuthReq{Username,Password}` (1145).
- Mappers: `mapPathRuleReqs(reqs []pathRuleReq, existing []storage.PathRule) ([]storage.PathRule, error)` (1174), `toPathRulesResp(rules []storage.PathRule) []pathRuleReq` (1874).
- Validation helpers (wire-typed): `validateUpstreamPool([]upstreamReq) error` (validation.go:112), `validateLBPolicy(string) error` (validation.go:223), `validateHealthCheck(healthCheckReq) error` (validation.go:258), `materialiseHealthCheck(healthCheckReq) healthCheckReq` (validation.go:311).
- Emission: `buildPathRulesSubroute(rules, proxyHandler, basicAuthBuilder)` (path_rules_emit.go:42), called at manager.go:1906–1917. The route `proxyHandler` is built inline at manager.go:1312–1600.
- Frontend: `sanitizePathRules(rules: PathRule[])` (web/frontend/src/lib/utils/path-rules.ts:53), `PathRulesSection.svelte` (174 lines), TS types `Upstream`/`HealthCheck`/`LBPolicy`/`PathRule` in `web/frontend/src/lib/api/types.ts`.

---

### Task 1: Storage — extend `PathRule` with upstream pool + validation

**Files:**
- Modify: `internal/storage/routes.go:99-139` (PathRule struct + Validate)
- Test: `internal/storage/routes_pathrule_upstream_test.go` (new)

**Interfaces:**
- Consumes: `storage.Upstream`, `storage.HealthCheck`, `storage.validateSameSchemePool`, `storage.LBPolicies`.
- Produces: extended `storage.PathRule` with `Upstreams []Upstream`, `LBPolicy string`, `HealthCheck *HealthCheck` (all json omitempty); `PathRule.Validate()` accepting upstream-only rules and rejecting the fully-empty rule + multi-scheme pools.

- [ ] **Step 1: Write the failing tests**

Create `internal/storage/routes_pathrule_upstream_test.go`:

```go
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package storage

import "testing"

func upstreamPool(urls ...string) []Upstream {
	out := make([]Upstream, len(urls))
	for i, u := range urls {
		out[i] = Upstream{URL: u, Weight: 1}
	}
	return out
}

func TestPathRule_Validate_UpstreamOnlyIsValid(t *testing.T) {
	// Pure routing: an upstream pool with NO protection is valid (Q3).
	pr := PathRule{
		PathPrefix: "/v1",
		Upstreams:  upstreamPool("http://api-a:8080"),
		LBPolicy:   LBPolicyRoundRobin,
	}
	if err := pr.Validate(); err != nil {
		t.Fatalf("upstream-only rule should be valid, got: %v", err)
	}
}

func TestPathRule_Validate_FullyEmptyIsRejected(t *testing.T) {
	// No basic-auth, no active IP filter, no upstream → still rejected.
	pr := PathRule{PathPrefix: "/x"}
	if err := pr.Validate(); err == nil {
		t.Fatal("fully-empty rule must be rejected")
	}
}

func TestPathRule_Validate_MultiSchemePoolRejected(t *testing.T) {
	pr := PathRule{
		PathPrefix: "/v1",
		Upstreams:  []Upstream{{URL: "http://a:8080", Weight: 1}, {URL: "https://b:8443", Weight: 1}},
		LBPolicy:   LBPolicyRoundRobin,
	}
	if err := pr.Validate(); err == nil {
		t.Fatal("mixed-scheme path pool must be rejected")
	}
}

func TestPathRule_Validate_HTTPSPoolDifferentFromRouteIsValid(t *testing.T) {
	// A path pool may be https even if (elsewhere) the route is http — the
	// PathRule itself only enforces same-scheme WITHIN its own pool (Q2).
	pr := PathRule{
		PathPrefix: "/legacy",
		Upstreams:  upstreamPool("https://old:8443"),
		LBPolicy:   LBPolicyRoundRobin,
	}
	if err := pr.Validate(); err != nil {
		t.Fatalf("https path pool should be valid on its own, got: %v", err)
	}
}

func TestPathRule_Validate_InvalidUpstreamURLRejected(t *testing.T) {
	pr := PathRule{
		PathPrefix: "/v1",
		Upstreams:  []Upstream{{URL: "://broken", Weight: 1}},
		LBPolicy:   LBPolicyRoundRobin,
	}
	if err := pr.Validate(); err == nil {
		t.Fatal("invalid upstream URL in path pool must be rejected")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run TestPathRule_Validate -v`
Expected: compile error (fields don't exist yet) or FAIL.

- [ ] **Step 3: Extend the struct**

In `internal/storage/routes.go`, replace the `PathRule` struct (lines 99-103):

```go
type PathRule struct {
	PathPrefix string                `json:"path_prefix"`
	BasicAuth  *BasicAuthRouteConfig `json:"basic_auth,omitempty"` // PasswordHash is a SECRET
	IPFilter   *IPFilter             `json:"ip_filter,omitempty"`
	// Per-path upstream routing (v2.23.0). When Upstreams is non-empty the
	// matched sub-path proxies to THIS pool instead of the route's. All
	// omitempty → a rule with no per-path pool stores byte-identically to
	// the pre-v2.23.0 shape (migration-free).
	Upstreams   []Upstream   `json:"upstreams,omitempty"`    // own pool; empty = inherit the route's
	LBPolicy    string       `json:"lb_policy,omitempty"`    // defaults to round_robin when pool non-empty
	HealthCheck *HealthCheck `json:"health_check,omitempty"` // own active HC for this path pool
}
```

- [ ] **Step 4: Extend `Validate`**

In `internal/storage/routes.go`, replace the protection-required check (lines 124-137). The new rule: valid if at least one of {basic-auth, active IP-filter, non-empty pool}; if a pool is present, validate every URL + same-scheme + weight; validate the HC when present.

```go
	hasUpstreams := len(p.Upstreams) > 0
	if p.BasicAuth == nil && (p.IPFilter == nil || !p.IPFilter.IsActive()) && !hasUpstreams {
		return fmt.Errorf("path_rule %q: must declare at least one of basic auth, IP filter, or an upstream", p.PathPrefix)
	}
	if p.BasicAuth != nil && p.BasicAuth.Username == "" {
		return fmt.Errorf("path_rule %q: basic auth requires a username", p.PathPrefix)
	}
	if p.BasicAuth != nil && p.BasicAuth.PasswordHash == "" {
		return fmt.Errorf("path_rule %q: basic auth requires a password hash", p.PathPrefix)
	}
	if p.IPFilter != nil {
		if err := p.IPFilter.Validate(); err != nil {
			return fmt.Errorf("path_rule %q: %w", p.PathPrefix, err)
		}
	}
	if hasUpstreams {
		for i, u := range p.Upstreams {
			if err := validateUpstreamURL(u.URL); err != nil {
				return fmt.Errorf("path_rule %q: upstreams[%d]: %w", p.PathPrefix, i, err)
			}
			if u.Weight < 1 {
				return fmt.Errorf("path_rule %q: upstreams[%d].weight must be >= 1", p.PathPrefix, i)
			}
		}
		if err := validateSameSchemePool(p.Upstreams); err != nil {
			return fmt.Errorf("path_rule %q: %w", p.PathPrefix, err)
		}
	}
	return nil
```

NOTE: confirm `validateUpstreamURL` is in package `storage` (it is used by `validateSameSchemePool`'s neighbourhood). If the per-URL validator lives only in the API layer, use `validateSameSchemePool` for scheme + rely on the API layer for per-URL syntax, and drop the per-URL loop here (adjust the `InvalidUpstreamURLRejected` test to target the API layer instead). Verify before implementing:
Run: `grep -n "func validateUpstreamURL\|func upstreamDial" internal/storage/*.go`

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/storage/ -run TestPathRule_Validate -v`
Expected: PASS (all 5).

- [ ] **Step 6: Full storage suite + vet**

Run: `go test ./internal/storage/ && go vet ./internal/storage/`
Expected: PASS, no vet warnings.

- [ ] **Step 7: Commit**

```bash
git add internal/storage/routes.go internal/storage/routes_pathrule_upstream_test.go
git commit -m "feat(path-upstream): storage PathRule gains optional upstream pool + validation"
```

---

### Task 2: API wire — thread upstream pool through path-rule mapper

**Files:**
- Modify: `internal/api/handler.go:1145-1210` (`pathRuleReq`, `mapPathRuleReqs`), `internal/api/handler.go:1874-1895` (`toPathRulesResp`)
- Test: `internal/api/routes_pathrule_upstream_test.go` (new)

**Interfaces:**
- Consumes: extended `storage.PathRule` (Task 1); existing `upstreamReq`, `healthCheckReq`, `validateUpstreamPool`, `validateLBPolicy`, `materialiseHealthCheck`, `validateHealthCheck`.
- Produces: `pathRuleReq` carrying `Upstreams []upstreamReq`, `LBPolicy string`, `HealthCheck *healthCheckReq`; `mapPathRuleReqs` maps + defaults them into storage; `toPathRulesResp` echoes them (non-secret).

- [ ] **Step 1: Write the failing test**

Create `internal/api/routes_pathrule_upstream_test.go`:

```go
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import "testing"

func TestMapPathRuleReqs_UpstreamPoolMapped(t *testing.T) {
	reqs := []pathRuleReq{{
		PathPrefix: "/v1",
		Upstreams:  []upstreamReq{{URL: "http://api-a:8080", Weight: 1}},
		LBPolicy:   "round_robin",
	}}
	out, err := mapPathRuleReqs(reqs, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(out) != 1 || len(out[0].Upstreams) != 1 || out[0].Upstreams[0].URL != "http://api-a:8080" {
		t.Fatalf("upstream pool not mapped: %+v", out)
	}
	if out[0].LBPolicy != "round_robin" {
		t.Fatalf("lb policy not mapped: %q", out[0].LBPolicy)
	}
}

func TestMapPathRuleReqs_UpstreamWeightAndLBDefaulted(t *testing.T) {
	// Weight 0 → 1; empty LBPolicy with a non-empty pool → round_robin.
	reqs := []pathRuleReq{{
		PathPrefix: "/v1",
		Upstreams:  []upstreamReq{{URL: "http://a:8080"}}, // weight omitted
	}}
	out, err := mapPathRuleReqs(reqs, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out[0].Upstreams[0].Weight != 1 {
		t.Fatalf("weight not defaulted to 1: %d", out[0].Upstreams[0].Weight)
	}
	if out[0].LBPolicy != "round_robin" {
		t.Fatalf("lb policy not defaulted: %q", out[0].LBPolicy)
	}
}

func TestMapPathRuleReqs_HealthCheckMapped(t *testing.T) {
	reqs := []pathRuleReq{{
		PathPrefix:  "/v1",
		Upstreams:   []upstreamReq{{URL: "http://a:8080", Weight: 1}},
		LBPolicy:    "round_robin",
		HealthCheck: &healthCheckReq{Enabled: true, URI: "/health"},
	}}
	out, err := mapPathRuleReqs(reqs, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out[0].HealthCheck == nil || !out[0].HealthCheck.Enabled || out[0].HealthCheck.URI != "/health" {
		t.Fatalf("health check not mapped: %+v", out[0].HealthCheck)
	}
	// Defaults must be materialised (Method/Interval/Timeout/Passes/Fails).
	if out[0].HealthCheck.Method == "" || out[0].HealthCheck.Interval == "" {
		t.Fatalf("health check defaults not materialised: %+v", out[0].HealthCheck)
	}
}

func TestToPathRulesResp_EchoesUpstreamNotSecrets(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/v1",
		Upstreams:  []storage.Upstream{{URL: "http://a:8080", Weight: 2}},
		LBPolicy:   "round_robin",
		BasicAuth:  &storage.BasicAuthRouteConfig{Username: "u", PasswordHash: "$argon2id$secret"},
	}}
	out := toPathRulesResp(rules)
	if len(out) != 1 || len(out[0].Upstreams) != 1 || out[0].Upstreams[0].URL != "http://a:8080" {
		t.Fatalf("upstream not echoed: %+v", out)
	}
	if out[0].Upstreams[0].Weight != 2 || out[0].LBPolicy != "round_robin" {
		t.Fatalf("lb/weight not echoed: %+v", out)
	}
	if out[0].BasicAuth != nil && out[0].BasicAuth.Password != "" {
		t.Fatalf("password must never be echoed")
	}
}
```

(Add `"github.com/barto95100/arenet/internal/storage"` to the test imports.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run 'TestMapPathRuleReqs|TestToPathRulesResp' -v`
Expected: compile error (fields don't exist) or FAIL.

- [ ] **Step 3: Extend `pathRuleReq`**

In `internal/api/handler.go`, replace `pathRuleReq` (lines 1151-1155):

```go
type pathRuleReq struct {
	PathPrefix string                `json:"pathPrefix"`
	BasicAuth  *pathRuleBasicAuthReq `json:"basicAuth,omitempty"`
	IPFilter   *ipFilterReq          `json:"ipFilter,omitempty"`
	// Per-path upstream routing (v2.23.0). Empty Upstreams = inherit the
	// route's pool. LBPolicy/HealthCheck are ignored when Upstreams is empty.
	Upstreams   []upstreamReq   `json:"upstreams,omitempty"`
	LBPolicy    string          `json:"lbPolicy,omitempty"`
	HealthCheck *healthCheckReq `json:"healthCheck,omitempty"`
}
```

- [ ] **Step 4: Extend `mapPathRuleReqs`**

In `internal/api/handler.go`, inside the `mapPathRuleReqs` loop (after the IPFilter block, before `out[i] = pr`, around line 1206), add the upstream mapping with weight + LB defaults + HC materialisation:

```go
		if len(r.Upstreams) > 0 {
			pool := make([]storage.Upstream, len(r.Upstreams))
			for j, u := range r.Upstreams {
				w := u.Weight
				if w == 0 {
					w = 1 // materialise default (storage validate() requires >= 1)
				}
				pool[j] = storage.Upstream{URL: u.URL, Weight: w}
			}
			pr.Upstreams = pool
			lb := r.LBPolicy
			if lb == "" {
				lb = storage.LBPolicyRoundRobin // default when a pool is present
			}
			pr.LBPolicy = lb
			if r.HealthCheck != nil && r.HealthCheck.Enabled {
				hc := materialiseHealthCheck(*r.HealthCheck)
				pr.HealthCheck = &storage.HealthCheck{
					Enabled:      hc.Enabled,
					URI:          hc.URI,
					Method:       hc.Method,
					Interval:     hc.Interval,
					Timeout:      hc.Timeout,
					ExpectStatus: hc.ExpectStatus,
					ExpectBody:   hc.ExpectBody,
					Passes:       hc.Passes,
					Fails:        hc.Fails,
				}
			}
		}
```

- [ ] **Step 5: Extend `toPathRulesResp`**

In `internal/api/handler.go`, inside the `toPathRulesResp` loop (after the IPFilter echo, before the loop ends, around line 1893), add:

```go
		if len(pr.Upstreams) > 0 {
			pool := make([]upstreamReq, len(pr.Upstreams))
			for j, u := range pr.Upstreams {
				pool[j] = upstreamReq{URL: u.URL, Weight: u.Weight}
			}
			out[i].Upstreams = pool
			out[i].LBPolicy = pr.LBPolicy
			if pr.HealthCheck != nil {
				out[i].HealthCheck = &healthCheckReq{
					Enabled:      pr.HealthCheck.Enabled,
					URI:          pr.HealthCheck.URI,
					Method:       pr.HealthCheck.Method,
					Interval:     pr.HealthCheck.Interval,
					Timeout:      pr.HealthCheck.Timeout,
					ExpectStatus: pr.HealthCheck.ExpectStatus,
					ExpectBody:   pr.HealthCheck.ExpectBody,
					Passes:       pr.HealthCheck.Passes,
					Fails:        pr.HealthCheck.Fails,
				}
			}
		}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/api/ -run 'TestMapPathRuleReqs|TestToPathRulesResp' -v`
Expected: PASS (all 4).

- [ ] **Step 7: Full api suite + vet**

Run: `go test ./internal/api/ && go vet ./internal/api/`
Expected: PASS, no vet warnings. (This also exercises the DisallowUnknownFields round-trip through existing create/update tests.)

- [ ] **Step 8: Commit**

```bash
git add internal/api/handler.go internal/api/routes_pathrule_upstream_test.go
git commit -m "feat(path-upstream): thread per-path upstream pool through the API wire mapper"
```

---

### Task 3: Emission refactor — extract `buildReverseProxyHandler` (byte-identity guard)

**Files:**
- Modify: `internal/caddymgr/manager.go:1312-1600` (extract the inline proxyHandler build)
- Create: `internal/caddymgr/reverse_proxy_emit.go` (the extracted builder)
- Test: `internal/caddymgr/reverse_proxy_emit_test.go` (new — byte-identity + unit)

**Interfaces:**
- Consumes: `storage.Upstream`, `storage.HealthCheck`, `storage.LBPolicy*`, `upstreamDial` (manager.go, existing).
- Produces:
  ```go
  // proxyPoolParams carries the PER-POOL inputs (route or path) to the
  // reverse_proxy builder. Route-invariant concerns (Host header, error
  // branding handle_response, flush_interval) are applied by the caller
  // or passed as shared arguments.
  type proxyPoolParams struct {
      Upstreams          []storage.Upstream
      LBPolicy           string
      HealthCheck        *storage.HealthCheck // nil = no active probe
      UsesHTTPS          bool
      InsecureSkipVerify bool
  }
  func buildReverseProxyHandler(p proxyPoolParams, sharedHandleResponse []map[string]any, flushInterval bool) (map[string]any, error)
  ```
  Returns the full `reverse_proxy` map (upstreams + load_balancing + Host header + transport-if-https + flush_interval-if-set + health_checks-if-enabled + handle_response=shared).

**This is the critical, 100%-traffic path. Refactor is behaviour-preserving: the route call must emit byte-identical JSON. A DEDICATED opus review gates this task.**

- [ ] **Step 1: Write the byte-identity golden test FIRST**

Create `internal/caddymgr/reverse_proxy_emit_test.go`. This test captures the CURRENT emitted route JSON (before refactor) as the golden reference, so the refactor is proven byte-identical. Use an existing config-build test helper if one exists (search first), else build a representative Route set.

Run first: `grep -n "func buildConfigJSON\|func TestBuildConfigJSON\|buildConfigJSON(" internal/caddymgr/*_test.go | head`

```go
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package caddymgr

import (
	"encoding/json"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// representativeRoutes covers the proxyHandler shape variants: plain http
// pool, multi-upstream weighted, https pool (transport), active health
// check, upload-streaming (flush_interval). NO per-path upstream — this is
// the pre-v2.23.0 surface whose emission must stay byte-identical.
func representativeRoutes() []storage.Route {
	return []storage.Route{
		{ID: "r1", Host: "plain.example.com", Upstreams: []storage.Upstream{{URL: "http://a:8080", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
		{ID: "r2", Host: "multi.example.com", Upstreams: []storage.Upstream{{URL: "http://a:8080", Weight: 2}, {URL: "http://b:8080", Weight: 3}}, LBPolicy: storage.LBPolicyWeightedRoundRobin},
		{ID: "r3", Host: "secure.example.com", Upstreams: []storage.Upstream{{URL: "https://a:8443", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
		{ID: "r4", Host: "hc.example.com", Upstreams: []storage.Upstream{{URL: "http://a:8080", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin, HealthCheck: storage.HealthCheck{Enabled: true, URI: "/health", Method: "GET", Interval: "10s", Timeout: "5s", Passes: 1, Fails: 1}},
	}
}

func TestBuildReverseProxyHandler_RouteEmissionByteIdentical(t *testing.T) {
	// GOLDEN: this captures the refactored output. Before committing the
	// refactor, run once against pre-refactor code to snapshot the golden
	// bytes into testdata/, then assert equality after the refactor.
	routes := representativeRoutes()
	cfg, err := buildConfigJSON(routes, buildOpts{}) // adjust to the real signature
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	got, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	golden := readGolden(t, "testdata/route_emission_golden.json") // helper below
	if string(got) != string(golden) {
		t.Fatalf("route emission changed — refactor is NOT byte-identical.\n got: %s\n want:%s", got, golden)
	}
}
```

Add a `readGolden`/`writeGolden` helper (or reuse the package's golden convention if one exists — search: `grep -rn "golden\|testdata" internal/caddymgr/*_test.go | head`).

IMPORTANT sequencing: (a) with the CURRENT (pre-refactor) code, run the test with a `-update` flag or a temporary `writeGolden` call to snapshot `testdata/route_emission_golden.json`; (b) commit the golden; (c) do the refactor; (d) the test must still pass. The golden is the proof.

- [ ] **Step 2: Snapshot the golden from pre-refactor code**

Temporarily add golden-writing, run:
Run: `go test ./internal/caddymgr/ -run TestBuildReverseProxyHandler_RouteEmissionByteIdentical` (writes testdata)
Then remove the write path so the test only asserts.
Expected: `testdata/route_emission_golden.json` created.

- [ ] **Step 3: Extract `buildReverseProxyHandler` into the new file**

Create `internal/caddymgr/reverse_proxy_emit.go` with the AGPL header. Move the proxyHandler assembly (manager.go:1312-1445 for upstreams/LB/Host/transport/flush/health, and the `handle_response` block 1566-1600 built by the caller and passed in). The builder takes `proxyPoolParams` + `sharedHandleResponse` + `flushInterval`. Emit exactly the same keys in the same insertion pattern (Go maps marshal by sorted key, so insertion order does not affect bytes — but KEEP the same keys/values). Reference the current code for the transport, health_checks, and load_balancing shapes verbatim.

- [ ] **Step 4: Rewire the route call site in manager.go**

At manager.go ~1312, replace the inline build with:

```go
		sharedHandleResponse := buildErrorBrandingHandleResponse(errorStatusCodes) // extract the 1566-1600 block into this helper too
		proxyHandler, err := buildReverseProxyHandler(proxyPoolParams{
			Upstreams:          r.Upstreams,
			LBPolicy:           r.LBPolicy,
			HealthCheck:        healthCheckPtr(r.HealthCheck), // &r.HealthCheck if Enabled else nil
			UsesHTTPS:          r.PoolUsesHTTPS(),
			InsecureSkipVerify: r.InsecureSkipVerify,
		}, sharedHandleResponse, r.UploadStreamingMode)
		if err != nil {
			return nil, fmt.Errorf("route %s (%s): %w", r.ID, r.Host, err)
		}
```

Preserve the Host-header set, the exact transport `{protocol:http, tls:{...}}` shape, and the `handle_response` two-block structure. Keep `errorStatusCodes` as the shared list.

- [ ] **Step 5: Run the byte-identity test + validate**

Run: `go test ./internal/caddymgr/ -run TestBuildReverseProxyHandler_RouteEmissionByteIdentical -v`
Expected: PASS (byte-identical). If it fails, the diff shows exactly what drifted — fix until identical.

- [ ] **Step 6: Full caddymgr suite (incl. LoadsCleanly) + race**

Run: `go test ./internal/caddymgr/ && go test -race ./internal/caddymgr/`
Expected: PASS both. The race run is mandatory before PR.

- [ ] **Step 7: Commit**

```bash
git add internal/caddymgr/reverse_proxy_emit.go internal/caddymgr/manager.go internal/caddymgr/reverse_proxy_emit_test.go internal/caddymgr/testdata/route_emission_golden.json
git commit -m "refactor(caddymgr): extract buildReverseProxyHandler (byte-identical route emission)"
```

---

### Task 4: Emission — per-path upstream in `buildPathRulesSubroute`

**Files:**
- Modify: `internal/caddymgr/path_rules_emit.go:42-76`
- Modify: `internal/caddymgr/manager.go:1906-1917` (pass the per-path proxy builder)
- Test: `internal/caddymgr/path_rules_upstream_emit_test.go` (new)

**Interfaces:**
- Consumes: `buildReverseProxyHandler` + `proxyPoolParams` (Task 3), the extended `storage.PathRule` (Task 1).
- Produces: a `buildPathRulesSubroute` that, for a rule with a non-empty `Upstreams`, emits ITS proxy (own pool/LB/HC/transport, shared branding) as the terminal handler; a rule with an empty pool keeps the route's `proxyHandler`; the catch-all keeps the route's `proxyHandler`.

**DEDICATED opus review gates this task** (transport-per-pool + shared handle_response + fail-closed IP-filter preserved).

- [ ] **Step 1: Write the failing tests**

Create `internal/caddymgr/path_rules_upstream_emit_test.go`:

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

// helper: emit the subroute for a route with the given path rules + a route
// proxy sentinel, and return the JSON string for substring assertions.
func emitPathSubrouteJSON(t *testing.T, rules []storage.PathRule) string {
	t.Helper()
	routeProxy := map[string]any{"handler": "reverse_proxy", "upstreams": []map[string]any{{"dial": "route-pool:80"}}}
	sub := buildPathRulesSubroute(rules, routeProxy, func(c storage.BasicAuthRouteConfig) map[string]any {
		return map[string]any{"handler": "authentication"}
	})
	b, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestPathRulesSubroute_RuleWithOwnUpstream(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/v1",
		Upstreams:  []storage.Upstream{{URL: "http://api-a:8080", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "api-a:8080") {
		t.Fatalf("path rule should proxy to its own upstream; got: %s", js)
	}
}

func TestPathRulesSubroute_RuleWithoutUpstreamUsesRoutePool(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/docs",
		BasicAuth:  &storage.BasicAuthRouteConfig{Username: "u", PasswordHash: "$h"},
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "route-pool:80") {
		t.Fatalf("protection-only rule must keep the route pool; got: %s", js)
	}
}

func TestPathRulesSubroute_CatchAllKeepsRoutePool(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/v1",
		Upstreams:  []storage.Upstream{{URL: "http://api-a:8080", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	// Both the path pool AND the route pool (catch-all) must appear.
	if !strings.Contains(js, "route-pool:80") {
		t.Fatalf("catch-all must keep the route pool; got: %s", js)
	}
}

func TestPathRulesSubroute_HTTPSPathPoolEmitsTransport(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/legacy",
		Upstreams:  []storage.Upstream{{URL: "https://old:8443", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "\"tls\"") {
		t.Fatalf("https path pool must emit a transport.tls block; got: %s", js)
	}
}

func TestPathRulesSubroute_IPBlockBeforeOwnUpstream(t *testing.T) {
	// fail-closed IP filter still gates BEFORE the path's own proxy.
	rules := []storage.PathRule{{
		PathPrefix: "/metrics",
		IPFilter:   &storage.IPFilter{Mode: storage.IPFilterModeAllow, CIDRs: []string{"10.0.0.0/8"}},
		Upstreams:  []storage.Upstream{{URL: "http://m:9090", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "static_response") || !strings.Contains(js, "m:9090") {
		t.Fatalf("expected both the IP 403 block and the own upstream; got: %s", js)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/caddymgr/ -run TestPathRulesSubroute -v`
Expected: FAIL (per-path upstream not emitted yet — rule proxies to route pool).

- [ ] **Step 3: Change `buildPathRulesSubroute` signature + logic**

In `internal/caddymgr/path_rules_emit.go`, add a per-path proxy resolver. The builder gains a closure that produces a rule's proxy (its own pool if present, else the route proxy):

```go
func buildPathRulesSubroute(
	rules []storage.PathRule,
	routeProxy map[string]any,
	basicAuthBuilder func(storage.BasicAuthRouteConfig) map[string]any,
	pathProxyBuilder func(storage.PathRule) (map[string]any, error), // NEW — nil-pool → routeProxy
) (map[string]any, error) {
	sorted := storage.SortPathRulesByPrefixLenDesc(rules)
	inner := make([]map[string]any, 0, len(sorted)+1)
	for _, pr := range sorted {
		handle := make([]map[string]any, 0, 3)
		if pr.IPFilter != nil && pr.IPFilter.IsActive() {
			if ipRoute := buildIPFilterRoute(*pr.IPFilter); ipRoute != nil {
				handle = append(handle, map[string]any{
					"handler": "subroute",
					"routes":  []map[string]any{ipRoute},
				})
			}
		}
		if pr.BasicAuth != nil {
			handle = append(handle, basicAuthBuilder(*pr.BasicAuth))
		}
		proxy, err := pathProxyBuilder(pr)
		if err != nil {
			return nil, err
		}
		handle = append(handle, proxy)
		inner = append(inner, map[string]any{
			"match":  []map[string]any{{"path": pathMatchers(pr.PathPrefix)}},
			"handle": handle,
		})
	}
	inner = append(inner, map[string]any{"handle": []map[string]any{routeProxy}})
	return map[string]any{"handler": "subroute", "routes": inner}, nil
}
```

(The signature now returns `(map[string]any, error)` — update the call site.)

- [ ] **Step 4: Wire the path proxy builder at the call site**

In `internal/caddymgr/manager.go` (~1906-1917), pass a builder that reuses `buildReverseProxyHandler` with the rule's own pool, falling back to `proxyHandler` when the pool is empty:

```go
		if len(r.PathRules) > 0 {
			pathRealm := fmt.Sprintf("Arenet route %s", r.Host)
			pathProxy := func(pr storage.PathRule) (map[string]any, error) {
				if len(pr.Upstreams) == 0 {
					return proxyHandler, nil // inherit the route pool
				}
				return buildReverseProxyHandler(proxyPoolParams{
					Upstreams:          pr.Upstreams,
					LBPolicy:           pr.LBPolicy,
					HealthCheck:        pr.HealthCheck, // already a pointer
					UsesHTTPS:          poolUsesHTTPS(pr.Upstreams), // small helper mirroring r.PoolUsesHTTPS()
					InsecureSkipVerify: r.InsecureSkipVerify,        // path pool inherits the route's TLS-verify posture
				}, sharedHandleResponse, r.UploadStreamingMode)
			}
			sub, err := buildPathRulesSubroute(r.PathRules, proxyHandler, func(c storage.BasicAuthRouteConfig) map[string]any {
				return buildBasicAuthHandlerFromConfig(c, pathRealm)
			}, pathProxy)
			if err != nil {
				return nil, fmt.Errorf("route %s (%s) path rules: %w", r.ID, r.Host, err)
			}
			handlers = append(handlers, sub)
		} else {
			handlers = append(handlers, proxyHandler)
		}
```

Add a package helper `poolUsesHTTPS(pool []storage.Upstream) bool` (mirrors the route predicate; check first whether `storage` already exposes one reusable on a bare pool — `grep -n "func.*PoolUsesHTTPS\|func poolUsesHTTPS" internal/**/*.go`). NOTE the decision: a path pool inherits the route's `InsecureSkipVerify` posture (no separate per-path toggle — YAGNI; documented in the spec's "no per-path transport UI").

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/caddymgr/ -run TestPathRulesSubroute -v`
Expected: PASS (all 5).

- [ ] **Step 6: Add per-path upstream to the LoadsCleanly fixture (SEPARATE from active-HC route) + full suite + race**

Extend the canonical `TestBuildConfigJSON_LoadsCleanly` fixture: add a route `pathupstream.example.com` carrying a path-rule WITH an upstream pool but **health-check DISABLED** (so no active-HC goroutine races the nested subroute — [[caddymgr_race_test_gate]]). Do NOT add active-HC-per-path to any subroute-heavy route in this fixture.

Run: `go test ./internal/caddymgr/ && go test -race ./internal/caddymgr/`
Expected: PASS both. Race run mandatory.

- [ ] **Step 7: Commit**

```bash
git add internal/caddymgr/path_rules_emit.go internal/caddymgr/manager.go internal/caddymgr/path_rules_upstream_emit_test.go
git commit -m "feat(path-upstream): emit per-path reverse_proxy pool (transport + HC + shared branding)"
```

---

### Task 5: Frontend types + `sanitizePathRules`

**Files:**
- Modify: `web/frontend/src/lib/api/types.ts:786` (PathRule interface)
- Modify: `web/frontend/src/lib/utils/path-rules.ts`
- Test: `web/frontend/src/lib/utils/path-rules.test.ts` (extend)

**Interfaces:**
- Consumes: existing `Upstream`, `HealthCheck`, `LBPolicy` TS types.
- Produces: `PathRule` gains `upstreams?: Upstream[]`, `lbPolicy?: LBPolicy`, `healthCheck?: HealthCheck`; `sanitizePathRules` treats a non-empty `upstreams` as active content (a pure-routing rule survives).

- [ ] **Step 1: Write the failing tests**

Extend `web/frontend/src/lib/utils/path-rules.test.ts`:

```ts
it('keeps a rule that has ONLY an upstream pool (pure routing)', () => {
	const rules = [
		{ pathPrefix: '/v1', upstreams: [{ url: 'http://a:8080', weight: 1 }], lbPolicy: 'round_robin' as const }
	];
	const out = sanitizePathRules(rules as any);
	expect(out).toHaveLength(1);
	expect(out[0].pathPrefix).toBe('/v1');
});

it('drops a rule with an EMPTY upstream pool and no protection', () => {
	const rules = [{ pathPrefix: '/v1', upstreams: [] }];
	const out = sanitizePathRules(rules as any);
	expect(out).toHaveLength(0);
});

it('keeps a rule with upstream + off-mode ipFilter and clears its residual cidrs', () => {
	const rules = [
		{ pathPrefix: '/v1', upstreams: [{ url: 'http://a:8080', weight: 1 }], ipFilter: { mode: 'off' as const, cidrs: ['8.8.8.8'] } }
	];
	const out = sanitizePathRules(rules as any);
	expect(out).toHaveLength(1);
	expect(out[0].ipFilter?.cidrs).toEqual([]);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd web/frontend && npx vitest run src/lib/utils/path-rules.test.ts`
Expected: FAIL (pure-routing rule dropped; empty-pool rule maybe kept incorrectly).

- [ ] **Step 3: Extend the TS `PathRule` type**

In `web/frontend/src/lib/api/types.ts`, add to the `PathRule` interface (near line 786):

```ts
	/** Per-path upstream routing (v2.23.0). Empty/absent = inherit the
	 *  route's pool. */
	upstreams?: Upstream[];
	lbPolicy?: LBPolicy;
	healthCheck?: HealthCheck;
```

- [ ] **Step 4: Extend `sanitizePathRules`**

In `web/frontend/src/lib/utils/path-rules.ts`, add an active-upstream predicate and include it in the keep filter:

```ts
/** Returns true when `rule.upstreams` is a non-empty pool (pure routing
 *  counts as active content — v2.23.0). */
function hasActiveUpstream(rule: PathRule): boolean {
	return !!rule.upstreams && rule.upstreams.length > 0;
}
```

Change the filter in `sanitizePathRules`:

```ts
		.filter((rule) => hasActiveBasicAuth(rule) || hasActiveIPFilter(rule) || hasActiveUpstream(rule))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run src/lib/utils/path-rules.test.ts`
Expected: PASS (all, including the 3 new).

- [ ] **Step 6: svelte-check**

Run: `npx svelte-check --threshold error`
Expected: 0 errors.

- [ ] **Step 7: Commit**

```bash
git add web/frontend/src/lib/api/types.ts web/frontend/src/lib/utils/path-rules.ts web/frontend/src/lib/utils/path-rules.test.ts
git commit -m "feat(path-upstream): frontend PathRule type + sanitize treats upstream as active content"
```

---

### Task 6: Frontend UI — "Upstream spécifique" disclosure in `PathRulesSection.svelte`

**Files:**
- Modify: `web/frontend/src/lib/components/routes/PathRulesSection.svelte`
- Modify: `web/frontend/src/lib/i18n/en.ts` + `fr.ts` (path-rule keys — find exact files)
- Test: `web/frontend/src/lib/components/routes/PathRulesSection.test.ts` (extend)

**Interfaces:**
- Consumes: extended `PathRule` TS type (Task 5).
- Produces: a collapsed disclosure per path-rule card with a URL+weight repeater, an LB `<select>`, and a health-check enable toggle (+ uri/interval when enabled); a `→ N backends` badge on the collapsed card when the pool is non-empty; new i18n keys EN+FR.

- [ ] **Step 1: Find the i18n files + existing path-rule keys**

Run: `grep -rln "pathRules" web/frontend/src/lib/i18n/ && grep -n "pathRules" web/frontend/src/lib/i18n/en.ts | head`
Note the exact key namespace (`routes.pathRules.*`) and the two locale files.

- [ ] **Step 2: Write the failing component tests**

Extend `web/frontend/src/lib/components/routes/PathRulesSection.test.ts` (mirror its existing render harness):

```ts
it('renders the collapsed "Upstream spécifique" disclosure per rule', async () => {
	// render with one rule, assert the disclosure summary/toggle exists and
	// the upstream fields are NOT visible until expanded.
	// (use the component's existing add-rule test helper)
});

it('shows a "→ N backends" badge when the rule has a non-empty pool', async () => {
	// render with a rule whose upstreams=[{url,weight},{url,weight}]
	// assert the collapsed card shows "→ 2 backends" (or the i18n equivalent testid)
});
```

(Fill these against the component's actual testing conventions — reuse the `data-testid` pattern already in the file. Keep assertions on stable testids, not raw copy.)

- [ ] **Step 3: Run tests to verify they fail**

Run: `npx vitest run src/lib/components/routes/PathRulesSection.test.ts`
Expected: FAIL (disclosure + badge not implemented).

- [ ] **Step 4: Add i18n keys (EN + FR)**

Add to both locale files under `routes.pathRules`:
- `upstreamDisclosureLabel`: EN "Specific upstream (optional)" / FR "Upstream spécifique (optionnel)"
- `upstreamInheritHint`: EN "By default this path follows the route's upstream." / FR "Par défaut, ce path suit l'upstream de la route."
- `upstreamAddBackend`: EN "Add a backend" / FR "Ajouter un backend"
- `upstreamLbLabel`: EN "Load balancing" / FR "Répartition de charge"
- `upstreamHealthCheckLabel`: EN "Active health-check" / FR "Health-check actif"
- `upstreamBackendsBadge`: EN "→ {n} backend(s)" / FR "→ {n} backend(s)" (interpolated count)

- [ ] **Step 5: Implement the disclosure + fields + badge**

In `PathRulesSection.svelte`: below the IPFilterFields block, add a collapsed `<details>` (or the app's existing disclosure component — check `open={...}` usage; the route HC uses a disclosure at +page.svelte:4189). Inside: a URL+weight repeater bound to `rule.upstreams` (add/remove buttons, default `{ url: '', weight: 1 }`), an LB `<select>` bound to `rule.lbPolicy`, and a health-check enable checkbox bound to `rule.healthCheck?.enabled` (materialise `rule.healthCheck = { enabled:true, uri:'', method:'GET', interval:'10s', timeout:'5s', expectStatus:0, expectBody:'', passes:1, fails:1 }` on first enable; set `undefined` on disable). On the collapsed card, show the `→ N backends` badge when `rule.upstreams?.length`. Do NOT wire the `testUpstream` API (route-scoped; out of scope per the UI decision).

- [ ] **Step 6: Run component tests + svelte-check + full frontend suite**

Run: `npx vitest run src/lib/components/routes/PathRulesSection.test.ts && npx svelte-check --threshold error && npx vitest run`
Expected: PASS, 0 svelte-check errors, full suite green.

- [ ] **Step 7: Verify i18n parity**

Run: (the repo's i18n parity guard) `npx vitest run -t i18n` or `grep -c "upstreamDisclosureLabel" web/frontend/src/lib/i18n/en.ts web/frontend/src/lib/i18n/fr.ts`
Expected: same key count in EN and FR.

- [ ] **Step 8: Commit**

```bash
git add web/frontend/src/lib/components/routes/PathRulesSection.svelte web/frontend/src/lib/components/routes/PathRulesSection.test.ts web/frontend/src/lib/i18n/en.ts web/frontend/src/lib/i18n/fr.ts
git commit -m "feat(path-upstream): PathRulesSection upstream disclosure + '→ N backends' badge + i18n"
```

---

### Task 7: Wire payload assembly + build + live smoke doc

**Files:**
- Modify: `web/frontend/src/routes/routes/+page.svelte` (path-rule payload assembly — pass upstreams/lbPolicy/healthCheck through `sanitizePathRules`)
- Create: `docs/smoke-test-path-upstream.md`
- Test: build + existing routes page tests

**Interfaces:**
- Consumes: everything above.
- Produces: the create/update payload carries per-path upstream fields; a live-smoke doc.

- [ ] **Step 1: Confirm the payload path**

Run: `grep -n "sanitizePathRules\|pathRules:" web/frontend/src/routes/routes/+page.svelte`
Confirm `pathRules: sanitizePathRules(formData.pathRules ...)` already forwards the whole rule object (so upstreams ride along automatically once the type + sanitize are updated). If the assembly hand-picks fields, add `upstreams`, `lbPolicy`, `healthCheck`.

- [ ] **Step 2: Full frontend build (bundling proof)**

Run: `cd web/frontend && npm run build`
Expected: build succeeds, adapter-static writes `build/`.

- [ ] **Step 3: Write the smoke-test doc**

Create `docs/smoke-test-path-upstream.md` mirroring `docs/smoke-test-path-rules.md`: a live checklist that (1) creates a route `api-bff` → route pool; (2) adds a path-rule `/v1 → own http pool`; (3) adds `/legacy → own https pool` (transport); (4) adds `/docs → route pool + basic-auth` (inherit); (5) verifies the branded error page appears on BOTH a route-pool 502 and a path-pool 502; (6) verifies an https path backend works; (7) verifies a pure-routing rule (no protection) is accepted. Leave the results table empty for the operator to fill during the live run.

- [ ] **Step 4: Backend + frontend full suites + race, final gate**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./... && go test -race ./internal/caddymgr/ && cd web/frontend && npx vitest run && npx svelte-check --threshold error`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/routes/routes/+page.svelte docs/smoke-test-path-upstream.md
git commit -m "feat(path-upstream): forward per-path upstream in the route payload + smoke doc"
```

---

## Post-plan (controller, not a task)

- **Dedicated opus reviews:** Task 3 (byte-identity refactor on the 100%-traffic path) and Task 4 (transport-per-pool + shared handle_response + fail-closed IP-filter). See spec §5.
- **Live smoke** per `docs/smoke-test-path-upstream.md` before merge (operator-run).
- **Final whole-branch opus review**, then `superpowers:finishing-a-development-branch`.
- **Version v2.23.0** — tag only after operator go-ahead.

## Self-Review notes
- Spec coverage: Q1 pool+LB+HC (Tasks 1,2,4,6) ✓; Q2 transport-per-pool + independent scheme (Task 1 validate, Task 4 emit + `TestPathRulesSubroute_HTTPSPathPoolEmitsTransport`) ✓; Q3 valid-with-upstream-only (Task 1 `UpstreamOnlyIsValid`, Task 5 sanitize) ✓; Q4 shared branding (Task 3 `sharedHandleResponse`, Task 4 passes it to path proxy) ✓; Q5 disclosure + badge, lean fields (Task 6) ✓; §3.1 byte-identity (Task 3 golden) ✓; §3.2 race gate (Tasks 3,4 step 6) ✓.
- Type consistency: storage type is `HealthCheck` (not `HealthCheckConfig`) — used consistently. `buildReverseProxyHandler(proxyPoolParams, sharedHandleResponse, flushInterval)` referenced identically in Tasks 3 and 4. `buildPathRulesSubroute` new signature `(rules, routeProxy, basicAuthBuilder, pathProxyBuilder) (map, error)` used in Task 4 steps 3 and 4.
- Open verifications flagged inline for the implementer: `validateUpstreamURL` package location (Task 1 step 4), golden-test helper convention (Task 3 step 1), `poolUsesHTTPS` reuse (Task 4 step 4), i18n file paths (Task 6 step 1), payload assembly shape (Task 7 step 1).
