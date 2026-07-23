# Path-based rules + IP allow/deny (v1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator apply basic-auth and source-IP allow/deny to specific URL sub-paths of a route, plus a reusable source-IP allow/deny filter at the whole-route level — without weakening the domain's global policy.

**Architecture:** Additive-override model. A new reusable `IPFilter` brick (mirrors `countryblock.Config`) emits native Caddy `client_ip` + `not` matchers. Route gains `IPFilter` (whole-domain) + `[]PathRule` (per-sub-path). Emission inserts an early route-IP block-handler (sibling of country-block) and replaces the trailing `reverse_proxy` with a path-matched subroute sorted longest-prefix-first + a catch-all. Migration-free (`omitempty`; zero path-rules = v2.20.3 behaviour).

**Tech Stack:** Go 1.25 (`net` for CIDR parsing), BoltDB, chi, Caddy v2.11.3 embedded (`http.matchers.client_ip` at `ip_matchers.go:185`, `http.matchers.not` at `matchers.go:1366`, `static_response`), SvelteKit (Svelte 5, TS), Vitest.

## Global Constraints

- **AGPL header** verbatim on every new Go and TS file.
- **Go**: `gofmt -s` clean, `go vet` clean; errors wrapped `fmt.Errorf("context: %w", err)`; no `panic` outside `main`; `slog` for logs; I/O funcs take `ctx` first.
- **Migration-free**: new struct fields `omitempty`; a pre-v1 route (no `ip_filter`/`path_rules`) decodes to zero-value and emits the identical v2.20.3 config.
- **Secret discipline**: `PathRule.BasicAuth.PasswordHash` is a SECRET — redact-on-GET, preserve-on-edit, never logged (same regime as the existing route `BasicAuth`).
- **Wire-field-gap checklist (RECURRING BUG — memory `route_wire_field_gap_regression`):** every new `storage.Route` field surfaced over the API MUST be added to the `routeRequest` struct (`handler.go:1224` area), the create map (`routes.go:1455`), the update map (`routes.go:1944`), AND the response (`toResponse` `handler.go:1706`), or `DisallowUnknownFields` 400s every route POST/PUT. Add a `routes_ip_filter_test` / `routes_path_rules_test` guard.
- **API wire tags are camelCase** (verified: `routeRequest.CountryBlock` = `json:"countryBlock"`, `handler.go:1224`). The new API wire fields are **`ipFilter`** and **`pathRules`** (camelCase), NOT snake_case — the storage struct's snake tags are for BoltDB, the API layer uses camelCase. The frontend sends/reads camelCase. Nested: `pathPrefix`, `basicAuth`, `ipFilter` inside a path rule (camelCase on the wire). Because `routeRequest` decodes into a **separate API-layer struct** (not `storage.Route` directly — storage uses snake), Task 3 needs API-layer mirror types with camelCase tags that map to the storage types.
- **IP matcher**: use Caddy `client_ip` (honours `ARENET_TRUSTED_PROXIES`), NEVER `remote_ip` (sees a fronting LB's IP).
- **Prefix matcher**: `/docs` emits `path:["/docs","/docs/*"]`. No regex, no exact-only.
- **Longest-prefix wins**: path-rules emitted sorted by descending `PathPrefix` length.
- **IP filter fail-closed**: allow-mode must block (403) when the client IP is NOT in the list — a wrong `not`-matcher inversion is fail-OPEN (security hole). Verify empirically.
- **Caddy empirical (CLAUDE.md)**: emitted config must `caddy.Validate()` (fold into the canonical `TestBuildConfigJSON_LoadsCleanly` fixture — ONE Validate call per package convention) + live smoke.
- **i18n**: all new UI copy in EN + FR, parity guard passes.
- **Branch**: `feature/path-based-rules` (spec `c44b629` already committed).

---

### Task 1: `IPFilter` storage brick + validation

**Files:**
- Create: `internal/storage/ipfilter.go`
- Test: `internal/storage/ipfilter_test.go`

**Interfaces:**
- Consumes: nothing (leaf).
- Produces:
  - `type IPFilter struct { Mode string; CIDRs []string; StatusCode int }` (JSON: `mode`, `cidrs,omitempty`, `statusCode,omitempty`).
  - Consts `IPFilterModeOff = "off"`, `IPFilterModeAllow = "allow"`, `IPFilterModeDeny = "deny"`.
  - `func (f IPFilter) Validate() error`.
  - `func (f IPFilter) IsActive() bool` (Mode is allow or deny).

- [ ] **Step 1: Write failing tests**

```go
// internal/storage/ipfilter_test.go (AGPL header)
package storage

import "testing"

func TestIPFilter_Validate(t *testing.T) {
	cases := []struct {
		name    string
		f       IPFilter
		wantErr bool
	}{
		{"off empty ok", IPFilter{Mode: ""}, false},
		{"off explicit ok", IPFilter{Mode: "off"}, false},
		{"allow with ip ok", IPFilter{Mode: "allow", CIDRs: []string{"192.168.1.10"}}, false},
		{"allow with cidr ok", IPFilter{Mode: "allow", CIDRs: []string{"10.0.0.0/8"}}, false},
		{"deny with ipv6 ok", IPFilter{Mode: "deny", CIDRs: []string{"2001:db8::/32"}}, false},
		{"allow empty list rejected", IPFilter{Mode: "allow"}, true},
		{"deny empty list rejected", IPFilter{Mode: "deny"}, true},
		{"bad mode rejected", IPFilter{Mode: "maybe", CIDRs: []string{"1.2.3.4"}}, true},
		{"bad cidr rejected", IPFilter{Mode: "allow", CIDRs: []string{"not-an-ip"}}, true},
		{"dup entry rejected", IPFilter{Mode: "allow", CIDRs: []string{"1.2.3.4", "1.2.3.4"}}, true},
		{"status ok 444", IPFilter{Mode: "deny", CIDRs: []string{"1.2.3.4"}, StatusCode: 444}, false},
		{"status bad 200 rejected", IPFilter{Mode: "deny", CIDRs: []string{"1.2.3.4"}, StatusCode: 200}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.f.Validate()
			if (err != nil) != c.wantErr {
				t.Fatalf("Validate()=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestIPFilter_IsActive(t *testing.T) {
	if (IPFilter{Mode: ""}).IsActive() || (IPFilter{Mode: "off"}).IsActive() {
		t.Fatal("off must be inactive")
	}
	if !(IPFilter{Mode: "allow"}).IsActive() || !(IPFilter{Mode: "deny"}).IsActive() {
		t.Fatal("allow/deny must be active")
	}
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run TestIPFilter -v`
Expected: FAIL — `undefined: IPFilter`.

- [ ] **Step 3: Implement**

```go
// internal/storage/ipfilter.go (AGPL header)
package storage

import (
	"fmt"
	"net"
)

const (
	IPFilterModeOff   = "off"
	IPFilterModeAllow = "allow"
	IPFilterModeDeny  = "deny"
)

// allowedIPFilterStatus mirrors country-block: 0 = default 403.
var allowedIPFilterStatus = map[int]struct{}{403: {}, 444: {}, 451: {}}

// IPFilter is a reusable source-IP allow/deny gate. Mode "allow" passes
// ONLY the listed IP/CIDR (403 otherwise); "deny" blocks the listed
// (rest passes). Emitted via Caddy's client_ip matcher (honours
// ARENET_TRUSTED_PROXIES). Mirrors countryblock.Config.
type IPFilter struct {
	Mode       string   `json:"mode"`
	CIDRs      []string `json:"cidrs,omitempty"`
	StatusCode int      `json:"statusCode,omitempty"`
}

func (f IPFilter) IsActive() bool {
	return f.Mode == IPFilterModeAllow || f.Mode == IPFilterModeDeny
}

func (f IPFilter) Validate() error {
	switch f.Mode {
	case "", IPFilterModeOff, IPFilterModeAllow, IPFilterModeDeny:
	default:
		return fmt.Errorf("ipfilter: mode %q is not one of off/allow/deny", f.Mode)
	}
	seen := make(map[string]struct{}, len(f.CIDRs))
	for _, e := range f.CIDRs {
		if _, _, err := net.ParseCIDR(e); err != nil {
			if net.ParseIP(e) == nil {
				return fmt.Errorf("ipfilter: %q is not a valid IP or CIDR", e)
			}
		}
		if _, dup := seen[e]; dup {
			return fmt.Errorf("ipfilter: %q appears more than once", e)
		}
		seen[e] = struct{}{}
	}
	if f.IsActive() && len(f.CIDRs) == 0 {
		return fmt.Errorf("ipfilter: mode %q requires at least one IP/CIDR", f.Mode)
	}
	if f.StatusCode != 0 {
		if _, ok := allowedIPFilterStatus[f.StatusCode]; !ok {
			return fmt.Errorf("ipfilter: statusCode %d must be 0 (default 403) or one of 403, 444, 451", f.StatusCode)
		}
	}
	return nil
}

// normalizeCIDR converts a bare IP to its single-host CIDR (/32 or /128)
// so emission can always feed the client_ip matcher CIDR ranges.
func (f IPFilter) NormalizedCIDRs() []string {
	out := make([]string, 0, len(f.CIDRs))
	for _, e := range f.CIDRs {
		if _, _, err := net.ParseCIDR(e); err == nil {
			out = append(out, e)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			out = append(out, e+"/32")
		} else {
			out = append(out, e+"/128")
		}
	}
	return out
}
```

- [ ] **Step 4: Run + vet + gofmt**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run TestIPFilter -v && go vet ./internal/storage/ && gofmt -l internal/storage/ipfilter.go`
Expected: PASS, no vet output, gofmt prints nothing.

- [ ] **Step 5: Commit**

```bash
git add internal/storage/ipfilter.go internal/storage/ipfilter_test.go
git commit -m "feat(routes): IPFilter storage brick (allow/deny source-IP gate)"
```

---

### Task 2: `PathRule` type + Route fields + validation

**Files:**
- Modify: `internal/storage/routes.go` (add `IPFilter`, `PathRules` to `Route`; add `PathRule` type; hook validation near `routes.go:856`)
- Test: `internal/storage/routes_path_rule_test.go`

**Interfaces:**
- Consumes: `IPFilter` (Task 1), existing `BasicAuthRouteConfig{Username, PasswordHash}`.
- Produces:
  - `Route.IPFilter *IPFilter` (json `ip_filter,omitempty`), `Route.PathRules []PathRule` (json `path_rules,omitempty`).
  - `type PathRule struct { PathPrefix string; BasicAuth *BasicAuthRouteConfig; IPFilter *IPFilter }` (json `path_prefix`, `basic_auth,omitempty`, `ip_filter,omitempty`).
  - `func (p PathRule) Validate() error`.
  - `func SortPathRulesByPrefixLenDesc(rules []PathRule) []PathRule` (pure, longest-first; stable).

- [ ] **Step 1: Add the types + fields**

In `internal/storage/routes.go`, add to the `Route` struct (after `CountryBlock`, before `RateLimit`):

```go
	// v1 path-based-rules. Empty on pre-v1 routes (migration-free).
	IPFilter  *IPFilter  `json:"ip_filter,omitempty"`   // whole-domain source-IP gate
	PathRules []PathRule `json:"path_rules,omitempty"`  // per-sub-path overrides (additive)
```

And add (near the BasicAuthRouteConfig type):

```go
// PathRule applies additive protections to a URL sub-tree of a route.
// PathPrefix "/docs" matches "/docs" and everything under "/docs/*"
// (emission concern). At least one of BasicAuth / IPFilter must be set.
type PathRule struct {
	PathPrefix string                `json:"path_prefix"`
	BasicAuth  *BasicAuthRouteConfig `json:"basic_auth,omitempty"` // PasswordHash is a SECRET
	IPFilter   *IPFilter             `json:"ip_filter,omitempty"`
}

func (p PathRule) Validate() error {
	if p.PathPrefix == "" || p.PathPrefix[0] != '/' {
		return fmt.Errorf("path_rule: path_prefix %q must start with /", p.PathPrefix)
	}
	if len(p.PathPrefix) > 256 {
		return fmt.Errorf("path_rule: path_prefix exceeds 256 characters")
	}
	for _, r := range p.PathPrefix {
		if r == ' ' || r == '\t' || r == '\n' {
			return fmt.Errorf("path_rule: path_prefix %q must not contain whitespace", p.PathPrefix)
		}
	}
	if p.BasicAuth == nil && p.IPFilter == nil {
		return fmt.Errorf("path_rule %q: must declare at least one protection (basic auth or IP filter)", p.PathPrefix)
	}
	if p.BasicAuth != nil && p.BasicAuth.Username == "" {
		return fmt.Errorf("path_rule %q: basic auth requires a username", p.PathPrefix)
	}
	if p.IPFilter != nil {
		if err := p.IPFilter.Validate(); err != nil {
			return fmt.Errorf("path_rule %q: %w", p.PathPrefix, err)
		}
	}
	return nil
}

// SortPathRulesByPrefixLenDesc returns the rules ordered longest-prefix
// first (Q4). Stable so equal-length prefixes keep declaration order.
func SortPathRulesByPrefixLenDesc(rules []PathRule) []PathRule {
	out := make([]PathRule, len(rules))
	copy(out, rules)
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].PathPrefix) > len(out[j].PathPrefix)
	})
	return out
}
```

Ensure `"sort"` is imported. Hook validation in `Route.Validate` next to the `CountryBlock.Validate()` call (~line 856):

```go
	if r.IPFilter != nil {
		if err := r.IPFilter.Validate(); err != nil {
			return err
		}
	}
	seenPrefix := make(map[string]struct{}, len(r.PathRules))
	for _, pr := range r.PathRules {
		if err := pr.Validate(); err != nil {
			return err
		}
		if _, dup := seenPrefix[pr.PathPrefix]; dup {
			return fmt.Errorf("path_rules: duplicate path_prefix %q", pr.PathPrefix)
		}
		seenPrefix[pr.PathPrefix] = struct{}{}
	}
```

- [ ] **Step 2: Write tests**

```go
// internal/storage/routes_path_rule_test.go (AGPL header)
package storage

import "testing"

func TestPathRule_Validate(t *testing.T) {
	ba := &BasicAuthRouteConfig{Username: "u", PasswordHash: "$argon2id$..."}
	ipf := &IPFilter{Mode: "allow", CIDRs: []string{"1.2.3.4"}}
	cases := []struct {
		name    string
		p       PathRule
		wantErr bool
	}{
		{"basic ok", PathRule{PathPrefix: "/docs", BasicAuth: ba}, false},
		{"ip ok", PathRule{PathPrefix: "/metrics", IPFilter: ipf}, false},
		{"both ok", PathRule{PathPrefix: "/x", BasicAuth: ba, IPFilter: ipf}, false},
		{"no leading slash", PathRule{PathPrefix: "docs", BasicAuth: ba}, true},
		{"empty prefix", PathRule{PathPrefix: "", BasicAuth: ba}, true},
		{"no protection", PathRule{PathPrefix: "/x"}, true},
		{"basic no user", PathRule{PathPrefix: "/x", BasicAuth: &BasicAuthRouteConfig{}}, true},
		{"bad ip filter", PathRule{PathPrefix: "/x", IPFilter: &IPFilter{Mode: "allow"}}, true},
		{"whitespace prefix", PathRule{PathPrefix: "/a b", BasicAuth: ba}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if (c.p.Validate() != nil) != c.wantErr {
				t.Fatalf("Validate wantErr=%v", c.wantErr)
			}
		})
	}
}

func TestSortPathRulesByPrefixLenDesc(t *testing.T) {
	in := []PathRule{{PathPrefix: "/docs"}, {PathPrefix: "/docs/admin"}, {PathPrefix: "/a"}}
	got := SortPathRulesByPrefixLenDesc(in)
	if got[0].PathPrefix != "/docs/admin" || got[2].PathPrefix != "/a" {
		t.Fatalf("not longest-first: %v", got)
	}
	// input must be unmutated (returns a copy).
	if in[0].PathPrefix != "/docs" {
		t.Fatal("input slice was mutated")
	}
}

func TestRoute_Validate_RejectsDuplicatePathPrefix(t *testing.T) {
	r := Route{
		Host:      "app.example.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		PathRules: []PathRule{
			{PathPrefix: "/docs", IPFilter: &IPFilter{Mode: "deny", CIDRs: []string{"1.2.3.4"}}},
			{PathPrefix: "/docs", BasicAuth: &BasicAuthRouteConfig{Username: "u"}},
		},
	}
	if err := r.Validate(); err == nil {
		t.Fatal("expected duplicate path_prefix rejection")
	}
}
```

- [ ] **Step 3: Run to verify fail, then it passes after Step 1's code**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run 'TestPathRule|TestSortPathRules|TestRoute_Validate_RejectsDuplicate' -v`
Expected: PASS (code from Step 1 already present). If Step 1 not yet applied → FAIL `undefined: PathRule`; apply Step 1 then re-run.

- [ ] **Step 4: Migration-free check + full storage suite**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ && go vet ./internal/storage/`
Expected: PASS (existing route tests unaffected — new fields are `omitempty`). Confirm a pre-v1 route JSON (no `ip_filter`/`path_rules`) round-trips with nil values; mention in the report.

- [ ] **Step 5: Commit**

```bash
git add internal/storage/routes.go internal/storage/routes_path_rule_test.go
git commit -m "feat(routes): PathRule type + Route.IPFilter/PathRules fields + validation"
```

---

### Task 3: API wire fields (the wire-field-gap checklist)

**Files:**
- Modify: `internal/api/handler.go` (`routeRequest` struct ~1224; `toResponse` ~1706)
- Modify: `internal/api/routes.go` (create map ~1455; update map ~1944)
- Test: `internal/api/routes_path_rules_test.go`

**Interfaces:**
- Consumes: `storage.Route.IPFilter`, `storage.Route.PathRules`, `storage.IPFilter`, `storage.PathRule`.
- Produces: route POST/PUT accept + echo `ip_filter` and `path_rules`; PathRule basic-auth `password_hash` redacted on GET.

- [ ] **Step 1: Failing test — POST a route with path_rules + ip_filter round-trips**

```go
// internal/api/routes_path_rules_test.go (AGPL header) — use the real
// harness: env := newTestEnv(t, false); env.router.ServeHTTP; env.store.
func TestCreateRoute_WithPathRulesAndIPFilter(t *testing.T) {
	env := newTestEnv(t, false)
	// API wire is camelCase (mirrors countryBlock). Nested keys too.
	body := `{
	  "host":"api.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],
	  "ipFilter":{"mode":"deny","cidrs":["10.0.0.0/8"]},
	  "pathRules":[
	    {"pathPrefix":"/metrics","ipFilter":{"mode":"allow","cidrs":["192.168.1.5"]}},
	    {"pathPrefix":"/docs","basicAuth":{"username":"doc","passwordHash":"$argon2id$v=19$m=65536,t=3,p=4$U0FMVFNBTFRTQUxUU0FMVA$S0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0U"}}
	  ]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s (wire-field-gap? DisallowUnknownFields)", rec.Code, rec.Body)
	}
	// GET redacts the path-rule basic-auth password hash.
	if strings.Contains(rec.Body.String(), "S0VZS0VZ") {
		t.Errorf("path-rule password_hash leaked in response: %s", rec.Body)
	}
}
```

> Read `internal/api/routes_external_cert_test.go` first for the exact harness (`newTestEnv`, `jsonBodyManualCert` style). Match it.

- [ ] **Step 2: Run to verify fail**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run TestCreateRoute_WithPathRulesAndIPFilter -v`
Expected: FAIL — 400 `unknown field "ipFilter"` (the gap).

- [ ] **Step 3: Add the 4 wire points (camelCase API mirror types)**

The API wire is **camelCase** (`routeRequest.CountryBlock` = `json:"countryBlock"`). `routeRequest` does NOT embed `storage.Route` (which uses snake tags for BoltDB), so add **API-layer mirror types** with camelCase tags in `handler.go`, plus a mapper to the storage types:

```go
// camelCase wire mirrors of the storage types (storage uses snake for BoltDB).
type ipFilterReq struct {
	Mode       string   `json:"mode"`
	CIDRs      []string `json:"cidrs,omitempty"`
	StatusCode int      `json:"statusCode,omitempty"`
}
type pathRuleReq struct {
	PathPrefix string        `json:"pathPrefix"`
	BasicAuth  *basicAuthReq `json:"basicAuth,omitempty"` // reuse the existing basicAuthReq if one exists; else {username, passwordHash}
	IPFilter   *ipFilterReq  `json:"ipFilter,omitempty"`
}
func (r ipFilterReq) toStorage() storage.IPFilter {
	return storage.IPFilter{Mode: r.Mode, CIDRs: r.CIDRs, StatusCode: r.StatusCode}
}
```

Add to `routeRequest`:

```go
	IPFilter  *ipFilterReq  `json:"ipFilter,omitempty"`
	PathRules []pathRuleReq `json:"pathRules,omitempty"`
```

> Check whether a `basicAuthReq` wire type already exists (the route-level basic auth uses one) and reuse it inside `pathRuleReq`; else define `{Username string; PasswordHash string}` with `json:"username"`/`json:"passwordHash"`.

In `internal/api/routes.go` create map (~1455) and update map (~1944), map the request mirrors to storage in the `storage.Route{...}` literal:

```go
		IPFilter:  mapIPFilterReq(req.IPFilter),   // nil-safe: returns *storage.IPFilter or nil
		PathRules: mapPathRuleReqs(req.PathRules), // []storage.PathRule
```

Write the small nil-safe mappers (`mapIPFilterReq`, `mapPathRuleReqs`) next to the handler.

In `handler.go` `toResponse` (~1706), add — redacting each path-rule basic-auth password hash:

```go
	// Redact secrets: path-rule basic-auth password hashes never echoed.
	pathRules := make([]storage.PathRule, len(r.PathRules))
	copy(pathRules, r.PathRules)
	for i := range pathRules {
		if pathRules[i].BasicAuth != nil {
			ba := *pathRules[i].BasicAuth
			ba.PasswordHash = ""
			pathRules[i].BasicAuth = &ba
		}
	}
	// ... set resp.IPFilter = r.IPFilter and resp.PathRules = pathRules
```

Add `IPFilter` + `PathRules` fields to the `routeResponse` struct. On UPDATE, apply preserve-on-edit for a path-rule with an empty PasswordHash (mirror the route-level basic-auth preserve pattern) — read how the existing route BasicAuth preserve works and match it.

- [ ] **Step 4: Run + full api suite**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run TestCreateRoute_WithPathRulesAndIPFilter -v && go test ./internal/api/ && go vet ./internal/api/`
Expected: PASS, no regression.

- [ ] **Step 5: Commit**

```bash
git add internal/api/handler.go internal/api/routes.go internal/api/routes_path_rules_test.go
git commit -m "feat(routes): wire ip_filter + path_rules through the route API (redact secrets)"
```

---

### Task 4: caddymgr — route-level IPFilter emission — DEDICATED REVIEW (fail-closed)

**Files:**
- Create: `internal/caddymgr/ip_filter_emit.go` (the matcher/handler builder)
- Modify: `internal/caddymgr/manager.go` (call it in the chain, sibling of country-block ~1733)
- Test: `internal/caddymgr/ip_filter_emit_test.go`

**Interfaces:**
- Consumes: `storage.IPFilter`.
- Produces: `func buildIPFilterRoute(f storage.IPFilter) map[string]any` — a Caddy `route` (matcher + `static_response` 403) that blocks the right traffic, or `nil` when inactive.

- [ ] **Step 1: Failing test — allow-mode fails CLOSED, deny-mode blocks listed**

```go
// internal/caddymgr/ip_filter_emit_test.go (AGPL header)
package caddymgr

import (
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

func TestBuildIPFilterRoute_Inactive(t *testing.T) {
	if buildIPFilterRoute(storage.IPFilter{Mode: "off"}) != nil {
		t.Fatal("off must emit nil")
	}
	if buildIPFilterRoute(storage.IPFilter{Mode: ""}) != nil {
		t.Fatal("empty must emit nil")
	}
}

func TestBuildIPFilterRoute_AllowFailsClosed(t *testing.T) {
	// allow mode: block everything NOT in the list → the matcher MUST be
	// a `not` wrapping client_ip, so a client outside the list is denied.
	r := buildIPFilterRoute(storage.IPFilter{Mode: "allow", CIDRs: []string{"192.168.1.5"}})
	m := r["match"].([]map[string]any)[0]
	if _, hasNot := m["not"]; !hasNot {
		t.Fatalf("allow mode MUST use a `not` matcher (fail-closed), got %v", m)
	}
	// the not wraps client_ip with the normalized CIDR (/32 for a bare IP)
	notSets := m["not"].([]map[string]any)
	clientIP := notSets[0]["client_ip"].(map[string]any)
	ranges := clientIP["ranges"].([]string)
	if len(ranges) != 1 || ranges[0] != "192.168.1.5/32" {
		t.Fatalf("expected client_ip ranges [192.168.1.5/32], got %v", ranges)
	}
	sr := r["handle"].([]map[string]any)[0]
	if sr["handler"] != "static_response" {
		t.Fatalf("expected static_response, got %v", sr)
	}
	if int(sr["status_code"].(int)) != 403 {
		t.Fatalf("default block status must be 403, got %v", sr["status_code"])
	}
}

func TestBuildIPFilterRoute_DenyBlocksListed(t *testing.T) {
	// deny mode: block clients IN the list → matcher is client_ip (no not).
	r := buildIPFilterRoute(storage.IPFilter{Mode: "deny", CIDRs: []string{"10.0.0.0/8"}, StatusCode: 444})
	m := r["match"].([]map[string]any)[0]
	if _, hasNot := m["not"]; hasNot {
		t.Fatalf("deny mode must NOT use `not`, got %v", m)
	}
	ranges := m["client_ip"].(map[string]any)["ranges"].([]string)
	if ranges[0] != "10.0.0.0/8" {
		t.Fatalf("expected 10.0.0.0/8, got %v", ranges)
	}
	if int(r["handle"].([]map[string]any)[0]["status_code"].(int)) != 444 {
		t.Fatal("status override 444 not applied")
	}
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ -run TestBuildIPFilterRoute -v`
Expected: FAIL — `undefined: buildIPFilterRoute`.

- [ ] **Step 3: Implement**

```go
// internal/caddymgr/ip_filter_emit.go (AGPL header)
package caddymgr

import "github.com/barto95100/arenet/internal/storage"

// buildIPFilterRoute emits a Caddy route that blocks the traffic an
// IPFilter forbids, using the native client_ip matcher (which honours
// ARENET_TRUSTED_PROXIES — NOT remote_ip). Returns nil when inactive.
//
// allow mode → block everything NOT in the list: match {not:{client_ip}}.
//   This is the FAIL-CLOSED shape: an unknown client hits the 403.
// deny mode → block the listed: match {client_ip}.
// Caddy has no ResponseMatcher `not` but MatchNot (http.matchers.not,
// matchers.go:1366) IS a request matcher — valid here.
func buildIPFilterRoute(f storage.IPFilter) map[string]any {
	if !f.IsActive() {
		return nil
	}
	status := f.StatusCode
	if status == 0 {
		status = 403
	}
	clientIP := map[string]any{"ranges": f.NormalizedCIDRs()}
	var match map[string]any
	if f.Mode == storage.IPFilterModeAllow {
		match = map[string]any{"not": []map[string]any{{"client_ip": clientIP}}}
	} else { // deny
		match = map[string]any{"client_ip": clientIP}
	}
	return map[string]any{
		"match": []map[string]any{match},
		"handle": []map[string]any{
			{"handler": "static_response", "status_code": status},
		},
	}
}
```

- [ ] **Step 4: Wire it into the route chain**

In `internal/caddymgr/manager.go`, right after the country-block emit (~1733), add:

```go
		// v1 path-based-rules: whole-domain source-IP gate. Sibling of
		// country-block — cheap static policy before crowdsec/auth/waf.
		// Emitted as a route (matcher + static_response) so it can be an
		// inner route of the subroute; wrap accordingly to match the
		// existing handler-slice shape.
		if r.IPFilter != nil {
			if ipRoute := buildIPFilterRoute(*r.IPFilter); ipRoute != nil {
				// The chain is a handler slice; a matcher+handler pair is
				// expressed as a `subroute` with one inner route so it
				// slots into `handlers`. (Matches wrapInSubroute usage.)
				handlers = append(handlers, map[string]any{
					"handler": "subroute",
					"routes":  []map[string]any{ipRoute},
				})
			}
		}
```

> The exact wrap (a bare route vs a one-route subroute) must `caddy.Validate()`. Adjust to whatever validates — the dedicated review + Task 8 Validate fixture is the gate.

- [ ] **Step 5: Run + vet**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ -run TestBuildIPFilterRoute -v && go vet ./internal/caddymgr/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/caddymgr/ip_filter_emit.go internal/caddymgr/manager.go internal/caddymgr/ip_filter_emit_test.go
git commit -m "feat(caddymgr): emit route-level IP filter (client_ip, allow fails closed)"
```

---

### Task 5: caddymgr — path-rules subroute emission — DEDICATED REVIEW

**Files:**
- Create: `internal/caddymgr/path_rules_emit.go`
- Modify: `internal/caddymgr/manager.go` (replace the trailing `reverse_proxy` append ~1913 with the path-subroute when PathRules present)
- Test: `internal/caddymgr/path_rules_emit_test.go`

**Interfaces:**
- Consumes: `storage.PathRule`, `storage.SortPathRulesByPrefixLenDesc`, `buildIPFilterRoute` (Task 4), the existing basic-auth handler builder (find it — used for route-level basic auth ~1795).
- Produces: `func buildPathRulesSubroute(rules []storage.PathRule, proxyHandler map[string]any, basicAuthBuilder func(storage.BasicAuthRouteConfig) map[string]any) map[string]any` — a `subroute` whose inner routes are the sorted path matches (each: path IPFilter block? + basic-auth? + proxy) followed by a catch-all proxy route.

- [ ] **Step 1: Failing test — subroute is longest-first + catch-all last**

```go
// internal/caddymgr/path_rules_emit_test.go (AGPL header)
func TestBuildPathRulesSubroute_LongestFirstPlusCatchAll(t *testing.T) {
	proxy := map[string]any{"handler": "reverse_proxy"}
	ba := func(c storage.BasicAuthRouteConfig) map[string]any {
		return map[string]any{"handler": "authentication", "user": c.Username}
	}
	rules := []storage.PathRule{
		{PathPrefix: "/docs", BasicAuth: &storage.BasicAuthRouteConfig{Username: "d"}},
		{PathPrefix: "/docs/admin", IPFilter: &storage.IPFilter{Mode: "allow", CIDRs: []string{"1.2.3.4"}}},
	}
	sr := buildPathRulesSubroute(rules, proxy, ba)
	routes := sr["routes"].([]map[string]any)
	// 2 path routes + 1 catch-all = 3
	if len(routes) != 3 {
		t.Fatalf("want 3 inner routes (2 rules longest-first + catch-all), got %d", len(routes))
	}
	// route[0] = the LONGER prefix /docs/admin
	p0 := routes[0]["match"].([]map[string]any)[0]["path"].([]string)
	if p0[0] != "/docs/admin" || p0[1] != "/docs/admin/*" {
		t.Fatalf("route0 must be /docs/admin (longest-first), got %v", p0)
	}
	// route[2] = catch-all: no match, just proxy
	if _, hasMatch := routes[2]["match"]; hasMatch {
		t.Fatalf("catch-all must have no match, got %v", routes[2]["match"])
	}
	if routes[2]["handle"].([]map[string]any)[0]["handler"] != "reverse_proxy" {
		t.Fatal("catch-all must proxy")
	}
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ -run TestBuildPathRulesSubroute -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement**

```go
// internal/caddymgr/path_rules_emit.go (AGPL header)
package caddymgr

import "github.com/barto95100/arenet/internal/storage"

// pathMatchers returns Caddy path matchers for a prefix: the prefix
// itself + everything under it. "/docs" → ["/docs","/docs/*"].
func pathMatchers(prefix string) []string {
	return []string{prefix, prefix + "/*"}
}

// buildPathRulesSubroute wraps the proxy in a subroute whose inner
// routes are the path-rules (sorted longest-prefix first, Q4) each
// applying its override handlers (path IP filter block, then basic
// auth) before proxying, followed by a match-less catch-all proxy.
func buildPathRulesSubroute(
	rules []storage.PathRule,
	proxyHandler map[string]any,
	basicAuthBuilder func(storage.BasicAuthRouteConfig) map[string]any,
) map[string]any {
	sorted := storage.SortPathRulesByPrefixLenDesc(rules)
	inner := make([]map[string]any, 0, len(sorted)+1)
	for _, pr := range sorted {
		handle := make([]map[string]any, 0, 3)
		if pr.IPFilter != nil && pr.IPFilter.IsActive() {
			// A path IP block inside the matched route: emit the block
			// route's matcher+handler as a nested subroute so a blocked
			// client gets the 403 before the proxy.
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
		handle = append(handle, proxyHandler)
		inner = append(inner, map[string]any{
			"match":  []map[string]any{{"path": pathMatchers(pr.PathPrefix)}},
			"handle": handle,
		})
	}
	// catch-all: no path match → plain proxy (paths with no rule).
	inner = append(inner, map[string]any{
		"handle": []map[string]any{proxyHandler},
	})
	return map[string]any{"handler": "subroute", "routes": inner}
}
```

- [ ] **Step 4: Wire into manager.go — replace the trailing proxy append**

In `manager.go`, where `handlers = append(handlers, proxyHandler)` is the final append (~1913), replace with:

```go
		if len(r.PathRules) > 0 {
			handlers = append(handlers, buildPathRulesSubroute(r.PathRules, proxyHandler, buildBasicAuthHandlerFromConfig))
		} else {
			handlers = append(handlers, proxyHandler)
		}
```

> `buildBasicAuthHandlerFromConfig` — find/extract the existing route basic-auth handler builder (used ~1795-1810 for `RouteAuthBasic`). If it's inline, extract a `func buildBasicAuthHandlerFromConfig(storage.BasicAuthRouteConfig) map[string]any` (same argon2id `hash_cache` shape — see memory `route_basic_auth_hash_cache`) and reuse it here AND at the route-level call site. The dedicated review verifies the hash_cache is preserved (RAM-exhaustion regression).

- [ ] **Step 5: Run + vet + full caddymgr suite**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ && go vet ./internal/caddymgr/`
Expected: PASS (existing tests unaffected — path-rules only emit when present).

- [ ] **Step 6: Commit**

```bash
git add internal/caddymgr/path_rules_emit.go internal/caddymgr/manager.go internal/caddymgr/path_rules_emit_test.go
git commit -m "feat(caddymgr): emit path-rules subroute (longest-prefix, basic-auth + IP per path)"
```

---

### Task 6: caddy.Validate coverage (fold into canonical fixture)

**Files:**
- Modify: `internal/caddymgr/manager_test.go` (`TestBuildConfigJSON_LoadsCleanly` fixture — add path-rules + route IPFilter to the canonical route so the single package Validate call provisions them)

**Interfaces:** Consumes the emission from Tasks 4-5.

- [ ] **Step 1: Extend the canonical fixture route**

In `TestBuildConfigJSON_LoadsCleanly` (`manager_test.go` ~1126), add to the fixture route:

```go
		IPFilter: &storage.IPFilter{Mode: "deny", CIDRs: []string{"10.0.0.0/8"}},
		PathRules: []storage.PathRule{
			{PathPrefix: "/docs", BasicAuth: &storage.BasicAuthRouteConfig{
				Username:     "doc",
				PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$U0FMVFNBTFRTQUxUU0FMVA$S0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0U",
			}},
			{PathPrefix: "/metrics", IPFilter: &storage.IPFilter{Mode: "allow", CIDRs: []string{"192.168.1.5"}}},
		},
```

- [ ] **Step 2: Run the canonical Validate test**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ -run 'TestBuildConfigJSON_LoadsCleanly$' -v`
Expected: PASS — the emitted config (route IP-filter block + path subroute + client_ip/not matchers + basic-auth) provisions cleanly through `caddy.Validate`. If it FAILS with an "unknown module" / provision error, the matcher shape is wrong — fix the emission (Task 4/5) until it validates. **This is the load-bearing empirical gate.**

- [ ] **Step 3: Run the handler-resolvable test too**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/caddymgr/ -run 'HandlersAllResolvable|LoadsCleanly'`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/caddymgr/manager_test.go
git commit -m "test(caddymgr): caddy.Validate covers path-rules + IP filter emission"
```

---

### Task 7: Frontend — types + route IP-filter section component

**Files:**
- Modify: `web/frontend/src/lib/api/types.ts` (add `IPFilter`, `PathRule` types; extend `Route` + `RouteRequest`)
- Create: `web/frontend/src/lib/components/routes/IPFilterFields.svelte` (reusable: mode radio + CIDR list)
- Test: `web/frontend/src/lib/components/routes/IPFilterFields.test.ts`

**Interfaces:**
- Produces: an `IPFilterFields` component bound to an `IPFilter` value; `IPFilter`/`PathRule` TS types matching the camelCase wire (`ipFilter`, `pathRules`, `pathPrefix`, `basicAuth`).

- [ ] **Step 1: Add types**

In `types.ts`:

```ts
// API wire is camelCase (matches the backend routeRequest mirror types).
export interface IPFilter {
	mode: '' | 'off' | 'allow' | 'deny';
	cidrs?: string[];
	statusCode?: number;
}
export interface PathRule {
	pathPrefix: string;
	basicAuth?: { username: string; passwordHash?: string; passwordSet?: boolean };
	ipFilter?: IPFilter;
}
```

Extend `Route` (response) and `RouteRequest` with `ipFilter?: IPFilter` and `pathRules?: PathRule[]`.

- [ ] **Step 2: Failing component test**

```ts
// IPFilterFields.test.ts — mirror existing component test style
import { render, fireEvent } from '@testing-library/svelte';
import IPFilterFields from './IPFilterFields.svelte';

it('shows the CIDR list only when mode is allow or deny', async () => {
	const { queryByTestId, getByTestId } = render(IPFilterFields, { value: { mode: 'off' } });
	expect(queryByTestId('ipfilter-cidrs')).toBeNull();
	const { getByTestId: g2 } = render(IPFilterFields, { value: { mode: 'allow', cidrs: ['1.2.3.4'] } });
	expect(g2('ipfilter-cidrs')).toBeTruthy();
});
```

- [ ] **Step 3: Run to verify fail**

Run: `cd web/frontend && npx vitest run src/lib/components/routes/IPFilterFields.test.ts`
Expected: FAIL — component missing.

- [ ] **Step 4: Build the component**

`IPFilterFields.svelte` (AGPL header): a mode radio group (Off / Allowlist / Denylist via `t()`), and — when mode is allow/deny — a chips/textarea input for IP/CIDR entries (`data-testid="ipfilter-cidrs"`). Two-way bind to a `value: IPFilter` prop (Svelte 5 `$bindable`). All copy through `t('routes.ipFilter.*')`. Mirror the existing CountryBlock section's control style.

- [ ] **Step 5: Run + svelte-check**

Run: `cd web/frontend && npx vitest run src/lib/components/routes/IPFilterFields.test.ts && npx svelte-check --threshold error`
Expected: PASS, 0 errors.

- [ ] **Step 6: Commit**

```bash
git add web/frontend/src/lib/api/types.ts web/frontend/src/lib/components/routes/IPFilterFields.svelte web/frontend/src/lib/components/routes/IPFilterFields.test.ts
git commit -m "feat(routes-ui): IPFilter types + reusable IP-filter fields component"
```

---

### Task 8: Frontend — path-rules editor section component

**Files:**
- Create: `web/frontend/src/lib/components/routes/PathRulesSection.svelte`
- Test: `web/frontend/src/lib/components/routes/PathRulesSection.test.ts`

**Interfaces:**
- Consumes: `IPFilterFields` (Task 7), `PathRule` type.
- Produces: a collapsed-by-default section binding a `PathRule[]`; each rule = a card with prefix input + basic-auth (user/pass) + `IPFilterFields`; add/remove rule.

- [ ] **Step 1: Failing test — add a rule, collapsed by default**

```ts
// PathRulesSection.test.ts
import { render, fireEvent } from '@testing-library/svelte';
import PathRulesSection from './PathRulesSection.svelte';

it('is collapsed by default and adds a rule card on demand', async () => {
	const { getByTestId, queryAllByTestId } = render(PathRulesSection, { value: [] });
	expect(queryAllByTestId('path-rule-card').length).toBe(0);
	await fireEvent.click(getByTestId('path-rules-add'));
	expect(queryAllByTestId('path-rule-card').length).toBe(1);
});
```

- [ ] **Step 2: Run to verify fail**

Run: `cd web/frontend && npx vitest run src/lib/components/routes/PathRulesSection.test.ts`
Expected: FAIL.

- [ ] **Step 3: Build the component**

`PathRulesSection.svelte` (AGPL header): a collapsible section (collapsed default) with an "Add rule" button (`data-testid="path-rules-add"`). Each rule (`data-testid="path-rule-card"`): a `pathPrefix` text input (helptext: "/docs protège /docs et tout ce qui est dessous"), an optional basic-auth (username + password, `passwordSet` placeholder on edit), an embedded `IPFilterFields` bound to `rule.ipFilter`, and a remove button. Two-way bind `value: PathRule[]` (`$bindable`). All copy via `t('routes.pathRules.*')`.

- [ ] **Step 4: Run + svelte-check**

Run: `cd web/frontend && npx vitest run src/lib/components/routes/PathRulesSection.test.ts && npx svelte-check --threshold error`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/components/routes/PathRulesSection.svelte web/frontend/src/lib/components/routes/PathRulesSection.test.ts
git commit -m "feat(routes-ui): collapsed path-rules editor section (prefix + basic-auth + IP)"
```

---

### Task 9: Frontend — wire the sections into the route editor + submit

**Files:**
- Modify: `web/frontend/src/routes/routes/+page.svelte` (mount `IPFilterFields` at route level + `PathRulesSection`; include `ipFilter`/`pathRules` in the create/update payload; hydrate from the loaded route)
- Test: `web/frontend/src/routes/routes/page.test.ts` (extend)

**Interfaces:** Consumes Task 7-8 components; sends `ipFilter`/`pathRules` on save.

- [ ] **Step 1: Failing test — the route payload includes pathRules**

```ts
it('includes ipFilter and pathRules in the save payload', async () => {
	// mock the routes API create; render the editor; set a route IP filter
	// (deny 10.0.0.0/8) + one path rule (/docs basic-auth); submit; assert
	// the POST body carries ipFilter + pathRules[0].pathPrefix === '/docs'.
	// (Mirror the existing route-form submit test in this file.)
});
```

> Read the existing submit test in `page.test.ts` and mirror its mock/assert pattern exactly; fill the body per that pattern.

- [ ] **Step 2: Run to verify fail**

Run: `cd web/frontend && npx vitest run src/routes/routes/page.test.ts`
Expected: FAIL (payload missing the fields).

- [ ] **Step 3: Wire it**

In `+page.svelte`: add form state `ipFilter: IPFilter` + `pathRules: PathRule[]`; mount `<IPFilterFields bind:value={formData.ipFilter} />` in a route-level section and `<PathRulesSection bind:value={formData.pathRules} />`; include them in the create/update payload (`ipFilter`, `pathRules`) — omit/clear when empty; hydrate from `r.ipFilter` / `r.pathRules` on edit (with `passwordSet` for path-rule basic-auth).

- [ ] **Step 4: Run + full frontend suite + svelte-check**

Run: `cd web/frontend && npx vitest run && npx svelte-check --threshold error`
Expected: PASS (1050+ tests), 0 errors.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/routes/routes/+page.svelte web/frontend/src/routes/routes/page.test.ts
git commit -m "feat(routes-ui): wire IP filter + path rules into the route editor"
```

---

### Task 10: i18n EN + FR (parity)

**Files:**
- Modify: `web/frontend/src/lib/i18n/locales/en.json`, `fr.json` (under `routes.ipFilter.*`, `routes.pathRules.*`)

**Interfaces:** Consumes every `t('routes.ipFilter.*' | 'routes.pathRules.*')` key referenced in Tasks 7-9.

- [ ] **Step 1: Grep the referenced keys**

Run: `grep -rho "routes\.\(ipFilter\|pathRules\)\.[a-zA-Z0-9_.]*" web/frontend/src/lib/components/routes/ web/frontend/src/routes/routes/+page.svelte | sort -u`
Add every listed key to BOTH locales.

- [ ] **Step 2: Add EN keys** (mode labels Off/Allowlist/Denylist, CIDR list label + helptext, path-rules section title, add/remove, prefix label + helptext "/docs matches /docs and everything under it", basic-auth labels).

- [ ] **Step 3: Add FR keys** — natural French, matching the existing `routes.*` tone.

- [ ] **Step 4: Run parity + component tests**

Run: `cd web/frontend && npx vitest run src/lib/i18n/index.test.ts && npx vitest run src/lib/components/routes/`
Expected: PASS (parity guard green, no missing key).

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/i18n/locales/en.json web/frontend/src/lib/i18n/locales/fr.json
git commit -m "i18n(routes): IP filter + path rules keys EN+FR"
```

---

### Task 11: Full build + empirical live-serve smoke

**Files:** Produces `docs/smoke-test-path-rules.md`.

- [ ] **Step 1: Full backend + frontend build + suites**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go build ./... && go vet ./... && go test ./internal/caddymgr/ ./internal/storage/ ./internal/api/` then `cd web/frontend && npm run build && npx vitest run && npx svelte-check --threshold error`
Expected: all green.

- [ ] **Step 2: Live smoke against a real binary** (per CLAUDE.md; reuse the smoke recipe from `docs/smoke-test-csr-generation.md` — dev binary + setup token + a test upstream). Document each in `docs/smoke-test-path-rules.md`:
  1. Create a proxy route to a test upstream with: route IP-filter `deny 203.0.113.0/24`; path-rule `/docs` basic-auth; path-rule `/metrics-zabbix` IP-allow `192.168.1.5`.
  2. `/api/v1/x` → 200 (public catch-all).
  3. `/docs` → 401 without creds; 200 with the basic-auth creds.
  4. `/metrics-zabbix` from an allowed source → 200; from another → 403. **Set `ARENET_TRUSTED_PROXIES` + send `X-Forwarded-For`, confirm the XFF IP (not the socket IP) is the one matched** — proves `client_ip` (not `remote_ip`).
  5. Longest-prefix: add `/docs/admin` IP-allow → `/docs/admin/x` hits the IP rule (403 from a non-allowed IP even WITH basic-auth creds), `/docs/other` still hits basic-auth.
  6. Route IP-deny inheritance: a request from `203.0.113.5` gets 403 on `/api/v1/x` too (global gate applies to all paths).
  7. WAF still fires on `/docs` (additive-override): a WAF-triggering payload to `/docs` is caught (if WAF enabled on the route).
  8. Restart → path-rules + IP-filter persist (BoltDB).

- [ ] **Step 3: Commit the smoke doc**

```bash
git add docs/smoke-test-path-rules.md
git commit -m "docs(routes): path-rules + IP filter live-serve smoke results"
```

---

## Post-plan (outside task loop)

- **Final opus whole-branch review** (non-negotiable) BEFORE the PR — special attention: the allow-mode fail-closed matcher, the layer ordering (path overrides don't bypass global WAF/CrowdSec), the wire-field-gap completeness, secret redaction of path-rule password hashes. Fix findings via subagent, then PR `feature/path-based-rules` → main.
- **Docs/Wiki** (Routes EN+FR): document per-path rules + route IP filter — follow-up docs PR.
- **v2 backlog**: forward-auth per path (passthrough/outpost × path-matching); per-path WAF on/off + rate-limit.
