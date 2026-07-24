# Per-path skip-verify + conditional weight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each `PathRule` its own `insecureSkipVerify` (so an https self-signed backend on one path no longer forces the whole route insecure), and hide the path pool's weight field unless its LB is `weighted_round_robin` (mirroring the route pool).

**Architecture:** Add one optional bool field to `storage.PathRule`, thread it through the API wire (request/map/response) and the frontend payload, and change ONE emission call site (`manager.go:1658`) to pass `pr.InsecureSkipVerify` instead of `r.InsecureSkipVerify`. `buildReverseProxyHandler`/`proxyPoolParams` already carry an `InsecureSkipVerify` field (v2.23.0) — only the SOURCE changes, no emission refactor. The weight fix is pure frontend: a per-card `weightVisible` derived from the rule's LB policy.

**Tech Stack:** Go 1.25 (storage, net/http API, caddymgr emission), Caddy v2.11.3, SvelteKit/Svelte 5 + TypeScript, Vitest.

## Global Constraints

- **AGPL header** on every new Go/TS file.
- **Migration-free:** the new `PathRule.InsecureSkipVerify` is `omitempty`; a path without it stores + emits byte-identically to v2.23.0.
- **Wire-field-gap** ([[route_wire_field_gap_regression]]): `insecureSkipVerify` must traverse `pathRuleReq` (request) + `mapPathRuleReqs` (map) + `toPathRulesResp` (response) + BOTH frontend payload sites (hydration + submit), or it is silently dropped.
- **Autonomy (Q1):** a path pool's skip-verify is `pr.InsecureSkipVerify` (default false = strict); it does NOT read the route's. A path with NO pool keeps inheriting the route's whole `proxyHandler` (unchanged).
- **Q2:** the path weight input is visible only when `rule.lbPolicy === 'weighted_round_robin'` (mirror `+page.svelte:1671`).
- **Q3:** the "skip TLS verify" checkbox is visible only when the path pool has at least one `https://` URL.
- **`go test -race ./internal/caddymgr/` before PR** ([[caddymgr_race_test_gate]]).
- **i18n EN+FR parity** for the one new key.
- **Version:** v2.23.1 (patch). No tag until operator go-ahead.

**Key existing anchors (verbatim from the codebase):**
- `storage.PathRule` struct at `internal/storage/routes.go:100-110` (has PathPrefix/BasicAuth/IPFilter/Upstreams/LBPolicy/HealthCheck).
- Wire mirror `pathRuleReq` at `internal/api/handler.go:1151-1159`; mapper `mapPathRuleReqs` upstream block at `handler.go:1212-1241`; response `toPathRulesResp` upstream block at `handler.go:1929-1949`.
- Emission call site at `internal/caddymgr/manager.go:1649-1660` — the `pathProxy` closure; line 1658 currently `InsecureSkipVerify: r.InsecureSkipVerify`; comment at 1646 asserts inheritance. `proxyPoolParams.InsecureSkipVerify` already exists (`reverse_proxy_emit.go:45`). `poolUsesHTTPS([]storage.Upstream) bool` at `path_rules_emit.go:36`.
- Frontend: `PathRule` TS type at `web/frontend/src/lib/api/types.ts` (~line 786, has upstreams?/lbPolicy?/healthCheck?); `PathRulesSection.svelte` weight input at lines 286-304, LB select 330-359, HC block 361-386; `+page.svelte` payload hydration ~1338 + submit ~2079.

---

### Task 1: Storage — `PathRule.InsecureSkipVerify` field

**Files:**
- Modify: `internal/storage/routes.go:100-110` (PathRule struct)
- Test: `internal/storage/routes_pathrule_upstream_test.go` (extend)

**Interfaces:**
- Produces: `storage.PathRule.InsecureSkipVerify bool` json `insecure_skip_verify,omitempty`.

- [ ] **Step 1: Write the failing test**

Add to `internal/storage/routes_pathrule_upstream_test.go`:

```go
func TestPathRule_InsecureSkipVerify_RoundTrips(t *testing.T) {
	pr := PathRule{
		PathPrefix:         "/legacy",
		Upstreams:          upstreamPool("https://old:8443"),
		LBPolicy:           LBPolicyRoundRobin,
		InsecureSkipVerify: true,
	}
	if err := pr.Validate(); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	if !pr.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should be true")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/storage/ -run TestPathRule_InsecureSkipVerify -v`
Expected: compile error (field doesn't exist).

- [ ] **Step 3: Add the field**

In `internal/storage/routes.go`, after the `HealthCheck` field in `PathRule` (line 110):

```go
	// InsecureSkipVerify (v2.23.1) applies ONLY to this path's own pool.
	// Autonomous: a path pool does NOT inherit the route's skip-verify
	// posture (Q1). Default false = strict TLS validation. Only consulted
	// when the pool is https (transport.tls is emitted). omitempty →
	// migration-free.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/storage/ -run TestPathRule_InsecureSkipVerify -v`
Expected: PASS.

- [ ] **Step 5: Full storage suite + vet**

Run: `go test ./internal/storage/ && go vet ./internal/storage/`
Expected: PASS, no warnings.

- [ ] **Step 6: Commit**

```bash
git add internal/storage/routes.go internal/storage/routes_pathrule_upstream_test.go
git commit -m "feat(path-upstream): PathRule gains per-path InsecureSkipVerify field"
```

---

### Task 2: API wire — thread `insecureSkipVerify` through the path-rule mapper

**Files:**
- Modify: `internal/api/handler.go:1151-1159` (pathRuleReq), `handler.go:1212-1241` (mapPathRuleReqs), `handler.go:1929-1949` (toPathRulesResp)
- Test: `internal/api/routes_pathrule_upstream_test.go` (extend)

**Interfaces:**
- Consumes: `storage.PathRule.InsecureSkipVerify` (Task 1).
- Produces: `pathRuleReq.InsecureSkipVerify bool` json `insecureSkipVerify,omitempty`; mapped in the `len(Upstreams)>0` block; echoed in response.

- [ ] **Step 1: Write the failing test**

Add to `internal/api/routes_pathrule_upstream_test.go`:

```go
func TestMapPathRuleReqs_InsecureSkipVerifyMapped(t *testing.T) {
	reqs := []pathRuleReq{{
		PathPrefix:         "/legacy",
		Upstreams:          []upstreamReq{{URL: "https://old:8443", Weight: 1}},
		LBPolicy:           "round_robin",
		InsecureSkipVerify: true,
	}}
	out, err := mapPathRuleReqs(reqs, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !out[0].InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify not mapped: %+v", out[0])
	}
}

func TestToPathRulesResp_EchoesInsecureSkipVerify(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix:         "/legacy",
		Upstreams:          []storage.Upstream{{URL: "https://old:8443", Weight: 1}},
		LBPolicy:           "round_robin",
		InsecureSkipVerify: true,
	}}
	out := toPathRulesResp(rules)
	if !out[0].InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify not echoed: %+v", out[0])
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/api/ -run 'TestMapPathRuleReqs_InsecureSkipVerify|TestToPathRulesResp_EchoesInsecure' -v`
Expected: compile error (field doesn't exist).

- [ ] **Step 3: Add the wire field**

In `internal/api/handler.go`, in `pathRuleReq` (after `HealthCheck`, line 1159):

```go
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
```

- [ ] **Step 4: Map it (request → storage)**

In `mapPathRuleReqs`, inside the `if len(r.Upstreams) > 0 {` block (after the HealthCheck map, before the closing brace at line 1240-1241):

```go
			pr.InsecureSkipVerify = r.InsecureSkipVerify
```

- [ ] **Step 5: Echo it (storage → response)**

In `toPathRulesResp`, inside the `if len(pr.Upstreams) > 0 {` block (after the HealthCheck echo, before the closing brace ~line 1948):

```go
			out[i].InsecureSkipVerify = pr.InsecureSkipVerify
```

- [ ] **Step 6: Run to verify it passes**

Run: `go test ./internal/api/ -run 'TestMapPathRuleReqs_InsecureSkipVerify|TestToPathRulesResp_EchoesInsecure' -v`
Expected: PASS (both).

- [ ] **Step 7: Full api suite + vet**

Run: `go test ./internal/api/ && go vet ./internal/api/`
Expected: PASS, no warnings (exercises the DisallowUnknownFields round-trip via existing tests).

- [ ] **Step 8: Commit**

```bash
git add internal/api/handler.go internal/api/routes_pathrule_upstream_test.go
git commit -m "feat(path-upstream): thread per-path insecureSkipVerify through the API wire"
```

---

### Task 3: Emission — pass the path's own skip-verify (autonomy)

**Files:**
- Modify: `internal/caddymgr/manager.go:1646-1659` (the pathProxy closure)
- Test: `internal/caddymgr/path_rules_upstream_emit_test.go` (extend)

**Interfaces:**
- Consumes: `storage.PathRule.InsecureSkipVerify` (Task 1); `proxyPoolParams.InsecureSkipVerify` (existing, v2.23.0).
- Produces: a path pool that emits `transport.tls.insecure_skip_verify` from its OWN field, independent of the route.

**This touches the TLS emission path — `go test -race ./internal/caddymgr/` is mandatory.**

- [ ] **Step 1: Write the failing tests**

Add to `internal/caddymgr/path_rules_upstream_emit_test.go`:

```go
func TestPathRulesSubroute_PathSkipVerifyAutonomous(t *testing.T) {
	// A path with insecureSkipVerify=true + https pool emits
	// transport.tls.insecure_skip_verify=true, driven by the PATH's field
	// (the emitPathSubrouteJSON helper wires InsecureSkipVerify from the
	// rule, mirroring the manager.go call site after this task).
	rules := []storage.PathRule{{
		PathPrefix:         "/legacy",
		Upstreams:          []storage.Upstream{{URL: "https://old:8443", Weight: 1}},
		LBPolicy:           storage.LBPolicyRoundRobin,
		InsecureSkipVerify: true,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "insecure_skip_verify") {
		t.Fatalf("expected insecure_skip_verify for the path pool; got: %s", js)
	}
}

func TestPathRulesSubroute_PathStrictByDefault(t *testing.T) {
	// A path with insecureSkipVerify=false (default) + https pool emits a
	// strict tls block (no insecure_skip_verify), proving the path does NOT
	// inherit a route-level insecure posture.
	rules := []storage.PathRule{{
		PathPrefix: "/legacy",
		Upstreams:  []storage.Upstream{{URL: "https://old:8443", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "\"tls\"") {
		t.Fatalf("https path pool must still emit a tls block; got: %s", js)
	}
	if strings.Contains(js, "insecure_skip_verify") {
		t.Fatalf("strict path pool must NOT emit insecure_skip_verify; got: %s", js)
	}
}
```

The `emitPathSubrouteJSON` helper (in that file) currently hardwires `InsecureSkipVerify: false` in its `pathProxy` closure. Update it to read from the rule:

Change (in `emitPathSubrouteJSON` and `firstRuleHandle`, both closures):
```go
			InsecureSkipVerify: false,
```
to:
```go
			InsecureSkipVerify: pr.InsecureSkipVerify,
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/caddymgr/ -run TestPathRulesSubroute_PathSkipVerify -v`
Expected: FAIL on the skip-verify test (helper passes false → the manager.go source isn't changed yet; the helper change in Step 1 makes the test meaningful, but the real call site must also change — do Step 3).

- [ ] **Step 3: Change the manager.go call site**

In `internal/caddymgr/manager.go`, in the `pathProxy` closure (line 1658), change:

```go
					InsecureSkipVerify: r.InsecureSkipVerify,
```
to:
```go
					InsecureSkipVerify: pr.InsecureSkipVerify,
```

And update the DECISION comment at line 1646-1648 to reflect autonomy:

```go
			// A path pool is autonomous (v2.23.1): its InsecureSkipVerify is
			// the path rule's OWN field, NOT the route's — so a self-signed
			// https backend on one path doesn't force the whole route insecure
			// (Q1). UploadStreamingMode is still inherited from the route (no
			// per-path toggle — YAGNI). A rule with no pool inherits the
			// route's whole proxyHandler.
```

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./internal/caddymgr/ -run TestPathRulesSubroute -v`
Expected: PASS (both new + the existing subroute tests).

- [ ] **Step 5: Full caddymgr suite + race + golden**

Run: `go test ./internal/caddymgr/ && go test -race ./internal/caddymgr/`
Expected: PASS both. The Task-3-v2.23.0 golden (`TestBuildReverseProxyHandler_RouteEmissionByteIdentical`) must still pass (its fixtures have no path rules).

- [ ] **Step 6: Commit**

```bash
git add internal/caddymgr/manager.go internal/caddymgr/path_rules_upstream_emit_test.go
git commit -m "fix(path-upstream): a path pool uses its OWN insecureSkipVerify, not the route's"
```

---

### Task 4: Frontend — TS type + payload wiring + conditional weight + TLS checkbox

**Files:**
- Modify: `web/frontend/src/lib/api/types.ts` (PathRule interface)
- Modify: `web/frontend/src/lib/components/routes/PathRulesSection.svelte`
- Modify: `web/frontend/src/routes/routes/+page.svelte` (payload hydration + submit)
- Modify: `web/frontend/src/lib/i18n/locales/en.json` + `fr.json` (one new key)
- Test: `web/frontend/src/lib/components/routes/PathRulesSection.test.ts` (extend)

**Interfaces:**
- Consumes: the wire field `insecureSkipVerify` (Task 2).
- Produces: `PathRule.insecureSkipVerify?: boolean`; a weight column gated on `weighted_round_robin`; a "skip TLS verify" checkbox gated on an https pool URL; the field carried through hydration + submit.

- [ ] **Step 1: Add the TS field**

In `web/frontend/src/lib/api/types.ts`, in the `PathRule` interface (after `healthCheck?`):

```ts
	/** Per-path TLS skip-verify (v2.23.1). Autonomous — does not inherit the
	 *  route's posture. Only meaningful when the path pool is https. */
	insecureSkipVerify?: boolean;
```

- [ ] **Step 2: Write the failing component tests**

Add to `web/frontend/src/lib/components/routes/PathRulesSection.test.ts` (match the existing behavior-based, testid style):

```ts
it('hides the weight input unless the path LB is weighted_round_robin', async () => {
	const value = [{ pathPrefix: '/v1', upstreams: [{ url: 'http://a:8080', weight: 1 }], lbPolicy: 'round_robin' as const }];
	const { queryByTestId } = render(PathRulesSection, { value });
	// round_robin → no weight input
	expect(queryByTestId('path-rule-upstream-weight-0-0')).toBeNull();
});

it('shows the weight input when the path LB is weighted_round_robin', async () => {
	const value = [{ pathPrefix: '/v1', upstreams: [{ url: 'http://a:8080', weight: 1 }], lbPolicy: 'weighted_round_robin' as const }];
	const { getByTestId } = render(PathRulesSection, { value });
	expect(getByTestId('path-rule-upstream-weight-0-0')).toBeInTheDocument();
});

it('shows the skip-TLS-verify checkbox only when the pool has an https URL', async () => {
	const httpRule = [{ pathPrefix: '/v1', upstreams: [{ url: 'http://a:8080', weight: 1 }], lbPolicy: 'round_robin' as const }];
	const { queryByTestId, rerender } = render(PathRulesSection, { value: httpRule });
	expect(queryByTestId('path-rule-skip-verify-0')).toBeNull();
	const httpsRule = [{ pathPrefix: '/v1', upstreams: [{ url: 'https://a:8443', weight: 1 }], lbPolicy: 'round_robin' as const }];
	await rerender({ value: httpsRule });
	expect(queryByTestId('path-rule-skip-verify-0')).toBeInTheDocument();
});
```

(If `rerender` isn't the harness's API, render two separate instances instead — match the file's existing conventions.)

- [ ] **Step 3: Run to verify they fail**

Run: `cd web/frontend && npx vitest run src/lib/components/routes/PathRulesSection.test.ts`
Expected: FAIL (weight always shown; no skip-verify checkbox).

- [ ] **Step 4: Add the i18n key (EN + FR)**

In both `web/frontend/src/lib/i18n/locales/en.json` and `fr.json`, under `routes.pathRules`:
- `upstreamSkipVerifyLabel`: EN "Skip TLS verification (self-signed backend)" / FR "Ignorer la vérification TLS (backend auto-signé)"

Keep EN/FR key parity.

- [ ] **Step 5: Gate the weight input (Q2)**

In `PathRulesSection.svelte`, derive per-card weight visibility and wrap the weight `<div class="w-24">…</div>` (lines 286-304) in it. Add a helper near the top script:

```ts
	function weightVisible(rule: PathRule): boolean {
		return rule.lbPolicy === 'weighted_round_robin';
	}
	function poolIsHttps(rule: PathRule): boolean {
		return !!rule.upstreams?.some((u) => u.url.trim().toLowerCase().startsWith('https://'));
	}
```

Wrap the weight block:
```svelte
									{#if weightVisible(rule)}
										<div class="w-24">
											<!-- existing weight label + input, unchanged -->
										</div>
									{/if}
```

- [ ] **Step 6: Add the skip-verify checkbox (Q1 + Q3)**

In `PathRulesSection.svelte`, after the health-check block (before the `</div>` at line 387), add a checkbox gated on `poolIsHttps(rule)`:

```svelte
							{#if rule.upstreams && rule.upstreams.length > 0 && poolIsHttps(rule)}
								<label class="inline-flex items-center gap-2 text-sm text-secondary cursor-pointer">
									<input
										type="checkbox"
										class="accent-cyan"
										checked={!!rule.insecureSkipVerify}
										onchange={(e) =>
											(value[i].insecureSkipVerify = (e.currentTarget as HTMLInputElement).checked)}
										data-testid="path-rule-skip-verify-{i}"
									/>
									{language.current && t('routes.pathRules.upstreamSkipVerifyLabel')}
								</label>
							{/if}
```

- [ ] **Step 7: Thread through the payload (hydration + submit)**

In `web/frontend/src/routes/routes/+page.svelte`:

Hydration (~line 1338-1342, the `pathRules: (r.pathRules ?? []).map((rule) => ({...}))` mapper) — add after `healthCheck`:
```js
				insecureSkipVerify: rule.insecureSkipVerify
```

Submit (~line 2079-2088, the conditional-spread inside `sanitizePathRules(...)`) — inside the `rule.upstreams && rule.upstreams.length > 0 ? {...}` spread, add `insecureSkipVerify`:
```js
								...(rule.upstreams && rule.upstreams.length > 0
									? {
											upstreams: rule.upstreams.map((u) => ({ url: u.url, weight: u.weight })),
											lbPolicy: rule.lbPolicy ?? 'round_robin',
											insecureSkipVerify: !!rule.insecureSkipVerify
										}
									: {}),
```
(Read the exact current spread first and match its shape — only ADD the `insecureSkipVerify` line.)

- [ ] **Step 8: Run tests + svelte-check + full suite**

Run: `cd web/frontend && npx vitest run src/lib/components/routes/PathRulesSection.test.ts && npx svelte-check --threshold error && npx vitest run`
Expected: PASS, 0 svelte-check errors, full suite green.

- [ ] **Step 9: i18n parity check**

Run: `grep -c "upstreamSkipVerifyLabel" web/frontend/src/lib/i18n/locales/en.json web/frontend/src/lib/i18n/locales/fr.json`
Expected: 1 in each.

- [ ] **Step 10: Commit**

```bash
git add web/frontend/src/lib/api/types.ts web/frontend/src/lib/components/routes/PathRulesSection.svelte web/frontend/src/lib/components/routes/PathRulesSection.test.ts web/frontend/src/routes/routes/+page.svelte web/frontend/src/lib/i18n/locales/en.json web/frontend/src/lib/i18n/locales/fr.json
git commit -m "feat(path-upstream): per-path skip-verify checkbox + conditional weight (UI)"
```

---

### Task 5: Build + changelog note + final gate

**Files:**
- Modify: `docs/smoke-test-path-upstream.md` (add a skip-verify gate note) — optional
- Test: full build + suites

**Interfaces:** consumes everything above.

- [ ] **Step 1: Full frontend build**

Run: `cd web/frontend && npm run build`
Expected: build succeeds.

- [ ] **Step 2: Add a smoke note for the new behaviour**

Append to `docs/smoke-test-path-upstream.md` a short note: a path with an https self-signed backend needs the per-path "Skip TLS verification" checkbox (v2.23.1); the route's own insecure-skip-verify no longer applies to a path that has its own pool.

- [ ] **Step 3: Final gate — all suites + race**

Run from repo root: `go test ./... && go test -race ./internal/caddymgr/`
Then from web/frontend: `npx vitest run && npx svelte-check --threshold error`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add docs/smoke-test-path-upstream.md
git commit -m "docs(path-upstream): note per-path skip-verify in the smoke doc (v2.23.1)"
```

---

## Post-plan (controller, not a task)
- Inline review after each task; ONE final whole-branch review before PR (no dedicated review — isolated field, no refactor).
- Version v2.23.1 — tag only after operator go-ahead.
- Changelog: the behaviour change (a path with its own pool that previously inherited the route's insecure-skip-verify is now strict by default) is documented — impact minimal (feature is 1 day old, only dogfooding uses it).

## Self-Review notes
- Spec coverage: Q1 autonomy (Task 1 field, Task 3 emission `pr.` + strict-by-default test) ✓; Q2 conditional weight (Task 4 `weightVisible` + 2 tests) ✓; Q3 https-gated checkbox (Task 4 `poolIsHttps` + test) ✓; wire-gap (Task 2 req+map+resp, Task 4 hydration+submit) ✓; byte-identity (Task 3 golden unchanged) ✓; race gate (Task 3 step 5) ✓; i18n parity (Task 4 step 9) ✓.
- Type consistency: `InsecureSkipVerify bool` (storage) / `insecureSkipVerify` (wire+TS) used consistently; `proxyPoolParams.InsecureSkipVerify` reused (no new emission type). `emitPathSubrouteJSON`/`firstRuleHandle` helper closures both updated to `pr.InsecureSkipVerify` (Task 3 step 1) so the emission tests exercise the real path.
- Open verification flagged for the implementer: the exact current shape of the `+page.svelte` submit spread (Task 4 step 7 — read before editing), and whether the test harness supports `rerender` (Task 4 step 2).
