# Per-Route Basic Auth Hash Cache — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable Caddy's built-in Basic Auth hash-verification cache on every emitted `http_basic` provider, so repeated same-credential verifications (the SSE-reconnection pattern) collapse to one argon2id derivation + cache hits — fixing the RAM/swap exhaustion.

**Architecture:** A one-line addition to the Caddy config translation: emit `"hash_cache": map[string]any{}` on the `http_basic` provider map. Guarded by a config-emission assertion; the shape's acceptance by real Caddy is already covered by an existing `caddy.Validate()` test over a basic-auth route.

**Tech Stack:** Go 1.25, embedded Caddy v2.11.3.

**Spec:** `docs/superpowers/specs/2026-07-13-basic-auth-hash-cache-design.md`

## Global Constraints

- Match Caddy's actual API: the field is `HashCache *Cache json:"hash_cache,omitempty"` (`caddyauth/basicauth.go:57`), provisioned from an empty object (`basicauth.go:133-136`). No tunable fields on `Cache`.
- gofmt -s clean, go vet clean; AGPL header already present (no new files).
- Do NOT change the argon2id cost, the handler-chain order, or forward-auth/none modes.
- Backend build/test: `go build ./...`, `go test ./internal/caddymgr/`.

---

### Task 1: Emit `hash_cache` on the basic-auth provider

**Files:**
- Modify: `internal/caddymgr/manager.go` (the `RouteAuthBasic` case, ~lines 1562-1573)
- Modify: `internal/caddymgr/manager_test.go` (`TestBuildConfigJSON_BasicAuth_EmitsAuthHandler`, ~line 859)

**Interfaces:** none new — a config-shape change only.

- [ ] **Step 1: Write the failing assertion**

In `internal/caddymgr/manager_test.go`, inside `TestBuildConfigJSON_BasicAuth_EmitsAuthHandler` (~line 859), after the block that extracts `httpBasic` and asserts `hash["algorithm"]` (right before or after the `accounts` assertions), add:

```go
	// hash_cache must be emitted so Caddy caches per-credential
	// verification (avoids re-running the 64 MiB argon2id hash on every
	// request — catastrophic for SSE-heavy upstreams). Empty object =
	// enabled.
	if _, ok := httpBasic["hash_cache"].(map[string]any); !ok {
		t.Errorf("http_basic.hash_cache missing or wrong type; want an (empty) object to enable Caddy's verification cache. got: %v", httpBasic["hash_cache"])
	}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/caddymgr/ -run 'TestBuildConfigJSON_BasicAuth_EmitsAuthHandler' -v`
Expected: FAIL — `http_basic.hash_cache missing or wrong type ... got: <nil>` (the key isn't emitted yet).

- [ ] **Step 3: Emit `hash_cache` in the provider**

In `internal/caddymgr/manager.go`, the `RouteAuthBasic` case (~line 1562), add the `hash_cache` key to the `http_basic` map. The map currently reads:

```go
				"http_basic": map[string]any{
					"hash":  map[string]any{"algorithm": "argon2id"},
					"realm": fmt.Sprintf("Arenet route %s", r.Host),
					"accounts": []map[string]any{
						{
							"username": r.BasicAuth.Username,
							"password": r.BasicAuth.PasswordHash,
						},
					},
				},
```

Change it to (insert the `hash_cache` key with its explanatory comment, after `realm`):

```go
				"http_basic": map[string]any{
					"hash":  map[string]any{"algorithm": "argon2id"},
					"realm": fmt.Sprintf("Arenet route %s", r.Host),
					// hash_cache enables Caddy's per-credential
					// verification cache (caddyauth.Cache). Without it,
					// Caddy re-runs the full 64 MiB argon2id derivation on
					// EVERY request; an SSE-heavy upstream that opens many
					// reconnecting streams then exhausts RAM+swap. The
					// cache collapses repeated identical verifications to
					// one hash (singleflight coalesces concurrent ones).
					// Empty object = enabled; the cache has no tunable
					// fields (internal random eviction). Tradeoff:
					// plaintext passwords stay in memory a bit longer —
					// acceptable, since Basic Auth receives them per
					// request over the wire regardless.
					"hash_cache": map[string]any{},
					"accounts": []map[string]any{
						{
							"username": r.BasicAuth.Username,
							"password": r.BasicAuth.PasswordHash,
						},
					},
				},
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/caddymgr/ -run 'TestBuildConfigJSON_BasicAuth_EmitsAuthHandler' -v`
Expected: PASS.

- [ ] **Step 5: Run the caddy.Validate coverage + full package**

Run: `go test ./internal/caddymgr/ -run 'TestBuildConfigJSON_LoadsCleanly$' -v`
Expected: PASS — this test builds a `RouteAuthBasic` route (`everything.example.com`) and runs `caddy.Validate()` on the emitted config, so it proves the real vendored Caddy v2.11.3 accepts `hash_cache: {}` on the http_basic provider. (If it FAILS with a provisioning/unknown-field error, the emitted shape is wrong — stop and report.)

Then the whole package: `go test ./internal/caddymgr/` → all pass (no regression).

- [ ] **Step 6: gofmt + vet + commit**

```bash
gofmt -s -w internal/caddymgr/manager.go internal/caddymgr/manager_test.go
go vet ./internal/caddymgr/
git add internal/caddymgr/manager.go internal/caddymgr/manager_test.go
git commit -m "fix(caddymgr): enable Caddy hash_cache on per-route basic auth

Per-route basic auth used argon2id (64 MiB/verification, login-calibrated)
re-run on EVERY request because the emitted http_basic provider had no
hash_cache. An SSE-heavy upstream (Dockhand) opens many reconnecting
streams; each reconnect re-derived the 64 MiB hash → RAM+swap exhaustion,
freezes, and 502s. Emit hash_cache:{} so Caddy caches per-credential
verification (singleflight coalesces concurrent identical checks) — its
documented mechanism for traffic-heavy secure-hash servers. Applies to all
basic-auth routes; argon2id cost unchanged. Guarded by an emission
assertion; caddy.Validate coverage via the existing LoadsCleanly test."
```

---

### Task 2: Runtime verification

**Files:** none (observation only).

- [ ] **Step 1: Build**

Run: `go build ./... && go build -o arenet ./cmd/arenet`
Expected: clean build.

- [ ] **Step 2: Confirm the emitted config carries hash_cache (surface check)**

The operator's real reproduction is an SSE-heavy upstream (Dockhand) with a basic-auth route under a Proxmox VM at 100% RAM — not reproducible in this workspace. The observable surface here is the emitted Caddy config. Run the binary with a basic-auth route (or rely on the `caddy.Validate` test from Task 1 Step 5 as the acceptance proof) and confirm the running config's `http_basic` provider contains `hash_cache`. Capture the relevant JSON snippet.

- [ ] **Step 3: Operator-side runtime confirmation (hand-off)**

The definitive runtime proof is on the operator's VM (they have Dockhand). Provide them the check: with the fixed binary and the Dockhand route in basic auth, load the SSE UI and confirm (a) the stream stays open (no freeze/502 loop), (b) `arenet` RAM stays bounded (no runaway to swap), and (c) a `curl -u user:pass` loop shows the first request paying ~100 ms (argon2id) and subsequent identical-credential requests returning fast (cache hits). Report PASS/FAIL from their observation.

---

## Self-Review

**Spec coverage:** emit `hash_cache: {}` on the http_basic provider → Task 1 Step 3. Emission guard → Task 1 Steps 1-2. caddy.Validate acceptance → Task 1 Step 5 (existing LoadsCleanly test, already covers a basic-auth route). Applies to all basic-auth routes (the emission is unconditional in the RouteAuthBasic case) → inherent. Runtime verification → Task 2. Non-goals (no cost change, no chain-order change) → respected (only the provider map gains one key). All covered.

**Placeholder scan:** No TBD/TODO; the full before/after map is given. Task 2's operator hand-off is a real constraint (the RAM-exhaustion repro needs the operator's Dockhand + VM), not a placeholder — the in-workspace surface (caddy.Validate + emitted-config check) is exercised in Task 1.

**Type consistency:** `hash_cache` emitted as `map[string]any{}` (Task 1 Step 3) matches the test assertion's `.(map[string]any)` type check (Task 1 Step 1). No new Go types or signatures.
