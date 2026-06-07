<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Discovery — WAF mode lifecycle bugs

**Date**: 2026-06-08
**Status**: Operator-reported, partial empirical confirmation pending.
**Severity**: HIGH — operators cannot reliably toggle `wafMode` per route. False security model in the dashboard ("this route is in detect mode" while it actually blocks).
**Refs**: Step I.4 spec (WAFMode enum), Step M security spec (Arenet WAF module), commit history `internal/waf/module.go`, `internal/caddymgr/manager.go`.

## §1 Operator evidence

Four distinct empirical observations from `barto95100@worldgeekwide.fr`'s homelab deployment.

### §1.1 Bug #1 — `wafMode="detect"` produces HTTP 403

- Route `1dcdd9ea-9f88-484a-b0e9-30de30e68207`, `wafMode="detect"` (verified via `GET /api/v1/routes/<id>` after the test).
- Arenet process restarted at 21:34:49 (fresh boot, fresh Provision pass — no prior Caddy state in memory).
- Request at 23:41:37: `GET /auth/login_flow` → response **HTTP 403**.
- Server log: `BLOCK 403 ... rule 920420 PROTOCOL` (CRS rule 920420 fires).
- **Expected**: HTTP 200 (or 405 from upstream) + log entry at DETECT level (severity-filtered, no block).

### §1.2 Bug #2 — Hot-reload doesn't propagate `wafMode` change

- Edit `wafMode: "detect" → "off"` via the admin UI.
- `PUT /api/v1/routes/<id>` returns 200; subsequent `GET /api/v1/routes/<id>` confirms `"wafMode":"off"` in the DB.
- mgr.Apply runs as part of the PUT flow (the existing reload path at `internal/api/routes.go:1274-1284`).
- New requests to the route **still block**.

### §1.3 Bug #3 — Mode change post-creation is sticky, even after restart

- Route `ha.worldgeekwide.fr` originally created with `wafMode="detect"`.
- Edited to `"off"` via the UI.
- Arenet restarted (fresh boot).
- New request → still 403.
- **Workaround**: DELETE the route + RECREATE it from scratch with `wafMode="off"` → HTTP 200 (WAF correctly skipped).

The DELETE-then-CREATE workaround is the key signal: a fresh-creation route with `wafMode="off"` is handled correctly (the cheap-skip path at `internal/caddymgr/manager.go:1756-1759` returns nil so no `arenet_waf` handler is emitted in the per-route chain). But a route whose `wafMode` was changed from a non-`"off"` value to `"off"` continues to fire the WAF — pointing at persisted state somewhere in the lifecycle chain (storage, caddymgr, Caddy, or Coraza).

## §2 Code-side findings

### §2.1 `internal/waf/module.go` — Coraza wrapper

**Mode-to-directive mapping** (`buildWAF`, lines 154-173):

```go
mode := "On"
if h.Mode == "detect" {
    mode = "DetectionOnly"
}
directives := h.Directives + "\nSecRuleEngine " + mode

cfg := coraza.NewWAFConfig().
    WithErrorCallback(h.onMatch).
    WithDirectives(directives)
```

The appended `SecRuleEngine` directive **does** receive the correct value for the mode field. The Coraza WAF is built with this directive — `coraza.NewWAF(cfg)` parses the directives in source order and applies the last `SecRuleEngine` (Coraza v3's `directiveSecRuleEngine` at `internal/seclang/directives.go:317-321` sets `options.WAF.RuleEngine = engine` — a WAF-level global, last write wins).

**Directive ordering verified empirically**:
- `Include @coraza.conf-recommended` declares `SecRuleEngine DetectionOnly` at line 8 of the recommended conf.
- `Include @crs-setup.conf.example` declares nothing.
- `Include @owasp_crs/*.conf` (CRS v4.25.0) — no file under `rules/@owasp_crs/` declares `SecRuleEngine` (grep-confirmed against `/Users/l.ramos/go/pkg/mod/github.com/corazawaf/coraza-coreruleset/v4@v4.25.0/rules/`).
- Arenet appends `\nSecRuleEngine On` (or `DetectionOnly`) AFTER all includes → **last write wins** → Arenet's intent should hold.

Therefore the directive composition is **structurally correct** for both modes.

**ServeHTTP branch on mode** (`module.go:306-348`):

```go
} else if it != nil {
    // In block mode the Coraza transaction is in
    // SecRuleEngine On so it returns a real interruption.
    // In detect mode it's DetectionOnly so we should NOT
    // see an interruption — but if the user's directives
    // include a disruptive rule that bypasses
    // DetectionOnly, fall through gracefully ...
    if h.Mode == "block" {
        return caddyhttp.HandlerError{ StatusCode: ..., ... }
    }
    // detect mode + interruption: log and continue.
    return next.ServeHTTP(w, r)
}
```

ServeHTTP **does** branch correctly on `h.Mode` (line 332). When mode is `"detect"`, it returns `next.ServeHTTP(w, r)` (pass-through) regardless of whether Coraza returned an interruption — defense-in-depth against a rogue disruptive directive.

**Critical Coraza v3 invariant** (`internal/corazawaf/transaction.go:328-340`): in `DetectionOnly` mode, `tx.Interrupt(it)` stores the interruption in `tx.detectionOnlyInterruption`, NOT in `tx.interruption`. So `tx.Interruption()` returns `nil` for DetectionOnly transactions. The `it != nil` branch in arenet's ServeHTTP **should never fire in detect mode** — making the in-code `if h.Mode == "block"` guard at line 332 effectively belt-and-braces.

**Unit-test confirmation** (`module_test.go:206-232`):

`TestArenetWaf_DetectMode_TripsRule_Emits_And_PassesThrough` exercises the full Provision → ServeHTTP path with a CRS-shaped rule, asserts `next.called == true` + `rec.Code == 200` + one event emitted. This test passes. So the in-Go logic is exercised and correct.

**The discrepancy**: operator empirical evidence says detect-mode-from-inception still produces 403. The unit test says detect mode passes through. The directive ordering is structurally correct. The Coraza invariant is verified. **There is no code path in the read surface that explains Bug #1 as reported.** §6 lists the empirical probes needed to disambiguate.

### §2.2 `internal/waf/module.go` — usage pool

Pool key composition (`computePoolKey`, lines 179-189):

```go
hash := sha256.New()
hash.Write([]byte(h.Mode))
hash.Write([]byte{0})
hash.Write([]byte(h.Directives))
hash.Write([]byte{0})
if h.LoadOWASPCRS {
    hash.Write([]byte("crs"))
}
return fmt.Sprintf("arenet-waf-%x", hash.Sum(nil))
```

The pool key includes `Mode` + `Directives` + `LoadOWASPCRS`, but **NOT** `RouteID`. The intent (per the struct comment at lines 175-178) is reuse: "two handlers with the same (mode, directives, load_owasp_crs) share a WAF instance". For the production caddymgr emit (`manager.go:1760-1768`), `Directives` is the same hardcoded constant for every route, and `LoadOWASPCRS` is always `true` — so **all routes with the same `wafMode` share ONE Coraza WAF instance** in the pool.

**Pool lifecycle on mode change**:

1. Route A created `wafMode="detect"` → pool key `K_detect` → WAF instance `W_detect` (refcount 1).
2. Route B created `wafMode="detect"` → pool key `K_detect` → reuses `W_detect` (refcount 2). ✓
3. Route A edited `wafMode="block"` → mgr.Apply → caddy.Load(cfg, true):
   - Caddy creates a NEW handler instance for A with `Mode="block"`.
   - Calls `Cleanup()` on the old A handler (`module.go:194-197`) → `wafPool.Delete(K_detect)` → refcount 2 → 1 → `W_detect` survives (B still uses it). ✓
   - Calls `Provision()` on the new A handler → `wafPool.LoadOrNew(K_block)` → constructs new `W_block`. ✓
4. Route A edited `wafMode="off"` → mgr.Apply → caddy.Load(cfg, true):
   - `buildWAFHandler("A", "off")` returns nil (`manager.go:1757-1759`) → NO `arenet_waf` handler in A's chain JSON.
   - **Open question**: does Caddy call `Cleanup()` on the OLD A handler when its module entry simply disappears from the chain? This is the Caddy lifecycle contract that requires empirical verification — see §6.

**Hypothesis for Bug #2 / #3**: if Caddy does NOT call `Cleanup()` on a handler that vanishes from the chain (only on handlers whose config differs), then:
- The old A handler instance leaks its pool reference.
- `wafPool.Delete(K_detect)` is never called for A.
- `W_detect` keeps refcount 2 (A's leak + B's legitimate hold).
- **More critically**: Caddy may KEEP the old A handler instance alive (not removed from the live routes) → requests routed to A still hit `ArenetWafHandler.ServeHTTP` with the old `Mode="detect"` field set.

This is unlikely under Caddy's documented `Load(cfg, true)` semantics (force-reload should tear down everything not in the new config), but it would precisely explain the operator evidence. §6 probe #2 disambiguates.

### §2.3 `internal/caddymgr/manager.go` — config rebuild on Apply

`applyLocked` (lines 336-411):

```go
routes, err := m.store.ListRoutes(ctx)                 // fresh from store every time
...
cfgJSON, err := buildConfigJSON(routes, buildOpts{...}) // FRESH BUILD
...
m.logger.Debug("applying caddy config", "routes", len(routes), "bytes", len(cfgJSON))
if err := caddy.Load(cfgJSON, true); err != nil {       // force-reload
    return fmt.Errorf("caddy.Load: %w", err)
}
```

The caddymgr side is **structurally correct**:

- Routes are read fresh from the store on every Apply.
- `buildConfigJSON` is called from scratch — no caching of previous results.
- `caddy.Load(cfgJSON, true)` — the `true` argument forces a full reload.

The `buildWAFHandler` helper at `manager.go:1756-1769` emits the WAF handler **only when** `mode != "" && mode != "off"`. So for a route edited to `"off"`, the new emitted JSON has NO `arenet_waf` entry in its chain. Caddy receives this. What happens next depends entirely on Caddy's force-reload semantics — see §6.

### §2.4 Receiver shape — ArenetWafHandler

Method receiver inventory (`grep -n "func.*ArenetWafHandler" internal/waf/module.go`):

```
103:func (ArenetWafHandler) CaddyModule() caddy.ModuleInfo
115:func (h *ArenetWafHandler) Validate() error
133:func (h *ArenetWafHandler) Provision(_ caddy.Context) error
154:func (h *ArenetWafHandler) buildWAF() (coraza.WAF, error)
179:func (h *ArenetWafHandler) computePoolKey() string
194:func (h *ArenetWafHandler) Cleanup() error
231:func (h *ArenetWafHandler) onMatch(mr types.MatchedRule)
306:func (h ArenetWafHandler) ServeHTTP(...) error
```

**`ServeHTTP` uses a VALUE receiver** (line 306), all others use pointer receivers. In Go, this is unusual but not broken: when Caddy calls `ServeHTTP` on a `*ArenetWafHandler`, Go promotes it (since the value method is in the method set of the pointer type). But the value receiver means the call **operates on a copy** of the struct: `h.Mode`, `h.waf`, `h.poolKey` are all copied.

This is **not** the bug — `h.waf` is an interface pointer (it points to the same underlying `coraza.WAF` regardless of struct copy), and `h.Mode` is read but never written during ServeHTTP. The copy is semantically equivalent for the data this method touches.

However, if a future refactor adds a mutable per-handler field (e.g., a request counter, a hot-config field), the value receiver would silently drop the mutation. **Flag this as a smell to clean up alongside the bug fixes** — change to `func (h *ArenetWafHandler) ServeHTTP(...)` for consistency with the rest of the type.

### §2.5 Observability gap

`grep -n "logger\|slog\|Info\|Debug\|Warn" internal/waf/module.go` finds:
- One `slog.Default()` call buried in the post-interruption block path (Coraza-emitted, not arenet-attributed).
- No boot-level "WAF handler provisioned" log per route.
- No per-request DEBUG log at handler entry showing the resolved mode.
- No pool-event logs ("pool hit", "pool miss", "WAF built", "WAF destructed").

`grep -n "waf\|WAF" internal/caddymgr/manager.go | grep -i "log\|info\|warn"` finds:
- No per-route WAF emit log.

**This makes both bugs invisible from process logs.** Operators have no way to confirm "the handler currently in the chain for route X is using mode Y, built at time Z from pool key K".

### §2.6 Test gap

Two end-to-end tests are missing:

1. **Hot-reload mode-change** — create route with `wafMode="detect"`, send live request (no block), edit to `wafMode="block"` via API, reload, send same request (should block now). Would catch Bug #2 immediately.
2. **Mode-to-off post-edit** — create route with `wafMode="block"`, edit to `wafMode="off"`, reload, send a request matching a CRS rule, assert HTTP 200 + zero events emitted. Would catch Bug #3 immediately.

The existing unit test `TestArenetWaf_DetectMode_TripsRule_Emits_And_PassesThrough` (`module_test.go:206-232`) exercises only the in-process Provision → ServeHTTP path on a SINGLE handler instance — it never exercises the Caddy lifecycle, the pool, or the reload-then-re-resolve path. **This is why both bugs slipped through CI.**

There's also a `TestBuildConfigJSON_WAF_DetectMode` in `manager_test.go:841-889` that verifies the JSON emit has `"mode": "detect"`. This passes for the JSON shape but doesn't exercise the full caddymgr → caddy.Load → handler lifecycle.

## §3 Root cause analysis

| Bug | Confidence | Root cause hypothesis |
|---|---|---|
| **#1** (detect produces 403) | LOW from code reading alone | The code as written should NOT produce this behavior. Either (a) the operator's `wafMode` was not actually `"detect"` at the moment Caddy provisioned the handler (e.g., the empirical timeline is reconstructed from later DB readback, after an intermediate edit), OR (b) bug #2/#3's stale-handler theory applies (Caddy is serving requests with an OLD handler instance whose `Mode=="block"`) and the "fresh restart" the operator describes did not actually flush the pool / state because of route-creation ordering. **Needs empirical probe #1 to confirm.** |
| **#2** (hot-reload doesn't propagate) | MEDIUM | Caddy's `Load(cfg, true)` MUST tear down handlers that disappear from the chain. If it does so correctly, Bug #2 cannot exist. If it does NOT — i.e., the WAF handler instance survives even though the new chain doesn't include it — we have a Caddy-lifecycle violation that explains both #2 and #3. **Needs empirical probe #2 to confirm.** |
| **#3** (delete-recreate works, edit doesn't) | MEDIUM-HIGH | The DELETE-then-CREATE workaround is the most diagnostic signal in the report. A FRESH route with `wafMode="off"` emits NO handler — the chain has no entry to leak. An EDITED route went through a transition where the old handler was registered with Caddy and never torn down. This is exactly the Caddy-lifecycle stale-handler hypothesis. Strongly suggests root cause is shared with #2. |

**Unified hypothesis**: there is ONE underlying defect, not two — Caddy's `Load(cfg, true)` may not be calling `Cleanup()` on `arenet_waf` handlers whose route is edited from a non-`"off"` mode to `"off"`. Bug #2 is the direct symptom; Bug #3 is the same defect surfaced via an explicit reload after restart (which suggests the leaked state may actually live in Caddy's in-memory chain registry across reloads, not just at runtime). Bug #1 may be a separate independent defect OR may be a misreading of timeline (the route may have been at `"block"` during the actual handler Provision).

**Why "may"**: read-only code inspection cannot distinguish between (a) "the code is correct and the operator's observation has another cause" and (b) "the code interacts with Caddy / Coraza in a way the doc doesn't capture and we need an empirical probe". The probes in §6 are designed to converge on the truth in 2-3 careful tests.

## §4 Fix proposal sketches (no code yet — operator review first)

Mapped to the brief's 4 phases.

### §4.1 Phase 1 — Lifecycle (caddymgr re-evaluation invariant)

**Status**: the read shows applyLocked already re-builds from scratch on every Apply. There is NOTHING for caddymgr to do here — the bug, if it exists at the lifecycle layer, lives **inside Caddy** (or in arenet's interaction with Caddy's UsagePool). Phase 1 as described in the brief turns out to be a non-starter; the symptom is real but the locus is downstream.

**Adjusted Phase 1**: add an explicit `wafPool.Delete(h.poolKey)` in `Cleanup()` IF the empirical probe confirms Cleanup isn't being called by Caddy. Alternative: add a `OnStop`/post-Apply hook in caddymgr that walks the previous-vs-new route set and explicitly purges pool entries for routes whose `wafMode` changed to `"off"` or was deleted.

### §4.2 Phase 2 — Semantic (mode-honoring ServeHTTP)

**Status**: ServeHTTP **already** branches correctly on `h.Mode` (line 332). The Coraza directive composition is correct. If Bug #1 reproduces against a clean fresh route with `wafMode="detect"` from inception (confirmed by probe #1), the fix is NOT in ServeHTTP — it's in finding what's wrong with our Coraza directive composition (perhaps the CRS files we use have a pre-parsed `SecRuleEngine On` we missed). 

**Adjusted Phase 2**: add a Provision-time assertion that `tx := h.waf.NewTransaction(); tx.IsRuleEngineOff() == false && expected-engine-state == actual-engine-state`. Surface the boot log line "WAF handler ROUTE_ID provisioned with engine=<On|DetectionOnly|Off>" so the operator can confirm reality vs intent independently of running a request. If the boot log says `DetectionOnly` but the request still blocks → bug is in coraza-caddy or in our handler chain, not in directive composition.

### §4.3 Phase 3 — Hot-reload without restart (atomic.Pointer)

**Question**: is mode-as-a-runtime-mutable field the right design? The brief says "atomic.Pointer pattern for mode field — mirror V.1.3 lesson." 

This is the **Country-Block W.3 pattern** (atomic.Pointer on `GlobalDefaultStatusCode` so env-var hot-reload would work via SIGHUP). For WAF mode, the answer is more nuanced: the **Coraza WAF instance itself** is built with the mode baked in via `SecRuleEngine`. You can't atomically swap the mode field without rebuilding the WAF instance — and rebuilding the WAF instance is exactly what `caddy.Load(cfg, true)` is supposed to do via the Provision/Cleanup cycle.

**Recommendation**: do NOT pursue Phase 3 as an independent fix. The "hot-reload" path IS Caddy's `Load(cfg, true)`. The bug is that this path isn't fully closing the loop. Fix the Caddy interaction (Phase 1 adjusted) and Phase 3 becomes redundant.

### §4.4 Phase 4 — Observability

**This is the highest-priority sub-fix**, independent of bug-fix scope, because it unblocks all future WAF debugging. Add:

1. **Boot log per route** in `Provision`: `slog.Info("waf handler provisioned", "route_id", h.RouteID, "mode", h.Mode, "pool_key", h.poolKey, "engine_state", engineStateFromTx)`.
2. **Cleanup log** in `Cleanup`: `slog.Info("waf handler cleaned up", "route_id", h.RouteID, "mode", h.Mode, "pool_key", h.poolKey, "remaining_refcount", refcountAfterDelete)`.
3. **Per-request DEBUG log** at ServeHTTP entry: `slog.Debug("waf request", "route_id", h.RouteID, "mode", h.Mode, "method", r.Method, "path", r.URL.Path)`. Gated behind a DEBUG level so production logs aren't flooded.
4. **Receiver fix**: change `func (h ArenetWafHandler) ServeHTTP` to `func (h *ArenetWafHandler) ServeHTTP` (cosmetic + future-proofing).

Independent commit per Phase 4 sub-item (or one bundled "obs" commit) so the discovery work isn't bottlenecked on the diagnostic fix.

## §5 Subsequent test additions

Once the bug is empirically located, add (these were already overdue):

1. **`TestWAFLifecycle_HotReloadModeChange`** in `internal/caddymgr/manager_test.go` or new `internal/waf/integration_test.go`: create route mode=detect, applyLocked, send live request (assert 200 + 1 detect event), edit DB to mode=block, applyLocked again, send same request (assert 403 + 1 block event). Pin against Bug #2 regression.

2. **`TestWAFLifecycle_EditToOffReleasesHandler`**: create route mode=block, applyLocked, edit DB to mode=off, applyLocked, send a request matching a CRS rule (assert 200, zero events emitted, **no `arenet_waf` handler in the live config**). Pin against Bug #3 regression. Use `caddy.GetCurrentConfig()` or equivalent to introspect the post-Apply state.

3. **`TestWAFPool_ModeChangeReleasesPoolEntry`** in `internal/waf/module_test.go`: directly exercise `Provision(mode=detect)` → `Cleanup()` → assert `wafPool.Delete` returned the expected refcount. Mirror of `TestNormalSink_*` patterns from V.1.

4. **`TestWAFDirectiveComposition_ProducesExpectedEngineState`** in `internal/waf/module_test.go`: provision a handler with each `Mode` value, call `h.waf.NewTransaction()` once, assert the transaction's `IsRuleEngineOff()` + an internal-API check on `RuleEngine` field equals the intent (`On` for `block`, `DetectionOnly` for `detect`). Catches a Coraza upgrade that subtly changes directive precedence.

## §6 Empirical probes (recommended before fix)

Two careful tests will resolve the open questions in §3 — operator should run these **before** we commit to a fix path.

### §6.1 Probe #1 — Confirm Bug #1 reproduces from inception

**Goal**: distinguish "code is correct, operator timeline confused" from "fresh-from-inception detect actually 403s".

**Steps**:
1. Restart arenet (clean Caddy state).
2. Create a fresh route via the API: `POST /api/v1/routes` with `{"host": "probe1.example.com", ..., "wafMode": "detect"}`. **DO NOT edit it post-creation.**
3. Add the boot log proposed in §4.4 sub-item 1 — confirm the log line says `mode=detect, engine_state=DetectionOnly`.
4. Send a request known to trip CRS 920420 (e.g., a request with a request-line malformation).
5. Observe: response status + event-table row.

**Outcomes**:
- **HTTP 200 + 1 detect event**: Bug #1 is a timeline artifact. Original observation was after an edit that didn't propagate (i.e., the same as Bug #2/#3). Investigation collapses to ONE bug.
- **HTTP 403 + 1 block event**: Bug #1 is real and independent. We need to dig into how `coraza.NewWAF(cfg)` interprets the directive string — possibly add a `WithDirectives` self-validation step that calls `tx := waf.NewTransaction(); assert tx.RuleEngine == expected`.

### §6.2 Probe #2 — Confirm Bug #2 root cause (Caddy Cleanup semantics)

**Goal**: distinguish "Caddy calls Cleanup correctly" from "Caddy leaks the old handler".

**Steps**:
1. Add the Cleanup log proposed in §4.4 sub-item 2.
2. Create route X with `wafMode="block"`. Confirm boot log shows `provisioned mode=block, pool_key=K1`.
3. Send a request that the WAF blocks → assert 403.
4. Edit route X via API to `wafMode="off"`. Confirm `mgr.Apply` ran (existing `manager.go:336-411` log line `"applying caddy config"`).
5. **Critical check**: do we see a `"waf handler cleaned up"` log entry for X with `pool_key=K1`?
6. Send the same blocking request → observe status.

**Outcomes**:
- **Cleanup log present + HTTP 200**: Caddy is doing its job; Bug #2 doesn't reproduce in this setup. Re-test the original operator scenario step-by-step with logs on.
- **Cleanup log present + HTTP 403**: Caddy called Cleanup but something ELSE is still routing requests to a WAF handler. Likely a stale chain entry or a Caddy-internal route cache. Escalate to a Caddy issue or check `caddy.Config.Load(force=true)` semantics in v2.11.3.
- **No Cleanup log + HTTP 403**: confirms the stale-handler hypothesis. Fix is in arenet's interaction with the UsagePool: either add explicit `wafPool.Delete` in a caddymgr post-Apply hook for routes whose mode transitioned to `"off"`, OR ensure `Cleanup` is called via a different lifecycle hook (e.g., `Module.Cleanup` instead of just relying on chain-membership inference).

### §6.3 Probe #3 — Confirm Bug #3 dependency on previous mode

**Goal**: confirm that the operator's "delete + recreate works" observation generalizes — i.e., the leak is in the EDIT path, not the CREATE path.

**Steps**:
1. With logs enabled: create route Y with `wafMode="off"` (fresh-creation off). Confirm NO "waf handler provisioned" log line for Y.
2. Edit Y to `wafMode="block"`. Confirm "waf handler provisioned" log for Y with `mode=block, pool_key=K2`.
3. Send blocking request → assert 403.
4. Edit Y to `wafMode="off"`. Confirm "waf handler cleaned up" log entry for Y, pool_key K2.
5. Send same request → assert status.

**Outcomes**: identical to probe #2 — but exercises the off→non-off→off path that the operator's Bug #3 specifically hits.

## §7 Backlog / non-blocking items

- `#R-WAF-receiver-fix`: change `ServeHTTP` to pointer receiver for consistency (§2.4). Cosmetic; not load-bearing today.
- `#R-WAF-test-gap`: §5 test additions. Add irrespective of bug-fix scope.
- `#R-WAF-pool-key-route-id`: consider including `RouteID` in the pool key. Trades the CRS-parse reuse optimization (~50 ms per route boot) for per-route WAF isolation. Probably NOT worth it (the boot-time delay is real on multi-route deployments), but document as a fallback if the pool-sharing model proves load-bearing for any bug.

## §8 What this discovery does NOT settle

- The **exact** Caddy v2.11.3 semantics for `Load(cfg, true)` when a chain-element disappears: documented behavior is "remove from chain + call Cleanup", but we have not verified empirically with arenet's wiring. Probe #2 settles this.
- Whether Coraza v3.7.0 has any known bug with `WithDirectives` + late `SecRuleEngine` directive override. The codebase + the directive-precedence model in `internal/seclang/directives.go:317-321` says no, but upstream issue tracker should be checked if Probe #1 produces HTTP 403.
- Whether the test seeds (`newProvisionedHandler` in `module_test.go`) construct the WAF with a meaningfully different directive set than production. Spot-check that the test directive string includes the same `coraza.conf-recommended` + CRS includes as production.

---

**Next operator decision**: do we run probes 1-3 before committing to fix scope, or do we commit speculatively to a fix that addresses the most-likely (stale-handler-on-edit-to-off) hypothesis and accept that Bug #1 may need a follow-up if the probe reveals a separate defect? CC's recommendation: **probe first** — 30 minutes of empirical disambiguation will save days of speculative fixing in the wrong layer.
