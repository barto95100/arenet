# Bug B — HC tracker reset on Caddy reload

**Ship target**: v2.9.8
**Author**: Ludovic Ramos
**Date**: 2026-06-25
**Status**: Approved — ready for implementation

## Operator-observed symptom

After modifying a route's health-check URI (e.g. `/test` → `/`) and saving,
the route's aggregate health badge stays stuck on `DOWN` indefinitely, even
when the new URI returns 200 and an empirical `curl` confirms the upstream
is reachable. The Arenet log shows zero new `health_checker.active` entries
after the reload, while pre-reload probes were clearly visible.

Empirical trace (2026-06-25 00:28–00:34, AreNET-test):

- 00:28:31 — probe `/test` → 404 → `status code out of tolerances` logged
- 00:29:31 — last probe with old URI → 404
- 00:29:51 — operator PUT modifies HC URI to `/`, full Caddy reload triggered
- 00:29:51 → 00:34:21+ — ZERO probe logs (5+ minute silence)
- 00:33:03 — operator `curl http://192.168.1.29:8123/` → 200 OK
- Badge in routes table: still `DOWN`

## Root cause — empirical citation

**Caddy v2.11.3 `reverseproxy/healthchecks.go:478,498` + `hosts.go:251-264`**

```go
// healthchecks.go:498
if upstream.setHealthy(true) {
    h.events.Emit(h.ctx, "healthy", ...)   // ← only fires if CAS succeeds
}

// hosts.go:251
func (u *Upstream) healthy() bool {
    return u.unhealthy.Load() == 0   // ← default 0 means HEALTHY at boot
}

// hosts.go:258
func (u *Upstream) setHealthy(healthy bool) bool {
    var unhealthy, compare int32 = 1, 0
    if healthy { unhealthy, compare = 0, 1 }
    return u.unhealthy.CompareAndSwap(compare, unhealthy)   // ← returns false if state unchanged
}
```

Caddy emits `healthy`/`unhealthy` events ONLY on state TRANSITIONS via the
atomic CAS pattern. New `Upstream` Go objects created at reload start with
the default healthy state (`unhealthy = 0`). The first probe success
therefore performs `setHealthy(true)` on an already-true state — CAS
returns `false` — no event fires.

Arenet's `HCStatusTracker` survives reloads (process-wide singleton, never
re-initialised between caddy.Load calls — verified `internal/caddyhc/listener.go:53-72`).
Its pre-reload value (often `"unhealthy"` from prior failed probes) sticks
until the next state TRANSITION arrives — which only happens if a probe
*fails* (going from initial-true to false). On a now-healthy upstream, no
event ever arrives → tracker stuck forever → UI badge stuck `DOWN`.

## Approach — chosen: A (clear tracker on reload)

The caddymgr clears the entire tracker map before every `caddy.Load` call.
All addresses revert to `StatusUnknown ("")`. The frontend's
`routeStatusUnknown` enum already renders gray "warm-up" badges (we shipped
this path in v2.9.6 with the `not_monitored` split). After ~1 probe
interval (default 30s), either:

- a probe failure produces a new `unhealthy` event → tracker repopulates
  to `unhealthy` → badge flips to `DOWN` (truthful)
- no event arrives (probes succeeding silently per Caddy's
  transition-only emit rule) → tracker stays at `""` → badge stays gray
  → operator legitimately knows "Arenet has not yet observed a failure on
  this upstream since the last config change"

Rejected alternatives:
- **A+ (selective per-upstream reset)**: chirurgical but +20 lines, ROI
  marginal — multi-route shared upstream gray for 30s is acceptable.
- **B (TTL stale)**: complex (~50 lines), fragile on long intervals
  (operator with interval=300s → TTL=45min stuck).
- **D (patch Caddy)**: not realistic short-term, and the transition-only
  semantics may be intentional upstream-design.

## Components changed

| File | Change |
|---|---|
| `internal/caddyhc/tracker.go` | +`Reset()` method (~8 lines) |
| `internal/caddyhc/tracker_test.go` | +`TestHCStatusTracker_Reset*` (~25 lines) |
| `internal/caddymgr/manager.go` | +`hcTracker` field, +`SetHCTracker()` setter, +nil-guarded `tracker.Reset()` call before each `caddy.Load` |
| `internal/caddymgr/manager_test.go` | Verify no regression on existing tests |
| `cmd/arenet/main.go` | Wire the existing `caddyhc.HCStatusTracker` singleton into the `caddymgr.Manager` via the new setter |

No frontend changes. No new API surface. No migration.

## Data flow

```
Operator clicks Save
  └→ PUT /api/v1/routes/<id>
      └→ api.Handler updates BoltDB
          └→ caddymgr.Manager.applyConfig() / Apply() / Load() (whichever
             is the unique caddy.Load call site)
              ├→ buildConfigJSON()
              ├→ NEW: m.hcTracker.Reset() (nil-guarded)
              └→ caddy.Load(cfg, false)
                  └→ new reverse_proxy handlers with fresh state
                      └→ first probe success → setHealthy(true) on
                         already-true → no event → tracker stays ""
                         → badge: UNKNOWN (gray, legitimate warm-up)
                      └→ first probe failure → setHealthy(false) →
                         event "unhealthy" → tracker = "unhealthy"
                         → badge: DOWN (truthful)
```

## Edge cases & invariants

1. **HC disabled route**: not affected — `routeStatusNotMonitored` gate
   short-circuits before consulting the tracker.
2. **Upstream shared across routes**: a single reset clears entries for
   ALL routes' upstreams. Each route's badge goes gray for ≤1 interval,
   then re-converges via natural event flow. Acceptable.
3. **No-op reload** (`config is unchanged`): we still reset. The next
   transition repopulates. No need to optimise — reset is O(N upstreams).
4. **Concurrent reset + probe event**: write-lock vs read-lock
   serialises correctly. An event arriving mid-reset may be clobbered
   by the empty map assignment — but the next transition re-records.
   Acceptable.
5. **Multiple reloads in rapid succession**: each reset is idempotent;
   no accumulating state.

## Test plan

### Unit test (new)

`TestHCStatusTracker_ResetClearsAllEntries` in `tracker_test.go`:

```
1. tr := NewTracker()
2. tr.RecordHealthy("10.0.0.1:80")
3. tr.RecordUnhealthy("10.0.0.2:80")
4. assert tr.Status(...) returns "healthy" and "unhealthy" respectively
5. tr.Reset()
6. assert tr.Status("10.0.0.1:80") == StatusUnknown
7. assert tr.Status("10.0.0.2:80") == StatusUnknown
8. tr.RecordHealthy("10.0.0.1:80")  // verify tracker is still usable
9. assert tr.Status("10.0.0.1:80") == StatusHealthy
```

### Manager integration

Existing manager tests verify the build path; no new manager test needed
for the Reset call site itself — the wire-up is trivial (nil-guarded
single call). Operator empirical validation post-deploy is the final
gate.

### Empirical operator validation

After deploying v2.9.8:
1. Trigger a route Save with any change (e.g. toggle HC enabled/disabled
   then back, or change HC URI).
2. Within 1s of the Save, the badge should turn gray (`UNKNOWN`).
3. Within 1 probe interval (default 30s), the badge should either:
   - stay gray (probes succeeding silently — legitimate)
   - flip to `DOWN` (a probe failed — also truthful)
4. Verify with operator's curl that the upstream state matches:
   - if curl returns 2xx → badge gray (no recent failure observed)
   - if curl returns 4xx/5xx → badge `DOWN` within fails×interval
     seconds

## What this does NOT fix

- Bug A (Caddy log "no automatic HTTPS will be applied") — separate
  investigation, cosmetic, empirically verified the redirect 307 DOES
  fire.
- The architectural "every reload is a full Caddy restart" limitation —
  accepted in this session (5s grace period is tolerable).
- Caddy's transition-only emit semantics — upstream design we don't
  challenge.

## Ship

- Tag: `v2.9.8`
- Title: `fix(caddyhc): reset tracker on Caddy reload`
- Body: empirical Caddy v2.11.3 transition-only emit semantics meant
  tracker kept stale "unhealthy" forever after reload. Reset on reload
  + reliance on existing routeStatusUnknown gray badge during warm-up.

## Gates before push

1. `go vet ./...` clean
2. `go test ./internal/caddyhc/... -race` green (new test passes)
3. `go test ./internal/caddymgr/... -race` green (no regression)
4. `go build ./cmd/arenet` clean
5. Operator deploys v2.9.8 and confirms badge converges correctly post-Save
