# Rate-limit clear via UI — Phase Q.2 sentinel field

**Ship target**: v2.9.13
**Author**: Ludovic Ramos
**Date**: 2026-06-26
**Status**: Approved — ready for implementation
**Cross-ref**: Step Q (rate-limiting shipped v2.5.0) + the
"V2 backlog : explicit-null PUT semantic" comment block in
`internal/api/routes.go:1822-1828`

## Operator-observed symptom

Editing a route, un-ticking the rate-limit toggle, clicking Save.
The UI reports success ; the form re-renders with rate-limit OFF.
Empirically, however, the upstream still rate-limits incoming
requests (visible as continuing `rate limit exceeded` log lines
post-save in journalctl).

Reproduction trace (operator-collected 2026-06-26, route
`8448574c-f122-47a9-a09e-fadd8d971a53` = proxmox.worldgeekwide.fr):

- 11:50:32 PUT /api/v1/routes/8448574c → 200 `config is unchanged`
- 11:50:55+ `rate limit exceeded` keeps firing on zone
  `route-8448574c-…`
- `curl http://127.0.0.1:8001/api/v1/routes` shows the stored
  route STILL carries the `rate_limit` block
  `{events: 5, window: "10s", key: "{http.request.remote.host}"}`
- `curl http://127.0.0.1:2019/config/apps/http/servers/arenet_https`
  shows the Caddy `rate_limit` handler STILL emitted on the route

## Root cause

Empirical citation `internal/storage/routes.go:485`:

```go
RateLimit *RouteRateLimit `json:"rate_limit,omitempty"`
```

The storage shape is **pointer-based** — `nil` = OFF,
non-nil = ON. There is no `Enabled` boolean inside
`RouteRateLimit`.

Empirical citation `internal/api/routes.go:1806-1838`:

```go
// PUT semantic: nil-pointer request preserves the previously
// stored RateLimit. Non-nil replaces. To clear a previously-set
// rate limit via PUT the operator… would need a separate
// sentinel field (frontend Phase Q.2 — clearRateLimit boolean).
// V2 backlog : explicit-null PUT semantic.
rateLimit := previous.RateLimit
if req.RateLimit != nil {
    next, _ := materialiseRateLimit(req.RateLimit)
    rateLimit = next
}
```

Empirical citation `web/frontend/src/routes/routes/+page.svelte:1693-1695`:

```typescript
if (formData.rateLimit !== null) {
    payload.rateLimit = formData.rateLimit;
}
// OFF: field absent from payload
```

The frontend correctly omits the field when the toggle is OFF.
The backend correctly treats an omitted field as "preserve
existing value". The chain is internally consistent — but the
combination provides NO path to clear a previously-stored
rate-limit short of deleting + recreating the route entirely.

`grep -rn "clearRateLimit" /Users/l.ramos/Documents/Projets/AreNET`
confirms the sentinel field is **only mentioned in comments**;
Phase Q.2 was designed but never shipped.

## Approach

Ship Phase Q.2 verbatim: add a `ClearRateLimit bool` sentinel
field to the POST and PUT route-request DTOs. When `true`, the
handler sets `route.RateLimit = nil` regardless of any
`req.RateLimit` value in the payload. When `false` (the default —
preserving every existing client), the legacy preserve-on-omit
semantic is untouched.

Rationale for a separate sentinel vs an explicit `"rateLimit": null`:

- Go's `encoding/json` cannot distinguish "field absent" from
  "field present with null value" when using `omitempty +
  *struct` decoder shape. Both decode to a nil pointer. A
  sentinel boolean is the only contract change that round-trips
  reliably across the JSON wire today without a custom
  UnmarshalJSON.
- Backwards-compatible: existing clients that don't know about
  `clearRateLimit` keep the same observable behaviour (defaults
  to false → preserve semantic).

## Components changed

| File | Change |
|---|---|
| `internal/api/routes.go` | +`ClearRateLimit bool` field on the route-request DTO struct ; handler: when true, force `rateLimit = nil` (overrides preserve-on-omit) |
| `internal/api/routes_test.go` | +4 tests: PUT with `clearRateLimit=true` clears; PUT with both clear + body — clear wins; PUT without clear (default) preserves; legacy POST/PUT round-trip unchanged |
| `web/frontend/src/lib/api/types.ts` (or wherever RouteRequest lives) | +`clearRateLimit?: boolean` on the type |
| `web/frontend/src/routes/routes/+page.svelte` | When `formData.rateLimit === null`, the payload now carries `clearRateLimit: true` (instead of omitting both fields). When non-null, behaviour unchanged. |
| `web/frontend/src/routes/routes/page.test.ts` | +vitest case: toggle OFF → payload has `clearRateLimit: true` |

No storage schema change. No migration. The on-disk `Route`
shape stays byte-for-byte identical.

## API surface (changed lines only)

### POST /api/v1/routes — request body extension

```json
{
  "host": "...",
  "upstreams": [...],
  "rateLimit": { "events": 5, "window": "10s", "key": "..." },
  "clearRateLimit": false   // ← NEW, optional, defaults false
}
```

When `clearRateLimit=true` on POST, the new route is created
with `RateLimit=nil` even if a `rateLimit` body is also present
(the sentinel wins).

### PUT /api/v1/routes/{id} — request body extension

Same extension. Semantic matrix:

| `clearRateLimit` | `rateLimit` in body | Result on stored route |
|---|---|---|
| absent / false | absent | **Preserve** existing (legacy behavior) |
| absent / false | present + valid | **Replace** with the new block |
| **true** | absent | **Clear** (set to nil) |
| **true** | present | **Clear** (sentinel overrides body) |

## Data flow (the OFF case fixed)

```
Operator: Routes → edit → un-ticks rate-limit toggle → Save
  └→ frontend onRateLimitToggle sets formData.rateLimit = null
  └→ submit builds payload:
       formData.rateLimit === null
         → payload.clearRateLimit = true       // ← NEW
         → payload.rateLimit absent
  └→ PUT /api/v1/routes/<id> { ..., clearRateLimit: true }
      └→ backend decode: req.ClearRateLimit == true
          └→ rateLimit = nil  (force; ignore req.RateLimit even if present)
          └→ store.UpdateRoute persists with RateLimit: nil
          └→ caddymgr.ReloadFromStore
              └→ Caddy reload — no rate_limit handler emitted
                  for this route → no zone, no enforcement
```

## Edge cases & invariants

1. **Operator never touched rate-limit on this PUT**:
   `clearRateLimit` defaults to false on absence → preserve-on-
   omit behaviour unchanged. No regression for any existing call
   path.
2. **Operator clears AND submits new rate-limit values
   simultaneously** (race in form state): sentinel wins. Clearer
   intent than "merge" — if you ticked OFF then re-typed values,
   the OFF state is what the toggle most recently emitted.
3. **POST with clearRateLimit=true on a brand-new route**:
   trivially correct (no previous state to clear; the result is
   identical to omitting both fields). Accepted as a no-op-but-
   valid request.
4. **Old client doesn't send the field**: backend treats as
   false → legacy preserve semantic. Zero breaking change.
5. **Old server doesn't know the field**: ignored by JSON decode
   (`DisallowUnknownFields` is NOT set on the route DTO — verified
   in the file header). The new frontend talking to an old server
   degrades gracefully to "field ignored, can't clear" — same as
   today.
6. **Validation of the rate-limit body when clearRateLimit=true**:
   skipped. If body would have been invalid (e.g. events=0), the
   clear still succeeds — the operator's intent was clear, not
   replace.

## Test plan

### Backend

- `TestUpdateRoute_ClearRateLimit_RemovesStoredValue` — given a
  route with stored rate-limit, PUT with `clearRateLimit=true`
  and no body, assert store reads back `RateLimit == nil`.
- `TestUpdateRoute_ClearRateLimit_OverridesBody` — same setup,
  PUT with `clearRateLimit=true` AND a valid `rateLimit` body,
  assert store reads back `nil` (sentinel wins).
- `TestUpdateRoute_NoClearRateLimit_PreservesLegacy` — PUT with
  `clearRateLimit=false` AND no body, assert preserve.
- `TestUpdateRoute_ReplaceRateLimit_Unchanged` — PUT with
  `clearRateLimit=false` AND new body, assert replace (regression
  pin for the unchanged-behaviour case).
- `TestCreateRoute_ClearRateLimit_NoOp` — POST with
  `clearRateLimit=true` AND no body, assert created with
  `RateLimit == nil` (trivial; covers the no-op-but-valid case).

### Frontend

- Existing routes page test: toggle OFF → payload carries
  `clearRateLimit: true`.

### Manual smoke (post-deploy v2.9.13)

1. Edit the proxmox route in the operator's homelab (currently
   carries the rate-limit causing the empirical bug)
2. Un-tick the rate-limit toggle
3. Save → toast OK
4. Reload page → toggle stays OFF, form fields cleared
5. `curl -k https://proxmox.worldgeekwide.fr/ -i` from a separate
   client a few times rapidly → no 429
6. `curl http://127.0.0.1:8001/api/v1/routes | jq '.[] |
   select(.id == "8448574c…") | .rateLimit'` → null/absent
7. `curl http://127.0.0.1:2019/config/apps/http/servers/
   arenet_https/routes | jq '...'` → no `rate_limit` handler on
   the route's handler chain
8. journalctl shows no further `rate limit exceeded` log entries
   for zone `route-8448574c…`

## What this does NOT change

- Storage shape (`Route.RateLimit *RouteRateLimit` stays).
- Caddy emit logic (handler still keyed off whether `RateLimit`
  is nil).
- POST/PUT semantics for any other field.
- Audit treatment (rate-limit clear is a normal route mutation
  that flows through the existing `route_updated` audit event —
  the before/after JSON snapshot already captures the
  `RateLimit` nil/non-nil delta).

## Ship

- Tag: `v2.9.13`
- Title: `fix(routes): Phase Q.2 clearRateLimit sentinel field`
- Body: operator-reported UI rate-limit toggle OFF appeared to
  work but the underlying state persisted. Phase Q.2 was
  designed but never shipped — adds the sentinel field to allow
  explicit-clear via PUT without breaking the preserve-on-omit
  default for legacy clients.

## Gates before push

1. `go vet ./...` clean
2. `go test ./internal/api/ -run "Route|RateLimit" -count=1` green
3. `go build ./cmd/arenet` clean
4. `cd web/frontend && npm run check` 0/0
5. `cd web/frontend && npm test -- --run routes/page` green
6. `cd web/frontend && npm run build` clean
7. Operator manual smoke confirms 8 steps above
