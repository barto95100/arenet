# Bug 1 — catch-all branded HTML + per-template default flag

**Ship target**: v2.9.10
**Author**: Ludovic Ramos
**Date**: 2026-06-25
**Status**: Approved — ready for implementation

## Operator-observed symptom

A request hitting Arenet for a host that is NOT configured (neither
primary nor alias on any route) currently receives:

```
HTTP/2 404
Content-Type: text/plain; charset=utf-8

Not Found - no route configured for this host
```

The plain-text body breaks visual consistency with the rest of the
product, which already serves branded HTML pages for upstream
4xx/5xx errors on configured routes (via the
`arenetDefaultErrorPages[code]` builtin or operator-defined
templates).

## Root cause

`internal/caddymgr/manager.go:catchAllRoute()` emits a hardcoded
`static_response` with `body: "Not Found - no route configured for
this host"` and no Content-Type override. Caddy serves it raw.

The function is appended to every server's routes slice
(`apps.http.servers.arenet_http.routes` and
`apps.http.servers.arenet_https.routes`) as the LAST route, so it
catches any host that does not match any earlier route's
`match.host` block.

## Approach

Two changes:

1. **`catchAllRoute()` resolves to branded HTML.** It returns the
   body of the operator-designated "default" template if one exists,
   else the builtin `arenetDefaultErrorPages[404]`. Content-Type is
   `text/html; charset=utf-8`. Sanitised via the existing
   `SanitizeErrorPageBody` pipeline (same hardening as per-route
   error pages).

2. **`ErrorPageTemplate.IsCatchallDefault bool` flag.** Allows the
   operator to designate one template as the global catch-all
   default via a checkbox in the existing template editor.
   Storage-enforced mutual exclusion: at most one template carries
   the flag at any time; setting it on Template B auto-clears it on
   Template A in the same write transaction.

The split lets operators leave Arenet branding in place by default
(no opt-in needed — the catch-all immediately looks like the rest
of the product) and customise globally without touching every route.

## Components changed

| File | Change |
|---|---|
| `internal/storage/error_template.go` | +`IsCatchallDefault bool` field; +mutual-exclusion enforcement in Create/Update; +`GetCatchallDefaultErrorPageTemplate(ctx)` accessor |
| `internal/storage/error_template_test.go` | +tests for the flag round-trip + mutual-exclusion invariant |
| `internal/caddymgr/manager.go` | `catchAllRoute()` signature change to accept the templates map; resolve catch-all body via `resolveCatchallBody()` helper; thread the map through `httpServer` build paths |
| `internal/caddymgr/error_pages.go` | +`resolveCatchallBody(templates map) string` helper |
| `internal/caddymgr/manager_test.go` + `error_pages_test.go` | Update existing catchall test to assert HTML body + Content-Type; add coverage for the template-default path |
| `internal/api/error_templates.go` | API already passes the full struct through; verify the JSON tag wires through |
| `web/frontend/src/routes/error-pages/...` (or wherever the template editor lives) | +checkbox "Use as catch-all default" in the template editor + binding |

No new endpoint. The existing `PUT /api/v1/error-templates/<id>`
already accepts the full struct.

## Data flow

```
Operator opens template editor (existing UI)
  └→ checks "Use as catch-all default"
  └→ PUT /api/v1/error-templates/<id>  body includes is_catchall_default=true
      └→ api.Handler validates + forwards to storage
          └→ storage.UpdateErrorPageTemplate
              ├→ if payload has is_catchall_default=true: clear flag
              │  on any other template in the same bbolt txn
              └→ persist row
                  └→ caddymgr ReloadFromStore (triggered by API)
                      └→ buildConfigJSON
                          ├→ ListErrorPageTemplates (existing)
                          ├→ catchAllRoute(templates)
                          │  └→ resolveCatchallBody(templates)
                          │     ├→ scan for IsCatchallDefault=true
                          │     ├→ if found: return template.Pages[404] sanitised
                          │     └→ else: return arenetDefaultErrorPages[404]
                          └→ emit static_response with HTML body + text/html
```

## Edge cases & invariants

1. **No template has the flag**: catch-all uses builtin Arenet
   default (current branded HTML, same look as configured routes).
2. **The "default" template has empty Pages[404]**: fall back to
   builtin Arenet 404. Empty body never escapes to the wire.
3. **The default template is deleted**: the flag goes with it.
   Catch-all silently reverts to builtin.
4. **Operator unchecks on the only-defaulted template**: catch-all
   reverts to builtin. No second template becomes default
   automatically.
5. **Operator checks the flag on a template that was already
   default**: idempotent no-op write.
6. **Race between two operators editing templates**: the bbolt
   write txn serialises; the loser's update either clears the
   winner's flag or leaves it alone depending on payload — last
   writer wins, consistent state guaranteed.
7. **Sanitisation**: the catch-all body passes through
   `SanitizeErrorPageBody` (same bluemonday policy applied to
   per-route templates). Defense-in-depth against compromised
   admin / reflected XSS.

## Test plan

### Storage tests
- `TestErrorPageTemplate_IsCatchallDefault_Roundtrip` — create
  template with flag=true, read back, assert flag preserved.
- `TestErrorPageTemplate_MutualExclusion` — create T1 with
  flag=true, create T2 with flag=true, assert T1's flag is now
  false in storage.
- `TestErrorPageTemplate_GetCatchallDefault` — returns the right
  template when one exists, returns (nil, ErrNotFound) when none.

### Manager tests
- Update existing `TestBuildConfigJSON_CatchAllRoute` (or
  equivalent) to assert: status_code=404,
  headers["Content-Type"]=["text/html; charset=utf-8"], body
  contains "powered by Arenet".
- New `TestBuildConfigJSON_CatchAllUsesDefaultTemplate` — given
  a template with flag=true and Pages[404] = "OPERATOR-CUSTOM",
  assert catch-all body == "OPERATOR-CUSTOM" sanitised.
- New `TestBuildConfigJSON_CatchAllFallsBackToBuiltinOnEmptyDefault`
  — given template with flag=true but Pages[404] = "", assert
  catch-all body == builtin Arenet 404.

### API
- Existing tests should pass through; one new test asserting the
  flag survives a round-trip via the API.

### Frontend
- Manual verification — checkbox checked, save, refresh, checkbox
  state preserved.

## What this does NOT fix

- Bug 2 (page Traefik passe sur l'alias) — investigated, confirmed
  non-bug, root cause was Traefik's own middleware broken
  post-reboot.

## Ship

- Tag: `v2.9.10`
- Title: `feat(error-pages): branded catch-all + per-template default flag`
- Body: operator-observed plain-text catch-all replaced with
  branded HTML. New per-template `is_catchall_default` flag with
  storage-enforced mutual exclusion lets operators globally
  override the catch-all page from the existing template editor.

## Gates before push

1. `go vet ./...` clean
2. `go test ./internal/storage/... ./internal/caddymgr/... ./internal/api/... -race` green
3. `go build ./cmd/arenet` clean
4. `cd web/frontend && npm run check && npm run build` clean
5. Operator manual verification: catch-all responds with branded
   HTML; toggling the checkbox in a template's editor changes the
   catch-all body live after the implicit reload
