# Step C — REST API + Admin UI: Design Spec

**Date**: 2026-05-15
**Status**: Approved, ready for plan
**Project**: Arenet (homelab-friendly reverse proxy with embedded Caddy)
**Predecessors**: Step A (skeleton), Step B (embedded Caddy + BoltDB)
**Successor**: Step D (auth) is out of scope here

## 1. Goal

Deliver a REST API and a minimal SvelteKit admin UI that allow CRUD on proxy
routes. Mutations applied via the API must take effect in the live Caddy
configuration immediately. In production, the Go binary serves both the API
and the embedded frontend. In dev, Vite serves the frontend on `:5173` while
the Go binary serves the API on `:8001`.

## 2. Locked decisions (from spec, not re-litigated)

1. **Go HTTP router**: `github.com/go-chi/chi/v5`.
2. **Frontend dev mode**: Vite on `:5173`, Go API on `:8001`, CORS middleware
   active only when `--dev` is set.
3. **UI state after mutation**: refetch `GET /api/v1/routes` after every
   POST/PUT/DELETE (no optimistic updates).
4. **Backend validation level**: reasonable — host non-empty, no whitespace,
   hostname format; upstreamUrl parsable with `http` or `https` scheme.
5. **Error response shape**: `{"error": "<message>"}` with HTTP 400 / 409 / 500.

## 3. Decisions resolved during brainstorming

| Q | Decision | Rationale |
|---|---|---|
| Q1: multiple validation errors | **Return first error only** | Spec mandates `{"error": "..."}` (string). Simpler client UX. |
| Q2: Caddy reload fails after DB mutation | **Rollback DB + HTTP 500** | Maintain the invariant DB ↔ Caddy. ~20 lines of Go. |
| Q3: duplicate `host` | **HTTP 409 in API handler** | Caddy would silently use the first matcher. Handler-level check preserves storage as pure CRUD. |
| Q4: GET `/` in dev mode | **Small HTML landing page** | Points the user to `:5173`. Free polish. |
| Validation URL parsing | **`url.ParseRequestURI`** (not `url.Parse`) | Rejects bare strings; better error messages. |
| CORS preflight | **`Access-Control-Max-Age: 3600`** | Avoid repeated preflights in dev. |
| Shutdown serverErr channel | **Drain after `Shutdown()`** | Don't silently lose post-shutdown errors. |
| `web/frontend/build/` gitignore | **Exception for `.gitkeep`** | Keep `//go:embed all:frontend/build` valid even on fresh clone. |
| CaddyManager injection in handler | **Via `CaddyReloader` interface** | Test handler without booting real Caddy; consumer-side interface. |
| `RestoreRoute` placement | **Storage method with explicit godoc** | Confines abstraction debt to one named method; alternative (caddymgr.ApplyConfig) doubles surface area. |
| Component extraction in SvelteKit | **None — single `+page.svelte`** | Premature for ~150 lines; extract when topology page lands in Step E. |
| Frontend test framework | **None this step** | Will add Vitest with D3/WebSocket work in Step E. |

## 4. Architecture

### 4.1 Package boundaries

```
internal/api/             NEW — HTTP handlers, validation, middleware, chi router
  handler.go              Handler struct + HTTP handlers
  routes.go               NewRouter() + route registration
  middleware.go           slog logger middleware + dev CORS
  validation.go           validateHost, validateUpstreamURL
  errors.go               writeError helper
  *_test.go

internal/storage/         UNCHANGED API + 1 new method
  routes.go               + RestoreRoute(ctx, Route) error      [godoc'd: api-only]

internal/caddymgr/        UNCHANGED. Already exposes ReloadFromStore(ctx) error.

web/                      NEW
  embed.go                //go:embed all:frontend/build + StaticFS()
  frontend/               NEW SvelteKit project
    src/
    static/
    package.json
    svelte.config.js
    vite.config.ts
    tsconfig.json
    tailwind.config.ts
    postcss.config.js
    README.md
    build/.gitkeep        ensures //go:embed matches before first build

cmd/arenet/main.go        MODIFIED — wire admin HTTP server, ordered shutdown
```

### 4.2 Dependencies

- Go: `github.com/go-chi/chi/v5` (already indirect via Caddy; promoted to direct).
- No other new Go deps.
- Node: SvelteKit 2, Svelte 5, Vite, Tailwind, `@sveltejs/adapter-static`,
  TypeScript strict.

### 4.3 Process model at runtime

```
arenet (single binary, single process)
├── goroutine: Caddy (HTTP :8080, HTTPS :8443 if any TLS route)
├── goroutine: Admin HTTP server (chi router on cfg.adminPort, default :8001)
│     ├── /api/v1/routes [GET, POST]
│     ├── /api/v1/routes/{id} [GET, PUT, DELETE]
│     └── /* → http.FileServer(embedded build) | dev landing HTML
└── main goroutine: blocks on signal, orchestrates shutdown
```

## 5. HTTP API

### 5.1 Common rules

- Base path: `/api/v1`
- All bodies and responses: `application/json`, UTF-8
- Errors: `{"error": "<human-readable english message>"}`
- Codes used: 200, 201, 204, 400, 404, 409, 500

### 5.2 Route resource (JSON)

```json
{
  "id": "uuid-v4",
  "host": "string",
  "upstreamUrl": "http://...",
  "tlsEnabled": false,
  "wafEnabled": false,
  "createdAt": "2026-05-15T20:35:58.976Z",
  "updatedAt": "2026-05-15T20:35:58.976Z"
}
```

JSON tags on the Go struct are camelCase. Internal Go field names stay
PascalCase. Note: this is JSON-tag-only — no DB migration, BoltDB stores
whatever shape `encoding/json` emits today and existing rows reload fine
because the field set didn't change.

### 5.3 Endpoints

| Method | Path | Body | Success | Failures |
|---|---|---|---|---|
| GET | /routes | — | 200 + `Route[]` (sorted by createdAt asc) | 500 |
| POST | /routes | `RouteRequest` | 201 + `Route` | 400 (validation), 409 (host taken), 500 (reload failed → rollback) |
| GET | /routes/{id} | — | 200 + `Route` | 404 |
| PUT | /routes/{id} | `RouteRequest` | 200 + `Route` | 400, 404, 409, 500 (rollback) |
| DELETE | /routes/{id} | — | 204 (no body) | 404, 500 (rollback) |

`RouteRequest` = `{ host, upstreamUrl, tlsEnabled, wafEnabled }`. All four
fields required in POST and PUT bodies (no partial updates).

### 5.4 Mutation flow (POST/PUT/DELETE)

**POST `/routes`**
1. Decode JSON → `RouteRequest`. Decode error → 400 `"invalid JSON body"`.
2. `validateHost(req.host)` → 400 on error.
3. `validateUpstreamURL(req.upstreamUrl)` → 400 on error.
4. Check host uniqueness via `store.ListRoutes`: if any existing route has
   `Host == req.Host` → 409 `"host already configured"`.
5. `store.CreateRoute(ctx, ...)` → 500 on storage error.
6. `caddyMgr.ReloadFromStore(ctx)` → on error: `store.DeleteRoute(ctx, created.ID)`,
   log `slog.Error`, return 500 `"caddy reload failed: <err>"`.
   - If the rollback delete also fails: log `slog.Error("rollback failed, DB
     and Caddy may diverge")` and still return 500 to client.
7. Return 201 + the persisted Route.

**PUT `/routes/{id}`**
1. Decode JSON → 400 on parse error.
2. Validate host + upstreamUrl → 400.
3. `store.GetRoute(ctx, id)` → 404 if absent. Keep as `previous`.
4. If `req.host != previous.host`: check no *other* route has `req.host` → 409.
5. `store.UpdateRoute(ctx, ...)` → 500 on error.
6. `ReloadFromStore` → on error: `store.UpdateRoute(ctx, previous)` rollback,
   log, return 500.
7. Return 200 + updated Route.

**DELETE `/routes/{id}`**
1. `store.GetRoute(ctx, id)` → 404 if absent. Keep as `previous`.
2. `store.DeleteRoute(ctx, id)` → 500 on error.
3. `ReloadFromStore` → on error: `store.RestoreRoute(ctx, previous)` rollback
   (preserves original ID + timestamps), log, return 500.
4. Return 204 No Content.

### 5.5 Validation rules

`validateHost(s)` — return on first failure:
- After `strings.TrimSpace(s)`: not empty → else `"host must not be empty"`.
- No whitespace in `s` → else `"host must not contain whitespace"`.
- RFC 1123-lite regex: labels `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?` separated
  by `.`, total ≤ 253 chars, case-insensitive → else `"host must be a valid
  hostname"`.

`validateUpstreamURL(s)`:
- Not empty → else `"upstreamUrl must not be empty"`.
- `url.ParseRequestURI(s)` succeeds → else `"upstreamUrl is not a valid URL"`.
- `strings.ToLower(u.Scheme) ∈ {"http", "https"}` → else `"upstreamUrl must
  use http or https scheme"`.
- `u.Host != ""` → else `"upstreamUrl must include a host"`.

No DNS lookup, no reachability test.

## 6. Middlewares

Mounted on the chi router in this order:

1. `chi/middleware.RequestID` — sets `X-Request-Id`, propagates in context.
2. **`slogLogger(logger)`** — custom: logs one line per request after the
   handler returns. Fields: `method`, `path`, `status`, `duration_ms`,
   `request_id`, `remote_addr`. Level: INFO on 2xx/3xx, WARN on 4xx, ERROR on
   5xx. Uses `chi/middleware.WrapResponseWriter` to capture status.
3. `chi/middleware.Recoverer` — converts panic into 500.
4. **`devCORS(allowOrigin)`** — only mounted when `cfg.dev == true`. Adds:
   - `Access-Control-Allow-Origin: http://localhost:5173`
   - `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
   - `Access-Control-Allow-Headers: Content-Type`
   - `Access-Control-Max-Age: 3600`
   On `OPTIONS`: respond 204 directly, do not call the next handler.

No auth middleware (Step D), no rate limit middleware.

## 7. Router wiring

```go
func NewRouter(h *Handler, dev bool) chi.Router {
    r := chi.NewRouter()
    r.Use(middleware.RequestID, slogLogger(h.logger), middleware.Recoverer)
    if dev {
        r.Use(devCORS("http://localhost:5173"))
    }
    r.Route("/api/v1", func(r chi.Router) {
        r.Get("/routes", h.listRoutes)
        r.Post("/routes", h.createRoute)
        r.Get("/routes/{id}", h.getRoute)
        r.Put("/routes/{id}", h.updateRoute)
        r.Delete("/routes/{id}", h.deleteRoute)
    })
    // Frontend hook is mounted by main.go (dev landing OR embed FS).
    return r
}
```

`main.go` mounts either `r.Get("/", devLandingHandler)` or
`r.Handle("/*", http.FileServer(http.FS(staticFS)))` depending on
`cfg.dev`. Chi routes by pattern specificity, so `/api/v1/...` always
wins over `/*`.

## 8. CaddyReloader interface

In `internal/api/handler.go`:

```go
type CaddyReloader interface {
    ReloadFromStore(ctx context.Context) error
}

type Handler struct {
    store  *storage.Store
    caddy  CaddyReloader
    logger *slog.Logger
}
```

`*caddymgr.CaddyManager` satisfies this implicitly (existing method).
Tests inject a `fakeCaddyReloader` that records calls and can be configured
to return an error to exercise rollback paths.

## 9. `storage.RestoreRoute`

New method, sole consumer is `internal/api` rollback path of DELETE.

```go
// RestoreRoute re-inserts an existing Route exactly as supplied, preserving
// the provided ID, CreatedAt and UpdatedAt timestamps.
//
// This method exists ONLY for the rollback path of internal/api when a Caddy
// reload fails after a DELETE. It bypasses the normal CreateRoute lifecycle
// (no UUID generation, no timestamp refresh) precisely to make rollback
// fidelity possible. Do NOT use it for business logic — use CreateRoute or
// UpdateRoute.
func (s *Store) RestoreRoute(ctx context.Context, r Route) error
```

Implementation: requires `r.ID != ""`, marshals as-is, `Put` into the routes
bucket. Returns an error if `r.ID` is empty or marshaling fails.

Unit test: `RestoreRoute` of a known Route then `GetRoute(id)` returns
identical values byte-for-byte (incl. timestamps).

## 10. Frontend (SvelteKit)

### 10.1 Stack

- SvelteKit 2 / Svelte 5
- TypeScript strict
- Tailwind via PostCSS plugin
- `@sveltejs/adapter-static`
- Vite dev server on `:5173`

### 10.2 Build mode

`+layout.ts` sets `prerender = true` and `ssr = false`. adapter-static
generates a single hydrated SPA shell (`fallback: '200.html'`). Go embeds
the entire `build/` directory.

### 10.3 File layout

```
web/frontend/
├── package.json
├── svelte.config.js
├── vite.config.ts
├── tsconfig.json
├── tailwind.config.ts
├── postcss.config.js
├── .env.example                 VITE_API_BASE_URL=http://localhost:8001
├── src/
│   ├── app.html
│   ├── app.css                  Tailwind directives
│   ├── app.d.ts
│   ├── routes/
│   │   ├── +layout.ts
│   │   └── +page.svelte         single page, all UI
│   └── lib/
│       └── api/
│           ├── client.ts        typed fetch wrapper, throws ApiError
│           └── types.ts         Route, RouteRequest, ApiError class
├── static/
│   └── favicon.svg              minimal placeholder
├── build/.gitkeep               present to keep //go:embed happy
└── README.md
```

### 10.4 Client (`src/lib/api/client.ts`)

- Reads `import.meta.env.VITE_API_BASE_URL ?? ''`.
- Exports `listRoutes`, `createRoute`, `updateRoute`, `deleteRoute`.
- Throws `ApiError(message, status)` on non-2xx (extracts `.error` from JSON
  body when possible).
- `204 No Content` returns `undefined`.

### 10.5 Single page (`+page.svelte`)

State (local Svelte 5 runes):
- `routes: Route[]`
- `loadError: string | null`
- `formOpen: boolean`
- `formMode: 'create' | 'edit'`
- `formData: RouteRequest`
- `formError: string | null`
- `editingId: string | null`

Operations:
- `loadRoutes()` — onMount + after every mutation.
- `submitForm()` — POST or PUT depending on mode; on success: refetch, close
  form; on error: `formError = err.message` (rendered red below the form).
- `deleteRow(r)` — `window.confirm(...)` then DELETE then refetch.
- `openCreate()` / `openEdit(r)` / `closeForm()` — toggle form state.

Markup: a `<table>` with columns Host, Upstream URL, TLS, WAF, Actions
(Edit / Delete buttons). Form inline above or below the table. Tailwind
utility classes only — no extracted components this step.

### 10.6 `.env` handling

`.env.example` committed with `VITE_API_BASE_URL=http://localhost:8001`. The
developer copies it to `.env` (gitignored). In production builds, the env var
is unset, so `BASE` resolves to `''` and the client hits same-origin paths,
which is what we want when the binary serves both.

### 10.7 README

~30 lines: Node ≥ 20 prereq, `npm install`, `npm run dev` (Vite on 5173,
requires Arenet running on 8001 — `--dev` flag), `npm run build` (produces
`build/`), how to test locally.

## 11. Go embed (`web/embed.go`)

```go
package web

import (
    "embed"
    "io/fs"
)

//go:embed all:frontend/build
var staticFS embed.FS

// StaticFS returns the embedded SvelteKit build directory rooted at
// frontend/build so that http.FileServer serves it from /.
func StaticFS() (fs.FS, error) {
    return fs.Sub(staticFS, "frontend/build")
}
```

The `all:` prefix is necessary because SvelteKit emits files starting with
`_` (e.g. `_app/`) which the default `//go:embed` rules skip. The
`build/.gitkeep` file guarantees the directory exists at compile time even
before the first `npm run build`.

## 12. `cmd/arenet/main.go` changes

### 12.1 New responsibilities

- Build the chi router via `api.NewRouter(handler, cfg.dev)`.
- Mount the frontend hook: `r.Get("/", devLanding)` in dev,
  `r.Handle("/*", http.FileServer(http.FS(staticFS)))` in prod.
- Start `&http.Server{Addr: cfg.adminPort, Handler: r, ReadHeaderTimeout: 5s,
  IdleTimeout: 60s}` in a goroutine.
- Drain a `serverErr chan error` after `Shutdown` to surface late errors.

### 12.2 Shutdown order

```
SIGINT/SIGTERM → ctx canceled
  1. adminSrv.Shutdown(ctxWithTimeout 10s)   // drain HTTP requests
  2. drain serverErr channel, log any error
  3. defer caddyMgr.Stop()                   // stop proxy
  4. defer store.Close()                     // close bbolt
```

### 12.3 Dev landing page

Inline HTML, ~15 lines, served at `GET /` when `cfg.dev` is true. Says
"Arenet — dev mode. Open Vite dev server at http://localhost:5173". No
template, just `fmt.Fprintf(w, html, cfg.adminPort)`.

### 12.4 Updated listening log

```
Arenet listening http=:8080 admin_api=:8001 [https=:8443 if any TLS route]
```

`admin_api` value comes from `cfg.adminPort`.

## 13. Makefile

New / changed targets:

- `frontend`: `cd web/frontend && npm install && npm run build`
- `build`: depends on `frontend`, then `go build`
- `dev-frontend`: `cd web/frontend && npm run dev`
- `run`, `test`, `clean`, `fmt`, `vet`: unchanged

`clean` should also remove `web/frontend/build/*` (but keep `.gitkeep`) and
`web/frontend/.svelte-kit/`. Document the side-effect in the target's
comment.

## 14. `.gitignore` additions

```
# Frontend
/web/frontend/node_modules/
/web/frontend/.svelte-kit/
/web/frontend/build/
!/web/frontend/build/.gitkeep
/web/frontend/.env
```

## 15. Tests

### 15.1 `internal/api/validation_test.go`

Table-driven. For each of `validateHost` and `validateUpstreamURL`: valid
cases (incl. `localhost`, `test.local`, `a.b.c.d.example.com`, max 253
chars), invalid cases (empty, whitespace inside, label starts with `-` or
`_`, `..`, 254 chars), and for URLs: empty, malformed, wrong scheme
(`ftp://`, `file://`), missing host (`http:///foo`).

### 15.2 `internal/api/handler_test.go`

`httptest.NewRecorder` + chi router. Helpers:

- `newTestHandler(t)` returns `{router, store, fakeCaddy}` with a temp DB and
  a configurable fake reloader.
- `seedRoute(t, store, ...)` to populate fixtures.

Matrix (every row is one `t.Run`):

| Endpoint | Case | Expected status | Side effect check |
|---|---|---|---|
| GET /routes | empty | 200, `[]` | — |
| GET /routes | 3 routes | 200, ordered | — |
| POST /routes | valid | 201 | route persisted, reload called 1× |
| POST /routes | invalid JSON | 400 | nothing persisted |
| POST /routes | empty host | 400 | nothing persisted |
| POST /routes | whitespace host | 400 | nothing persisted |
| POST /routes | bad scheme | 400 | nothing persisted |
| POST /routes | duplicate host | 409 | nothing new persisted |
| POST /routes | reload fails | 500 | route removed (rollback) |
| GET /routes/{id} | exists | 200 | — |
| GET /routes/{id} | missing | 404 | — |
| PUT /routes/{id} | valid same host | 200 | reload called |
| PUT /routes/{id} | valid new host | 200 | reload called |
| PUT /routes/{id} | new host collides | 409 | route unchanged |
| PUT /routes/{id} | missing | 404 | — |
| PUT /routes/{id} | reload fails | 500 | route restored to previous |
| DELETE /routes/{id} | exists | 204 | route gone, reload called |
| DELETE /routes/{id} | missing | 404 | — |
| DELETE /routes/{id} | reload fails | 500 | route restored via RestoreRoute |
| OPTIONS /routes | dev=true | 204 + CORS headers + Max-Age | — |
| OPTIONS /routes | dev=false | no `Access-Control-Allow-Origin` header | — |

### 15.3 `internal/storage/routes_test.go`

Add a `TestRestoreRoute` subtest:
- RestoreRoute of a Route with known ID + timestamps.
- GetRoute returns identical values (incl. timestamps).
- RestoreRoute with empty ID returns an error.

### 15.4 Run mode

All tests pass with `go test -race -count=1 ./...`.

### 15.5 Out of scope

- No frontend tests (no Vitest yet — Step E).
- No end-to-end browser test.
- No load test.

## 16. Out of scope (deferred)

- Authentication / authorization (Step D).
- WebSocket metrics, topology dashboard (Step E).
- WAF / Coraza wiring through the API (Step F).
- CrowdSec wiring (Step G).
- Wildcard host matchers (`*.example.com`).
- Partial PATCH updates.
- Pagination on `GET /routes`.
- File upload, certificate management UI.
- i18n.

## 17. Acceptance criteria

1. `make build` produces a single binary including the SvelteKit build.
2. `./bin/arenet --dev --insert-test-route` listens on `:8080`, `:8001`, and
   shows `admin_api=:8001` in the startup log.
3. `cd web/frontend && npm run dev` opens an admin UI on `:5173` that lists
   the test route, can create/edit/delete routes, and updates Caddy live.
4. `curl http://test.local:8080/` proxies to whatever upstream is configured
   in the UI.
5. `curl -i http://localhost:8001/api/v1/routes` returns the JSON list.
6. `curl -X POST -d '{"host":"","upstreamUrl":"http://x"}'
   http://localhost:8001/api/v1/routes` returns
   `400 {"error": "host must not be empty"}`.
7. `go test -race -count=1 ./...` is green.
8. `go vet ./...` is clean.
9. Ctrl+C produces an ordered shutdown (admin server, then Caddy, then
   storage) with no warnings.
