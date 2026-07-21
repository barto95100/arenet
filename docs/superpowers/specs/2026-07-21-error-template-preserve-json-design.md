# Preserve JSON / API responses from error-page branding — Design

**Status:** design brainstormed with user 2026-07-21, 4 decisions locked
(Q1–Q4). Bugfix, patch bump. Branch `fix/error-template-preserve-json`.

**One-line:** Stop Arenet's branded HTML error page from replacing a proxied
upstream's **JSON / API** error responses — so an API call through a
reverse-proxy route (e.g. the Arenet admin behind its own FQDN) receives the
real `{"error":...}` body instead of a `text/html` 4xx page, while a human
navigating to a route still gets the branded page.

---

## 1. Motivation

Arenet emits a `handle_response` block per reverse-proxy route
(`buildConfigJSON`, `internal/caddymgr/manager.go:1521`) that converts every
upstream 4xx/5xx (except 401/407) into a Caddy `error`, which the errors chain
serves as the branded HTML page. This is correct for a human navigating to a
route whose upstream is down (a friendly 502 page), but **it also overwrites a
proxied API's structured JSON error responses**.

Two dogfooding bugs, both proven via DevTools, share this single root cause —
the operator runs the Arenet admin behind a reverse-proxy route
(`arenet.worldgeekwide.fr` → the admin API), so admin API responses traverse
the branding block:

- Manual-cert upload conflict → backend returns
  `400 {"error":"chain_specified_twice: ..."}`, but the browser receives the
  branded `text/html` 400 page. The frontend `safeJSON()` fails → the user
  sees a bare "HTTP 400" with no actionable message.
- Manual-cert delete guard → backend returns
  `409 {"error":..., "blockingRoutes":["regitry.sccnf.fr"]}`, branded to HTML
  → the frontend renders "is in use by: " with an **empty** route list, so the
  operator can't tell which route to repoint.

Both are the branding block eating a legitimate structured API response.

## 2. Non-goals (locked)

- ❌ **Removing / weakening the branded page for human navigation.** A request
  to a proxied web upstream that 404s or 502s still gets the branded HTML page.
  This fix only spares JSON / API responses.
- ❌ **A per-route opt-in toggle.** An API JSON response should never be
  branded — this is correct-by-default, not a knob (Q3).
- ❌ **Touching the 401/407 handling.** Those codes are already excluded from
  the branding block (the Harbor/Docker `Www-Authenticate` fix) and stay so.
- ❌ **Touching operator error-templates.** The branding block (block C below)
  is emitted verbatim; custom templates keep working.
- ❌ **Matching exotic JSON content types** (`application/problem+json`,
  `application/vnd.api+json`). `application/json*` only (Q2). Widen later if a
  real need appears — the `/api/` path block (block A) already covers most
  API-shaped responses regardless of Content-Type.

## 3. Locked decisions (brainstorm Q1–Q4)

| # | Decision | Rationale |
|---|----------|-----------|
| Q1 | The pass-through covers **exactly the branding block's status codes** (400,402,403,…,451,500–511; 401/407 already excluded). | Symmetry: any error that would be branded is spared iff it's an API/JSON response. |
| Q2 | JSON detection = response `Content-Type: application/json*` (wildcard covers `; charset=utf-8`). | Exactly what Arenet's `writeError` emits (`internal/api/errors.go`), verified. |
| Q3 | Applied to **every reverse-proxy route** (zero operator config). | The default branded page already applies to all routes; sparing JSON must too. |
| Q4 | Spare the branding when the request path is **`/api/*`** OR the response is **JSON**. | Captures Arenet admin actions (all under `/api/v1/`) AND any proxied third-party API, even one that omits its Content-Type. |

## 4. Empirically verified Caddy v2.11.3 invariants

Per CLAUDE.md §Empirical verification — every claim below was read in the
vendored source, cited by file:line:

1. **`handle_response` entries evaluate in slice order and stop at the first
   match** — `modules/caddyhttp/reverseproxy/reverseproxy.go:1113-1173`: the
   loop `continue`s on a non-matching `Match`, and a matching entry runs its
   routes then `return nil` (no fall-through). If **none** match,
   `finalizeResponse` copies the upstream response verbatim.
2. **`ResponseMatcher` matches `StatusCode` AND `Headers` (positive AND, no
   `not`)** — `modules/caddyhttp/responsematchers.go:27-44`.
3. **The header matcher supports a trailing wildcard** — `application/json*`
   matches `application/json; charset=utf-8` via the `HasSuffix`-wildcard
   branch in `modules/caddyhttp/matchers.go` `matchHeaders`.
4. **`copy_response` (`http.handlers.copy_response`) copies the upstream
   response verbatim to the client** from inside a `handle_response` route —
   `modules/caddyhttp/reverseproxy/copyresponse.go:46`. Without it a matching
   block would `return nil` **without** copying the body (the response would be
   lost), so the pass-through blocks MUST use `copy_response`, not an empty route.
5. **A `handle_response` route receives the ORIGINAL request** (with its path)
   and is a normal caddyhttp route — `reverseproxy.go:1150`
   (`rh.Routes.Compile(next).ServeHTTP(rw, origReq.WithContext(ctx))`). So an
   inner route may carry a `match` with a request **`path`** matcher, which is
   how block A matches `/api/*` (the `ResponseMatcher` alone can't see the path).

## 5. The change — three ordered `handle_response` blocks

In `buildConfigJSON` (`manager.go:1521`), replace the single branding block
with three, in this order. Extract the shared status-code list into a local
(`errorStatusCodes`) so it is declared once (DRY) and referenced by all three.

**Block A — `/api/*` path pass-through** (matches API actions of any Content-Type):
```go
{
  "match": map[string]any{"status_code": errorStatusCodes},
  "routes": []map[string]any{
    {
      "match": []map[string]any{ {"path": []string{"/api/*"}} },
      "handle": []map[string]any{ {"handler": "copy_response"} },
    },
  },
}
```
The inner `match` is a request matcher on the original request's path; when it
matches, `copy_response` sends the upstream JSON verbatim. When the inner
match fails (path not `/api/*`), the inner route is a no-op and control
returns from the `handle_response` — see §6 edge case E1.

**Block B — JSON response pass-through** (matches any JSON error, any path):
```go
{
  "match": map[string]any{
    "status_code": errorStatusCodes,
    "headers": map[string]any{"Content-Type": []string{"application/json*"}},
  },
  "routes": []map[string]any{
    { "handle": []map[string]any{ {"handler": "copy_response"} } },
  },
}
```

**Block C — branding (existing, unchanged)**: the current block verbatim
(status-code list now referencing `errorStatusCodes`), serving the `error`
handler for everything blocks A/B didn't spare.

Evaluation (Caddy stops at first `handle_response` whose `Match` passes):
- `/api/v1/...` 409 JSON → block A's `Match` (status) passes → inner path
  matches → `copy_response` → JSON verbatim. ✅
- proxied third-party `/data` 422 JSON → block A status passes but inner path
  `/api/*` fails (E1) → block B status+Content-Type passes → `copy_response`. ✅
- `regitry.sccnf.fr` 502 HTML → block A status passes, inner path fails; block
  B Content-Type fails (not JSON); block C brands it. ✅
- upstream 404 HTML page → same as above → branded. ✅

## 6. Edge cases

- **E1 — block A matches status but the inner `/api/*` path does not.** The
  outer `handle_response` has already "matched" (status only), so per invariant
  #1 Caddy will NOT fall through to block B/C from the *outer* loop — it runs
  block A's routes and returns. The inner route, whose `match` fails, is a
  no-op, so **nothing is copied and nothing is branded → the response falls
  through to Caddy's default finalize (verbatim copy)**. This must be verified
  empirically (smoke): a non-`/api` JSON path must still reach block B, OR the
  verbatim fall-through must itself be acceptable (it is — an un-branded
  verbatim response is the desired outcome for any API). **If** the smoke shows
  block A's status-only outer match swallows non-`/api` responses before block
  B can run, restructure: give block A's OUTER `handle_response` no status-only
  match and instead gate everything inside one block via inner routes ordered
  path-first then json — decided against pre-emptively to keep blocks simple,
  but this is the documented fallback. **The smoke test in §8 is the gate.**
- **E2 — JSON response with no charset** (`application/json`). `application/json*`
  matches (prefix). ✅
- **E3 — API response with no Content-Type at all.** Block A (path `/api/*`)
  still spares it; block B would not. Covered by Q4's OR. ✅
- **E4 — maintenance mode routes.** Emitted on a separate exclusive subroute
  (`manager.go:1547`), unaffected — this change only touches the proxy handler's
  `handle_response`.

## 7. Files

- `internal/caddymgr/manager.go` — `buildConfigJSON` ~1521: extract
  `errorStatusCodes`, emit blocks A + B before block C.
- `internal/caddymgr/error_template_json_test.go` (new) — JSON-shape unit tests
  + `caddy.Validate()` on the emitted config.

## 8. Testing (empirical gates — load-bearing Caddy path)

1. **JSON shape unit test**: `buildConfigJSON` for a reverse-proxy route emits
   THREE `handle_response` blocks in order A, B, C; block A's inner route has a
   `path:["/api/*"]` matcher + `copy_response`; block B matches
   `Content-Type: application/json*` + `copy_response`; block C is the
   unchanged `error` handler.
2. **`caddy.Validate()`**: the emitted full config validates cleanly (the
   `TestBuildConfigJSON_LoadsCleanly` pattern from CLAUDE.md). Three
   `handle_response` blocks with `copy_response` + a request path matcher must
   be a valid Caddy config.
3. **Live smoke (the E1 gate)**: run a binary; create a route proxying a tiny
   upstream that returns, on demand, (a) a `/api/x` 409 `application/json`
   body, (b) a `/data` 422 `application/json` body, (c) a `/page` 404
   `text/html` body. Through the FQDN route, assert: (a) client receives the
   JSON verbatim (`Content-Type: application/json`, body intact); (b) client
   receives the JSON verbatim (proves block B catches non-`/api` JSON — the E1
   check); (c) client receives the branded HTML page. Also re-confirm the real
   scenario: the actual Arenet admin `409 blockingRoutes` reaches the browser
   as JSON.

## 9. Process weight

LIGHT — single-file backend change + tests. Dedicated review on the emitted
config correctness (this is the gateway's config path; a malformed
`handle_response` could break every proxied route's error handling). ONE final
review before PR. Live smoke is mandatory (E1 is only settled empirically).
