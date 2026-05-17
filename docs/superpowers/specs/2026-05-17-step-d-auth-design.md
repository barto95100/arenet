# Step D — Local Authentication & Audit Log

## 1.1 Goal

Add a single-admin authentication system and an extended audit log to Arenet.
This step transforms Arenet from an open-by-default admin panel (Step C) into
a credentialed application suitable for deployment beyond a fully trusted
local network.

Predecessors: Step C closed at v0.1.0-poc (43 commits, REST API + admin UI
fully operational, no authentication).

Successors planned:
- Step D2 — Multi-user accounts with admin/editor roles
- Step D3 — SSO via OIDC (Authentik, Authelia, Keycloak compatible)
- Step E — Topology visualization + live metrics (WebSocket)

Step D delivers the minimal credentialed-access foundation that all subsequent
steps depend on.

## 1.2 Scope

Step D delivers, end-to-end:

- **First-boot admin setup** — when the database contains zero users, the UI
  serves a setup form gated by a server-generated token displayed in the logs.
  Override via `ARENET_ADMIN_USERNAME` and `ARENET_ADMIN_PASSWORD` for
  automated deployments.

- **Username/password login** — argon2id hashing, sliding session with
  configurable duration (24h default, 30 days with "Remember me"). Session
  state persisted in BoltDB.

- **15-minute inactivity lock** — server-side `last_activity` tracking, lock
  screen overlay preserving UI state, re-authentication via password only
  (not full re-login).

- **Common password protection** — embedded top-10k password blocklist
  (offline, instant) plus HaveIBeenPwned k-anonymity check (online,
  best-effort) with deferred re-verification at next login if HIBP was
  unreachable.

- **Per-IP rate limiting** — Tier 1 (5 failures in 5 min → 15 min block),
  Tier 2 (10 failures in 1h → 1h block). Trusted proxies via
  `ARENET_TRUSTED_PROXIES` env var (CIDR list) for correct IP extraction
  behind Cloudflare or similar.

- **Extended audit log** — every authentication event and every route
  mutation produces an immutable audit entry with username snapshot, IP,
  user agent, and before/after diff. Audit reads themselves are audited.

- **New page `/audit`** — DataTable with filters by date range, action type,
  and username. Expandable rows show full event detail including before/after
  JSON.

- **Backward compatibility with Step C** — existing Step C databases open
  cleanly with the Step D binary. Routes are preserved. The empty `users`
  bucket triggers the setup flow automatically on first start.

## 1.3 Out of scope

Explicitly deferred from Step D:

- **Multi-admin accounts and roles** — Step D maintains exactly one user.
  Multi-user with admin/editor roles is Step D2.

- **API tokens (Bearer auth)** — needed for CI/Ansible/Terraform integration.
  Cookie-only authentication in Step D does not preclude adding token-based
  auth later. Deferred to Phase 2+.

- **SSO / OIDC** — federation with Authentik, Authelia, Keycloak is Step D3.
  Architected such that the cookie-session model maps naturally onto an OIDC
  callback flow.

- **2FA / TOTP** — applicable only when Arenet is exposed on the public
  internet. Deferred to Phase 3 if usage patterns demonstrate need.

- **Password reset by email** — not applicable to single-admin homelab. The
  admin can be recreated by deleting the `users` bucket and restarting,
  triggering the setup flow. Documented in operator runbook.

- **Audit retention, export, and archive** — Step D writes audit events
  indefinitely. At 100 events/day with full metadata, BoltDB grows ~10 MB
  per year, acceptable. Retention policies and export tooling come in
  Phase 2+.

- **Persistent rate limit counters** — in-memory only. A restart resets
  counters. Acceptable because password strength (15+ chars) and argon2id
  cost make brute force infeasible regardless of rate limit state.

- **Security and threat dashboard** — visualization of blocked IPs,
  attack patterns, webhook notifications to external firewalls (FortiGate,
  Unifi, n8n). Deferred to Step F (see `docs/roadmap.md`).

- **Explicit CSRF tokens** — `SameSite=Strict` cookie attribute provides
  sufficient defense for Step D's threat model. Token-based CSRF protection
  may be added in Step D2+ if requirements evolve.

## 1.4 Locked decisions

Step D rests on 17 decisions documented in
`docs/superpowers/decisions/2026-05-17-step-d-design-decisions-final.md`.
Quick reference:

| ID    | Topic                          | Decision                                                                 |
|-------|--------------------------------|--------------------------------------------------------------------------|
| Q1    | Session mechanism              | Opaque cookie, HttpOnly+Secure+SameSite=Strict, state in BoltDB          |
| Q2    | First-boot bootstrap           | Setup UI + token-in-logs + env override                                  |
| Q3    | Session duration               | 24h sliding / 30d remember-me                                            |
| Q3bis | Inactivity lock                | 15 min, lock screen overlay (Pattern B), UI state preserved              |
| Q4    | Password hashing               | argon2id (m=64MiB, t=3, p=4) via alexedwards/argon2id                    |
| Q5    | Audit log                      | Extended pack, UUID v7 keys, BoltDB bucket, no auto-retention            |
| Q6    | Auth endpoints                 | 6 endpoints + per-IP rate limit (Tier 1/2)                               |
| D1    | Refactor *Tx storage           | ~~Annulled~~ — D2 makes it unnecessary                                   |
| D2    | Audit placement                | After Caddy reload success, best-effort                                  |
| D3    | Audit Event schema             | 10 fields, no secrets in JSON, outcome encoded in Action                 |
| D4    | Audit integration              | Helper `appendAudit`, `AuditAppender` interface consumer-side            |
| D5    | Username validation            | `^[a-z0-9_-]+$`, 3..32, reject uppercase                                 |
| D6    | Password validation            | 15..128, top-10k embedded + HIBP best-effort + re-check at login         |
| D7    | Action enum                    | 13 events (past tense), no session_expired, no rolled_back               |
| D8    | Rate limit & IP                | In-memory counters, trusted proxies via env var, slog WARN on Tier 2     |
| D9    | CSRF                           | SameSite=Strict only (Level 1)                                           |
| D10   | Audit visibility (Phase 1)     | Single admin sees everything; per-role filtering in Phase 2              |
| D11   | Storage error during login     | HTTP 503 with generic message; details to slog.Error                     |

## 1.5 Threat model

Step D is designed to defend Arenet against the following threats:

- **Online brute-force on the login form** — mitigated by per-IP rate
  limiting (Tier 1 + Tier 2) and argon2id's deliberate computational cost
  (~100ms per password verification on modern hardware).

- **Offline brute-force on a leaked database** — mitigated by argon2id's
  memory-hardness (64 MiB per attempt, GPU/ASIC-resistant) combined with
  15+ character password requirement and common-password screening.

- **Compromised passwords from third-party breaches** — mitigated by
  HaveIBeenPwned k-anonymity check at password creation and deferred
  re-check at next login if HIBP was unreachable initially.

- **Session theft via XSS** — mitigated by `HttpOnly` cookie attribute.
  JavaScript cannot read the session token even if an XSS vulnerability
  is found in a dependency.

- **Cross-site request forgery** — mitigated by `SameSite=Strict` cookie
  attribute. Browsers refuse to send the cookie on requests originating
  from other sites.

- **Abandoned authenticated sessions** — mitigated by 15-minute inactivity
  lock requiring password re-entry, plus 24h/30d session expiration.

- **Network-level eavesdropping** — mitigated by `Secure` cookie attribute
  in production (cookie only sent over HTTPS) plus the standard expectation
  that Arenet is served over TLS terminated by its embedded Caddy or an
  upstream proxy.

- **Audit log tampering by an authenticated administrator** — out of scope.
  The administrator has full BoltDB file access by design. Tamper-evident
  logging (hash chains, external write-once log) is a Phase 3+ concern if
  Arenet ever serves multi-tenant scenarios.

## 1.6 Security non-goals

Step D explicitly does not protect against:

- **Physical or filesystem access to the host running Arenet** — anyone
  with read access to `data.db` can extract password hashes and replay
  session cookies. Defense is OS-level (file permissions, full-disk
  encryption).

- **A compromised password that the legitimate admin has typed correctly
  into the form** — argon2id verifies it, the user gains access. Mitigation
  is user discipline (password manager, no password reuse).

- **TLS termination and certificate management** — Caddy handles this
  for routes; the admin API inherits the same behavior. Step D does not
  add a separate TLS layer for `/api/v1/*`.

- **Denial of service via authenticated requests** — an admin who knows
  their password can flood the API. Per-IP rate limiting applies only to
  authentication endpoints, not to authenticated route operations.

- **Side-channel attacks on argon2id** — timing variations, memory
  access patterns, etc. are not actively defended against. The threat
  model assumes attackers cannot execute code on the host running Arenet.

- **Supply-chain attacks on Go modules** — out of scope for application
  design. Dependencies are pinned in `go.mod`; module integrity is
  verified via Go's module proxy and `go.sum`.

## 2. Architecture & Package boundaries

This section maps the 17 locked decisions onto concrete Go and Svelte
package boundaries. It defines what is new, what is modified, what stays
untouched, and why. Subsequent sections (3 through 9) detail the contents
of each package; this section is the map.

### 2.1 Package layout

```text
arenet/
├── cmd/arenet/main.go                       MODIFIED  wiring
│
├── internal/
│   ├── auth/                                NEW
│   │   ├── bootstrap.go                     first-boot setup token + env override
│   │   ├── user.go                          User struct, UserStore CRUD
│   │   ├── password.go                      argon2id hash/verify, top-10k check
│   │   ├── hibp.go                          HaveIBeenPwned k-anonymity client
│   │   ├── session.go                       Session struct, SessionStore CRUD, sliding TTL
│   │   ├── ratelimit.go                     per-IP failure counters (in-memory)
│   │   ├── middleware.go                    cookie → session → user context, no-auth / soft-auth / hard-auth
│   │   ├── ipextract.go                     trusted proxies + X-Forwarded-For policy
│   │   ├── errors.go                        sentinel errors (ErrUserNotFound, ErrSessionExpired, ...)
│   │   └── data/common-passwords.txt        embedded top-10k (gzipped, ~30 KB)
│   │
│   ├── audit/                               NEW
│   │   ├── audit.go                         Event struct, Store Append/AppendTx/List
│   │   ├── actions.go                       Action enum (13 constants)
│   │   └── filter.go                        Filter struct for List queries
│   │
│   ├── storage/                             MODIFIED (minimal)
│   │   ├── storage.go                       add DB() accessor + 3 new buckets in NewStore
│   │   └── routes.go                        unchanged (per D1 annulled)
│   │
│   ├── api/                                 MODIFIED (extensive)
│   │   ├── handler.go                       Handler gains auth.Service and audit.Store deps
│   │   ├── routes.go                        existing handlers + appendAudit calls at the end
│   │   ├── auth.go                          NEW: 8 handlers (setup, login, logout, me, unlock, heartbeat, sessions list/delete)
│   │   ├── audit.go                         NEW: GET /api/v1/audit handler
│   │   ├── middleware.go                    add ratelimit middleware, integrate auth middleware groups
│   │   └── audit_helpers.go                 NEW: appendAudit, mustMarshal, contextual enrichment
│   │
│   └── caddymgr/                            unchanged (Step B/C)
│
└── web/
    └── frontend/
        └── src/
            ├── lib/
            │   ├── api/
            │   │   ├── client.ts            MODIFIED: 401 → goto /login, 403 → trigger lock state
            │   │   ├── auth.ts              NEW: setup/login/logout/me/unlock/heartbeat/sessions
            │   │   └── audit.ts             NEW: list with filters
            │   ├── stores/
            │   │   ├── auth.ts              NEW: current user, isLoading, lock state
            │   │   └── idle.ts              NEW: client-side 15-min timer
            │   └── components/
            │       └── LockScreen.svelte    NEW: overlay with password input
            └── routes/
                ├── +layout.svelte           MODIFIED: gate on auth bootstrap, mount LockScreen
                ├── login/+page.svelte       NEW
                ├── setup/+page.svelte       NEW
                └── audit/+page.svelte       NEW
```

### 2.2 New Go packages

Two new packages are created under `internal/`:

**`internal/auth/`** holds everything related to who the caller is: users,
sessions, password hashing and validation, HIBP client, rate limiting,
context propagation via middleware, and IP extraction with trusted-proxy
logic. Approximately 10 source files.

**`internal/audit/`** holds everything related to what the caller did: the
`Event` struct, the action enum, the `Store` with both standalone and
transactional append methods, and the `Filter` type for queries.
Approximately 3 source files.

The two packages have **no mutual dependency**. `auth` does not import
`audit`, and `audit` does not import `auth`. The integration happens in
`internal/api`, which imports both. This separation is deliberate: it keeps
each package independently testable and allows audit to evolve toward
external sinks (Loki, Elasticsearch) in Phase 2+ without touching auth.

### 2.3 Modified Go packages

**`internal/storage/`** receives a minimal change: a new `DB() *bolt.DB`
method on `Store` for handle sharing (see 2.4), and three new buckets
created in `NewStore` alongside the existing `routes` bucket. The
`routes.go` file and all existing CRUD methods are **unchanged** (decision
D1 annulled).

**`internal/api/`** receives the bulk of the modifications: the `Handler`
struct gains two new fields (`auth` and `audit`), `NewHandler` gains two
parameters with nil checks, the existing three mutation handlers each get
a single `appendAudit` call at the end, and the chi router is restructured
into three middleware groups (see 2.5). Four new files are added:
`auth.go` (8 handlers), `audit.go` (1 handler), `audit_helpers.go`
(centralized audit emission helper), and the rate limit middleware in
`middleware.go`.

**`cmd/arenet/main.go`** receives wiring changes only: instantiate the
auth services and audit store after the storage store, pass them to
`NewHandler`, and start the session cleanup goroutine alongside the
existing admin server goroutine.

No other packages are touched. `internal/caddymgr/` remains unchanged,
ensuring Step C's reverse-proxy behavior is preserved.

### 2.4 Storage handle sharing

bbolt enforces a fundamental constraint: **only one writer per database
file at a time**. The new packages cannot open independent connections
to the same `data.db`. The architecture must share a single `*bolt.DB`
handle across all three packages that need it.

To minimize disruption to Step C, `storage.Store` exposes its underlying
handle through a new `DB() *bolt.DB` accessor (decision 2.5 from yesterday's
Section 2 audit, choice Option A). `cmd/arenet/main.go` calls this accessor
once after `NewStore` succeeds and passes the result to the constructors
of `auth.UserStore`, `auth.SessionStore`, and `audit.Store`. Each store
operates on its own bucket name and does not touch the others.

Three new buckets are created idempotently in `storage.NewStore`, alongside
the existing `routes` bucket: `users`, `sessions`, and `audit`. The use of
`tx.CreateBucketIfNotExists` ensures that a Step C database opened by a
Step D binary cleanly gains the new buckets on first run without
migration.

This design is contractual: future contributors must not attempt to open
a second `*bolt.DB` against the same file from a different package. The
constraint is documented inline in `storage.DB`'s godoc.

### 2.5 chi router structure

The admin HTTP server uses chi (Step C). Step D restructures the route tree
into three middleware groups, each with its own combination of guards:

```text
chi.Router
├── Use(RequestID, slogLogger, Recoverer)
├── Use(devCORS)                          [dev mode only]
│
└── Route /api/v1
    │
    ├── Route /auth
    │   ├── Use(rateLimit)                [NEW — Tier 1 + Tier 2 per IP]
    │   │
    │   ├── POST /setup                   [no-auth + setup-token gate]
    │   ├── POST /login                   [no-auth]
    │   │
    │   ├── Group [soft-auth]             [cookie required, session exists, idle OK]
    │   │   ├── POST /logout
    │   │   ├── GET  /me
    │   │   └── POST /unlock
    │   │
    │   └── Group [hard-auth]             [cookie + session + not expired + not idle]
    │       ├── POST /heartbeat
    │       ├── GET  /sessions
    │       └── DELETE /sessions/{id}
    │
    └── Group [hard-auth]                 [cookie + session + not expired + not idle]
        ├── GET    /routes                [Step C handler + audit_viewed not emitted: read]
        ├── POST   /routes                [Step C handler + appendAudit]
        ├── GET    /routes/{id}           [Step C handler unchanged]
        ├── PUT    /routes/{id}           [Step C handler + appendAudit]
        ├── DELETE /routes/{id}           [Step C handler + appendAudit]
        └── GET    /audit                 [NEW handler + emits audit_viewed]
```

Three middleware levels:

- **no-auth**: no cookie verification. `/setup` and `/login`. The setup
  endpoint additionally checks that no admin user exists yet; if one does,
  setup returns 404 (refuses to expose its existence).

- **soft-auth**: cookie required, session must exist in BoltDB, but idle
  state is allowed. Used by endpoints that the lock screen needs (the UI
  polls `/me` to populate the lock screen with the username, and calls
  `/unlock` to leave the locked state). `/logout` is also soft-auth so
  that an already-idle session can be cleanly terminated.

- **hard-auth**: cookie required, session must exist, must not be
  expired (24h/30d absolute), and must not be idle (>15 min without
  activity). Used by all business endpoints (routes, audit) and by
  session self-management endpoints.

Rate-limit middleware is scoped to `/api/v1/auth/*` only. Authenticated
business endpoints are not rate-limited (an admin who knows their
password may legitimately make many calls).

Detailed middleware behavior — including how 401 vs 403 is decided, how
`last_activity` is updated, and how the request context propagates user
identity to handlers — is specified in Section 5.

### 2.6 Frontend package layout

The frontend gains three new pages, two new stores, one new component,
and modifications to the shared layout and HTTP client.

**New pages** (`web/frontend/src/routes/`):

- `/setup/+page.svelte` — shown when the application detects no admin
  user exists. Accepts the setup token from server logs plus the new
  admin's username and password.

- `/login/+page.svelte` — username/password form with "Remember me"
  checkbox. Submits to `/api/v1/auth/login`, redirects to `/routes` on
  success.

- `/audit/+page.svelte` — DataTable of audit events with filter controls
  (date range, action type, username). Expandable rows show full event
  detail including before/after JSON.

**New stores** (`web/frontend/src/lib/stores/`):

- `auth.ts` — current user info (id, username), authentication state
  (`unknown` / `authenticated` / `locked` / `anonymous`), lock-screen
  visibility, isLoading flag during transitions.

- `idle.ts` — client-side 15-minute timer reset on any successful API call
  via the client layer. Triggers the lock-screen overlay locally before
  the server enforces it on the next request.

**New component** (`web/frontend/src/lib/components/`):

- `LockScreen.svelte` — full-screen overlay rendered above the existing
  app. Shows the username (read from the auth store) and a single password
  field. Submits to `/api/v1/auth/unlock`. On success, hides itself; on
  failure, displays the error inline. Preserves underlying UI state.

**Modified files**:

- `web/frontend/src/lib/api/client.ts` — intercepts HTTP 401 and 403
  responses globally. 401 clears the auth store and redirects to `/login`.
  403 sets the locked state on the auth store, which makes
  `LockScreen.svelte` appear via the layout's reactivity.

- `web/frontend/src/routes/+layout.svelte` — gates the entire app on the
  auth store. While the auth state is `unknown`, renders a centered
  spinner and calls `/api/v1/auth/me` once on mount to bootstrap.
  Renders the existing sidebar + main layout when `authenticated`.
  Renders `LockScreen.svelte` on top when `locked`. Redirects to `/login`
  when `anonymous`, and to `/setup` when the server returns the "no admin
  yet" indicator on the bootstrap call.

**Sidebar** — gains a fifth navigation item, "Audit", positioned after
"Routes" and before "Topology". The final order is:

1. Routes (active)
2. Audit (active, new)
3. Topology (disabled, Step E)
4. Security (disabled, Step F)
5. Settings (disabled, Phase 2+)

The cyan-rail active highlight and existing collapse/expand behavior
apply unchanged.

### 2.7 Go dependency additions

Two Go module additions:

- **`github.com/alexedwards/argon2id`** — wrapper around
  `golang.org/x/crypto/argon2` that produces and parses PHC-format hash
  strings. MIT license, ~250 LOC, audit-friendly. Provides
  `CreateHash(password, params)` and `ComparePasswordAndHash(password,
  hash)`.

- **`github.com/google/uuid`** — already present in Step C as a transitive
  dependency. Step D requires version v1.7.0 or later for `uuid.NewV7()`,
  which generates time-sortable UUIDs used as audit-event keys.

No other new dependencies. The HIBP client is implemented from scratch in
`internal/auth/hibp.go` using only the standard library (`net/http`,
`crypto/sha1`, `bufio`).

### 2.8 No new frontend dependencies

Step D adds no new npm packages. All new pages and components are built
using the existing Step C design system primitives (Modal, DataTable,
Input, Checkbox, Button, Badge, Card, StatusDot, Spinner) and the
existing stores pattern. The LockScreen overlay reuses the same Modal
patterns (focus trap, Escape handling) adapted for full-screen display.

This constraint serves two goals: reducing npm audit surface (a
recurring source of supply-chain vulnerabilities), and forcing reuse of
the Step C primitives, which strengthens their design by exercising
them in new contexts.
