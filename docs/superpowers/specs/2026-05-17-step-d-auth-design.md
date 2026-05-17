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

## 3. Storage schemas

Step D introduces three new data types and their respective stores, all
operating on the shared `*bolt.DB` handle exposed by `storage.Store.DB()`
(see 2.4). This section specifies each struct, the bucket layout, the
store's public API, and the validation rules applied at the storage
boundary.

### 3.1 Overview

Three new buckets are created in `storage.NewStore` alongside the
existing `routes` bucket:

| Bucket     | Key type                       | Value         | Owner store           |
|------------|--------------------------------|---------------|-----------------------|
| `users`    | UUID v4 string                 | JSON `User`   | `auth.UserStore`      |
| `sessions` | 256-bit base64 string          | JSON `Session`| `auth.SessionStore`   |
| `audit`    | UUID v7 raw bytes (16 bytes)   | JSON `Event`  | `audit.Store`         |

All three stores share the same `*bolt.DB` handle, consistent with bbolt's
single-writer constraint. Each store operates only on its designated
bucket; no store reaches across bucket boundaries.

All timestamps are stored in UTC. JSON tags are snake_case at the storage
layer (matching the existing `storage.Route` convention) and converted to
camelCase by the API layer wire shapes (matching the existing
`routeResponse` convention from Step C).

### 3.2 User

A `User` represents a single admin account. Phase 1 has exactly one row
in the bucket at any time.

```go
// User represents a single admin account.
//
// Phase 1: exactly one row. The setup flow creates it; the first login
// records LastLoginAt. Phase 2 will allow multiple rows with admin/editor
// roles (see docs/roadmap.md).
type User struct {
    ID                  string    `json:"id"`                   // UUID v4
    Username            string    `json:"username"`             // lowercase, 3..32
    DisplayName         string    `json:"display_name"`         // free text, ≤64
    PasswordHash        string    `json:"password_hash"`        // argon2id PHC string
    HIBPCheckStatus     string    `json:"hibp_check_status"`    // "pending" | "clean" | "compromised" | "skipped"
    HIBPCheckedAt       time.Time `json:"hibp_checked_at,omitempty"`
    PasswordCompromised bool      `json:"password_compromised"`
    CreatedAt           time.Time `json:"created_at"`
    UpdatedAt           time.Time `json:"updated_at"`
    LastLoginAt         time.Time `json:"last_login_at,omitempty"`
}
```

**Bucket**: `users`
**Key**: `User.ID` (UUID v4 string generated by `uuid.NewString()`)
**No secondary index** (see 3.6 — `GetByUsername` performs a full bucket
scan, acceptable for Phase 1 with `Count == 1`).

**`auth.UserStore` public API**:

```go
type UserStore interface {
    // Create persists a new user. Hashes the password with argon2id,
    // generates the UUID, sets CreatedAt and UpdatedAt. Returns
    // ErrUsernameTaken if the username already exists.
    Create(ctx context.Context, username, displayName, password string) (User, error)

    // GetByID returns the user with the given ID, or ErrUserNotFound.
    GetByID(ctx context.Context, id string) (User, error)

    // GetByUsername returns the user with the given username, or
    // ErrUserNotFound. O(n) scan; acceptable for Phase 1 single-admin.
    GetByUsername(ctx context.Context, username string) (User, error)

    // Count returns the number of users currently in the bucket.
    // Used by the bootstrap flow (count == 0 → setup mode).
    Count(ctx context.Context) (int, error)

    // UpdatePassword re-hashes and stores a new password, updates
    // UpdatedAt, and resets HIBPCheckStatus to "pending" so the new
    // password gets re-verified at next login.
    UpdatePassword(ctx context.Context, id, newPassword string) error

    // UpdateHIBPStatus updates the HIBP fields after a deferred re-check
    // at login. Best-effort: failure logs but does not block the login.
    UpdateHIBPStatus(ctx context.Context, id string, status string, compromised bool) error

    // RecordLogin updates LastLoginAt. Best-effort: failure logs but
    // does not block the login response.
    RecordLogin(ctx context.Context, id string) error
}
```

**Validation rules** (enforced by `Create` and `UpdatePassword`):

- **Username**: regex `^[a-z0-9_-]+$`, length 3..32, `strings.TrimSpace`
  applied first. Uppercase characters cause `ErrUsernameInvalid` with
  message "username must be lowercase".
- **DisplayName**: length ≤64, may be empty.
- **Password**: length 15..128. Checked against the embedded top-10k list
  before hashing; if found, returns `ErrPasswordCommon`. HIBP check is
  asynchronous and orthogonal (see Section 7).

**Sentinel errors**:

```go
var (
    ErrUserNotFound     = errors.New("auth: user not found")
    ErrUsernameTaken    = errors.New("auth: username already taken")
    ErrUsernameInvalid  = errors.New("auth: username does not match required format")
    ErrPasswordTooShort = errors.New("auth: password must be at least 15 characters")
    ErrPasswordTooLong  = errors.New("auth: password must be at most 128 characters")
    ErrPasswordCommon   = errors.New("auth: password is in the list of common compromised passwords")
)
```

### 3.3 Session

A `Session` represents a server-side authenticated session bound to a
user. The session ID is the opaque token stored in the user's browser
cookie.

```go
// Session represents a server-side authenticated session.
//
// The ID is the opaque 256-bit token also stored in the user's
// arenet_session cookie. ExpiresAt enforces the absolute upper bound
// (24h or 30d); LastActivity enforces the 15-minute idle lock window.
type Session struct {
    ID           string    `json:"id"`            // 256-bit base64 url-safe (43 chars)
    UserID       string    `json:"user_id"`
    IssuedAt     time.Time `json:"issued_at"`
    ExpiresAt    time.Time `json:"expires_at"`    // sliding TTL: 24h or 30d
    LastActivity time.Time `json:"last_activity"`
    RememberMe   bool      `json:"remember_me"`
    IP           string    `json:"ip"`            // captured at issue time
    UserAgent    string    `json:"user_agent"`    // captured at issue time
}
```

**Bucket**: `sessions`
**Key**: `Session.ID` — 32 random bytes from `crypto/rand`, base64
url-safe encoded without padding (43 characters). Same value as the
cookie sent to the browser.

The `Username` is intentionally **not** stored in `Session`. The single
source of truth is `User`. Resolving a session to a username requires
one extra BoltDB lookup at the API layer; this cost is negligible
(<1ms) and avoids denormalization drift if the user is renamed.

**`auth.SessionStore` public API**:

```go
type SessionStore interface {
    // Create generates a new session ID via crypto/rand, computes
    // ExpiresAt from RememberMe (now+24h or now+30d), and persists.
    Create(ctx context.Context, userID string, rememberMe bool, ip, userAgent string) (Session, error)

    // Get returns the session by ID. If ExpiresAt < now, the session
    // is deleted (lazy purge) and ErrSessionExpired is returned. The
    // idle check (LastActivity + 15min) is NOT performed here; the
    // middleware does it separately so that /auth/me and /auth/unlock
    // can retrieve an idle session.
    Get(ctx context.Context, id string) (Session, error)

    // Touch updates LastActivity to now and extends ExpiresAt by the
    // sliding TTL window. Best-effort: failure logs warning but does
    // not fail the calling request. Called by the hard-auth middleware
    // on every successful authenticated request.
    Touch(ctx context.Context, id string) error

    // Delete removes the session. Idempotent (no error if absent).
    Delete(ctx context.Context, id string) error

    // DeleteAllForUser deletes every session owned by userID. Used by
    // "logout everywhere" actions and by Phase 2 user-management flows.
    // Returns the number of sessions deleted.
    DeleteAllForUser(ctx context.Context, userID string) (int, error)

    // ListForUser returns all sessions for userID, including expired
    // ones not yet lazy-purged. The UI filters expired entries client-side.
    ListForUser(ctx context.Context, userID string) ([]Session, error)

    // CleanupExpired deletes all sessions with ExpiresAt < now. Called
    // by the background cleanup goroutine every 6 hours. Returns the
    // number of sessions deleted.
    CleanupExpired(ctx context.Context) (int, error)
}
```

**Sentinel errors**:

```go
var (
    ErrSessionNotFound = errors.New("auth: session not found")
    ErrSessionExpired  = errors.New("auth: session expired")
)
```

The middleware uses the distinction between these two errors to decide
the HTTP status code: a missing session is 401 (re-login from scratch);
an expired session is also 401 (the cookie is stale, same outcome from
the user's perspective). The distinction is preserved at the storage
layer for observability and future use.

### 3.4 Audit Event

An audit `Event` is an immutable record of one action that occurred in
Arenet. Once written, an event is never updated or deleted (Phase 1 has
no retention policy; see Section 11 — Out of scope).

```go
// Event is a single audit log entry.
//
// Events are immutable once written. UUID v7 keys provide natural
// chronological ordering via BoltDB cursor iteration, so no secondary
// time index is needed.
//
// Security rule: BeforeJSON and AfterJSON MUST NOT contain secrets
// (password hashes, session tokens, etc.). Producers strip sensitive
// fields before serializing.
type Event struct {
    ID                    string          `json:"id"`                       // UUID v7
    Timestamp             time.Time       `json:"timestamp"`                // redundant with v7 but explicit
    ActorUserID           string          `json:"actor_user_id,omitempty"`  // "" for unauthenticated events
    ActorUsernameSnapshot string          `json:"actor_username_snapshot,omitempty"`
    Action                string          `json:"action"`                   // see actions.go enum
    TargetType            string          `json:"target_type,omitempty"`    // "route" | "user" | "session" | ""
    TargetID              string          `json:"target_id,omitempty"`
    BeforeJSON            json.RawMessage `json:"before_json,omitempty"`    // nil for create / login / ...
    AfterJSON             json.RawMessage `json:"after_json,omitempty"`     // nil for delete / login_failure / ...
    Message               string          `json:"message,omitempty"`        // free text (login_failure reason, etc.)
    IP                    string          `json:"ip,omitempty"`
    UserAgent             string          `json:"user_agent,omitempty"`
}
```

**Bucket**: `audit`
**Key**: `Event.ID` — 16 raw bytes of a UUID v7 generated by
`uuid.NewV7()`. UUID v7 encodes the timestamp in its leading bits, so
BoltDB's lexicographic key ordering yields natural chronological
iteration. `bucket.Cursor().Last()` returns the most recent event,
`Prev()` walks backward in time. No secondary time index is needed.

The keys are stored as **raw 16-byte slices**, not string-encoded. The
JSON `id` field exposes the human-readable hyphenated form for API and
UI consumption.

**`audit.Store` public API**:

```go
type Store interface {
    // Append persists a new event in its own transaction. Generates
    // the UUID v7 (which sets Timestamp implicitly), the caller fills
    // all other fields. Used by handlers that don't need atomicity
    // with another mutation.
    Append(ctx context.Context, evt Event) error

    // AppendTx is the transactional variant: it accepts a *bolt.Tx
    // from the caller and writes within that transaction. Reserved
    // for future atomic patterns; Step D handlers use Append.
    AppendTx(tx *bolt.Tx, evt Event) error

    // List returns events matching the filter, in reverse chronological
    // order (most recent first), paginated. The returned cursor is
    // opaque and should be passed back in Filter.Cursor to fetch the
    // next page. Returns nextCursor == "" when there are no more pages.
    List(ctx context.Context, f Filter) (events []Event, nextCursor string, err error)
}
```

**`audit.Filter`**:

```go
// Filter narrows the events returned by List. Zero values mean "no
// filter on this field". Limit defaults to 50 if zero. Cursor is the
// opaque token returned by the previous List call.
type Filter struct {
    ActorUserID string
    Action      string
    TargetType  string
    TargetID    string
    From        time.Time // inclusive
    To          time.Time // exclusive
    Limit       int       // max 200, default 50
    Cursor      string    // opaque, from previous List call
}
```

The cursor is the hyphenated UUID v7 of the last event returned by the
previous call. List uses `bucket.Cursor().Seek()` to position past it
and then iterates with `Prev()`.

**`AppendTx` rationale**: Step D handlers use `Append` (own transaction)
because audit emission is post-success and best-effort (decision D2).
`AppendTx` is included in the API for symmetry and to support Phase 2+
patterns where audit might need to be atomic with a multi-bucket
transaction. It is not used in Step D itself.

### 3.5 Bucket initialization

`storage.NewStore` is modified to create the three new buckets
idempotently alongside the existing `routes` bucket:

```go
func NewStore(dbPath string) (*Store, error) {
    if dbPath == "" {
        return nil, errors.New("storage: dbPath must not be empty")
    }
    if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
        return nil, fmt.Errorf("storage: create data dir: %w", err)
    }

    db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 3 * time.Second})
    if err != nil {
        return nil, fmt.Errorf("storage: open bbolt %q: %w", dbPath, err)
    }

    if err := db.Update(func(tx *bolt.Tx) error {
        for _, name := range [][]byte{
            []byte("routes"),    // Step B/C
            []byte("users"),     // Step D
            []byte("sessions"),  // Step D
            []byte("audit"),     // Step D
        } {
            if _, err := tx.CreateBucketIfNotExists(name); err != nil {
                return fmt.Errorf("create bucket %q: %w", name, err)
            }
        }
        return nil
    }); err != nil {
        _ = db.Close()
        return nil, fmt.Errorf("storage: init buckets: %w", err)
    }

    return &Store{db: db}, nil
}

// DB returns the underlying bbolt handle. Reserved for the auth and
// audit packages, which share the same database file per bbolt's
// single-writer constraint. Other consumers MUST NOT call this and
// MUST use the typed methods on Store.
func (s *Store) DB() *bolt.DB {
    return s.db
}
```

**Migration story**: a Step C database opened by a Step D binary contains
only the `routes` bucket. `CreateBucketIfNotExists` creates the three
new buckets empty on first open. The `users` bucket being empty
triggers the setup flow at the API layer (see Section 4). All Step C
routes are preserved untouched. There is no schema versioning; the
buckets either exist or are created on the fly.

### 3.6 No secondary indexes

Phase 1 deliberately omits all secondary indexes:

- **`GetByUsername`** performs a full scan of the `users` bucket. With
  exactly one user in Phase 1, this is O(1) in practice. Phase 2 will
  add an inverted index (a `usernames` bucket mapping `username → user_id`)
  when the user count grows.

- **Session iteration by user** (`ListForUser`, `DeleteAllForUser`)
  scans the entire `sessions` bucket. Step D will typically have 1-5
  active sessions, so the cost is negligible. A secondary index would
  be added in Phase 2+ if session counts exceed a few hundred.

- **Audit event filtering** by `ActorUserID`, `Action`, `TargetType`,
  or `TargetID` is done at query time by iterating the `audit` bucket
  in reverse chronological order and filtering in memory. With ~100
  events per day and one year of retention, this is ~36k events to
  scan in the worst case, which BoltDB handles in <50ms. A secondary
  index (e.g. `audit_by_actor`) becomes worthwhile only if the audit
  bucket grows beyond ~1M events, which is unlikely without retention
  policy changes (Phase 2+).

The rationale is YAGNI: every secondary index doubles the write cost
of mutations and complicates the consistency model. Single-admin
homelab usage does not justify that cost, and the index can be added
later without breaking changes to the public API (the methods stay
the same; only the internal lookup strategy changes).

## 4. Auth endpoints — HTTP detail

This section specifies the wire contract of every endpoint introduced
in Step D: request shape, response shape, error responses, audit events
emitted, and side effects on session state. It is the contract that
both the backend handlers and the frontend client must honor.

### 4.1 Overview

Step D adds ten new HTTP endpoints. Nine are under `/api/v1/auth/*`,
one is `/api/v1/audit` for reading the audit log.

| Method | Path                              | Group     | Audit emitted                         |
|--------|-----------------------------------|-----------|---------------------------------------|
| POST   | `/api/v1/auth/setup`              | no-auth   | `setup_admin_created`                 |
| POST   | `/api/v1/auth/login`              | no-auth   | `login_success` or `login_failure`    |
| POST   | `/api/v1/auth/logout`             | soft-auth | `logout`                              |
| GET    | `/api/v1/auth/me`                 | soft-auth | — (read, not audited)                 |
| POST   | `/api/v1/auth/unlock`             | soft-auth | `unlock_success` or `unlock_failure`  |
| POST   | `/api/v1/auth/heartbeat`          | hard-auth | — (heartbeat, not audited)            |
| GET    | `/api/v1/auth/sessions`           | hard-auth | — (read, not audited)                 |
| DELETE | `/api/v1/auth/sessions/{id}`      | hard-auth | `session_revoked`                     |
| POST   | `/api/v1/auth/me/password`        | hard-auth | `password_changed`                    |
| GET    | `/api/v1/audit`                   | hard-auth | `audit_viewed`                        |

Middleware groups (specified in Section 5):

- **no-auth**: no session cookie required.
- **soft-auth**: cookie + valid session, idle state allowed.
- **hard-auth**: cookie + valid session + not idle (within 15-minute
  inactivity window).

All endpoints share these conventions:

- Request and response bodies use **camelCase** JSON (matching Step C's
  `routeRequest` / `routeResponse` convention).
- The internal storage layer uses snake_case (Section 3); the API layer
  performs the case transformation.
- Error responses use the single-key envelope `{"error": "message"}`
  (matching Step C). Errors are returned one at a time, not as lists.
- Error messages are in English. The frontend may translate for display.
- No internal details (file paths, SQL fragments, stack traces) appear
  in error messages exposed to the client.
- Rate limit middleware applies to all `/api/v1/auth/*` endpoints (see
  Section 5 for tier definitions). The `/api/v1/audit` endpoint is not
  rate-limited because it requires a valid authenticated session.

### 4.2 POST /api/v1/auth/setup

Creates the first admin account. Available only when the `users`
bucket is empty.

**Group**: no-auth (the user has not authenticated yet by definition)

**Request body**:

```json
{
  "setupToken": "8f3a9b2c4e7d1f6a...",
  "username": "admin",
  "displayName": "Site Admin",
  "password": "correct-horse-battery-staple-15"
}
```

- `setupToken` (string, required): the token displayed in the server
  logs at startup. Regenerated on every restart until an admin exists.
- `username` (string, required): lowercase, 3..32, regex `^[a-z0-9_-]+$`.
- `displayName` (string, optional): free text, ≤64. Empty allowed.
- `password` (string, required): 15..128 characters. Validated against
  the embedded top-10k list synchronously. HIBP check launched
  asynchronously after creation (see Section 7).

**Response 201**:

```json
{
  "id": "a3a6e27d-043b-425a-8e40-868bf1943de8",
  "username": "admin",
  "displayName": "Site Admin",
  "createdAt": "2026-05-17T14:23:00.000Z"
}
```

Sets the session cookie:

```text
Set-Cookie: arenet_session=<256-bit base64>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400
```

The newly created admin is immediately logged in (24h session, no
remember-me at setup time). The `Secure` attribute is omitted in
`--dev` mode (see 4.11).

**Errors**:

| Status | Body                                                                          | Trigger                                       |
|--------|-------------------------------------------------------------------------------|-----------------------------------------------|
| 400    | `{"error": "username must be lowercase"}`                                     | Username regex / length validation fails      |
| 400    | `{"error": "password must be at least 15 characters"}`                        | Password too short                            |
| 400    | `{"error": "password is in the list of common compromised passwords"}`        | Top-10k match                                 |
| 400    | `{"error": "displayName must be at most 64 characters"}`                      | Display name too long                         |
| 400    | `{"error": "invalid JSON body"}`                                              | Body not valid JSON                           |
| 403    | `{"error": "setup token invalid or expired"}`                                 | `setupToken` mismatch                         |
| 404    | `{"error": "setup unavailable: an admin already exists"}`                     | Setup attempted after admin exists            |
| 429    | `{"error": "too many attempts, retry after 15 minutes"}` + `Retry-After: 900` | Rate limit triggered                          |
| 500    | `{"error": "internal error"}`                                                 | Unexpected failure (DB write fails, etc.)     |

**Audit event emitted on success**: `setup_admin_created` with
`ActorUserID` set to the new user's ID, `TargetType: "user"`,
`TargetID` set to the new user's ID, `AfterJSON` containing the new
`User` struct **with `PasswordHash` removed** (no secrets in audit).

**Notes**:

- The 404 on "admin already exists" is deliberate: returning 403 or
  409 would confirm the endpoint exists, which is a minor info leak.
  404 indicates "this resource is not available in your current state".
- The setup token is invalidated server-side immediately after a
  successful setup, preventing replay.

### 4.3 POST /api/v1/auth/login

Authenticates an existing user and issues a session.

**Group**: no-auth

**Request body**:

```json
{
  "username": "admin",
  "password": "correct-horse-battery-staple-15",
  "rememberMe": false
}
```

- `username` (string, required): the username to log in as.
- `password` (string, required): the user's password.
- `rememberMe` (boolean, optional, default `false`): when `true`, the
  session uses a 30-day sliding TTL instead of the default 24h.

**Response 200**:

```json
{
  "id": "a3a6e27d-043b-425a-8e40-868bf1943de8",
  "username": "admin",
  "displayName": "Site Admin"
}
```

Sets the session cookie with `Max-Age` of either 86400 (24h) or
2592000 (30d) seconds based on `rememberMe`.

**Errors**:

| Status | Body                                                            | Trigger                                            |
|--------|-----------------------------------------------------------------|----------------------------------------------------|
| 400    | `{"error": "invalid JSON body"}`                                | Body not valid JSON                                |
| 400    | `{"error": "username and password are required"}`               | Missing required field                             |
| 401    | `{"error": "invalid credentials"}`                              | Username not found OR password mismatch (same msg) |
| 429    | `{"error": "too many attempts, retry after 15 minutes"}`        | Tier 1 rate limit (5 failures in 5 min)            |
| 429    | `{"error": "too many attempts, retry after 1 hour"}`            | Tier 2 rate limit (10 failures in 1h)              |
| 503    | `{"error": "authentication service temporarily unavailable"}`   | User store unreachable (decision D11)              |

**Audit events emitted**:

- On success: `login_success` with `ActorUserID` set, `IP` and
  `UserAgent` captured.
- On bad credentials: `login_failure` with `ActorUserID` empty (we
  may not have a matching user), `ActorUsernameSnapshot` set to the
  attempted username (truncated to 32 chars for safety), `Message`
  set to `"user_not_found"` or `"bad_password"`.
- On rate limit: `login_failure` with `Message: "rate_limited_tier_1"`
  or `"rate_limited_tier_2"`.

**Security notes**:

- The same `401 invalid credentials` message is returned whether the
  username does not exist or the password is wrong. This prevents
  username enumeration.
- A constant-time string comparison (`subtle.ConstantTimeCompare`) is
  used inside `argon2id.ComparePasswordAndHash` to prevent timing
  attacks (the library handles this internally).
- The attempted username in `login_failure` is truncated to prevent
  log injection of arbitrarily large strings.

**Side effects on success**:

- A new `Session` is created in the `sessions` bucket.
- `User.LastLoginAt` is updated (best-effort, failure logged but does
  not fail the login response).
- If `User.HIBPCheckStatus == "pending"`, an asynchronous HIBP
  re-check is launched (see Section 7).

### 4.4 POST /api/v1/auth/logout

Terminates the current session.

**Group**: soft-auth (idle sessions can still be cleanly logged out)

**Request body**: empty.

**Response 204**: no body.

Clears the cookie:

```text
Set-Cookie: arenet_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0
```

**Errors**:

| Status | Body                                       | Trigger                            |
|--------|--------------------------------------------|------------------------------------|
| 401    | `{"error": "no active session"}`           | No cookie or session not found     |

**Audit event emitted**: `logout` with `ActorUserID` and
`ActorUsernameSnapshot` set. `Message` set to `"manual"` to
distinguish from session expiry (which is not audited per D7).

**Notes**:

- The endpoint is idempotent: calling it without a session returns
  401 but does not destabilize the client. The frontend treats 401
  the same as success here (the user wanted to log out, they are
  now logged out).
- The session is deleted from the `sessions` bucket on successful
  logout.

### 4.5 GET /api/v1/auth/me

Returns the current authenticated user's identity and session state.

**Group**: soft-auth (must work when locked, to populate the lock
screen with the username)

**Request body**: none.

**Response 200**:

```json
{
  "id": "a3a6e27d-043b-425a-8e40-868bf1943de8",
  "username": "admin",
  "displayName": "Site Admin",
  "locked": false,
  "passwordCompromised": false,
  "hibpCheckStatus": "clean"
}
```

- `id`, `username`, `displayName`: from the `User` struct.
- `locked` (boolean): `true` if the current session has exceeded
  the 15-minute inactivity window. Used by the frontend to show
  the lock-screen overlay.
- `passwordCompromised` (boolean): `true` if a HIBP re-check has
  detected the user's password in a breach database. Used by the
  frontend to show a banner urging immediate password change.
- `hibpCheckStatus` (string): one of `"pending"`, `"clean"`,
  `"compromised"`, `"skipped"`. Useful for the frontend to show a "verifying
  your password against breach databases..." indicator if pending.

**Errors**:

| Status | Body                              | Trigger                              |
|--------|-----------------------------------|--------------------------------------|
| 401    | `{"error": "no active session"}`  | No cookie or session expired/missing |

**Important behavior**: `/auth/me` does **not** update
`Session.LastActivity`. This is critical: if it did, the frontend
polling `/me` to keep the lock screen populated would silently
reset the idle timer server-side, making the lock screen
permanent unreachable. The middleware for soft-auth specifically
skips the Touch call for this endpoint (see Section 5).

**No audit emitted**: this is a read operation. Step D's audit
policy (decision Q5) audits authentication events and mutations,
not routine reads.

### 4.6 POST /api/v1/auth/unlock

Re-authenticates an idle session to lift the lock screen.

**Group**: soft-auth

**Request body**:

```json
{
  "password": "correct-horse-battery-staple-15"
}
```

**Response 200**:

```json
{
  "unlocked": true
}
```

**Errors**:

| Status | Body                                                            | Trigger                            |
|--------|-----------------------------------------------------------------|------------------------------------|
| 400    | `{"error": "invalid JSON body"}`                                | Body not valid JSON                |
| 400    | `{"error": "password is required"}`                             | Missing password                   |
| 401    | `{"error": "invalid password"}`                                 | Password does not match the user   |
| 429    | `{"error": "too many attempts, retry after 15 minutes"}`        | Tier 1 rate limit                  |
| 429    | `{"error": "too many attempts, retry after 1 hour"}`            | Tier 2 rate limit                  |

**Audit events emitted**:

- On success: `unlock_success` with `ActorUserID`, `IP`, `UserAgent`.
- On failure: `unlock_failure` with `ActorUserID`, `Message:
  "bad_password"`.

**Side effects on success**:

- `Session.LastActivity` updated to now (lifts the idle state).
- Client-side idle timer is reset (the frontend triggers this on
  receiving the success response).

**Rate limit scope**: unlock failures count against the same
per-IP buckets as login failures. This prevents an attacker from
brute-forcing the password via the lock screen.

### 4.7 POST /api/v1/auth/heartbeat

Refreshes the session sliding TTL without performing any business
operation. Called by the frontend periodically (e.g., every 5
minutes while the tab is active) to keep the session alive during
long viewing sessions without mutations.

**Group**: hard-auth (must succeed only when the session is
actively used, not when idle)

**Request body**: empty.

**Response 204**: no body.

**Errors**:

| Status | Body                              | Trigger                            |
|--------|-----------------------------------|--------------------------------------|
| 401    | `{"error": "no active session"}`  | No cookie or session expired/missing |
| 403    | `{"error": "session locked"}`     | Session is in idle state             |

**Audit emitted**: none. Heartbeat is too frequent (~12 per hour
per active tab) to be useful in the audit log.

**Side effect**: `Session.LastActivity` updated to now (via the
hard-auth middleware's standard Touch call).

**Note**: this endpoint exists for symmetry with `/me`. The
difference is that `heartbeat` requires hard-auth and touches
`LastActivity`, while `/me` requires soft-auth and does not.
Frontend flow: poll `/me` to know the session state; call
`heartbeat` periodically to keep the session alive.

### 4.8 GET /api/v1/auth/sessions

Returns all sessions owned by the current authenticated user.

**Group**: hard-auth

**Request body**: none.

**Response 200**:

```json
{
  "sessions": [
    {
      "id": "Tj9k...",
      "issuedAt": "2026-05-15T08:00:00.000Z",
      "lastActivity": "2026-05-17T14:23:00.000Z",
      "expiresAt": "2026-05-18T14:23:00.000Z",
      "ip": "192.168.1.42",
      "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/...",
      "rememberMe": false,
      "isCurrent": true
    },
    {
      "id": "Mp2k...",
      "issuedAt": "2026-04-20T12:00:00.000Z",
      "lastActivity": "2026-05-16T18:00:00.000Z",
      "expiresAt": "2026-06-15T18:00:00.000Z",
      "ip": "10.0.0.5",
      "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5)...",
      "rememberMe": true,
      "isCurrent": false
    }
  ]
}
```

- `isCurrent`: `true` for exactly one session, the one matching the
  cookie of the current request. The frontend uses this to disable
  the "revoke" button on the current session (use `/logout` instead).
- Expired sessions are filtered out server-side before responding.

**Errors**:

| Status | Body                              | Trigger                            |
|--------|-----------------------------------|--------------------------------------|
| 401    | 401 standard                      | No session / expired                 |
| 403    | 403 standard                      | Session locked                       |

**Audit emitted**: none (read operation).

### 4.9 DELETE /api/v1/auth/sessions/{id}

Revokes (deletes) a specific session owned by the current user.

**Group**: hard-auth

**Request body**: none. The session ID is in the URL.

**Response 204**: no body.

**Errors**:

| Status | Body                                                              | Trigger                                                |
|--------|-------------------------------------------------------------------|--------------------------------------------------------|
| 400    | `{"error": "cannot revoke own current session; use /logout"}`     | Attempting to revoke the session matching the cookie   |
| 404    | `{"error": "session not found"}`                                  | Session does not exist OR belongs to another user      |

**Audit event emitted**: `session_revoked` with `ActorUserID`
(revoker), `TargetType: "session"`, `TargetID` (the revoked
session ID), `BeforeJSON` containing the revoked `Session`
struct.

**Security note**: returning 404 when the session belongs to
another user (rather than 403) prevents discovering which session
IDs belong to which users by trial.

### 4.9bis POST /api/v1/auth/me/password

Changes the authenticated user's password. Revokes all other active 
sessions of this user as a side effect.

**Group**: hard-auth

**Request body**:

```json
{
  "currentPassword": "old-password-15-or-more",
  "newPassword": "new-password-15-or-more"
}
```

- `currentPassword` (string, required): the user's current password, 
  verified before any change is applied.
- `newPassword` (string, required): the desired new password. Subject 
  to the same validation as creation (length 15..128, top-10k check, 
  HIBP best-effort).

**Response 204**: no body. The current session cookie remains valid; 
the user stays logged in on this device.

**Errors**:

| Status | Body                                                                       | Trigger                                          |
|--------|----------------------------------------------------------------------------|--------------------------------------------------|
| 400    | `{"error": "invalid JSON body"}`                                           | Body not valid JSON                              |
| 400    | `{"error": "currentPassword and newPassword are required"}`                | Missing required field                           |
| 400    | `{"error": "password must be at least 15 characters"}`                     | New password too short                           |
| 400    | `{"error": "password must be at most 128 characters"}`                     | New password too long                            |
| 400    | `{"error": "password is in the list of common compromised passwords"}`     | New password matches top-10k                     |
| 401    | `{"error": "current password is incorrect"}`                               | `currentPassword` verification failed            |
| 403    | `{"error": "session locked"}`                                              | Session is in idle state (hard-auth gate)        |
| 500    | `{"error": "internal error"}`                                              | Unexpected failure                               |

**Audit event emitted on success**: `password_changed` with 
`ActorUserID` set, `TargetType: "user"`, `TargetID` set to the same 
user ID. `BeforeJSON` and `AfterJSON` are both `null` (no diff is 
emitted since the only changed field is the password hash, which is 
forbidden in audit content per decision D3).

**Side effects on success**:

1. The user's `PasswordHash` is updated with the argon2id hash of 
   `newPassword`.
2. `User.HIBPCheckStatus` is reset to `"pending"`. The new password 
   will be re-verified against HIBP at the next successful login.
3. `User.PasswordCompromised` is reset to `false`.
4. `User.UpdatedAt` is refreshed.
5. **All other sessions of this user are revoked**. The current 
   session (the one whose cookie made this request) is preserved; 
   the user stays logged in on this device. Other devices (mobile, 
   another browser) are signed out at their next request 
   (which will return 401 since their session no longer exists).

**Rationale for multi-session revocation**: when a user changes their 
password, the most likely cause is that the previous password was 
compromised (HIBP banner, suspicion of theft, etc.). Revoking other 
sessions prevents an attacker who has already logged in elsewhere 
from continuing to operate undetected. The current session is 
spared so the user is not signed out of the device they just used 
to change the password.

**Rate limiting**: this endpoint is subject to the same per-IP rate 
limit as other authentication endpoints. A user repeatedly typing 
the wrong `currentPassword` will be blocked after the Tier 1 
threshold.

**Security note**: the `currentPassword` field is verified using 
`argon2id.ComparePasswordAndHash` (constant-time), preventing timing 
attacks. A `login_failure`-equivalent audit event is **not** emitted 
for incorrect `currentPassword` attempts (the user is already 
authenticated; a typo is not an authentication failure). The slog 
logger records the attempt at Info level for observability.

### 4.10 GET /api/v1/audit

Returns audit events matching the supplied filters, paginated.

**Group**: hard-auth

**Query parameters**:

| Param            | Type     | Description                                                              |
|------------------|----------|--------------------------------------------------------------------------|
| `actor_user_id`  | string   | Filter by actor user ID                                                  |
| `action`         | string   | Filter by exact action (e.g. `login_success`)                            |
| `target_type`    | string   | Filter by target type (`route`, `user`, `session`)                       |
| `target_id`      | string   | Filter by target ID                                                      |
| `from`           | RFC3339  | Include events with `Timestamp >= from`                                  |
| `to`             | RFC3339  | Include events with `Timestamp < to`                                     |
| `limit`          | integer  | Max events to return, default 50, max 200                                |
| `cursor`         | string   | Opaque pagination token from previous response                           |

Filters combine with AND semantics. Empty parameters are ignored.

**Response 200**:

```json
{
  "events": [
    {
      "id": "0190a3f8-7d3c-7234-9abc-def012345678",
      "timestamp": "2026-05-17T14:23:00.123Z",
      "actorUserId": "a3a6e27d-043b-425a-8e40-868bf1943de8",
      "actorUsernameSnapshot": "admin",
      "action": "route_created",
      "targetType": "route",
      "targetId": "f7b9c0d1-a234-5678-90ab-cdef12345678",
      "beforeJson": null,
      "afterJson": {"id":"f7b9c0d1-...","host":"api.local",...},
      "message": "",
      "ip": "192.168.1.42",
      "userAgent": "Mozilla/5.0 ..."
    }
  ],
  "nextCursor": "0190a3f8-7d3c-7234-9abc-def012345678"
}
```

- `nextCursor`: opaque token to pass to the next call. Empty string
  (or omitted) means no more events.
- Events are sorted by `timestamp` descending (most recent first).
- `beforeJson` and `afterJson` are returned as parsed JSON objects
  in the response (not as escaped strings), making the frontend's
  display logic trivial.

**Errors**:

| Status | Body                                                  | Trigger                          |
|--------|-------------------------------------------------------|----------------------------------|
| 400    | `{"error": "invalid 'from' timestamp"}`               | `from` not RFC3339               |
| 400    | `{"error": "invalid 'to' timestamp"}`                 | `to` not RFC3339                 |
| 400    | `{"error": "invalid 'limit' parameter"}`              | `limit` not integer or out of range |
| 400    | `{"error": "invalid cursor"}`                         | Cursor not a valid UUID v7       |
| 401    | 401 standard                                          | No session                       |
| 403    | 403 standard                                          | Session locked                   |

**Audit event emitted**: `audit_viewed` with `ActorUserID` set,
`Message` containing a compact representation of the filters
applied (e.g. `"action=login_failure&from=2026-05-01"`). This
allows an admin to see who is consulting the audit log and what
they searched for.

**Note**: in Phase 1 with a single admin, this self-audit may seem
redundant. It is included to be ready for Phase 2 (multi-user)
where it becomes meaningful for accountability.

### 4.11 Cookie attributes

The session cookie is named `arenet_session` and uses the following
attributes:

| Attribute  | Production value    | Dev mode value (`--dev`)         |
|------------|---------------------|----------------------------------|
| `HttpOnly` | yes                 | yes                              |
| `Secure`   | yes                 | **no** (HTTP allowed for local)  |
| `SameSite` | `Strict`            | `Strict`                         |
| `Path`     | `/`                 | `/`                              |
| `Max-Age`  | 86400 or 2592000    | 86400 or 2592000                 |
| `Domain`   | (not set)           | (not set)                        |

- `HttpOnly` prevents JavaScript access (XSS defense).
- `Secure` is **omitted** in `--dev` mode because Vite serves over
  HTTP locally. Setting `Secure` on HTTP would prevent the cookie
  from being sent, breaking dev.
- `SameSite=Strict` is the primary CSRF defense (decision D9).
  Browsers refuse to send the cookie on cross-site requests.
- `Path=/` makes the cookie available to all paths under the
  origin, including `/api/v1/auth/me` and `/api/v1/routes`.
- `Domain` is not set, restricting the cookie to the exact origin
  (no subdomain sharing). This is intentional defense against
  subdomain compromise.
- `Max-Age` is 86400 seconds (24h) for normal logins, or 2592000
  seconds (30d) when `rememberMe: true`. The browser also enforces
  expiry; the server enforces sliding TTL via the `expiresAt`
  field in the session.

CORS in dev mode (decision implicit in Step C extension) adds:

```text
Access-Control-Allow-Credentials: true
```

This is **required** for the browser to send cookies on
cross-origin requests (Vite at `:5173` → API at `:8001`). The
Step C `devCORS` middleware will be updated in Section 5 to
include this header.

### 4.12 Error envelope convention

All error responses use the single-key envelope:

```json
{"error": "human-readable message"}
```

Rules:

- **One error per response**, never an array. If a request triggers
  multiple validation failures, the first failure encountered wins
  and is returned. This matches Step C's existing pattern and
  simplifies the frontend display logic.
- **Messages in English** at the API boundary. The frontend may
  translate for display (Step D ships English-only UI; localization
  is out of scope).
- **No internal details exposed**. Stack traces, file paths, SQL
  fragments, and database error messages are never included. The
  detailed error is logged via slog at the appropriate level (Error
  for unexpected failures, Warn for recoverable, Info for expected).
- **Status code is authoritative**. The frontend dispatches on the
  HTTP status; the message is for human display only.

Status code semantics (consistent across all Step D endpoints):

| Code | Meaning                                                                       |
|------|-------------------------------------------------------------------------------|
| 200  | Success with response body                                                    |
| 201  | Resource created with response body                                           |
| 204  | Success with no response body                                                 |
| 400  | Validation error in request (client should fix and retry)                     |
| 401  | Authentication required or invalid credentials (frontend → `/login`)          |
| 403  | Authenticated but forbidden, including session locked (frontend → lock screen)|
| 404  | Resource not found, including disambiguating cases (e.g. own session check)   |
| 409  | Conflict (existing Step C convention for uniqueness)                          |
| 429  | Rate limit exceeded, includes `Retry-After` header                            |
| 500  | Unexpected server error                                                       |
| 503  | Service temporarily unavailable (storage unreachable, decision D11)           |

### 4.13 Audit event wire format

The `Event` struct (Section 3.4) uses snake_case JSON tags for
storage. The API layer transforms these into camelCase for the
wire format consumed by the frontend, consistent with Step C's
`routeResponse` pattern.

Snake_case storage → camelCase wire mapping:

| Storage field              | Wire field                |
|----------------------------|---------------------------|
| `id`                       | `id`                      |
| `timestamp`                | `timestamp`               |
| `actor_user_id`            | `actorUserId`             |
| `actor_username_snapshot`  | `actorUsernameSnapshot`   |
| `action`                   | `action`                  |
| `target_type`              | `targetType`              |
| `target_id`                | `targetId`                |
| `before_json`              | `beforeJson`              |
| `after_json`               | `afterJson`               |
| `message`                  | `message`                 |
| `ip`                       | `ip`                      |
| `user_agent`               | `userAgent`               |

`beforeJson` and `afterJson` are returned as **parsed JSON
objects** in the wire format, not as escaped JSON strings. This
makes the frontend's display logic trivial (no need to
double-parse). The transformation happens in the API handler
via `json.RawMessage` → `interface{}` decoding before re-encoding
the response.

All Phase 1 fields are exposed unconditionally. Phase 2 may
introduce role-based field filtering (e.g. an `editor` role may
not see `ip` of other users' events), but this is deferred per
decision D10.

---

End of Section 4. The middleware behavior, context propagation,
and request-flow details are specified in Section 5.

## 5. Middleware chain

This section specifies the middleware layers that protect the API. It
covers the ordering inside chi, the three authentication gates
(no-auth, soft-auth, hard-auth), the rate limiter, the IP extraction
logic, the context propagation contract, and the modifications to
Step C's CORS middleware.

### 5.1 Overview

Step D introduces three authentication gates, each with different
strictness:

- **no-auth** allows requests without a session cookie. Used by
  `/setup` and `/login` (the user has not authenticated yet, by
  definition).

- **soft-auth** requires a valid session cookie but allows the
  session to be in the idle state. Used by `/logout` (we want to
  cleanly terminate an idle session), `/me` (the lock screen needs
  the username), and `/unlock` (idle is the precondition).

- **hard-auth** requires a valid session cookie AND that the session
  is not idle (i.e., `LastActivity` is within the past 15 minutes).
  Used by all business endpoints (routes, audit, sessions
  management).

The need for three gates instead of two comes from a UX requirement:
when an admin's session goes idle, we want to lock the UI (require
password re-entry) without forcing a full re-login. The lock screen
must be able to display the admin's username, which requires reading
the session. So `/me` cannot be hard-auth (it would return 403 when
idle, defeating the purpose) but cannot be no-auth either (it would
leak info to unauthenticated callers).

The router orchestrates these gates via three chi groups. Cross-cutting
middlewares (logging, panic recovery, CORS, rate limit) wrap all of
them. See 5.2.

### 5.2 Middleware ordering in the router

The full middleware stack, executed in order on every request to
`/api/v1/*`:

```go
r := chi.NewRouter()

// Outermost: request identification, structured logging, panic recovery.
// These apply to every request, regardless of authentication group.
r.Use(middleware.RequestID)              // chi built-in: adds X-Request-ID
r.Use(slogLogger(logger))                // Step C: structured access log
r.Use(middleware.Recoverer)              // chi built-in: catches panics

// Dev-only: cross-origin support for Vite at :5173.
if devMode {
    r.Use(devCORS("http://localhost:5173"))  // Step C, modified in 5.10
}

r.Route("/api/v1", func(r chi.Router) {

    // Auth endpoints: rate-limited.
    r.Route("/auth", func(r chi.Router) {
        r.Use(rateLimit(rateLimiter))    // NEW (5.3): per-IP failure counters

        // No-auth subgroup: /setup, /login.
        r.Post("/setup", h.setup)
        r.Post("/login", h.login)

        // Soft-auth subgroup: /logout, /me, /unlock.
        r.Group(func(r chi.Router) {
            r.Use(auth.SoftAuthMiddleware(sessionStore, userStore))  // NEW (5.6)
            r.Post("/logout", h.logout)
            r.Get("/me", h.me)
            r.Post("/unlock", h.unlock)
        })

        // Hard-auth subgroup: /heartbeat, /sessions, DELETE /sessions/{id}.
        r.Group(func(r chi.Router) {
            r.Use(auth.HardAuthMiddleware(sessionStore, userStore))  // NEW (5.7)
            r.Post("/heartbeat", h.heartbeat)
            r.Get("/sessions", h.listSessions)
            r.Delete("/sessions/{id}", h.deleteSession)
        })
    })

    // Business endpoints: hard-auth, no rate limit (authenticated callers
    // are trusted to not flood; the workload is naturally bounded by UI use).
    r.Group(func(r chi.Router) {
        r.Use(auth.HardAuthMiddleware(sessionStore, userStore))
        r.Get("/routes", h.listRoutes)
        r.Post("/routes", h.createRoute)
        r.Get("/routes/{id}", h.getRoute)
        r.Put("/routes/{id}", h.updateRoute)
        r.Delete("/routes/{id}", h.deleteRoute)
        r.Get("/audit", h.listAudit)
    })
})
```

The ordering rationale:

- **`RequestID` first** so that every subsequent log entry has the
  same correlation ID. The handler can pull it via
  `chimw.GetReqID(r.Context())` for inclusion in audit events and
  error responses.

- **`slogLogger` second** so it observes the final HTTP status set by
  any subsequent middleware (including 401 from auth middleware) and
  any panic recovered by `Recoverer`.

- **`Recoverer` third** so panics from handlers or auth middleware
  produce a 500 response and a structured log entry instead of
  terminating the process. (Step C convention preserved.)

- **`devCORS` fourth**, before any auth gate, so that preflight
  OPTIONS requests succeed without authentication. Browsers send
  preflight without cookies; failing them at the auth layer would
  break dev.

- **`rateLimit` fifth**, scoped only to `/api/v1/auth/*`. Applying
  it to authenticated business endpoints would risk locking out an
  active admin during heavy UI use (e.g., bulk operations).

- **Auth middleware (soft or hard) sixth**, scoped to specific
  subgroups. Endpoints requiring different gates live in separate
  `r.Group` blocks so each gets only the middleware it needs.

### 5.3 Rate limit middleware (per-IP)

The `rateLimit` middleware enforces decision Q6 + D8: per-IP failure
counters in two tiers, in-memory only.

**Scope**: applies only to routes mounted under `/api/v1/auth/*`. It
counts failures (HTTP 401, 403 from auth-related causes) and blocks
the source IP when thresholds are exceeded. It does **not** count
successes — a frequent legitimate user never hits the limit.

**Tiers**:

- **Tier 1**: 5 authentication failures from the same IP within 5
  minutes → block that IP for 15 minutes. Designed to catch typical
  brute-force scripts that try a handful of common passwords.

- **Tier 2**: 10 authentication failures from the same IP within 1
  hour → block that IP for 1 hour. Designed to catch slower
  distributed attacks that pace themselves under Tier 1.

Both tiers operate concurrently. A single failure increments both
counters; whichever threshold is hit first triggers the corresponding
block. The longer block wins if both fire.

**HTTP behavior**:

- On block, the middleware returns 429 with:
  - Body: `{"error": "too many attempts, retry after 15 minutes"}`
    (or 1 hour for Tier 2).
  - Header: `Retry-After: <seconds-until-unblock>`.

**Reset on success**:

- A successful `/login` or `/unlock` clears the failure counters for
  the calling IP. This prevents legitimate users who typo their
  password a few times from being penalized after they finally
  succeed.

- `setup` does not reset the counter (the counter is essentially
  unused before any user exists; the setup endpoint itself is rate-
  limited identically).

**Logging**:

- Every Tier 2 hit emits a structured `slog.Warn` entry:

```go
logger.Warn("rate limit tier 2 triggered, IP blocked",
    slog.String("ip", clientIP),
    slog.String("username_attempted", attemptedUsername),
    slog.Int("failure_count_window", 10),
    slog.Time("blocked_until", until),
    slog.String("suggestion", "consider blocking this IP at network level"),
)
```

This is the primary observability hook for operators to detect
attacks and configure their upstream firewall (FortiGate, OPNsense,
Unifi). A future Step F (see `docs/roadmap.md`) will surface this
data in a Security UI page with optional webhook forwarding.

**Storage**:

In-memory only, per decision D8. The state is a
`map[string]*counter` protected by a `sync.Mutex`, where `counter`
holds a sliding window of recent failure timestamps and the current
block expiry. A goroutine launched at server startup garbage-collects
entries that have been inactive for 2 hours (no failures, no block
active), bounding memory growth.

The internal method `GetBlockedIPs() []BlockedIP` is exposed for
future consumption by Step F's Security UI. It is **not** exposed via
HTTP in Step D.

### 5.4 IP extraction middleware

Correctly identifying the source IP of a request is essential for
rate limiting and audit logging. When Arenet runs behind a reverse
proxy (Cloudflare, Caddy on a front host, nginx, etc.),
`r.RemoteAddr` returns the proxy's IP, not the client's. Conversely,
trusting `X-Forwarded-For` blindly allows any client to forge their
source IP.

**Configuration**:

The `ARENET_TRUSTED_PROXIES` environment variable holds a
comma-separated list of CIDR ranges considered trusted. Example:

```text
ARENET_TRUSTED_PROXIES=10.0.0.0/8,192.168.0.0/16,2001:db8::/32
```

Empty or unset → no proxy is trusted. `RemoteAddr` is used directly.

**Logic** (applied early in the request lifecycle, before
`rateLimit` and auth middleware):

1. Parse `r.RemoteAddr` → IP.
2. If the parsed IP is **not** within any trusted CIDR → use it
   as the client IP. `X-Forwarded-For` is ignored.
3. If the parsed IP **is** within a trusted CIDR → read
   `X-Forwarded-For`. Take the **leftmost** entry (the original
   client per RFC 7239). Validate it is a parseable IP. If
   parsing fails, fall back to `r.RemoteAddr`.
4. Store the resolved IP in the request context under
   `auth.ClientIPKey`.

**Implementation detail**: a small package-level function
`auth.ClientIPFromContext(ctx) string` exposes the value to handlers
and other middleware (rate limit, audit helper).

**Edge cases**:

- **Multiple `X-Forwarded-For` headers**: chi reads all of them as a
  single comma-separated string. The leftmost token is the original
  client.
- **IPv6 in `X-Forwarded-For`**: parsed correctly by `net.ParseIP`.
  No special handling.
- **Malformed `X-Forwarded-For`**: falls back to `RemoteAddr`
  without erroring out the request. A `slog.Debug` line records the
  malformed value for troubleshooting.
- **`r.RemoteAddr` includes a port** (`192.168.1.42:54321`): the
  middleware strips the port before checking CIDR membership.

**Note**: this middleware is mounted near the top of the chain, just
after `Recoverer`. Both `rateLimit` and the auth middlewares read
the client IP from context, not from `r.RemoteAddr` directly. This
ensures all components see the same authoritative value.

### 5.5 No-auth middleware

There is no dedicated middleware for the no-auth group. The endpoints
in this group (`/setup`, `/login`) have specific preconditions that
they check inline:

- `/setup` checks that the `users` bucket is empty. If not, returns
  404 (see 4.2). The `setupToken` is checked against the in-memory
  current value generated at startup.

- `/login` performs the username/password check. No middleware needed
  beyond what is already in the stack (rate limit, logging, etc.).

These endpoints are mounted directly under `r.Route("/auth", ...)`
without any additional middleware group. The rate limit middleware
applies because it's mounted at the `/auth` route level.

### 5.6 Soft-auth middleware

The soft-auth middleware enforces: cookie present AND session valid
AND session not expired (absolute 24h/30d TTL). It does NOT enforce
the 15-minute idle window.

```go
package auth

import (
    "context"
    "net/http"
    "errors"
)

// SoftAuthMiddleware returns a chi-compatible middleware that
// validates the session cookie and populates the request context
// with user identity. It allows idle sessions (LastActivity outside
// the 15-min window) so that the lock screen flow can function.
//
// On failure, responds with HTTP 401 and clears the session cookie.
// On success, calls the next handler with the enriched context.
//
// The middleware does NOT call sessionStore.Touch() — that would
// reset the idle timer on every /me call and make the lock screen
// unreachable. Touch is the hard-auth middleware's responsibility.
func SoftAuthMiddleware(sessions SessionStore, users UserStore) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            cookie, err := r.Cookie("arenet_session")
            if err != nil {
                writeAuthError(w, "no active session")
                return
            }

            session, err := sessions.Get(r.Context(), cookie.Value)
            if err != nil {
                // Both ErrSessionNotFound and ErrSessionExpired map to 401.
                // The Set-Cookie header tells the browser to drop the stale cookie.
                clearSessionCookie(w)
                writeAuthError(w, "no active session")
                return
            }

            user, err := users.GetByID(r.Context(), session.UserID)
            if err != nil {
                if errors.Is(err, ErrUserNotFound) {
                    // Session references a deleted user. Clean up and 401.
                    _ = sessions.Delete(r.Context(), session.ID)
                    clearSessionCookie(w)
                    writeAuthError(w, "no active session")
                    return
                }
                // Storage error (decision D11): 503.
                writeServiceUnavailable(w, "authentication service temporarily unavailable")
                return
            }

            // Compute is_locked once here for downstream consumers.
            isLocked := time.Since(session.LastActivity) > 15*time.Minute

            ctx := r.Context()
            ctx = context.WithValue(ctx, UserIDKey, user.ID)
            ctx = context.WithValue(ctx, UsernameKey, user.Username)
            ctx = context.WithValue(ctx, SessionIDKey, session.ID)
            ctx = context.WithValue(ctx, IsLockedKey, isLocked)

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

Behavioral summary:

| Condition                                  | Outcome                                       |
|--------------------------------------------|-----------------------------------------------|
| No `arenet_session` cookie                 | 401 "no active session"                       |
| Cookie present, session not found          | 401 + clear cookie                            |
| Cookie present, session expired            | 401 + clear cookie + lazy purge of session    |
| Cookie present, session valid, user gone   | 401 + clear cookie + delete orphan session    |
| Cookie present, session valid, user OK     | Pass through with context populated           |
| Storage error (DB unreachable)             | 503 "authentication service unavailable"      |

The middleware populates four context keys for downstream consumers:
`UserIDKey`, `UsernameKey`, `SessionIDKey`, `IsLockedKey`. The
`IsLockedKey` value is read by `/me` to populate the `locked` field
of its response (see 4.5).

### 5.7 Hard-auth middleware

The hard-auth middleware builds on soft-auth by adding the idle
check and the `Touch` call.

```go
// HardAuthMiddleware returns a chi-compatible middleware that
// validates the session and refuses idle sessions.
//
// On success, updates Session.LastActivity (best-effort) so that
// active use of authenticated endpoints keeps the session alive
// without explicit /heartbeat calls.
func HardAuthMiddleware(sessions SessionStore, users UserStore) func(http.Handler) http.Handler {
    softAuth := SoftAuthMiddleware(sessions, users)
    return func(next http.Handler) http.Handler {
        return softAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Soft-auth already populated the context. Check is_locked.
            if locked, _ := r.Context().Value(IsLockedKey).(bool); locked {
                writeForbidden(w, "session locked")
                return
            }

            sessionID, _ := r.Context().Value(SessionIDKey).(string)

            // Best-effort: refresh LastActivity. Failure logs but doesn't fail the request.
            if err := sessions.Touch(r.Context(), sessionID); err != nil {
                slog.Default().Warn("session touch failed",
                    slog.String("err", err.Error()),
                    slog.String("session_id", sessionID),
                )
            }

            next.ServeHTTP(w, r)
        }))
    }
}
```

Behavioral summary:

| Condition                                            | Outcome                              |
|------------------------------------------------------|--------------------------------------|
| Any soft-auth failure                                | Soft-auth response (401 or 503)      |
| Session valid but idle (LastActivity + 15min < now)  | 403 "session locked"                 |
| Session valid and active                             | Touch (best-effort) + pass to handler|

Composition rationale: hard-auth wraps soft-auth rather than
duplicating its logic. This guarantees consistency between the two —
any change to the session lookup logic happens in one place.

The `Touch` call is **after** the idle check, not before. If we
touched first, a stale check could refresh `LastActivity` for an idle
session that we are about to reject. The correct sequence is: check
freshness → reject if stale → otherwise refresh.

### 5.8 Context propagation

Auth-related values propagate through the request context via
type-safe accessors in `internal/auth`:

```go
package auth

type ctxKey string

const (
    UserIDKey    ctxKey = "auth.user_id"
    UsernameKey  ctxKey = "auth.username"
    SessionIDKey ctxKey = "auth.session_id"
    IsLockedKey  ctxKey = "auth.is_locked"
    ClientIPKey  ctxKey = "auth.client_ip"
)

// UserIDFromContext returns the authenticated user's ID, or empty
// string if the request is not authenticated.
func UserIDFromContext(ctx context.Context) string {
    v, _ := ctx.Value(UserIDKey).(string)
    return v
}

// UsernameFromContext returns the authenticated user's username.
func UsernameFromContext(ctx context.Context) string {
    v, _ := ctx.Value(UsernameKey).(string)
    return v
}

// SessionIDFromContext returns the current session ID.
func SessionIDFromContext(ctx context.Context) string {
    v, _ := ctx.Value(SessionIDKey).(string)
    return v
}

// IsLockedFromContext returns true if the session is in the idle
// lock state (only meaningful within soft-auth handlers).
func IsLockedFromContext(ctx context.Context) bool {
    v, _ := ctx.Value(IsLockedKey).(bool)
    return v
}

// ClientIPFromContext returns the resolved client IP (X-Forwarded-For
// aware, see 5.4).
func ClientIPFromContext(ctx context.Context) string {
    v, _ := ctx.Value(ClientIPKey).(string)
    return v
}
```

Convention: handlers use these accessors, never
`r.Context().Value(...)` directly. The accessors:

- Provide type safety (no `interface{}` cast at the call site).
- Return zero-value (empty string, false) instead of panicking on
  missing keys, simplifying handler logic.
- Localize all knowledge of the context keys in the `auth` package.

Using `ctxKey` as the key type (instead of plain string) prevents
accidental collision with other packages' context keys, per Go's
standard library guidance.

### 5.9 Audit context enrichment

The `appendAudit` helper (introduced in 4 and implemented in
`internal/api/audit_helpers.go`) pulls all contextual fields from
the request before delegating to `audit.Store.Append`:

```go
package api

import (
    "encoding/json"
    "net/http"
    "github.com/barto95100/arenet/internal/audit"
    "github.com/barto95100/arenet/internal/auth"
)

// appendAudit emits an audit event with context enrichment.
// Best-effort: failure logged via slog.Warn but does not affect
// the HTTP response.
//
// The caller fills evt.Action, evt.TargetType, evt.TargetID,
// evt.BeforeJSON, evt.AfterJSON, evt.Message. The helper fills:
//   - evt.ActorUserID and evt.ActorUsernameSnapshot from context
//   - evt.IP from context (X-Forwarded-For aware, see 5.4)
//   - evt.UserAgent from r.Header
// ID and Timestamp are filled by audit.Store.Append via uuid.NewV7.
func (h *Handler) appendAudit(r *http.Request, evt audit.Event) {
    ctx := r.Context()
    evt.ActorUserID = auth.UserIDFromContext(ctx)
    evt.ActorUsernameSnapshot = auth.UsernameFromContext(ctx)
    evt.IP = auth.ClientIPFromContext(ctx)
    evt.UserAgent = r.UserAgent()

    if err := h.audit.Append(ctx, evt); err != nil {
        h.logger.Warn("audit append failed",
            "err", err.Error(),
            "action", evt.Action,
            "target_id", evt.TargetID,
        )
    }
}

// mustMarshalForAudit serializes a value to JSON for inclusion in
// audit event Before/After fields. Returns nil on marshal error;
// the event is still emitted, just without the diff.
//
// Callers MUST strip sensitive fields (PasswordHash on User,
// session tokens, etc.) before passing the value here.
func mustMarshalForAudit(v any) json.RawMessage {
    raw, err := json.Marshal(v)
    if err != nil {
        return nil
    }
    return raw
}
```

Usage pattern in handlers (this is how 4.2-4.10's audit lines
materialize):

```go
// Inside h.createRoute after successful Caddy reload:
h.appendAudit(r, audit.Event{
    Action:     audit.ActionRouteCreated,
    TargetType: "route",
    TargetID:   created.ID,
    AfterJSON:  mustMarshalForAudit(created),
})
```

The helper is intentionally non-fatal. Audit emission failures are
observability concerns, not request-flow concerns. A failed audit
emit logs at Warn level and the operator can investigate; the
business operation has already succeeded by this point and reporting
its success to the client takes priority.

### 5.10 CORS in dev mode (modified)

Step C's `devCORS` middleware allowed cross-origin requests from
Vite at `:5173` for the standard methods. Step D requires one
addition: `Access-Control-Allow-Credentials: true`. Without this
header, browsers refuse to send cookies on cross-origin requests,
breaking the entire authentication flow in dev mode.

The modified middleware:

```go
// devCORS allows preflight + simple requests from allowOrigin, with
// credentials. Only mounted in dev mode by NewRouter.
//
// Step D modification: Access-Control-Allow-Credentials is now set
// so that the browser sends the arenet_session cookie on cross-origin
// requests from Vite (:5173) to the API (:8001).
func devCORS(allowOrigin string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
            w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
            w.Header().Set("Access-Control-Allow-Credentials", "true")    // NEW (Step D)
            w.Header().Set("Access-Control-Max-Age", "3600")
            if r.Method == http.MethodOptions {
                w.WriteHeader(http.StatusNoContent)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

Frontend correspondance: every `fetch` call in `web/frontend/src/lib/api/client.ts`
must include `credentials: 'include'`. Without this option, the
browser does not attach the cookie on cross-origin requests even if
the server allows it. Step C's client.ts will be updated accordingly
in Section 6.

Production note: in production mode (no `--dev` flag), `devCORS` is
not mounted at all. The frontend is served from the same origin as
the API (via `//go:embed`), so cookies are sent natively without
any CORS gymnastics. The `Access-Control-Allow-Credentials` addition
is purely a dev-mode concern.

## 6. Frontend integration

This section specifies the Svelte 5 / SvelteKit 2 changes required to
integrate authentication and audit into the existing Step C admin UI.
It covers the new pages, the new component, the two new stores, the
two new API client modules, and the modifications to the existing
layout shell and HTTP client.

### 6.1 Overview

Step D introduces the following frontend artifacts:

**New pages** (under `web/frontend/src/routes/`):
- `/login` — username/password form
- `/setup` — first-boot admin creation form
- `/audit` — audit log explorer with filters

**New component** (under `web/frontend/src/lib/components/`):
- `LockScreen.svelte` — full-screen overlay for idle session re-auth

**New modal** (reuses Step C `Modal` primitive):
- `ChangePasswordModal.svelte` — invoked from the compromised-password
  banner

**New stores** (under `web/frontend/src/lib/stores/`):
- `auth.ts` — current user identity and authentication state
- `idle.ts` — client-side 15-minute inactivity timer

**New API client modules** (under `web/frontend/src/lib/api/`):
- `auth.ts` — typed wrappers for `/api/v1/auth/*`
- `audit.ts` — typed wrappers for `/api/v1/audit`

**Modified files**:
- `web/frontend/src/lib/api/client.ts` — credentials, 401/403
  interceptors, idle timer reset
- `web/frontend/src/routes/+layout.svelte` — auth bootstrap gate,
  heartbeat, LockScreen mount, compromised-password banner
- `web/frontend/src/lib/components/Sidebar.svelte` — fifth nav item
  for `/audit`

**Application states**: the layout shell distinguishes four states
of the application, driven by the auth store:

| State           | Cause                                              | UI behavior                             |
|-----------------|----------------------------------------------------|-----------------------------------------|
| `unknown`       | Initial state before bootstrap completes           | Centered spinner, no chrome             |
| `anonymous`     | No session, or session lookup failed (401)         | Redirect to `/login` (which links to `/setup`) |
| `authenticated` | Valid session, not idle                            | Normal layout (sidebar + main)          |
| `locked`        | Valid session but idle >15 min, OR 403 from server | Normal layout + LockScreen overlay      |

State transitions:

- `unknown → authenticated`: bootstrap `/me` succeeds with `locked: false`
- `unknown → locked`: bootstrap `/me` succeeds with `locked: true`
- `unknown → anonymous`: bootstrap `/me` returns 401
- `authenticated → locked`: client idle timer fires OR a request returns 403
- `locked → authenticated`: successful `/unlock` call
- `* → anonymous`: any request returns 401, or explicit `logout()`

The bootstrap call happens once at layout mount. Subsequent state
changes happen via the API client interceptors and the idle timer.

### 6.2 Auth store (`lib/stores/auth.ts`)

The auth store holds the current user identity and authentication
state, exposed as Svelte 5 runes (`$state`) for fine-grained reactivity.

```ts
// web/frontend/src/lib/stores/auth.ts
import type { User } from '$lib/api/auth';

export type AuthState = 'unknown' | 'anonymous' | 'authenticated' | 'locked';

class AuthStore {
    user = $state<User | null>(null);
    state = $state<AuthState>('unknown');
    isBootstrapping = $state(false);

    async bootstrap(): Promise<void> {
        this.isBootstrapping = true;
        try {
            const me = await authApi.me();
            this.user = me;
            this.state = me.locked ? 'locked' : 'authenticated';
        } catch (err) {
            if (err instanceof ApiError && err.status === 401) {
                this.state = 'anonymous';
                this.user = null;
            } else {
                // Network or 5xx error — leave state as 'unknown' so the
                // layout shows the spinner. The user can refresh.
                console.error('auth bootstrap failed:', err);
            }
        } finally {
            this.isBootstrapping = false;
        }
    }

    async login(username: string, password: string, rememberMe: boolean): Promise<void> {
        const user = await authApi.login(username, password, rememberMe);
        this.user = user;
        this.state = 'authenticated';
    }

    async logout(): Promise<void> {
        try {
            await authApi.logout();
        } catch (err) {
            // Even if the server fails, clear local state.
            console.warn('logout request failed (clearing local state anyway):', err);
        }
        this.user = null;
        this.state = 'anonymous';
    }

    async unlock(password: string): Promise<void> {
        await authApi.unlock(password);
        this.state = 'authenticated';
        // The user object is still valid; only the state changes.
    }

    setLocked(): void {
        if (this.state === 'authenticated') {
            this.state = 'locked';
        }
    }

    clear(): void {
        this.user = null;
        this.state = 'anonymous';
    }
}

export const auth = new AuthStore();
```

Design notes:

- The store is a **singleton class instance** rather than a function
  returning runes. Svelte 5's runes work in classes, and the singleton
  pattern matches Step C's `toast.ts` and `loading.ts` stores.

- The `unknown` state is critical: it signals that bootstrap has not
  yet completed. The layout shell displays a centered spinner during
  `unknown` to avoid flashing the login page for half a second before
  the bootstrap completes.

- The `bootstrap()` method is intentionally tolerant: a network
  failure leaves the state as `unknown`, allowing the user to refresh
  rather than being kicked to login on a transient connectivity
  glitch.

- `setLocked()` is idempotent and only transitions from
  `authenticated`. Trying to lock from `anonymous` or `unknown` is a
  no-op, preventing race conditions during page transitions.

- `clear()` is called by the API client's 401 interceptor (see 6.4).

### 6.3 Idle store (`lib/stores/idle.ts`)

The idle store implements the client-side counterpart of the 15-minute
inactivity check. Its purpose is to trigger the lock screen client-side
**before** the next API request gets a 403, providing immediate UX
feedback.

```ts
// web/frontend/src/lib/stores/idle.ts
import { auth } from './auth';

const IDLE_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

class IdleStore {
    private timerId: ReturnType<typeof setTimeout> | null = null;
    private lastReset = $state(Date.now());

    start(): void {
        this.reset();
        document.addEventListener('visibilitychange', this.onVisibilityChange);
    }

    stop(): void {
        if (this.timerId !== null) {
            clearTimeout(this.timerId);
            this.timerId = null;
        }
        document.removeEventListener('visibilitychange', this.onVisibilityChange);
    }

    /**
     * Reset the idle timer. Called by the API client on every successful
     * server interaction (decision: activity = server action only, not
     * mouse/keyboard).
     */
    reset(): void {
        if (auth.state !== 'authenticated') {
            return; // No point timing an unauthenticated or already-locked session.
        }
        this.lastReset = Date.now();
        if (this.timerId !== null) {
            clearTimeout(this.timerId);
        }
        this.timerId = setTimeout(() => {
            auth.setLocked();
            this.timerId = null;
        }, IDLE_TIMEOUT_MS);
    }

    private onVisibilityChange = (): void => {
        if (document.visibilityState === 'hidden') {
            // Tab hidden — keep the existing timer running but don't start
            // new ones. When the user returns, if the timer fired in the
            // meantime, they are already in locked state.
        }
        // No special handling on visible: the next API call will reset
        // the timer naturally if the session is still authenticated.
    };
}

export const idle = new IdleStore();
```

Design notes:

- **Activity definition**: per decision Q3bis, "activity" means a
  server API call, not mouse moves or keyboard events. The idle
  store does not listen for `mousemove` / `keydown` — those are
  unreliable (an automated tool moving the cursor would defeat the
  lock) and noisy.

- **Defense in depth**: the client timer is the UX layer. The server's
  `LastActivity` check (in hard-auth middleware) is the security
  layer. If a user disables JavaScript or tampers with the timer,
  the server still enforces the lock at the next API call.

- **Tab hidden behavior**: the timer continues running when the tab
  is hidden (we don't pause it). This matches the user's intuition:
  if they leave the tab open in the background for 30 minutes, they
  expect to find it locked when they return. Pausing the timer
  during hidden tabs would defeat the purpose.

- **No timer on `locked` or `anonymous`**: the `reset()` method
  short-circuits when the auth state is not `authenticated`. This
  prevents wasted timers and accidental transitions out of locked
  state.

### 6.4 API client modifications (`lib/api/client.ts`)

The Step C `client.ts` is modified to:

1. Include cookies on every request (`credentials: 'include'`).
2. Intercept 401, 403, and 429 responses and dispatch to the
   appropriate store action.
3. Reset the idle timer on every successful response.

```ts
// web/frontend/src/lib/api/client.ts (modified)
import { auth } from '$lib/stores/auth';
import { idle } from '$lib/stores/idle';
import { toast } from '$lib/stores/toast';
import { goto } from '$app/navigation';

export class ApiError extends Error {
    constructor(
        public kind: 'validation' | 'system' | 'auth' | 'forbidden' | 'rate_limited',
        public status: number,
        public message: string,
        public retryAfterSeconds?: number,
    ) {
        super(message);
    }
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const url = `${import.meta.env.VITE_API_BASE_URL || ''}${path}`;
    let response: Response;
    try {
        response = await fetch(url, {
            ...init,
            credentials: 'include', // NEW: send arenet_session cookie cross-origin
            headers: {
                'Content-Type': 'application/json',
                ...init.headers,
            },
        });
    } catch (err) {
        // Network error
        throw new ApiError('system', 0, 'network error: ' + (err as Error).message);
    }

    // Handle authentication-related statuses BEFORE attempting to parse the body.
    if (response.status === 401) {
        auth.clear();
        // Avoid redirect loops: only navigate if we're not already on /login or /setup.
        const here = window.location.pathname;
        if (here !== '/login' && here !== '/setup') {
            goto('/login');
        }
        throw new ApiError('auth', 401, 'authentication required');
    }

    if (response.status === 403) {
        // Distinguish "session locked" (the only 403 in Step D) from future
        // role-based 403s by checking the error message body.
        const body = await response.json().catch(() => ({ error: 'forbidden' }));
        if (body.error === 'session locked') {
            auth.setLocked();
            throw new ApiError('forbidden', 403, 'session locked');
        }
        throw new ApiError('forbidden', 403, body.error || 'forbidden');
    }

    if (response.status === 429) {
        const retryAfter = parseInt(response.headers.get('Retry-After') || '0', 10);
        const body = await response.json().catch(() => ({ error: 'rate limited' }));
        toast.push({ kind: 'error', message: body.error || 'rate limited' });
        throw new ApiError('rate_limited', 429, body.error, retryAfter);
    }

    // Reset idle timer on any successful response (including 4xx that are
    // not auth/rate-limit-related, since those still constitute server
    // interaction). 5xx and network errors do not reset the timer.
    if (response.status < 500) {
        idle.reset();
    }

    if (response.status >= 400 && response.status < 500) {
        const body = await response.json().catch(() => ({ error: 'unknown error' }));
        throw new ApiError('validation', response.status, body.error || 'validation failed');
    }

    if (response.status >= 500) {
        const body = await response.json().catch(() => ({ error: 'internal error' }));
        throw new ApiError('system', response.status, body.error || 'server error');
    }

    if (response.status === 204) {
        return undefined as T;
    }

    return response.json();
}
```

Design notes:

- **`credentials: 'include'` on every request**: required for the
  browser to attach the `arenet_session` cookie on cross-origin
  requests (dev mode: Vite at `:5173` → API at `:8001`). In
  production same-origin, this option is a no-op.

- **401 handling**: the interceptor clears the auth store and
  navigates to `/login`. The `here !== '/login'` guard prevents an
  infinite redirect loop if `/login` itself somehow returns 401
  (e.g., during the very first bootstrap when there's no session).

- **403 disambiguation**: Step D has exactly one cause for 403
  (`session locked`). The interceptor matches the error message to
  decide between "lock screen" and "generic forbidden". Phase 2
  will introduce role-based 403s (`editor cannot delete users`);
  those will be distinguished here.

- **429 toast**: rate-limit responses surface a toast immediately.
  The login form also displays an inline error (since the request
  came from there), making the rate limit doubly visible.

- **Idle reset gate**: any response with status `< 500` resets the
  idle timer. 5xx responses are excluded because a server hiccup
  should not artificially extend the session. Network errors (no
  response at all) likewise don't reset.

### 6.5 Auth API client (`lib/api/auth.ts`)

Type-safe wrappers for the auth endpoints. Mirrors the wire
shapes from Section 4.

```ts
// web/frontend/src/lib/api/auth.ts
import { request } from './client';

export interface User {
    id: string;
    username: string;
    displayName: string;
    locked: boolean;
    passwordCompromised: boolean;
    hibpCheckStatus: 'pending' | 'clean' | 'compromised' | 'skipped';
}

export interface Session {
    id: string;
    issuedAt: string;
    lastActivity: string;
    expiresAt: string;
    ip: string;
    userAgent: string;
    rememberMe: boolean;
    isCurrent: boolean;
}

export const authApi = {
    setup(setupToken: string, username: string, displayName: string, password: string): Promise<User> {
        return request<User>('/api/v1/auth/setup', {
            method: 'POST',
            body: JSON.stringify({ setupToken, username, displayName, password }),
        });
    },

    login(username: string, password: string, rememberMe: boolean): Promise<User> {
        return request<User>('/api/v1/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password, rememberMe }),
        });
    },

    logout(): Promise<void> {
        return request<void>('/api/v1/auth/logout', { method: 'POST' });
    },

    me(): Promise<User> {
        return request<User>('/api/v1/auth/me');
    },

    unlock(password: string): Promise<{ unlocked: boolean }> {
        return request<{ unlocked: boolean }>('/api/v1/auth/unlock', {
            method: 'POST',
            body: JSON.stringify({ password }),
        });
    },

    heartbeat(): Promise<void> {
        return request<void>('/api/v1/auth/heartbeat', { method: 'POST' });
    },

    listSessions(): Promise<{ sessions: Session[] }> {
        return request<{ sessions: Session[] }>('/api/v1/auth/sessions');
    },

    deleteSession(id: string): Promise<void> {
        return request<void>(`/api/v1/auth/sessions/${id}`, { method: 'DELETE' });
    },

    // changePassword is specified in Section 4 (added by amendment).
    // It returns 204 on success and revokes all other sessions of this user.
    changePassword(currentPassword: string, newPassword: string): Promise<void> {
        return request<void>('/api/v1/auth/me/password', {
            method: 'POST',
            body: JSON.stringify({ currentPassword, newPassword }),
        });
    },
};
```

### 6.6 Audit API client (`lib/api/audit.ts`)

```ts
// web/frontend/src/lib/api/audit.ts
import { request } from './client';

export interface AuditEvent {
    id: string;
    timestamp: string;
    actorUserId: string;
    actorUsernameSnapshot: string;
    action: string;
    targetType: string;
    targetId: string;
    beforeJson: unknown | null;
    afterJson: unknown | null;
    message: string;
    ip: string;
    userAgent: string;
}

export interface AuditFilter {
    actorUserId?: string;
    action?: string;
    targetType?: string;
    targetId?: string;
    from?: string;  // RFC 3339
    to?: string;    // RFC 3339
    limit?: number;
    cursor?: string;
}

export interface AuditListResponse {
    events: AuditEvent[];
    nextCursor: string;
}

export const auditApi = {
    list(filter: AuditFilter): Promise<AuditListResponse> {
        const params = new URLSearchParams();
        if (filter.actorUserId) params.set('actor_user_id', filter.actorUserId);
        if (filter.action) params.set('action', filter.action);
        if (filter.targetType) params.set('target_type', filter.targetType);
        if (filter.targetId) params.set('target_id', filter.targetId);
        if (filter.from) params.set('from', filter.from);
        if (filter.to) params.set('to', filter.to);
        if (filter.limit) params.set('limit', String(filter.limit));
        if (filter.cursor) params.set('cursor', filter.cursor);
        const query = params.toString();
        return request<AuditListResponse>(`/api/v1/audit${query ? '?' + query : ''}`);
    },
};
```

Note that the filter keys are snake_case in the URL parameters
(matching the server's expected query string format) while the
TypeScript object uses camelCase (matching frontend conventions).
The translation happens in the `list()` function.

### 6.7 Layout shell modifications (`+layout.svelte`)

The root layout is the gate that decides what to render based on
the auth state. It also owns the heartbeat lifecycle and the
compromised-password banner.

```svelte
<!-- web/frontend/src/routes/+layout.svelte (modified) -->
<script lang="ts">
    import { onMount, onDestroy } from 'svelte';
    import { goto } from '$app/navigation';
    import { page } from '$app/state';
    import { auth } from '$lib/stores/auth';
    import { idle } from '$lib/stores/idle';
    import { authApi } from '$lib/api/auth';
    import Sidebar from '$lib/components/Sidebar.svelte';
    import LockScreen from '$lib/components/LockScreen.svelte';
    import ChangePasswordModal from '$lib/components/ChangePasswordModal.svelte';
    import ToastContainer from '$lib/components/ToastContainer.svelte';
    import Button from '$lib/components/Button.svelte';
    import Spinner from '$lib/components/Spinner.svelte';

    const HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
    let heartbeatId: ReturnType<typeof setInterval> | null = null;
    let changePasswordModalOpen = $state(false);

    onMount(async () => {
        await auth.bootstrap();

        // Once authenticated, start the idle timer and the heartbeat.
        if (auth.state === 'authenticated' || auth.state === 'locked') {
            idle.start();
            startHeartbeat();
        }

        // Redirect anonymous users to /login (the link to /setup is on /login).
        if (auth.state === 'anonymous') {
            const here = page.url.pathname;
            if (here !== '/login' && here !== '/setup') {
                goto('/login');
            }
        }
    });

    onDestroy(() => {
        idle.stop();
        stopHeartbeat();
    });

    function startHeartbeat() {
        if (heartbeatId !== null) return;
        heartbeatId = setInterval(() => {
            // Only heartbeat when tab is visible (decision: visible-only).
            if (document.visibilityState !== 'visible') return;
            // Only heartbeat when authenticated and not locked.
            if (auth.state !== 'authenticated') return;
            authApi.heartbeat().catch((err) => {
                // 401 and 403 are handled by the client interceptor.
                // Other errors are logged but non-fatal.
                console.warn('heartbeat failed:', err);
            });
        }, HEARTBEAT_INTERVAL_MS);
    }

    function stopHeartbeat() {
        if (heartbeatId !== null) {
            clearInterval(heartbeatId);
            heartbeatId = null;
        }
    }
</script>

{#if auth.state === 'unknown'}
    <div class="flex items-center justify-center min-h-screen">
        <Spinner size="lg" />
    </div>
{:else if auth.state === 'anonymous'}
    <!-- /login or /setup page renders directly -->
    <slot />
{:else}
    <!-- authenticated or locked: full layout with optional compromised-password banner -->
    {#if auth.user?.passwordCompromised}
        <div class="bg-danger/10 border-b border-danger text-danger px-6 py-3 flex items-center justify-between" role="alert">
            <div>
                <strong>Your password has been found in a known data breach.</strong>
                Change it immediately to secure your account.
            </div>
            <Button variant="danger" size="sm" on:click={() => changePasswordModalOpen = true}>
                Change password
            </Button>
        </div>
    {/if}
    <div class="flex min-h-screen bg-base">
        <Sidebar />
        <main class="flex-1 p-6 relative" aria-busy={false}>
            <slot />
        </main>
    </div>
    <ToastContainer />
    <ChangePasswordModal bind:open={changePasswordModalOpen} />
    {#if auth.state === 'locked'}
        <LockScreen />
    {/if}
{/if}
```

Design notes:

- **Bootstrap is the first thing**: `onMount` waits for
  `auth.bootstrap()` to complete before rendering anything else. The
  `unknown` state shows a spinner; nothing else is reactive on it.

- **Heartbeat lifecycle**: started after bootstrap when in
  `authenticated` state, stopped on unmount. The interval handler
  itself double-checks `document.visibilityState` and `auth.state`
  to avoid wasted calls.

- **LockScreen mounted conditionally**: when `auth.state === 'locked'`,
  the LockScreen renders as a sibling of the main layout (not
  replacing it). The CSS `z-index` of LockScreen ensures it visually
  covers everything.

- **Compromised-password banner**: rendered above the main layout
  when `auth.user.passwordCompromised === true`. Clicking "Change
  password" opens `ChangePasswordModal`. The modal is always mounted
  (controlled by `open` prop) to preserve form state across
  show/hide cycles.

- **Anonymous redirect with guard**: redirecting to `/login` from
  `/login` would loop. The guard checks the current path. The `/setup`
  path is reached via a link on the `/login` page, not via an
  automatic detection (decision: keep the flow simple, the user
  knows whether they're a first-time setup or a returning login).

### 6.8 LockScreen component (`lib/components/LockScreen.svelte`)

A full-screen overlay rendered above the existing UI when the
session is in the `locked` state. Preserves the underlying UI
state (modals, scroll position, form drafts).

```svelte
<!-- web/frontend/src/lib/components/LockScreen.svelte -->
<script lang="ts">
    import { onMount } from 'svelte';
    import { auth } from '$lib/stores/auth';
    import { ApiError } from '$lib/api/client';
    import Input from './Input.svelte';
    import Button from './Button.svelte';

    let password = $state('');
    let error = $state<string | null>(null);
    let submitting = $state(false);
    let passwordInput: HTMLInputElement;

    onMount(() => {
        passwordInput?.focus();
    });

    async function handleSubmit(e: Event) {
        e.preventDefault();
        if (submitting) return;
        if (!password) {
            error = 'Password is required';
            return;
        }
        submitting = true;
        error = null;
        try {
            await auth.unlock(password);
            // On success, the auth store transitions to 'authenticated'
            // and this component unmounts via the parent's {#if} guard.
        } catch (err) {
            if (err instanceof ApiError) {
                error = err.status === 401 ? 'Incorrect password' : err.message;
            } else {
                error = 'Unexpected error';
            }
            password = '';
            passwordInput?.focus();
        } finally {
            submitting = false;
        }
    }
</script>

<div
    class="fixed inset-0 z-[1000] backdrop-blur-md bg-base/80 flex items-center justify-center"
    role="dialog"
    aria-modal="true"
    aria-labelledby="lockscreen-title"
>
    <div class="bg-elevated border border-default rounded-lg shadow-glow-cyan p-8 w-96 max-w-full mx-4">
        <h2 id="lockscreen-title" class="text-2xl font-semibold text-primary mb-2">
            Session locked
        </h2>
        <p class="text-secondary text-sm mb-6">
            Signed in as <span class="font-mono text-primary">{auth.user?.username ?? ''}</span>.
            Enter your password to continue.
        </p>
        <form on:submit={handleSubmit}>
            <Input
                bind:element={passwordInput}
                bind:value={password}
                type="password"
                label="Password"
                autocomplete="current-password"
                error={error}
                disabled={submitting}
            />
            <Button
                type="submit"
                variant="primary"
                size="md"
                loading={submitting}
                disabled={submitting}
                class="w-full mt-4"
            >
                Unlock
            </Button>
        </form>
    </div>
</div>
```

Design notes:

- **Full-screen overlay with backdrop blur**: the CSS
  `backdrop-filter: blur(...)` on the overlay obscures the
  underlying UI without removing it from the DOM. This preserves
  state (open modals, scroll positions, form drafts) so the user
  resumes exactly where they were after unlocking.

- **`z-[1000]`**: high enough to cover modals (Step C modals use
  z-index in the low hundreds). If Phase 2 introduces z-index
  competition, this is the value to adjust.

- **No Escape handler**: unlike a regular Modal, the LockScreen
  cannot be dismissed. There is no "cancel" path; the user must
  authenticate or close the tab.

- **Accessibility**: `role="dialog"` + `aria-modal="true"` +
  `aria-labelledby` mark it as a modal dialog. The password input
  receives focus on mount.

- **Username display from store**: `auth.user?.username` reads from
  the store, populated by the soft-auth flow (the session lookup
  still succeeds when locked). If the user object is somehow null
  (edge case), the fallback `''` keeps the layout intact.

- **`autocomplete="current-password"`**: lets password managers fill
  the input.

- **Error display**: the `Input` component's existing `error` prop
  shows the message in red under the field. No toast.

- **`reduced-motion` respect**: the underlying transitions on the
  overlay (if any are added later) are disabled via the global
  reduced-motion rule already in `app.css` from Step C.

### 6.9 Login page (`routes/login/+page.svelte`)

Standard username/password form with "Remember me" checkbox. Includes
a link to `/setup` for first-boot scenarios.

```svelte
<!-- web/frontend/src/routes/login/+page.svelte -->
<script lang="ts">
    import { goto } from '$app/navigation';
    import { auth } from '$lib/stores/auth';
    import { ApiError } from '$lib/api/client';
    import Input from '$lib/components/Input.svelte';
    import Checkbox from '$lib/components/Checkbox.svelte';
    import Button from '$lib/components/Button.svelte';
    import Card from '$lib/components/Card.svelte';

    let username = $state('');
    let password = $state('');
    let rememberMe = $state(false);
    let usernameError = $state<string | null>(null);
    let passwordError = $state<string | null>(null);
    let formError = $state<string | null>(null);
    let submitting = $state(false);

    async function handleSubmit(e: Event) {
        e.preventDefault();
        if (submitting) return;
        usernameError = passwordError = formError = null;
        if (!username) { usernameError = 'Username is required'; return; }
        if (!password) { passwordError = 'Password is required'; return; }
        submitting = true;
        try {
            await auth.login(username, password, rememberMe);
            goto('/routes');
        } catch (err) {
            if (err instanceof ApiError) {
                if (err.status === 401) {
                    formError = 'Invalid username or password';
                } else if (err.status === 400) {
                    formError = err.message;
                } else if (err.status === 429) {
                    formError = err.message; // toast already shown by client.ts
                } else {
                    formError = 'Unable to sign in. Try again later.';
                }
            } else {
                formError = 'Unexpected error';
            }
        } finally {
            submitting = false;
        }
    }
</script>

<div class="flex items-center justify-center min-h-screen bg-base p-4">
    <Card class="w-96 max-w-full p-8">
        <h1 class="text-3xl font-semibold text-primary mb-2">
            <span class="text-cyan font-mono">A</span><span class="font-mono">RENET</span>
        </h1>
        <p class="text-secondary mb-6 text-sm">Sign in to the admin panel.</p>
        {#if formError}
            <div class="mb-4 p-3 rounded bg-danger/10 border border-danger text-danger text-sm" role="alert">
                {formError}
            </div>
        {/if}
        <form on:submit={handleSubmit}>
            <Input
                bind:value={username}
                label="Username"
                autocomplete="username"
                error={usernameError}
                disabled={submitting}
            />
            <div class="mt-4">
                <Input
                    bind:value={password}
                    type="password"
                    label="Password"
                    autocomplete="current-password"
                    error={passwordError}
                    disabled={submitting}
                />
            </div>
            <div class="mt-4">
                <Checkbox bind:checked={rememberMe} label="Remember me for 30 days" disabled={submitting} />
            </div>
            <Button
                type="submit"
                variant="primary"
                size="md"
                loading={submitting}
                disabled={submitting}
                class="w-full mt-6"
            >
                Sign in
            </Button>
        </form>
        <p class="text-secondary text-xs mt-6 text-center">
            First time? <a href="/setup" class="text-cyan hover:underline">Set up admin account</a>
        </p>
    </Card>
</div>
```

Design notes:

- **Single-page layout**: no sidebar, no chrome, full-screen
  centered card.

- **Branding consistency**: the wordmark mirrors the sidebar's
  `ARENET` style (cyan `A`, monospace).

- **Inline error placement**: per-field errors next to the input
  (via `Input` component's existing `error` prop), form-level
  errors in a red banner at the top of the form.

- **`autocomplete` attributes**: enable password manager
  integration.

- **"First time?" link**: gives the user a clear path to `/setup`
  without requiring them to know the URL. This is the primary
  discovery mechanism for the setup flow.

### 6.10 Setup page (`routes/setup/+page.svelte`)

First-boot admin creation. Same structure as login, with the
addition of the setup token field and a banner explaining where
to find it.

```svelte
<!-- web/frontend/src/routes/setup/+page.svelte -->
<script lang="ts">
    import { goto } from '$app/navigation';
    import { authApi } from '$lib/api/auth';
    import { auth } from '$lib/stores/auth';
    import { ApiError } from '$lib/api/client';
    import Input from '$lib/components/Input.svelte';
    import Button from '$lib/components/Button.svelte';
    import Card from '$lib/components/Card.svelte';

    let setupToken = $state('');
    let username = $state('');
    let displayName = $state('');
    let password = $state('');
    let errors = $state<Record<string, string | null>>({});
    let formError = $state<string | null>(null);
    let submitting = $state(false);

    async function handleSubmit(e: Event) {
        e.preventDefault();
        if (submitting) return;
        errors = {};
        formError = null;
        submitting = true;
        try {
            const user = await authApi.setup(setupToken, username, displayName, password);
            auth.user = user;
            auth.state = 'authenticated';
            goto('/routes');
        } catch (err) {
            if (err instanceof ApiError) {
                if (err.status === 403) {
                    errors = { setupToken: 'Invalid or expired setup token' };
                } else if (err.status === 404) {
                    formError = 'Setup is not available: an admin account already exists.';
                } else if (err.status === 400) {
                    // Heuristic field mapping based on error message content.
                    const msg = err.message.toLowerCase();
                    if (msg.includes('username')) errors = { username: err.message };
                    else if (msg.includes('password')) errors = { password: err.message };
                    else if (msg.includes('displayname')) errors = { displayName: err.message };
                    else formError = err.message;
                } else {
                    formError = err.message;
                }
            } else {
                formError = 'Unexpected error';
            }
        } finally {
            submitting = false;
        }
    }
</script>

<div class="flex items-center justify-center min-h-screen bg-base p-4">
    <Card class="w-[28rem] max-w-full p-8">
        <h1 class="text-3xl font-semibold text-primary mb-2">
            Initial setup
        </h1>
        <p class="text-secondary mb-2 text-sm">Create the first admin account.</p>
        <div class="mb-6 p-3 rounded bg-cyan/10 border border-cyan/30 text-sm">
            <p class="text-primary">
                <strong>Setup token required.</strong>
            </p>
            <p class="text-secondary mt-1">
                Look in your Arenet server logs for a line beginning with
                <code class="font-mono text-cyan">Setup token:</code>.
                The token is regenerated on every restart until an admin exists.
            </p>
        </div>
        {#if formError}
            <div class="mb-4 p-3 rounded bg-danger/10 border border-danger text-danger text-sm" role="alert">
                {formError}
            </div>
        {/if}
        <form on:submit={handleSubmit}>
            <Input
                bind:value={setupToken}
                label="Setup token"
                placeholder="Paste from server logs"
                error={errors.setupToken}
                disabled={submitting}
            />
            <div class="mt-4">
                <Input
                    bind:value={username}
                    label="Username"
                    placeholder="e.g. admin"
                    autocomplete="username"
                    error={errors.username}
                    disabled={submitting}
                />
            </div>
            <div class="mt-4">
                <Input
                    bind:value={displayName}
                    label="Display name (optional)"
                    placeholder="e.g. Site Admin"
                    error={errors.displayName}
                    disabled={submitting}
                />
            </div>
            <div class="mt-4">
                <Input
                    bind:value={password}
                    type="password"
                    label="Password (minimum 15 characters)"
                    autocomplete="new-password"
                    error={errors.password}
                    disabled={submitting}
                />
            </div>
            <Button
                type="submit"
                variant="primary"
                size="md"
                loading={submitting}
                disabled={submitting}
                class="w-full mt-6"
            >
                Create admin account
            </Button>
        </form>
    </Card>
</div>
```

Design notes:

- **Informational banner**: explicitly explains the setup-token
  flow. This is a one-time page; the explanation is essential for
  user adoption.

- **Error mapping heuristic**: 400 responses from `/setup` don't
  include structured field information. The page makes a best-effort
  mapping based on substring matching of the error message. Phase 2
  will introduce structured field-level errors (`{field: "username",
  error: "..."}`) when we have the appetite for a wire-format
  breaking change.

- **`autocomplete="new-password"`**: prompts password managers to
  suggest a new strong password.

### 6.11 Audit page (`routes/audit/+page.svelte`)

The audit log explorer. Uses Step C's `DataTable` primitive with
expandable rows. Filter changes auto-apply with a 300ms debounce
to avoid hammering the server on every keystroke.

```svelte
<!-- web/frontend/src/routes/audit/+page.svelte -->
<script lang="ts">
    import { onMount } from 'svelte';
    import { auditApi, type AuditEvent, type AuditFilter } from '$lib/api/audit';
    import { ApiError } from '$lib/api/client';
    import DataTable from '$lib/components/DataTable.svelte';
    import Input from '$lib/components/Input.svelte';
    import Button from '$lib/components/Button.svelte';
    import Spinner from '$lib/components/Spinner.svelte';

    const ACTIONS = [
        '',
        'login_success', 'login_failure', 'logout',
        'unlock_success', 'unlock_failure',
        'session_revoked',
        'setup_admin_created', 'password_changed',
        'route_created', 'route_updated', 'route_deleted',
        'audit_viewed',
        'password_hibp_clean', 'password_hibp_pending', 'password_compromised_detected',
    ];

    const DEBOUNCE_MS = 300;

    let fromValue = $state('');
    let toValue = $state('');
    let actionFilter = $state('');
    let events = $state<AuditEvent[]>([]);
    let nextCursor = $state<string>('');
    let loading = $state(false);
    let loadError = $state<string | null>(null);
    let debounceTimer: ReturnType<typeof setTimeout> | null = null;

    async function load(reset: boolean = false) {
        loading = true;
        loadError = null;
        try {
            const filter: AuditFilter = { limit: 50 };
            if (fromValue) filter.from = fromValue;
            if (toValue) filter.to = toValue;
            if (actionFilter) filter.action = actionFilter;
            if (!reset && nextCursor) filter.cursor = nextCursor;
            const res = await auditApi.list(filter);
            events = reset ? res.events : [...events, ...res.events];
            nextCursor = res.nextCursor;
        } catch (err) {
            loadError = err instanceof ApiError ? err.message : 'Failed to load audit events';
        } finally {
            loading = false;
        }
    }

    function scheduleReload() {
        if (debounceTimer) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            load(true);
        }, DEBOUNCE_MS);
    }

    // Auto-apply filter changes: any change to fromValue, toValue, or
    // actionFilter triggers a debounced reload.
    $effect(() => {
        // Read the values to subscribe to changes.
        const _ = fromValue + toValue + actionFilter;
        scheduleReload();
    });

    onMount(() => {
        load(true);
    });
</script>

<div class="space-y-6">
    <div>
        <h1 class="text-4xl font-semibold text-primary">Audit log</h1>
        <p class="text-secondary mt-1">Review authentication events and route mutations.</p>
    </div>

    <!-- Filters: changes auto-apply with debounce -->
    <div class="grid grid-cols-3 gap-4 p-4 bg-elevated border border-default rounded-lg">
        <Input bind:value={fromValue} label="From (RFC 3339)" placeholder="2026-05-01T00:00:00Z" />
        <Input bind:value={toValue} label="To (RFC 3339)" placeholder="2026-05-18T00:00:00Z" />
        <div>
            <label class="block text-xs uppercase tracking-wide text-secondary mb-1">Action</label>
            <select bind:value={actionFilter} class="w-full bg-base border border-default rounded px-3 py-2 text-primary">
                {#each ACTIONS as action}
                    <option value={action}>{action || 'All actions'}</option>
                {/each}
            </select>
        </div>
    </div>

    {#if loadError}
        <div class="p-4 rounded bg-danger/10 border border-danger text-danger" role="alert">
            {loadError}
        </div>
    {/if}

    {#if loading && events.length === 0}
        <div class="flex justify-center mt-12">
            <Spinner size="lg" />
        </div>
    {:else if events.length === 0}
        <p class="text-secondary text-center mt-12">No audit events match the current filters.</p>
    {:else}
        <!-- DataTable with expandable rows: row shows summary, expanded shows JSON -->
        <DataTable
            items={events}
            headers={['Time', 'Action', 'Actor', 'Target', 'IP']}
        >
            <!-- Row template and expanded template implemented via Svelte snippets;
                 details in Step D Chunk 7 frontend implementation. -->
        </DataTable>
        {#if nextCursor}
            <div class="flex justify-center">
                <Button variant="secondary" size="md" on:click={() => load(false)} disabled={loading}>
                    {loading ? 'Loading…' : 'Load more'}
                </Button>
            </div>
        {/if}
    {/if}
</div>
```

Design notes:

- **Auto-apply with debounce**: any change to a filter field
  triggers a 300ms-debounced reload. This avoids the round-trip
  cost of typing each character of a date while still feeling
  instant to the user.

- **Action dropdown**: hard-coded list of all Step D action values
  (matches the enum in `internal/audit/actions.go`). Phase 2 may
  fetch this dynamically.

- **Pagination**: cursor-based, "Load more" button. Each click
  appends to the existing list; a filter change resets the list.

- **Expanded row content**: implementation details deferred to the
  Step D execution plan (chunk for frontend). The expanded view
  will show formatted `beforeJson`/`afterJson`, full IP, full user
  agent.

### 6.12 Sidebar modifications

The sidebar gains a fifth navigation item, "Audit", positioned
between "Routes" and "Topology". The implementation is a one-line
addition to the existing items array; no logic changes.

```ts
// Inside Sidebar.svelte, the navItems array gains:
{ href: '/audit', label: 'Audit', icon: 'activity', disabled: false },
```

The existing `disabled: true` flag stays on Topology, Security, and
Settings. The cyan-rail active highlight, the collapse animation,
and all other Step C sidebar behavior are unchanged.

The Lucide icon `activity` (a heartbeat/pulse line) is appropriate
for an audit log. Alternative candidates: `list`, `clock`,
`scroll-text`. The choice is finalized in the implementation chunk.

### 6.13 Change-password modal

The `ChangePasswordModal.svelte` component is mounted by the layout
shell (see 6.7) and opened by the compromised-password banner or
(in Phase 2) by a Settings page entry.

```svelte
<!-- web/frontend/src/lib/components/ChangePasswordModal.svelte -->
<script lang="ts">
    import { authApi } from '$lib/api/auth';
    import { auth } from '$lib/stores/auth';
    import { toast } from '$lib/stores/toast';
    import { ApiError } from '$lib/api/client';
    import Modal from './Modal.svelte';
    import Input from './Input.svelte';
    import Button from './Button.svelte';

    let { open = $bindable() } = $props();

    let currentPassword = $state('');
    let newPassword = $state('');
    let confirmPassword = $state('');
    let errors = $state<Record<string, string | null>>({});
    let submitting = $state(false);

    async function handleSubmit() {
        if (submitting) return;
        errors = {};
        if (!currentPassword) { errors.current = 'Required'; return; }
        if (newPassword.length < 15) { errors.new = 'Must be at least 15 characters'; return; }
        if (newPassword !== confirmPassword) { errors.confirm = 'Passwords do not match'; return; }
        submitting = true;
        try {
            await authApi.changePassword(currentPassword, newPassword);
            toast.push({ kind: 'success', message: 'Password changed successfully. Other sessions have been signed out.' });
            // The server clears passwordCompromised on the User and revokes
            // all other sessions of this user. Refresh from /me.
            await auth.bootstrap();
            // Clear the form.
            currentPassword = newPassword = confirmPassword = '';
            open = false;
        } catch (err) {
            if (err instanceof ApiError) {
                if (err.status === 401) errors.current = 'Incorrect current password';
                else if (err.status === 400) errors.new = err.message;
                else toast.push({ kind: 'error', message: err.message });
            } else {
                toast.push({ kind: 'error', message: 'Unexpected error' });
            }
        } finally {
            submitting = false;
        }
    }
</script>

<Modal bind:open title="Change password">
    <Input bind:value={currentPassword} type="password" label="Current password" autocomplete="current-password" error={errors.current} disabled={submitting} />
    <div class="mt-4">
        <Input bind:value={newPassword} type="password" label="New password (≥ 15 characters)" autocomplete="new-password" error={errors.new} disabled={submitting} />
    </div>
    <div class="mt-4">
        <Input bind:value={confirmPassword} type="password" label="Confirm new password" autocomplete="new-password" error={errors.confirm} disabled={submitting} />
    </div>
    <div class="mt-2 text-xs text-secondary">
        Changing your password will sign out all other active sessions on other devices.
    </div>
    <div slot="footer" class="flex justify-end gap-2">
        <Button variant="ghost" size="md" on:click={() => open = false} disabled={submitting}>Cancel</Button>
        <Button variant="primary" size="md" on:click={handleSubmit} loading={submitting} disabled={submitting}>
            Change password
        </Button>
    </div>
</Modal>
```

Design notes:

- **Modal reuses Step C Modal primitive**: focus trap, escape
  handling, click-outside-to-dismiss all inherited.

- **Three fields**: current password (verification), new password
  (≥15 chars), confirm new password (typo prevention).

- **Server-side validation**: the backend re-validates the new
  password against the top-10k list and re-checks HIBP
  asynchronously. If the new password is also compromised, the
  server returns 400 and the modal stays open with the error
  inline.

- **Multi-session revocation notice**: an explicit text under the
  inputs warns that other sessions will be signed out. The toast
  on success reinforces the message.

- **Post-change cleanup**: after a successful change, the modal
  triggers `auth.bootstrap()` which re-fetches `/me`. The server
  has cleared `passwordCompromised` on the user, so the banner
  disappears reactively.

- **No deep linking from sidebar in Step D**: the change-password
  modal is reached via the compromised-password banner. Routine
  password changes (for users without the compromised flag) will
  get a dedicated `/settings` entry in Phase 2.

## 7. HIBP integration (HaveIBeenPwned)

This section specifies how Arenet integrates with the HaveIBeenPwned 
(HIBP) Pwned Passwords service to detect passwords that have been 
exposed in known data breaches. It covers the two-tier defense 
(embedded list + online API), the k-anonymity protocol, the 
synchronous flow at password creation, the deferred re-check at 
login, and the audit events emitted.

### 7.1 Overview

Passwords in Arenet face two layers of compromise detection:

**Tier 1 — Embedded top-10k list** (always active): a list of the 
10 000 most common compromised passwords is embedded in the binary 
via `//go:embed`. Lookup is O(1) against an in-memory map, 
synchronous, and works offline. Approximately 30 KB compressed.

**Tier 2 — HaveIBeenPwned API** (active by default, disableable): 
an HTTPS call to `api.pwnedpasswords.com` using the k-anonymity 
protocol checks the password against HIBP's full database (over 
800 million breached passwords as of 2025). The protocol guarantees 
that neither the password nor its full hash is transmitted; only the 
first 5 characters of the SHA-1 hash leave the server.

The two tiers operate at two moments:

**At password creation or change** (synchronous): both Tier 1 and 
Tier 2 run. Tier 1 is instant. Tier 2 has a 5-second timeout; if it 
returns before timeout, its result is authoritative. If it times 
out or fails (network error, HIBP down), the user is still created 
but `User.HIBPCheckStatus` is set to `"pending"` for deferred 
verification.

**At successful login** (deferred re-check): if 
`User.HIBPCheckStatus == "pending"`, a fresh HIBP check is launched 
asynchronously after the login response is sent. The user is 
already logged in; the result of the check updates 
`User.HIBPCheckStatus` and `User.PasswordCompromised`. If the 
password is found to be compromised, the next page load (which 
calls `/me`) surfaces the `passwordCompromised: true` flag, 
triggering the change-password banner described in Section 6.13.

This deferred re-check is **the only way** Arenet can verify the 
password against HIBP after creation: once stored as an argon2id 
hash, the plaintext is gone forever (by design). The login flow is 
the unique moment we hold the plaintext briefly, and we exploit 
that to retry HIBP if the previous attempt failed or has aged.

### 7.2 The k-anonymity protocol

HIBP's Pwned Passwords API exposes 800+ million SHA-1 hashes of 
known breached passwords. Naively, to check whether a given 
password is in the database, one would compute its SHA-1 and look 
it up. This would require either downloading the entire database 
(many GB) or sending the password's hash to HIBP — both undesirable.

K-anonymity solves this elegantly:

1. The client computes `SHA1(password)` and uppercases it. Example: 
   `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8` for "password".

2. The client splits the hash into a **5-character prefix** (`5BAA6` 
   in the example) and a **35-character suffix** 
   (`1E4C9B93F3F0682250B6CF8331B7EE68FD8`).

3. The client sends only the 5-character prefix to 
   `https://api.pwnedpasswords.com/range/5BAA6`.

4. HIBP responds with a plain-text list of all 35-character suffixes 
   that share that prefix, paired with their breach count:

```text
0018A45C4D1DEF81644B54AB7F969B88D65:1
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
01330C689E5D64F660D6947A93AD634EF8F:3
...
```

5. The client searches its own suffix in the response. If found, 
   the password is compromised, with a count indicating how many 
   times it appears across breaches.

Properties:

- **HIBP never sees the password**, not even its full hash.
- **HIBP receives only the 5-char prefix**, which corresponds to 
  one of 1,048,576 possible buckets. Each bucket maps to ~800 
  passwords on average. Identifying which specific password was 
  checked is impractical.
- **No authentication or rate limit problematic for our use** — 
  HIBP allows free access; they ask only for a sensible 
  User-Agent.
- **SHA-1 is not used for storage** anywhere in Arenet. It is the 
  protocol HIBP defined for compatibility reasons in 2018; our 
  password storage uses argon2id (decision Q4).

### 7.3 HIBP client implementation

The HIBP client lives in `internal/auth/hibp.go`. It exposes one 
public function:

```go
// HIBPStatus reflects the outcome of a HIBP check.
type HIBPStatus string

const (
    HIBPStatusClean        HIBPStatus = "clean"
    HIBPStatusCompromised  HIBPStatus = "compromised"
    HIBPStatusPending      HIBPStatus = "pending"  // network/timeout failure
    HIBPStatusSkipped      HIBPStatus = "skipped"  // disabled via env var
)

// HIBPClient performs k-anonymity checks against the HaveIBeenPwned
// Pwned Passwords API. It is stateless apart from the http.Client
// (which holds its own connection pool).
type HIBPClient struct {
    httpClient *http.Client
    userAgent  string
    disabled   bool
}

// NewHIBPClient constructs a client honoring ARENET_HIBP_DISABLED.
func NewHIBPClient() *HIBPClient {
    disabled := os.Getenv("ARENET_HIBP_DISABLED") == "true"
    return &HIBPClient{
        httpClient: &http.Client{
            Timeout: 5 * time.Second,
        },
        userAgent: "Arenet/0.1 (homelab-reverse-proxy)",
        disabled:  disabled,
    }
}

// CheckPassword queries HIBP for the given plaintext password.
// Returns one of: HIBPStatusClean, HIBPStatusCompromised, 
// HIBPStatusPending (on network/timeout/parse error), or 
// HIBPStatusSkipped (when disabled via env var).
//
// The returned error is non-nil ONLY for programming errors (the 
// SHA-1 hash is unconditionally computable, so encoding failures 
// indicate code bugs). Network and parse failures are translated 
// into HIBPStatusPending without an error, so callers don't need 
// to special-case timeouts.
func (c *HIBPClient) CheckPassword(ctx context.Context, password string) (HIBPStatus, error) {
    if c.disabled {
        return HIBPStatusSkipped, nil
    }

    // Compute SHA-1 of password.
    hash := sha1.Sum([]byte(password))
    hashHex := strings.ToUpper(hex.EncodeToString(hash[:]))
    prefix := hashHex[:5]
    suffix := hashHex[5:]

    // Build request.
    url := "https://api.pwnedpasswords.com/range/" + prefix
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return HIBPStatusPending, fmt.Errorf("hibp: build request: %w", err)
    }
    req.Header.Set("User-Agent", c.userAgent)
    req.Header.Set("Accept", "text/plain")

    // Execute.
    resp, err := c.httpClient.Do(req)
    if err != nil {
        // Network error, DNS failure, timeout, TLS error, etc.
        // All translate to "pending" — the user is not blocked,
        // we retry at next login.
        return HIBPStatusPending, nil
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        // HIBP returned 5xx, 429, etc. Treat as pending.
        return HIBPStatusPending, nil
    }

    // Parse response: lines of "SUFFIX:COUNT", look for our suffix.
    scanner := bufio.NewScanner(resp.Body)
    for scanner.Scan() {
        line := scanner.Text()
        sep := strings.IndexByte(line, ':')
        if sep <= 0 {
            continue // malformed line, skip
        }
        if strings.EqualFold(line[:sep], suffix) {
            // Found: the password is compromised.
            return HIBPStatusCompromised, nil
        }
    }
    if err := scanner.Err(); err != nil {
        // Read error mid-stream. Treat as pending.
        return HIBPStatusPending, nil
    }

    // Suffix not found in the response: the password is clean.
    return HIBPStatusClean, nil
}
```

Design notes:

- **`context.Context` is honored**: callers can cancel via context, 
  e.g., when the HTTP handler's request context is cancelled by 
  the client closing the connection.

- **5-second timeout via `http.Client.Timeout`**: this is the 
  hard upper bound. Combined with the context timeout from the 
  caller (typically the request's deadline), the effective timeout 
  is the minimum of the two.

- **All failures map to `pending`**: callers don't need to 
  distinguish DNS failure from 5xx from parse error. The semantics 
  are uniform: "we couldn't verify, we'll try again later".

- **No retries**: this is best-effort. Retrying inside the function 
  would multiply latency and risk hitting HIBP rate limits in 
  pathological cases. The deferred re-check at login serves as the 
  natural retry mechanism.

- **`strings.EqualFold` for the suffix comparison**: HIBP responses 
  are uppercase hex, our `hashHex` is too, but defensive 
  case-insensitive comparison costs nothing and protects against 
  future HIBP format changes.

- **`bufio.Scanner` for line-by-line parsing**: the response is 
  typically ~20 KB (800 lines of 45 chars). Scanning avoids 
  loading the full body into memory.

### 7.4 Top-10k embedded list

The list of the 10 000 most common compromised passwords is sourced 
from the [SecLists project](https://github.com/danielmiessler/SecLists), 
specifically `Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt` 
(formerly named `10-million-password-list-top-10000.txt`; renamed upstream by 
SecLists, same xato.net source). SecLists is MIT-licensed and compatible with 
Arenet's AGPL-3.0.

The list is embedded into the binary at compile time via 
`//go:embed`, gzip-compressed to reduce binary size from ~80 KB 
(raw) to ~30 KB (compressed).

```go
// internal/auth/data/common-passwords.txt.gz
// (binary artifact, see internal/auth/password.go for the embed directive)

// internal/auth/password.go
package auth

import (
    "bufio"
    "compress/gzip"
    "embed"
    "strings"
    "sync"
)

//go:embed data/common-passwords.txt.gz
var commonPasswordsCompressed embed.FS

var (
    commonPasswords     map[string]struct{}
    commonPasswordsOnce sync.Once
)

// loadCommonPasswords reads and decompresses the embedded list on
// first call. Subsequent calls are no-ops (sync.Once).
func loadCommonPasswords() {
    commonPasswordsOnce.Do(func() {
        f, err := commonPasswordsCompressed.Open("data/common-passwords.txt.gz")
        if err != nil {
            // This should never happen with //go:embed — the file
            // is bundled at compile time. Panic indicates a build
            // misconfiguration.
            panic("auth: cannot open embedded common-passwords list: " + err.Error())
        }
        defer f.Close()

        gz, err := gzip.NewReader(f)
        if err != nil {
            panic("auth: cannot decompress embedded common-passwords list: " + err.Error())
        }
        defer gz.Close()

        m := make(map[string]struct{}, 10000)
        scanner := bufio.NewScanner(gz)
        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line != "" {
                // Store lowercase for case-insensitive lookup.
                m[strings.ToLower(line)] = struct{}{}
            }
        }
        commonPasswords = m
    })
}

// isCommonPassword returns true if the password (case-insensitive)
// is in the embedded top-10k list.
func isCommonPassword(password string) bool {
    loadCommonPasswords()
    _, found := commonPasswords[strings.ToLower(password)]
    return found
}
```

Design notes:

- **`sync.Once` for lazy initialization**: the list loads on first 
  call, not at package init. This avoids slowing down binary 
  startup if the auth package is imported but no password 
  validation occurs (rare, but cheap to optimize for).

- **Case-insensitive comparison**: "Password123" and "password123" 
  must both be rejected. The list itself is normalized to 
  lowercase at load time; lookup lowercases the input.

- **Panic on failed embed/decompress**: these failures indicate 
  build problems (`//go:embed` directive misconfigured, gzip data 
  corrupted). The application cannot meaningfully proceed without 
  the list; failing fast is correct.

- **Never disabled**: unlike HIBP, the top-10k check has no env 
  var to turn it off. There is no scenario where allowing 
  `password123` as an admin password is acceptable. The check 
  adds negligible latency (~1 µs per call).

### 7.5 Integration in password validation flow

Password validation occurs at three entry points: user creation 
(`UserStore.Create`), password change (`UserStore.UpdatePassword`), 
and the asynchronous re-check at login (described in 7.6). The 
synchronous flow at creation and change follows the same sequence:

```text
Length check (15..128 chars)        — synchronous, in-process
Top-10k embedded list check         — synchronous, in-process
HIBP k-anonymity check              — synchronous, network (5s timeout)
argon2id hash                       — synchronous, CPU-bound (~100ms)
Persist user                        — synchronous, BoltDB write
```

Steps 1 and 2 are short-circuiting: if they fail, the validation 
returns an error immediately without touching the network or 
computing argon2id. This protects HIBP from being hit by trivially 
bad passwords (`abc123`) and saves the user's time on the most 
common rejection cases.

Step 3 (HIBP) has three outcomes:

- **Clean**: the password is not in HIBP's database. Validation 
  proceeds to step 4. `User.HIBPCheckStatus` is set to `"clean"`.

- **Compromised**: the password is in HIBP's database. Validation 
  returns `ErrPasswordCommon` with the message "password is in 
  the list of common compromised passwords". The user is **not** 
  created.

- **Pending**: HIBP was unreachable (timeout, network error, 5xx). 
  Validation proceeds to step 4 — the password is accepted. 
  `User.HIBPCheckStatus` is set to `"pending"` for later 
  re-verification at login.

Pseudocode for `UserStore.Create`:

```go
func (s *userStore) Create(ctx context.Context, username, displayName, password string) (User, error) {
    // Step 1: length
    if len(password) < 15 {
        return User{}, ErrPasswordTooShort
    }
    if len(password) > 128 {
        return User{}, ErrPasswordTooLong
    }

    // Step 1.5: other field validation (username, display name)
    if err := validateUsername(username); err != nil {
        return User{}, err
    }
    if len(displayName) > 64 {
        return User{}, ErrDisplayNameTooLong
    }

    // Step 2: top-10k check
    if isCommonPassword(password) {
        return User{}, ErrPasswordCommon
    }

    // Step 3: HIBP check (5s timeout, best-effort)
    hibpStatus, _ := s.hibp.CheckPassword(ctx, password)
    if hibpStatus == HIBPStatusCompromised {
        return User{}, ErrPasswordCommon
    }

    // Step 4: argon2id hash
    hash, err := argon2id.CreateHash(password, s.argon2Params)
    if err != nil {
        return User{}, fmt.Errorf("auth: hash password: %w", err)
    }

    // Step 5: build and persist
    now := time.Now().UTC()
    user := User{
        ID:              uuid.NewString(),
        Username:        username,
        DisplayName:     displayName,
        PasswordHash:    hash,
        HIBPCheckStatus: string(hibpStatus),  // "clean", "pending", or "skipped"
        HIBPCheckedAt:   now,
        CreatedAt:       now,
        UpdatedAt:       now,
    }

    if err := s.persist(ctx, user); err != nil {
        return User{}, err
    }

    return user, nil
}
```

`UpdatePassword` follows the same pattern, with these differences:

- The argon2id-verified `currentPassword` is checked first (HTTP 
  401 if mismatch); only then are length/top-10k/HIBP checks run 
  on the new password.
- `HIBPCheckedAt` is updated regardless of outcome.
- All other sessions of the user are revoked after the successful 
  update (per Section 4.9bis).

### 7.6 The asynchronous re-check at login

If `User.HIBPCheckStatus == "pending"` at successful login, a 
fresh HIBP check is launched after the response is sent. The user 
is already logged in; the outcome of the check updates the user 
record and surfaces via `/me` on the next page load.

Flow inside the `/login` handler, post-verification:

```go
// Inside h.login, after argon2id verification succeeds and the
// session has been created:

// (Best-effort) update LastLoginAt
go s.userStore.RecordLogin(context.Background(), user.ID)

// Trigger HIBP re-check if still pending.
if user.HIBPCheckStatus == string(HIBPStatusPending) {
    go h.recheckHIBP(user.ID, password)
}

// Build response and return to client.
writeJSON(w, http.StatusOK, loginResponse{...})
```

The `recheckHIBP` method:

```go
// recheckHIBP runs an asynchronous HIBP check for an existing
// user's password. It does NOT take the request context (the
// request will complete before this function returns); it uses
// a fresh background context with a 30-second timeout.
//
// The password parameter is the plaintext supplied by the user at
// login; it stays in memory only for the duration of this call
// and is never logged.
//
// Outcomes:
//   - clean: update HIBPCheckStatus to "clean", emit audit event
//   - compromised: set passwordCompromised=true, emit audit event
//   - pending: leave the user as-is, log warn, retry at next login
//   - skipped: leave the user as-is (shouldn't happen — we only call
//     recheckHIBP when status is "pending", and "skipped" can't
//     transition to "pending")
func (h *Handler) recheckHIBP(userID, password string) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    status, _ := h.hibp.CheckPassword(ctx, password)

    switch status {
    case auth.HIBPStatusClean:
        if err := h.userStore.UpdateHIBPStatus(ctx, userID, string(status), false); err != nil {
            h.logger.Warn("hibp recheck: update user failed", "err", err.Error(), "user_id", userID)
            return
        }
        h.appendAuditBackground(userID, audit.Event{
            Action:     audit.ActionPasswordHIBPClean,
            TargetType: "user",
            TargetID:   userID,
        })

    case auth.HIBPStatusCompromised:
        if err := h.userStore.UpdateHIBPStatus(ctx, userID, string(status), true); err != nil {
            h.logger.Warn("hibp recheck: update user failed", "err", err.Error(), "user_id", userID)
            return
        }
        h.appendAuditBackground(userID, audit.Event{
            Action:     audit.ActionPasswordCompromisedDetected,
            TargetType: "user",
            TargetID:   userID,
            Message:    "deferred HIBP check at login confirmed password is in breach database",
        })

    case auth.HIBPStatusPending:
        // Still unreachable. Log and retry at next login.
        h.logger.Warn("hibp recheck: still pending", "user_id", userID)

    case auth.HIBPStatusSkipped:
        // Shouldn't reach here; defensive no-op.
    }
}
```

Design notes:

- **30-second timeout for the async check**: more generous than 
  the 5-second timeout at creation because no user is waiting. We 
  want the check to succeed if at all possible.

- **`context.Background()` instead of `r.Context()`**: the HTTP 
  request will have completed by the time this function runs. 
  Using the request context would cause the check to be cancelled 
  the moment the client connection closes.

- **Plaintext password lives only in this goroutine**: it is 
  passed as an argument (not stored anywhere), and the function 
  returns when the check completes. The garbage collector reclaims 
  the memory.

- **`appendAuditBackground`**: a variant of the standard 
  `appendAudit` helper that does not require a `*http.Request` 
  argument. It synthesizes the actor information from the user ID 
  directly. The IP and User-Agent are left empty (the audit event 
  is not tied to a specific request anymore).

- **Failure to update the user record is a warning, not a panic**: 
  the user is already logged in successfully; failing to update 
  their HIBP status is a degraded outcome but not catastrophic. 
  Next login will retry.

### 7.7 Audit events emitted

Three audit events relate to HIBP, all declared in Section 3.4 and 
listed in the enum in `internal/audit/actions.go`:

| Event                              | When emitted                                                     |
|------------------------------------|------------------------------------------------------------------|
| `password_hibp_clean`              | Synchronous create OR async re-check confirms clean              |
| `password_hibp_pending`            | Synchronous create: HIBP unreachable, user accepted as "pending" |
| `password_compromised_detected`    | Async re-check at login confirms compromised                     |

Notes:

- `password_hibp_clean` at create is **not** strictly necessary 
  (the user creation event already implies the password was clean), 
  but emitting it explicitly makes the audit log self-describing: 
  an operator filtering by HIBP events sees all relevant transitions.

- `password_compromised_detected` only fires at async re-check, 
  never at create. At create, a confirmed-compromised password 
  causes the user creation to fail with 400; no user is created, 
  so no audit event is emitted (decision: failed validation is 
  not audited, only successful state changes are).

- All three events have `TargetType: "user"` and `TargetID` set 
  to the user's ID, allowing easy filtering of HIBP history per 
  user.

- `BeforeJSON` and `AfterJSON` are always `null` for these events. 
  The only changing fields (`HIBPCheckStatus`, `PasswordCompromised`) 
  are derived state, not user-facing data; including them in the 
  audit JSON would add noise without value.

### 7.8 Configuration: disabling HIBP

HIBP checks can be disabled via environment variable:

```text
ARENET_HIBP_DISABLED=true
```

When disabled:

- `HIBPClient.CheckPassword` returns `HIBPStatusSkipped` immediately 
  without making any network call.
- New users get `HIBPCheckStatus: "skipped"` and 
  `HIBPCheckedAt` set to creation time.
- No HIBP-related audit events are emitted.
- The compromised-password banner never appears (because 
  `PasswordCompromised` is never set).
- The top-10k embedded check **continues to run** (it is not 
  affected by this env var).

Use cases:

- **Air-gapped lab**: Arenet deployed in an environment with no 
  outbound internet. HIBP would always time out; disabling 
  silences the noise.
- **Testing and CI**: avoid hitting HIBP from automated test 
  suites (which would also be poor netizenship — 
  HIBP asks not to be hammered).
- **Strict data-residency requirements**: some regulated 
  environments (defense, healthcare in certain jurisdictions) may 
  forbid any outbound calls to third-party services, even 
  k-anonymity-protected ones.

The default is **enabled**. Operators must explicitly opt out by 
setting the env var. This errs on the side of better security for 
the typical homelab deployment.

### 7.9 Security considerations

**SHA-1 is not used for password storage**. SHA-1 is cryptographically 
broken for collision resistance but remains adequate as a hash for 
the HIBP protocol, which doesn't depend on collision resistance. 
Password storage in Arenet uses argon2id (decision Q4), an entirely 
separate algorithm.

**K-anonymity privacy guarantees**:

- HIBP receives a 5-character hex prefix, representing one of 
  1,048,576 possible buckets. Each bucket maps to roughly 800 
  passwords on average across the database.
- An adversary observing the HIBP request stream (e.g., HIBP's 
  operator, a state-level network observer) can deduce which 
  bucket was queried, but cannot determine which of ~800 
  passwords within the bucket was the actual subject.
- Repeated queries from the same user for different passwords are 
  not linkable without TLS interception; the TLS connection itself 
  is the privacy boundary.

**TLS to HIBP**: the request is `https://api.pwnedpasswords.com`, 
verified against the standard system CA bundle. Go's `net/http` 
default behavior is correct (no `InsecureSkipVerify`).

**Logging hygiene**:

- Plaintext passwords are never logged. The HIBP client receives 
  the password as a parameter, computes its SHA-1, sends only the 
  prefix, and returns. The password string is never written to 
  slog, never written to any file.
- The 5-char prefix is not considered sensitive (millions of users 
  share each bucket) and may appear in debug logs if explicitly 
  enabled.

**Threat model boundaries**:

- HIBP being malicious is out of scope. We trust HIBP's operator 
  (Troy Hunt) and the k-anonymity guarantee. A compromised HIBP 
  would at worst learn the buckets we query, which is far less 
  damaging than learning the passwords.
- The local network being malicious is partially out of scope. A 
  man-in-the-middle attacker capable of breaking TLS could observe 
  the bucket queries. This is the same threat that every TLS-based 
  service faces and is mitigated by Arenet's standard practice of 
  running behind a reverse proxy with TLS termination.
- Local memory disclosure (e.g., a process memory dump while the 
  user is logging in) could reveal the password in plaintext for 
  the brief window between HTTP body parse and argon2id verification. 
  This is the same trust boundary as every password-handling 
  service; argon2id by design cannot eliminate the plaintext-in-RAM 
  exposure during verification.

## 8. Trusted proxies and client IP extraction

This section specifies how Arenet identifies the real source IP of 
each incoming request when running behind one or more reverse proxies 
(Cloudflare, a front Caddy, nginx, an internal load balancer). 
Correctly resolving the client IP is essential for two Step D 
features: per-IP rate limiting (Section 5.3) and audit logging 
(Section 3.4). This section is the canonical reference; Section 5.4 
gives the middleware-level summary and points here for the details.

### 8.1 Overview

In a typical Arenet deployment, requests may arrive through several 
layers:

- **Direct exposure**: client → Arenet. `r.RemoteAddr` is the 
  client IP.
- **Behind a CDN**: client → Cloudflare → Arenet. `r.RemoteAddr` 
  is Cloudflare's edge IP; the real client IP is in 
  `X-Forwarded-For`.
- **Behind a local proxy**: client → Caddy/nginx on the same host 
  → Arenet on `127.0.0.1`. `r.RemoteAddr` is `127.0.0.1`; the real 
  client IP is in `X-Forwarded-For`.
- **Chained proxies**: client → CDN → load balancer → Arenet. The 
  immediate upstream is the load balancer; `X-Forwarded-For` 
  contains the chain in order.

The challenge: blindly trusting `X-Forwarded-For` lets any direct 
client forge their source IP simply by setting the header. The 
solution: trust the header only when the immediate caller 
(`r.RemoteAddr`) is itself a known trusted proxy.

Configuration is via a single environment variable, 
`ARENET_TRUSTED_PROXIES`, holding a comma-separated list of CIDR 
ranges. No proxy is trusted by default — `r.RemoteAddr` is always 
used unless explicitly configured otherwise. This is decision D8.

### 8.2 Configuration via environment variable

The `ARENET_TRUSTED_PROXIES` environment variable accepts a 
comma-separated list of IPv4 and IPv6 CIDR ranges:

```text
ARENET_TRUSTED_PROXIES=10.0.0.0/8,192.168.0.0/16,2001:db8::/32
```

Rules:

- **Empty or unset**: no proxy is trusted. `r.RemoteAddr` is always 
  used as the client IP, regardless of `X-Forwarded-For`.
- **Whitespace tolerant**: leading/trailing spaces around each CIDR 
  are trimmed.
- **CIDR mandatory**: bare IPs (without `/32` or `/128`) are 
  rejected. The operator must write `10.0.0.5/32` for a single host.
- **Mixed IPv4 and IPv6**: both families are supported in the same 
  list.

**Parsing happens once at server startup**. Subsequent changes to 
the environment variable require a server restart. There is no hot 
reload (consistent with the rest of Arenet's configuration model: 
environment-driven, restart-to-reconfigure).

**Fail-fast on parse errors**: if any CIDR in the list is malformed, 
the server logs an error at `slog.Error` level and refuses to 
start:

```text
ERROR auth: invalid CIDR in ARENET_TRUSTED_PROXIES: "10.0.0.0/33"
```

Rationale: a malformed CIDR is a configuration bug. Silently 
skipping the malformed entry could lead to subtly wrong trust 
boundaries (e.g., the operator intends to trust `10.0.0.0/8` but a 
typo makes it `10.0.0.0/33`, so the trust is silently dropped and 
client IPs are misattributed). Crashing at startup forces the 
operator to fix the configuration before any traffic is processed.

### 8.3 IP extraction algorithm

For every request, the IP extractor middleware computes the client 
IP as follows:

```text
1. Parse RemoteAddr → strip port → get caller IP
2. If caller IP ∈ any trusted CIDR → go to step 3, else → go to step 4
3. Read X-Forwarded-For header, take leftmost entry, validate as IP
   - If valid → use it as client IP
   - If invalid → fall back to caller IP, log Debug
4. Use caller IP as client IP
5. Store resolved IP in request context under ClientIPKey
```

The leftmost entry of `X-Forwarded-For` is, per RFC 7239, the 
original client. Subsequent entries are intermediate proxies, added 
left-to-right as the request traverses each hop.

Worked examples (assuming `ARENET_TRUSTED_PROXIES=10.0.0.0/8`):

| RemoteAddr      | X-Forwarded-For                 | Resolved client IP | Why                          |
|-----------------|--------------------------------|--------------------|-----------------------------|
| `203.0.113.5`   | (absent or any value)          | `203.0.113.5`      | RemoteAddr not in trusted CIDR |
| `10.0.0.1`      | `198.51.100.42`                | `198.51.100.42`    | RemoteAddr trusted, XFF used   |
| `10.0.0.1`      | `198.51.100.42, 10.0.0.7`      | `198.51.100.42`    | Leftmost of XFF (chain)        |
| `10.0.0.1`      | `not-an-ip`                    | `10.0.0.1`         | XFF malformed, fallback        |
| `10.0.0.1`      | (absent)                       | `10.0.0.1`         | No XFF, fallback to RemoteAddr |
| `203.0.113.5`   | `forged-attacker-input`        | `203.0.113.5`      | Forge attempt ignored          |

The last example illustrates the security property: even if a 
direct client sends `X-Forwarded-For: 10.0.0.1`, the extractor 
discards it because `203.0.113.5` is not a trusted proxy.

### 8.4 Edge cases

**Multiple `X-Forwarded-For` headers**: HTTP allows the same header 
to appear multiple times. Go's `http.Header` concatenates them with 
commas: `req.Header.Get("X-Forwarded-For")` returns 
`"198.51.100.42, 198.51.100.43"`. Our parser splits on comma and 
takes the leftmost token. This is correct: the leftmost entry of 
the combined header is still the original client.

**IPv6 in `X-Forwarded-For`**: `net.ParseIP` handles IPv6 
correctly, including bracketed forms (`[2001:db8::1]`) and zone 
identifiers. The extractor strips brackets if present before 
parsing. IPv6 addresses with embedded zones (`fe80::1%eth0`) are 
not expected in real-world XFF headers; if encountered, parsing 
fails and we fall back to RemoteAddr.

**`X-Real-IP` is not used**. Some proxies (older nginx 
configurations) set `X-Real-IP` instead of or alongside 
`X-Forwarded-For`. Arenet only honors `X-Forwarded-For`. The 
rationale is simplicity: supporting two headers doubles the 
attack surface (now both can be checked, the proxy must 
synchronize them, etc.) and `X-Forwarded-For` is the de facto 
standard. Operators using `X-Real-IP`-only proxies should 
reconfigure their proxy to set `X-Forwarded-For`.

**`CF-Connecting-IP` is not used**. Cloudflare populates a 
proprietary header `CF-Connecting-IP` in addition to 
`X-Forwarded-For`. Arenet ignores this header for the same 
reasons as `X-Real-IP`: standard headers only, single source of 
truth. Cloudflare reliably sets `X-Forwarded-For` as well, so no 
information is lost. Sub-agents implementing the IP extractor 
must not add `CF-Connecting-IP` support; that is an explicit 
non-goal of Step D.

**`r.RemoteAddr` includes a port**. Go's `r.RemoteAddr` is in the 
form `host:port` (`192.168.1.42:54321` or `[::1]:54321`). The 
extractor strips the port before any CIDR check or use. This is 
done via `net.SplitHostPort`, which handles both IPv4 and 
bracketed IPv6 correctly.

**Loopback addresses (`127.0.0.1`, `::1`) are not auto-trusted**. 
A common deployment pattern is Arenet running behind a local 
Caddy/nginx on the same host, where requests arrive from 
`127.0.0.1`. In this case, the operator **must** add 
`127.0.0.1/32` (and `::1/128` if IPv6 is in use) to 
`ARENET_TRUSTED_PROXIES`. Without it, Arenet will use `127.0.0.1` 
as the client IP for every request — effectively disabling 
per-client rate limiting.

The choice not to auto-trust loopback is deliberate. Auto-trusting 
hides a security-relevant decision from the operator and breaks 
the principle that the trust boundary is explicit. The cost is 
one extra line of configuration; the benefit is that every 
production deployment is consciously configured.

**Empty `X-Forwarded-For` token**: if `X-Forwarded-For: , 
198.51.100.42`, the leftmost token is empty. The parser treats 
this as a malformed header and falls back to RemoteAddr.

**Trailing whitespace in XFF tokens**: `X-Forwarded-For: 
198.51.100.42 , 198.51.100.43` is valid; each token is trimmed 
before parsing.

### 8.5 Implementation

The IP extractor lives in `internal/auth/ipextract.go`. It is a 
small, stateless package-level component constructed once at 
startup.

```go
// IPExtractor resolves the client IP for incoming requests,
// honoring X-Forwarded-For from configured trusted proxies.
//
// The extractor is goroutine-safe: trustedCIDRs is read-only after
// construction. No mutex is needed.
type IPExtractor struct {
    trustedCIDRs []*net.IPNet
}

// NewIPExtractor parses the comma-separated CIDR list and returns
// a configured extractor. Returns an error if any CIDR is malformed;
// the server should fail-fast in this case (do not start).
//
// Pass an empty string to disable proxy trust entirely; in that
// case, ClientIP always returns RemoteAddr.
func NewIPExtractor(cidrList string) (*IPExtractor, error) {
    e := &IPExtractor{}
    cidrList = strings.TrimSpace(cidrList)
    if cidrList == "" {
        return e, nil
    }
    for _, raw := range strings.Split(cidrList, ",") {
        raw = strings.TrimSpace(raw)
        if raw == "" {
            continue
        }
        _, ipNet, err := net.ParseCIDR(raw)
        if err != nil {
            return nil, fmt.Errorf("auth: invalid CIDR in ARENET_TRUSTED_PROXIES: %q", raw)
        }
        e.trustedCIDRs = append(e.trustedCIDRs, ipNet)
    }
    return e, nil
}

// ClientIP resolves the client IP for the given request. See
// Section 8.3 for the algorithm. Returns an empty string only if
// RemoteAddr itself is unparseable (which is exceptional).
func (e *IPExtractor) ClientIP(r *http.Request) string {
    callerIP, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        // RemoteAddr lacked a port (rare, e.g. Unix socket): use as-is.
        callerIP = r.RemoteAddr
    }
    callerParsed := net.ParseIP(callerIP)
    if callerParsed == nil {
        return "" // unparseable, will surface as empty in audit
    }

    // Check if caller is a trusted proxy.
    trusted := false
    for _, cidr := range e.trustedCIDRs {
        if cidr.Contains(callerParsed) {
            trusted = true
            break
        }
    }
    if !trusted {
        return callerIP
    }

    // Caller is trusted: honor leftmost XFF entry.
    xff := r.Header.Get("X-Forwarded-For")
    if xff == "" {
        return callerIP
    }
    leftmost := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
    leftmost = strings.Trim(leftmost, "[]") // strip brackets if IPv6
    if net.ParseIP(leftmost) == nil {
        return callerIP // malformed XFF, fallback
    }
    return leftmost
}
```

Design notes:

- **No mutex**: `trustedCIDRs` is populated at construction and 
  never modified. All subsequent calls are read-only. Multiple 
  goroutines may call `ClientIP` concurrently without locking.

- **Empty CIDR list = pass-through**: `NewIPExtractor("")` returns 
  an extractor with zero trusted CIDRs. `ClientIP` then always 
  returns `RemoteAddr`, equivalent to having no proxy support.

- **Bracket-stripping for IPv6**: bracketed forms in XFF 
  (`[2001:db8::1]`) are unusual but technically valid. Stripping 
  them defensively avoids parse failures on legitimate input.

- **Empty return on unparseable RemoteAddr**: an empty client IP 
  surfaces clearly in audit events and rate limit counters (the 
  empty string is its own bucket). This makes the anomaly visible 
  in operations rather than masking it.

### 8.6 Middleware integration

The extractor runs as a middleware in the chi router, positioned 
between `Recoverer` and `rateLimit`:

```go
// Order in NewRouter (Section 5.2 reminder):
//   RequestID → slogLogger → Recoverer → devCORS → ipExtractMW → ...

func ipExtractMiddleware(extractor *auth.IPExtractor) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ip := extractor.ClientIP(r)
            ctx := context.WithValue(r.Context(), auth.ClientIPKey, ip)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

The middleware is mounted **once at the top of `/api/v1` route 
group**, not separately in each subgroup. Every authenticated and 
unauthenticated subgroup downstream benefits from the resolved IP 
via `auth.ClientIPFromContext(ctx)` (Section 5.8).

The order matters:

- **After `Recoverer`**: so that panics during IP parsing (which 
  should not happen, but defensively) are caught.
- **Before `rateLimit`**: the rate limiter reads the IP from 
  context; it must be populated first.
- **Before all auth middlewares**: the audit helper 
  (`appendAudit`) reads the IP from context when recording 
  events.

### 8.7 Logging

At startup, the parsed CIDR list is logged at `Info` level once:

```text
INFO auth: trusted proxies configured count=3 cidrs="10.0.0.0/8,192.168.0.0/16,2001:db8::/32"
```

If the list is empty:

```text
INFO auth: no trusted proxies configured (X-Forwarded-For will be ignored)
```

Rationale: the operator must be able to see, at boot, what trust 
boundary is in effect. This is a single line per startup, no 
ongoing volume. The CIDRs themselves are not considered sensitive 
(an operator reading their own server logs).

**No per-request logging in the normal flow**. Resolving an IP for 
every request would produce log volume linear in traffic, which is 
excessive for normal operation. The resolved IP appears in:

- The `slogLogger` access log (which already records every 
  request).
- Every audit event (Section 3.4).
- The rate-limit Tier 2 warning when blocking (Section 5.3).

These cover the relevant observability needs without per-request 
duplication.

**Debug-level logging for malformed XFF**: when `X-Forwarded-For` 
contains an unparseable token and the extractor falls back to 
`RemoteAddr`, a `slog.Debug` line records the anomaly. This is 
opt-in (default slog level is Info) and intended for 
troubleshooting unusual proxy configurations:

```text
DEBUG auth: malformed X-Forwarded-For, falling back to RemoteAddr xff="not-an-ip" remote_addr="10.0.0.1:54321"
```

### 8.8 Security considerations

**The trust decision is on the immediate caller, not the chain**. 
The extractor checks whether `r.RemoteAddr` is in a trusted CIDR. 
It does not validate the entire chain in `X-Forwarded-For`. If the 
chain is `client → CDN → load balancer → Arenet`, and Arenet trusts 
the load balancer, then the extractor honors the leftmost XFF 
entry — but it does not verify that the CDN's entry is itself a 
trusted intermediate.

This is the standard model for XFF-based IP extraction. It works 
because the trusted proxy is responsible for sanitizing the 
header it forwards. Cloudflare, for example, strips and 
regenerates `X-Forwarded-For` on every request to prevent 
upstream forgery. Our trust assumption is that operators who add 
Cloudflare to `ARENET_TRUSTED_PROXIES` understand that they are 
delegating XFF sanitization to Cloudflare.

**Misconfiguration risk**: trusting too broad a CIDR (e.g., 
`0.0.0.0/0`) effectively disables IP verification. Any client 
could then send a forged `X-Forwarded-For` and have it honored. 
The fail-fast on malformed CIDRs (Section 8.2) does not catch 
overly-broad valid CIDRs; the operator is responsible for 
keeping the list minimal and accurate.

**Multi-hop proxies and audit integrity**: the audit log records 
only the resolved client IP, not the intermediate hops. If 
investigation requires tracing the full path of a request, the 
operator must correlate Arenet's audit log with upstream proxy 
access logs (Cloudflare's, the load balancer's). This is the 
typical setup for SOC investigations and was already accepted in 
decision D8.

**No CAPTCHA or human-verification bypass**: the resolved IP is 
used for rate limiting and audit, never for granting elevated 
privileges. There is no "trusted IP bypasses authentication" 
mechanism in Arenet. Even an admin connecting from a trusted 
proxy must complete the full auth flow.

**Operator responsibility checklist**:

- Keep `ARENET_TRUSTED_PROXIES` minimal: only include the CIDRs of 
  proxies you actually deploy.
- Re-audit the list whenever you change your infrastructure (add 
  a CDN, change load balancer subnet, etc.).
- For deployments behind a local proxy on the same host, include 
  `127.0.0.1/32` and `::1/128`.
- For deployments behind Cloudflare, include Cloudflare's IP 
  ranges (published at 
  https://www.cloudflare.com/ips/). Note that this list changes 
  occasionally; review on each Arenet upgrade.
- Do not include `0.0.0.0/0` or `::/0` (entire internet) — that 
  would disable proxy verification entirely.

## 9. Audit log UI

This section specifies the detailed UX behavior of the `/audit` 
page introduced in Section 6.11. While Section 6 sketched the page 
structure and the API integration, Section 9 is the authoritative 
reference for the interaction patterns, the visual encoding of 
events, the expanded-row format, and the edge-case handling. A 
sub-agent implementing the audit page consults this section.

The audit page is the only Step D UI that surfaces complex 
structured data (JSON before/after, multiple categorical filters, 
expand/collapse rows). The other pages (login, setup, lock screen) 
are linear form flows; audit needs explicit attention.

### 9.1 Overview

The `/audit` page is reached via the fifth sidebar item (between 
Routes and Topology, see Section 6.12). It displays a paginated, 
filtered list of audit events with the following capabilities:

- Auto-applied filters with 300ms debounce (decision validated in 
  Section 6.11)
- Color-coded action badges by category
- Expand/collapse rows revealing full event details
- Click-to-filter on action badges and actor usernames
- Cursor-based pagination via "Load more"

The page is hard-auth-gated (Section 5.7), and accessing it emits 
an `audit_viewed` event (Section 4.10 — meta-audit).

### 9.2 Page layout

The page is composed of four vertically stacked regions:

```text
┌──────────────────────────────────────────────────────────────┐
│ Header                                                       │
│   Title "Audit log"                                          │
│   Subtitle "Review authentication events and route mutations"│
├──────────────────────────────────────────────────────────────┤
│ Filter panel (3-column grid, responsive)                     │
│   [From RFC 3339]   [To RFC 3339]   [Action ▼]               │
│   Active filter pills (if any)                               │
├──────────────────────────────────────────────────────────────┤
│ DataTable                                                    │
│   Columns: Time | Action | Actor | Target | IP               │
│   Rows: collapsed by default; click to expand                │
├──────────────────────────────────────────────────────────────┤
│ Pagination footer                                            │
│   [Load more] (visible when nextCursor non-empty)            │
└──────────────────────────────────────────────────────────────┘
```

Rendering states:

- **Loading (initial)**: centered spinner, no chrome around it. 
  Filter panel still visible and interactive.
- **Loaded with events**: DataTable populated, "Load more" button 
  if pagination available.
- **Loaded with zero events**: empty state message "No audit 
  events match the current filters." No "Load more" button.
- **Server error**: red banner above the DataTable with the error 
  message and a "Retry" button. Existing events (if any) remain 
  visible.

The DataTable component reuses Step C's primitive 
(`web/frontend/src/lib/components/DataTable.svelte`). The audit 
page passes a custom row template that handles the expand/collapse 
state per-row.

### 9.3 Filter behaviors

**Auto-apply with debounce**: any change to a filter field 
schedules a reload via a 300ms `setTimeout`. If another change 
occurs within the debounce window, the previous timer is cleared 
and a new one starts. The effect (in Svelte 5 runes terms) reads 
all three filter values to subscribe to changes; the actual 
fetch is gated by the timer.

**Combination semantics**: filters combine with AND. If both 
`action=login_success` and `from=2026-05-01` are set, only events 
matching both are returned. Empty filters are silently ignored 
(an empty `from` field does not match "events before any date" — 
it simply does not constrain the time range).

**Clearing a filter**: emptying the input field is the way to 
clear it. The page does not display an explicit "All actions" 
option separately from the empty string in the dropdown — the 
empty string IS "all actions" semantically.

**Filter persistence**: Step D does not persist filter state. 
Navigating away from `/audit` and back resets the page to default 
state (no filters). URL query parameters are not used in Step D 
(decision: keep the URL clean; bookmark-and-share of filtered 
audit views is deferred to Phase 2).

**Active filter pills**: when one or more filters are active, a 
strip of pill-shaped indicators appears above the DataTable:

```text
[ Action: login_failure × ]  [ From: 2026-05-01T00:00:00Z × ]
```

Clicking the × on a pill clears that specific filter (resets the 
input field and triggers a reload). A "Clear all filters" button 
appears to the right of the pills when at least one is active.

### 9.4 Row display (collapsed)

Each row in the table displays five columns:

**Time**: a relative time string (e.g. "2 hours ago", "yesterday", 
"3 days ago") rendered in the user's locale. The full RFC 3339 
timestamp appears as a `title` attribute (HTML tooltip) on hover. 
Implementation uses a small helper based on 
`Intl.RelativeTimeFormat` — no external library dependency.

**Action**: a colored badge displaying the action name. Categories 
and colors:

| Category   | Colour  | Actions in category                                          |
|------------|---------|--------------------------------------------------------------|
| Auth       | Cyan    | `login_success`, `login_failure`, `logout`, `unlock_success`, `unlock_failure` |
| Mutation   | Amber   | `route_created`, `route_updated`, `route_deleted`, `password_changed`, `setup_admin_created` |
| Security   | Red     | `session_revoked`, `password_compromised_detected`            |
| HIBP       | Violet  | `password_hibp_clean`, `password_hibp_pending`                |
| Meta       | Slate   | `audit_viewed`                                               |

The colors are sourced from the existing Step C design tokens (in 
`app.css`): `--color-cyan`, `--color-warning`, `--color-danger`, 
plus two additions for Step D: `--color-violet`, `--color-slate`. 
Each badge is the action name in white text on the category color 
at 30% opacity, with a 1px border at full opacity (matching the 
Step C button style).

The badge is **clickable**: clicking it sets the action filter to 
this row's action value. To prevent this click from also 
triggering the row expand, the badge's event handler calls 
`event.stopPropagation()`.

**Actor**: the actor's `displayName` (falling back to `username` 
if displayName is empty), rendered in regular text. A small icon 
button (Lucide `filter`) appears next to it on hover; clicking 
the icon sets the actor filter to this row's `actorUserId`. The 
icon click also calls `stopPropagation()` to avoid expanding the 
row.

When `ActorUserID` is empty (unauthenticated events like a failed 
login), the column displays the `ActorUsernameSnapshot` (the 
attempted username, captured at the time of the event) in italic 
muted text, with no filter icon (cannot filter on an unidentified 
actor).

**Target**: a compact representation of the target. Formats:

```text
route: a1b2c3d4-…
user:  e5f6g7h8-…
session: i9j0k1l2-…
(none)  — for events without a target (e.g. login_failure)
```

The UUID is truncated to its first 8 characters with an ellipsis. 
The full UUID appears in the tooltip on hover. The target column 
is **not** clickable for filtering in Step D (the `target_id` 
filter is reachable via the filter panel if needed).

**IP**: the resolved client IP rendered in monospace font. Empty 
IPs (events without a request context, e.g. background HIBP 
re-check) render as `—`. On narrow viewports, this column may be 
hidden by the responsive behavior of Step C's `DataTable` component; 
the full IP is always visible in the expanded row.

**Row click target**: clicking anywhere on the row that is **not** 
the action badge or the filter icon expands or collapses the row. 
This is implemented by attaching the click handler to the `<tr>` 
element, and having the badge and filter icon call 
`stopPropagation()` on their own click handlers.

### 9.5 Row display (expanded)

When a row is expanded, a sub-region appears below it (still 
inside the table, as a `<tr>` with `colspan="5"`) displaying all 
fields of the event:

```text
┌──────────────────────────────────────────────────────────────┐
│ Full timestamp:  2026-05-17T14:23:00.123Z UTC                │
│ Actor:           admin (a3a6e27d-043b-425a-8e40-868bf1943de8)│
│ Target:          route (f7b9c0d1-a234-5678-90ab-cdef12345678)│
│ IP:              198.51.100.42                               │
│ User-Agent:      Mozilla/5.0 (Macintosh; Intel Mac OS X 14…) │
│ Message:         (none)                                      │
│                                                              │
│ Before:                       After:                         │
│ ┌──────────────────────────┐  ┌──────────────────────────┐  │
│ │ (null)                   │  │ {                        │  │
│ │                          │  │   "id": "f7b9c0d1-...",  │  │
│ │                          │  │   "host": "api.local",   │  │
│ │                          │  │   ...                    │  │
│ │                          │  │ }                        │  │
│ └──────────────────────────┘  └──────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

Field details:

- **Full timestamp**: RFC 3339 with milliseconds, UTC explicitly 
  appended. Always UTC regardless of the user's locale (decision: 
  audit logs are operational records, not user-facing time 
  displays; UTC avoids timezone confusion across distributed 
  teams).

- **Actor**: `displayName (username)` followed by the full ID in 
  parentheses. If the actor is anonymous, displays 
  `(unauthenticated) — attempted: <username_snapshot>`.

- **Target**: `<type> (<full UUID>)`. Empty for events without a 
  target.

- **IP**: the full resolved IP, monospace.

- **User-Agent**: the full UA string, monospace, with CSS 
  `word-break: break-all` so long strings wrap rather than 
  overflow.

- **Message**: the `Message` field. Empty messages render as 
  `(none)` in muted text.

- **Before / After**: two side-by-side `<pre>` blocks, each 
  containing `JSON.stringify(value, null, 2)` of the respective 
  field. If a field is `null`, the corresponding block shows 
  `(null)` in muted text. The two blocks are equal-width on 
  desktop and stack vertically on mobile (breakpoint at 768px).

**No syntax highlighting in Step D**. The JSON is rendered as 
plain monospace text. Syntax highlighting (keys in blue, strings 
in green, etc.) is a Phase 2 enhancement; it requires either a 
client-side library (Prism, Shiki, highlight.js — all add ~30 KB) 
or a custom tokenizer. The cost-benefit does not justify it for 
Step D, where the audit reader is an admin who can read raw JSON.

**No side-by-side diff in Step D**. When both Before and After are 
present (e.g. `route_updated`), displaying a visual diff between 
the two would help spot exactly what changed. This is deferred to 
Phase 2 — it requires a diff library and an additional UI mode. 
Step D shows the two blocks separately and the reader infers the 
differences.

**Long JSON collapsing**: if either Before or After JSON exceeds 
50 lines when stringified, the block initially shows the first 50 
lines followed by a "Show more" link. Clicking it expands the 
block to full content. This caps the visual footprint of huge 
events (rare, but possible if a route has many headers or rules).

### 9.6 Filter interaction patterns

Three interactions trigger filter changes from row content:

1. **Click on action badge**: sets `actionFilter` to the row's 
   `action` value. Triggers a reload (after 300ms debounce).

2. **Click on actor's filter icon** (visible on hover next to the 
   username): sets `actorUserIdFilter` to the row's 
   `actorUserId`. Triggers a reload.

3. **Click on a pill's ×**: clears that specific filter. 
   Triggers a reload.

All three interactions update the corresponding input field in 
the filter panel (so the user can see and further adjust the 
filter). They do not modify the URL (no query params, see 9.3).

The filter panel input fields and the click-to-filter actions are 
both writers of the same reactive state. Svelte 5 runes handle 
the binding transparently; no manual synchronization is needed.

### 9.7 Pagination

Cursor-based pagination per the API contract (Section 4.10):

- **Default page size**: 50 events per request. The frontend does 
  not expose a "page size" selector in Step D; the value is 
  hard-coded.

- **Load more button**: appears below the DataTable when 
  `nextCursor !== ""`. Clicking it issues an API call with the 
  same filters plus the current `nextCursor`. The new events are 
  appended to the existing list (not replaced).

- **Filter change semantics**: any filter change resets the list. 
  The next API call has `cursor: ""` (no cursor → fresh query), 
  and the response replaces the events array. The "Load more" 
  button reappears if the fresh response has a non-empty 
  `nextCursor`.

- **Loading state during "Load more"**: the button shows 
  "Loading..." and disables itself. The existing rows remain 
  visible (do not hide them during fetch).

- **Pagination footer error handling**: if a "Load more" call 
  fails, a toast notifies the user and the button re-enables to 
  allow retry. The existing rows are not removed.

### 9.8 JSON rendering details

The `beforeJson` and `afterJson` fields arrive from the API as 
**already-parsed JavaScript values** (Section 4.13). The frontend 
does not double-parse; it directly stringifies for display:

```ts
function formatJson(value: unknown): string {
    if (value === null || value === undefined) return '(null)';
    try {
        return JSON.stringify(value, null, 2);
    } catch (err) {
        // Circular references or unstringifiable values.
        // Should not happen with API-sourced data, but defensive.
        return '(unable to render JSON)';
    }
}
```

The `<pre>` block has `white-space: pre-wrap` so long lines wrap 
within the block, and `overflow-x: auto` as a fallback for 
non-wrappable content. The font is the design system's monospace 
stack.

If the JSON exceeds 50 lines, the rendering is truncated:

```ts
function formatJsonWithFold(value: unknown): { display: string, foldable: boolean } {
    const full = formatJson(value);
    const lines = full.split('\n');
    if (lines.length <= 50) {
        return { display: full, foldable: false };
    }
    return {
        display: lines.slice(0, 50).join('\n') + '\n... (truncated, click to expand)',
        foldable: true,
    };
}
```

The Svelte component manages a `foldedOpen` state per JSON block; 
clicking "Show more" sets it to `true` and re-renders with the 
full content.

### 9.9 Edge cases

**Very long User-Agent**: User-Agent strings can exceed 200 
characters. In the collapsed-row view, the IP column is the 
rightmost; the UA appears only in the expanded view, where the 
`<pre>` block with `word-break: break-all` handles overflow 
gracefully. No truncation in the expanded view; truncation only 
applies to the collapsed-row tooltip (truncate at 80 chars + 
ellipsis).

**Timestamps and timezones**: all displayed timestamps are UTC. 
The relative time string ("2 hours ago") is computed from UTC 
timestamps; the result is locale-relative but timezone-anchored 
to UTC. The full timestamp in the expanded view includes a literal 
"UTC" suffix to make the convention explicit.

**Empty audit log**: when the API returns zero events with no 
filters applied, the empty state shows a friendly message ("No 
audit events recorded yet."). When zero events with filters 
applied, the message differs ("No audit events match the current 
filters."). Both messages are accompanied by no spinner and no 
"Load more" button.

**Server error during initial load**: a red banner appears above 
the filter panel:

```text
┌──────────────────────────────────────────────────────────────┐
│ ⚠ Failed to load audit events: <error message>     [ Retry ] │
└──────────────────────────────────────────────────────────────┘
```

Clicking Retry re-runs the load with the current filters. The 
existing events array remains empty (the load failed before any 
data arrived).

**Server error during "Load more"**: a toast notification is 
pushed via the existing toast store; the existing rows stay 
visible; the "Load more" button re-enables for retry.

**Network timeout**: the API client (Section 6.4) treats timeouts 
as system errors and throws `ApiError('system', 0, ...)`. The 
audit page handles this the same as any other server error.

**Filter by a future date range**: the API returns an empty 
events array with no error. The empty state message applies.

**Filter combinations with zero results**: same — empty state, no 
error.

**Permission to view audit events**: in Step D Phase 1, there is 
a single admin and they see all events. Phase 2 will introduce 
per-role visibility (e.g. editor sees only their own actions). The 
UI is built without permission-aware fields in Step D; this is a 
decision recorded as D10.

### 9.10 Accessibility

**Semantic table structure**: the events list is a true HTML 
`<table>` with `<thead>`, `<tbody>`, `<tr>`, `<th>`, `<td>` 
elements. Screen readers parse the structure natively.

**Expandable rows accessibility**: each row's clickable area is 
also a button-like role. The implementation uses:

- `tabindex="0"` on the `<tr>` so it receives keyboard focus.
- `role="button"` on the `<tr>` to signal the actionable nature.
- `aria-expanded="true"` or `"false"` reflecting the row state.
- `aria-controls="event-detail-<id>"` pointing to the expanded 
  detail row.
- Keyboard handler: `Enter` or `Space` triggers the toggle 
  (matching `<tr>` to standard button behavior).

**Filter pill accessibility**: each filter pill has:

- A visible × button with `aria-label="Remove filter: <field>=<value>"`.
- The pill itself is not focusable; only the × is.

**Color contrast**: the badge colors (cyan, amber, red, violet, 
slate) at 30% opacity with full-opacity borders meet WCAG AA 
contrast against the dark background of the design system. White 
text on the 30%-opacity badges is intentional — the badge 
background is a tinted glass effect, not the solid color.

**No sortable columns in Step D**: clicking column headers does 
not sort. Sortable columns are a Phase 2 enhancement (the API 
already returns events in descending chronological order, which is 
the default and overwhelmingly the desired order).

**Reduced motion**: the row expand/collapse animation respects 
`prefers-reduced-motion: reduce` via the global rule already in 
`app.css` from Step C. When reduced motion is requested, the 
expanded content appears instantly without sliding.

**Screen reader announcements on filter changes**: a 
`<div role="status" aria-live="polite">` outside the visible 
viewport announces "Loaded N events" after a successful load and 
"No events match the filters" on empty results. This avoids 
silent UI changes from being missed by screen reader users.

## 10. Acceptance criteria

This section enumerates the verifiable criteria that determine 
whether Step D is "done". Each criterion is a precise statement of 
expected behavior that can be tested manually (via curl and 
browser interaction) or automatically (Go unit/integration tests). 
This section is the contract that the implementation chunks 
satisfy.

The criteria are organized by domain rather than by component. A 
single failing criterion blocks the Step D acceptance, regardless 
of which file or package implements it.

### 10.1 Overview

Step D delivers three families of behavior:

1. **Authentication and session management** (Sections 10.2–10.4): 
   the foundation; everything else depends on it.
2. **Password protection** (Section 10.5): the HIBP integration 
   and embedded top-10k list.
3. **Audit and observability** (Section 10.6): the immutable 
   record of authentication and mutation events.

Plus three transversal areas:

4. **Trusted proxies** (Section 10.7): correct IP attribution.
5. **Frontend integration** (Section 10.8): UX flows the user sees.
6. **Configuration** (Section 10.9): the env vars that operators 
   touch.

Each criterion is independently verifiable: passing one does not 
imply passing another. The implementation is considered Step D 
complete when **all** criteria below pass.

### 10.2 Authentication flow

**AC-AUTH-01** — At first boot (no admin in BoltDB), the server 
logs a structured `slog.Info` line containing 
`Setup token: <opaque-256-bit-string>`. The token regenerates on 
every restart while no admin exists.

**AC-AUTH-02** — `POST /api/v1/auth/setup` with a valid 
`setupToken`, `username: "admin"`, `displayName: "Test"`, 
`password: "<15+ chars valid>"` returns 201 with the new User 
JSON, and sets the `arenet_session` cookie.

**AC-AUTH-03** — After AC-AUTH-02, a second call to 
`POST /api/v1/auth/setup` returns 404 with body 
`{"error": "setup unavailable: an admin already exists"}`.

**AC-AUTH-04** — `POST /api/v1/auth/login` with correct username 
and password returns 200 with the User JSON and sets the session 
cookie. The cookie has attributes `HttpOnly; Secure; 
SameSite=Strict; Path=/; Max-Age=86400` in production mode (no 
`--dev`), and `Secure` omitted in `--dev` mode.

**AC-AUTH-05** — `POST /api/v1/auth/login` with non-existent 
username returns 401 with body `{"error": "invalid credentials"}`. 
The same response is returned for an existing username with wrong 
password (no username enumeration).

**AC-AUTH-06** — `POST /api/v1/auth/login` with `rememberMe: true` 
sets the cookie `Max-Age=2592000` (30 days).

**AC-AUTH-07** — `POST /api/v1/auth/logout` deletes the session 
from BoltDB and returns 204 with `Set-Cookie: arenet_session=; 
Max-Age=0`.

**AC-AUTH-08** — After 24 hours of inactivity on a non-remember-me 
session, the next API call returns 401 (the session has expired 
absolutely).

**AC-AUTH-09** — After 30 days of inactivity on a remember-me 
session, the next API call returns 401.

**AC-AUTH-10** — `GET /api/v1/auth/me` returns the current user's 
JSON including `locked: false` when the session is active.

**AC-AUTH-11** — Argon2id parameters are `m=64MiB, t=3, p=4` 
(decision Q4). Verified by inspecting the generated PHC string in 
`User.PasswordHash`.

### 10.3 Session locking

**AC-LOCK-01** — After 15 minutes without an authenticated API 
call, `GET /api/v1/auth/me` returns 200 with `locked: true` in 
the response body.

**AC-LOCK-02** — After 15 minutes without an authenticated API 
call, any hard-auth endpoint (e.g. `GET /api/v1/routes`) returns 
403 with body `{"error": "session locked"}`.

**AC-LOCK-03** — `POST /api/v1/auth/unlock` with correct password 
returns 200 with `{"unlocked": true}`, updates `Session.LastActivity` 
to now, and subsequent hard-auth calls succeed.

**AC-LOCK-04** — `POST /api/v1/auth/unlock` with wrong password 
returns 401 with `{"error": "invalid password"}` and emits a 
`unlock_failure` audit event.

**AC-LOCK-05** — `GET /api/v1/auth/me` does NOT touch 
`Session.LastActivity`. Verified: polling `/me` every minute while 
nothing else happens still triggers the lock after 15 minutes.

**AC-LOCK-06** — The frontend's `LockScreen` component appears 
when `auth.state === 'locked'`. The underlying UI (sidebar, main 
content, open modals) remains in the DOM behind a backdrop-blur 
overlay.

**AC-LOCK-07** — The client-side idle timer (Section 6.3) calls 
`auth.setLocked()` after 15 minutes of no successful API call. 
Server activity (Touch in hard-auth middleware) and client timer 
agree on the threshold.

### 10.4 Rate limiting

**AC-RATE-01** — Five consecutive `POST /api/v1/auth/login` calls 
with wrong credentials from the same IP within 5 minutes cause the 
sixth call from that IP to return 429 with header 
`Retry-After: 900` and body 
`{"error": "too many attempts, retry after 15 minutes"}`.

**AC-RATE-02** — Ten consecutive failed `POST /api/v1/auth/login` 
calls from the same IP within 1 hour cause the eleventh call from 
that IP to return 429 with header `Retry-After: 3600`.

**AC-RATE-03** — A successful `POST /api/v1/auth/login` from an 
IP resets that IP's failure counter (Tier 1 and Tier 2 both 
cleared).

**AC-RATE-04** — Tier 2 trigger emits an `slog.Warn` line with 
structured fields `ip`, `username_attempted`, `failure_count_window`, 
`blocked_until`, `suggestion`.

**AC-RATE-05** — Rate limit counters are stored in memory only. 
After a server restart, all counters are cleared (verified by 
hitting Tier 1, restarting the binary, and verifying the IP is no 
longer blocked).

**AC-RATE-06** — Rate limit is per-IP, not per-username. Two 
different attackers from the same IP attempting different 
usernames share the same counter.

### 10.5 Password validation

**AC-PW-01** — `POST /api/v1/auth/setup` with `password` of 14 
characters returns 400 with body 
`{"error": "password must be at least 15 characters"}`.

**AC-PW-02** — `POST /api/v1/auth/setup` with `password` of 129 
characters returns 400 with body 
`{"error": "password must be at most 128 characters"}`.

**AC-PW-03** — `POST /api/v1/auth/setup` with `password: 
"password12345678"` (in top-10k list) returns 400 with body 
`{"error": "password is in the list of common compromised passwords"}`.

**AC-PW-04** — Password validation is case-insensitive against 
the top-10k list. `"Password12345678"`, `"PASSWORD12345678"`, 
and `"password12345678"` are all rejected.

**AC-PW-05** — With HIBP enabled (default) and reachable, 
`POST /api/v1/auth/setup` with a password known to HIBP but not in 
top-10k returns 400 with the same error message as top-10k 
rejections.

**AC-PW-06** — With HIBP unreachable (verified by blocking 
`api.pwnedpasswords.com` at the network level), 
`POST /api/v1/auth/setup` succeeds and the created User has 
`HIBPCheckStatus: "pending"`.

**AC-PW-07** — A subsequent successful `POST /api/v1/auth/login` 
for a user with `HIBPCheckStatus: "pending"` triggers an 
asynchronous HIBP re-check. After the check completes (with HIBP 
now reachable), the User's `HIBPCheckStatus` is updated to 
`"clean"` or `"compromised"`.

**AC-PW-08** — When the async re-check finds the password 
compromised, the User's `PasswordCompromised` is set to `true`, 
and an audit event `password_compromised_detected` is emitted.

**AC-PW-09** — `GET /api/v1/auth/me` for a user with 
`PasswordCompromised: true` returns the field in the response 
JSON. The frontend's compromised-password banner renders.

**AC-PW-10** — `POST /api/v1/auth/me/password` with correct 
`currentPassword` and valid `newPassword` returns 204, updates 
`User.PasswordHash`, sets `HIBPCheckStatus: "pending"`, sets 
`PasswordCompromised: false`, and revokes all other sessions of 
this user.

**AC-PW-11** — `POST /api/v1/auth/me/password` with wrong 
`currentPassword` returns 401 with 
`{"error": "current password is incorrect"}`. The session is not 
modified.

**AC-PW-12** — With `ARENET_HIBP_DISABLED=true`, no HIBP HTTP 
request is made (verified by network logs). New users get 
`HIBPCheckStatus: "skipped"`.

### 10.6 Audit log

**AC-AUDIT-01** — A successful login emits an `Event` with 
`Action: "login_success"`, `ActorUserID` set, 
`ActorUsernameSnapshot` matching the username, `IP` set, 
`UserAgent` set, `BeforeJSON` and `AfterJSON` both nil.

**AC-AUDIT-02** — A failed login emits an event with 
`Action: "login_failure"`, `ActorUserID` empty (no matching user), 
`ActorUsernameSnapshot` set to the attempted username (truncated 
to 32 chars), `Message: "user_not_found"` or `"bad_password"`.

**AC-AUDIT-03** — A successful logout emits an event with 
`Action: "logout"`, `Message: "manual"`.

**AC-AUDIT-04** — `POST /api/v1/routes` (route create) emits 
`Action: "route_created"`, `TargetType: "route"`, `TargetID` set 
to the new route's ID, `BeforeJSON: nil`, `AfterJSON` containing 
the created route. Emission is AFTER the Caddy reload succeeds 
(decision D2).

**AC-AUDIT-05** — `PUT /api/v1/routes/{id}` emits 
`Action: "route_updated"`, with `BeforeJSON` containing the 
previous route state and `AfterJSON` containing the new state.

**AC-AUDIT-06** — `DELETE /api/v1/routes/{id}` emits 
`Action: "route_deleted"`, with `BeforeJSON` containing the 
deleted route state and `AfterJSON: nil`.

**AC-AUDIT-07** — `GET /api/v1/audit` (loading the audit page) 
emits an `Action: "audit_viewed"` event with the filters used in 
the `Message` field.

**AC-AUDIT-08** — `GET /api/v1/audit` returns events in 
descending chronological order (most recent first).

**AC-AUDIT-09** — `GET /api/v1/audit?action=login_failure` 
returns only events with `action == "login_failure"`. Other 
actions are filtered out.

**AC-AUDIT-10** — `GET /api/v1/audit?from=2026-05-01T00:00:00Z` 
returns only events with `timestamp >= 2026-05-01T00:00:00Z`.

**AC-AUDIT-11** — `GET /api/v1/audit?limit=10` returns at most 
10 events. The response includes `nextCursor` if there are more.

**AC-AUDIT-12** — Passing the previous `nextCursor` back as 
`cursor` query parameter returns the next page of events, no 
overlap and no skip.

**AC-AUDIT-13** — Audit events are written AFTER the business 
mutation completes (verified by killing the server between the 
mutation and the audit append; the mutation persists but the 
audit event does not, per decision D2 best-effort policy).

**AC-AUDIT-14** — Audit `BeforeJSON` and `AfterJSON` never 
contain `PasswordHash`, session tokens, or any other secret 
field. Verified by inspecting events emitted during `setup_admin_created`.

### 10.7 Trusted proxies

**AC-PROXY-01** — With `ARENET_TRUSTED_PROXIES` empty or unset, 
the client IP in audit events is always derived from 
`r.RemoteAddr`, regardless of any `X-Forwarded-For` sent by the 
caller.

**AC-PROXY-02** — With `ARENET_TRUSTED_PROXIES=10.0.0.0/8` and 
a request from `10.0.0.1` carrying 
`X-Forwarded-For: 203.0.113.5`, the client IP in audit events is 
`203.0.113.5`.

**AC-PROXY-03** — With `ARENET_TRUSTED_PROXIES=10.0.0.0/8` and 
a request from `192.168.1.1` (not in trusted range) carrying 
`X-Forwarded-For: 203.0.113.5`, the client IP in audit events 
is `192.168.1.1` (the forged header is ignored).

**AC-PROXY-04** — With `ARENET_TRUSTED_PROXIES=10.0.0.0/8` and 
a request from `10.0.0.1` carrying 
`X-Forwarded-For: 203.0.113.5, 10.0.0.7`, the client IP is 
`203.0.113.5` (leftmost entry).

**AC-PROXY-05** — With `ARENET_TRUSTED_PROXIES="10.0.0.0/33"` 
(malformed CIDR), the server fails to start and logs 
`ERROR auth: invalid CIDR in ARENET_TRUSTED_PROXIES`.

**AC-PROXY-06** — Loopback addresses `127.0.0.1` and `::1` are 
not auto-trusted. Without explicit inclusion in 
`ARENET_TRUSTED_PROXIES`, requests from loopback have their 
`X-Forwarded-For` ignored.

**AC-PROXY-07** — At server startup, an `slog.Info` line records 
the parsed trusted CIDRs (or "no trusted proxies configured" if 
empty).

### 10.8 Frontend integration

**AC-FE-01** — At application mount, the layout calls 
`/api/v1/auth/me`. While the call is in flight, the page shows a 
centered spinner with no other chrome.

**AC-FE-02** — When `/me` returns 401 and the user is not on 
`/login` or `/setup`, the layout navigates to `/login`.

**AC-FE-03** — When `/me` returns 200 with `locked: false`, the 
sidebar and main content render normally.

**AC-FE-04** — When `/me` returns 200 with `locked: true`, the 
sidebar and main content render normally AND the `LockScreen` 
overlay appears on top.

**AC-FE-05** — The `LockScreen` overlay covers the entire 
viewport with `backdrop-filter: blur(...)`. The underlying UI 
(scroll position, open modals, form drafts) remains intact and 
re-appears after a successful unlock.

**AC-FE-06** — The `LockScreen` displays the username of the 
locked user (read from `auth.user.username`).

**AC-FE-07** — Successful unlock from the `LockScreen` transitions 
`auth.state` from `locked` to `authenticated`. The LockScreen 
unmounts via the parent `{#if}`.

**AC-FE-08** — The compromised-password banner appears at the top 
of the layout when `auth.user.passwordCompromised === true`. 
Clicking "Change password" opens the `ChangePasswordModal`.

**AC-FE-09** — A successful password change via the modal 
triggers `auth.bootstrap()`, which re-fetches `/me`. The banner 
disappears reactively.

**AC-FE-10** — A toast notification reading "Password changed 
successfully. Other sessions have been signed out." appears after 
a successful password change.

**AC-FE-11** — The audit page (`/audit`) auto-applies filter 
changes with a 300ms debounce. Typing in the "From" field issues 
a new API call 300ms after the last keystroke.

**AC-FE-12** — Action badges on audit rows are colored by 
category (Auth: cyan, Mutation: amber, Security: red, HIBP: 
violet, Meta: slate). Clicking a badge sets the action filter to 
that row's action value.

**AC-FE-13** — Clicking the actor filter icon on an audit row 
sets the `actorUserId` filter to that row's value.

**AC-FE-14** — Clicking anywhere on an audit row (excluding the 
action badge and actor filter icon) expands the row to show full 
details: full timestamp, full IDs, IP, User-Agent, message, and 
Before/After JSON.

**AC-FE-15** — The sidebar has exactly five items in this order: 
Routes (active), Audit (active), Topology (disabled), Security 
(disabled), Settings (disabled).

**AC-FE-16** — Every authenticated API call sends the cookie 
(`credentials: 'include'`). Verified by inspecting the request 
headers in browser dev tools.

**AC-FE-17** — Heartbeat fires only when 
`document.visibilityState === 'visible'`. Verified by hiding the 
tab and confirming no heartbeat requests in network logs.

### 10.9 Configuration

**AC-CONFIG-01** — Setting `ARENET_ADMIN_USERNAME` and 
`ARENET_ADMIN_PASSWORD` at first boot (when no admin exists) 
creates the admin automatically without requiring the setup flow.

**AC-CONFIG-02** — Setting `ARENET_ADMIN_USERNAME` and 
`ARENET_ADMIN_PASSWORD` when an admin already exists does nothing 
(no overwrite, no error). A startup `slog.Info` line records that 
the env vars are ignored because an admin exists.

**AC-CONFIG-03** — `ARENET_HIBP_DISABLED=true` disables all HIBP 
HTTP calls. New users get `HIBPCheckStatus: "skipped"`. The 
compromised-password banner never appears.

**AC-CONFIG-04** — `ARENET_HIBP_DISABLED` with any value other 
than `"true"` (case-sensitive) leaves HIBP enabled. The value 
`"True"`, `"1"`, `"yes"` do NOT disable HIBP.

**AC-CONFIG-05** — `ARENET_TRUSTED_PROXIES` parsing follows 
Section 8.2. Acceptance criteria covered by AC-PROXY-01 through 
AC-PROXY-07.

### 10.10 Security non-goals reminder

The following are explicitly NOT delivered in Step D and are 
documented here so reviewers do not flag their absence as bugs:

- **No 2FA / MFA**: deferred to Step D2 (multi-user). Step D is 
  single-admin, password-only.
- **No multi-user / role-based access**: Step D Phase 1 has 
  exactly one user (admin role implicit). Phase 2 will introduce 
  admin/editor/viewer roles.
- **No OIDC / SSO**: deferred to Step D3. Step D does not 
  integrate with Authentik, Authelia, Keycloak, or any external 
  identity provider.
- **No dedicated password-change page**: Step D's only entry point 
  for password change is the modal launched from the 
  compromised-password banner. Phase 2 will add a `/settings` 
  page with routine password management.
- **No password reset flow**: there is no "forgot password" link. 
  If the admin loses their password, the recovery path is to 
  delete the BoltDB file (loses all data) or to use a future 
  CLI admin tool (Phase 2).
- **No account lockout per user**: rate limiting is per-IP, not 
  per-user. A locked-out admin can switch IPs to retry. This is 
  acceptable in a single-admin homelab context; multi-user 
  deployments in Phase 2 will revisit.
- **No security dashboard / webhook**: visibility of blocked IPs 
  and threat-related signals is deferred to Step F (see 
  `docs/roadmap.md`).
- **No Coraza WAF / advanced threat detection**: deferred to 
  Step G (see `docs/roadmap.md`).

## 11. Out of scope (deferred to future steps)

This section enumerates work that is intentionally deferred beyond 
Step D, organized by the milestone where it will be delivered. It 
serves as the planning counterpart to Section 10.10: while 10.10 
tells reviewers what NOT to flag as missing in the current step, 
Section 11 tells the architect where each deferred concern lives 
on the roadmap.

The canonical source of truth for milestone planning is 
`docs/roadmap.md`. This section reflects the state of that 
document at Step D spec freeze and may diverge slightly as the 
roadmap evolves.

### 11.1 Overview

Step D is the foundation: single-admin authentication with 
password protection, session management, lock screen, audit log, 
and HIBP integration. Building on this foundation, future steps 
add complementary capabilities without rewriting the core.

The deferred items fall into three categories:

- **Authentication extensions** (Step D2, D3): expand the auth 
  model — multi-user, 2FA, OIDC.
- **Operational maturity** (Phase 2 of Step D, Step F): polish 
  the UI and add security observability.
- **Network-layer defense** (Step G, H): integrate WAF and IP 
  reputation.

Plus a small set of features that are **permanently out of scope** 
for design or feasibility reasons (Section 11.8).

### 11.2 Deferred to Step D2 (Multi-user + 2FA)

Step D2 transforms Arenet from single-admin to multi-user:

- **Multi-user with roles**: `admin`, `editor`, `viewer`. Admins 
  manage users and have full access; editors create/modify 
  routes; viewers see configuration and audit log read-only.
- **2FA / MFA**: TOTP (RFC 6238) as the primary second factor, 
  with WebAuthn (FIDO2) as the modern alternative for users with 
  hardware keys.
- **Account-level lockout**: a per-user failure counter, separate 
  from the existing per-IP rate limiter. Prevents an attacker 
  from cycling IPs to attack a single user.
- **User management UI**: a `/users` page for admins to create, 
  disable, delete users, and reset their 2FA.
- **Per-role audit visibility** (decision D10): editors see only 
  events tied to their own actions or to routes they manage; 
  admins see everything.
- **Per-role field filtering**: certain fields (other users' IPs, 
  other users' display names) may be redacted for editors/viewers 
  in the audit response.

### 11.3 Deferred to Step D3 (OIDC integration)

Step D3 enables single sign-on for users already invested in an 
identity provider:

- **OIDC client**: integration with GoAuthentik, Authelia, and 
  Keycloak. These three are explicit targets because they cover 
  the most popular self-hosted identity providers used in homelab 
  environments.
- **Authorization Code with PKCE flow**: redirect to provider → 
  callback → state and PKCE verification → session creation.
- **Group-to-role mapping**: a configurable mapping of provider 
  groups (e.g. "arenet-admins") to Arenet roles 
  (admin/editor/viewer).
- **Mixed authentication**: local password users (from Step D) 
  and OIDC users coexist. Admins choose at user creation whether 
  the user is local or OIDC-bound.
- **Logout propagation**: a logout from Arenet optionally 
  triggers a back-channel logout at the OIDC provider (RP-Initiated 
  Logout per OIDC spec).

### 11.4 Deferred to Phase 2 of Step D

These are enhancements to Step D itself, queued behind more 
urgent steps but explicitly recognized as desirable:

- **Dedicated `/settings` page**: routine password management 
  (not driven by the compromised-password banner), profile 
  display name editing, active sessions overview with revoke 
  buttons.
- **URL query parameters for audit filters**: filters reflected 
  in the URL (e.g. `/audit?action=login_failure&from=2026-05-01`) 
  to support bookmark and share.
- **Sortable audit table columns**: click column header to 
  sort. Backend support requires extending `audit.Filter` with 
  a sort key.
- **Syntax highlighting in audit JSON view**: lightweight 
  tokenizer for keys, strings, numbers, booleans. Considered 
  but skipped in Step D for bundle size.
- **Side-by-side diff in audit expanded rows**: for events with 
  both `BeforeJSON` and `AfterJSON` (e.g. `route_updated`), 
  render a visual diff. Requires a diff library or custom 
  implementation.
- **Audit log retention policy**: configurable automatic purge 
  of events older than N days. Step D ships with no retention 
  (events accumulate forever), which is fine for low-volume 
  homelab use but becomes a concern at higher scales.
- **Audit log export**: CSV and JSON download, optionally 
  filtered by the current view. Useful for compliance reviews.
- **Structured field-level errors at `/setup`**: replace the 
  heuristic substring-matching of error messages with explicit 
  `{field, error}` pairs in the response. Requires a 
  wire-format change.
- **Auto-detection of "no admin exists"**: a small endpoint 
  (`/api/v1/setup-status`) that lets the frontend redirect 
  to `/setup` on first boot without the user needing to know 
  the URL.

### 11.5 Deferred to Step F (Security observability)

Step F adds operator-facing visibility into security events:

- **Security UI page**: a new sidebar entry surfacing blocked 
  IPs from the rate limiter (Tier 2 hits), recent suspicious 
  activity, and aggregate counts.
- **Webhook for security events**: configurable endpoint that 
  receives JSON payloads on Tier 2 rate-limit hits and other 
  security signals. Designed for integration with FortiGate, 
  Slack, Discord, ntfy, or any inbound webhook receiver.
- **Real-time alerting on suspicious patterns**: e.g. login 
  attempts on a non-existent username across multiple IPs 
  (distributed scan), or repeated `unlock_failure` from the 
  same session (compromise attempt).
- **IP geolocation enrichment**: optional integration with 
  MaxMind GeoIP or similar to display country/city in audit 
  events. Local database, no external calls per request.
- **User-Agent parsing**: categorize UAs (browser, OS, bot, 
  unknown) for faster scanning in the audit log.

The rate limiter in Step D already collects the underlying 
data (`GetBlockedIPs()` in Section 5.3) but does not expose it 
via HTTP. Step F bridges that gap.

### 11.6 Deferred to Step G (Web Application Firewall)

Step G integrates a WAF layer in front of business endpoints:

- **Coraza WAF integration**: embedded WAF module in the 
  request pipeline, evaluating requests against rulesets.
- **OWASP Core Rule Set**: standard CRS rules for SQL 
  injection, XSS, command injection, etc.
- **Custom rules**: operator-defined rules per route (e.g. 
  block specific user agents, enforce JSON-only on API 
  endpoints).
- **WAF event logging**: rule hits feed into the audit log as 
  new event types (`waf_blocked`, `waf_warned`), correlatable 
  with auth events.

The WAF runs inside Arenet's binary (not as a separate process), 
preserving Step C's single-binary deployment model.

### 11.7 Deferred to Step H (IP reputation)

Step H enriches the threat model with external intelligence:

- **AbuseIPDB integration**: real-time check of incoming IPs 
  against AbuseIPDB's database, with configurable thresholds 
  for warning vs blocking.
- **Threat intel feeds**: configurable ingestion of CIDR 
  blocklists (Spamhaus DROP, Emerging Threats, etc.).
- **Pre-emptive blocking of known-bad IPs**: rejected at the 
  earliest middleware layer, before auth or business logic 
  runs.
- **Integration with security audit**: pre-emptive blocks 
  emit audit events for visibility.

### 11.8 Permanently out of scope

The following features are deliberately excluded from Arenet's 
long-term roadmap. Listing them here protects against scope 
creep and clarifies the product's design philosophy.

- **Account recovery via email**: Arenet has no email 
  infrastructure and will not acquire one. Email is a 
  significant operational concern (SMTP credentials, 
  deliverability, anti-spam coordination) disproportionate to 
  the value for a self-hosted admin tool. The recovery path 
  for a lost password is operator action (admin CLI tool, 
  Phase 2) or database surgery.

- **SMS-based 2FA**: requires a paid carrier (Twilio, etc.), 
  introduces dependencies, and is no longer considered a 
  strong second factor by NIST 800-63B due to SIM-swap 
  attacks. Step D2 will offer TOTP and WebAuthn instead.

- **Biometric authentication**: hardware-dependent (fingerprint 
  reader, camera), browser-specific (WebAuthn already covers 
  this where supported), and inconsistent across the 
  self-hosted homelab user base.

- **Passwordless flows (magic links, etc.)**: the design 
  philosophy of Arenet treats the password as the primary 
  factor, complemented by 2FA in D2 and SSO in D3. Throwaway 
  flows like magic links shift the security boundary to the 
  user's email inbox, which is rarely better protected than 
  their Arenet password.

- **Federation between Arenet instances**: a multi-instance 
  mesh with shared identity or shared routes is out of scope. 
  Arenet is a single-instance admin tool; users wanting 
  multi-site coordination should use a higher-level 
  orchestrator (Terraform, Ansible) above multiple 
  independent Arenet instances.

These exclusions are not final in the sense of "we will never 
reconsider them" — software is soft. But they represent the 
current product direction and the reasoning behind it. Future 
reviewers should weigh proposals to reverse these decisions 
against the rationale above.
