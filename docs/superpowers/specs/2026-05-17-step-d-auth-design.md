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
    HIBPCheckStatus     string    `json:"hibp_check_status"`    // "pending" | "clean" | "compromised"
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

Step D adds nine new HTTP endpoints. Eight are under `/api/v1/auth/*`,
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
  `"compromised"`. Useful for the frontend to show a "verifying
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
