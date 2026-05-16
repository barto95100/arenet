# Step D — Design Decisions

**Date**: 2026-05-16
**Status**: Decisions taken, spec writing pending
**Project**: Arenet (homelab-friendly reverse proxy with embedded Caddy)
**Predecessors**: Step C closed (REST API + SvelteKit admin UI, 43 commits)
**Successor**: Step D spec writing → plan → implementation

## Purpose

This file captures the six design decisions taken during the Step D brainstorming
session on 2026-05-16. The next session will use them as the input for the full
design spec (`docs/superpowers/specs/YYYY-MM-DD-step-d-auth-design.md`). No code
should be written from these decisions alone — they are the pre-spec checkpoint.

---

## Q1 — Session mechanism

**Decision**: Cookie-based session, server-side state.

- **Cookie attributes**: `HttpOnly`, `Secure`, `SameSite=Strict`.
- **Storage**: session state persisted in BoltDB (new bucket, separate from
  routes). Each session row holds: session ID, user ID, issued-at, expires-at,
  last-activity timestamp, remember-me flag, source IP at issue time, user-agent
  at issue time.
- **Cookie value**: opaque random session ID (e.g. 256-bit base64), NOT a JWT.
  Server is authoritative; revocation is a row delete.

**Rationale**: Browser-only admin tool, no need for stateless JWT complexity.
Server-side state allows instant revocation, per-session metadata, and audit
trail correlation. Cookie + HttpOnly + Strict eliminates XSS token theft and
CSRF on cross-site form submissions.

**Implications**:
- All authenticated API calls and frontend navigations rely on the cookie being
  attached automatically by the browser.
- The `Secure` flag means HTTPS is required in production; in dev mode it must
  be relaxed (see Q1 implementation notes when the spec is written).
- A logout endpoint deletes the BoltDB row and clears the cookie.

---

## Q2 — First-boot admin bootstrap

**Decision**: Hybrid mode — Setup UI by default, token in logs as fallback,
env override for fully unattended deployments.

- **Default path (interactive)**: on first boot, if no admin user exists in
  BoltDB, the frontend redirects every route to `/setup` regardless of auth
  state. The setup form collects: admin username, password (with confirmation),
  optional display name. Submitting creates the admin user and immediately logs
  the session in.
- **Token-in-logs path**: when the binary starts and no admin exists, it also
  logs a one-shot setup token (random 32 bytes hex) at INFO level. Hitting
  `/setup?token=<token>` bypasses the form's "is this really first boot?" guard
  for headless/automation scenarios where the operator can read logs but cannot
  use a browser yet.
- **Env override path**: setting `ARENET_ADMIN_USERNAME` and
  `ARENET_ADMIN_PASSWORD` at first boot creates the admin user
  non-interactively. Useful for Docker/k8s/ansible deployments. Takes
  precedence over the token-in-logs path.

**Rationale**: Homelab users typically have a browser. Token-in-logs handles
the edge case of installing via SSH-only. Env override handles full automation.
None of the three relies on a default password.

**Implications**:
- One BoltDB user row from boot onwards. Multi-admin is out of scope for
  Phase 1 (revisit when needed).
- The setup route is guarded by "no admin exists" — once set up, hitting
  `/setup` returns 404 or redirects to login.

---

## Q3 — Session duration

**Decision**: 24h sliding TTL by default, 30 days when "Remember me" is checked
at login.

- **Default session (no remember me)**:
  - Issued with a 24h `expires_at`.
  - Every authenticated request extends `expires_at` forward by 24h from the
    moment of the request (sliding window).
  - Closing the browser does NOT invalidate the cookie (it's a persistent
    cookie with an explicit expiration, not a session cookie) — but inactivity
    for 24h does.
- **Remember-me session**:
  - Issued with a 30-day `expires_at`.
  - Same sliding extension on every authenticated request.
  - Survives browser restarts trivially.

**Rationale**: 24h is a reasonable balance between "stay logged in while I
work" and "auto-logout if I forget". Remember-me serves the "this is my own
homelab on my trusted laptop" case. Sliding TTL prevents mid-task expiration
during long sessions.

**Implications**:
- A background goroutine periodically purges expired sessions from BoltDB
  (every 5 minutes or so). Lazy deletion on next lookup is also acceptable
  (verify in spec which is simpler given bbolt's API).
- Cookie `Max-Age` matches the BoltDB `expires_at` so client and server stay
  in sync.

---

## Q3bis — Inactivity lock

**Decision**: 15 minute client-side inactivity timer, server-side activity
authority, Pattern B (lock-screen overlay), defense-in-depth.

- **Idle threshold**: 15 minutes of no user activity in the browser tab.
- **Activity definition**: mouse move, key press, scroll, click. NOT
  background tab visibility events.
- **Authority**: the server's `last_activity` column is the source of truth.
  The client UI's 15-minute timer is a UX nicety, not the security boundary.
  This means the server enforces inactivity even if the client clock is
  manipulated.
- **Lock UX**: when the client detects 15 minutes idle, it overlays a "Lock
  screen" component on the current page that requires re-entering the
  password to dismiss. The page state behind the lock is preserved (form
  inputs, scroll position, open modals — all kept in memory). On unlock, the
  user resumes exactly where they were.
- **Defense in depth**: the server returns 403 Forbidden (not 401) when a
  request arrives with a session that has been idle > 15 minutes. The client
  catches this status and triggers the lock screen even if its own timer
  hasn't fired yet (clock drift, network resume from sleep, etc.).
- **Distinct from session expiration**: the lock is a soft re-auth. The
  session itself is NOT invalidated by the lock; only inactivity > 24h (or
  > 30d for remember-me) ends the session entirely.

**Rationale**: Pattern B was chosen over Pattern A (full re-login destroying
state) because admin tasks often involve filling forms over many minutes
and losing input to a lock screen is hostile. The 403 vs 401 distinction
lets the client distinguish "re-auth in place" from "session is gone, go to
login page".

**Implications**:
- A new `lock_screen` state lives in the frontend `+layout.svelte` (or a
  store) and gates pointer events behind a modal-like overlay.
- The lock screen calls a dedicated `/api/v1/auth/unlock` endpoint that
  accepts the current session cookie + password and, on success, updates the
  session's `last_activity` to now.
- This is more code than a simple "expire and re-login" flow, but the UX win
  is real for an admin tool.

---

## Q4 — Password hashing

**Decision**: argon2id via `github.com/alexedwards/argon2id`, OWASP 2024
recommended parameters.

- **Library**: `github.com/alexedwards/argon2id` (MIT, well-maintained,
  uses Go's `golang.org/x/crypto/argon2` under the hood).
- **Parameters**:
  - Memory: 64 MiB
  - Iterations (time): 3
  - Parallelism: 4
  - Salt length: 16 bytes
  - Key length: 32 bytes
- **Hash format**: standard PHC string format
  `$argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>` — stored in BoltDB
  as the user row's `password_hash` column.
- **Verification**: `argon2id.ComparePasswordAndHash(password, hash)` (constant
  time, library handles all parsing).

**Rationale**: argon2id is the OWASP-recommended modern hash for password
storage (Memory-hard, side-channel resistant). The `alexedwards/argon2id`
wrapper avoids re-implementing PHC string encoding. OWASP 2024 parameters
balance security against a homelab CPU (64MiB × 3 iterations ≈ 200-500ms on
modern hardware, acceptable for an admin login that happens once per day).

**Implications**:
- A user row stores ONLY the PHC hash, never the plaintext.
- Setup, login, unlock, and "change password" all call
  `CreateHash` / `ComparePasswordAndHash` from the same library.
- Parameters are constants in a `crypto` or `auth` sub-package; future
  rotation is documented but not automatic (re-hashing on next login is a
  follow-up if params ever change).

---

## Q5 — Audit log

**Decision**: Extended pack — full schema with UUID v7 IDs, username snapshot,
before/after JSON diffs, IP + UA, dedicated BoltDB bucket, atomic transactions,
admin UI page `/audit` with filters, no automatic retention.

- **Schema** (one row per audit event):
  - `id`: UUID v7 (time-sortable, monotonic), used as the bucket key for natural
    chronological ordering.
  - `timestamp`: redundant with v7 ID but stored explicitly for readability.
  - `actor_user_id`: foreign reference to the user row at the time of action.
  - `actor_username_snapshot`: the username string at the time of the event.
    Stored even though `actor_user_id` is present, because users can be
    renamed in the future and the audit log must remain readable post-rename.
  - `action`: enum string (login_success, login_failure, logout, unlock_success,
    unlock_failure, route_create, route_update, route_delete,
    setup_admin_created, password_changed, session_revoked, …).
  - `target_type`: `"route" | "user" | "session" | null` depending on action.
  - `target_id`: ID of the affected resource, or null.
  - `before_json`: JSON snapshot of the resource before the change (null on
    create / pure read-style events).
  - `after_json`: JSON snapshot of the resource after the change (null on
    delete).
  - `ip`: client IP at the time of the action.
  - `user_agent`: HTTP `User-Agent` string at the time of the action.
- **Storage**: dedicated BoltDB bucket `audit`, separate from `routes`,
  `users`, `sessions`. Keys are UUID v7 (bytes), values are the JSON-marshaled
  row.
- **Atomicity**: every mutation that produces an audit event writes the
  business mutation AND the audit row in the SAME bbolt transaction. This
  guarantees that an audit log line cannot exist without its underlying
  mutation and vice versa. Caddy reload still happens outside the transaction
  (after commit); the audit row is written even if Caddy reload subsequently
  fails (the rollback path generates an additional audit row of action
  `route_create_rolled_back` or similar — to be detailed in the spec).
- **Admin UI**: a new page at `/audit` (sidebar item enabled in Step D,
  replacing the disabled placeholder of Step C). Renders a paginated reverse-
  chronological table with filter bar: by actor, by action type, by date
  range, by target. Each row expandable to show the full before/after JSON
  diff.
- **Retention**: NONE automatic in Phase 1. The bucket grows indefinitely.
  Operators can manually prune via a future maintenance CLI. Storage is cheap
  for a homelab admin tool and audit completeness is more valuable than disk
  savings.

**Rationale**: The "extended pack" was chosen over the minimal version
because audit logs are write-once and replaying history is critical when
investigating a suspected compromise. Storing username snapshots and full
before/after diffs avoids the standard "we renamed the user, now the old
audit log shows a confusing 'unknown_user_42 deleted route X'" problem.

**Implications**:
- All mutating handlers in `internal/api` gain an audit emission step inside
  the same transaction as the storage mutation. Storage layer exposes a
  `WithAudit(ctx, mutation, audit)` or similar helper to keep the API
  ergonomic.
- The sidebar gains a 5th item ("Audit") that is enabled after Step D
  (whereas Topology/Security/Settings remain disabled until later steps).
- UUID v7 generation needs a library (or a small implementation) —
  `github.com/google/uuid` v1.7+ supports it via `uuid.NewV7()`.

---

## Q6 — Auth endpoints

**Decision**: 6 endpoints under `/api/v1/auth/*`, rate-limited by IP, with
clean 401/403 separation.

- **Endpoints**:
  - `POST /api/v1/auth/setup` — first-boot only, creates admin user.
    Returns 404 if an admin already exists. Body: `{username, password,
    displayName?, token?}` (token required if setup token mechanism is
    used). On success: 201 + sets session cookie.
  - `POST /api/v1/auth/login` — body `{username, password, rememberMe}`.
    Returns 200 + sets session cookie on success. Returns 401 on bad
    credentials with a generic message ("invalid username or password" —
    do not reveal whether the username exists).
  - `POST /api/v1/auth/logout` — invalidates the current session (cookie
    required). Returns 204. Clears cookie via Set-Cookie expiry.
  - `POST /api/v1/auth/unlock` — body `{password}`. Cookie must be present
    and the session must NOT be expired (only idle-locked). On success
    updates `last_activity` and returns 200. On failure returns 401 (counts
    against rate limit).
  - `GET /api/v1/auth/me` — returns the current authenticated user's row
    (username, displayName, createdAt). Used by the frontend on initial
    page load to bootstrap the auth state and pick between login screen,
    setup screen, or normal app shell.
  - `GET /api/v1/auth/sessions` — lists the current user's active sessions
    (id, ip, ua, issued_at, last_activity, current?). Useful for "log me
    out everywhere" or visibility. A companion `DELETE
    /api/v1/auth/sessions/{id}` revokes a specific session.

- **Rate limiting**: per source IP, sliding window.
  - **Tier 1**: 5 failed auth attempts in 5 minutes → return 429 with
    `Retry-After`. Failed = `login` returning 401, `unlock` returning 401,
    `setup` returning 401, anything else producing a 401.
  - **Tier 2**: 10 failed attempts in 1 hour → return 429 with a longer
    `Retry-After` (15-60 minutes, to be decided in spec).
  - Successful auth resets the counters for that IP.
  - Implementation: in-memory ring buffer or a `golang.org/x/time/rate`
    limiter keyed by IP. Persisted across restarts? NO — Phase 1 keeps it
    in-memory; restarting Arenet resets the counters (acceptable because
    restarts are infrequent and an attacker who can trigger restarts has
    deeper problems).

- **401 vs 403 distinction**:
  - **401 Unauthorized**: no valid session, or session expired entirely.
    Client redirects to the full login screen, state is lost. Emitted by
    `login` (bad creds), any endpoint requiring auth when cookie is absent
    or invalid, and any endpoint when the session is expired.
  - **403 Forbidden**: valid session, but locked due to inactivity (> 15
    minutes). Client triggers the lock-screen overlay (Q3bis Pattern B),
    page state preserved. Emitted by any authenticated endpoint when
    `last_activity + 15min < now` AND the session is otherwise valid.
  - Frontend `client.ts` intercepts 401 and 403 differently and dispatches
    accordingly.

**Rationale**: Six endpoints is the minimum coherent surface for login +
logout + lock + bootstrap + introspection. Per-IP rate limit is the
standard mitigation against credential stuffing for a single-admin tool
where a real user wouldn't trigger more than a handful of attempts. Clean
401/403 separation is what enables Q3bis Pattern B; without it the lock
screen wouldn't know when to fire.

**Implications**:
- New middleware in `internal/api` reads the cookie, looks up the session
  in BoltDB, checks expiration and last-activity, and injects the user into
  the request context. This middleware sits between Recoverer and the
  per-route handlers, after the dev CORS middleware.
- The dev CORS middleware in Step C must be updated when Step D lands to
  add the `Authorization` header to `Access-Control-Allow-Headers` IF the
  frontend ever uses a non-cookie auth path. With cookie-only auth it's
  not strictly needed, but it's worth documenting now to avoid a CORS
  surprise later if we add an API token mechanism.
- The frontend `lib/api/client.ts` needs an interceptor (a thin wrapper
  around `fetch`) that handles 401 (logout + redirect) and 403 (set lock
  state in a store) globally. Today's client throws an `ApiError` on
  non-2xx; this stays, but the page-level handlers need a centralized
  401/403 reaction that doesn't rely on every callsite remembering to
  redirect.

---

## Cross-cutting concerns for the spec

1. **Backwards compatibility with Step C state**: existing Step C admin tools
   (curl on `/api/v1/routes`) currently work without any auth. Step D
   introduces a hard auth requirement. The dev landing page and a "no admin
   bootstrapped yet" branch are the only unauthenticated paths.

2. **Migration**: a clean Step D install has zero users → setup flow fires.
   An upgrade from Step C (which had no auth) has zero users in the new
   `users` bucket → setup flow fires. No data loss for existing routes.

3. **CSRF**: with `SameSite=Strict` cookies, classic CSRF is neutralized.
   No need for explicit anti-CSRF tokens in Phase 1. Document this
   explicitly in the spec so a future reviewer doesn't add CSRF tokens
   unnecessarily.

4. **Audit log of "Caddy reload failed, rolled back" events**: the rollback
   path of Step C produces a synthetic event. The spec needs to decide
   whether this is one audit row (`route_create_rolled_back`) or two
   (`route_create` + `route_create_rolled_back`). My initial preference is
   one row with action `route_create_rolled_back` and `before_json: null`,
   `after_json: null`, plus an explanatory message field — but defer to
   spec writing.

5. **What about logout-all?** A `DELETE /api/v1/auth/sessions` (without
   id) that revokes all sessions for the current user is a natural
   extension of Q6's session list endpoint. Not in the initial 6 but trivial
   to add — flag in spec.

---

## Next steps

1. Open new session.
2. Use `superpowers:brainstorming` skill to confirm these decisions and
   surface anything missing.
3. Write the full design spec at
   `docs/superpowers/specs/2026-05-17-step-d-auth-design.md` based on this
   decisions file.
4. `superpowers:writing-plans` to produce the implementation plan.
5. Execute via `subagent-driven-development` for the backend
   (storage/auth, middleware, handlers) and `executing-plans` for the
   frontend (login screen, setup screen, lock screen, audit page).

End of decisions document.
