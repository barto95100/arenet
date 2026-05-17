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
