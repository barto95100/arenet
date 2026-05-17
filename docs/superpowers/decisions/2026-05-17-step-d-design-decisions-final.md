# Step D — Design Decisions (Final)

Date: 2026-05-17
Status: AUDIT COMPLETE — Ready for spec writing

## Validated foundation decisions (Q1-Q6, validated 2026-05-16 late evening)

Q1 — Session mechanism
- Cookie HttpOnly Secure SameSite=Strict (Secure off in --dev mode for HTTP local)
- Opaque 256-bit base64 token (cookie value)
- State persisted in BoltDB bucket "sessions"

Q2 — First-boot admin bootstrap
- Setup UI as primary flow
- Setup token (32 bytes random) generated at each boot until admin exists
- Token displayed in server logs only
- Override via env vars ARENET_ADMIN_USERNAME and ARENET_ADMIN_PASSWORD for Docker/K8s automation

Q3 — Session duration
- 24h sliding default (refreshed on each authenticated request)
- 30 days sliding if "Remember me" checkbox checked at login
- Lazy deletion on expired lookup
- Cleanup goroutine every 6h to evict definitively expired sessions

Q3bis — Inactivity lock screen
- 15 minutes of server-side inactivity triggers lock
- Pattern B: lock screen overlay, UI state preserved behind it
- Activity defined as: action server (any API call except /auth/me and /auth/heartbeat)
- Defense in depth: client-side timer + server-side last_activity check
- /auth/me does NOT update last_activity (otherwise lock screen polling resets the timer)
- After unlock: user resumes exactly where they were (modals, filters, etc.)

Q4 — Password hashing
- argon2id via github.com/alexedwards/argon2id
- Parameters: memory=64 MiB, iterations=3, parallelism=4, salt=16 bytes, key=32 bytes
- PHC string format storage

Q5 — Audit log
- Pack: extended (auth events + mutations on routes/users/sessions; NOT routine reads)
- UUID v7 keys for natural time-sorting in BoltDB
- Username snapshot at action time (preserves history across renames)
- Before/After JSON for mutations
- IP + UserAgent captured
- BoltDB bucket "audit" with transactional writes
- Page /audit with filters
- NO automatic retention (manual purge via future CLI command)
- Audit reads themselves are audited (action audit_viewed)

Q6 — Auth endpoints
- 6 endpoints under /api/v1/auth/* : setup, login, logout, me, unlock, heartbeat
- Plus: GET /auth/sessions and DELETE /auth/sessions/{id} for self-management
- Rate limit per IP: Tier 1 (5 failures in 5 min → block 15 min), Tier 2 (10 failures in 1h → block 1h)
- Retry-After header on 429 responses
- 401 = re-login required, 403 = lock screen active

## Refinement decisions (D1-D11, validated 2026-05-17 morning audit)

D1 — Refactor *Tx storage methods
- ANNULLED
- Reason: D2 makes atomic mutation+audit unnecessary, so internal/storage remains unchanged

D2 — Audit placement in handlers
- Audit emission happens AFTER successful Caddy reload only
- Best-effort: audit failure logs a slog warning but does not fail the HTTP response
- Rollback paths (Caddy reload fails) are NOT audited (the system reverts to pre-mutation state)
- Pattern: validate → uniqueness → mutation → Caddy reload → audit emit (success) OR rollback (no audit)

D3 — Audit Event schema
- 10 fields: ID (UUID v7), Timestamp, ActorUserID, ActorUsernameSnapshot, Action, TargetType, TargetID, BeforeJSON, AfterJSON, Message, IP, UserAgent
- Outcome encoded directly in Action (e.g. login_success vs login_failure), no separate Outcome field
- No Metadata flexible field (typed fields preferred)
- Rule: never serialize secrets (passwords, hashes, tokens) in BeforeJSON/AfterJSON
- Message field used for free text like login_failure reason

D4 — Audit integration in handlers
- Helper Handler.appendAudit(r, evt) centralizes context enrichment (user_id, username, IP, UA)
- Interface AuditAppender defined consumer-side in internal/api (similar to CaddyReloader pattern)
- Handler struct gains an audit AuditAppender field
- NewHandler gains an audit parameter with nil-check panic
- Audit calls placed at the end of each successful mutation handler
- No audit on GET routes (read operations not audited per Q5)

D5 — Username validation
- Regex: ^[a-z0-9_-]+$ (lowercase letters, digits, underscore, hyphen)
- Length: 3..32 characters
- TrimSpace applied before validation
- Reject 400 if uppercase characters detected (no silent lowercasing)

D6 — Password validation
- Length: 15..128 characters
- No complexity rules (NIST 2017 anti-pattern)
- Common password check:
  - Local: embedded top-10k passwords list (SecLists, MIT license, ~30 KB compressed) — immediate, offline
  - HIBP: k-anonymity API check on password creation — best-effort
  - If HIBP unreachable: password accepted, marked hibp_check_status="pending"
  - Re-check at next successful login if pending
  - If detected compromised: flag user, banner UI at next login, force password change
- New User struct fields: HIBPCheckStatus, HIBPCheckedAt, PasswordCompromised

D7 — Action enum (13 events for Step D)
- Authentication: login_success, login_failure, logout
- Lock screen: unlock_success, unlock_failure
- Sessions: session_revoked
- Setup: setup_admin_created
- Password: password_changed
- Routes (renamed to past tense): route_created, route_updated, route_deleted
- Audit: audit_viewed
- HIBP: password_hibp_clean, password_hibp_pending, password_compromised_detected
- session_expired REMOVED (internal lazy purge, not user action)
- route_*_rolled_back REMOVED (per D2, rollback paths not audited)

D8 — Rate limit storage + IP extraction
- Storage: in-memory only (sync.Mutex + map)
- Documented in code: not persisted, counters reset at restart, acceptable given password strength (D6) and argon2id cost
- Trusted proxies via env var ARENET_TRUSTED_PROXIES (CIDR list, e.g. "10.0.0.0/8,192.168.0.0/16,cloudflare_ranges")
- IP extraction: prefer X-Forwarded-For if request originates from trusted proxy, else RemoteAddr
- slog WARN on every Tier 2 hit with structured fields (ip, username_attempted, blocked_until) + explicit "consider blocking at network level" message
- Internal method GetBlockedIPs() prepared for future Security dashboard (Step F)
- Security/Threat dashboard with webhook system DEFERRED to Step F (see docs/roadmap.md)

D9 — CSRF protection
- Level 1: SameSite=Strict cookie attribute only
- No explicit CSRF tokens
- Rationale documented inline in code (OWASP modern guideline, all target browsers support SameSite, scope-bounded threat model)
- Roadmap: explicit CSRF tokens reconsidered in Step D2+ if threat model changes

D10 — Audit visibility in Phase 1
- Single admin sees everything (no per-role filtering in Step D)
- Filtering by role to be added in Phase 2 (Step D2 with admin/editor roles)
- Documented in code with TODO referencing roadmap

D11 — Storage error during login
- 503 Service Unavailable returned to client with generic message "authentication service temporarily unavailable"
- Detailed error logged via slog.Error (no leak to client)
- Distinct from 401 (ErrUserNotFound is business-as-usual, returned as 401 with audit event login_failure / user_not_found)

## Section 2 architecture (validated 2026-05-16 late evening, reconfirmed 2026-05-17)

- New packages: internal/auth and internal/audit (separate, no mutual dependency)
- internal/storage exposes DB() *bolt.DB (Option A) to share the bbolt handle with new packages
- 3 new BoltDB buckets: users, sessions, audit (created in storage.NewStore alongside existing routes bucket)
- Router chi with 3 middleware groups: no-auth, soft-auth, hard-auth
- Sidebar: 5 items — Routes (active), Audit (new active), Topology (disabled, Step E), Security (disabled, Step F), Settings (disabled, Phase 2+)

## Estimated workload

Revised after morning audit:
- Backend: 21-26h
- Frontend: 14-20h
- Tests + integration: 4-6h
- Total: 39-52h (6-8 sessions at current pace)

## Out of scope (deferred)

- Multi-admin / roles → Step D2
- API tokens (Bearer auth) → Phase 2+
- SSO / OIDC → Step D3
- Password reset by email → not applicable single-admin homelab
- 2FA / TOTP → Phase 3 if exposed publicly
- Permanent account lockout → covered partially by Tier 2 rate limit
- Audit retention / export / archive → Phase 2+
- Persistent rate limit counters → in-memory acceptable for Step D
- Security/Threat dashboard + webhook → Step F (documented in docs/roadmap.md)

## Next step

Write the official design spec at docs/superpowers/specs/2026-05-17-step-d-auth-design.md based on these 17 decisions.
