# Step D — Design WIP, paused 2026-05-17 02:11

**Status**: PAUSED mid-spec drafting. Resume next session.
**Source decisions**: `docs/superpowers/decisions/2026-05-16-step-d-design-decisions.md`
**Target spec**: `docs/superpowers/specs/2026-05-17-step-d-auth-design.md` (NOT yet written — only drafted in chat).

## Why this file exists

During the 2026-05-17 spec drafting session, the assistant introduced several
sub-decisions that the user did NOT explicitly validate. None are obviously
wrong, but the user wants to audit them with a rested head before they land
in the official spec. This WIP file is the safe checkpoint: it freezes the
state of the conversation so the next session can resume cleanly.

---

## Validated decisions (Q1–Q6, explicitly confirmed during the 2026-05-16 brainstorm)

These six decisions are settled and ready to feed the spec:

1. **Q1 — Session mechanism**: cookie-based, server-side state.
   - Cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, opaque 256-bit base64
     (NOT a JWT).
   - State storage: BoltDB bucket dedicated to sessions.
   - Server is authoritative; revocation = row delete.

2. **Q2 — First-boot admin bootstrap**: hybrid mode.
   - Default: setup UI when no admin exists.
   - Fallback: one-shot setup token logged at INFO on boot.
   - Override: `ARENET_ADMIN_USERNAME` / `ARENET_ADMIN_PASSWORD` env vars
     for unattended deploys.

3. **Q3 — Session duration**: 24h sliding TTL default, 30 days with
   "Remember me". TTL extends on every authenticated request.

   **Q3bis — Inactivity lock**: 15 min idle, Pattern B (lock-screen overlay,
   page state preserved), server-side `last_activity` is authority,
   403 vs 401 distinction for client dispatch.

4. **Q4 — Password hashing**: argon2id via
   `github.com/alexedwards/argon2id` with OWASP 2024 params
   (m=64 MiB, t=3, p=4, salt 16 B, key 32 B). PHC string format stored in
   the user row.

5. **Q5 — Audit log**: extended pack.
   - UUID v7 keys (chronological), username snapshot, before/after JSON,
     IP, user-agent.
   - Dedicated BoltDB bucket `audit`.
   - Mutation + audit row in the same bbolt transaction.
   - Admin UI page `/audit` with filters (actor, action, date range,
     target). Paginated reverse-chronological.
   - No automatic retention in Phase 1.

6. **Q6 — Auth endpoints**: 6 endpoints under `/api/v1/auth/*`
   (setup, login, logout, unlock, me, sessions). Per-IP sliding rate limit
   with two tiers (5/5min, 10/1h). Strict 401 vs 403 split.

---

## Pending sub-decisions (NOT validated by user — audit at resume)

These were either tranchés by the assistant alone or surfaced as
clarifications during section drafting. All need explicit user sign-off
before landing in the spec.

### From the 2026-05-17 ambiguity pass (A1–A5)

The user replied "A1.C, A2.a, A3=regen, A4.a, A5 d'accord" at 02:00.
**Pre-validated but to re-read at rested head** — the wording below is
the assistant's transcription, double-check it matches intent:

- **A1.c — Audit reads policy**: do NOT audit reads of `/api/v1/routes`
  or page views. DO audit reads of the audit log itself
  (`audit_viewed` event). Rationale: route reads would 100× the log
  volume; audit log reads matter because an attacker would consult them
  to evaluate cover-up effort.

- **A2.a — Audit log visibility**: in Phase 1 single-admin, every admin
  sees the entire log. Revisit when multi-admin / roles are introduced.

- **A3 — Setup token regen**: the setup token is regenerated at every
  boot as long as no admin exists. The previous token is invalidated.
  No explicit expiration window — the token lives only in process memory
  and dies with the next reboot if unused.

- **A4.a — Lock during in-flight request**: the request that triggered
  the lock (because its 403 response arrived while a mutation was
  pending) is NOT replayed automatically after unlock. The user
  re-clicks Submit. Rationale: auto-replay creates subtle bugs
  (double-submit on navigation, stale state races).

- **A5 — Storage failure on auth path**: `last_activity` update is
  best-effort (warn + continue). Login returns **503 Service
  Unavailable** (not 500) if the `users` bucket is unreachable, so
  operators can distinguish "auth subsystem KO" from "unexpected
  server error".

### Sub-decisions introduced during Section 1 drafting (NOT discussed)

- **CSRF: not protected explicitly** — relies on `SameSite=Strict`
  cookies to neutralize the vector. Documented in the spec to prevent
  a future reviewer from adding redundant CSRF tokens. **Needs
  explicit validation**: is the user comfortable accepting this
  trade-off, or do they want belt-and-braces CSRF tokens anyway?

- **`message` field on audit rollback events** — when a Caddy reload
  fails after a successful storage mutation, ONE audit row is written
  (e.g. `route_create_rolled_back`) with `before_json: null`,
  `after_json: null`, and a free-text `message` field holding the Caddy
  error. The original `route_create` row is NOT emitted because the
  mutation never settled. **Needs validation**: is one row preferable
  to two (route_create then route_create_rolled_back)?

- **Rate-limit counters in-memory only** — restart of the binary
  resets the failure counters per IP. No persistence in BoltDB.
  Rationale: restarts are infrequent in homelab; an attacker capable
  of forcing restarts has deeper access. **Needs validation**:
  acceptable trade-off or worth persisting?

- **Rate-limit Tier 2 Retry-After**: assistant proposed **30 minutes**
  (midpoint of the 15-60min range in the decisions file). **Needs
  validation**: 30 min OK or pick a specific value?

### Sub-decisions introduced during Section 2 drafting (NOT discussed)

- **`storage.DB()` accessor exposed** (Option A vs refactoring into
  `storage.DB` + `storage.RouteStore`). Assistant chose Option A
  (simpler, no Step C refactor). User said "OK Option A" in their
  Section 2 validation — **considered validated**, restating here for
  trace.

- **`internal/auth` and `internal/audit` as two separate packages**
  rather than grouping under `internal/security/`. User said "OK
  séparés" — **validated**, restating here.

- **Sessions persisted in BoltDB** rather than in-memory. User said
  "OK persistance" — **validated**.

- **Audit as a 5th sidebar item** (alongside Routes / Topology /
  Security / Settings) rather than replacing Security. User said
  "OK 5e item" — **validated**.

### Sub-decisions introduced during Section 3 drafting (NOT discussed)

- **Username validation rules**: `^[a-zA-Z0-9_-]+$`, length 3..32.
  Assistant's proposal. **Needs validation**: too restrictive?

- **Password min length 12** (OWASP 2024 allows 8). Assistant's
  proposal, more conservative. **Needs validation**: 12 or 8?

- **`session_expired` audit event** added to the action enum.
  Assistant's proposal. **Needs validation**: useful visibility
  ("sessions die alone") or noise?

- **`*Tx` variants on storage methods** for atomic mutation + audit
  row writing. Assistant's proposal: refactor Step C storage to expose
  `CreateRouteTx`, `UpdateRouteTx`, `DeleteRouteTx`, `RestoreRouteTx`
  variants. **Needs validation**: refactor storage (~100 LOC touched)
  or duplicate the audit API instead?

- **Action enum** as listed in the assistant's draft — needs review
  for completeness AND naming conventions (e.g.
  `route_create` vs `routes.create` vs `RouteCreate`).

- **Per-endpoint auth gate levels** (no-auth / soft-auth / hard-auth)
  documented in middleware specifically for `/auth/logout`,
  `/auth/me`, `/auth/unlock` skipping idle check but enforcing
  session validity. User raised this point during Section 2
  validation and assistant confirmed the comportement; **considered
  pre-validated** but verify the exact mapping per endpoint at
  resume.

- **`/auth/me` does NOT update `last_activity`** to avoid the
  LockScreen polling itself out of idle. Assistant's reasoning,
  unrelated to user input. **Needs validation**.

---

## Drafted sections (in chat memory, NOT written to spec file)

The assistant drafted three sections that the user did NOT validate
end-to-end (only validated Section 1 and Section 2 outlines, paused
mid-Section 3):

### Section 1 — Goal, locked decisions, scope (drafted, NOT written)

- 1.1 Goal: 4 bullets summarizing setup, login, lock, audit + Step C
  backwards compatibility.
- 1.2 Locked decisions: 11 numbered points re-stating Q1–Q6 plus A1–A5
  plus three pre-Section-1 sub-decisions (CSRF, audit rollback message
  field, rate-limit in-memory).
- 1.3 Out of scope: 8 bullets (multi-admin, API tokens, SSO, password
  reset by email, 2FA, account lockout, audit retention, rate-limit
  persistence, pluggable audit sinks).

### Section 2 — Architecture & package boundaries (drafted, NOT written)

- 2.1 New Go packages (`internal/auth`, `internal/audit`).
- 2.2 BoltDB buckets (`users`, `sessions`, `audit`).
- 2.3 Dependencies (`alexedwards/argon2id`, `google/uuid` v1.7+).
- 2.4 Package boundary diagram.
- 2.5 `storage.DB()` accessor exposed (Option A).
- 2.6 Router structure with 3 auth gate levels.
- 2.7 Frontend file layout (login/setup/audit pages + LockScreen
  component + new stores).

### Section 3 — Storage schemas (drafted, NOT written, paused mid-section)

- 3.1 `User` struct + UserStore methods + validation rules.
- 3.2 `Session` struct + SessionStore methods + lazy expiration on Get.
- 3.3 `Event` struct + Audit Store + action enum + transactional
  variant for atomic writes.
- 3.4 Bucket initialization at `NewStore`.

Section 3 ended with 5 validation questions to the user that were never
answered (username regex, password min length, session_expired event,
storage `*Tx` refactor, action enum completeness).

---

## RESUME HERE

1. **Audit the 2026-05-17 sub-decisions block above with a rested
   head**. For each item flagged "Needs validation", confirm or
   override. Pay attention to:
   - CSRF stance (no token, SameSite=Strict only)
   - Single-row vs two-rows on audit rollback semantics
   - Rate-limit in-memory persistence
   - Password min length (12 vs 8)
   - `/auth/me` not updating `last_activity`
   - `*Tx` refactor scope on `internal/storage`

2. **Then** start writing the official spec at
   `docs/superpowers/specs/2026-05-17-step-d-auth-design.md` section
   by section, using:
   - The 6 validated Q1–Q6 decisions (above).
   - The 2026-05-17 A1–A5 answers (above) once re-confirmed.
   - Any overrides to the assistant-introduced sub-decisions.

3. The drafted Section 1 / 2 / 3 outlines (in this file) are a
   reasonable starting structure. Discard or rewrite freely.

4. Suggested per-section validation cadence: same as Step C
   (one section drafted → user OK → write to spec file → next section).
   Avoid letting sub-decisions accumulate without explicit user signoff.
