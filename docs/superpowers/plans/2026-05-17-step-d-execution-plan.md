# Step D — Execution plan

**Status**: Active
**Spec frozen**: `v0.2.0-step-d-spec` (commit 5e08665, 5643 lines)
**Plan author**: Ludovic Ramos
**Created**: 2026-05-17

## 1. Overview

This document is the execution plan for implementing Step D (admin 
authentication, audit log, HIBP integration, trusted-proxy IP 
extraction) as specified in 
`docs/superpowers/specs/2026-05-17-step-d-auth-design.md` (tag 
`v0.2.0-step-d-spec`).

The plan organizes the implementation work into **8 chunks**, each 
delivering a self-contained slice of functionality with its own 
acceptance criteria, estimated effort, and assignment 
(solo work vs. sub-agent delegation). Chunks are designed to be 
executed in a recommended order (Section 3 — dependency graph), 
with quality gates between each (Section 5).

### 1.1 Methodology

The plan applies three principles validated during the spec phase:

- **Spec-driven**: every chunk references the precise spec sections 
  it implements. No design decisions happen at execution time 
  without first amending the spec.
- **AC-validated**: every chunk lists the acceptance criteria 
  (Section 10 of the spec) it must satisfy. Completion = ACs pass.
- **Auditable progress**: each chunk produces one or more commits 
  on `main`, with messages referencing the chunk number and the 
  ACs covered. The git log is the canonical record of progress.

### 1.2 Solo vs. sub-agent

Five of the eight chunks are **solo** work (the operator implementing 
with Claude Code in pair-programming mode), three are **delegable** 
to sub-agents. The split is based on three criteria:

- **Criticality**: backend authentication code (sessions, password 
  handling, middleware) is implemented solo. A subtle bug in 
  hard-auth or HIBP would compromise security; the cost of 
  reviewing sub-agent output to the same standard is at least as 
  high as writing the code directly.
- **Spec precision**: chunks whose spec section is exhaustive (e.g. 
  Section 6 frontend integration, where most components have full 
  Svelte snippets) are good candidates for sub-agent delegation. 
  Ambiguity is the enemy of delegation.
- **Surface area**: chunks touching multiple cross-cutting concerns 
  (e.g. router wiring, middleware ordering) stay solo because the 
  integration cost dominates the chunk cost.

**Mandatory rule for sub-agent chunks**: every sub-agent chunk goes 
through a code review by the operator before commit, plus a manual 
test of the chunk's critical acceptance criteria, plus a check that 
no TODO/FIXME comment was left behind. This rule is non-negotiable 
and is detailed in Section 6 (sub-agent delegation protocol).

### 1.3 Chunks at a glance

| # | Chunk                                          | Sections of spec        | Solo/Delegable | Effort  | Risk    |
|---|------------------------------------------------|-------------------------|----------------|---------|---------|
| 1 | Backend storage layer                          | 3                       | Solo           | 4-5h    | High    |
| 2 | Backend auth package (middleware, HIBP, IP)    | 5, 7, 8                 | Solo           | 5-6h    | High    |
| 3 | Backend audit package + helpers                | 3.4, 5.9                | Mix            | 3h      | Medium  |
| 4 | Backend endpoints (handlers /auth/* + /audit)  | 4 (all subsections)     | Solo           | 4-5h    | High    |
| 5 | Frontend stores + API clients                  | 6.2 → 6.6               | Delegable      | 3h      | Low     |
| 6 | Frontend pages (/login, /setup) + Sidebar      | 6.9, 6.10, 6.12         | Delegable      | 3h      | Low     |
| 7 | Frontend LockScreen + banner + ChangePassword  | 6.7, 6.8, 6.13          | Mix            | 4h      | Medium  |
| 8 | Frontend Audit page                            | 6.11, 9 (all)           | Delegable      | 4h      | Low     |

**Total estimated effort**: 30-37 hours of implementation work, 
distributed across 6-8 working sessions at the operator's typical 
pace.

### 1.4 Out of scope for this plan

The following are explicitly NOT covered by this execution plan and 
are documented as deferred:

- **Phase 2 enhancements** (Section 11.4 of the spec): settings page, 
  query param filters, sortable columns, audit retention. Will get 
  a separate execution plan when Phase 2 is greenlit.
- **Step D2, D3, F, G, H**: outside the scope of Step D. See 
  `docs/roadmap.md` and Section 11 of the spec.

## 2. Prerequisites

Before any chunk begins, the following must be true:

### 2.1 Spec stability

The spec at tag `v0.2.0-step-d-spec` must be the active reference. 
Any modification to the spec during execution requires:

1. An explicit amendment commit on the spec file with a clear 
   message ("Step D spec: amend section X — reason").
2. A re-tagging of the spec (`v0.2.0-step-d-spec` → 
   `v0.2.1-step-d-spec`).
3. A note in this execution plan's changelog (added as Section 9 if 
   not already present).

The spec is the source of truth. Chunks that diverge from the spec 
are bugs, not features.

### 2.2 Step C must remain functional

All Step C functionality (routes CRUD, Caddy reload, single binary 
build) must continue to pass after each chunk. Step D extends Step 
C; it does not replace it.

Concretely:

- `go test ./...` for Step C packages must pass before each chunk 
  starts and after each chunk completes.
- The dev-mode demo flow (create a route, see Caddy reload, hit the 
  route) must still work.

### 2.3 Tooling

The operator must have on hand:

- Go 1.25+ (matching Step C, see CLAUDE.md)
- Node 20+ for the frontend
- A terminal with the project root at the working directory
- A Caddy binary available locally for integration tests
- `curl` for endpoint tests
- A web browser for the frontend tests

### 2.4 References

The plan assumes the operator has the following documents accessible 
in their environment:

- `docs/superpowers/specs/2026-05-17-step-d-auth-design.md` — the spec
- `docs/superpowers/decisions/2026-05-17-step-d-design-decisions-final.md` 
  — the 17 design decisions
- `docs/roadmap.md` — long-term planning
- This plan: `docs/superpowers/plans/2026-05-17-step-d-execution-plan.md`

## 3. Chunk dependency graph

The chunks can be executed in the following recommended order. The 
graph shows hard dependencies (the dependent chunk **cannot start** 
until its prerequisite is merged):

```text
   ┌──────────────────────────────────┐
   │ Chunk 1                          │
   │ Backend storage layer            │
   │ (User, Session, Audit structs)   │
   └────────────────┬─────────────────┘
                    │
       ┌────────────┴────────────┐
       │                         │
       ▼                         ▼
┌──────────────┐         ┌──────────────────────┐
│ Chunk 2      │         │ Chunk 3              │
│ Auth package │         │ Audit package +      │
│ (mw,HIBP,IP) │         │ helpers              │
└──────┬───────┘         └──────────┬───────────┘
       │                            │
       └────────────┬───────────────┘
                    ▼
        ┌────────────────────────┐
        │ Chunk 4                │
        │ Backend endpoints      │
        │ (handlers /auth/*,     │
        │  /audit)               │
        └────────────┬───────────┘
                     │
                     │  (backend complete; frontend can begin)
                     │
                     ▼
        ┌────────────────────────┐
        │ Chunk 5                │
        │ Frontend stores +      │
        │ API clients            │
        └────────────┬───────────┘
                     │
       ┌─────────────┼─────────────┬─────────────┐
       │             │             │             │
       ▼             ▼             ▼             ▼
   ┌──────┐     ┌──────┐     ┌──────┐       ┌──────┐
   │Chunk6│     │Chunk7│     │Chunk8│       │ ...  │
   │login │     │Lock  │     │Audit │       │      │
   │setup │     │banner│     │page  │       │      │
   └──────┘     └──────┘     └──────┘       └──────┘

   (Chunks 6, 7, 8 are parallelizable among themselves;
    they all depend on Chunk 5 but not on each other.)
```

### 3.1 Critical path

The longest dependency path is Chunk 1 → Chunk 2 → Chunk 4 → 
Chunk 5 → (any of 6, 7, 8). With approximate efforts:

- Chunk 1: 4-5h
- Chunk 2: 5-6h
- Chunk 4: 4-5h
- Chunk 5: 3h
- Chunk 6/7/8: 3-4h each

**Critical path = 19-23 hours of solo work, plus 3-4 hours of any 
parallel frontend chunk**. If chunks 6, 7, 8 are executed in 
parallel via sub-agents (with review time), the total wall-clock 
time for frontend can be compressed to ~4-5 hours instead of 
10-11 hours sequentially.

### 3.2 Parallelization opportunities

- **Chunks 2 and 3 in parallel**: both depend only on Chunk 1. 
  Chunk 3 (audit package) is simpler and can be implemented while 
  Chunk 2 is in progress, if the operator has spare capacity (e.g., 
  Chunk 3 delegated to a sub-agent while operator works on Chunk 2 
  solo).
- **Chunks 6, 7, 8 in parallel**: all three depend only on Chunk 5. 
  They touch different files (different pages, different 
  components) so there's no merge conflict risk. Ideal for 
  sub-agent delegation.

### 3.3 Soft ordering hints

Within each tier of the graph, some chunks are preferable to do 
first:

- After Chunk 5 (frontend foundation), do **Chunk 6 (login/setup)** 
  first. It exercises the entire auth flow end-to-end (login → 
  layout → routes page) and catches integration bugs early.
- **Chunk 7 (LockScreen)** is best done second because it needs 
  the layout to be working (Chunk 6 ships the working layout) and 
  the change-password modal needs auth in place.
- **Chunk 8 (audit page)** can be last; it's the most 
  self-contained piece and benefits from a stable backend.

## 4. Chunks

This section details each chunk: scope, spec references, effort, 
assignment (solo or delegable), acceptance criteria covered, 
implementation notes, and commit strategy. The 8 chunks are 
presented in dependency order (see Section 3).

### 4.1 Chunk 1 — Backend storage layer

**Scope**: implement the three new buckets (`users`, `sessions`, 
`audit`) on top of the existing `storage.Store` from Step C, plus 
the typed stores `auth.UserStore`, `auth.SessionStore`, and 
`audit.Store` that operate on those buckets via the shared 
`*bolt.DB` handle.

**Spec sections**: 3 (entire section — Storage schemas, all 
subsections 3.1 through 3.6).

**Effort**: 4-5 hours.

**Assignment**: **Solo**. This chunk defines the data model that 
every other chunk depends on; subtle errors here propagate 
everywhere. The cost of getting it wrong outweighs the cost of 
implementing it directly.

**Files created or modified**:

```text
internal/storage/storage.go        # MODIFIED: expose DB(), add 3 new buckets
internal/auth/types.go             # NEW: User, Session structs
internal/auth/userstore.go         # NEW: auth.UserStore implementation
internal/auth/sessionstore.go      # NEW: auth.SessionStore implementation
internal/auth/errors.go            # NEW: sentinel errors (ErrUserNotFound, etc.)
internal/audit/types.go            # NEW: Event struct + Filter
internal/audit/actions.go          # NEW: ActionXXX constants (15 action values per D7)
internal/audit/store.go            # NEW: audit.Store implementation
```

**Tests to write within this chunk**:

- `internal/auth/userstore_test.go`: create user, get by ID, get by 
  username, count, update password, sentinel errors.
- `internal/auth/sessionstore_test.go`: create session, get, touch, 
  delete, list for user, cleanup expired.
- `internal/audit/store_test.go`: append, list with filters, 
  pagination via cursor, immutability.

Coverage target: ≥80% for these three packages.

**Acceptance criteria covered**:

- AC-AUTH-11 (argon2id params verified in PHC string)
- Partial: AC-AUTH-04 (cookie attributes — finalized in Chunk 4)
- Partial: AC-AUDIT-01 → AC-AUDIT-14 (storage layer correctness; 
  endpoint emission verified in Chunks 3 & 4)
- Partial: AC-LOCK-05 (storage allows querying lastActivity without 
  side-effect)

**Implementation notes**:

- The argon2id parameters `m=64MiB, t=3, p=4` are hardcoded as 
  constants in `internal/auth/types.go` and used by 
  `UserStore.Create`. Verify the resulting PHC string includes 
  `$argon2id$v=19$m=65536,t=3,p=4$...`.
- The `users` bucket lookup `GetByUsername` does a full scan in 
  Phase 1 (see spec 3.6); accept this as O(1) in practice.
- `Session.ID` is `crypto/rand` × 32 bytes encoded with 
  `base64.RawURLEncoding`. Confirm length = 43 chars.
- `Event.ID` uses `uuid.NewV7()`. Store the raw 16 bytes as the 
  bucket key; the JSON `id` exposes the hyphenated form.
- The `audit` bucket's cursor pagination uses `Cursor().Seek()` 
  on the raw 16-byte key. Test with at least 100 events to 
  confirm the cursor logic.

**Commit strategy**: one or two commits.

- Commit A: storage.go modifications + bucket creation + DB() 
  exposure. Message: "Step D: storage — expose DB() and create 
  users/sessions/audit buckets".
- Commit B: auth + audit packages with their stores. Message: 
  "Step D: internal/auth and internal/audit — User/Session/Event 
  storage". 

**Dependencies**: none beyond Step C.

**Downstream impact**: Chunks 2, 3, 4 cannot start until this 
chunk merges. Chunks 5-8 (frontend) are not impacted by this 
chunk's internals; they consume the API contract defined in 
Chunk 4.

### 4.2 Chunk 2 — Backend auth package (middleware, HIBP, IP extractor)

**Scope**: implement the three middleware groups (no-auth, 
soft-auth, hard-auth), the HIBP client with k-anonymity protocol, 
the embedded top-10k password list, the IP extractor with trusted 
proxy support, and the context propagation helpers.

**Spec sections**: 5 (entire section — Middleware chain), 7 
(entire section — HIBP integration), 8 (entire section — Trusted 
proxies and IP extraction).

**Effort**: 5-6 hours.

**Assignment**: **Solo**. This is the security core of Step D. 
Subtle bugs in `HardAuthMiddleware` (e.g., the Touch-before-check 
inversion discussed during the spec phase) would compromise the 
entire idle-lock model. The HIBP integration must correctly 
handle the k-anonymity protocol and the deferred re-check flow.

**Files created or modified**:

```text
internal/auth/middleware.go         # NEW: SoftAuthMiddleware, HardAuthMiddleware
internal/auth/context.go            # NEW: ctxKey, accessors (UserIDFromContext, etc.)
internal/auth/ratelimit.go          # NEW: per-IP rate limiter (in-memory)
internal/auth/ipextract.go          # NEW: IPExtractor + ClientIP method
internal/auth/hibp.go               # NEW: HIBPClient + CheckPassword
internal/auth/password.go           # NEW: isCommonPassword + embedded top-10k loader
internal/auth/data/common-passwords.txt.gz  # NEW: embedded asset (~30 KB)
```

**Tests to write within this chunk**:

- `internal/auth/middleware_test.go`: soft-auth with valid 
  session, expired session, idle session; hard-auth refusing 
  idle; verify Touch happens AFTER idle check.
- `internal/auth/ratelimit_test.go`: tier 1 (5/5min), tier 2 
  (10/1h), reset on success, slog Warn on tier 2.
- `internal/auth/ipextract_test.go`: the 6 scenarios from 
  spec 8.3 (worked examples table).
- `internal/auth/hibp_test.go`: with mocked HTTP server, test 
  clean / compromised / pending / skipped outcomes. Verify 
  k-anonymity (only 5-char prefix is sent).
- `internal/auth/password_test.go`: top-10k lookup case-insensitive.

Coverage target: ≥85% for `internal/auth` (higher than Chunk 1 
because security-critical).

**Acceptance criteria covered**:

- AC-LOCK-01 → AC-LOCK-07 (all session locking scenarios)
- AC-RATE-01 → AC-RATE-06 (all rate limiting scenarios)
- AC-PW-01 → AC-PW-06 (password validation: length, top-10k, HIBP)
- AC-PW-12 (HIBP disabled via env var)
- AC-PROXY-01 → AC-PROXY-07 (all trusted proxy scenarios)

**Implementation notes**:

- `HardAuthMiddleware` wraps `SoftAuthMiddleware`; do NOT duplicate 
  the session lookup logic. The idle check happens AFTER the soft 
  authentication succeeds.
- The Touch call is **after** the idle check, never before. If 
  you find yourself writing Touch first, stop — it's the bug 
  discussed in spec 5.7.
- The HIBP client uses SHA-1 only for the protocol, never for 
  storage. Confirm this in code comments.
- The top-10k list uses `//go:embed` with `embed.FS`. The file 
  must be at `internal/auth/data/common-passwords.txt.gz` 
  (relative to the package).
- The IP extractor parses CIDRs at startup; fail fast on 
  malformed CIDR.
- The rate limiter is per-IP in-memory; on server restart, all 
  counters are cleared (this is intentional, per spec 5.3).

**Sub-tests to add for security correctness**:

- A test that confirms `HardAuthMiddleware` returns 403 when 
  `LastActivity + 15min < now`, and that Touch is NOT called in 
  that path.
- A test that confirms HIBP plaintext password is never logged.
- A test that confirms `X-Forwarded-For` is ignored when 
  `r.RemoteAddr` is not in a trusted CIDR.

**Commit strategy**: three commits.

- Commit A: IP extractor + tests. Message: "Step D: 
  internal/auth/ipextract — trusted proxy IP resolution".
- Commit B: rate limiter + tests. Message: "Step D: 
  internal/auth/ratelimit — per-IP two-tier rate limiter".
- Commit C: middleware (soft/hard) + HIBP + password validation 
  + tests. Message: "Step D: internal/auth middleware, HIBP, and 
  password validation".

**Dependencies**: Chunk 1 must be merged (uses UserStore, 
SessionStore types).

### 4.3 Chunk 3 — Backend audit package + helpers

**Scope**: implement the audit package's helper functions used 
by the handlers (`appendAudit`, `appendAuditBackground`, 
`mustMarshalForAudit`), the ActionXXX constants, and the wiring 
that audit events are emitted post-mutation.

**Spec sections**: 3.4 (Audit Event schema), 5.9 (Audit context 
enrichment).

**Effort**: 3 hours.

**Assignment**: **Mix** (semi-critical). The helper functions are 
straightforward and can be delegated to a sub-agent if the 
operator is short on time. However, the rule that audit emission 
happens AFTER successful business mutation (decision D2) is 
critical and must be respected by the handlers in Chunk 4 — 
that's the operator's responsibility regardless.

**Files created or modified**:

```text
internal/api/audit_helpers.go       # NEW: appendAudit, mustMarshalForAudit
internal/audit/actions.go           # MODIFIED: ensure all 15 ActionXXX constants present
```

**Tests to write within this chunk**:

- `internal/api/audit_helpers_test.go`: appendAudit fills 
  ActorUserID and IP from context correctly; failure path logs 
  Warn without panicking.
- Confirm `mustMarshalForAudit` returns nil (not crashes) on 
  unmarshalable input.

Coverage target: ≥80% for the helper code.

**Acceptance criteria covered**:

- AC-AUDIT-01 → AC-AUDIT-07 (audit event shape and field 
  correctness; emission verified end-to-end in Chunk 4)

**Implementation notes**:

- `appendAudit` reads `ActorUserID`, `ActorUsernameSnapshot`, and 
  `ClientIP` from the request context (populated by middleware 
  from Chunk 2).
- `mustMarshalForAudit` is intentionally named "must" but does NOT 
  panic; it returns nil on error. The name is a Go idiom for 
  "best-effort with sensible default", consistent with 
  `regexp.MustCompile` (which panics, in contrast).
- The 15 ActionXXX constants (per decision D7 in decisions-final.md) 
  must all be present with their exact string values. Use a 
  `const` block, not a `var` map (compile-time guarantee of 
  values). The canonical list is in `decisions-final.md` under D7; 
  the spec references these actions throughout Sections 4, 5, 7, 
  9, and 10 but does not enumerate them in a single block.

**Commit strategy**: one commit.

- Commit: "Step D: internal/api audit helpers + 
  internal/audit/actions constants".

**Sub-agent delegation note**: if delegated, the sub-agent 
receives spec sections 3.4 and 5.9 plus this chunk's description, 
plus decision D7 from decisions-final.md. Output review checklist:

1. All 15 ActionXXX constants are present and match the names in 
   D7.
2. `appendAudit` does NOT log the plaintext of `Message` if it 
   contains sensitive content (passwords, tokens).
3. `mustMarshalForAudit` does not panic on circular references.
4. Audit append failure does NOT propagate to the caller 
   (best-effort policy).

**Dependencies**: Chunk 1 (audit.Store) must be merged.

### 4.4 Chunk 4 — Backend endpoints (handlers /auth/* + /audit)

**Scope**: implement the 10 HTTP handlers (the 9 `/auth/*` 
endpoints plus `GET /audit`), wire them into the chi router with 
the correct middleware groups, set the session cookie correctly, 
and emit audit events post-success.

**Spec sections**: 4 (entire section — all subsections including 
4.9bis for changePassword).

**Effort**: 4-5 hours.

**Assignment**: **Solo**. This chunk integrates all the backend 
work from Chunks 1-3 and exposes it via HTTP. Errors here are 
visible to the entire frontend and have security implications 
(cookie attributes, status codes, error messages).

**Files created or modified**:

```text
internal/api/handler.go             # MODIFIED: add fields for auth/audit stores
internal/api/router.go              # MODIFIED: mount new middlewares + endpoints
internal/api/auth_handlers.go       # NEW: handlers for /auth/* endpoints
internal/api/audit_handlers.go      # NEW: handler for GET /audit
internal/api/setup_token.go         # NEW: setup token generation + verification
cmd/arenet/main.go                  # MODIFIED: wire stores, log setup token
```

**Tests to write within this chunk**:

- `internal/api/auth_handlers_test.go`: end-to-end test of each 
  endpoint via `httptest.Server`, covering happy path + each 
  error code from the spec tables.
- `internal/api/audit_handlers_test.go`: list events with various 
  filters, cursor pagination.
- `internal/api/router_test.go`: middleware ordering is correct 
  (RequestID → slogLogger → Recoverer → devCORS → 
  ipExtractMiddleware → rateLimit → auth groups).

Coverage target: ≥75% for `internal/api` (lower than auth because 
some integration scenarios are best tested manually).

**Acceptance criteria covered**:

- AC-AUTH-01 → AC-AUTH-11 (entire auth flow)
- AC-PW-07 → AC-PW-11 (HIBP deferred re-check, password change)
- AC-AUDIT-01 → AC-AUDIT-14 (audit events emission end-to-end)
- AC-RATE-01 → AC-RATE-06 (rate limit responses with 429 + 
  Retry-After)

**Implementation notes**:

- Setup token generation: `crypto/rand` × 32 bytes, hex-encoded. 
  Stored in process memory only; regenerated on each restart 
  while no admin exists. Logged at `slog.Info` at boot with the 
  message `Setup token: <hex>`.
- Cookie attributes are exactly as in spec 4.11: 
  `HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={86400|2592000}`. 
  In `--dev` mode, omit `Secure`.
- The error envelope is `{"error": "human-readable message"}` for 
  all error responses. Status code is authoritative.
- Setup endpoint returns 404 (not 403 or 409) when an admin 
  already exists — this is decision Q2.
- Audit emission for mutations (route_created, etc.) happens 
  AFTER the Caddy reload succeeds (decision D2). Verify with a 
  test that injects a Caddy reload failure: no audit event is 
  emitted.
- `/api/v1/auth/me` does NOT call `Session.Touch` — verified by 
  a test polling /me every 100ms for 16 minutes and observing 
  the eventual lock.

**Commit strategy**: three commits.

- Commit A: setup token + setup endpoint + setup_admin_created 
  audit. Message: "Step D: /auth/setup endpoint with token 
  bootstrap".
- Commit B: login + logout + me + unlock + heartbeat + sessions 
  endpoints with audit. Message: "Step D: auth endpoints 
  (login, logout, me, unlock, heartbeat, sessions)".
- Commit C: changePassword endpoint + audit endpoint + final 
  router wiring + integration tests. Message: "Step D: 
  changePassword and audit endpoints; router complete".

**Dependencies**: Chunks 1, 2, 3 must be merged.

**Downstream impact**: backend is now feature-complete. Frontend 
chunks (5, 6, 7, 8) can begin. The API contract is set at this 
point; any change to it requires a spec amendment.
