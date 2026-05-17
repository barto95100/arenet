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
