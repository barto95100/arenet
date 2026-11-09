<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Implementation plan — access-log viewer (Phase 1).
-->

# Access-log viewer (Phase 1) — implementation plan

- **Spec:** `docs/superpowers/specs/2026-11-09-access-log-viewer-design.md`
- **Branch:** `feature/access-log-viewer`
- **Target:** v2.80.0

Order follows the `guard` discipline: for each unit of logic, the test
is written against the defect/behaviour and seen to fail before the code
makes it pass.

## T1 — Reader package `internal/accesslog`

New, self-contained package (no Caddy imports). Pure file logic, so it
is unit-testable against a temp dir.

- `EnumerateFiles(resolvedPath string) []logFile` — the current file
  plus rotated siblings found by globbing the lumberjack naming
  (`<prefix>-*.log` and `<prefix>-*.log.gz`) in the log's directory,
  ordered **newest→oldest** by filename (timestamp is lexical). Each
  carries `{path, compressed bool}`. Current file first.
- `Tail(resolvedPath string, lines int) ([]string, error)` — bounded
  end-of-file read of the **current file only** (seek-from-end, cap
  bytes); never opens rotated files.
- `Search(resolvedPath string, q string, field Field, max int, caps Caps)
  (Result, error)` — tiered:
  1. current + uncompressed rotated (newest→oldest);
  2. gzipped rotated (`gzip.NewReader`, streaming) **only if (1) found
     nothing**.
  Stop at first hit when `field==Uuid`; otherwise collect up to `max`,
  bounded by `caps.MaxBytes` and `caps.Deadline`. Return
  `Result{Lines, FilesScanned, BytesScanned, Truncated, SearchedCompressed, ElapsedMs}`.
- Line match is a substring on the raw JSON line for `ip`/`path`, and an
  exact token match for `uuid` (anchored to avoid partial-uuid hits).
  Parsing the line into fields for display is a thin JSON decode of the
  matched lines only (not every scanned line).

**Tests (fail first):** spec gates §7.1–§7.5 live here —
find-in-current / find-in-rotated / find-in-gz / not-found-clean /
**Tier-2-skipped-on-Tier-1-hit** (a `.gz` written as garbage so the test
fails loudly if the reader ever opens it on a hot hit) / tail-bounded /
glob-correctness (matches `access-<ts>.log(.gz)`, rejects `access.log.old`).

## T2 — API handlers (admin-only)

- `internal/api/access_log_read.go`: `getAccessLogTail` and
  `getAccessLogSearch`. Resolve the path through the existing
  `h.resolveAccessLogPath(cfg)` (reuse `AccessLogPathResolver`); read the
  stored `AccessLogConfig` to know if logging is **disabled** → return an
  explicit empty result with a reason, not an error.
- Validate/clamp `lines`, `max`, `field`; reject unknown `field`.
- **Ignore any client-supplied path** (spec gate §7.7).
- Route wiring in `routes.go` **inside the `RequireAdminMiddleware()`
  group** (the one at ~:397), under `/admin/access-log/{tail,search}`.

**Tests (fail first):** literal-JSON wire tests (memory
*test-the-wire-not-the-struct*) for both endpoints — shape of a result
row and of the metadata block; `field=bogus` → 400; log-disabled → empty
+ reason; a `path=../../etc/passwd` param changes nothing. A viewer-role
request is rejected (admin-gate test alongside the other admin-group
tests).

## T3 — Frontend (lazy, admin-only)

- Extend `web/frontend/src/routes/logs/+page.svelte` (or a child
  component `AccessLogPanel.svelte`): a collapsed **"Access log"** section
  that fetches **nothing on mount**. Buttons: *Show latest* (tail) and a
  search box with a field selector (request id / IP / path).
- API module `web/frontend/src/lib/api/accessLog.ts` (`tailAccessLog`,
  `searchAccessLog`) via the central `client.ts`.
- Render matched lines with method / status / uri / time, and the
  `arenet_denied` gate as a pill when present. Show the metadata line
  ("searched X/Y files; also searched compressed").
- **Hide the whole section for non-admin** (role already known client
  side; the server enforces regardless).
- i18n: every new string in **both** `locales/en` and `locales/fr`
  (the parity test must pass).

**Tests:** a Vitest for the panel — mount does **no** fetch; clicking
*Show latest* calls the tail endpoint once; search calls search with the
chosen field. Assert on behaviour, not internals.

## T4 — Smoke + docs

- `docs/smoke-test-access-log-viewer.md`: enable the access log, force a
  404 to get a request id on the error page, paste it into the UI search,
  confirm the line is found; repeat after forcing a rotation (shrink
  `RollSizeMB`, generate traffic) to hit a `.gz`.
- Operator doc note under `docs/operations/` (how to look up a request
  id from an error page in the UI) + wiki-seed EN/FR if user-facing.

## Non-regression

- `GET/PUT /settings/access-log` wire unchanged (byte-identical).
- The existing Logs-page event streams unchanged; the new section is
  additive and inert until clicked.
- `go test -race ./...`, `go vet`, `gofmt -s`; frontend `npm run check &&
  npm test` (incl. i18n parity).
