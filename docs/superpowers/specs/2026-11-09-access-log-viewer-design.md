<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Design spec — access-log viewer (Phase 1).
-->

# Access-log viewer in the UI — design (Phase 1)

- **Date:** 2026-11-09
- **Target version:** v2.80.0
- **Status:** DRAFT — awaiting operator review
- **Related:** `2026-09-27-access-log-for-crowdsec-design.md` (the access
  log itself, v2.50), `internal/caddymgr/denial_marker.go` (the
  `arenet_denied` log field, v2.62), `internal/caddymgr/access_log.go`
  (redaction + roll config).

## 1. Problem

Arenet error pages (and the maintenance page) print a **request id** =
Caddy's `{http.request.uuid}` (`error_pages.go:354,403`,
`maintenance.go:291`). Referencing that placeholder makes Caddy generate
the UUID and write it to the **access log** (`denial_marker.go:28-31`),
so the id on screen and the id in the log are the same string — a real
correlation handle.

But today that handle is only reachable **from the filesystem** (SSH +
`grep` on the log file). The UI cannot show it:

- The access-log API (`internal/api/access_log.go`) only GET/PUTs the
  **config** and reports the resolved path — it never reads the file's
  **content**.
- The UI "Logs" page (`web/frontend/src/routes/logs/+page.svelte`) is
  **not** the access log: by its own header comment it unifies the
  internal event streams (WAF / throttle / rate-limit / auth / cert /
  country-block). A "true access-log stream" is listed there as *not yet
  done*.

So an operator handed a request id by a user cannot look it up without
shell access to the box.

## 2. Goals / Non-goals

**Goals (Phase 1)**
- Look up a request id (or IP / path substring) **from the UI**, across
  the current log **and its rotated/compressed siblings**, bounded.
- View the **tail** of the current access log on demand.
- **Never auto-load** the file when the Logs page mounts (operator's
  explicit constraint): content is fetched only on a button action.

**Non-goals (Phase 1 — deliberately deferred)**
- **No** per-request correlation with the WAF/security events by request
  id. The events carry **no** `{http.request.uuid}` field (`WafEvent` =
  `internal/waf/event.go:178`), so an exact join is impossible without a
  schema change. That is **Phase 2** (add the uuid to the events). We do
  **not** do fuzzy (timestamp+IP+path) correlation: a wrong join is worse
  than none (see memory *misleading-wording-bugs*).
  - Mitigation available for free: the access-log line already carries
    **`arenet_denied`** (WAF / CrowdSec / country / rate-limit), so the
    viewer shows *which gate* refused without any join.
- No live "follow"/tail-stream (future).
- No full-file download from the UI (that is what SSH / the data volume
  is for; we expose only bounded reads).
- No editing or deletion of logs.

## 3. Rotation & compression — the search must follow the files

Confirmed empirically against the pinned deps (Caddy **v2.11.4** →
lumberjack **v2.2.1**, `lumberjack.go:39-40,247-258`):

- Current file: the configured path, e.g. `access.log`.
- Rotated backup: `<prefix>-<timestamp><ext>`, timestamp format
  `2006-01-02T15-04-05.000` → e.g. `access-2026-11-09T15-04-05.000.log`.
- Compressed (`Compress`/`roll_gzip` on, default **on**): `.gz` appended
  → `access-2026-11-09T15-04-05.000.log.gz`.

Config bounds (`internal/storage/access_log_config.go`):
`RollSizeMB` default 10 / max **1024**; `RollKeep` default 5 / max
**100**; `Compress` default **true**. Worst case ≈ **100 GB across ~101
files**, mostly `.gz`. The reader therefore MUST be bounded and
streaming — never load a whole file, never load everything.

The timestamp in the name is **lexicographically sortable**, so rotated
files can be ordered newest→oldest by filename alone (no stat needed).

### 3.1 Tiered search (operator's strategy)

1. **Tier 1 — hot:** the current file **+ uncompressed rotated** files
   (`<prefix>-*.log`), newest→oldest.
2. **Tier 2 — cold:** gzipped rotated files (`<prefix>-*.log.gz`),
   newest→oldest, **only if Tier 1 yielded nothing** (operators usually
   report an incident quickly, so the hit is almost always in Tier 1).

A mix of `.log` and `.log.gz` can coexist (operator toggled Compress at
some point) — both extensions are always considered, regardless of the
*current* Compress setting. `.gz` is decompressed with a streaming
`gzip.Reader`, never to a temp file.

## 4. API (read-only, admin-only)

Two new GET endpoints, wired **inside the admin-only group**
(`auth.RequireAdminMiddleware()`, `routes.go:397`) and under the `/admin`
prefix like the other admin surfaces (`/admin/backup`). A viewer-role
account cannot reach them. The client sends **only** query params —
**never a path** (the server resolves it via `ResolveAccessLogPath`; no
traversal surface).

| Endpoint | Purpose | Bounds |
|---|---|---|
| `GET /admin/access-log/tail?lines=N` | Last N lines of the **current file only**. | `lines` default 200, **max 1000**. Reads from the file's end, never the whole file. |
| `GET /admin/access-log/search?q=…&field=uuid\|ip\|path&max=M` | Tiered search across current + rotated (+ `.gz` on Tier-1 miss). | `max` default 200, max 1000; hard caps on bytes scanned and wall-clock; **stop at first hit when `field=uuid`** (unique). |

Search fields are exactly **`uuid` / `ip` / `path`** (operator-confirmed
as sufficient); no status/method/time-range filter in Phase 1.

Response (both) is JSON: parsed line objects (method, uri, status,
`arenet_denied`, ts, remote_ip…) **plus** search metadata:
`{ filesScanned, bytesScanned, truncated, searchedCompressed, elapsedMs }`
— reported honestly so the UI can say "searched 6 of 48 files, stopped at
limit". Lines are already `REDACTED` on disk, so nothing sensitive is
re-exposed.

Degenerate states return cleanly, not as errors: log **disabled**, file
**absent**, directory unreadable → explicit empty result with a reason.

## 5. Frontend / UX

- On the Logs page, a dedicated **"Access log"** affordance (button /
  panel) that fetches **nothing on mount**. It only calls the API when
  the operator clicks (tail) or submits a search.
- A search box (request id / IP / path). Paste the id from an error page,
  hit search → the matching line, with the `arenet_denied` gate shown as
  a pill when present.
- The metadata line ("searched X/Y files…", "also searched compressed")
  is surfaced so slow cold searches are explained, not mysterious.

## 6. Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| A1 | Two read-only endpoints (`tail`, `search`); no file content auto-loaded by the page. | Matches the operator's "don't load the whole thing on open" constraint; read-only keeps the attack surface minimal. |
| A2 | Client never sends a path; server resolves via `ResolveAccessLogPath`. | No path-traversal surface; one source of truth for where the log is. |
| A7 | **Admin-only**: both endpoints sit in the `auth.RequireAdminMiddleware()` group under `/admin/access-log/*`. Not readable by a viewer role. | Operator decision — raw request logs (even redacted) are an admin surface, same posture as `/admin/backup`. |
| A8 | Search fields limited to `uuid` / `ip` / `path`. | Operator-confirmed sufficient; keeps the parser and the UI simple for v1. |
| A3 | Tiered search: current + `.log` first, `.gz` only on a Tier-1 miss. | Operator's observation that incidents are reported fast → the hit is nearly always recent/uncompressed; avoids burning CPU decompressing 100 `.gz` on every query. |
| A4 | `uuid` search stops at first match; `ip`/`path` collect up to `max`, bounded by bytes + timeout. | UUID is unique (one line); substring fields are not, so they need a cap and honest truncation. |
| A5 | **No** WAF-event correlation in Phase 1; rely on the `arenet_denied` field already in the line. | The events have no request uuid; a fuzzy join would mislead. Exact join is Phase 2 (schema change). |
| A6 | Enumerate rotated files by glob on the lumberjack naming (`<prefix>-*.log`, `<prefix>-*.log.gz`), ordered by filename. | Naming verified in lumberjack v2.2.1; timestamp is lexically sortable, so no per-file stat. Never assume `.1 .2 .3`. |

## 7. Empirical validation gates (write the test first — see `guard`)

1. **Find by uuid** in: (a) the current file, (b) an uncompressed rotated
   file, (c) a gzipped rotated file. Each returns the exact line.
2. **Not-found** (uuid absent from every tier) → clean empty result with
   `searchedCompressed=true`, not an error.
3. **Tier gate:** a match present in the current file **does not open any
   `.gz`** (assert via a `.gz` sentinel that would corrupt the result if
   read, or an injected read counter). Proves Tier 2 is skipped on a
   Tier-1 hit.
4. **Tail** reads only the current file and respects `lines` ≤ max;
   a file far larger than the cap is **not** fully read (bounded-read
   assertion).
5. **Glob correctness:** `access-<ts>.log` and `access-<ts>.log.gz` match;
   an unrelated `access.log.old` or a different stem does not.
6. **Degenerate:** log disabled / file missing → explicit empty + reason.
7. **No path from client:** a `path=`/`../` query param is ignored; the
   resolved path is always `ResolveAccessLogPath`'s.

## 8. Rollout

Single feature branch `feature/access-log-viewer`, PR → merge → tag
**v2.80.0**. Non-regression: the access-log config endpoints and the
existing Logs page event streams are untouched (byte-identical wire for
`GET/PUT /settings/access-log`).
