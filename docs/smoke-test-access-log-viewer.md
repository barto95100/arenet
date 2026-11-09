<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Smoke-test procedure — access-log viewer (Phase 1, v2.80.0).
-->

# Smoke test — access-log viewer (v2.80.0)

Manual procedure on a real instance. The automated gates
(`internal/accesslog`, `internal/api/access_log_read_test.go`, the
`AccessLogPanel` Vitest) cover the logic; this confirms the end-to-end
loop an operator actually walks: *error page → request id → UI lookup*,
including after rotation.

- **Spec:** `docs/superpowers/specs/2026-11-09-access-log-viewer-design.md`
- **Plan:** `docs/superpowers/plans/2026-11-09-access-log-viewer.md`

## Preconditions

- An admin session (the viewer is admin-only; a viewer role must see no
  "Access log" section and get 403 on the endpoints).
- At least one proxied route.

## 1. Enable the access log

1. Settings → Access log → enable. Leave the defaults (10 MB / 5 files /
   compress on).
2. Save → confirm the resolved path is shown (e.g.
   `/var/log/arenet/access.log` under systemd, `<data>/logs/access.log`
   otherwise).

## 2. Generate a request id on an error page

1. Hit a route in a way that Arenet refuses (e.g. a path the WAF blocks,
   or a geo-blocked source), or request a non-existent host to get the
   404 error page.
2. On the error page, copy the **request id** shown at the bottom.

## 3. Look it up in the UI (hot tier)

1. Logs page → expand **Access log** (admin only). Confirm **nothing was
   fetched** when the page first opened (the section is collapsed and
   inert until expanded, and no request fires until a button is clicked).
2. Field = **Request ID**, paste the id, **Search**.
3. Expect exactly one row: the method / status / path of the refused
   request, and — when a gate refused it — the **Blocked by** pill
   (`waf` / `country` / …) from the `arenet_denied` field.
4. The metadata line should read "Searched 1 file(s) in N ms" and **not**
   mention compressed files (the hit was in the current file).

## 4. Tail

1. Click **Show latest** → the last ~200 lines of the current file, newest
   last. Confirm it returns promptly even on a large file (bounded read).

## 5. Look it up after rotation (cold tier)

1. Settings → Access log → lower **Rotate at (MB)** to `1`, save.
2. Generate traffic until the file rotates (a rotated
   `access-<timestamp>.log.gz` appears next to `access.log`).
3. Force a fresh error page, copy its request id, then generate enough
   traffic to push that line into a rotated **`.gz`**.
4. Logs → Access log → search that id by **Request ID**.
5. Expect the row to be found, and the metadata line to say it **also
   searched compressed files** (the cold tier was reached because the hot
   tier missed).

## 6. Negative / guard checks

- Search a random id that is nowhere → "No matching line found." (clean
  empty state, not an error), metadata says compressed files were also
  searched.
- Disable the access log, reopen the panel, search → the panel states the
  log is disabled rather than erroring.
- A **viewer**-role account: no "Access log" section; `GET
  /api/v1/admin/access-log/tail` and `/search` return **403**.

## Verdict

Record PASS/FAIL per step. A FAIL on step 3 or 5 (id not found) is the
feature's core promise broken and blocks the release.
