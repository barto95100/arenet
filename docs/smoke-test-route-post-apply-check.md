<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke — post-apply route check (v2.35.0)

Date: 2026-09-21. Real binary (macOS, `--dev`, HTTP listener :8080), a
Python HTTP server on 127.0.0.1:9912 as the backend.

| Step | Expected | Observed |
|---|---|---|
| Create `check.localhost` → :9912 (up) | ok | `check.status=ok`, `httpStatus=200` |
| Update the upstream to :9913 (closed) | undone | 409 `route_check_rolled_back` ("answered 502 Bad Gateway"), 4 s; stored upstream back to :9912; live traffic through Caddy 200 |
| Backend stopped, update to :9914 | kept + warning (previous fails too) | 200, `check.status=failed` 502, stored upstream :9914, 8 s |
| Setting off, update | no probe | `check.status=skipped` "disabled in settings" |
| New HTTPS route on a public name | not a failure | `check.status=pending_certificate` (ACME staging, no cert yet) |
| Audit | rollback recorded | `route_update_rolled_back` with the probe detail |

Note: a first run showed the "backend stopped" case undone — a
leftover backend from an earlier smoke still listened on :9912, so the
previous version really answered. Re-run with the port free: kept, as
designed.

Verdict: **pass**.
