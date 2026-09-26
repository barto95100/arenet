<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke — scheduled backups (v2.33.0)

Date: 2026-09-21. Real binary (macOS, `--dev`), a local SMTP sink on
`127.0.0.1:2525` recording every message, an email alert channel
pointing at it, a temp folder standing in for a NAS mount.

| Step | Expected | Observed |
|---|---|---|
| PUT with a folder that does not exist (unmounted NAS) | refused | 400 `backup_dir_unwritable` naming the folder |
| PUT folder = NAS, daily slot now+2 min, keep 2, email each, alert channel | saved | 200, `passphraseSet`, time zone `UTC+02:00 (CEST)`, `nextRunAt` = slot; log "scheduled backups enabled" |
| Back up now | encrypted file + email | 200, `arenet-backup-auto-…-223443.json` 0600 in the NAS folder; email received, attachment = same 3104 bytes, `encryption` header |
| Wait for the slot | runs by itself | `…-223643.json` written at 22:36 (next minute tick), email sent |
| Retention keep=2 | 2 files | 2 files |
| CrowdSec deleted, then restore from the list | state back | 200 report; CrowdSec configured again |
| `GET /admin/backups/..%2Farenet.db` | refused | 404 |
| NAS folder removed, back up now | failure alerted | 500 `backup_failed`; alert history shows category `backup` "Arenet backup failed"; failure email received |

Docker was not available on the test machine: the default folder lives
in the `arenet-data` volume like the rest of the state, the NAS bind
mount is documented (UID 65532), and the time-zone database is
embedded in the binary (`time/tzdata`, fallback verified in
`time/zoneinfo_read.go:543`) so `TZ` works in the distroless image.
**To check on a Docker host after merge.**

Verdict: **pass** (native).
