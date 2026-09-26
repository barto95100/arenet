<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke — passphrase-encrypted backups (v2.31.0)

Date: 2026-09-21. Real binaries, macOS, `--dev`. Instance A and B run
this branch, OLD runs `origin/main` (v2.29). Passphrase used:
`phrase secrète 🔐 de test` (non-ASCII on purpose). A fake CrowdSec
LAPI logs the `X-Api-Key` it receives.

| Step | Expected | Observed |
|---|---|---|
| A seeds a Cloudflare provider, CrowdSec key, webhook channel | — | 201 / 200 / 201 |
| A `GET /admin/backup?include-secrets=true` | refused | 400 `passphrase_required` |
| A `POST /admin/backup` with a 5-char passphrase | refused | 400 `passphrase_too_short`, `params.min=12` |
| A `POST /admin/backup` with the passphrase | encrypted file | 200, `X-Arenet-Backup-Encrypted: true`, schema `2.0.0`, argon2id 64 MiB, **0** seeded secret in the file |
| B (fresh) restore without / with a wrong passphrase | refused, nothing written | 400 `passphrase_required` / `passphrase_invalid` |
| B restore with the passphrase | restored and applied | 200; A's admin logs in on B; bouncer calls the LAPI with the restored key |
| OLD (v2.29, fresh) restore of the encrypted file | refused, nothing written | 400 "schema_version 2.0.0 (major mismatch …)"; CrowdSec still unconfigured |
| CLI `--export --include-secrets` without passphrase | refused | exit 1, "needs a backup passphrase" |
| CLI export with `--passphrase-file` | encrypted file | exit 0, schema `2.0.0`, mode `600`, 0 leak |
| CLI `--restore` without / with `ARENET_BACKUP_PASSPHRASE` | refused / restored | exit 1 "is encrypted: pass --passphrase-file…" / exit 0 "config restored" |

UI flows (export modal, passphrase field on an encrypted file,
translated errors) are covered by `BackupSection.test.ts`; to check by
hand on the test host after merge.

Verdict: **pass**.
