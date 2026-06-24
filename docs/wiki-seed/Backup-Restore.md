# Backup & Restore

Arenet ships a **full-snapshot JSON export/import** of every BoltDB-stored config object : routes, DNS providers, forward-auth providers, OIDC config + allowlist, users (including password hashes), error page templates.

Cert files and TLS keys are NOT in the snapshot — they live in Caddy's filesystem store and are auto-reissued by ACME on the new host (unless you also copy `/var/lib/arenet/caddy/` separately).

---

## Quick start : export

1. Sidebar → **Settings** → **Backup & restore** section
2. Pick one :
   - **Export (redacted)** : downloads the JSON with secrets replaced by sentinel placeholders (`"sentinel:..."`)
   - **Export with secrets…** : danger-variant ConfirmDialog → confirm → downloads JSON with PLAINTEXT secrets

Both produce a file named `arenet-backup-YYYYMMDD-HHMMSS.json`.

**Redacted export** is the daily-backup-friendly form : safe to store in cloud storage, git, anywhere. Restoring requires Arenet to inherit the sentinel placeholders from its live state (works for in-place restore on the same instance ; fails for clean-instance restore unless you use the `allowIncompleteRestore` flag).

**With-secrets export** is the disaster-recovery form : restore-anywhere, no inheritance needed. Store this in an encrypted vault (age, GPG, password manager attachment) — the file contains plaintext admin password hashes (Argon2id resistant but still not for arbitrary eyes), OVH DNS API keys, OIDC client secrets, forward-auth client secrets, per-route Basic Auth password hashes.

---

## Quick start : restore

1. Sidebar → **Settings** → **Backup & restore** section
2. **Browse** → pick a previously-exported JSON file
3. Review the two opt-in checkboxes :
   - **Allow incomplete restore** : sentinels that can't inherit from the live store will be cleared (affected secrets need to be manually re-saved post-restore). Use when restoring a redacted export to a fresh instance.
   - **Allow empty users** : accept a backup that has zero users in it. The next boot will re-trigger the setup-token wizard. Use only for "factory reset" scenarios.
4. Click **Restore** (danger button)
5. Wait for the report ; success shows counts (`3 routes imported, 1 user imported, ...`)

The restore is **atomic** : all-or-nothing. Validation failures abort before any storage write. After the storage write succeeds, Arenet **hot-reloads** Caddy from the new BoltDB state. If the Caddy reload fails (rare ; would indicate a config bug), Arenet **rolls back** the BoltDB to the pre-restore state — you stay on the old, known-good config.

---

## What's in the snapshot

JSON schema v1 (`schema_version: "1.0.0"`) :

```json
{
  "schema_version": "1.0.0",
  "exported_at": "2026-06-24T07:00:00Z",
  "secrets_included": false,
  "arenet_version": "v2.9.3",
  "routes": [ ... full Route objects ... ],
  "dns_providers": [ ... DNSProviderConfig objects ... ],
  "forward_auth_providers": [ ... ForwardAuthProvider objects ... ],
  "oidc_config": { ... OIDCConfig including allowlist ... },
  "users": [ ... User objects with PasswordHash ... ]
}
```

Fields **NOT** in the snapshot :
- Caddy cert filesystem (`/var/lib/arenet/caddy/`) — back this up separately if you want to skip ACME re-issuance on restore
- Audit log (BoltDB `audit` bucket) — historical events, not config
- SQLite event tables (waf_event, cert_event, throttle_event, ...) — runtime observability, not config
- Server position (last-known geo, dashboard map state)
- OIDC manager runtime cache (rebuilt at first OIDC use)

---

## Sentinel resolution explained

When you export **redacted**, secrets are replaced by sentinels :

```json
"clientSecret": "sentinel:oidc-config:default:client_secret"
"passwordHash": "sentinel:users:alice:password_hash"
"applicationSecret": "sentinel:dns_providers:ovh:application_secret"
```

When you restore, Arenet's `resolveSentinels` step looks up each sentinel in the LIVE store :

- **Same instance restore** : the sentinel resolves to the live value → restored verbatim
- **Different instance** : the sentinel doesn't exist in the target's live store → restore fails (loud-fail, AC #15)
- **Different instance + `allowIncompleteRestore: true`** : the sentinel is cleared (empty string) → restored with empty value → next boot prints a WARN listing every cleared field for the operator to re-save

This is the "two paths forward" wording you see in the reject error :

> Restore rejected: schema_version X is MAJOR-incompatible. Two paths forward: (1) downgrade Arenet to a binary that knows this schema major ; (2) export current config and re-import.

---

## Disaster recovery scenarios

### Scenario A : in-place upgrade with pre-upgrade snapshot

```bash
# Before upgrade
[UI] Export (redacted) → save to ~/backups/arenet-pre-upgrade.json

# Do the upgrade
docker compose pull && docker compose up -d

# Verify
curl http://localhost:8001/healthz

# If something broke, restore
[UI] Browse → pick arenet-pre-upgrade.json → Allow incomplete: NO → Restore
```

### Scenario B : fresh-host migration

```bash
# Source host
[UI] Export with secrets → save to ~/backups/arenet-full.json
# Copy to new host
scp ~/backups/arenet-full.json newhost:/root/

# Source host — copy Caddy cert files too (optional, skips ACME re-issuance)
docker cp arenet:/var/lib/arenet/caddy ~/backups/caddy-state
scp -r ~/backups/caddy-state newhost:/root/

# New host
# 1. Install Arenet via docker-compose / systemd (see Installation page)
# 2. Restore the Caddy cert files BEFORE first boot
# 3. Run the setup wizard with a throwaway admin (will be overwritten by restore)
# 4. [UI] Browse → arenet-full.json → Allow incomplete: NO → Restore
# 5. Verify : try logging in with the original admin account
```

### Scenario C : "factory reset" then restore from clean backup

```bash
# Stop Arenet, wipe state
docker compose down
docker volume rm arenet_arenet-data
docker compose up -d

# First boot generates a new setup token
docker logs arenet | grep "setup token"

# Setup wizard → create throwaway admin
# [UI] Browse → previous backup → Allow incomplete + Allow empty users : NO/YES per case → Restore
```

---

## Pre-snapshot rollback safety

Before each restore, Arenet **export-snapshots the current state in-memory** (`backup.Export(secrets=true)`). If the Caddy reload AFTER the import fails (rare), Arenet immediately re-applies the pre-snapshot to BoltDB → you stay on the known-good config.

This is invisible to the operator unless the rollback ITSELF fails (edge incompressible), in which case Arenet returns 500 with the BoltDB in an indeterminate state and an audit event `config_restored_rejected reason=rollback_failed` — at that point manually restore from a file backup.

The pre-snapshot lives in process memory only, discarded as soon as the handler returns. No persistent rollback log.

---

## Automation

Schedule periodic exports via cron + curl :

```bash
#!/bin/bash
# /etc/cron.daily/arenet-backup
SESSION_COOKIE=$(curl -s -c - -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"backup-bot","password":"..."}' \
  http://localhost:8001/api/v1/auth/login \
  | grep arenet_session | awk '{print $7}')

curl -H "Cookie: arenet_session=$SESSION_COOKIE" \
  "http://localhost:8001/api/v1/admin/backup?include-secrets=false" \
  > /var/backups/arenet/$(date +%Y%m%d).json
```

Then rotate with `find /var/backups/arenet -mtime +30 -delete`.

For more robustness, use a **service account** ([Users](Users) page → Create service account → role=admin) instead of impersonating a human user.

---

## Schema versioning

The snapshot carries `schema_version: "1.0.0"`. The restore enforces **MAJOR-equal** at import time : an import with `schema_version: "2.x.x"` is rejected by a binary that knows `1.x.x` (and vice versa). MINOR + PATCH differences pass through (additive fields are tolerated).

When Arenet introduces a breaking schema change, the major bump → operators see the loud reject + the "two paths forward" message. Migration tooling will accompany any future MAJOR bump.

---

## Audit trail

Every export emits a `config_exported` audit event with `secrets_included=true/false` + per-bucket row counts. Every restore emits `config_restored` (success) or `config_restored_rejected` (failure) with the snapshot's SHA-256 for forensic correlation.

Visible in `/audit` filtered by action.

---

## See also

- [Installation](Installation) — required for the "fresh host" scenario
- [OIDC SSO](OIDC-SSO) — the OIDC allowlist is part of the snapshot
- [Troubleshooting](Troubleshooting) — restore failure diagnosis
- `internal/backup/` — export + import + sentinel resolution implementation
- `internal/api/backup_handlers.go` — REST handlers with rollback path
- [`docs/operations/backup.md`](https://github.com/barto95100/arenet/blob/main/docs/operations/backup.md) — Docker-volume-level backup pattern (complementary to UI backup)
