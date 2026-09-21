# Backup & Restore

**🌐 English** · [Français](Backup-Restore-FR)

Arenet ships a **full-snapshot JSON export/import** of every BoltDB-stored config object : routes, DNS providers, forward-auth providers, OIDC config + allowlist, users (including password hashes), error page templates.

Cert files and TLS keys are NOT in the snapshot — they live in Caddy's filesystem store and are auto-reissued by ACME on the new host (unless you also copy `/var/lib/arenet/.local/share/caddy/` separately). See [Certificates](Certificates) for the on-disk layout.

---

## Quick start : export

1. Sidebar → **Settings** → **Backup & restore** section
2. Pick one :
   - **Export (redacted)** : downloads the JSON with secrets replaced by sentinel placeholders (`"$$ARENET_REDACTED$$"`)
   - **Export with secrets…** : asks for a **passphrase** (twice, at least 12 characters) → downloads the JSON with every secret **encrypted** with it (v2.31)

Both produce a file named `arenet-backup-YYYYMMDD-HHMMSS.json`.

**Redacted export** is the daily-backup-friendly form : safe to store in cloud storage, git, anywhere. Restoring requires Arenet to inherit the sentinel placeholders from its live state (works for in-place restore on the same instance ; fails for clean-instance restore unless you use the `allowIncompleteRestore` flag).

**With-secrets export** is the disaster-recovery form : restore-anywhere, no inheritance needed. Since **v2.31** every secret in it — password hashes, DNS credentials, TLS private keys, OIDC / forward-auth / CrowdSec secrets, alert channel credentials, service-account token hashes — is **encrypted** with the passphrase you choose (key derived with argon2id, AES-256-GCM); the rest of the file stays readable JSON. **Keep the passphrase** (password manager): without it the file can only be restored without its secrets. The plaintext with-secrets export no longer exists.

Since **v2.29.0** the redacted export also masks the **Basic Auth password hashes of path rules** and the values of **credential-bearing route headers** (`Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key`, and any header whose name contains `token`, `secret`, `password` or `api-key`). On restore they are inherited from the live route with the same id, like the other secrets.

---

## Quick start : restore

1. Sidebar → **Settings** → **Backup & restore** section
2. **Browse** → pick a previously-exported JSON file. For an **encrypted** file a **passphrase** field appears — enter the one chosen at export (a wrong one is rejected before anything is written)
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
  "exported_at": "2026-09-21T07:00:00Z",
  "secrets_included": false,
  "arenet_version": "v2.29.0",
  "routes": [ ... ],
  "dns_providers": [ ... ],
  "forward_auth_providers": [ ... ],
  "oidc_config": { ... },
  "maxmind_config": { ... },
  "users": [ ... including service accounts ... ],
  "external_certificates": [ ... ],
  "extras": {
    "managed_domains": [ ... ],
    "error_templates": [ ... ],
    "maintenance_page": { ... },
    "alert_channels": [ ... ],
    "alert_rules": [ ... ],
    "crowdsec_config": { ... },
    "crowdsec_watcher": { ... },
    "automation_rules": { ... },
    "update_check": { ... },
    "geoip_update": { ... },
    "server_position": { ... },
    "api_tokens": [ ... ]
  }
}
```

| Area | Section | Secrets (redacted by default) |
| ---- | ------- | ----------------------------- |
| Routes (incl. path rules, headers) | `routes` | Basic Auth hashes, credential-bearing header values |
| Users (local, OIDC, service accounts) | `users` | password hashes |
| DNS providers | `dns_providers` | every secret credential of the provider type |
| Forward-auth providers, OIDC | `forward_auth_providers`, `oidc_config` | client secrets |
| MaxMind account | `maxmind_config` | license key |
| Uploaded TLS certificates | `external_certificates` | private keys |
| Wildcard managed domains | `extras.managed_domains` | — |
| Error page templates, maintenance page | `extras.error_templates`, `extras.maintenance_page` | — |
| Alert channels and rules | `extras.alert_channels`, `extras.alert_rules` | SMTP password, webhook **URL** (a Discord / Slack URL is a credential) and header values |
| CrowdSec bouncer + watcher | `extras.crowdsec_config`, `extras.crowdsec_watcher` | API key, watcher password |
| Automation rules | `extras.automation_rules` | — |
| Update check, GeoIP auto-update | `extras.update_check`, `extras.geoip_update` | — |
| Server position (manual only) | `extras.server_position` | — |
| Service-account API tokens | `extras.api_tokens` | token hashes |

**The `extras` section (v2.29.0).** Backups made before v2.29.0 have no `extras` : restoring one leaves all those areas untouched. A backup with `extras` **replaces** each of them — including emptying a list or removing a setting absent from the file. Two exceptions : an auto-detected server position is never exported (it belongs to the host) and the live one is kept ; runtime state (last send / last error of channels and rules, token last use) is not exported.

After a restore, Arenet applies everything without a restart : Caddy reload (routes, certificates, error pages, maintenance page, managed domains), the restored CrowdSec settings, automation rules and watcher, and the update-check / GeoIP schedules. Service accounts keep working with **their existing tokens** — integrations (n8n, Home Assistant…) need no new token.

Fields **NOT** in the snapshot :
- Caddy cert filesystem (`/var/lib/arenet/.local/share/caddy/`) — back this up separately if you want to skip ACME re-issuance on restore
- Audit log (BoltDB `audit` bucket) — historical events, not config
- SQLite event tables (waf_event, cert_event, throttle_event, ...) — runtime observability, not config
- Sessions (everyone logs in again after a restore onto another instance)
- OIDC manager runtime cache (rebuilt at first OIDC use)

---

## Sentinel resolution explained

When you export **redacted**, every secret is replaced by the literal sentinel `$$ARENET_REDACTED$$` :

```json
"client_secret": "$$ARENET_REDACTED$$",
"password_hash": "$$ARENET_REDACTED$$",
"config": { "url": "$$ARENET_REDACTED$$", "method": "POST", ... }
```

When you restore, Arenet resolves each sentinel against the row of the **same identity** in the LIVE store (same route / user / channel / token id, same DNS provider id *and* type, the single CrowdSec row…) :

- **Same instance restore** : the sentinel resolves to the live value → restored verbatim
- **Different instance** : nothing to inherit → the restore is rejected, nothing is written
- **Different instance + `allowIncompleteRestore: true`** : the secret is cleared → restored with an empty value → the next boot prints a WARN listing every cleared field to re-save by hand. A service-account token whose hash cannot be inherited is **dropped** (a token without its hash can never authenticate) — issue a new one from the Users page.

The reject error names the row and field and gives the two paths forward : re-export the source with secrets included, or pass `--allow-incomplete-restore` knowingly.

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
docker cp arenet:/var/lib/arenet/.local/share/caddy ~/backups/caddy-state
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

## Encryption key (v2.30)

Since v2.30 the secrets inside `arenet.db` are encrypted with `arenet.key` (see [Updates → Migration safety](Updates#5-migration-safety)). This changes nothing for the JSON backups on this page: the export decrypts, so a **with-secrets** export is plaintext (protect it) and a **redacted** one carries sentinels, exactly as before; a restore encrypts again with the target's own key. The key itself is **never** in a JSON backup.

It matters for **file-level** backups (tar of the data directory): `arenet.db` is useless without the matching `arenet.key`. A tarball of the whole data directory holds both — store it like a secret, or keep the key elsewhere with `ARENET_SECRET_KEY_FILE` and back it up on its own.

---

## Pre-snapshot rollback safety

Before each restore, Arenet **export-snapshots the current state in-memory** (`backup.Export(secrets=true)`). If the Caddy reload AFTER the import fails (rare), Arenet immediately re-applies the pre-snapshot to BoltDB → you stay on the known-good config.

This is invisible to the operator unless the rollback ITSELF fails (edge incompressible), in which case Arenet returns 500 with the BoltDB in an indeterminate state and an audit event `config_restored_rejected reason=rollback_failed` — at that point manually restore from a file backup.

The pre-snapshot lives in process memory only, discarded as soon as the handler returns. No persistent rollback log.

---

## Scheduled backups (v2.33)

**Settings → Backup → Scheduled backups** makes Arenet back itself up on its own:

- **When** — every day or every week, at a time in the **server's time zone** (shown in the card; in Docker it is UTC unless `TZ` is set, e.g. `TZ: Europe/Paris` in `environment:`).
- **Where** — a folder: by default `<data dir>/backups` (`/var/lib/arenet/backups`). To keep backups **off the machine**, mount a NAS share and enter its path. Arenet write-tests the folder when you save and reports a clear error otherwise; a custom folder that disappears (unmounted NAS) makes the backup fail — it never silently falls back to the local disk.
- **Retention** — the N most recent backups are kept; older ones are deleted (only files named `arenet-backup-auto-*.json`, nothing else in the folder is touched).
- **Encryption** — every file is a with-secrets backup **encrypted with the passphrase** you set in the card (stored by Arenet, itself encrypted with `arenet.key`). Keep the passphrase in your password manager: it is all you need to restore a file on another machine.
- **Email** — never / every backup / once a week, through one of your **email alert channels** (Settings → Alerting). The file is attached (limit 10 MiB; beyond, the email says so and the backup stays in the folder).
- **Failures** — always shown in the notification bell, and sent to the alert channels you check.
- **The list** — download, restore (with the stored passphrase — a file encrypted with an older passphrase is restored from *Restore* above with that passphrase) or delete each backup; **Back up now** runs one immediately.

A missed slot (Arenet stopped at that time) runs once at the next start. Enabling the schedule does not back up at once — use *Back up now*.

**NAS, native install:** mount the share (e.g. `/mnt/nas/arenet-backups` in `/etc/fstab`), make it writable by the `arenet` user, enter the path in the card.

**NAS, Docker:** mount the share on the host, `sudo chown 65532:65532 /mnt/nas/arenet-backups`, add `- /mnt/nas/arenet-backups:/backups` under `volumes:` in `docker-compose.yml` (commented example in the reference file), `docker compose up -d`, then enter `/backups` in the card.

Not included: TLS certificates (re-issued automatically), metrics / event history, `arenet.key` (not needed to restore a passphrase-encrypted backup).

---

## Automation

Schedule periodic exports with a **service account** token (admin UI → **Users** page → Create service account → role=admin):

```bash
#!/bin/bash
# /etc/cron.daily/arenet-backup
TOKEN=$(cat /root/.arenet-backup-token)          # arn_… service-account token
API=http://localhost:8001/api/v1

# Redacted export (no secrets) — safe anywhere
curl -fsS -H "Authorization: Bearer $TOKEN" "$API/admin/backup" \
  > /var/backups/arenet/$(date +%Y%m%d).json

# Export WITH secrets, encrypted with a passphrase kept in a 0600 file
jq -n --rawfile p /root/.arenet-backup-pass '{passphrase: ($p | rtrimstr("\n"))}' \
  | curl -fsS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d @- "$API/admin/backup" > /var/backups/arenet/$(date +%Y%m%d)-full.json
```

Then rotate with `find /var/backups/arenet -mtime +30 -delete`.

From the CLI (Arenet stopped — BoltDB is single-process):

```bash
arenet --data-dir /var/lib/arenet --export /var/backups/arenet/full.json \
  --include-secrets --passphrase-file /root/.arenet-backup-pass
arenet --data-dir /var/lib/arenet --restore /var/backups/arenet/full.json \
  --passphrase-file /root/.arenet-backup-pass
```

`ARENET_BACKUP_PASSPHRASE` (the passphrase itself) or `ARENET_BACKUP_PASSPHRASE_FILE` work too.

Restoring an encrypted file through the API: pass the passphrase **base64-encoded** (so any character survives the HTTP header) — `curl -H "X-Arenet-Backup-Passphrase: $(printf %s "$PASS" | base64)" --data-binary @full.json "$API/admin/restore"`. A missing or wrong passphrase returns `400` with `code` `passphrase_required` / `passphrase_invalid`.

---

## Schema versioning

The snapshot carries `schema_version: "1.0.0"` — **`2.0.0` for a passphrase-encrypted export** (v2.31). The restore enforces **MAJOR-equal** at import time : a binary older than v2.31 rejects an encrypted file with a clear message instead of restoring the encrypted values as if they were the secrets ; v2.31+ reads both. MINOR + PATCH differences pass through (additive fields are tolerated).

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
