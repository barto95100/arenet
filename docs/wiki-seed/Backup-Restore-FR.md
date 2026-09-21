# Backup & Restore

[English](Backup-Restore) · **🌐 Français**

Arenet ship un **export/import JSON full-snapshot** de chaque objet de config stocké dans BoltDB : routes, DNS providers, forward-auth providers, config OIDC + allowlist, users (incluant les password hashes), templates de pages d'erreur.

Les fichiers cert et clés TLS ne sont PAS dans le snapshot — ils vivent dans le store filesystem de Caddy et sont auto-réémis par ACME sur le nouveau host (sauf si tu copies aussi `/var/lib/arenet/caddy/` séparément).

---

## Quick start : export

1. Sidebar → **Settings** → section **Backup & restore**
2. Choisis un :
   - **Export (redacted)** : télécharge le JSON avec les secrets remplacés par des placeholders sentinel (`"sentinel:..."`)
   - **Export with secrets…** : danger-variant ConfirmDialog → confirme → télécharge le JSON avec les secrets en PLAINTEXT

Les deux produisent un fichier nommé `arenet-backup-YYYYMMDD-HHMMSS.json`.

**Export redacted** est la forme daily-backup-friendly : safe à stocker en cloud storage, git, n'importe où. La restauration nécessite qu'Arenet hérite des placeholders sentinel depuis son live state (fonctionne pour la restauration in-place sur la même instance ; fail pour la restauration clean-instance sauf si tu utilises le flag `allowIncompleteRestore`).

**Export with-secrets** est la forme disaster-recovery : restore-anywhere, pas d'héritage nécessaire. Stocke ce fichier dans un vault encrypté (age, GPG, attachement de password manager) — le fichier contient des password hashes admin en plaintext (Argon2id résistant mais quand même pas pour des yeux arbitraires), API keys DNS OVH, client secrets OIDC, client secrets forward-auth, password hashes Basic Auth par route.

---

## Quick start : restore

1. Sidebar → **Settings** → section **Backup & restore**
2. **Browse** → choisis un fichier JSON précédemment exporté
3. Review les deux checkboxes opt-in :
   - **Allow incomplete restore** : les sentinels qui ne peuvent pas hériter depuis le live store seront cleared (les secrets affectés doivent être re-saved manuellement post-restore). À utiliser quand tu restaure un export redacted vers une instance fresh.
   - **Allow empty users** : accepte un backup qui a zéro users. Le prochain boot re-déclenchera le wizard setup-token. À utiliser uniquement pour les scénarios "factory reset".
4. Clique **Restore** (bouton danger)
5. Attends le report ; le succès montre les counts (`3 routes imported, 1 user imported, ...`)

La restauration est **atomique** : all-or-nothing. Les validation failures abort avant tout write de stockage. Après que le write de stockage succeed, Arenet **hot-reload** Caddy depuis le nouveau state BoltDB. Si le reload Caddy échoue (rare ; indiquerait un bug de config), Arenet **rollback** le BoltDB à son état pré-restore — tu restes sur l'ancienne config known-good.

---

## Ce qui est dans le snapshot

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

Champs **NON** dans le snapshot :
- Filesystem cert Caddy (`/var/lib/arenet/caddy/`) — back up ça séparément si tu veux skip la ré-émission ACME au restore
- Audit log (bucket BoltDB `audit`) — événements historiques, pas de la config
- Tables d'événements SQLite (waf_event, cert_event, throttle_event, ...) — observabilité runtime, pas de la config
- Position serveur (last-known geo, état de la map du dashboard)
- Cache runtime du manager OIDC (reconstruit au premier usage OIDC)

---

## Résolution sentinel expliquée

Quand tu export **redacted**, les secrets sont remplacés par des sentinels :

```json
"clientSecret": "sentinel:oidc-config:default:client_secret"
"passwordHash": "sentinel:users:alice:password_hash"
"applicationSecret": "sentinel:dns_providers:ovh:application_secret"
```

Quand tu restore, le step `resolveSentinels` d'Arenet look up chaque sentinel dans le store LIVE :

- **Restore même instance** : le sentinel résout vers la valeur live → restauré verbatim
- **Instance différente** : le sentinel n'existe pas dans le live store target → restore fail (loud-fail, AC #15)
- **Instance différente + `allowIncompleteRestore: true`** : le sentinel est cleared (string vide) → restauré avec valeur vide → le prochain boot print un WARN listant chaque champ cleared pour que l'opérateur le re-save

C'est le wording "two paths forward" que tu vois dans l'erreur de reject :

> Restore rejected: schema_version X is MAJOR-incompatible. Two paths forward: (1) downgrade Arenet to a binary that knows this schema major ; (2) export current config and re-import.

---

## Scénarios de disaster recovery

### Scénario A : upgrade in-place avec snapshot pré-upgrade

```bash
# Avant upgrade
[UI] Export (redacted) → save vers ~/backups/arenet-pre-upgrade.json

# Fais l'upgrade
docker compose pull && docker compose up -d

# Vérifie
curl http://localhost:8001/healthz

# Si quelque chose a cassé, restore
[UI] Browse → pick arenet-pre-upgrade.json → Allow incomplete: NO → Restore
```

### Scénario B : migration vers fresh-host

```bash
# Host source
[UI] Export with secrets → save vers ~/backups/arenet-full.json
# Copie vers le nouvel host
scp ~/backups/arenet-full.json newhost:/root/

# Host source — copie aussi les fichiers cert Caddy (optionnel, skip la ré-émission ACME)
docker cp arenet:/var/lib/arenet/caddy ~/backups/caddy-state
scp -r ~/backups/caddy-state newhost:/root/

# Nouvel host
# 1. Installe Arenet via docker-compose / systemd (voir page Installation)
# 2. Restore les fichiers cert Caddy AVANT le premier boot
# 3. Run le wizard de setup avec un admin jetable (sera overwriten par le restore)
# 4. [UI] Browse → arenet-full.json → Allow incomplete: NO → Restore
# 5. Vérifie : essaie de log in avec le compte admin original
```

### Scénario C : "factory reset" puis restore depuis backup clean

```bash
# Stop Arenet, wipe state
docker compose down
docker volume rm arenet_arenet-data
docker compose up -d

# Le premier boot génère un nouveau setup token
docker logs arenet | grep "setup token"

# Wizard de setup → crée un admin jetable
# [UI] Browse → backup précédent → Allow incomplete + Allow empty users : NO/YES selon cas → Restore
```

---

## Pre-snapshot rollback safety

Avant chaque restore, Arenet **export-snapshot l'état courant in-memory** (`backup.Export(secrets=true)`). Si le reload Caddy APRÈS l'import échoue (rare), Arenet re-applique immédiatement le pre-snapshot au BoltDB → tu restes sur la config known-good.

C'est invisible pour l'opérateur sauf si le rollback LUI-MÊME fail (edge incompressible), auquel cas Arenet retourne 500 avec le BoltDB dans un state indéterminé et un événement d'audit `config_restored_rejected reason=rollback_failed` — à ce point restore manuellement depuis un backup fichier.

Le pre-snapshot vit en mémoire process uniquement, discarded dès que le handler retourne. Pas de log de rollback persistant.

---

## Automation

Schedule des exports périodiques via cron + curl :

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

Puis rotate avec `find /var/backups/arenet -mtime +30 -delete`.

Pour plus de robustness, utilise un **service account** (page [Users] → Create service account → role=admin) au lieu d'impersonate un user humain.

---

## Schema versioning

Le snapshot porte `schema_version: "1.0.0"`. Le restore enforce **MAJOR-equal** à l'import : un import avec `schema_version: "2.x.x"` est rejeté par un binaire qui connaît `1.x.x` (et vice versa). Les différences MINOR + PATCH passent (les champs additifs sont tolérés).

Quand Arenet introduit un breaking schema change, le bump major → les opérateurs voient le loud reject + le message "two paths forward". L'outillage de migration accompagnera tout futur bump MAJOR.

---

## Trail d'audit

Chaque export émet un événement d'audit `config_exported` avec `secrets_included=true/false` + counts de lignes par bucket. Chaque restore émet `config_restored` (succès) ou `config_restored_rejected` (échec) avec le SHA-256 du snapshot pour la corrélation forensique.

Visible dans `/audit` filtré par action.

---

## See also

- [Installation](Installation-FR) — requis pour le scénario "fresh host"
- [OIDC SSO](OIDC-SSO-FR) — l'allowlist OIDC fait partie du snapshot
- [Troubleshooting](Troubleshooting) — diagnostic d'échec de restore
- `internal/backup/` — implémentation export + import + résolution sentinel
- `internal/api/backup_handlers.go` — handlers REST avec chemin de rollback
- [`docs/operations/backup.md`](https://github.com/barto95100/arenet/blob/main/docs/operations/backup.md) — pattern backup au niveau Docker-volume (complémentaire au backup UI)
