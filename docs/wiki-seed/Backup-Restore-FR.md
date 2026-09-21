# Backup & Restore

[English](Backup-Restore) · **🌐 Français**

Arenet ship un **export/import JSON full-snapshot** de chaque objet de config stocké dans BoltDB : routes, DNS providers, forward-auth providers, config OIDC + allowlist, users (incluant les password hashes), templates de pages d'erreur.

Les fichiers cert et clés TLS ne sont PAS dans le snapshot — ils vivent dans le store filesystem de Caddy et sont auto-réémis par ACME sur le nouveau host (sauf si tu copies aussi `/var/lib/arenet/caddy/` séparément).

---

## Quick start : export

1. Sidebar → **Settings** → section **Backup & restore**
2. Choisis un :
   - **Export (redacted)** : télécharge le JSON avec les secrets remplacés par des placeholders sentinel (`"$$ARENET_REDACTED$$"`)
   - **Export with secrets…** : danger-variant ConfirmDialog → confirme → télécharge le JSON avec les secrets en PLAINTEXT

Les deux produisent un fichier nommé `arenet-backup-YYYYMMDD-HHMMSS.json`.

**Export redacted** est la forme daily-backup-friendly : safe à stocker en cloud storage, git, n'importe où. La restauration nécessite qu'Arenet hérite des placeholders sentinel depuis son live state (fonctionne pour la restauration in-place sur la même instance ; fail pour la restauration clean-instance sauf si tu utilises le flag `allowIncompleteRestore`).

**Export with-secrets** est la forme disaster-recovery : restore-anywhere, pas d'héritage nécessaire. Stocke ce fichier dans un vault encrypté (age, GPG, attachement de password manager) — le fichier contient des password hashes admin en plaintext (Argon2id résistant mais quand même pas pour des yeux arbitraires), API keys DNS OVH, client secrets OIDC, client secrets forward-auth, password hashes Basic Auth par route.

Depuis la **v2.29.0**, l'export redacted masque aussi les **password hashes Basic Auth des règles par chemin** et les valeurs des **en-têtes de route porteurs d'identifiants** (`Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key`, et tout en-tête dont le nom contient `token`, `secret`, `password` ou `api-key`). À la restauration, ils sont hérités de la route live de même id, comme les autres secrets.

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

Schéma JSON v1 (`schema_version: "1.0.0"`) :

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
  "users": [ ... y compris les comptes de service ... ],
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

| Domaine | Section | Secrets (masqués par défaut) |
| ------- | ------- | ---------------------------- |
| Routes (règles par chemin, en-têtes compris) | `routes` | hashes Basic Auth, valeurs des en-têtes d'authentification |
| Utilisateurs (locaux, OIDC, comptes de service) | `users` | hashes des mots de passe |
| Fournisseurs DNS | `dns_providers` | tous les identifiants secrets du type de fournisseur |
| Fournisseurs forward-auth, OIDC | `forward_auth_providers`, `oidc_config` | secrets clients |
| Compte MaxMind | `maxmind_config` | clé de licence |
| Certificats TLS importés | `external_certificates` | clés privées |
| Domaines gérés (wildcards) | `extras.managed_domains` | — |
| Modèles de pages d'erreur, page de maintenance | `extras.error_templates`, `extras.maintenance_page` | — |
| Canaux et règles d'alerte | `extras.alert_channels`, `extras.alert_rules` | mot de passe SMTP, **URL** des webhooks (une URL Discord / Slack est un identifiant) et valeurs des en-têtes |
| Bouncer + watcher CrowdSec | `extras.crowdsec_config`, `extras.crowdsec_watcher` | clé API, mot de passe du watcher |
| Règles d'automatisation | `extras.automation_rules` | — |
| Vérification des mises à jour, mise à jour GeoIP | `extras.update_check`, `extras.geoip_update` | — |
| Position du serveur (manuelle uniquement) | `extras.server_position` | — |
| Tokens API des comptes de service | `extras.api_tokens` | hashes des tokens |

**La section `extras` (v2.29.0).** Les backups antérieurs à v2.29.0 n'ont pas d'`extras` : les restaurer ne touche à aucun de ces domaines. Un backup avec `extras` **remplace** chacun d'eux — y compris vider une liste ou supprimer un réglage absent du fichier. Deux exceptions : une position serveur détectée automatiquement n'est jamais exportée (elle dépend de la machine) et celle en place est conservée ; l'état d'exécution (dernier envoi / dernière erreur des canaux et règles, dernière utilisation des tokens) n'est pas exporté.

Après une restauration, Arenet applique tout sans redémarrage : rechargement de Caddy (routes, certificats, pages d'erreur, page de maintenance, domaines gérés), réglages CrowdSec restaurés, règles et watcher d'automatisation, planification des vérifications de mise à jour et de GeoIP. Les comptes de service continuent de fonctionner avec **leurs tokens existants** — les intégrations (n8n, Home Assistant…) n'ont pas besoin d'un nouveau token.

Champs **NON** dans le snapshot :
- Filesystem cert Caddy (`/var/lib/arenet/caddy/`) — sauvegarde-le séparément si tu veux éviter la ré-émission ACME au restore
- Audit log (bucket BoltDB `audit`) — événements historiques, pas de la config
- Tables d'événements SQLite (waf_event, cert_event, throttle_event, ...) — observabilité runtime, pas de la config
- Sessions (tout le monde se reconnecte après une restauration sur une autre instance)
- Cache runtime du manager OIDC (reconstruit au premier usage OIDC)

---

## Résolution sentinel expliquée

Quand tu exportes **sans secrets**, chaque secret est remplacé par la sentinelle littérale `$$ARENET_REDACTED$$` :

```json
"client_secret": "$$ARENET_REDACTED$$",
"password_hash": "$$ARENET_REDACTED$$",
"config": { "url": "$$ARENET_REDACTED$$", "method": "POST", ... }
```

À la restauration, Arenet résout chaque sentinelle depuis la ligne de **même identité** dans le store LIVE (même id de route / utilisateur / canal / token, même id *et* même type de fournisseur DNS, l'unique ligne CrowdSec…) :

- **Restore même instance** : la sentinelle prend la valeur live → restaurée telle quelle
- **Instance différente** : rien à hériter → la restauration est refusée, rien n'est écrit
- **Instance différente + `allowIncompleteRestore: true`** : le secret est vidé → restauré avec une valeur vide → le prochain boot affiche un WARN listant chaque champ vidé à ressaisir. Un token de compte de service dont le hash ne peut pas être hérité est **retiré** (un token sans hash ne peut jamais s'authentifier) — émets-en un nouveau depuis la page Utilisateurs.

L'erreur de refus nomme la ligne et le champ, et donne les deux options : ré-exporter la source avec les secrets, ou passer `--allow-incomplete-restore` en connaissance de cause.

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
