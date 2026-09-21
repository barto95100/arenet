<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Secrets au repos : fuites, chiffrement, backups — Design

**Status:** brainstormé avec l'opérateur 2026-09-21, décisions verrouillées.
Vague 2 de l'analyse concurrentielle (Caddy Proxy Manager chiffre ses clés
privées au repos). Livraison en **trois PR** :

- **PR 1 — correctifs de fuite** : `autosave.json`, secrets absents des
  backups, en-têtes sensibles des routes dans les backups.
- **PR 2 — chiffrement au repos** des secrets dans `arenet.db`.
- **PR 3 — backups « avec secrets » chiffrés par phrase secrète.**

## Constat (inventaire du 2026-09-21)

Aucun chiffrement aujourd'hui ; seule la permission 0600 de `arenet.db`
(dossier 0700, `internal/storage/storage.go:150-163`) protège :

| Secret | Stockage | Backup aujourd'hui |
|---|---|---|
| Identifiants DNS (champs `Secret` du registre) | `dns_providers` | sentinelle ✅ |
| `ExternalCertificate.KeyPEM` (clés importées + clés de CSR) | `external_certificates` | sentinelle ✅ |
| `CrowdSecConfig.APIKey` | `crowdsec_config` | **absent** ❌ |
| `WatcherCredentials.Password` (CrowdSec machine) | `automation` | **absent** ❌ |
| `MaxMindConfig.LicenseKey` | `maxmind_config` | sentinelle ✅ |
| `OIDCConfig.ClientSecret` | `oidc_config` | sentinelle ✅ |
| `ForwardAuthProvider.ClientSecret` | `forward_auth_providers` | sentinelle ✅ |
| `alerting Channel.Config` (mot de passe SMTP, URL/en-têtes webhook) | `alerting_channels` | **absent** ❌ |
| `Session.ID` (valeur brute du cookie, clé du bucket) | `sessions` | non exporté |
| En-têtes de route (`Authorization`…) | `routes` | **en clair** ❌ |

Déjà protégés : mots de passe utilisateurs et basic auth (argon2id), tokens
de comptes de service (SHA-256).

**Fuite parallèle vérifiée** : `caddy.Load(cfg, false)` persiste la config
dans `autosave.json` tant que `admin.config.persist` n'est pas `false`
(`caddy@v2.11.4/caddy.go:377-392`) ; Arenet n'émet pas cette option
(`caddymgr/manager.go:965` `adminConfig{Disabled}`) → copie en clair des
identifiants DNS, clés privées et clé CrowdSec dans
`$XDG_CONFIG_HOME/caddy/autosave.json` à chaque rechargement. Arenet ne
s'en sert jamais (pas de `--resume`).

**Hors périmètre** : clés des certificats ACME dans le stockage certmagic
(fichiers PEM de Caddy — fonctionnement normal de Caddy).

## Décisions

| # | Décision | Pourquoi |
|---|----------|----------|
| K1 | **Clé = fichier auto-généré** `arenet.key` (32 octets aléatoires, 0600) dans le dossier de données ; surchargeable par `ARENET_SECRET_KEY_FILE` (secret Docker, disque séparé). | Zéro configuration. Protège une base ou un backup copié ailleurs. Ne protège pas d'un accès root complet à la machine (aucune solution automatique ne le peut) — dit clairement dans la doc. |
| K2 | **Backups « avec secrets » chiffrés par une phrase** saisie à l'export ; sans phrase, export « sans secrets » (sentinelles) comme aujourd'hui. | Restaurable sur une autre machine avec la phrase ; un fichier de backup volé ne livre rien. |
| K3 | **Couper `autosave.json`** (`admin.config.persist: false`). | Sinon le chiffrement de la base ne sert à rien. |
| K4 | **Sauvegarder les 3 secrets oubliés** (clé CrowdSec, mot de passe watcher, canaux d'alerte). | Aujourd'hui perdus silencieusement à la restauration. |
| K5 | **Masquer les en-têtes sensibles** des routes dans les backups (`Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key`, et tout nom contenant `token`, `secret`, `api-key`, `password`). | Un token dans un en-tête injecté vers l'upstream est un secret. |

## PR 1 — correctifs de fuite

1. `adminConfig` gagne `Config *adminConfigPersist` → émis
   `"admin":{"disabled":true,"config":{"persist":false}}`. Test : la config
   émise le contient ; `caddy.Validate` passe ; un test d'intégration
   vérifie qu'aucun `autosave.json` n'est écrit (répertoire de config
   redirigé vers un dossier temporaire).
2. `backup.Snapshot` gagne `crowdsec_config`, `crowdsec_watcher`,
   `alerting_channels` (pointeurs / slices, `omitempty` → un ancien backup
   s'importe inchangé). Sentinelles sur `api_key`, `password`, et sur la
   config **entière** d'un canal (URL de webhook incluse — elle vaut
   secret : Discord / Slack). Import : résolution par identité (id du canal)
   avec repli sur la valeur existante, comme les autres secrets.
3. En-têtes de route : valeurs des noms sensibles (K5) remplacées par la
   sentinelle à l'export sans secrets ; résolues à l'import depuis la route
   existante de même id.
4. Doc : wiki Backup-Restore EN/FR (ce qui est inclus), release note.

## PR « backup complet » (ajoutée le 2026-09-21)

Constat : le backup ne contient que routes, utilisateurs, DNS,
forward-auth, OIDC, MaxMind et certificats externes. **Absents** :
domaines gérés (wildcards), modèles de pages d'erreur, page de maintenance,
canaux + règles d'alerte, config CrowdSec, automatisation (identifiants
watcher + règles), réglages (vérif. mises à jour, mise à jour GeoIP,
position serveur), tokens des comptes de service (les comptes sont
restaurés, pas leurs tokens → comptes inutilisables).

- Nouvelle section `extras` (`SnapshotExtras`) : **absente** (backup
  ≤ v2.25) → aucun de ces buckets n'est touché ; **présente** → chaque
  bucket est remplacé (un singleton absent = ligne supprimée).
- État d'exécution non exporté : `last_*` des canaux et règles,
  `last_used_at` des tokens ; position serveur exportée seulement en mode
  `manual`.
- Secrets (sentinelles, héritage par identité à l'import) : mot de passe
  SMTP, **URL** et en-têtes des webhooks (une URL Discord / Slack est un
  secret), clé API CrowdSec, mot de passe watcher, `token_hash` (un token
  non résolu est retiré de la restauration, pas restauré vide).
- Validation : domaines (+ fournisseur DNS présent), modèles (+ un seul
  catch-all), canaux (par type), règles (+ canaux présents), CrowdSec,
  watcher, jeu de règles d'automatisation, tokens (utilisateur = compte de
  service présent, un seul token actif par compte).
- Après restauration : rechargement Caddy (existant) + application
  CrowdSec, automatisation, planification des vérifications de mise à
  jour et de la mise à jour GeoIP.

Précisions d'implémentation (2026-09-21) :

- Tokens lus en lignes brutes par `storage.ListAPITokenRows` (storage
  possède le bucket, pas le type) → aucune signature `Export` / `Import`
  modifiée.
- Position serveur : absente du backup (mode auto) → la ligne en place est
  **conservée** (exception à « singleton absent = supprimé »).
- Règles d'automatisation stockées sous l'enveloppe `{"rules": RuleSet}`
  (écrite par l'API) : la validation décode cette enveloppe.
- CrowdSec restauré : `ApplyCrowdSecConfig` remplace le rechargement
  Caddy (un seul rechargement, couvert par le rollback) ; en cas d'échec,
  la base est restaurée et les réglages d'avant sont ré-appliqués. Ligne
  CrowdSec absente du backup → réglages en cours conservés jusqu'au
  prochain démarrage (repli sur les variables d'environnement).
- Automatisation, vérif. des mises à jour, GeoIP : appliqués après un
  rechargement réussi, au mieux (la base reste la référence au boot).
- Smoke binaire réel (2 instances) : le token d'un compte de service de A
  authentifie sur B après restauration et après redémarrage ; le bouncer
  de B bascule à chaud sur la clé restaurée ; export sans secrets sans
  fuite ; restauration sans secrets sur la même instance → 6 sentinelles
  héritées, secrets intacts.

## PR 2 — chiffrement au repos

- **Package** `internal/secrets` (nouveau, justifié : primitive transverse
  utilisée par storage, backup et cmd) :
  - `Keyring` : charge ou crée la clé (création atomique `O_EXCL`, 0600) ;
  - `Seal(plaintext, aad) string` → `enc:v1:<base64(nonce‖ciphertext)>`,
    **AES-256-GCM** (stdlib), nonce aléatoire de 12 octets, AAD = nom du
    champ (`dns_providers.credentials`, …) pour qu'une valeur ne puisse pas
    être déplacée d'un champ à l'autre ;
  - `Open(s, aad)` : valeur sans préfixe `enc:v1:` → renvoyée telle quelle
    (compatibilité pendant la migration).
- **Stockage** : chiffrement à l'écriture / déchiffrement à la lecture dans
  le package `storage`, champ par champ (liste du constat). Le reste du code
  (API, caddymgr) continue de voir des valeurs en clair.
- **Sessions** : la clé du bucket devient `SHA-256(id)` (même modèle que les
  tokens de service) ; conséquence assumée : **une reconnexion unique** de
  tous les utilisateurs après la mise à jour.
- **Migration au démarrage** idempotente (valeurs sans préfixe → chiffrées)
  dans une transaction.
- **Garde-fou clé** : l'empreinte de la clé (8 premiers octets de
  SHA-256) est enregistrée dans un bucket `meta`. Au démarrage, si la base
  contient des valeurs chiffrées et que la clé est **absente ou
  différente**, Arenet **refuse de démarrer** avec un message explicite —
  il ne génère jamais une nouvelle clé qui rendrait les secrets
  illisibles.
- **Backup de la clé** : la doc et un log au premier démarrage rappellent
  de sauvegarder `arenet.key` (hors du backup de config).
- Tests : aller-retour, AAD, valeur altérée rejetée, migration idempotente,
  garde-fou clé absente / différente, aucune valeur en clair dans le fichier
  BoltDB après migration (lecture binaire du fichier).

### Constats d'implémentation (2026-09-21)

- **bbolt ne nettoie pas les pages libérées** : sceller une ligne en
  place laisse l'ancienne version en clair dans une page libre du
  fichier (prouvé par test). D'où `Store.Compact()` (copie dans un
  fichier neuf puis remplacement atomique) après toute passe qui a
  réécrit des lignes — au boot seulement, avant de partager `DB()`.
- **Journal d'audit** (même fichier) : les créations / modifications
  gardaient l'URL des webhooks, les en-têtes sensibles des routes et
  les hashes Basic Auth des règles par chemin — visibles aussi dans
  l'UI d'audit. Rédaction complétée pour les nouveaux événements +
  nettoyage unique des anciens (`ScrubAuditSecrets`, JSON brut, id et
  horodatage conservés).
- **Sessions** : `GET /auth/sessions` renvoyait les identifiants bruts
  (= cookies) de tous les navigateurs de l'utilisateur, et l'audit /
  les logs les enregistraient. L'API liste et révoque désormais par
  *handle*.
- Démarrage : clé absente ou différente sur une base chiffrée → refus
  explicite (code 1), jamais de nouvelle clé. L'export CLI ne crée pas
  de clé sur une base jamais chiffrée.
- Hors périmètre, documenté : blocs disque de l'ancien fichier après
  remplacement (niveau système de fichiers), anciennes sauvegardes
  fichier de `arenet.db` prises avant la mise à niveau.

## PR 3 — backups chiffrés par phrase

- Export « avec secrets » : phrase obligatoire (≥ 12 caractères) ; clé de
  backup dérivée par **argon2id** (sel aléatoire stocké dans l'en-tête du
  backup, paramètres enregistrés) ; chaque secret du snapshot est scellé
  avec cette clé (même format `enc:v1:` + AAD).
- `schema_version` → `1.1.0` ; l'import d'un backup chiffré exige la phrase
  (400 `passphrase_required` / `passphrase_invalid`) ; un backup 1.0.x
  s'importe comme avant.
- UI Réglages → Backup : champ phrase (confirmée) à l'export avec secrets,
  demandé à l'import si nécessaire. CLI `arenet backup` :
  `--passphrase-file` / `ARENET_BACKUP_PASSPHRASE`.

### Précisions d'implémentation PR 3 (2026-09-21)

- **`schema_version` 2.0.0** (et non 1.1.0) pour un export chiffré :
  un binaire antérieur accepte tout MAJOR 1 et restaurerait les
  valeurs `enc:v1:` comme des secrets (mots de passe → verrouillage
  de l'admin). Avec MAJOR 2 il refuse proprement. Les exports sans
  secrets restent en 1.0.0 ; un fichier ouvert redevient 1.0.0.
- Une seule liste des champs secrets (`visitSecrets`) sert au
  masquage, au scellement et à l'ouverture ; AAD = chemin
  `entité/id/champ` → une valeur ne peut pas changer de ligne.
- argon2id t=3, m=64 Mio, p=4, sel 16 octets ; bornes à l'import
  (t ≤ 10, m ≤ 1 Gio, p ≤ 16) contre un fichier piégé ; valeur témoin
  scellée pour détecter une mauvaise phrase avant tout.
- `Import` refuse un snapshot encore chiffré et des valeurs scellées
  sans en-tête (fichier modifié).
- API : `GET /admin/backup` = sans secrets (l'ancien
  `include-secrets=true` en clair → 400) ; `POST /admin/backup`
  `{"passphrase"}` = export chiffré ; restauration avec l'en-tête
  `X-Arenet-Backup-Passphrase` en base64 (fetch refuse les caractères
  non Latin-1 dans un en-tête). Codes `passphrase_required`,
  `passphrase_invalid`, `passphrase_too_short`.
- CLI : `--include-secrets` exige `--passphrase-file` /
  `ARENET_BACKUP_PASSPHRASE_FILE` / `ARENET_BACKUP_PASSPHRASE`.

## Non-goals

- ❌ Chiffrer toute la base BoltDB (seuls les secrets le sont).
- ❌ Stockage de la clé dans un coffre externe (Vault, KMS) → backlog.
- ❌ Rotation de clé outillée → backlog (procédure manuelle documentée).
- ❌ Stockage certmagic de Caddy.
