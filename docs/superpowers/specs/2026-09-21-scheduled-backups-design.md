<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Sauvegardes automatiques — Design

**Status:** brainstormé avec l'opérateur 2026-09-21, décisions verrouillées.
Cible : **v2.33.0**. Construit sur le backup complet (v2.29) et les backups
chiffrés par phrase secrète (v2.31).

**One-line :** Arenet sauvegarde seul sa configuration selon un planning,
dans un dossier (local ou NAS monté) et/ou par email, fichiers chiffrés
par phrase secrète, avec rétention, liste dans l'UI et alerte en cas
d'échec — en natif comme en Docker.

## Décisions

| # | Décision | Pourquoi |
|---|----------|----------|
| S1 | **Intégré à Arenet** (pas de script externe). | Tout dans l'UI, statut visible, réutilise export / chiffrement / alertes / audit. |
| S2 | **Destination = un dossier**, réglé dans l'UI, défaut `<data-dir>/backups`. Un NAS s'utilise en montant son partage (NFS / SMB, ou volume Docker). | Pas de dépendance ni d'identifiant distant ; un dossier NAS suffit pour sortir du disque. S3 / WebDAV → backlog. |
| S3 | **Email** via un **canal d'alerte email existant** choisi dans l'UI ; pièce jointe. | Une seule config SMTP à maintenir. |
| S4 | **Fréquence de l'email au choix** : jamais / à chaque sauvegarde / une fois par semaine. | Choix opérateur. |
| S5 | **Toujours « avec secrets », chiffré par une phrase secrète** stockée par Arenet (scellée avec `arenet.key`). | Restaurable ailleurs avec la seule phrase ; un fichier ou un email volé ne livre rien. |
| S6 | **Échec → alerte** : toujours dans l'historique d'alertes (cloche), plus les canaux choisis (tous types). | Une sauvegarde qui échoue en silence ne sert à rien. |
| S7 | **Docker supporté** tel quel (dossier par défaut dans le volume) ; NAS = volume supplémentaire, documenté. | Demande opérateur. |

## Modèle (`storage.BackupScheduleConfig`, bucket `backup_schedule`, clé `config`)

```go
type BackupScheduleConfig struct {
    Enabled         bool     `json:"enabled"`
    Frequency       string   `json:"frequency"`        // "daily" | "weekly"
    Time            string   `json:"time"`             // "HH:MM", heure du serveur
    Weekday         int      `json:"weekday"`          // 0=dimanche..6, si weekly
    Keep            int      `json:"keep"`             // 1..365, défaut 14
    Dir             string   `json:"dir"`              // absolu ; "" = <data-dir>/backups
    Passphrase      string   `json:"passphrase"`       // SECRET (scellé au repos)
    EmailMode       string   `json:"emailMode"`        // "never" | "each" | "weekly"
    EmailChannelID  string   `json:"emailChannelId"`   // canal d'alerte de type email
    AlertChannelIDs []string `json:"alertChannelIds"`  // canaux alertés en cas d'échec
    // État d'exécution (non exporté dans les backups) :
    LastRunAt, LastEmailAt *time.Time
    LastStatus, LastError, LastFile, LastEmailError string
}
```

Validation : fréquence / heure / jour / `keep` dans leurs bornes ; phrase
≥ 12 caractères quand `Enabled` ; `EmailMode != never` ⇒ canal existant de
type email ; canaux d'alerte existants ; dossier absolu. **Test d'écriture
du dossier** à l'enregistrement (création d'un fichier temporaire puis
suppression) → message clair (« Arenet ne peut pas écrire dans … : vérifie
le montage et les droits — UID 65532 en Docker »). Le dossier par défaut
est créé (0700) ; un dossier personnalisé doit exister.

`Passphrase` est ajouté au codec de chiffrement au repos (v2.30) et à la
liste des secrets des backups (`visitSecrets`) ; la config est incluse
dans `extras` (état d'exécution exclu), rechargée après restauration.

## Exécution (`internal/autobackup`, nouveau package)

Justification : service d'exécution (goroutine, fichiers, email) distinct
du moteur d'export pur `internal/backup`.

- **Planification** : tic toutes les minutes ; une sauvegarde est due quand
  le dernier créneau prévu (`Time` du jour, ou du `Weekday`) est passé et
  que `LastRunAt` est antérieur → **rattrapage** d'un créneau manqué
  pendant un arrêt (une seule fois). Démarrage / arrêt / rechargement selon
  le schéma existant (hook de config, contexte racine).
- **Une exécution** : `backup.Export(secrets)` → `SealSnapshot(phrase)` →
  écriture **atomique** (`.tmp` + `rename`) de
  `arenet-backup-auto-AAAAMMJJ-HHMMSS.json` en 0600 → **rétention** (garde
  les `Keep` plus récents ; ne supprime que les fichiers de ce motif
  exact) → email si dû → statut persisté + événement d'audit.
  Exécutions sérialisées (mutex) ; « Sauvegarder maintenant » passe par le
  même chemin.
- **Email** : `EmailSender` gagne l'envoi d'une pièce jointe
  (`multipart/mixed`, base64, stdlib) en réutilisant connexion / STARTTLS /
  auth factorisées. Plafond **10 Mio** : au-delà, email sans pièce jointe
  expliquant pourquoi + échec signalé. Hebdomadaire = envoyé avec la
  première sauvegarde réussie ≥ 7 jours après `LastEmailAt`.
- **Échec** (export, écriture, rétention, email) : `LastStatus=error`,
  événement d'alerte ponctuel (catégorie `backup`, sévérité warning)
  dispatché vers `AlertChannelIDs` → historique + cloche toujours.

## API (admin)

| Méthode | Chemin | Rôle |
|---|---|---|
| GET / PUT | `/settings/backup-schedule` | config ; phrase en écriture seule (`passphraseSet`), vide au PUT = inchangée ; `nextRunAt` calculé |
| POST | `/admin/backups/run` | sauvegarder maintenant (synchrone, renvoie le résultat) |
| GET | `/admin/backups` | liste des fichiers du dossier (nom, taille, date) |
| GET | `/admin/backups/{name}` | téléchargement |
| DELETE | `/admin/backups/{name}` | suppression |
| POST | `/admin/backups/{name}/restore` | restauration avec la phrase stockée (même pipeline que `/admin/restore`, rollback compris) |

`{name}` validé par l'expression exacte du motif (aucun chemin, aucun
`..`) — protection contre la traversée de répertoire.

## UI (Réglages → Backup, nouvelle carte « Sauvegardes automatiques »)

Activation, fréquence + heure (+ jour), rétention, dossier, phrase secrète
(+ confirmation ; « définie » si déjà enregistrée), email (mode + canal),
canaux d'alerte en cas d'échec ; statut (dernière exécution, résultat,
prochaine) ; bouton « Sauvegarder maintenant » ; tableau des fichiers
(télécharger, restaurer, supprimer). i18n FR + EN.

## Docker

- Défaut `/var/lib/arenet/backups` → dans le volume `arenet-data`, rien à
  faire.
- NAS : `- /mnt/nas/arenet-backups:/backups` dans `docker-compose.yml`,
  `chown 65532:65532` du dossier hôte, puis `/backups` dans l'UI.
- Heure : celle du conteneur (**UTC** sauf `TZ=Europe/Paris` dans
  `environment:`) — l'UI affiche le fuseau utilisé. **À vérifier
  empiriquement** : présence des données de fuseaux dans l'image
  distroless (sinon `import _ "time/tzdata"`).

## Tests / validation

- Unitaires : calcul du créneau (quotidien, hebdo, rattrapage, changement
  d'heure), rétention (motif strict), écriture atomique, validation du
  dossier, nom de fichier (traversée), message multipart (pièce jointe
  décodable), plafond de taille, email hebdo, alerte sur échec.
- Smoke binaire réel : sauvegarde planifiée et manuelle, fichier chiffré
  restaurable via la liste, rétention, dossier non inscriptible, email vers
  un serveur SMTP de test local, conteneur Docker (volume par défaut + bind
  mount 65532, `TZ`).

## Non-goals

- ❌ Cibles distantes S3 / WebDAV / SFTP (backlog).
- ❌ Sauvegarde des certificats certmagic, de l'historique des métriques
  / événements, de `arenet.key`.
- ❌ Planification de type cron libre (quotidien / hebdo suffisent).
