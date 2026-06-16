<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Alerting — Guide opérateur

Ce document décrit le sous-système d'alerting d'Arenet :
comment configurer des canaux de notification, comment
écrire des règles de déclenchement, et comment lire
l'historique des envois. Couvre la version V1 (Step AL,
commits `47d20dd` → `ab252e5`).

> **TL;DR**. Aller dans **Alerting** dans la barre
> latérale → créer un canal (Webhook ou Email) → cliquer
> **Test** pour vérifier qu'il fonctionne → créer une
> règle qui pointe vers ce canal → cliquer **Test** sur
> la règle → l'événement apparaît dans l'onglet
> **Historique**. Les règles sont ensuite évaluées
> automatiquement toutes les 30 secondes par le watcher.

## Sommaire

1. [Introduction](#introduction)
2. [Concepts](#concepts)
3. [Configurer un canal webhook](#configurer-un-canal-webhook)
4. [Configurer un canal email](#configurer-un-canal-email)
5. [Configurer une règle](#configurer-une-règle)
6. [Tester depuis l'UI](#tester-depuis-lui)
7. [Lire l'historique](#lire-lhistorique)
8. [Dépannage](#dépannage)
9. [Architecture en bref](#architecture-en-bref)
10. [Limitations V1](#limitations-v1)

---

## Introduction

Arenet possède un sous-système d'alerting natif qui
surveille en continu certains signaux internes (taux
d'événements WAF, expiration des certificats, état des
composants système) et envoie une notification quand une
condition opérateur-définie est satisfaite. Les
notifications sont dispatchées vers un ou plusieurs
**canaux** (webhook HTTP ou email SMTP) selon les
**règles** que vous configurez. Chaque envoi laisse une
trace dans l'**historique** consultable depuis l'UI.

Le sous-système comporte quatre acteurs principaux :

- **Canaux** — destinations de notification (webhook,
  email). Un homelab en a typiquement 1 à 3.
- **Règles** — conditions de déclenchement avec routing
  multi-canal et fenêtre de silence (cooldown).
- **Watcher** — goroutine qui évalue les règles toutes
  les 30 secondes et déclenche les envois.
- **Historique** — table `alert_event` (SQLite) qui
  conserve 30 jours d'événements.

Toute la configuration passe par la page **Alerting** dans
la barre latérale. Aucune édition de fichier de configuration
n'est requise.

## Concepts

### Canaux

Un canal est une destination de notification. Arenet V1
supporte deux types :

- **Webhook** — HTTP POST vers une URL opérateur-choisie,
  avec en-têtes personnalisés et timeout configurable.
  Compatible avec tout récepteur HTTP : Slack
  (Incoming Webhooks), Discord (Webhooks),
  Alertmanager, n8n, scripts personnels.
- **Email** — envoi SMTP avec support TLS implicite
  (port 465), STARTTLS (port 587) ou non chiffré.
  Recipient multiples (To, Cc, Bcc).

Chaque canal possède une **sévérité minimum** : seules les
règles qui déclenchent à un niveau ≥ ce minimum atteignent
le canal. Pratique pour avoir un canal "high-priority only"
(critique + urgence) et un canal "everything"
(info + au-dessus).

### Règles

Une règle décrit **quoi observer** (une source), **comment
décider** (un évaluateur), et **où envoyer** (un ou
plusieurs canaux). Arenet V1 propose deux types
d'évaluateur :

- **Seuil (threshold)** — compare une valeur numérique
  contre un opérateur (`>`, `>=`, `<`, `<=`, `==`, `!=`)
  et une valeur seuil. Exemple : "alerter si le taux
  de blocages WAF > 50 sur 5 minutes".
- **État (state)** — compare une chaîne contre une
  valeur attendue. Exemple : "alerter si le composant
  CrowdSec est dans l'état `degraded`".

### Sources d'observation

Arenet V1 expose 3 sources hardcodées. Chacune accepte des
paramètres opérateur (encodés en JSON dans la BDD) :

| Source | Type de valeur | Paramètres |
|---|---|---|
| `waf_event_rate` | numérique (compteur) | `routeId` (optionnel), `windowSecs` (60-86400, défaut 300), `action` (BLOCK / DETECT / toutes) |
| `cert_expiry` | numérique (jours) | `host` (optionnel — vide = cert le plus proche d'expirer) |
| `system_health` | chaîne (`healthy` / `degraded` / `unhealthy`) | `component` (vide = global, ou `caddy` / `boltdb` / `metrics` / `crowdsec` / `certmagic`) |

### Cooldown LRU

Après chaque envoi vers un canal donné, ce canal est mis
en silence pour la durée du **cooldown** de la règle (30 s
minimum, 24 h maximum, 5 minutes par défaut). Pendant le
cooldown, même si la condition reste vraie, aucun nouveau
message n'est envoyé sur ce canal pour cette règle. Évite
le pager-fatigue : une condition persistante produit un
unique message par cycle de cooldown, pas un message par
tick de 30 s.

Le cooldown est **per-(règle, canal)** : si une même règle
cible 3 canaux, chacun a son propre cooldown indépendant.
Le cooldown est en mémoire seulement — un redémarrage
d'Arenet remet à zéro tous les compteurs (V2 candidat :
persistance).

### Sévérité

Quatre niveaux (entiers 0..3) :

| Niveau | Token | Label FR | Sémantique |
|---|---|---|---|
| 0 | `info` | Info | Informationnel, aucune action requise |
| 1 | `warning` | Avertissement | Condition dégradée à surveiller |
| 2 | `critical` | Critique | Action opérateur requise sous peu |
| 3 | `emergency` | Urgence | Arenet en difficulté, plan de données impacté possible |

La sévérité de la règle se propage à l'événement émis et au
canal de routage (via le filtre `minSeverity` du canal).

## Configurer un canal webhook

### Cas d'usage

- **Slack** — créer une "Incoming Webhook" dans Slack,
  copier l'URL `https://hooks.slack.com/services/...`,
  configurer un canal avec template body `{"text":"[{{.Severity}}] {{.Subject}}"}`.
- **Discord** — créer un Webhook dans les paramètres du
  salon, utiliser l'URL `https://discord.com/api/webhooks/...`,
  template body `{"content":"[{{.Severity}}] {{.Subject}}\n{{.Body}}"}`.
- **n8n / Make / Zapier** — utiliser un trigger Webhook,
  Arenet émet le `AlertEvent` complet en JSON (laisser
  les templates vides pour récupérer la structure native).
- **Alertmanager** — pas de support natif V1 (le format
  Arenet n'est pas le format Prometheus AlertManager).
  Utiliser un proxy de format si nécessaire.

### Étapes

1. Aller dans **Alerting** dans la barre latérale.
2. Onglet **Canaux** → bouton **Ajouter un canal**.
3. Choisir **Type = Webhook**, donner un **Nom** en
   slug (ex : `slack-ops`, `discord-alerts`).
4. Laisser **Actif** coché.
5. Choisir une **Sévérité minimum** :
   - `Info` pour tout recevoir.
   - `Critique` pour ne recevoir que les niveaux 2-3.
6. **URL** : coller l'URL fournie par le récepteur
   (Slack/Discord/n8n).
7. **Méthode** : `POST` (seule valeur supportée V1).
8. **Timeout (s)** : 10 s par défaut. Augmenter si le
   récepteur est lent (max 60 s).
9. **En-têtes HTTP** : ajouter `Authorization: Bearer ...`
   ou `X-Custom-Header: ...` si le récepteur l'exige.
   Les valeurs d'en-têtes sont stockées en clair et
   redactées (`[redacted]`) lors de la lecture API et
   dans l'audit log.
10. **Template du corps** (optionnel) : si vide, Arenet
    envoie l'événement complet en JSON. Si rempli, le
    template Go (`text/template`) est rendu avec les
    placeholders documentés ci-dessous.
11. **Créer**.
12. **Édit** sur la ligne créée → bouton **Envoyer un
    test** dans le pied de la modale → vérifier qu'un
    toast vert apparaît et que le récepteur reçoit
    bien le message.

### Placeholders disponibles dans les templates de canal

Le canal voit chaque `AlertEvent` au moment de l'envoi.
Les champs disponibles via Go `text/template` :

| Placeholder | Description |
|---|---|
| `{{.ID}}` | UUID unique de l'événement |
| `{{.Timestamp}}` | Horodatage UTC RFC 3339 |
| `{{.RuleID}}` | UUID de la règle qui a déclenché |
| `{{.RuleName}}` | Nom slug de la règle |
| `{{.Severity}}` | Token `info` / `warning` / `critical` / `emergency` |
| `{{.Category}}` | Catégorie opérateur-définie |
| `{{.Subject}}` | Sujet (rendu à l'avance par la règle) |
| `{{.Body}}` | Corps (rendu à l'avance par la règle) |
| `{{.Labels.<key>}}` | Labels propagés depuis la source |
| `{{.Context.<key>}}` | Contexte structuré propagé depuis la source |

Les fonctions de template additionnelles (sprig) **ne
sont pas disponibles** V1 — voir [Limitations V1](#limitations-v1).

## Configurer un canal email

### Pré-requis

Un relais SMTP accessible : votre fournisseur (Gmail,
ProtonMail, mailgun), un Postfix local, ou
[maildev](https://github.com/maildev/maildev) pour tester
localement (`docker run -p 1080:1080 -p 1025:1025 maildev/maildev`).

### Étapes

1. Onglet **Canaux** → **Ajouter un canal**.
2. **Type = Email**, donner un nom slug.
3. **Sévérité minimum** : selon ce que ce canal doit
   recevoir (cf. webhook).
4. **Hôte SMTP** : le hostname sans port (ex :
   `smtp.gmail.com`, `localhost` pour maildev).
5. **Port** : 587 (STARTTLS, le plus courant), 465 (TLS
   implicite), 25 (non chiffré, déconseillé sauf local).
6. **Utilisateur SMTP** + **Mot de passe SMTP** : laisser
   vides pour un relais local sans auth. Sinon les
   credentials fournis par le provider. En mode
   **Édit**, le mot de passe est affiché comme
   `[défini]` ; cocher **Modifier le mot de passe** pour
   le remplacer.
7. **From** : l'adresse expéditeur (doit être autorisée
   par le relais, sinon rejet 550).
8. **To** : un ou plusieurs destinataires (boutons
   `+ Ajouter` / `×`).
9. **Options avancées** (collapsible) : Cc, Bcc.
10. **Chiffrement** :
    - **STARTTLS (port 587)** — recommandé par défaut.
    - **TLS implicite (port 465)** — relais legacy.
    - **Aucun** — uniquement pour les relais locaux
      isolés.
11. **Templates** (optionnel) : sujet et corps. Mêmes
    placeholders que webhook.
12. **Créer** → **Édit** → **Envoyer un test** pour
    vérifier qu'un email arrive bien à destination.

### Test local avec maildev

```sh
docker run --rm -p 1080:1080 -p 1025:1025 maildev/maildev
```

Configurer le canal avec :

- **Hôte SMTP** : `localhost`
- **Port** : `1025`
- **Utilisateur / Mot de passe** : laisser vides
- **From** : `alerts@arenet.local`
- **To** : `ops@arenet.local`
- **Chiffrement** : **Aucun**

Le bouton **Envoyer un test** déclenche l'envoi ; le
message apparaît instantanément dans l'UI maildev sur
<http://localhost:1080>.

## Configurer une règle

### Étapes générales

1. Onglet **Règles** → **Ajouter une règle**.
2. **Nom** : un slug court (`block-rate-high`,
   `cert-expiring`, `crowdsec-down`).
3. **État** : décocher pour créer la règle en silence
   (utile pour préparer une règle complexe avant
   activation).
4. **Catégorie** : libre (ex : `waf`, `cert`, `system`).
   Surfacée dans l'historique et dans la `Category` de
   l'événement.
5. **Sévérité** : du niveau de l'alerte émise (voir
   tableau plus haut).
6. **Source** + **paramètres** : voir sections par source
   ci-dessous.
7. **Type de règle** :
   - **Seuil (numérique)** pour `waf_event_rate` et
     `cert_expiry`.
   - **État (chaîne)** pour `system_health`.
8. **Paramètres d'évaluation** : opérateur + valeur seuil,
   ou valeur attendue.
9. **Canaux** : cocher au moins un canal actif.
10. **Cooldown (secondes)** : 30 minimum, 86400 maximum.
    Voir [Cooldown LRU](#cooldown-lru).
11. **Templates** (collapsible, optionnel) : sujet/corps
    personnalisés. Sinon défauts :
    - Sujet : `[{{.Severity}}] {{.RuleName}} fired`
    - Corps : `Rule {{.RuleName}} fired. Source {{.Source}} value: {{.Value}}`
12. **Créer**.

### Source `waf_event_rate`

**Cas d'usage** — détecter une attaque WAF en cours
(scanning, brute-force, fuzzing) en surveillant le taux
de blocages.

- **Route** : sélectionner une route spécifique pour ne
  surveiller que celle-ci, ou **Toutes les routes** pour
  agréger.
- **Fenêtre (secondes)** : durée du compteur glissant.
  300 (5 min) est un bon défaut ; 60 pour réagir vite,
  3600 pour lisser les pics légitimes.
- **Action** : `BLOCK` ne compte que les blocages durs ;
  `DETECT` ne compte que les événements en mode
  détection (pas de blocage effectif) ; **Toutes**
  agrège.

**Évaluation** — type **Seuil**, opérateur `>`, valeur
seuil = nombre d'événements au-dessus duquel alerter.

**Exemple** — "alerter en `Critique` si > 50 blocages WAF
sur la route `api` en 5 minutes, cooldown 10 minutes" :

- Source = `waf_event_rate`
- routeId = `<uuid de la route api>`, windowSecs = 300,
  action = `BLOCK`
- Évaluateur = Seuil, opérateur `>`, valeur 50
- Sévérité = Critique, cooldown = 600

### Source `cert_expiry`

**Cas d'usage** — alerter avant qu'un certificat n'expire
(Let's Encrypt renouvelle à T-30j ; un cert à T-14j sans
renouvellement automatique signale un problème).

- **Hôte** (optionnel) : un domaine spécifique. Si vide,
  Arenet surveille le certificat le plus proche
  d'expirer dans le tracker.

**Évaluation** — type **Seuil**. La source émet le nombre
de jours restants avant `NotAfter` (peut être négatif
pour un cert expiré). Opérateur typique : `<`.

**Exemple** — "alerter en `Avertissement` si un cert
expire dans moins de 14 jours, cooldown 24 h pour ne pas
spammer pendant qu'on attend le renouvellement" :

- Source = `cert_expiry`, hôte vide
- Évaluateur = Seuil, opérateur `<`, valeur 14
- Sévérité = Avertissement, cooldown = 86400

### Source `system_health`

**Cas d'usage** — détecter une dégradation d'un composant
interne d'Arenet (admin Caddy bloqué, CrowdSec LAPI
injoignable, BoltDB lent, etc.).

- **Composant** : `Global` pour la santé agrégée, ou un
  composant spécifique : `caddy`, `boltdb`, `metrics`,
  `crowdsec`, `certmagic`.

**Évaluation** — type **État (chaîne)**. La source émet
la valeur courante : `healthy` / `degraded` / `unhealthy`
(la valeur exacte exposée par `/system/health`).

**Exemple** — "alerter en `Critique` si le composant
CrowdSec passe en `degraded`, cooldown 5 minutes" :

- Source = `system_health`, component = `crowdsec`
- Évaluateur = État, valeur attendue = `degraded`
- Sévérité = Critique, cooldown = 300

### Multi-canal routing

Une règle peut cibler plusieurs canaux. Chaque canal a
son propre filtre `minSeverity` côté canal ; un canal qui
filtre à `Critique` ne recevra pas une règle qui fire en
`Avertissement`, même si la règle le cible explicitement.

Le dispatcher essaie chaque canal en séquence ; un canal
en échec n'empêche pas les autres de recevoir l'alerte
(contrat de succès-partiel V1).

### Tuning du cooldown

- **30 s** — minimum, équivalent à 1 fire par tick. À
  réserver aux conditions vraiment transitoires.
- **5 min** — défaut. Bonne valeur pour des alertes
  opérationnelles (WAF, health).
- **1 h** — pour des conditions persistantes où le
  rappel est utile mais pas urgent (cert expiry).
- **24 h** — silence pratique : une alerte par jour
  même si la condition est continue. Utile pour des
  alertes "vous devriez réparer ça mais pas urgent".

Le cooldown est **per-(règle, canal)**, donc une règle
qui cible 3 canaux peut avoir un canal qui re-fire et
deux autres encore en cooldown sans interférence.

## Tester depuis l'UI

Deux boutons **Test** existent, avec des sémantiques
différentes :

### Test d'un canal (bouton dans la table Canaux ou dans
la modale d'édition)

Endpoint : `POST /api/v1/settings/alerting/channels/{id}/test`.

- Construit un événement synthétique avec sujet `Arenet
  alerting test — channel "<nom>"`.
- Dispatche directement vers ce canal **en court-
  circuitant les règles** : l'événement va à ce canal,
  point.
- Respecte toujours `channel.minSeverity` (l'événement
  test est `Info`/niveau 0 ; si le canal filtre à
  ≥ `Avertissement`, le test sera ignoré et le retour
  expliquera pourquoi).
- Met à jour `lastSentAt` / `lastError` sur la ligne.

### Test d'une règle (bouton dans la table Règles ou dans
la modale d'édition)

Endpoint : `POST /api/v1/settings/alerting/rules/{id}/test`.

- **Bypass complet du cooldown** : déclenche
  immédiatement même si la règle a fire récemment.
- **Bypass de `rule.Enabled`** : déclenche même si la
  règle est désactivée (l'opérateur a cliqué Test
  explicitement).
- **Bypass de la source/évaluateur** : ne consulte ni
  la source ni l'évaluateur — l'événement test est
  toujours envoyé.
- Sujet : `[TEST] Arenet alerting rule "<nom>"
  force-fired by operator`.
- Respecte `channel.minSeverity` (cf. ci-dessus).
- Le résultat liste les canaux atteints (`channelsFired`),
  ceux en échec (`errors`), et ceux ignorés
  (`skipped`).

Les deux tests laissent une trace dans l'historique avec
le sujet `[TEST] …` — utile pour repérer rapidement
les fires synthétiques.

## Lire l'historique

L'onglet **Historique** liste les `alert_event` les plus
récents en premier. Chaque ligne :

- **Date** : relative (`il y a 5 min`), hover pour
  l'horodatage UTC exact.
- **Règle** : nom de la règle (snapshot au moment du fire ;
  un renommage de règle ne change pas les anciennes
  lignes).
- **Sévérité** : badge coloré, hover pour la description
  du niveau.
- **Catégorie** : la valeur libre saisie sur la règle.
- **Sujet** : truncate avec hover full.
- **Envoyés** : nombre de canaux qui ont fire avec
  succès, hover pour les IDs.
- **Échecs** : nombre de canaux en échec, hover pour le
  détail des erreurs.

### Filtres

- **Depuis / Jusqu'à** : plage RFC 3339 (laisser vide
  pour open-ended).
- **Sévérité** : un seul niveau ou Toutes.
- **Règle** : sélectionne une règle dans la liste (chargée
  depuis `/rules`).
- **Catégorie** : texte exact (insensible à la casse côté
  serveur).

Les changements de filtres sont auto-appliqués après 300
ms de debounce. **Réinitialiser les filtres** efface
tout en un clic.

### Pagination

Cursor-based, 50 lignes par page. Bouton **Charger plus**
en bas tant qu'un curseur reste disponible.

### Rétention

30 jours au niveau ligne (mirror des autres tables
d'événements). Le pruner tourne dans la boucle de
retention horaire. Plus long → snapshot `metrics.db`
externe.

## Dépannage

### "Ma règle ne fire pas"

Checklist :

1. **La règle est-elle active ?** Onglet Règles → badge
   `Actif`. Si `Désactivé`, le watcher l'ignore. Cliquer
   Édit → cocher État → Enregistrer.
2. **Le watcher tourne-t-il ?** Dans le log de boot
   arenet, chercher :
   ```
   alerting watcher started interval=30s sources=[cert_expiry system_health waf_event_rate]
   ```
   Si absent, l'observabilité est probablement en mode
   dégradé (cf. `/system/health`).
3. **La condition est-elle réellement satisfaite ?**
   Cliquer **Test** sur la règle pour forcer un envoi —
   si Test fonctionne mais la règle ne fire pas
   automatiquement, c'est que la source ne retourne
   pas la valeur attendue. Vérifier les paramètres de
   source dans Édit.
4. **Cooldown actif ?** La colonne **Dernière fire**
   montre quand le dernier envoi a eu lieu. Si c'est
   récent et le cooldown long, attendre, ou utiliser
   Test pour bypasser.
5. **Les canaux sont-ils actifs ?** Onglet Canaux →
   chaque canal de la règle doit être `Actif`. Le
   filtre `minSeverity` du canal doit accepter la
   sévérité de la règle.
6. **`lastError` sur la règle ?** Colonne **Dernière
   éval** avec badge `Erreur` → hover pour le message
   (souvent : source non enregistrée, paramètre invalide,
   timeout source).

### "Mes webhooks fail"

- **URL invalide** : doit commencer par `http://` ou
  `https://`. Vérifier que l'hôte est joignable depuis
  arenet (pas de blocage firewall).
- **Certificat TLS non vérifié** : Arenet utilise le
  trust-store système. Pour un récepteur self-signé,
  installer le CA dans `/etc/ssl/certs/` ou utiliser
  HTTP.
- **Timeout** : le défaut 10 s convient à la plupart
  des récepteurs publics (Slack, Discord). Augmenter
  jusqu'à 60 s pour un endpoint plus lent.
- **Headers redactés à la lecture** : c'est intentionnel
  côté API GET (`[redacted]` au lieu de la valeur). Le
  vrai secret reste stocké et envoyé. Si vous voulez
  rotater, taper la nouvelle valeur dans l'éditeur de
  header (laisser `[redacted]` tel quel pour conserver
  l'ancien).
- **5xx upstream** : pas de retry V1. Le canal récepteur
  doit être stable, ou utiliser un buffer intermédiaire
  (n8n, AWS SQS, etc.).

### "Mes emails fail"

- **`email: dial smtp` connect refused** : hôte/port
  inaccessible. Vérifier `telnet host port` depuis la
  machine.
- **`email: starttls`** : le serveur ne supporte pas
  STARTTLS sur ce port. Essayer TLS implicite (465)
  ou aucun chiffrement (25, local only).
- **`email: auth: 535`** : credentials rejetés. Vérifier
  username/password (en édit, cocher **Modifier le mot
  de passe** pour saisir une nouvelle valeur).
- **`email: RCPT TO ...: 550`** : un des destinataires
  est invalide ou le relais refuse de transmettre. Souvent
  la `From` n'est pas autorisée par le relais.
- **Gmail** : nécessite un App Password ; les mots de
  passe principaux ne fonctionnent plus depuis 2022.

### "Le watcher semble inactif"

- Vérifier `GET /healthz` → doit retourner 200.
- Vérifier `GET /system/health` → si le composant
  `metrics` est `unhealthy`, l'observabilité est down
  et la source `waf_event_rate` ne peut pas lire.
- Chercher dans le journalctl :
  ```
  alerting watcher started
  ```
  Si absent, soit arenet n'a pas terminé son boot, soit
  une erreur de wiring (chercher `alerting: ` dans le log).
- Le watcher polle toutes les 30 s. Pour un test rapide,
  cliquer **Test** sur une règle (bypass watcher) pour
  vérifier l'aval (dispatcher + sink + History).

## Architecture en bref

```
┌─────────────────┐    poll 30s    ┌──────────────┐
│   AlertRule     │───────────────▶│   Watcher    │
│   (BoltDB)      │                │  (goroutine) │
└─────────────────┘                └──────┬───────┘
                                          │ source.Read(params)
                                          ▼
┌─────────────────┐                ┌──────────────┐
│   Source        │◀───────────────│  Evaluator   │
│   registry      │                │  (threshold  │
│   (in-memory)   │                │   / state)   │
└─────────────────┘                └──────┬───────┘
                                          │ fire = true
                                          ▼
┌─────────────────┐    skip if     ┌──────────────┐
│   Cooldown LRU  │◀───────────────│  Dispatcher  │
│   (in-memory)   │                │  fan-out     │
└─────────────────┘                └──────┬───────┘
                                          │ per channel
                                          ▼
                          ┌───────────────┼────────────────┐
                          ▼               ▼                ▼
                    ┌─────────┐     ┌─────────┐      ┌──────────┐
                    │ Webhook │     │  Email  │      │  ...V2   │
                    │ Sender  │     │ Sender  │      │  Slack ? │
                    └────┬────┘     └────┬────┘      └──────────┘
                         │               │
                         └───────┬───────┘
                                 │ alert_event row
                                 ▼
                          ┌─────────────┐
                          │  SQLite     │
                          │ alert_event │──▶ History tab
                          └─────────────┘
```

- **Stockage** :
  - BoltDB : channels, rules.
  - SQLite (`metrics.db`) : `alert_event` (30 jours).
- **Goroutines** : 1 watcher (`Run(ctx)`), drivée par un
  `time.Ticker` 30 s + un tick immédiat au boot.
- **Concurrence** : LRU sous `sync.Mutex` (V1 sequential
  per-rule).

## Limitations V1

Les choses ci-dessous sont des choix V1 conscients et
documentés. Aucune n'est un bug.

- **Source picker hardcodé** — 3 sources V1
  (waf_event_rate, cert_expiry, system_health). Le
  registre est statique au boot ; exposer un endpoint
  dynamique apporterait zéro gain pour l'opérateur.
  V2 si une demande émerge.
- **Pas de retry sur échec d'envoi** — un seul essai
  par fire. Si le récepteur est down, l'alerte est
  perdue (le log et l'audit contiennent l'erreur,
  mais pas de re-tentative). KISS V1, dépend de la
  stabilité du récepteur.
- **Pas de Slack/Discord natifs** — utiliser webhook
  avec template body au format attendu (cf. exemples
  plus haut). V2 candidat si la mise en forme des
  templates devient ennuyeuse.
- **Cooldown reset au restart** — le cooldown LRU est
  en mémoire seulement. Un restart d'arenet pendant
  une incident peut re-déclencher toutes les règles.
  V2 candidat : persistence BoltDB.
- **Pas de notifications "resolved"** — Arenet émet
  quand une condition devient vraie, pas quand elle
  redevient fausse. Pratique pour le pager-fatigue
  (pas de "all clear" spam) mais peut surprendre les
  utilisateurs venant d'Alertmanager.
- **Templates sandboxés** — Go `text/template` stdlib
  uniquement, **pas de sprig**. Les fonctions `env`,
  `expandenv`, `tpl` et autres exposeraient des
  surfaces SSRF / RCE pour un template hand-edité par
  l'opérateur (voir ADR Step AL D8). Les built-ins
  stdlib (`printf`, `eq`, `len`) suffisent pour V1.
- **Mono-tenant** — pas de notion d'organisation ou
  d'équipe. Toute la config alerting est partagée
  par tous les admins.
- **Webhook POST seulement** — pas de PUT/PATCH. V2
  candidat si un récepteur l'exige (rare en pratique).

## Références

- Spec : `docs/superpowers/specs/2026-06-15-step-al-alerting.md`
- ADR : `docs/superpowers/decisions/2026-06-15-step-al-decisions.md`
- Smoke test opérateur : `docs/smoke-test-step-al.md`
- Release notes : `docs/release-notes/v1.7.0-step-al.md`

## Endpoints API

Pour les opérateurs qui préfèrent l'API directe (CI, scripts) :

| Méthode | Chemin | Description |
|---|---|---|
| `GET` | `/api/v1/settings/alerting/channels` | Liste des canaux (secrets redactés) |
| `POST` | `/api/v1/settings/alerting/channels` | Créer un canal |
| `GET` | `/api/v1/settings/alerting/channels/{id}` | Détail (secrets redactés) |
| `PUT` | `/api/v1/settings/alerting/channels/{id}` | Mise à jour (preserve-on-omit pour secrets) |
| `DELETE` | `/api/v1/settings/alerting/channels/{id}` | Suppression |
| `POST` | `/api/v1/settings/alerting/channels/{id}/test` | Envoi synthétique |
| `GET` | `/api/v1/settings/alerting/rules` | Liste des règles |
| `POST` | `/api/v1/settings/alerting/rules` | Créer une règle |
| `GET` | `/api/v1/settings/alerting/rules/{id}` | Détail |
| `PUT` | `/api/v1/settings/alerting/rules/{id}` | Mise à jour |
| `DELETE` | `/api/v1/settings/alerting/rules/{id}` | Suppression |
| `POST` | `/api/v1/settings/alerting/rules/{id}/test` | Envoi forcé bypass cooldown |
| `GET` | `/api/v1/observability/alert-events` | Historique avec pagination |

Toutes les routes sous `/settings/alerting/` sont
admin-only ; `/observability/alert-events` est
viewer+ accessible.
