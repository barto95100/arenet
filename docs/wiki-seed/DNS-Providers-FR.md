# DNS Providers

[English](DNS-Providers) · **🌐 Français**

Arenet émet des **certificats TLS wildcard** (`*.example.com`) via le challenge ACME **DNS-01**, qui nécessite un accès API à ta zone DNS. Un *DNS provider* dans Arenet est un jeu de credentials sauvegardé pour cette API. Depuis la **v2.12.0**, tu peux configurer **plusieurs** providers — par exemple un compte OVH pour tes domaines perso et un autre pour le travail — et faire pointer chaque wildcard vers celui qui possède sa zone.

> **OVH est le seul type de provider en v1.** Le design est extensible à d'autres types (Cloudflare, Route53) — voir [backlog V3](#backlog-v3).

---

## Pourquoi DNS-01 (et quand un provider est nécessaire)

Les certificats par route utilisent le challenge **HTTP-01** par défaut et ne nécessitent **aucun** DNS provider — Caddy répond au challenge sur `:80`. Un DNS provider n'est nécessaire que pour les certificats **wildcard**, car un wildcard ne peut pas être validé en HTTP-01 ; ACME exige DNS-01 pour `*.example.com`.

| Tu veux… | Challenge | DNS provider requis ? |
| -------- | --------- | --------------------- |
| Un cert pour `app.example.com` (host unique) | HTTP-01 (défaut) | Non |
| Un wildcard `*.example.com` (tous les sous-domaines) | DNS-01 | **Oui** |
| Un host unique en DNS-01 (ex. derrière un firewall avec :80 fermé) | DNS-01 | **Oui** |

---

## Multi-config (v2.12.0)

Chaque provider est une entrée indépendante avec :

| Champ | Signification |
| ----- | ------------- |
| **Libellé** | Un nom libre que tu choisis (ex. `OVH perso`, `OVH pro`). Affiché dans le dropdown du wizard. |
| **Type** | `ovh` (le seul type en v1). |
| **Endpoint** | La région OVH : `ovh-eu`, `ovh-ca`, `ovh-us`, `kimsufi-eu`, `kimsufi-ca`, `soyoustart-eu`, `soyoustart-ca`. |
| **Application key / Application secret / Consumer key** | Les trois credentials API OVH (gardés secrets ; jamais réaffichés après sauvegarde). |

Deux providers utilisant des comptes OVH différents portent chacun leurs propres credentials, si bien que les wildcards sur des zones appartenant à des comptes distincts se valident chacun via le bon.

---

## Configuration, étape par étape

### 1. Créer les credentials API OVH

Dans la console API OVH (`https://api.ovh.com/createToken/` pour `ovh-eu`), crée un token avec les droits sur la zone DNS dont certmagic a besoin :

- `GET /domain/zone/*`
- `PUT /domain/zone/*`
- `POST /domain/zone/*`
- `DELETE /domain/zone/*`

Tu obtiens une **Application key**, une **Application secret** et une **Consumer key**. Note-les — ce sont les trois champs secrets ci-dessous.

### 2. Ajouter le provider dans Arenet

Ouvre **Réglages → DNS Providers → + Ajouter un provider DNS**, puis remplis :

- **Libellé** — un nom qui te parle (`OVH perso`).
- **Endpoint** — ta région OVH (`ovh-eu` pour la plupart des comptes européens).
- **Application key / Application secret / Consumer key** — issus de l'étape 1.

Enregistre. La ligne affiche un badge `configuré`. Ajoute un second provider de la même manière si tu gères un second compte.

> Tu édites un provider plus tard ? Laisse les champs secrets **vides** pour conserver les valeurs stockées (ne re-saisis un secret que si tu le fais tourner).

### 3. Créer un certificat wildcard

Va dans **Certificats → + Wildcard apex**. Le wizard demande :

- **Domaine apex** — ex. `example.com` (le wildcard `*.example.com` est implicite).
- **DNS provider** — le dropdown liste tes providers configurés par libellé ; choisis celui qui possède cette zone.
- **Inclure l'apex nu dans le SAN du cert** — couvrir aussi `example.com` lui-même, pas seulement ses sous-domaines.

Une fois déclaré, chaque route dont le host correspond à `*.example.com` est servie par ce seul certificat wildcard.

---

## Migration depuis l'ancien provider unique

Avant la v2.12.0, il n'y avait qu'une seule config OVH globale. Au **premier démarrage de la v2.12.0+**, Arenet la migre automatiquement :

- L'ancienne config devient un provider libellé **« OVH (default) »** avec un id stable.
- Chaque wildcard existant est re-pointé dessus.

La migration est **transparente et idempotente** — aucune coupure ACME, rien à faire. Un restore d'un backup antérieur à la v2.12 suit le même chemin au démarrage suivant.

---

## Sûreté à la sauvegarde (v2.12.2)

Modifier un provider prend désormais effet **immédiatement** dans la config Caddy en cours (création, édition et suppression rechargent toutes Caddy). Deux garde-fous protègent tes certs :

- **Supprimer un provider encore utilisé par un wildcard** est refusé avec une erreur claire nommant les wildcards bloquants — réassigne-les ou supprime-les d'abord.
- **Supprimer le dernier provider configuré alors que des routes DNS-01 en dépendent** est refusé aussi (elles retomberaient sinon silencieusement sur un cert auto-signé). Supprimer un provider *de rechange* alors qu'un autre configuré reste est autorisé.

Si un host DNS-01 se retrouve sans provider configuré (ex. via un import incohérent), Arenet émet un avertissement explicite nommant les hosts concernés au lieu d'échouer en silence.

---

## Dépannage

| Symptôme | Cause probable | Solution |
| -------- | -------------- | -------- |
| Cert wildcard bloqué / la route sert un cert auto-signé | Aucun provider configuré, ou credentials erronés | Ajoute/corrige le provider dans les Réglages ; surveille `journalctl -u arenet` pour les erreurs ACME |
| `acmeChallenge "dns-01" requires a configured DNS provider` (400 à la sauvegarde d'une route) | Route en DNS-01 sans provider | Configure d'abord un provider, ou utilise HTTP-01 pour cette route |
| Impossible de supprimer un provider (409) | Il est encore référencé par un wildcard, ou c'est le dernier dont une route DNS-01 a besoin | Réassigne/supprime ces wildcards ou routes d'abord |
| Credentials rejetés par OVH | Token sans droits sur la zone ou mauvaise région | Recrée le token avec les quatre règles `/domain/zone/*` ; vérifie que l'endpoint correspond à la région de ton compte |

Aide plus générale : [Troubleshooting](Troubleshooting-FR).

---

## Rester à jour

La v2.12.3 d'Arenet a ajouté un **vérificateur de mises à jour opt-in**. Active-le dans **Réglages → Mises à jour** pour être notifié (badge dans la topbar + règle d'alerting optionnelle) quand une version stable plus récente sort — pour qu'un correctif comme la sûreté ci-dessus t'arrive rapidement. Arenet ne se met jamais à jour tout seul ; tu gardes le contrôle du moment de la mise à niveau.

Le **switch d'activation est UI uniquement** (pas de toggle env — le check reste inactif tant que tu n'as pas opt-in). Une fois activé, le check tourne ~30s après le boot puis toutes les **24h** ; un bouton « Vérifier maintenant » contourne la cadence. Pour changer la cadence, définis **`ARENET_UPDATE_CHECK_INTERVAL`** (une durée Go comme `12h` ; défaut `24h`, minimum `1h` — les valeurs plus basses ou invalides retombent sur `24h`). Vois comment mettre à jour une fois notifié dans [Mettre à jour Arenet](Updates-FR).

---

## Backlog V3

- **Test de connexion** — un bouton pour valider les credentials OVH d'un provider sans sauvegarder de cert.
- **Plus de types de providers** — Cloudflare, Route53. Le champ `Type` et l'icône de provider du wizard le préparent déjà.

---

_Voir aussi : [Routes](Routes-FR) · [Installation](Installation-FR) · [Backup & Restore](Backup-Restore-FR)_
