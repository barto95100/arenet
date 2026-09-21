# DNS Providers

[English](DNS-Providers) · **🌐 Français**

Arenet émet des **certificats TLS wildcard** (`*.example.com`) via le challenge ACME **DNS-01**, qui nécessite un accès API à ta zone DNS. Un *DNS provider* dans Arenet est un jeu de credentials sauvegardé pour cette API. Depuis la **v2.12.0**, tu peux configurer **plusieurs** providers — par exemple un compte OVH pour tes domaines perso et un autre pour le travail — et faire pointer chaque wildcard vers celui qui possède sa zone.

> **Depuis la v2.26.0, neuf types de providers sont supportés** — OVHcloud, Cloudflare, DigitalOcean, Gandi, Hetzner, Infomaniak, Porkbun, Amazon Route 53 et Scaleway. Voir [Providers supportés](#providers-supportés-v2260).

---

## Pourquoi DNS-01 (et quand un provider est nécessaire)

Les certificats par route utilisent le challenge **HTTP-01** par défaut et ne nécessitent **aucun** DNS provider — Caddy répond au challenge sur `:80`. Un DNS provider n'est nécessaire que pour les certificats **wildcard**, car un wildcard ne peut pas être validé en HTTP-01 ; ACME exige DNS-01 pour `*.example.com`.

| Tu veux… | Challenge | DNS provider requis ? |
| -------- | --------- | --------------------- |
| Un cert pour `app.example.com` (host unique) | HTTP-01 (défaut) | Non |
| Un wildcard `*.example.com` (tous les sous-domaines) | DNS-01 | **Oui** |
| Un host unique en DNS-01 (ex. derrière un firewall avec :80 fermé) | DNS-01 | **Oui** |

---

## Providers supportés (v2.26.0)

| Type | Credentials | Droits nécessaires au token |
| ---- | ----------- | --------------------------- |
| **OVHcloud** | Endpoint (région), Application key, Application secret, Consumer key | `GET/PUT/POST/DELETE /domain/zone/*` |
| **Cloudflare** | Jeton API, jeton de zone facultatif | *Zone → DNS → Edit* sur la ou les zones. Si le jeton API est limité à certaines zones, ajoute un *jeton de zone* avec *Zone → Zone → Read* sur toutes les zones |
| **DigitalOcean** | Jeton API | Lecture + écriture (ou les scopes `domain` read/create/update/delete) |
| **Gandi** | Jeton d'accès personnel | *Gérer la configuration technique des noms de domaine* (LiveDNS) sur le domaine |
| **Hetzner** | Jeton API Hetzner **Cloud** | Read & Write sur le projet qui héberge la zone. Les zones doivent être dans le DNS de la nouvelle Hetzner Console — les jetons de l'ancienne DNS Console (dns.hetzner.com) ne fonctionnent pas |
| **Infomaniak** | Jeton API | Le scope *domain* |
| **Porkbun** | Clé API, clé API secrète | L'*API Access* doit être activé sur chaque domaine dans le tableau de bord Porkbun |
| **Amazon Route 53** | Région, ID de clé d'accès, clé d'accès secrète, ID de zone hébergée facultatif | `route53:ListHostedZonesByName`, `ListResourceRecordSets`, `ChangeResourceRecordSets`, `GetChange` |
| **Scaleway** | Clé secrète (clé API IAM), ID d'organisation | *DomainsDNSFullAccess* |

> **Statut des tests.** OVHcloud est le provider de référence, testé en réel par le mainteneur. Les huit autres sont **validés automatiquement** — chaque build vérifie que les champs de credentials d'Arenet correspondent au vrai module DNS Caddy de chaque provider, et le smoke de la v2.26.0 a confirmé que chaque module atteint la vraie API du provider (en rejetant proprement des credentials factices) — mais ils ne sont **pas testés de bout en bout par le mainteneur** (pas de compte chez eux) : aucun certificat réel n'a encore été émis via ces providers. Utilise le bouton [Tester la connexion](#tester-la-connexion-v2260) pour vérifier tes propres credentials, et signale tout problème.

Chaque formulaire de provider renvoie vers la page où créer ses credentials. Les droits évoluent côté providers — en cas de doute, leur propre documentation fait foi.

---

## Multi-config (v2.12.0)

Chaque provider est une entrée indépendante avec :

| Champ | Signification |
| ----- | ------------- |
| **Libellé** | Un nom libre que tu choisis (ex. `OVH perso`, `Cloudflare pro`). Affiché dans le dropdown du wizard. |
| **Type** | Un des [providers supportés](#providers-supportés-v2260). Choisi à la création ; pour changer de type, supprime puis recrée le provider. |
| **Credentials** | Les champs de ce type (voir le tableau ci-dessus). Les champs secrets ne sont jamais réaffichés après sauvegarde ; les autres (endpoint OVH, région Route 53, ID d'organisation Scaleway…) sont affichés dans la liste. |

Deux providers — du même type avec des comptes différents, ou de types différents — portent chacun leurs propres credentials, si bien que les wildcards sur des zones appartenant à des comptes ou providers distincts se valident chacun via le bon.

---

## Configuration, étape par étape

### 1. Créer les credentials API

Crée un token avec les droits listés dans [Providers supportés](#providers-supportés-v2260) (le formulaire d'Arenet renvoie vers la bonne page pour chaque type). Exemple pour **OVHcloud** : dans la console API OVH (`https://api.ovh.com/createToken/` pour `ovh-eu`), crée un token avec les droits sur la zone DNS dont certmagic a besoin :

- `GET /domain/zone/*`
- `PUT /domain/zone/*`
- `POST /domain/zone/*`
- `DELETE /domain/zone/*`

Tu obtiens une **Application key**, une **Application secret** et une **Consumer key**. Note-les — ce sont les trois champs secrets ci-dessous.

Pour **Cloudflare** : *My Profile → API Tokens → Create Token*, modèle *Edit zone DNS*, limité à ta zone.

### 2. Ajouter le provider dans Arenet

Ouvre **Réglages → DNS Providers → + Ajouter un provider DNS**, puis remplis :

- **Libellé** — un nom qui te parle (`OVH perso`).
- **Type** — ton provider DNS. Les champs de credentials s'adaptent (les obligatoires sont marqués `*`).
- **Credentials** — issus de l'étape 1 (pour OVH : l'endpoint, ex. `ovh-eu` pour la plupart des comptes européens, et les trois clés).

Enregistre. La ligne affiche un badge `configuré`. Clique sur **⚡ Tester la connexion** sur la ligne pour vérifier les credentials tout de suite. Ajoute d'autres providers de la même manière pour d'autres comptes.

> Tu édites un provider plus tard ? Laisse les champs secrets **vides** pour conserver les valeurs stockées (ne re-saisis un secret que si tu le fais tourner).

### 3. Créer un certificat wildcard

Va dans **Certificats → + Wildcard apex**. Le wizard demande :

- **Domaine apex** — ex. `example.com` (le wildcard `*.example.com` est implicite).
- **DNS provider** — le dropdown liste tes providers configurés par libellé ; choisis celui qui possède cette zone.
- **Inclure l'apex nu dans le SAN du cert** — couvrir aussi `example.com` lui-même, pas seulement ses sous-domaines.

Une fois déclaré, chaque route dont le host correspond à `*.example.com` est servie par ce seul certificat wildcard.

---

## Tester la connexion (v2.26.0)

Le bouton **⚡** d'un provider configuré ouvre *Tester la connexion*. Arenet liste les enregistrements d'une zone via l'API du provider avec les credentials enregistrés — le même chemin de code que le challenge ACME DNS-01 — et affiche le nombre d'enregistrements trouvés, ou le message d'erreur du provider.

- **Zone** — pré-remplie avec le premier apex wildcard rattaché au provider ; sinon saisis une zone gérée par le compte (ex. `example.com`).
- **Lecture seule** — rien n'est créé ni modifié dans ta zone.
- Un résultat vert prouve l'authentification et l'accès en **lecture**. L'écriture n'est exercée qu'à l'émission du certificat : si un wildcard échoue quand même, vérifie les droits d'écriture du token.
- Les secrets ne figurent jamais dans le résultat : les messages d'erreur de provider qui recopient un credential sont masqués (`[REDACTED]`).

---

## Migration depuis l'ancien provider unique

Avant la v2.12.0, il n'y avait qu'une seule config OVH globale. Au **premier démarrage de la v2.12.0+**, Arenet la migre automatiquement :

- L'ancienne config devient un provider libellé **« OVH (default) »** avec un id stable.
- Chaque wildcard existant est re-pointé dessus.

La migration est **transparente et idempotente** — aucune coupure ACME, rien à faire. Un restore d'un backup antérieur à la v2.12 suit le même chemin au démarrage suivant.

La v2.26.0 change le format de stockage des credentials des providers (pour supporter plusieurs types). Les providers OVH existants sont convertis automatiquement au démarrage, et les backups faits avec des versions antérieures se restaurent comme avant. La configuration Caddy émise pour un provider OVH est inchangée.

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
| *Tester la connexion* échoue en 401 / 403 / « invalid token » | Credential erroné, ou token sans droits sur cette zone | Recrée le token avec les droits de [Providers supportés](#providers-supportés-v2260) ; vérifie que la zone appartient à ce compte |
| *Tester la connexion* OK mais le wildcard n'est pas émis | Le token peut lire la zone mais pas y écrire d'enregistrements TXT | Accorde les droits d'écriture (édition) sur les enregistrements DNS ; surveille `journalctl -u arenet` pour l'erreur ACME |
| Hetzner : « the token you have provided is invalid » | Jeton de l'ancienne DNS Console, ou zone pas encore migrée | Utilise un jeton API Hetzner **Cloud** et une zone hébergée dans la Hetzner Console |

Aide plus générale : [Troubleshooting](Troubleshooting-FR).

---

## Rester à jour

La v2.12.3 d'Arenet a ajouté un **vérificateur de mises à jour opt-in**. Active-le dans **Réglages → Mises à jour** pour être notifié (badge dans la topbar + règle d'alerting optionnelle) quand une version stable plus récente sort — pour qu'un correctif comme la sûreté ci-dessus t'arrive rapidement. Arenet ne se met jamais à jour tout seul ; tu gardes le contrôle du moment de la mise à niveau.

Le **switch d'activation est UI uniquement** (pas de toggle env — le check reste inactif tant que tu n'as pas opt-in). Une fois activé, le check tourne ~30s après le boot puis toutes les **24h** ; un bouton « Vérifier maintenant » contourne la cadence. Pour changer la cadence, définis **`ARENET_UPDATE_CHECK_INTERVAL`** (une durée Go comme `12h` ; défaut `24h`, minimum `1h` — les valeurs plus basses ou invalides retombent sur `24h`). Vois comment mettre à jour une fois notifié dans [Mettre à jour Arenet](Updates-FR).

---

## Backlog

- **Plus de types de providers** — en ajouter un est désormais un petit changement (entrée de registre + module Caddy) ; ouvre une issue avec le provider dont tu as besoin.
- **Choix du provider par route** pour les routes DNS-01 à host unique (les managed domains choisissent déjà leur provider).
- **Réglages de propagation DNS-01** (résolveurs personnalisés, délai de propagation) pour les configurations split-horizon.

---

_Voir aussi : [Routes](Routes-FR) · [Installation](Installation-FR) · [Backup & Restore](Backup-Restore-FR)_
