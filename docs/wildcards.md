<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Wildcards & Managed Domains — Guide opérateur

Ce document explique comment Arenet gère les certificats
wildcard via le mécanisme des **managed domains**. Couvre la
configuration, l'auto-détection, les scénarios multi-domaines,
les cas particuliers, et le débogage. Référentiel : Step O.1
(commits `Step O`) + Sujet 2 (UX badge, commit ce document).

> **TL;DR**. Aller dans **SSL / Certificates** → ajouter un
> apex (e.g. `example.com`, provider DNS, credentials) →
> Arenet émet un cert `*.example.com` + `example.com` (selon
> `includeApex`) → chaque route sur un sous-domaine direct
> (`api.example.com`, `app.example.com`) hérite
> automatiquement de ce cert, sans demande ACME
> supplémentaire. Le badge **« Couvert par
> *.example.com »** sur la liste des routes confirme
> l'héritage à l'œil.

## Sommaire

1. [Introduction](#introduction)
2. [Pourquoi un wildcard](#pourquoi-un-wildcard)
3. [Configurer un managed domain](#configurer-un-managed-domain)
4. [Règle d'auto-détection — RFC 6125](#règle-dauto-détection--rfc-6125)
5. [Scénarios multi-wildcards](#scénarios-multi-wildcards)
6. [Cas particuliers](#cas-particuliers)
7. [Opt-out — cert dédié par route](#opt-out--cert-dédié-par-route)
8. [Dépannage](#dépannage)
9. [Architecture en bref](#architecture-en-bref)

---

## Introduction

Un **managed domain** est une déclaration unique « j'ai un
apex DNS et je veux qu'Arenet gère un cert wildcard pour
lui ». Une fois cette déclaration créée, toutes les routes
configurées sur un sous-domaine direct de cet apex héritent
automatiquement du cert sans demande ACME individuelle.

Au lieu de N demandes HTTP-01 (une par sous-domaine), Arenet
fait **une** demande DNS-01 et sert le même cert wildcard à
toutes les routes couvertes.

## Pourquoi un wildcard

Trois bénéfices concrets pour un homelab :

- **Moins de demandes ACME.** Une demande DNS-01 par apex
  au lieu de N HTTP-01. Réduit le risque d'atteindre les
  rate limits Let's Encrypt (50 émissions / semaine par
  apex enregistré).
- **Sous-domaines privés.** HTTP-01 nécessite que Let's
  Encrypt joigne le sous-domaine depuis Internet. DNS-01
  ne demande qu'une mise à jour de TXT record → les
  sous-domaines accessibles uniquement depuis le LAN
  (`prometheus.example.com`, `nas.example.com`) peuvent
  obtenir un cert public valide sans exposition.
- **Création de route instantanée.** Pas d'attente
  ACME : la nouvelle route hérite du cert wildcard
  immédiatement, prête à servir TLS dès le premier
  démarrage de Caddy.

## Configurer un managed domain

1. Ouvrir **SSL / Certificates** dans la barre latérale.
2. Cliquer **Add managed domain**.
3. Renseigner :
   - **Apex** : le domaine racine (`example.com`,
     sans `*.` ni sous-domaine).
   - **Provider DNS** : OVH, Cloudflare, Gandi, etc.
     (la liste reflète les providers supportés par
     la version courante).
   - **Credentials** : token API du provider — utilisé
     par Caddy pour mettre à jour le TXT record pendant
     le challenge DNS-01.
   - **Include apex** : si activé (défaut), le cert
     couvre `*.example.com` ET `example.com` (apex
     direct). Si désactivé, seuls les sous-domaines
     directs sont couverts.
4. Valider. Arenet écrit la déclaration dans BoltDB
   (`bucketManagedDomains`) et reconfigure Caddy pour
   émettre le cert.

Au prochain démarrage de Caddy (ou reload), une
demande DNS-01 part vers le provider. Le résultat
arrive en quelques secondes à quelques minutes selon
la latence DNS du provider.

## Règle d'auto-détection — RFC 6125

Quand une route est créée ou éditée, Arenet vérifie si
son hostname est **couvert** par un managed domain
existant. La règle de couverture suit **RFC 6125**, qui
limite les wildcards à **un seul label DNS** entre le
hostname et l'apex.

| Hostname | Apex managed | Couvert ? | Raison |
|---|---|---|---|
| `api.example.com` | `example.com` | ✅ | un label (`api`) |
| `app.example.com` | `example.com` | ✅ | un label (`app`) |
| `example.com` | `example.com` | ✅ (si `includeApex=true`) | apex direct |
| `example.com` | `example.com` | ❌ (si `includeApex=false`) | apex désactivé |
| `deep.api.example.com` | `example.com` | ❌ | deux labels (`deep.api`) |
| `*.example.com` | `example.com` | ❌ | un wildcard ne se couvre pas lui-même |
| `api.other.com` | `example.com` | ❌ | apex différent |

> ⚠️ **Le cas « deux labels » est strict.** Un cert
> `*.example.com` ne couvre PAS `deep.api.example.com`,
> même si beaucoup de validators clients tolèrent le
> multi-label en pratique. Arenet refuse l'auto-héritage
> pour rester aligné sur le standard et éviter de servir
> un cert que certains clients (e.g. Go std `crypto/tls`,
> certains mobiles) rejetteraient. Pour `deep.api.example.com`
> il faut soit un managed domain dédié à `api.example.com`,
> soit un cert dédié à la route.

## Scénarios multi-wildcards

Arenet gère plusieurs managed domains en parallèle. La
matching opère **par hostname** et retient le premier
managed domain qui couvre (ordre lexicographique des apex,
voir [Cas particuliers](#cas-particuliers)).

### Scénario 1 — deux apex distincts

Setup :
- MD #1 : `worldgeekwide.fr`
- MD #2 : `sct-telecom.fr`

Routes :
- `sonarr.worldgeekwide.fr` → couvert par `worldgeekwide.fr`
- `proxmox.sct-telecom.fr` → couvert par `sct-telecom.fr`
- `api.other-domain.com` → non couvert → cert dédié auto-émis

Sur la liste des routes le badge **« Couvert par
*.worldgeekwide.fr »** s'affiche sur les routes du premier
groupe, **« Couvert par *.sct-telecom.fr »** sur le
deuxième, **« Cert dédié (HTTP-01) »** sur la route hors
des deux apex.

### Scénario 2 — apex imbriqués

Setup :
- MD #1 : `example.com`
- MD #2 : `staging.example.com`

Routes :
- `app.example.com` → couvert par `example.com` (`staging`
  ne match pas — `app` n'est pas sous `staging`)
- `app.staging.example.com` → couvert par `staging.example.com`
  ([cas spécifique détaillé ci-dessous](#cas-particuliers))
- `staging.example.com` (apex direct du MD #2) → couvert
  par `staging.example.com` si `includeApex=true`

### Scénario 3 — apex non couvrant

Si le hostname d'une nouvelle route ne matche aucun
managed domain, Arenet bascule sur la stratégie
**per-route ACME** — la route demande son propre cert
via HTTP-01 ou DNS-01 selon la valeur d'`acmeChallenge`
configurée. Le badge affiche alors **« Cert dédié (HTTP-01) »**
ou **« Cert dédié (DNS-01) »**.

## Cas particuliers

### Apex imbriqués — qui gagne ?

Avec MD #1 `example.com` et MD #2 `staging.example.com`,
une route `app.staging.example.com` matche **les deux**
managed domains en théorie :
- contre `example.com` : prefix `app.staging` = deux
  labels → **rejet** (règle RFC 6125 single-label).
- contre `staging.example.com` : prefix `app` = un label
  → **acceptation**.

Donc `staging.example.com` couvre. Pas d'ambiguïté.

Mais si la route est `direct.example.com` :
- contre `example.com` : prefix `direct` = un label → acceptation.
- contre `staging.example.com` : prefix ne se termine pas
  par `.staging.example.com` → rejet.

Là aussi pas d'ambiguïté.

L'ambiguïté n'apparaît que si on a deux MDs identiques
ou se chevauchant (e.g. `example.com` + `example.com` —
rejeté à la création par le storage layer).

### Apex direct (`includeApex`)

Un cert wildcard `*.example.com` **ne couvre PAS** l'apex
`example.com` lui-même (RFC 6125). C'est pour ça que
les certs Let's Encrypt wildcards sont en fait double-SAN
`*.example.com` + `example.com` — émis avec le flag
`includeApex=true` côté Arenet (défaut).

Si tu désactives `includeApex`, le cert ne porte pas
l'apex et une route `example.com` ne sera PAS couverte
— elle tombera sur le path per-route ACME comme une
route hors apex.

### Casse + trailing dot

DNS est insensible à la casse et le point final est
canonique (RFC 1035). Arenet normalise :
`App.Example.Com.` matche un apex stocké `example.com`.

### Wildcard explicite dans une route

Une route configurée avec `host: *.example.com` (le
wildcard littéral comme hostname) **ne sera pas
auto-couverte** par un MD `example.com`. La route doit
déclarer son propre `acmeChallenge: dns-01` et son
provider — c'est elle qui définit le wildcard, pas le
MD. Cas rare en pratique.

## Opt-out — cert dédié par route

Pour certains use cases (paiements, staging, debug d'un
cert particulier) on veut un cert dédié alors qu'un
wildcard couvrant existe. Le flag **`useDedicatedCert`**
sur la route active l'opt-out :

1. Sur la route concernée, ouvrir le panneau d'édition.
2. Activer la case **« Use a dedicated cert for this
   route (opt out of the wildcard) »**.
3. Choisir le challenge ACME (`http-01` par défaut,
   `dns-01` si tu veux émettre depuis une zone non
   joignable).
4. Sauvegarder. Le badge bascule de **« Couvert par
   *.example.com »** vers **« Cert dédié (HTTP-01) »** /
   **« Cert dédié (DNS-01) »**.

Le wildcard reste émis (les autres routes continuent de
l'utiliser) — seul cette route demande un cert
supplémentaire.

## Dépannage

### « Pourquoi ma route n'utilise pas le wildcard ? »

Checklist dans l'ordre :

1. **Le badge dit « Cert dédié » au lieu de « Couvert
   par *.X »** → le hostname n'est pas couvert par un
   MD. Vérifier :
   - Le MD existe-t-il et son apex est-il **exact** ?
     (`example.com`, pas `Example.com` ni `*.example.com`)
   - Le hostname de la route a-t-il **un seul label**
     entre lui-même et l'apex ? `deep.api.example.com`
     contre `example.com` est rejeté (RFC 6125).
   - Si la route est l'apex lui-même (`example.com`) :
     l'option `includeApex` est-elle activée sur le MD ?

2. **Le badge dit « Couvert par » mais le cert servi
   est dédié.** Vérifier `useDedicatedCert` sur la
   route — peut-être que l'opt-out est actif.

3. **Le cert wildcard n'est pas encore émis.** La
   demande DNS-01 prend de quelques secondes à
   quelques minutes selon le provider. Pendant ce
   temps Caddy sert un cert auto-signé (Caddy
   internal CA). Vérifier les logs Caddy pour
   `obtained certificate for ...`.

### « Comment vérifier quel cert est utilisé ? »

Plusieurs surfaces :

- **UI routes list** : badge `Couvert par *.<apex>` ou
  `Cert dédié (HTTP-01)` / `Cert dédié (DNS-01)`.
- **API REST** :
  ```
  GET /api/v1/routes
  ```
  Lire le champ `effectiveCertSource` sur chaque route :
  - `managed-domain:example.com` — couvert par le MD `example.com`
  - `per-route-acme:dns-01` — cert dédié DNS-01
  - `per-route-acme:http-01` — cert dédié HTTP-01
  - `per-route-internal` — Caddy interne (auto-signé)
  - absent — pas de TLS sur la route
- **CLI** : `curl -s https://<hostname> | openssl x509 -noout -text` pour
  lire le cert servi (SAN, dates, émetteur).

### « Le wildcard n'a pas été émis »

- Les credentials du provider DNS sont-ils corrects ?
  Tester depuis un autre client (terraform-provider-ovh,
  cli officielle, etc.) — Arenet remonte les erreurs du
  provider dans les logs.
- Le provider supporte-t-il l'API qu'Arenet utilise ?
  La liste figure dans le menu **Provider** de la fiche
  managed domain.
- Y a-t-il un rate limit atteint ? Let's Encrypt rejette
  au-delà de 50 émissions par semaine et par apex.

## Architecture en bref

```
storage.ManagedDomain (BoltDB bucket "managedDomains")
        ↓
storage.ListManagedDomains() — ordre lexicographique
        ↓
caddymgr.IsHostCoveredByManagedDomain(host, mds)
        ↓
        ├─→ true : route servie par le cert wildcard
        │           (config Caddy : tls.policies[].subjects
        │            = *.apex + apex, tls.automation.policies
        │            avec issuer DNS-01)
        │
        └─→ false : per-route ACME (HTTP-01 / DNS-01)
                    OU Caddy internal CA pour les
                    hostnames privés (LAN, .local)
```

**Points clés** :
- L'API REST côté frontend lit le champ dérivé
  `effectiveCertSource` calculé par
  `computeEffectiveCertSource` (`internal/api/handler.go`).
- Le calcul est **pur** sur le tuple (route, liste MDs)
  — pas d'I/O.
- Caddy ne sait rien des managed domains : c'est
  Arenet qui traduit le modèle en config Caddy au
  build-time.

---

**Cross-references** : Step O.1 backlog
(`docs/backlog-step-o.md`), Sujet 2 commit
(badge UX). Pour les détails Go consulter
`internal/caddymgr/managed_domain.go` (matcher
RFC 6125) et `internal/api/handler.go:1407`
(`computeEffectiveCertSource`).
