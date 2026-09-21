<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Vérification après application d'une route — Design

**Status:** brainstormé avec l'opérateur 2026-09-21, décisions verrouillées.
Vague 2 de l'analyse concurrentielle (CaddyUI : « post-apply checks with
rollback »). Cible : **v2.35.0**.

**One-line :** après l'enregistrement d'une route, Arenet s'envoie une vraie
requête à travers Caddy ; si la route ne répond plus et que revenir à
l'ancienne version la répare, il annule la modification et l'explique —
sinon il garde la modification et avertit.

## Constat (code, 2026-09-21)

- Un **rejet** de config par Caddy est déjà annulé en base
  (`api/routes.go` : create → DeleteRoute, update / toggle → UpdateRoute
  `previous`, delete → RestoreRoute).
- Rien ne vérifie qu'une route **répond** : une route vers un upstream
  injoignable est acceptée, les visiteurs reçoivent des 502.
- Seule sonde existante : directe vers l'upstream (`routes_test_upstream.go`).

## Faits vérifiés (source)

1. Upstream injoignable → **502**, délai dépassé → **504**
   (`caddy/v2 modules/caddyhttp/reverseproxy/reverseproxy.go:1606-1610`),
   aucun upstream disponible (tous « unhealthy ») → **503** (`:640`).
2. Certificat pas encore émis → le handshake TLS échoue
   (« no certificate available », `certmagic/handshake.go:419`) :
   `caddy.Load` rend la main avant la fin de l'émission ACME.
3. Caddy écoute sur toutes les interfaces aux ports HTTP / HTTPS
   (`caddymgr` `HTTPListen` / `HTTPSListen`) ; une route TLS reçoit une
   redirection automatique HTTP → HTTPS.

## Décisions

| # | Décision | Pourquoi |
|---|----------|----------|
| R1 | **Revenir en arrière seulement si ça répare** : échec → remettre l'ancienne version, re-vérifier ; ancienne OK → garder l'annulation (409 + explication) ; ancienne KO aussi → ré-appliquer la modification et avertir. | Un upstream éteint n'est pas la faute de la modification ; ne jamais « punir » une modif qui n'a rien cassé. |
| R2 | **Création / réactivation jamais annulées** (avertissement seul). | On crée souvent la route avant de démarrer le service. |
| R3 | **Sonde = vraie requête à travers Caddy** (`127.0.0.1:<port>`, Host + SNI de la route). | Voit aussi les erreurs de config côté Caddy, pas seulement l'upstream. |
| R4 | **Active par défaut, désactivable** (Réglages). | Sûr par défaut ; échappatoire si un cas particulier gêne. |

## Sonde

- Hôte sondé : l'hôte principal ; s'il est wildcard, le premier alias non
  wildcard ; sinon pas de sonde (`skipped`).
- Routes TLS : `https://127.0.0.1:<https>/` avec SNI = hôte, vérification
  du certificat **désactivée** (on teste le routage, pas la chaîne ;
  certificat interne en dev, staging…). Routes non TLS :
  `http://127.0.0.1:<http>/` avec `Host`.
- Pas de suivi des redirections ; en-tête `X-Arenet-Probe: 1`.
- Résultat :
  - **ok** — toute réponse HTTP hors 502 / 503 / 504 (y compris 401 / 403 /
    3xx / 4xx / 5xx applicatifs : Caddy a routé la requête) ;
  - **failed** — 502 / 503 / 504, ou connexion refusée / délai au listener ;
  - **pending_certificate** — échec du handshake TLS (certificat en cours
    d'émission) : ni échec ni succès, signalé comme tel ;
  - **skipped** — sonde désactivée, route désactivée / en maintenance,
    pas d'hôte sondable.
- Jusqu'à 3 essais espacés de 2 s (délai 4 s chacun) : le premier succès
  arrête ; laisse le temps à Caddy / au backend (≈ 10 s au pire).

## Déroulé par action

| Action | Sonde | Si **failed** |
|---|---|---|
| Création | oui | avertissement (jamais annulée) |
| Modification | oui | ancienne version remise + sondée : OK → annulation (409 `route_check_rolled_back`) ; KO → modification ré-appliquée + avertissement |
| Réactivation | oui | avertissement |
| Désactivation / maintenance / suppression | non | — |

Réponse : le corps habituel gagne `check: {status, httpStatus?, detail}` ;
l'annulation renvoie 409 `route_check_rolled_back` (params : hôte,
statut, détail). Audit : `route_update_rolled_back` avec avant / après.

## Réglage

`storage.RouteCheckConfig{Enabled}` (bucket `route_check`, ligne absente =
**activé**) ; `GET/PUT /settings/route-check` ; inclus dans les
`extras` du backup.

## UI

- Après enregistrement : `ok` → toast habituel ; `failed` → toast d'avertissement
  (route enregistrée mais ne répond pas, avec le statut) ;
  `pending_certificate` → toast d'information ; 409 → le panneau reste
  ouvert avec l'explication (« ta modification a été annulée : la route
  répondait avant et plus après — 502 … »).
- Réglages : interrupteur « Vérifier les routes après enregistrement ».

## Tests / validation

- Unitaires : classification (codes, handshake, refus), choix de l'hôte,
  essais, déroulé (création avertie, modif annulée si l'ancienne marche,
  ré-appliquée sinon, réglage off).
- Smoke binaire réel : modif vers un port fermé → annulée ; upstream
  éteint → modif gardée + avertissement ; nouvelle route TLS publique →
  `pending_certificate` ; réglage off → aucune sonde.

## Non-goals

- ❌ Surveillance continue (les health checks existent).
- ❌ Sonde de chaque règle de chemin / alias (hôte principal, `/`).
- ❌ Annulation d'une suppression.
