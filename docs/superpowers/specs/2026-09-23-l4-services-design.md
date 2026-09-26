<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Services TCP (niveau 4) — Design

**Status:** proposé 2026-09-23, décisions à verrouiller avec l'opérateur.
Cas de validation : serveur mail **Stalwart** sur une VM d'un autre réseau,
interface d'administration (Bulwark) déjà servie en HTTPS par une route Arenet.
Cible : **v2.42.0**.

**One-line :** Arenet sait relayer des connexions TCP brutes (mail, et plus
tard d'autres protocoles) vers un backend, en préservant l'IP réelle du client
via le PROXY protocol, avec filtrage d'IP source, décisions CrowdSec et limites
de connexions — sans jamais déchiffrer le trafic.

## Pourquoi maintenant

La documentation de Stalwart recommande explicitement `caddy-l4` (`l4proxy` +
`l4tls`) avec PROXY protocol v2 pour les ports 25 / 465 / 993 / 4190, et précise
qu'il faut recompiler Caddy avec `xcaddy`. Arenet embarque Caddy **comme
bibliothèque** : ajouter les modules à la compilation suffit, l'opérateur n'a
rien à compiler.

## Vérifications empiriques faites avant d'écrire cette spec

| Affirmation | Vérifié où |
|---|---|
| `caddy-l4` expose un proxy TCP/UDP avec health checks, LB, `max_connections` | `modules/l4proxy/proxy.go`, `upstream.go` (champs JSON `upstreams`, `health_checks`, `load_balancing`, `proxy_protocol`) |
| **Correction PR 1** : aucune politique pondérée, et un backend ne porte pas de poids | `modules/l4proxy/loadbalancing.go` — policies : `round_robin`, `least_conn`, `ip_hash`, `first`, `random`, `random_choose` |
| **Correction PR 1** : le champ est `selection` avec une clé `policy` en ligne, pas `selection_policy` | `modules/l4proxy/loadbalancing.go:37` — `caddy.Validate` a refusé la première version |
| **Correction PR 1** : la version indirecte (2023) n'avait ni `handlers.close` ni `matchers.not`, et nommait son matcher IP `ip` | comparaison v0.0.0-2023 / v0.1.1 ; dépendance désormais **directe, épinglée v0.1.1** (v0.1.2 ferait monter quic-go 0.59.1 → 0.60.0, donc la pile HTTP/3) |
| Le PROXY protocol émis est `v1` ou `v2`, refus sinon | `modules/l4proxy/proxy.go:82-83` (Validate) |
| Filtrage d'IP source natif en CIDR | `layer4/matchers.go` (`layer4.matchers.ip`, champ `ranges`) |
| Les décisions CrowdSec s'appliquent au niveau 4 | `caddy-crowdsec-bouncer@v0.13.0/layer4/l4.go:44` → `layer4.matchers.crowdsec` |
| Le SNI peut être lu sans déchiffrer | `modules/l4tls/matcher.go` (lecture du ClientHello) |
| Stalwart accepte le PROXY protocol v1 **et** v2 | stalw.art/docs/server/reverse-proxy/proxy-protocol — `proxyTrustedNetworks`, `overrideProxyTrustedNetworks` (IP ou CIDR) |
| `caddy-l4` est déjà dans l'arbre de dépendances (indirect, via le bouncer) | `go.mod:166` |

## Décisions

| # | Décision | Pourquoi |
|---|----------|----------|
| L1 | **Objet distinct** `TCPService`, pas un champ de `Route`. Entrée de barre latérale séparée. | Une route = un hôte HTTP avec WAF, chemins, pages d'erreur. Un service L4 n'a aucun de ces concepts ; les fondre produirait un formulaire à moitié grisé. |
| L2 | **TCP seulement en v1.** UDP en v2. | Le cas mail n'a pas d'UDP, et l'UDP double la surface de test (pas de connexion, pas de health check au sens TCP). |
| L3 | **Passthrough uniquement en v1** : Arenet ne déchiffre rien. Pas de terminaison TLS, pas de routage SNI. | Sur le 25, TLS se négocie par STARTTLS *après* le début du dialogue SMTP : un proxy L4 ne peut pas s'en mêler. Sur 465/993, terminer obligerait à parler en clair au backend. Stalwart garde ses certificats. |
| L4 | **PROXY protocol v2 proposé par défaut**, réglable (aucun / v1 / v2). L'UI affiche la valeur exacte à reporter dans `proxyTrustedNetworks` côté backend. | Sans lui, le backend voit l'IP d'Arenet : SPF cassé, antispam aveugle, limites par IP inopérantes. La doc de Stalwart prévient qu'un réglage dépareillé **casse les connexions en silence** — d'où le couplage explicite dans l'UI. |
| L5 | **CrowdSec activé par défaut** sur un service quand le bouncer est configuré, désactivable par service. | Le matcher niveau 4 existe et partage l'app CrowdSec déjà provisionnée. Le port 25 est la cible la plus martelée d'une installation mail. |
| L6 | **Filtrage d'IP source** par service (liste d'autorisation / de refus, en CIDR), même vocabulaire que les routes. Un refus est un `handlers.close` **explicite**, jamais l'abandon implicite de caddy-l4. | Natif (`layer4.matchers.remote_ip`). Indispensable pour 4190 / 993 qu'on restreint souvent au LAN ou au VPN. |
| L7 | **Garde-fou de ports** : refus *avant* application pour 80, 443, le port d'admin et 2019 ; refus d'un port déjà pris par un autre service ; détection de l'absence de `CAP_NET_BIND_SERVICE` pour un port < 1024 avec le message d'action exact. | Un échec de rechargement Caddy est bien pire qu'un refus de validation : la config live peut rester en plan. |
| L8 | **Avertissement Docker** : si Arenet tourne en conteneur, l'UI affiche la ligne `ports:` à ajouter au compose. | Sinon tout est vert dans l'interface et rien ne fonctionne — le port n'est pas publié. |
| L9 | **Ce qui ne s'applique pas est écrit dans l'UI** : pas de WAF, pas de pages d'erreur, pas de blocage par pays, pas d'authentification. | Ne pas laisser croire qu'un service Postgres est protégé par le CRS. |
| L10 | **Un `layer4` server par service**, nommé d'après l'id du service. | Isole les erreurs de provisioning : un service invalide ne fait pas tomber les autres. |

## Ports recommandés pour le cas mail (documentés dans l'UI)

| Port | Protocole | Pour qui | Recommandation |
|---|---|---|---|
| 25 | SMTP (STARTTLS opportuniste) | **serveurs distants**, jamais les clients | indispensable pour recevoir du mail |
| 465 | Submission, TLS implicite | iOS / Android / Thunderbird / Outlook moderne | recommandé (RFC 8314) |
| 587 | Submission, STARTTLS | Outlook de bureau, profils d'autoconfiguration anciens | recommandé pour la compatibilité |
| 993 | IMAP, TLS implicite | tous les clients | indispensable |
| 4190 | ManageSieve | gestion des filtres | optionnel, à restreindre au LAN/VPN |
| 143 / 110 / 995 | IMAP STARTTLS, POP3 | hérité | à n'ouvrir que si un client l'exige |

## Modèle de données

```go
type TCPService struct {
    ID, Name        string
    Listen          string   // "0.0.0.0:465" ; l'interface est explicite
    Upstreams       []TCPUpstream // host:port + max_connections (pas de poids)
    LBPolicy        string
    HealthCheck     *L4HealthCheck // connexion TCP, intervalle, timeout
    ProxyProtocol   string   // "", "v1", "v2"
    IPFilter        *IPFilter // réutilise le type des routes
    CrowdSecEnabled bool
    MaxConnections  int
    Disabled        bool
}
```

## API

- `GET/POST /tcp-services`, `GET/PUT/DELETE /tcp-services/{id}` — admin only, audité.
- `POST /tcp-services/{id}/test` — ouvre une connexion TCP vers le backend et
  rapporte le résultat, **avant** d'appliquer.
- La validation refuse : port réservé, port déjà utilisé, backend vide,
  `proxy_protocol` hors {"", v1, v2}, CIDR invalide.

## UI

Nouvelle entrée de barre latérale **Services TCP**, même grammaire que les
routes : liste avec pastilles de posture (CrowdSec, filtrage IP, limite),
panneau latéral en sections repliables avec résumés. Section **Backend**
ouverte par défaut ; les autres repliées.

Le bloc PROXY protocol affiche, quand il est activé, l'encart à reporter chez
le backend — pour Stalwart : `proxyTrustedNetworks` = l'IP d'Arenet.

## Tests

Unitaires (émission JSON `layer4`, garde-fou de ports, validation), non-régression
(une installation sans service TCP produit une config Caddy **byte-identique**),
et smoke binaire réel : un service vers un `nc -l`, vérification que la bannière
PROXY v2 arrive bien en tête de connexion.

## Non-goals v1

- ❌ UDP.
- ❌ Terminaison TLS et routage SNI (donc pas de partage du 443).
- ❌ Blocage par pays au niveau 4.
- ❌ Relais **sortant** : le courrier sortant quitte la VM Stalwart par son
  propre chemin. Conséquence à documenter : le MX pointe sur l'IP d'Arenet
  (entrant), mais le SPF et le reverse DNS doivent couvrir l'IP de **sortie**
  de Stalwart.

## Points d'exploitation à documenter

1. `CAP_NET_BIND_SERVICE` dans l'unité systemd pour les ports < 1024 ; à ajouter
   à `packaging/systemd/` et à l'installeur.
2. En Docker, publier les ports dans le compose.
3. Certificats du backend : Arenet occupe le port 80, donc un HTTP-01 depuis
   Stalwart ne peut pas aboutir seul. Deux sorties : DNS-01 côté Stalwart, ou
   une route Arenet qui relaie `/.well-known/acme-challenge/*` vers lui.
