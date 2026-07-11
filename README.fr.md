<div align="center">

<img src="web/frontend/src/lib/assets/arenet-logo.png" alt="Arenet" width="120" />

# Arenet

[English](README.md) · **🌐 Français**

**Un reverse proxy homelab-friendly avec sécurité intégrée**

[![Release](https://img.shields.io/github/v/release/barto95100/arenet?style=flat-square&color=2563eb)](https://github.com/barto95100/arenet/releases)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![Caddy](https://img.shields.io/badge/caddy-v2.11-1f88c0?style=flat-square)](https://caddyserver.com)
[![Coraza](https://img.shields.io/badge/coraza-v3.7%20%2B%20CRS%20v4-d62828?style=flat-square)](https://coraza.io)

Reverse proxy single-binary qui combine le moteur HTTP production-grade de Caddy v2 avec une UI d'admin homelab-friendly et des intégrations sécurité natives — WAF, réputation IP, blocage par pays, rate limiting — habituellement présentes uniquement dans les produits commerciaux.

[Démarrage rapide](#-démarrage-rapide) · [Fonctionnalités](#-fonctionnalités) · [Captures](#-captures) · [Comparaison](#-vs-alternatives) · [Documentation](#-documentation)

</div>

---

## ✨ Pourquoi Arenet

La plupart des reverse proxies homelab (Nginx Proxy Manager, Zoraxy) te donnent une UI d'admin par-dessus un moteur HTTP, puis s'arrêtent là. Les outils production-grade (Caddy, Traefik) te donnent le moteur mais te laissent la stack sécurité en devoirs — câble ton propre WAF, ta propre source de réputation IP, ton propre pipeline d'alertes.

Arenet est le **moteur + UI + stack sécurité dans un seul binaire**. Configure une route, choisis un mode TLS, active un profil WAF, attache un SSO OIDC, câble une alerte Discord sur les échecs de renouvellement de certificat — tout depuis la même UI d'admin, tout servi par un seul binaire Go, tout backé par un seul BoltDB embarqué.

Conçu pour l'opérateur qui fait tourner 5-50 routes sur un seul host homelab et qui veut une posture production sans la complexité production.

## 🚀 Démarrage rapide

Deux chemins d'installation, tous les deux sous 5 minutes.

### Docker (recommandé)

```bash
# Récupère le fichier compose de référence et démarre la stack. Il
# câble le volume de données, la capacité NET_BIND_SERVICE pour
# :80/:443 et le healthcheck intégré au binaire.
curl -O https://raw.githubusercontent.com/barto95100/arenet/main/docker-compose.yml
docker compose up -d
```

L'UI d'admin sur `:8001` écoute sur `127.0.0.1` uniquement par
défaut. Récupère le token de setup avec
`docker compose logs arenet | grep 'Setup token'`, puis accède à
l'admin via un tunnel SSH (`ssh -L 8001:localhost:8001 <host>`) et
ouvre `http://localhost:8001`.

Guide complet : [docs/install/docker-quickstart.md](docs/install/docker-quickstart.md)

### Linux natif + systemd

```bash
# Télécharge le binaire release + l'unit systemd, crée l'utilisateur
# arenet + le dossier de données, puis active & démarre le service.
curl -fsSL https://raw.githubusercontent.com/barto95100/arenet/main/packaging/systemd/install.sh | sudo bash
```

Récupérez ensuite le token de setup : `sudo journalctl -u arenet | grep 'Setup token'`.

Guide complet : [docs/install/systemd-native.md](docs/install/systemd-native.md)

## 🎯 Fonctionnalités

### Routing & TLS
- 🔀 **Reverse proxy par route** avec load balancing pondéré, hostnames alias, health checks actifs avancés (status code + body regex)
- 🔒 **Auto-HTTPS** via Caddy ACME (Let's Encrypt + ZeroSSL fallback) — HTTP-01, DNS-01 (provider OVH natif), wildcard via apex managed-domain
- 🌐 **HTTP/3 (QUIC)** actif par défaut sur chaque route HTTPS — zéro config requise
- 🔄 **Préservation du header Host** par défaut — fonctionne out-of-the-box avec les IdP OIDC, SaaS multi-tenant et tout backend qui construit des URLs depuis `Host:`
- 🩹 **Hot-reload** de chaque changement de route sans dropper les connexions en cours
- 📦 **Support HTTPS-to-HTTPS upstream** avec skip optionnel de la vérification TLS pour backends internes auto-signés
- 🎨 **Pages d'erreur personnalisées** par route via templates HTML (401/403/404/429/500/502/503/504), avec **catch-all brandé** optionnel pour les hosts non matchés (template promotable via une seule checkbox)

### Sécurité
- 🛡️ **WAF intégré** via Coraza v3 + OWASP CRS v4 avec opt-out par route, exclusion par règle, exclusion par tag (ex. exclure toutes les règles `attack-protocol` sur un backend bruyant)
- 🚦 **Rate limiting** par route (événements/fenêtre/clé, ex. "60 req/min par IP distante sur /api/login")
- 🌍 **Blocage par pays** via MaxMind GeoLite2 embarqué (liste blanche / liste noire par route)
- 🔥 **Intégration CrowdSec** pour le threat intelligence communautaire (bouncer LAPI, auto-ban sur décisions communautaires)
- 🔐 **SSO OIDC** avec allowlist (canonicalisation email + sub, opt-in accept-unverified-email, authentik/Keycloak/Authelia testés)
- 👥 **RBAC** avec rôles `viewer` / `admin` + compte local break-glass préservé quand OIDC est câblé
- 🚪 **Forward auth** (Authelia / oauth2-proxy / Authentik external auth) câblé par route
- 🔒 **Basic auth** par route (Argon2id, sémantique preserve-on-edit pour les secrets)

### Observabilité
- 📊 **Dashboard topologie live** (SvelteKit + D3.js) avec particules req/s en temps réel, métriques par route, clustering par alias
- 📈 **Timeseries par route** (req/s, taux 4xx/5xx, latence p95, taux WAF detect/block) — Step L
- 🔍 **Log d'activité unifié** (`/logs`) — événements WAF + rate-limit + auth + throttle + cert avec histogramme de sources, filtre par niveau, recherche, GeoIP par IP distante
- 🛡️ **Drilldown des événements WAF** par route — distribution par catégorie CRS, historique de règle, triage de faux positifs
- 🗺️ **Carte du monde GeoIP** montrant la distribution live des blocages par pays
- 📋 **Audit log** pour chaque changement de config avec diff avant/après et attribution de l'acteur
- 🎫 **Observabilité du cycle de vie des certificats** — track chaque événement `cert_obtained`, `cert_failed`, `cert_ocsp_revoked` avec rétention 90j

### Alerting (Step AL)
- 🔔 **Routing multi-canal** — webhook Discord, webhook générique, email SMTP
- 📐 **Règles threshold + state** — `waf_event_rate > 10`, `cert_expiry < 14d`, `system_health == degraded`, `cert_renewal_failed > 0`
- ⏱️ **Watcher polling 30s** avec cooldown par règle pour prévenir les tempêtes d'alertes
- 📜 **Historique des alertes** avec pinpointing de règle + statut de livraison par canal
- 🧪 **Mode test** — déclenche une alerte synthétique à travers n'importe quel canal pour valider le câblage

### Opérations
- 💾 **Backup/Restore via UI** — snapshot de config complet (routes, users, OIDC, DNS providers, forward-auth, allowlists) avec résolution sentinel pour les secrets et rollback atomique sur échec de reload Caddy
- 🌓 **Thèmes Dark + Light** avec détection préférence système et persistance par utilisateur
- 🎨 **Pages d'erreur brandées** + templates HTML personnalisés avec support des placeholders Caddy (`{http.request.uri}`, `{http.request.uuid}`, etc.), incluant un catch-all brandable pour les requêtes arrivant sur des hostnames non configurés
- ⚙️ **Wizard de setup initial** avec setup token one-time pour le bootstrap cold-boot
- 🐳 **Binaire unique** (~100 Mo) — pas de sidecars, pas d'agents, pas de dépendance Redis/PostgreSQL externe

## 📸 Captures

> Captures à venir. Pour un aperçu live, suis le [démarrage rapide](#-démarrage-rapide) et ouvre `http://<host>:8001`.

## 🆚 vs Alternatives

| Fonctionnalité                | Arenet | Zoraxy | NPM     | Traefik | Caddy raw |
| ----------------------------- | ------ | ------ | ------- | ------- | --------- |
| Install single-binary         | ✅     | ✅     | ❌      | ✅      | ✅        |
| UI d'admin web                | ✅     | ✅     | ✅      | Limitée | ❌        |
| WAF intégré (OWASP CRS)       | ✅     | ❌     | ❌      | Plugin  | Plugin    |
| Bouncer CrowdSec              | ✅     | ❌     | ❌      | Plugin  | Plugin    |
| Blocage par pays              | ✅     | ❌     | ❌      | Plugin  | Plugin    |
| Graphe topologie live         | ✅     | ❌     | ❌      | ❌      | ❌        |
| SSO OIDC + RBAC               | ✅     | ❌     | ❌      | Limité  | ❌        |
| Backup/restore via UI         | ✅     | Limité | ✅      | ❌      | ❌        |
| Règles d'alerting par route   | ✅     | ❌     | ❌      | ❌      | ❌        |
| Auto-HTTPS + HTTP/3           | ✅     | ✅     | ✅      | ✅      | ✅        |
| Observabilité cycle cert      | ✅     | ❌     | ❌      | Limitée | Logs only |
| AGPL-3.0 (truly open-source)  | ✅     | ✅     | MIT     | MIT     | Apache    |

Le positionnement d'Arenet : **sécurité + observabilité production-grade qui ship dans la boîte**, pas comme N plugins à câbler ensemble.

## 📚 Documentation

| Section | Où |
| ------- | -- |
| Installation (Docker + systemd) | [docs/install/](docs/install/) |
| Opérations (backup, config, hardening) | [docs/operations/](docs/operations/) |
| Vérification HTTP/3 + firewall | [docs/operations/http3.md](docs/operations/http3.md) |
| Sous-système d'alerting (channels, rules, watcher) | [docs/alerting.md](docs/alerting.md) |
| Troubleshooting | [docs/operations/troubleshooting.md](docs/operations/troubleshooting.md) |
| **Wiki utilisateur** (guides how-to) | [GitHub Wiki](https://github.com/barto95100/arenet/wiki) |
| Référence API | [docs/api/](docs/api/) |
| Pratiques d'ingénierie | [docs/ENGINEERING-PRACTICES.md](docs/ENGINEERING-PRACTICES.md) |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Arenet (single Go binary)                              │
├─────────────────────────────────────────────────────────┤
│  SvelteKit Admin UI (static build, embed.FS)            │
│           ↓                                             │
│  REST API + WebSocket (chi + gorilla/websocket)         │
│           ↓                                             │
│  BoltDB (config, users, audit) + SQLite (event store)   │
│           ↓                                             │
│  Caddy Manager (routes → Caddy JSON config)             │
│           ↓                                             │
│  Caddy v2 (embedded library)                            │
│   + Coraza WAF (OWASP CRS v4)                           │
│   + CrowdSec bouncer                                    │
│   + caddy-ratelimit                                     │
└─────────────────────────────────────────────────────────┘
```

Caddy est embarqué en tant que **library**, pas exécuté en sidecar — un processus, une stack réseau, un chemin de shutdown.

## 🛠️ Construit avec

- **[Caddy v2.11](https://caddyserver.com)** — moteur HTTP, auto-HTTPS, ACME
- **[Coraza v3.7](https://coraza.io)** + **[OWASP CRS v4.25](https://coreruleset.org)** — WAF
- **[Bouncer CrowdSec](https://github.com/hslatman/caddy-crowdsec-bouncer)** — réputation IP
- **[caddy-ratelimit](https://github.com/mholt/caddy-ratelimit)** — throttling par route
- **[BoltDB](https://github.com/etcd-io/bbolt)** — stockage config + audit
- **[SvelteKit 5](https://kit.svelte.dev)** + **[Tailwind CSS](https://tailwindcss.com)** + **[D3.js](https://d3js.org)** — frontend
- **Go 1.25+** — toolchain single-binary

## 🤝 Contribuer

Arenet est actuellement un projet single-developer mais les contributions sont les bienvenues.

- Rapports de bugs + demandes de feature → [GitHub Issues](https://github.com/barto95100/arenet/issues)
- Pratiques d'ingénierie + conventions de code → [docs/ENGINEERING-PRACTICES.md](docs/ENGINEERING-PRACTICES.md)
- Tous les fichiers source DOIVENT porter le header AGPL-3.0 — voir `CLAUDE.md` § "AGPLv3 Header"
- Règle de vérification empirique — toute affirmation sur le comportement runtime de Caddy / Coraza / CrowdSec doit citer la source ou être backée par un test

## 🌐 Traductions

L'UI, le README et le Wiki d'Arenet sont i18n complete end-to-end en **anglais** et **français** dès v2.10.x.

- UI app : EN + FR (Phase 3 frontend i18n, ships v2.9.x)
- README : [English](README.md) · [Français](README.fr.md)
- Wiki : [English](https://github.com/barto95100/arenet/wiki/Home) · [Français](https://github.com/barto95100/arenet/wiki/Home-FR)

Les contributions pour des langues additionnelles (DE, ES, IT, etc.) sont les bienvenues — voir la page [`Home`](https://github.com/barto95100/arenet/wiki/Home-FR) du wiki et `web/frontend/src/lib/i18n/locales/` pour la structure de bundle existante. Ouvre une issue d'abord pour coordonner.

## 📜 License

[AGPL-3.0](LICENSE) — copyleft pour le cas d'usage network-served. Les modifications servies sur un réseau doivent être rendues disponibles sous la même licence.

## 🙏 Inspiré par

[Zoraxy](https://github.com/tobychui/zoraxy) par tobychui — le pattern homelab-UI-on-reverse-proxy qui a prouvé que l'audience existe. Arenet reconstruit le concept par-dessus Caddy avec des intégrations sécurité natives et une stack d'observabilité conçue pour l'opérateur qui fait tourner un homelab sérieusement.

---

<div align="center">

**Fait pour les opérateurs homelab qui veulent une posture production sans la complexité production.**

[⬆ retour en haut](#arenet)

</div>
