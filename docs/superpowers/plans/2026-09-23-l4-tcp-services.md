<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Services TCP (niveau 4) — plan d'implémentation

Spec : `docs/superpowers/specs/2026-09-23-l4-services-design.md` (décisions L1–L10
verrouillées par l'opérateur 2026-09-23).
Cible : **v2.42.0**. Cas de validation : Stalwart sur une VM d'un autre réseau.

## Architecture

- **`internal/storage/tcpservice.go`** (nouveau) : type `TCPService` + CRUD sur
  un bucket `tcp_services`, même forme que `routes.go` (id ULID, `CreatedAt` /
  `UpdatedAt`, `Validate()`). Pas de migration : bucket créé à vide, une
  installation existante n'en a aucun.

  ```go
  type TCPService struct {
      ID, Name        string
      ListenAddr      string   // "0.0.0.0" | "192.168.1.10" | "::"
      ListenPort      int
      Upstreams       []TCPUpstream // Host, Port, MaxConnections (caddy-l4 ne pondère pas)
      LBPolicy        string   // round_robin | least_conn | ip_hash | first | random
      HealthCheck     *TCPHealthCheck // Enabled, Interval, Timeout
      ProxyProtocol   string   // "" | "v1" | "v2"
      IPFilter        *IPFilter // réutilisé tel quel depuis routes.go
      CrowdSecEnabled bool
      MaxConnections  int      // 0 = illimité
      Disabled        bool
  }
  ```

- **`internal/caddymgr/layer4.go`** (nouveau) : `buildLayer4App(services)` →
  `map[string]any` de l'app `layer4`, **un server par service** (L10), nommé
  `svc_<id>`. Chaque server : `listen: ["tcp/<addr>:<port>"]`, une route dont
  le `match` agrège (dans cet ordre) `layer4.matchers.crowdsec` quand activé,
  puis `layer4.matchers.ip` (`ranges`) quand un filtre existe, et dont le
  `handle` est `layer4.handlers.proxy` (`upstreams[].dial`, `health_checks`,
  `load_balancing`, `proxy_protocol`, `max_connections`).
  `buildConfigJSON` insère l'app **seulement si au moins un service actif
  existe** — sinon la config émise reste byte-identique à aujourd'hui.

- **`internal/caddymgr/ports.go`** (nouveau) : `ReservedPorts(cfg)` → 80, 443,
  le port d'admin, 2019 ; `CheckListen(services, cfg)` → erreur nommant le
  conflit (réservé / déjà pris par un autre service). Appelé par la validation
  API **et** par le manager avant émission (défense en profondeur).
  `CanBindPrivileged()` : tente un `net.Listen` sur le port demandé au moment
  de la validation, et si `EACCES` sur un port < 1024, renvoie l'erreur qui
  nomme `CAP_NET_BIND_SERVICE` et la ligne systemd à ajouter.

- **`internal/api/tcpservices.go`** (nouveau) : CRUD admin + `POST
  /tcp-services/{id}/test` (dial TCP vers chaque backend, timeout 3 s, rapport
  par backend). Audité comme les routes (`tcp_service_created/updated/deleted`).

- **Modules Caddy** : import de `caddy-l4` dans `cmd/arenet/main.go` (bloc des
  imports blancs, à côté de `caddy-ratelimit` et des fournisseurs DNS)
  (`l4proxy`, `l4tls`, `l4subroute`) + passage de la dépendance de `indirect`
  à directe dans `go.mod`.

- **Frontend** : nouvelle route `/tcp-services`, entrée de barre latérale,
  liste + panneau latéral en `RouteSection`, `ModeSelector` pour le PROXY
  protocol, `SwitchRow` pour CrowdSec, `IPFilterFields` réutilisé tel quel.

## Tâches

1. **Stockage** *(fait — PR 1)* — `TCPService` + CRUD + `Validate()` (port 1–65535, au moins un
   backend, `ProxyProtocol` ∈ {"", v1, v2}, CIDR du filtre parsables, pas de doublon de backend)
   + tests table-driven. Inclusion dans backup/restore (`internal/backup`) et
   dans le snapshot de la topologie plus tard (tâche 8).
2. **Émission Caddy** *(fait — PR 1)* — `buildLayer4App` + tests : JSON attendu pour un service
   nu, avec PROXY protocol, avec filtre IP, avec CrowdSec, avec health check ;
   **non-régression** : zéro service → config byte-identique (assert sur le
   JSON complet, pattern `TestBuildConfigJSON_*` existant) ; `caddy.Validate()`
   sur la config émise avec services, et résolvabilité des handlers/matchers
   (le pattern qui a rattrapé cinq bugs au Step I.7).
3. **Garde-fou de ports** *(fait — PR 1)* — `ReservedTCPPorts` / `ValidateTCPListen` / `CanBindTCP`
   + tests (conflit réservé, conflit entre deux services, message EACCES).
4. **Modules + build** *(fait — PR 1 : v0.1.1, binaire 111,1 → 111,4 Mo)* — import `caddy-l4`, `go.mod` en dépendance directe,
   `go build` et `go vet` verts, vérification que la taille du binaire reste
   raisonnable (le module est déjà dans l'arbre, l'ajout doit être marginal).
5. **API** *(fait — PR 2)* — handlers CRUD + `/test`, rattachement au routeur, audit, rôles
   (admin uniquement), fragment **OpenAPI** (le test de couverture des deux
   sens échouera tant qu'il manque).
6. **Rechargement** *(fait — PR 2)* — `ReloadFromStore` prend les services en compte ; un
   service invalide n'empêche pas les routes HTTP de se recharger (L10) ;
   journalisation `slog` du nombre de services montés et des ports écoutés.
7. **Frontend** *(fait — PR 3, plus les compteurs en PR « métriques »)* — page liste (pastilles : CrowdSec, filtrage IP, limite),
   panneau d'édition en sections, avertissement Docker quand
   `ARENET_IN_CONTAINER`/détection `/.dockerenv`, encart PROXY protocol
   affichant l'IP d'Arenet à reporter dans `proxyTrustedNetworks`, bouton
   **Tester** câblé sur `/test`, section « ce qui ne s'applique pas » (L9).
   i18n FR + EN, tests Vitest.
8. **Topologie** — les services TCP apparaissent à côté des routes (nœud
   service → backends), en lecture seule.
9. **Packaging** *(fait — la capability était déjà dans l'unité ; commentaire élargi aux ports L4, exemple Docker complété)* — `AmbientCapabilities=CAP_NET_BIND_SERVICE` +
   `NoNewPrivileges` compatible dans `packaging/systemd/arenet.service`,
   mention dans l'installeur ; `docker-compose.yml` d'exemple avec les ports
   mail commentés.
10. **Docs** *(fait)* — page wiki **Services TCP** (EN + FR) avec le cas Stalwart de bout
    en bout : ports 25/465/587/993 (+4190 restreint), `proxyTrustedNetworks`,
    l'avertissement « un seul côté = casse silencieuse », le rappel SPF/rDNS
    sortant, et la route de relais ACME `/.well-known/acme-challenge/*`.
11. **Smoke binaire réel** *(fait à chaque PR : bannière PROXY v2 en TCP puis en UDP, compteurs exacts)* — service vers un `nc -l` : connexion relayée,
    **bannière PROXY v2 lue en tête de flux**, filtre IP qui refuse une source
    hors plage, port réservé refusé avant application, et zéro service →
    config identique.

## Découpage en PR

| PR | Contenu | Pourquoi ce découpage |
|---|---|---|
| 1 | Tâches 1–4 : stockage, émission, garde-fou, modules | Le cœur, testable sans API ni UI ; la non-régression byte-identique se prouve ici. |
| 2 | Tâches 5–6 : API + rechargement + OpenAPI | Utilisable par script avant toute UI ; un smoke curl valide déjà le cas Stalwart. |
| 3 | Tâche 7 : interface | Maquette soumise à l'opérateur **avant** d'écrire le formulaire (comme pour les routes). |
| 4 | Tâches 8–10 : topologie, packaging, docs | Finition ; le packaging doit précéder l'usage réel des ports < 1024. |

Smoke (tâche 11) à la fin de la PR 2 **et** rejoué à la fin de la PR 4.

## Risques et parades

| Risque | Parade |
|---|---|
| L'app `layer4` refuse de démarrer et fait tomber tout le rechargement | Un server par service (L10) + `caddy.Validate()` avant `Load` ; en cas d'échec, l'erreur nomme le service fautif. |
| Port < 1024 sans capability → échec au démarrage du service | Test de bind **à la validation**, message nommant `CAP_NET_BIND_SERVICE` ; jamais découvert au rechargement. |
| PROXY protocol dépareillé → connexions cassées en silence | Encart UI couplé + bouton Tester ; la doc dit explicitement les deux côtés. |
| Opérateur croit son service protégé par le WAF | Section L9 dans le formulaire, et la page wiki le redit. |
| Le binaire grossit | Mesure avant/après en tâche 4 ; le module est déjà tiré par le bouncer. |

## Définition de terminé

`go build`, `go vet`, `go test -race ./...`, `npm run check`, `npm test`,
`npm run build` verts ; non-régression byte-identique prouvée ; smoke binaire
réel joué ; wiki EN + FR ; et le cas Stalwart de l'opérateur fonctionne avec
l'IP client réelle visible dans les journaux de Stalwart.

## Écarts par rapport au plan, et pourquoi

- **8. Topologie : non fait.** Le plan la prévoyait en PR 4. Les compteurs de la
  PR « métriques » donnent déjà la visibilité qui manquait, et représenter un
  relais dans un graphe pensé pour des hôtes HTTP demande un vrai travail de
  conception — à traiter séparément plutôt qu'à bâcler ici.
- **UDP : avancé en amont.** Prévu en v2, ajouté juste après la PR 1 parce que
  l'opérateur a recadré le périmètre (« pas seulement Stalwart ») et qu'un champ
  de protocole coûte une heure sur un modèle jeune contre une migration après
  l'interface.
- **Sauvegarde des services : lacune.** La tâche 1 la mentionnait, la PR 1 l'a
  oubliée. Rattrapée avec l'UDP.
- **Métriques L4 : ajoutées au plan.** Elles n'y figuraient pas ; sans elles un
  relais est la seule partie de l'installation que personne ne peut surveiller.
