# Path-rules dans la topology (structure) — Design

**Status:** brainstormé avec l'opérateur 2026-07-24, 4 décisions verrouillées.
Branche `feature/topology-path-pools`. Version cible **v2.24.0** (minor — nouvelle
capacité d'affichage). Fait suite au per-path upstream (v2.23.0/1) qui a créé du
routage par path aujourd'hui INVISIBLE sur le graphe de topology.

**One-line:** Afficher les branches de routage par path sur le graphe de
topology : une route dont des path-rules ont leur propre pool se ramifie en
**plusieurs clusters de backends** (un par branche), étiquetés par leur préfixe,
au lieu d'un seul cluster.

## Contexte (le manque)

La topology montre aujourd'hui, par route : `FQDN (host) → Caddy Hub →
BackendCluster (pool de la route) → UpstreamNode ×N`, plus les AliasNodes. Elle
ne connaît QUE le pool de la route (`TopologyRoute.upstreams`). Les pools des
path-rules (`/v1→A`, `/legacy→B` de v2.23.0) sont **invisibles** : une route
qui éclate vers 3 backends selon l'URL apparaît comme un seul pool. La topology
cache donc l'information clé que la feature per-path upstream apporte.

Fait empirique vérifié : le metrics handler compte par `route_id` (+ par host
via IncByHost pour les aliases), PAS par path-rule (`Submit(status, srcIP,
routeID)` — pas de scope path). Le trafic de `/v1` et `/legacy` est agrégé au
niveau route. → conditionne le périmètre (voir Q1).

## Décisions (Q1–Q4)

| # | Décision | Pourquoi |
|---|----------|----------|
| Q1 | **C — structure d'abord, trafic vivant en backlog.** v1 dessine les branches path→backend (statique) ; le trafic par branche (req/s, erreurs par path) est un cycle SÉPARÉ. | Les métriques ne sont PAS comptées par path aujourd'hui ; un graphe vivant par branche exigerait un compteur par (route, path) dans le hot-path middleware — chantier lourd. La structure seule répond déjà à "voit-on les paths ?" sans toucher le comptage. |
| Q2 | **A — un BackendCluster par branche**, sous la même route : cluster racine (pool route) + un cluster par path-rule avec pool. | Représentation la plus fidèle : un cluster = un pool = une destination de trafic. Montre exactement la ramification. |
| Q3 | **A2 + B2.** (A2) le préfixe s'affiche dans l'EN-TÊTE du cluster (pas sur l'edge). (B2) v1 = seulement les path-rules qui ont leur PROPRE pool ; les protection-only qui héritent ne créent pas de node. | A2 reste lisible quand il y a plusieurs branches, cohérent avec "le cluster EST la branche". B2 garde v1 cadré ; ajout des path-sans-pool (en badge) possible plus tard sans casser le layout. |
| Q4 | **A — enrichir la structure topology** : `TopologyRoute` gagne un champ `pathPools`, peuplé depuis `storage.Route.PathRules`. Pas de nouveau flux, pas de métrique touchée. | La topology reçoit déjà le storage.Route complet (buildRoute y a accès). Symétrique à `upstreams`. Un endpoint séparé désynchroniserait. |

## 1. Périmètre v1 = STRUCTURE seulement

On dessine les branches (préfixe, pool, LB, skip-verify) statiques. Le TRAFIC
vivant par branche est backlog explicite (voir §5).

## 2. Backend — la structure topology gagne les path-pools

Ancrage : `internal/api/topology/builder.go`, `buildRoute(r *storage.Route, …)`
(ligne 132) — construit déjà le cluster route depuis `r.Upstreams` (163-194).

Nouveau type dans le package `topology` :
```go
// PathPool is one per-path routing branch: a path-rule that declares its
// own upstream pool. Rendered as a separate BackendCluster labelled by its
// prefix. Path-rules WITHOUT a pool (protection-only, inherit the route
// pool) are NOT emitted (v1 = only branches that change the backend — B2).
type PathPool struct {
    PathPrefix         string     `json:"pathPrefix"`
    Upstreams          []Upstream `json:"upstreams"`
    LBPolicy           string     `json:"lbPolicy"`
    InsecureSkipVerify bool       `json:"insecureSkipVerify,omitempty"`
}
```

Champ ajouté à la structure `Route` (package topology) :
```go
    PathPools []PathPool `json:"pathPools,omitempty"`
```

Peuplement dans `buildRoute` : après `out.Upstreams`, itérer `r.PathRules` et
n'émettre un `PathPool` que si `len(pr.Upstreams) > 0` (B2). RÉUTILISER la même
conversion `storage.Upstream → topology.Upstream` que le pool route (DRY —
extraire un helper si besoin).

Invariants :
- **Aucune métrique touchée** (C). Les PathPool ne portent pas de compteurs.
- `omitempty` → une route sans path-pool sérialise EXACTEMENT comme avant
  (dashboards/instances existants inchangés) — garde de non-régression.
- WS métrique (`ws_topology.go`) + snapshot métrique intacts. On n'enrichit que
  la STRUCTURE (`BuildSnapshot` via `buildRoute`).

## 3. Frontend — un cluster par branche sous la route

Ancrage : `web/frontend/src/routes/topology/_layout.ts` (builder nodes/edges) +
`_types.ts`. Aujourd'hui : route → `FQDN → Hub → BackendCluster(route) →
UpstreamNode ×N`.

Type TS (miroir backend) sur `TopologyRoute` :
```ts
export interface TopologyPathPool {
    pathPrefix: string;
    upstreams: TopologyUpstream[];
    lbPolicy: string;
    insecureSkipVerify?: boolean;
}
// sur TopologyRoute :
    pathPools?: TopologyPathPool[];
```

Construction des nodes dans `_layout.ts` : par route, émettre —
- le **cluster racine** (pool route), en-tête `/` (A2), inchangé fonctionnellement ;
- **un cluster par `pathPool`** : un `BackendClusterNode` + ses `UpstreamNode`
  enfants, en-tête = préfixe (`/v1`, `/legacy`) (A2), edge Hub→cluster.

Les path-rules sans pool ne produisent rien (B2).

Réutilisation : **`BackendClusterNode.svelte` + `UpstreamNode.svelte` tels
quels** — un pool de path est un pool comme un autre. Seul ajout : un champ
`pathPrefix?` sur `BackendClusterNodeData`, affiché dans l'en-tête UNIQUEMENT
quand présent. Le cluster RACINE (pool route) NE reçoit PAS de `pathPrefix` →
son rendu reste strictement inchangé (pas de "/" ajouté, non-régression visuelle
du cluster existant). Seuls les clusters de path portent une étiquette de préfixe.

Layout / positionnement (partie load-bearing) : empiler les clusters de path
comme des frères du cluster racine sous la même ligne de route, **calqué sur le
modèle d'empilement des AliasNodes** (déjà éprouvé — hauteurs/gaps calculés dans
`_layout.ts`). Chaque cluster de path est rattaché au même Hub.

Risque : le layout D3/xyflow est dense (6 types de nodes, positions calculées).
Multiplier les clusters densifie une route à beaucoup de paths. Mitigation :
réutiliser le modèle aliases + revue attentive de `_layout.ts` + la garde des
tests layout existants (`_layout.test.ts`).

## 4. Tests

Backend (`internal/api/topology/`) :
- `buildRoute` : route avec 2 path-rules (pool `/v1` + protection-only `/docs`)
  → `PathPools` contient SEULEMENT `/v1` (B2).
- Un `PathPool` porte le bon préfixe + pool + LB + skip-verify.
- **Non-régression** : route SANS path-pool → snapshot JSON inchangé (`pathPools`
  absent via omitempty). Comparaison sur une route existante.
- Conversion `storage.Upstream → topology.Upstream` partagée (pas de divergence
  entre pool route et path-pool).

Frontend (`_layout.ts` + `_types.ts`) :
- `_layout.test.ts` : route avec `pathPools` → N+1 clusters (racine + un par
  path-pool), chacun avec son en-tête de préfixe, relié au Hub.
- Route sans `pathPools` → graphe identique à avant (non-régression layout).
- En-tête cluster : préfixe quand présent, `/` (ou rien) pour la racine.
- `svelte-check` 0, vitest vert.

**Vérification visuelle (feature visuelle) :** dogfooding sur
`testpath.worldgeekwide.fr` (a déjà `/v1`, `/legacy` avec pools + `/docs`
protection-only) → ouvrir la topology, vérifier 3 clusters (racine + `/v1` +
`/legacy`), `/docs` n'ajoute pas de cluster, layout lisible.

## Process
LIGHT-medium. Backend = ajout de champ isolé (structure builder, pas de métrique,
pas d'émission Caddy). Frontend = le layout est load-bearing → revue attentive de
`_layout.ts` (dédiée possible, sinon inline soignée + garde des tests layout).
Revue finale whole-branch. Pas de `-race` (aucune touche caddymgr/émission).
Version v2.24.0 (minor), tag après go opérateur.

## 5. Backlog explicite (acté)
**Trafic vivant par branche** (req/s + erreurs par path-rule sur le graphe) —
nécessite un compteur métrique par (route, path) dans le hot-path
`internal/metrics/middleware.go` (le `RouteMetricsHandler.Submit` gagne un scope
path, l'émission Caddy thread le path scope) + remontée dans le snapshot
métrique + animation par cluster de path. Son propre cycle brainstorm→spec→plan.
Non concerné par v1.
