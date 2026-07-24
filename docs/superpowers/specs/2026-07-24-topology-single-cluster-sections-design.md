# Topology : paths dans UN cluster unique (sections) — Design

**Status:** brainstormé avec l'opérateur 2026-07-24, décisions verrouillées.
Branche `feature/topology-single-cluster-sections`. Version cible **v2.25.0**
(minor — remplace le rendu topology de v2.24.0/v2.24.1). Issu de 2 dogfoods
visuels successifs qui ont recadré le besoin réel.

**One-line:** Afficher les path-pools d'une route DANS UN SEUL cluster (comme un
pool multi-upstream), les backends groupés en **sections par préfixe** (racine
puis `── /v1 ──`, `── /legacy ──`), avec **une ligne hub→section** par pool.
Remplace les clusters-séparés-par-path (v2.24.0) + branches-pointillées-empilées
(v2.24.1).

## Contexte (pourquoi cette 3e approche)

- v2.24.0 : un cluster SÉPARÉ par pool (root + chaque path) → dogfood : les
  clusters flottaient, dispersés, sans lien visible avec la route.
- v2.24.1 : branches pointillées + empilement à gap réduit → dogfood : toujours
  pas le rendu "comme les aliases" voulu ; l'opérateur a alors précisé le vrai
  besoin : soit un conteneur englobant, soit — retenu — **faire comme un pool
  MULTI-UPSTREAM** : un seul bloc, les paths empilés dedans.
- L'opérateur veut GARDER les lignes hub→(par path) car elles porteront le
  trafic-par-path plus tard (backlog) — elles ne sont pas décoratives.

## Décisions

| # | Décision | Pourquoi |
|---|----------|----------|
| Opt.2 | **UN cluster par route** (pas N clusters séparés) ; les paths sont des enfants du cluster, comme les N backends d'un pool multi-upstream. | Le plus proche du rendu existant ; un seul bloc par route ; réutilise le mécanisme upstream-enfant (parentId+extent). |
| Q1=C | **Sous-sections visuelles par préfixe** dans le cluster : un en-tête `── /v1 ──` puis ses backends. | Plus lisible que "1 ligne/backend avec préfixe répété" quand un path a plusieurs backends. |
| Q2=B | Le pool RACINE reste SANS en-tête (ses backends en haut) ; les sections de path apparaissent EN DESSOUS. | Non-régression : une route SANS path a un rendu strictement inchangé (aucun en-tête ajouté). |
| Q3 | **Une ligne hub→section** : du caddy-hub vers le 1er upstream de CHAQUE pool (racine + chaque path). | Montre les branches de routage dès maintenant ; chaque ligne portera le trafic de son path quand le backlog trafic-par-path arrivera. |

## 1. Backend — inchangé

Le backend émet DÉJÀ `topology.Route.PathPools []PathPool` (v2.24.0 :
pathPrefix + upstreams + lbPolicy + insecureSkipVerify). **On garde ce champ tel
quel** — c'est exactement la donnée voulue. Aucune migration, aucune métrique
(structure only ; trafic-par-path reste backlog).

## 2. Frontend — un cluster, N sections, N lignes hub→section

Fait empirique vérifié (@xyflow/svelte) : le `BackendClusterNode` parent N'A PAS
de Handle (BackendClusterNode.svelte:88 "No <Handle> on the parent") ; chaque
`UpstreamNode` enfant A un Handle target à gauche (UpstreamNode.svelte:56). Donc
les edges hub→ visent les UPSTREAMS enfants, pas le cluster. → une "ligne
hub→section" = une ligne vers le 1er upstream de la section. Faisable sans
nouveau mécanisme de handle.

**Nodes émis par route (dans `_layout.ts`) :**
- 1 `BackendClusterNode` (le bloc unique), hauteur = Σ(backends racine) +
  Σ_path(hauteur en-tête + backends du path).
- Les `UpstreamNode` du pool racine (sans en-tête — Q2=B), parentés au cluster.
- Par path-pool : un **en-tête de section** (nouveau node enfant léger
  `PathSectionHeaderNode`, ~24px, portant le préfixe) + ses `UpstreamNode`,
  tous parentés au même cluster.

**En-têtes de section :** nouveau type de node enfant `path-section-header` +
composant `PathSectionHeaderNode.svelte` (juste le préfixe, style discret genre
`── /v1 ──`), inséré entre les groupes d'upstreams, parenté au cluster comme les
UpstreamNode (parentId + extent:'parent', draggable:false, selectable:false).

**Lignes hub→section (Q3) :** une ligne `caddy-hub → 1er upstream de chaque
pool`. La ligne RACINE porte le trafic global (non-structurelle, comportement
historique) — la racine n'a PAS d'en-tête de section (Q2=B) MAIS a bien sa ligne
hub→racine, celle qui existe déjà aujourd'hui. Les lignes de PATH sont
`structural` (pointillées — réutilise le flag `structural` de FlowEdgeData + le
rendu de AnimatedFlowEdge de v2.24.1, le SEUL morceau qu'on garde). Demain :
chaque ligne portera le trafic de son path.

NOTE non-régression edges : aujourd'hui, une route SANS path émet ses edges
hub→upstream en fan-out (une par upstream du pool racine — voir le fan-out
existant dans `_layout.ts`). Ce comportement racine doit rester INCHANGÉ ; on
n'ajoute des edges structural QUE pour les path-pools. Le "1er upstream de chaque
pool" concerne l'ancrage des lignes de PATH ; la racine garde son fan-out
existant.

## 3. Nettoyage v2.24.0/v2.24.1 (code devenu mort)

RETIRER :
- La flatten `clusterSpecs` root+path (v2.24.0) → revient à 1 cluster par route.
- Le stacker à gap variable `computeStackYsWithGaps` + `INTRA_ROUTE_GAP` /
  `INTER_ROUTE_GAP` (v2.24.1) → plus de clusters multiples à espacer ; revient au
  stacker uniforme `computeStackYsForHeights`.
- `pathPrefix` sur `BackendClusterNodeData` (en-tête de cluster de v2.24.0) →
  remplacé par les en-têtes de SECTION internes.

GARDER :
- Le champ backend `PathPools` (la donnée).
- Le flag `structural` sur FlowEdgeData + le rendu pointillé de AnimatedFlowEdge
  (v2.24.1) — réutilisé pour les lignes hub→section-de-path.

Grep de vérification : 0 référence morte à `computeStackYsWithGaps`,
`INTRA_ROUTE_GAP`, `INTER_ROUTE_GAP`, ni à `pathPrefix` sur le cluster.

## 4. Tests

Frontend (`_layout.ts` + `_types.ts` + `_layout.test.ts`) :
- **1 cluster/route** : une route avec paths → EXACTEMENT UN `backend-cluster`
  node ; N en-têtes de section + tous les upstreams (racine + paths) parentés à
  ce cluster.
- **Sections** : un `path-section-header` par path-pool, bon préfixe, positionné
  AVANT les upstreams de ce pool ; le pool RACINE sans en-tête (Q2=B).
- **Hauteur** : cluster height = racine + Σ(en-tête + backends) par path ; aucun
  enfant ne déborde.
- **Lignes hub→section** : une ligne caddy-hub → 1er upstream de chaque pool ;
  racine non-structurelle, path structural.
- **NON-RÉGRESSION route-sans-path** : route sans path-pool → UN cluster, ZÉRO
  en-tête de section, UN edge hub→upstream, stacking + rendu identiques à
  AVANT v2.24.0 (retour au modèle simple). Un test l'asserte.
- **Nettoyage** : grep 0 référence à computeStackYsWithGaps / INTRA/INTER gap /
  cluster.pathPrefix.
- `svelte-check` 0, suite vitest verte.

**Vérification visuelle (obligatoire) :** dogfood sur testpath → UN seul bloc :
`:9099` (racine) puis `── /v1 ── :9199`, `── /legacy ── :9299`, `── /pub ──
:9199` ; des lignes du hub vers chaque section ; `/docs` (protection-only, sans
pool) n'apparaît pas. Une route sans path = bloc simple inchangé.

## Process
LIGHT-medium. Frontend-only. Le layout est load-bearing (3e passe sur
`_layout.ts`) → **revue dédiée**. Nouveau node `PathSectionHeaderNode`. Revue
finale whole-branch. Pas de `-race`. v2.25.0 (minor), tag après re-dogfood + go.

## Backlog (inchangé)
Trafic vivant par-path (req/s + erreurs par path-rule) — les lignes hub→section
sont DÉJÀ en place pour le porter ; le jour venu, remonter un compteur par
(route, path) dans le hot-path + animer chaque ligne + sa section. Son propre
cycle.
