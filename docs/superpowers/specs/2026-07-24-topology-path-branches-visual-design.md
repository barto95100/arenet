# Fix visuel topology path-pools : branches + regroupement — Design

**Status:** brainstormé avec l'opérateur 2026-07-24, 4 décisions verrouillées.
Branche `fix/topology-path-branches-visual`. Version cible **v2.24.1** (patch —
fix visuel de v2.24.0). Issu du dogfood visuel de v2.24.0.

**One-line:** Rendre les branches de path VISIBLES et REGROUPÉES dans la
topology : (1) un stroke pointillé net relie le hub Caddy à chaque cluster de
path (aujourd'hui l'edge existe mais est tracé en gris opacity 0.2 → invisible) ;
(2) les clusters d'une même route sont empilés contigus (comme les aliases sous
leur FQDN) au lieu d'être dispersés dans le stack global.

## Contexte (2 défauts du dogfood v2.24.0)

Le visuel a montré que les clusters de path (`/v1`, `/legacy`, `/pub`)
apparaissent bien AVEC leur préfixe en en-tête (ça, ça marche), MAIS :
1. **Pas de regroupement** : les clusters flottent, dispersés verticalement dans
   le stack global, sans lien visible avec leur route `testpath`. Contraste net
   avec les aliases, qui sont empilés serrés sous leur FQDN.
2. **Branches invisibles** : les edges hub Caddy → cluster de path SONT émis
   (vérifié) mais `AnimatedFlowEdge` les trace au tier "dead" (reqPerSec 0) =
   stroke gris `stroke-opacity: 0.2`, sans particules → quasi-invisible sur fond
   noir, et le hub (source) est souvent hors-cadre.

Diagnostic empirique : `AnimatedFlowEdge.svelte` trace DÉJÀ le stroke à trafic
nul (tier dead : opacity 0.2, `stroke-width: 1.5`, sans particules — ligne
94-96 + tierStrokeStyle). Le problème n'est donc pas "la ligne ne se dessine
pas" mais "la ligne dead est trop discrète pour signaler une branche de routage".

## Décisions (Q1–Q4)

| # | Décision | Pourquoi |
|---|----------|----------|
| Q1 | Relier via des **edges hub Caddy → cluster de path** (déjà émis dans `_layout.ts`). | Réutilise le hub central ; résout rattachement + visibilité d'un coup, cohérent avec FQDN→hub→cluster existant. |
| Q2 | **Réutiliser `animated-flow`** (pas de nouveau type d'edge) — le composant trace déjà le stroke à trafic nul, particules seulement si reqPerSec>0. | Moins de code neuf ; le jour où le backlog "trafic par branche" arrive, les particules s'animeront automatiquement. RISQUE assumé : on touche le composant edge PARTAGÉ → garde de non-régression stricte. |
| Q3 | **Renforcer le stroke** des branches structurelles : pointillé (`stroke-dasharray`) + opacity ~0.5, distinct du tier dead. | Le pointillé = convention "lien structurel / potentiel" ; lisible ; le mécanisme dasharray existe déjà (tier "bad"). Signifie "branche de routage sans trafic mesuré" (cohérent v1 structure-only). |
| Q4 | **Empilement contigu par route** : clusters d'une route (racine + ses paths) groupés verticalement serrés (petit gap), grand gap avant la route suivante. | L'esprit "comme les aliases" (empilés serrés sous leur FQDN). Aucun nouveau composant : juste un gap variable dans le stack. `clusterSpecs` est déjà ordonné root-puis-paths par route (v2.24.0). |

## 1. Fix edges (Q1+Q2+Q3) — stroke "structural" visible

Mécanisme existant : `AnimatedFlowEdge.svelte` dérive un `tier` de `reqPerSec` ;
à 0 → tier `dead` → stroke gris opacity 0.2, 0 particule. Le stroke est tracé,
juste trop discret. `tierStrokeStyle(t)` retourne la string de style, appliquée
à `<BaseEdge>`.

**Fix :** distinguer une **branche structurelle** (edge de path-pool) d'un vrai
flux idle. `FlowEdgeData` (dans `_types.ts`) gagne un flag `structural?: boolean`,
posé par `pathPoolFlowData()` (`_layout.ts` ~745). `AnimatedFlowEdge` rend un
edge `structural` avec un style dédié :
```
stroke: <gris clair lisible>; stroke-opacity: 0.5; stroke-width: 1.5; stroke-dasharray: 5 4;
```
toujours SANS particules (0 trafic). Un edge de trafic normal à 0 (route idle)
garde son tier "dead" ACTUEL inchangé (non-régression).

Implémentation : dans `AnimatedFlowEdge`, brancher sur `data.structural` AVANT le
calcul de tier pour le stroke — si structural, retourner le style pointillé ; le
compte de particules reste 0 (structural implique 0 trafic en v1).

## 2. Fix regroupement (Q4) — empilement contigu par route

Problème : `clusterSpecs` (v2.24.0) est une liste plate (root r1, path r1a, path
r1b, root r2, …) passée à `computeStackYsForHeights` avec un gap UNIFORME
(`ROW_SPACING_Y`) → tous les clusters également espacés, aucun regroupement.

**Fix :** moduler le gap. Petit gap `INTRA_ROUTE_GAP` entre clusters d'une même
route ; grand gap `INTER_ROUTE_GAP` avant le cluster racine d'une nouvelle route.
`clusterSpecs` est déjà ordonné root-puis-paths par route → annoter chaque spec
avec un booléen "ouvre une nouvelle route" (vrai pour un cluster racine) et
fournir un stacker à gap variable (variante de `computeStackYsForHeights` prenant
un tableau de gaps, OU un nouveau helper `computeStackYsWithGaps(heights, gaps)`).

Résultat : `testpath` racine + `/v1` + `/legacy` + `/pub` = bloc vertical serré,
lu comme un groupe ; espace avant la route suivante.

## 3. Non concerné / gardes
- Pas de nouveau composant, pas de conteneur englobant (décision Q4-A). Edges +
  gaps uniquement.
- **Non-régression edges (le risque de Q2/C) :** une route sans path-pool et
  TOUT edge de trafic réel gardent un rendu STRICTEMENT identique — le style
  pointillé ne s'applique QUE si `data.structural === true`. Test dédié sur
  `tierStrokeStyle`/le rendu + revue attentive de `AnimatedFlowEdge`.
- **Non-régression layout :** une route sans path-pool = un seul cluster, Y
  inchangé (le gap variable n'a d'effet qu'avec ≥2 clusters ; INTER_ROUTE_GAP
  entre routes doit égaler l'espacement inter-cluster actuel pour préserver le
  rendu multi-route sans paths — vérifier que le stack global d'un jeu de routes
  sans paths reste identique à v2.24.0).
- Structure only maintenu (aucune métrique touchée).

## 4. Tests
- `_layout.test.ts` : (a) les clusters d'une route sont contigus — Y adjacents,
  gap intra-route < gap inter-route ; (b) l'edge hub→cluster de path porte
  `data.structural === true` ; (c) NON-RÉGRESSION : un jeu de routes SANS paths
  produit le même stacking Y qu'avant (INTER_ROUTE_GAP === ancien ROW_SPACING_Y).
- `AnimatedFlowEdge` : `structural=true` → style dasharray + opacity 0.5, 0
  particule ; `structural`-absent à 0 trafic → tier dead inchangé (non-régression
  du stroke existant).
- Suite frontend verte, svelte-check 0.
- **RE-DOGFOOD visuel (obligatoire — c'est ce qui a attrapé le bug) :** rouvrir
  la topology sur `testpath` → branches pointillées visibles du hub vers chaque
  cluster de path ; clusters de la route groupés serrés ; une route sans path
  inchangée.

## Process
LIGHT — 2-3 fichiers (`_layout.ts` gaps + flag structural, `_types.ts` flag,
`AnimatedFlowEdge.svelte` style). Revue attentive sur `AnimatedFlowEdge` (edge
PARTAGÉ = risque de régression sur tous les edges). Revue finale whole-branch.
Pas de backend, pas de `-race`. v2.24.1 (patch), tag après re-dogfood + go
opérateur.

## Backlog (rappel)
Trafic vivant par branche (req/s par path) — inchangé, toujours backlog. Quand il
arrivera, les edges `structural` deviendront de vrais `animated-flow` (le flag
`structural` sera retiré, le composant animera les particules).
