# Path-upstream : skip-verify par path + poids conditionnel — Design

**Status:** brainstormé avec l'opérateur 2026-07-24, 3 décisions verrouillées.
Branche `fix/path-upstream-tls-weight`. Version cible **v2.23.1** (patch — 2
corrections de la feature per-path upstream v2.23.0). Issu du dogfooding live
(smoke 8/8) qui a révélé les deux manques.

**One-line:** Deux corrections au per-path upstream (v2.23.0) :
(1) un `insecureSkipVerify` **propre à chaque path-rule** (un backend HTTPS
auto-signé sur un path ne force plus TOUTE la route en insecure) ;
(2) le champ **poids** du pool d'un path n'apparaît que si sa répartition est
`weighted_round_robin`, comme le pool de la route.

## Contexte (le trou trouvé en dogfooding)

Smoke 8/8 validé, mais deux frictions :
- Le backend HTTPS auto-signé de `/legacy` exigeait `insecureSkipVerify`, or le
  seul endroit pour l'activer est **au niveau route** (le pool du path hérite de
  `r.InsecureSkipVerify`, `manager.go:1658`). Donc protéger UN path en
  skip-verify affaiblit la vérif TLS de TOUTE la route — l'inverse de la
  granularité que la feature apporte.
- Le pool du path affiche le champ **poids en dur** (Task 6 v2.23.0), alors que
  le pool de la route ne l'affiche que si la LB = `weighted_round_robin`
  (`weightVisible`, `+page.svelte:1671`). Incohérence UX : le poids ne sert
  qu'à `weighted_round_robin` et n'a aucun effet sur les 5 autres politiques.

## Décisions (Q1–Q3)

| # | Décision | Pourquoi |
|---|----------|----------|
| Q1 | `insecureSkipVerify` d'un path = **autonome** : le pool du path gère son propre skip-verify (défaut `false` = strict), la route n'y touche pas. Un path SANS pool continue d'hériter du proxy route entier. | Cohérent avec Q2 de v2.23.0 ("chaque pool indépendant") ; le transport TLS est déjà déduit par pool, le skip-verify est son corollaire naturel. Un pool de path est pleinement autonome (upstreams+LB+HC+transport+skip-verify). |
| Q2 | Le champ **poids** du pool path n'est visible que si `rule.lbPolicy === 'weighted_round_robin'`, comme le pool route. | Le poids n'a de sens que pour weighted_round_robin ; le montrer partout est trompeur. Aligne l'UI path sur l'UI route (`weightVisible`). |
| Q3 | La case « Ignorer la vérif TLS » ne s'affiche **que si le pool du path détecte au moins une URL `https://`**. | Cohérent avec le pool route qui n'affiche l'avertissement TLS que sur https ; évite une case trompeuse sur un backend http (où le transport TLS n'est même pas émis). |

## Correction 1 — `insecureSkipVerify` par path-rule

Nouveau champ optionnel sur `PathRule`, à travers les 4 surfaces habituelles
(mêmes surfaces qu'upstreams/lbPolicy/healthCheck de v2.23.0 —
[[route_wire_field_gap_regression]]) :

| Surface | Changement |
|---|---|
| **storage** `internal/storage/routes.go` (PathRule struct) | `InsecureSkipVerify bool` json `insecure_skip_verify,omitempty` (migration-free). Pas de validation spécifique (bool). |
| **wire API** `internal/api/handler.go` | `pathRuleReq.InsecureSkipVerify bool` json `insecureSkipVerify,omitempty` ; mappé dans `mapPathRuleReqs` (dans le bloc `len(Upstreams)>0`, comme lbPolicy) ; echo dans `toPathRulesResp` (non secret). |
| **émission** `internal/caddymgr/manager.go:1658` | passe `pr.InsecureSkipVerify` au lieu de `r.InsecureSkipVerify` au `proxyPoolParams` du path. Corriger le commentaire `manager.go:1646` qui affirme l'héritage. |
| **frontend** `types.ts` + `PathRulesSection.svelte` | `PathRule.insecureSkipVerify?: boolean` ; case « Ignorer la vérif TLS » dans le disclosure, visible seulement si le pool a une URL `https://` (Q3). |

**Sémantique (Q1) :** `pr.InsecureSkipVerify` défaut `false` (strict). La route
en skip-verify n'affecte QUE son propre pool + les paths SANS pool (qui héritent
via `proxyHandler`). Un path AVEC pool est autonome.

**Payload frontend** (`+page.svelte`) : ajouter `insecureSkipVerify` aux DEUX
sites hand-pick (hydratation ~1338 + submit ~2079), comme on l'a fait pour les 3
champs v2.23.0 — sinon l'édition droppe le champ.

**`buildReverseProxyHandler` / `proxyPoolParams`** : INCHANGÉ — le champ
`InsecureSkipVerify` existe déjà dans `proxyPoolParams` (v2.23.0). Seule la
SOURCE change (`pr.` au lieu de `r.`) au call site. Donc pas de refacto émission.

## Correction 2 — poids conditionnel dans le pool path

Pure UI, `PathRulesSection.svelte` : dériver par carte
`weightVisible = rule.lbPolicy === 'weighted_round_robin'` et n'afficher la
colonne poids que dans ce cas (miroir de `+page.svelte:1671`). Le poids reste
stocké/envoyé (défaut `1` matérialisé côté backend, déjà en place) — juste masqué
quand la LB ne l'utilise pas. Aucun changement backend.

## Non concerné (YAGNI)
- Pas de nouveau composant, pas de refacto émission (`buildReverseProxyHandler`
  intact), pas de champ TLS transport séparé (déduit du schéma).
- `UploadStreamingMode` reste hérité de la route pour les paths (pas de toggle
  par path — hors périmètre, YAGNI).

## Byte-identité / migration
- `InsecureSkipVerify` omitempty → un path sans ce champ émet comme avant.
- CHANGEMENT DE COMPORTEMENT assumé : un path AVEC pool qui, en v2.23.0,
  héritait du skip-verify de la route, devient **strict par défaut** en v2.23.1.
  C'est le fix voulu (la granularité). À documenter dans le changelog. Un
  opérateur qui voulait le skip-verify sur ce path devra cocher la case du path.
  (Impact réel minime : la feature a 1 jour, seul le dogfooding l'utilise.)

## Tests
- **storage** : round-trip du champ (défaut false, true préservé).
- **wire** : `insecureSkipVerify` traverse req+map+resp (wire-gap).
- **émission** (caddymgr) : un path avec `insecureSkipVerify:true` + pool https
  émet `transport.tls.insecure_skip_verify:true` ; un path avec `false` + pool
  https émet `tls:{}` (strict) MÊME SI la route est en skip-verify (prouve
  l'autonomie Q1). `go test -race ./internal/caddymgr/` obligatoire
  ([[caddymgr_race_test_gate]]).
- **frontend** : `PathRulesSection` — poids masqué sauf weighted_round_robin ;
  case TLS visible seulement si pool https ; `sanitizePathRules`/payload
  portent le champ. i18n EN+FR parité.
- **byte-identité** : le golden route-emission reste identique (pas de path
  rules dans le fixture golden).

## Process
LIGHT — backend 4 surfaces + 2 fichiers front + i18n. On touche l'émission TLS
→ `go test -race` caddymgr + un test d'émission autonomie skip-verify. Pas de
revue dédiée opus (champ isolé, pas de refacto). Revue inline par tâche + une
revue finale whole-branch. Version v2.23.1 (patch), tag après go opérateur.
