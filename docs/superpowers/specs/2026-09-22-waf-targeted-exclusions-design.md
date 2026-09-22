<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Exclusions WAF ciblées depuis l'historique — Design

**Status:** brainstormé avec l'opérateur 2026-09-22, décisions verrouillées.
Vague 2 de l'analyse concurrentielle, chantier « règles WAF personnalisées »,
**PR 1 / 3** (2 = règles guidées, 3 = éditeur SecLang + assistant).
Cible : **v2.36.0**.

**One-line :** sur un événement WAF (faux positif), un bouton « Exclure »
crée une exclusion **ciblée** : la règle reste active mais n'inspecte plus
le champ qui a déclenché (ex. le paramètre `content`), par défaut
seulement sur le chemin de l'événement.

## Constat (code, 2026-09-22)

- Par route : mode `off/detect/block`, streaming upload, CRS désactivable,
  exclusions **sur toute la route** par ID (`WAFExcludeRules`) et par tag
  (`WAFExcludeTags`), émises dans un `SecAction id:999001` placé **avant**
  les `Include` du CRS (`caddymgr/manager.go:2999-3030`).
- Aucune exclusion par champ ni par chemin ; aucun lien entre l'historique
  WAF et les réglages de la route.
- L'événement stocké (`observability.WafEvent`) n'a pas le nom du champ
  qui a déclenché ; `PayloadSample` vient de `MatchedDatas()` (valeur
  seulement, `waf/module.go:654-669`).
- Plage d'IDs `100000-199999` réservée aux règles générées par Arenet
  (`storage/routes.go:562-567`) ; seul `100001` est pris (garde du plan
  d'administration).

## Faits vérifiés (source Coraza v3.7.0)

1. `ctl:ruleRemoveTargetById=<id>;<VAR>:<clé>` est supporté
   (`internal/actions/ctl.go:152-165`) ; doit s'exécuter **avant** la règle
   visée (phase 1, avant les `Include`).
2. L'exception s'applique quand la variable **de la règle** est égale à
   `<VAR>` (`internal/corazawaf/rule.go:231-238`) ; la clé est comparée en
   minuscules (`transaction.go:661`). `ARGS` est éclaté en
   `ARGS_GET` + `ARGS_POST` (`transaction.go:699-712`).
3. `types.MatchData` expose `Variable()` et `Key()` (`types/rule_match.go:10-14`) ;
   `Variable` est celle de la règle (`GetField` → `Variable_: rv.Variable`,
   `transaction.go:677`) : `VAR:clé` d'un événement est donc **exactement**
   la cible à retirer.
4. Règles d'évaluation / initialisation du CRS : `901xxx`, `949xxx`,
   `959xxx`, `980xxx`. Les exclure désactive le blocage lui-même → jamais
   proposées.

## Décisions

| # | Décision | Pourquoi |
|---|----------|----------|
| E1 | **Exclusion par champ** (`VAR:clé`) proposée depuis un événement. | Méthode recommandée par OWASP : la règle continue de protéger les autres champs. |
| E2 | **Limitée au chemin de l'événement, coché par défaut** (décochable → tous les chemins de la route). | Le plus étroit par défaut. |
| E3 | Événement **sans champ** (anciens événements, règle sur l'URL…) → le bouton propose l'exclusion **sur toute la route** (ajout à `WAFExcludeRules`), avec avertissement. | Reste utilisable, sans inventer de cible. |
| E4 | **Gestion dans le menu WAF de la route** : liste « Exclusions ciblées » lisible, suppression, ajout manuel. | Tout le réglage WAF d'une route au même endroit. |
| E5 | Par route seulement ; le mode (detect/block) de la route s'applique. | Décisions communes au chantier. |

## Modèle

```go
// storage.Route
WAFTargetedExclusions []WAFTargetedExclusion `json:"waf_targeted_exclusions,omitempty"`

type WAFTargetedExclusion struct {
    RuleID     int    `json:"rule_id"`              // 200000..999999, hors 901/949/959/980xxx
    Target     string `json:"target"`               // "ARGS:content", "REQUEST_HEADERS:user-agent"…
    Path       string `json:"path,omitempty"`       // "" = tous les chemins
    PathPrefix bool   `json:"path_prefix,omitempty"` // true = le chemin et ce qui est en dessous
}
```

Validation (API) :
- `RuleID` : même plage que `WAFExcludeRules`, et pas dans les familles
  protégées (E4 faits §4) ;
- `Target` : `VAR:clé` ; `VAR` ∈ `ARGS, ARGS_GET, ARGS_POST, ARGS_NAMES,
  REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS,
  REQUEST_HEADERS_NAMES, FILES, FILES_NAMES` ; clé non vide, ≤ 128, sans
  espace, `"`, `'`, `,`, `;`, `\`, `|`, caractère de contrôle (injection
  dans l'action `ctl`) ;
- `Path` : vide ou commence par `/`, ≤ 512, sans espace, `"`, `\`,
  caractère de contrôle ;
- au plus 100 exclusions par route ; doublons exacts supprimés ; ordre
  canonique (tri) pour une config stable.

## Émission Caddy / Coraza

Après le `SecAction 999001` existant, avant les `Include` du CRS ; IDs
`110000 + i` (plage réservée Arenet, ordre canonique) :

```
SecAction "id:110000,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:content"
SecRule REQUEST_FILENAME "@streq /api/save" "id:110001,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:content"
SecRule REQUEST_FILENAME "@beginsWith /api/" "id:110002,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=941100;ARGS:body"
```

« Et en dessous » sur un chemin sans `/` final (`/api`) émet **deux**
directives, `@streq /api` et `@beginsWith /api/` : `@beginsWith /api`
seul laisserait passer `/apix` (constaté au smoke, corrigé avant la PR).

Aucune exclusion ciblée → directives **identiques octet pour octet** à
aujourd'hui (golden inchangé). CRS désactivé → émises quand même (comme
`999001`, sans effet).

## Événements

- Nouvelle colonne `matched_var` (`TEXT NOT NULL DEFAULT ''`, migration
  observability V12 → V13) : `VAR:clé` du `MatchData` retenu pour
  l'échantillon ; vide si la variable n'a pas de clé (`REQUEST_FILENAME`,
  `REQUEST_URI`…). Tronquée à 256 octets, **non** masquée (c'est un nom de
  champ, pas une valeur).
- API événements : champ `matchedVar`.

## API

`POST /api/v1/routes/{id}/waf-exclusions` — corps
`{ruleId, target?, path?, pathPrefix?}` :
- avec `target` → ajout à `WAFTargetedExclusions` ;
- sans `target` → ajout à `WAFExcludeRules` (E3) ;
- même chemin qu'une modification de route : validation, audit
  `route_update`, rechargement Caddy, annulation si Caddy refuse ;
  même permission que modifier une route ; 409 si déjà présente (sans
  effet) ; réponse = route mise à jour.

`GET/PUT` de la route transportent `wafTargetedExclusions` (pointeur :
absent = inchangé), pour l'édition dans le formulaire.

## UI

- Listes d'événements WAF (`WafEventList`, page sécurité par route, page
  WAF, dashboard) : bouton « Exclure… » sur une ligne si la règle n'est
  ni protégée ni une règle Arenet (`1xxxxx`), la route existe et
  l'utilisateur peut modifier les routes.
- Fenêtre : explication en clair (« la règle 942100 (SQLi) n'inspectera
  plus le paramètre `content` sur `/api/save` ») ; case « seulement sur
  ce chemin » cochée + « et en dessous » ; chemin modifiable ; sans champ
  → avertissement « toute la route ». Toast de confirmation.
- Formulaire de route, menu WAF : section « Exclusions ciblées » sous les
  tags, une ligne lisible par exclusion (supprimer), bouton « Ajouter »
  (règle, type de champ + nom, chemin optionnel).
- i18n FR + EN.

## Sauvegarde / restauration

Champ de `storage.Route` → inclus tel quel dans le backup ; test
aller-retour.

## Tests / validation

- Unitaires : validation (cibles, chemins, familles protégées, limites),
  ordre canonique, émission (sans / avec chemin / préfixe), golden
  inchangé sans exclusion, `caddy.Validate` avec exclusions ciblées.
- **E2E Coraza** (vrai CRS) : requête `ARGS:content` déclenchant 942100 en
  block → 403 ; exclusion ciblée → 200 ; même charge dans un autre
  paramètre → 403 ; même requête sur un autre chemin → 403 (exclusion
  avec chemin) ; `matched_var` enregistré = `ARGS:content`.
- Front : bouton visible / masqué (règle protégée, règle Arenet),
  fenêtre (cas avec / sans champ), section du formulaire.
- Smoke binaire réel : faux positif provoqué → exclusion depuis
  l'historique → requête acceptée ; autre paramètre toujours bloqué.

## Non-goals

- ❌ Exclusions globales (toutes routes).
- ❌ Suggestions automatiques d'exclusions (analyse de l'historique).
- ❌ Modifier le comportement des champs existants (IDs / tags sur toute
  la route).
- ❌ Règles personnalisées (PR 2 et 3).
