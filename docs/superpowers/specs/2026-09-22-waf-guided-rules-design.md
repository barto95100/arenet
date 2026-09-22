<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Règles WAF guidées — Design

**Status:** brainstormé avec l'opérateur 2026-09-22, décisions verrouillées.
Vague 2, chantier « règles WAF personnalisées », **PR 2 / 3** (1 =
exclusions ciblées, v2.36.0 ; 3 = éditeur SecLang + assistant).
Cible : **v2.37.0**.

**One-line :** dans le menu WAF d'une route, un formulaire (sans SecLang)
pour écrire « bloquer si méthode POST **et** chemin commence par /login
**et** User-Agent absent » ; Arenet génère la règle Coraza.

## Décisions

| # | Décision | Pourquoi |
|---|----------|----------|
| G1 | Critères : **chemin**, **méthode**, **User-Agent**, **en-tête** (par nom). | Choix opérateur. |
| G2 | **Pas d'IP source** : déjà couvert par le « Filtrage IP dédié » des règles par chemin. | Remarque opérateur, vérifiée (`Routes-FR.md` §règles par chemin). |
| G3 | Action unique : **Bloquer**, qui suit le mode de la route (block → 403, detect → journalisé). | Choix opérateur ; cohérent avec le reste du WAF. |
| G4 | Une règle = 1 à 8 critères, **tous** doivent correspondre (ET) ; un critère accepte plusieurs valeurs (**une parmi**). | Choix opérateur (ET) ; les listes de valeurs rendent possibles « UA contient sqlmap / nikto / masscan » et « méthode n'est pas GET / POST ». |
| G5 | Par route seulement, dans le menu WAF ; nom, activée / désactivée, phrase lisible. | Décision commune du chantier ; même esprit que la phrase du filtre géo. |
| G6 | Modèles de départ (boutons qui pré-remplissent) : fichiers sensibles, scanners connus, méthodes limitées. | Aide pour démarrer, sans règle cachée. |

## Modèle

```go
// storage.Route
WAFCustomRules []WAFCustomRule `json:"waf_custom_rules,omitempty"`

type WAFCustomRule struct {
    ID         int                `json:"id"`       // 120000..129999, stable (lien avec l'historique)
    Name       string             `json:"name"`
    Disabled   bool               `json:"disabled,omitempty"`
    Conditions []WAFRuleCondition `json:"conditions"`
}
type WAFRuleCondition struct {
    Field    string   `json:"field"`            // path | method | user_agent | header
    Header   string   `json:"header,omitempty"` // field=header
    Operator string   `json:"operator"`
    Values   []string `json:"values,omitempty"`
}
```

| Champ | Opérateurs | Valeurs |
|---|---|---|
| path | `is`, `begins_with`, `contains` | 1..20 ; `is`/`begins_with` commencent par `/` ; sensible à la casse |
| method | `is`, `is_not` | 1..10 jetons `[A-Z]+` (mis en majuscules) |
| user_agent | `contains`, `is`, `missing` (absent ou vide) | 1..20 sauf `missing` ; insensible à la casse |
| header | `present`, `absent`, `contains`, `is` | nom `[A-Za-z0-9_-]{1,64}` ; valeurs 1..20 pour contains/is ; insensible à la casse |

Valeurs : 1..256 caractères, sans `"`, `\`, ni caractère de contrôle.
Nom : 1..64 caractères, sans `"`, `'`, `\`, ni caractère de contrôle.
≤ 50 règles par route.

**IDs** : conservés à la modification (le client renvoie `id`) ; une
nouvelle règle (`id` 0) reçoit le plus grand ID de la route + 1 (≥ 120000,
≤ 129999). ID inconnu ou dupliqué → 400.

## Émission Coraza

Après les exclusions (999001, 110000+), avant les `Include` du CRS ;
règles désactivées non émises ; émises même CRS désactivé (le WAF reste
branché). Une règle = une chaîne `SecRule … chain` :

```
SecRule REQUEST_METHOD "@rx ^(?:POST)$" "id:120000,phase:1,deny,status:403,log,severity:CRITICAL,tag:arenet-custom,msg:'Arenet custom rule 120000',chain"
  SecRule REQUEST_FILENAME "@rx ^(?:/login)" "chain"
  SecRule &REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:User-Agent "@rx ^0?$" "t:none"
```

- valeurs échappées (`regexp.QuoteMeta`) dans un `@rx` ; `is` → `^(?:a|b)$`,
  `begins_with` → `^(?:a|b)`, `contains` → `(?:a|b)` ;
- insensible à la casse : `t:lowercase` + valeurs en minuscules ;
- `is_not` → `!@rx` ; `present`/`absent` → `&REQUEST_HEADERS:<nom>` `@gt 0` / `@eq 0` ;
- `missing` (UA) → compte 0 **ou** valeur vide (`^0?$` sur le compte et la valeur) ;
- `severity:CRITICAL` : visible en mode detect (filtre sévérité ≤ 4 de
  `onMatch`) ; `deny` : disruptif en mode block.

## Événements

- Catégorie **`CUSTOM`** pour 120000–129999 (`CategoryForRule`).
- `GET /security/events` enrichit `ruleName` (nom de la règle de la route)
  pour ces IDs.
- Pas de bouton « Exclure… » sur ces règles (déjà : `1xxxxx`).

## UI

Menu WAF de la route, section « Règles personnalisées » : liste (phrase,
interrupteur, modifier, supprimer), bouton « Ajouter une règle »,
éditeur (nom, critères ajoutables / supprimables, phrase en direct),
3 modèles. Grisé si le WAF est `off`. i18n FR + EN.

## Tests

Validation (champs, opérateurs, valeurs, injection, IDs), émission
(formes, ordre, désactivées, golden inchangé sans règle),
`caddy.Validate`, **E2E Coraza** (chaque opérateur match / non-match,
ET entre critères, mode detect vs block), API (POST/PUT, IDs stables,
`ruleName`), front (éditeur, phrase, modèles), smoke binaire réel.

## Non-goals

- ❌ IP / réseau (règles par chemin), paramètres, corps.
- ❌ Autres actions (journaliser seulement, autoriser sans CRS).
- ❌ OU entre critères, regex libres (→ PR 3 SecLang).
- ❌ Règles globales.
