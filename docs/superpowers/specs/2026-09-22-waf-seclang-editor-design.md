<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Éditeur SecLang par route + assistant — Design

**Status:** brainstormé avec l'opérateur 2026-09-22, décisions verrouillées.
Vague 2, chantier « règles WAF personnalisées », **PR 3 / 3** (1 =
exclusions ciblées #80, 2 = règles guidées #81). Cible : **v2.38.0**.

**One-line :** une zone SecLang par route (mode expert) avec quatre aides
pour les non-experts : pont règle guidée → SecLang, modèles commentés,
testeur de requête, aide à la saisie.

## Constat (source, 2026-09-22)

- Le WAF est construit avec `WithRootFS(mergefs.Merge(coreruleset.FS,
  mergefsio.OSFS))` (`internal/waf/module.go:301`) : un `Include` ou un
  opérateur `*FromFile` peut lire **n'importe quel fichier de l'hôte**.
- Coraza v3.7.0 implémente `@inspectFile` en **exécutant un programme**
  (`internal/operators/inspect_file.go:53`, `exec.CommandContext`),
  `@rbl` fait des requêtes DNS (`rbl.go:71`), l'action `setenv` modifie
  l'environnement du processus.
- `ctl:ruleEngine`, `ctl:auditEngine`, `ctl:requestBodyAccess`,
  `ctl:*BodyLimit`, `ctl:debugLogLevel` changent la politique du moteur
  (`internal/actions/ctl.go:434-472`).

## Décisions

| # | Décision | Pourquoi |
|---|----------|----------|
| S1 | **Liste blanche stricte** : directives `SecRule`, `SecAction`, `SecMarker` seulement ; opérateurs et actions sur liste blanche ; refus à l'enregistrement avec **numéro de ligne**. | Choix opérateur ; les faits ci-dessus rendent une liste noire trop risquée. |
| S2 | IDs imposés **130000–139999**, uniques ; chaque début de chaîne et chaque `SecAction` porte un ID. | Choix opérateur ; aucune collision CRS / Arenet ; l'historique sait que c'est une règle personnalisée. |
| S3 | Exécuté **avant le CRS**, après les exclusions et les règles guidées. | Choix opérateur. |
| S4 | Mode de la route respecté (`SecRuleEngine` ajouté par Arenet en dernier, comme aujourd'hui). | Décision commune du chantier. |
| S5 | Les 4 aides : pont guidé → SecLang, modèles commentés, testeur, aide à la saisie. | Choix opérateur (brainstorm PR 1). |

### Liste blanche

- **Opérateurs** : `@rx @streq @beginsWith @endsWith @contains
  @pm @within @eq @ge @gt @le @lt @ipMatch @detectSQLi
  @detectXSS @validateByteRange @validateUrlEncoding
  @validateUtf8Encoding @strmatch @unconditionalMatch @noMatch` (avec
  ou sans `!` ; sans `@` = `@rx`). Refusés notamment : `@inspectFile`,
  `@pmFromFile`, `@ipMatchFromFile`, `@rbl`, `@validateSchema`,
  `@geoLookup`.
- **Actions** : `id phase chain deny block drop pass allow status
  redirect log nolog auditlog noauditlog msg logdata tag severity rev
  ver maturity capture multiMatch setvar expirevar skip skipAfter t`.
  Refusées : `exec setenv initcol` et tout le reste.
- **ctl** autorisés : `ruleRemoveById ruleRemoveByTag ruleRemoveByMsg
  ruleRemoveTargetById ruleRemoveTargetByTag ruleRemoveTargetByMsg
  requestBodyProcessor forceRequestBodyVariable`.
- Collection `ENV` et macros `%{ENV.…}` refusées (ajout pendant
  l'implémentation : l'environnement du processus peut contenir des
  secrets, ex. clés du fournisseur DNS, qui fuiraient via `logdata`).
- Backticks refusés (blocs multi-lignes de Coraza).
- ≤ 64 Kio de texte, ≤ 200 règles.

Validation en deux temps : analyse Arenet (liste blanche, IDs, lignes)
puis compilation Coraza du texte seul, **sans système de fichiers**
(erreurs de syntaxe fines). La config complète passe ensuite par
`caddy.Load` comme toute modification (rollback si refus).

## Modèle / émission

`storage.Route.WAFSecLang string` (`waf_seclang,omitempty`). Émis tel
quel après les règles guidées, avant les `Include` du CRS ; émis même CRS
désactivé. Vide → config **identique**.

Catégorie d'événement `CUSTOM` étendue à 120000–139999 ; `ruleName` des
règles SecLang = leur `msg`.

## API

- `POST/PUT /routes` : `wafSecLang` (pointeur : absent = inchangé) ;
  invalide → 400 code `seclang_invalid`, `params.errors[{line, message}]`.
- `POST /waf/seclang/validate` `{seclang}` → `{errors: [...], nextId}`
  (vérification en direct dans l'éditeur, ID libre suivant).
- `POST /waf/seclang/from-guided` `{rule, id}` → `{seclang}` (pont :
  même générateur que les règles guidées, commenté).
- `POST /routes/{id}/waf-test` `{method, path, headers[], body,
  seclang?}` → `{blocked, status, blockedBy, matches[{id, msg,
  severity, data}], mode}` : la requête d'exemple passe dans Coraza avec
  la config WAF de la route (brouillon SecLang inclus si fourni),
  moteur **On** pour savoir si elle serait bloquée ; aucun trafic réel,
  aucun événement enregistré.

Toutes réservées aux admins.

## UI (menu WAF de la route, section « SecLang (avancé) », repliée)

- Éditeur CodeMirror : coloration SecLang, autocomplétion (directives,
  variables, opérateurs, actions), erreurs soulignées à la ligne
  (validation en direct).
- **Modèles** commentés ligne par ligne, insérés avec le prochain ID
  libre : API JSON uniquement, méthodes autorisées, protéger /admin par
  IP, bloquer un pays sur un chemin… (liste finale au plan).
- **Pont** : sur une règle guidée, « Convertir en SecLang » → la règle
  guidée est remplacée par son SecLang commenté (nouvel ID 13xxxx).
- **Testeur** : méthode, chemin, en-têtes, corps → « bloquée (403) par
  la règle 130002 « … » » ou « acceptée », liste des règles déclenchées
  (CRS compris) ; teste le brouillon non enregistré.

## Tests

Analyse (chaque refus : directive, opérateur, action, ctl, ID hors
plage / manquant / dupliqué, chaîne), compilation Coraza, émission +
`caddy.Validate`, E2E (règle SecLang bloque / journalise selon le mode),
testeur (bloquée / acceptée / brouillon), pont (sortie compilable et
équivalente), API, front (éditeur, modèles, testeur, pont), smoke
binaire réel (y compris tentatives `Include /etc/passwd`,
`@inspectFile`, `setenv`, `ctl:ruleEngine=Off` → 400).

## Non-goals

- ❌ SecLang global (toutes routes).
- ❌ Directives de configuration du moteur (`SecRequestBodyLimit`…).
- ❌ Fichiers de données (`*FromFile`), scripts.
