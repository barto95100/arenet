<!-- Arenet spec — error-page {arenet.request.*} escaped placeholders (#367). AGPL-3.0. © 2026 The Arenet Authors. -->

# Spec — Placeholders `{arenet.request.*}` échappés pour les pages d'erreur (#367)

- **Issue**: #367 (suite de #365 ; fondation de #362)
- **Target release**: v2.87.0 (merge avant #362)
- **Branche**: `feat/error-page-arenet-request-vars` (basée sur `origin/main`)
- **Date**: 2026-11-24
- **Statut**: SPEC — en attente de GO opérateur avant guards RED + impl GREEN

---

## 1. Problème

Les pages d'erreur custom sont servies par `static_response`, dont
`repl.ReplaceKnown` **n'échappe pas** le HTML (`error_pages.go:36`). La
protection F42 (`neutralizeDangerousPlaceholders`, `error_pages.go:289`) doit
donc défanger `{http.request.host|uri|uri.path|header.*}` (XSS reflété), au prix
que l'opérateur ne peut **pas** afficher host/path proprement (seules les formes
`*_escaped` percent-encodées existent). But : exposer host/path **lisibles et
XSS-safe**.

## 2. Pourquoi PAS le handler `templates` Caddy (finding sécurité, vérifié)

Caddy v2.11.9, le handler `templates` exécute le corps comme template Go avec un
FuncMap exposant `include/readFile/httpInclude/listFiles/fileExists`
(`tplcontext.go:80-93`) **+ tout `sprig.TxtFuncMap()`** (`tplcontext.go:599` ;
`env`/`expandenv`/`getHostByName` — sprig `functions.go:270-274`). Les corps
étant **écrits côté opérateur**, les exécuter ouvrirait secret-exfil
(`{{env …}}`), LFI (`{{readFile}}`), SSRF (`{{httpInclude}}`) — régression du
modèle de menace « admin compromis / XSS » (`error_pages.go:101-103`). Rejeté.
Détail complet dans le body de #367.

## 3. Scope (minimal, Option A)

1. **Nouveau module Caddy** `http.handlers.arenet_error_vars` (pattern existant
   `http.handlers.arenet_*` : countryblock `module.go:37`, waf, cert_info…).
   Struct **vide** (aucune config, aucun FuncMap). `ServeHTTP` :
   - récupère le Replacer de la requête
     (`r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)`), défensif si
     absent (→ `next` direct) ;
   - `repl.Set("arenet.request.host", html.EscapeString(r.Host))` ;
   - `repl.Set("arenet.request.path", html.EscapeString(r.URL.Path))` ;
   - appelle `next`.
   Enregistré à l'init (`caddy.RegisterModule`), comme countryblock.
2. **Émission** : `buildErrorRoutesForRoute` (`error_pages.go:602` + fallback
   `:625`) préfixe le `Handle` de **chaque** route d'erreur :
   `[{"handler":"arenet_error_vars"}, {"handler":"static_response", …}]`.
   L'ordre du `Handle` garantit que le handler s'exécute **avant** `static_response`.
3. **Résolution** : `static_response`/`ReplaceKnown` résout `{arenet.request.host}`
   / `{arenet.request.path}` comme clés custom posées par `repl.Set` (lookup map
   connu → pas de défang, pas touché par F42 qui ne cible que `{http.request.*}`).
4. **Doc** : `docs/operations/` + note éditeur Templates (FR+EN) listant les 2
   nouveaux placeholders à côté des `*_escaped`.

## 4. Hors scope (strict — demande opérateur)

- Pas de FuncMap / moteur de template ; pas de `env`/`readFile`/`httpInclude`/`getHostByName`.
- Pas de modif de bluemonday, `stripDangerousAtRules`, ni de l'API `static_response`.
- Aucun placeholder au-delà de `request.host` + `request.path` (les `{arenet.ban.*}` = #362).
- Pas de contexte d'échappement URL/JS : les pages d'erreur sont du **HTML pur**
  (confirmé framing b) → `html.EscapeString` suffit.

## 5. Décisions (sign-off opérateur — confirmées 2026-11-24)

| ID | Question | Décision |
|----|----------|----------|
| D1 | Nommage | `{arenet.request.host}` / `{arenet.request.path}` — namespace `arenet.`, pas de collision `{http.request.*}`, cohérent #362 |
| D2 | Échappement | `html.EscapeString` (HTML pur), gère `< > " ' &` ; UTF-8 préservé (IDN/path non-ASCII) |
| D3 | Ordre | handler AreNET en tête du `Handle`, avant `static_response` (garanti par l'ordre du slice) |
| D4 | F42 | inchangé ; le handler n'ajoute QUE `{arenet.*}`, ne touche jamais `{http.*}` |
| D5 | Mécanisme | mini-module Caddy dédié (pas de réutilisation du hot-path metrics : garantit l'exécution pour TOUTE route d'erreur, y compris 404 route-not-found) |

## 6. Guards (TDD, RED d'abord)

| Guard | Scénario | Attendu |
|-------|----------|---------|
| G_arenet_request_host_escaped | `host` = `a"><script>` | rendu final HTML-échappé (`&lt;script&gt;` …) |
| G_arenet_request_path_escaped | `path` contient `< > " ' &` | rendu HTML-échappé |
| G_arenet_request_path_unicode | `path` UTF-8 (IDN, accents) | rendu correct, octets UTF-8 intacts |
| G_http_request_still_defanged | corps avec `{http.request.host}` | **reste défangé** (F42 intact) |
| G_replacer_injection_order | émission JSON d'une route d'erreur | `arenet_error_vars` à l'index 0, **avant** `static_response` |
| G_no_template_funcs_exposed | corps avec `{{env "X"}}` / `{{readFile …}}` / `{env.X}` | **non exécuté** (rendu littéral / défangé) — aucune fonction template, aucun accès secret/fichier |
| G_arenet_vars_set_on_replacer | ServeHTTP du handler | le Replacer contient `arenet.request.host`/`path` échappés au moment où `next` (static_response) consomme |

> `G_no_template_funcs_exposed` verrouille le cœur de la décision sécurité : prouver
> qu'on n'a PAS introduit de moteur de template. `{env.X}` est déjà couvert par F42
> (`dangerousPlaceholderPrefixes`, `error_pages.go:227`) — le guard le re-confirme.

## 7. Reinjection (skill guard §3)

- Retirer l'`html.EscapeString` (poser la valeur brute) ⇒ **G_arenet_request_host_escaped** rouge, autres verts.
- Émettre `arenet_error_vars` **après** `static_response` ⇒ **G_replacer_injection_order** rouge (et le rendu ne substitue plus → host_escaped rouge aussi, donc séparer l'assertion d'ordre sur le JSON émis).
- Défanger aussi `{arenet.*}` par erreur ⇒ host_escaped rouge (clé non résolue).
- Toucher F42 pour laisser passer `{http.request.host}` ⇒ **G_http_request_still_defanged** rouge.

## 8. Non-régression (instruments)

- **Golden JSON d'émission** : la diff des routes d'erreur doit montrer **uniquement**
  le préfixe `arenet_error_vars` ajouté, rien d'autre (relire la diff `testdata/`,
  jamais `-update` aveugle — skill guard §1).
- **Rendu non-régression** : pour un set représentatif de corps stockés qui
  **n'utilisent pas** `{arenet.request.*}`, le rendu final est **byte-identique**
  avant/après (le nouveau handler ne fait que poser des clés non consommées).
- **`caddy.Validate`** sur la config générée (nouveau handler résolvable +
  `TestBuildConfigJSON_HandlersAllResolvable` étendu).

## 9. Gates de validation empirique

- `go build ./... && go vet ./...` propre ; `go test -race -count=1 ./internal/caddymgr/... ./internal/<module>/...` vert.
- `caddy.Validate` passe (handler `arenet_error_vars` enregistré).
- Dogfood AreNET-test : page 403 avec `{arenet.request.host}`/`{arenet.request.path}`
  → host/path affichés lisibles ; tenter `<script>` dans host (via Host header) →
  échappé dans la source servie.

## 10. Non-goals

- Pas de `{arenet.ban.*}` (c'est #362, qui consommera le même système).
- Pas de nouvelle UI au-delà de la liste des placeholders dans l'éditeur.
- Pas d'échappement configurable (toujours HTML).
