<!-- Arenet plan — AreNET Allowlist UI (#364). AGPL-3.0. © 2026 The Arenet Authors. -->

# Plan — AreNET Allowlist UI (#364)

Spec : `docs/superpowers/specs/2026-11-23-allowlist-ui.md` (GO opérateur 2026-11-23,
4 décisions D-STORE/D-BACKUP/D-SLUG/D-DEGRADED validées). Target v2.85.0.
Branche : `feat/allowlist-ui` (depuis `main` @ 7a5836f = v2.84.5).

Discipline : **TDD** (tests G_* RED d'abord), golden non-régression **avant** tout
changement du trigger, `cp` pour toute réinjection (jamais `git checkout`),
commits logiques séparés, ne commiter QUE les fichiers voulus (jamais
`skills-lock.json` ni `.claude/skills/apple-design`).

---

## Jalon 0 — Docs (ce commit)

- [x] Spec.
- [x] Plan.
- Commit `docs(allowlist): spec + plan pour #364` (spec + plan uniquement).

## Jalon 1 — Golden non-régression (AVANT tout changement trigger)

But : prouver que `nil AllowlistChecker` laisse le trigger byte-identique à
v2.84.5. Le trigger n'émet pas d'artefact sérialisé → golden = **test de
caractérisation** sur les `Intent` émis.

- [ ] `TestTrigger_NilAllowlistChecker_EmitsUnchangedIntents` dans
      `internal/automation/trigger_test.go` : fixture d'événements (WAF RCE ×N,
      throttle, auth) → set d'intents attendu. Écrit et **vert sur le code
      v2.84.5 actuel** (caractérise l'existant).
- [ ] Commit `test(automation): golden intents baseline before allowlist hook`
      (test seul, sur code inchangé).

## Jalon 2 — Tests G_* en RED

Introduire les **signatures minimales** pour que ça compile, mais retournant des
stubs inertes (interface `AllowlistChecker`, type `Category`, `Source.Category()`
renvoyant une valeur, resolver non câblé) → les tests compilent et **échouent sur
le comportement**, pas sur la compilation.

Backend automation :
- [ ] `Category` type + `Source.Category()` (stub RED : renvoie une constante fixe).
- [ ] Interface `AllowlistChecker` + champ `EngineConfig.AllowlistChecker`.
- [ ] G_allowlist_match, G_allowlist_scope, G_allowlist_inactive,
      G_allowlist_cidr_match, G_allowlist_no_crowdsec_dep (fake checker),
      G_allowlist_category_map → tous RED.

Store/resolver (`internal/allowlist`) :
- [ ] G_allowlist_cidr_validation, G_allowlist_rebuild_on_mutation,
      G_allowlist_degraded → RED (store pas encore implémenté).

API :
- [ ] G_allowlist_wire (JSON littéral) → RED.

- [ ] Commit `test(allowlist): G_* guards RED` (tests + stubs minimaux).
- **Vérifier chaque RED échoue pour SA raison** (lire les sorties).

## Jalon 3 — Backend GREEN

- [ ] `internal/allowlist/store.go` : `Open(ctx, path)` (modernc, WAL,
      busy_timeout, SetMaxOpenConns(1)), schéma `allowlist` + `allowlist_entry`,
      migrate chain + `schema_version`, CRUD, validation `net/netip`.
- [ ] `internal/allowlist/resolver.go` : `Resolver` + `atomic.Pointer[resolvedSet]`,
      `Lookup(addr, cat)`, `Rebuild()` ; `resolvedSet` = prefixes par catégorie
      (actifs + scope couvrant).
- [ ] `Source.Category()` réel (mapping D4), `Category` block/throttle/audit.
- [ ] Hook trigger `trigger.go:533` (après `scenario :=`, avant cooldown) +
      log INFO `automation: ban skipped (allowlisted)`.
- [ ] Adapter `cmd/arenet/allowlist_adapter.go` : branche `allowlist.Resolver` sur
      `automation.AllowlistChecker` (mapping `automation.Category`→resolver cat).
- [ ] Wiring `cmd/arenet/main.go` : ouvrir `security.db`, construire resolver,
      injecter dans `EngineConfig`, câbler `Rebuild()` sur les mutations API.
      Politique dégradée D-DEGRADED : échec ouverture → resolver vide + WARN.
- [ ] API `internal/api/allowlists.go` : handlers CRUD + validation + audit +
      `Rebuild()` ; montage `routes.go` (GET viewer, writes admin).
- [ ] OpenAPI `internal/api/openapi/allowlists.yaml` + `x-arenet-role`
      (sinon `openapi_test` casse — cf. `openapi-route-must-be-documented`).
- [ ] Backup `internal/backup` : inclure `security.db` export/import + test round-trip.
- [ ] Tous les guards backend GREEN. **Réinjecter chaque défaut** (cp) → le guard
      bite, les siblings restent verts.
- [ ] `go build ./... && go vet ./... && go test -race ./...` verts.
- [ ] `go list -deps ./internal/automation` ne contient ni crowdsec ni allowlist.
- [ ] Commits logiques : `feat(allowlist): sqlite store + resolver`,
      `feat(automation): allowlist skip hook`, `feat(api): allowlist CRUD`,
      `feat(backup): include security.db`.

## Jalon 4 — Frontend GREEN

- [ ] `lib/api/allowlists.ts` (client + types).
- [ ] `routes/security/allowlists/+page.svelte` : table + état vide + modal
      suppression.
- [ ] Formulaire create/edit : nom→slug, description, textarea entrées (validation
      live), 3 checkboxes scope (défaut cochés), toggle actif.
- [ ] Sidebar : item `/security/allowlists` (`navAllowlists`) près de WAF +
      active-match sur le pathname.
- [ ] i18n FR + EN (parité `index.test.ts`), ARIA labels.
- [ ] Limitation origin=arenet affichée (état vide + aide).
- [ ] Tests vitest (liste, formulaire, validation, wire types).
- [ ] `npm run check && npm test` verts.
- [ ] Commits : `feat(web): allowlist API module + types`,
      `feat(web): allowlists page + form`, `feat(web): sidebar + i18n`.

## Jalon 5 — Docs / smoke

- [ ] `docs/smoke-test-allowlist.md` (procédure dogfood).
- [ ] Doc utilisateur (créer une allowlist).
- [ ] Doc opérateur : limitation origin=arenet (texte verbatim spec §8) +
      wiki-seed FR/EN.
- [ ] Commit `docs(allowlist): smoke + user + operator docs`.

## Jalon 6 — PR + CI

- [ ] Push `feat/allowlist-ui`, ouvrir PR (grosse, commits logiques, body détaillé,
      PAS d'attribution AI).
- [ ] CI verte (backend race + frontend).
- [ ] Ping opérateur pour review finale. **Pas de merge sans GO.**

## Post-merge (après GO + dogfood v2.85.0)

- [ ] Release notes v2.85.0 détaillées.
- [ ] Fermer #364 avec commentaire (PR + release).
- [ ] Bascule prod srv2009298 v2.82.0 → v2.85.0 (ensemble, après dogfood OK).

---

## Pings prévus (jalons)

plan prêt → tests RED prêts → backend GREEN → frontend GREEN → PR CI verte.
