<!-- Arenet spec — AreNET Allowlist UI (#364). AGPL-3.0. © 2026 The Arenet Authors. -->

# Spec — AreNET Allowlist UI (#364)

- **Issue**: #364
- **Target release**: v2.85.0 (minor — grosse feature)
- **Architecture**: Option A — AreNET-native (aucune dépendance CrowdSec write API)
- **Date**: 2026-11-23
- **Statut**: SPEC — en attente de GO opérateur avant plan + implémentation
- **Chantier amont**: v2.84.5 (bump CrowdSec v1.8.1 + Caddy v2.11.9) dogfoodée OK le 2026-11-23

---

## 1. Problème & contexte

La Security Automation d'AreNET pousse des décisions de ban vers la LAPI CrowdSec
(`origin=arenet`, scénarios `arenet/*`) quand un vecteur franchit un seuil WAF /
throttle / auth. Aujourd'hui **aucun moyen d'exempter une IP de confiance** (sonde
uptime, IP de bureau, scanner interne, monitoring) d'être bannie par cette
automation : si le monitoring déclenche une règle WAF, il se fait bannir.

Objectif : une **allowlist native AreNET** qui fait que le trigger Security
Automation **n'émet jamais d'intent** pour une IP exemptée, avec une portée
paramétrable par catégorie.

**Pourquoi Option A (AreNET-native) et pas CrowdSec** : décision déjà prise et
re-validée empiriquement (voir mémoire `crowdsec-upgrade-blocked-by-bouncer`). Le
**write** API allowlist de CrowdSec (PR crowdsec#4843) est **toujours ouvert /
non-publié** et son accès est `trusted_ips`-gated (pas un token watcher). Une
allowlist « source de vérité CrowdSec » n'est donc **pas constructible** en
release. On garde l'enforcement 100 % côté AreNET, dans le trigger.

---

## 2. Non-goals

- **Pas** d'exemption des décisions CrowdSec natives / Community Blocklist / bans
  `cscli`. L'allowlist AreNET ne couvre QUE les bans d'origine `arenet`
  (automation). Limitation documentée explicitement (§8).
- **Pas** de write vers la LAPI CrowdSec (API inexistante en release).
- **Pas** de presets built-in (localhost / RFC1918 / monitors). L'utilisateur crée
  tout à la main.
- **Pas** de modification du bouncer, du WAF Coraza, du rate-limit, ni du data
  plane Caddy. L'allowlist agit en amont de l'émission d'intent, point final.
- **Pas** de dédup inter-hôtes / cluster (hors scope, cf. `crowdsec-three-parts`).

---

## 3. Décisions de design (verrouillées par l'opérateur)

| ID | Décision | Valeur |
|----|----------|--------|
| D1 | Placement UI | Sidebar → Sécurité → **Allowlists**, nouvel item plat près de WAF (`Sidebar.svelte:131-137`) |
| D2 | Presets built-in | **Aucun** — création manuelle intégrale |
| D3 | Portée par catégorie | 3 cases par allowlist : **block / throttle / audit**, toutes cochées par défaut |
| D4 | Mapping scénarios → catégories | `block`=`arenet/waf-*` · `throttle`=`arenet/throttle-tier*` · `audit`=`arenet/auth-*` |
| D5 | Architecture | Option A — store SQLite AreNET + enforcement dans le trigger, **zéro dépendance CrowdSec** |
| D6 | Log de skip | INFO `automation: ban skipped (allowlisted)` |
| D7 | Route frontend | `/security/allowlists` (SvelteKit) |
| D8 | Target | v2.85.0 |

### Décisions à trancher par l'opérateur (sign-off sur cette spec)

| ID | Question | Recommandation | Alternative |
|----|----------|----------------|-------------|
| **D-STORE** | Où vit le SQLite ? | **Nouveau fichier dédié `security.db` + package `internal/allowlist`** (store + migrate, calqués sur `internal/observability/storage.go`). Raison : les allowlists sont de la **config durable**, elles ne doivent PAS vivre dans `metrics.db` qui est purgé par rétention et rebâti en mode dégradé (`observability` « log + continue » en cas de corruption → on perdrait les allowlists silencieusement). | Réutiliser `metrics.db` avec 2 tables jamais touchées par la boucle de rétention (plus léger, mais couple la config à la télémétrie). |
| **D-BACKUP** | Backup/restore des allowlists | **Inclure `security.db` dans l'export/import `internal/backup`** (CLAUDE.md Lesson 8 : schéma géré sur les 2 axes). Pas de sentinelle secret nécessaire (aucun secret). | Hors backup pour v2.85.0, noté en dette. |
| **D-SLUG** | « Nom = slug validé » (scope frontend) | Nom libre affiché + **slug dérivé** (`[a-z0-9-]`, unique) comme clé stable, pour déep-link / logs futurs. | Nom libre unique seul, pas de slug. |
| **D-DEGRADED** | Si `security.db` illisible au boot | **Fail-safe strict : allowlist vide** (aucune exemption) + log WARN. Mieux vaut ne bannir personne par erreur que bannir une IP de confiance ? NON — fail-safe = on protège, donc on **ban quand même** (allowlist vide), jamais l'inverse. | Abort boot (trop agressif pour une feature annexe). |

---

## 4. Architecture backend

### 4.1 Store (`internal/allowlist`, nouveau package — cf. D-STORE)

Calqué sur `internal/observability/storage.go` : driver `modernc.org/sqlite`, DSN
`file:security.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)`,
`SetMaxOpenConns(1)`, `schema_version` + migrate chain idempotente
(`CREATE TABLE IF NOT EXISTS`).

```
CREATE TABLE allowlist (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  slug         TEXT    NOT NULL UNIQUE,         -- D-SLUG
  name         TEXT    NOT NULL,
  description  TEXT    NOT NULL DEFAULT '',
  enabled      INTEGER NOT NULL DEFAULT 1,      -- 0/1
  scope_block     INTEGER NOT NULL DEFAULT 1,
  scope_throttle  INTEGER NOT NULL DEFAULT 1,
  scope_audit     INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT NOT NULL,                   -- RFC3339
  updated_at   TEXT NOT NULL
);
CREATE TABLE allowlist_entry (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  allowlist_id INTEGER NOT NULL REFERENCES allowlist(id) ON DELETE CASCADE,
  cidr_or_ip   TEXT    NOT NULL,                -- normalisé CIDR (IP → /32 ou /128)
  note         TEXT    NOT NULL DEFAULT '',
  created_at   TEXT    NOT NULL
);
CREATE INDEX idx_entry_allowlist ON allowlist_entry(allowlist_id);
```

Validation serveur stricte : chaque `cidr_or_ip` parsé via `net/netip`
(`ParsePrefix` ; une IP nue → `/32` IPv4 ou `/128` IPv6). Rejet des entrées
invalides au niveau API avec message par ligne.

### 4.2 Résolution rapide en mémoire (hot path)

Le trigger lit l'allowlist **une fois par intent candidat** ; il faut un accès
**lock-free**. Pattern déjà présent dans le repo : `RuleSetHolder`
(`trigger.go:243-260`, `atomic.Pointer` swap).

- `internal/allowlist.Resolver` détient un `atomic.Pointer[resolvedSet]`.
- `resolvedSet` = structure immuable : liste de `netip.Prefix` par catégorie
  (`block` / `throttle` / `audit`), ne contenant que les entrées des allowlists
  **actives** dont le scope couvre la catégorie.
- `Resolver.Lookup(ip netip.Addr, cat Category) bool` : balaye les prefixes de la
  catégorie (O(n), n petit en homelab ; si besoin plus tard, bascule sur un
  `netipx.IPSet`/trie — noté, pas v2.85.0).
- Reconstruction (`Rebuild()`) sur **toute mutation CRUD** (create/update/delete
  d'allowlist ou d'entrée, toggle actif) et au boot. Swap atomique du pointeur.

### 4.3 Hook dans le trigger (`internal/automation`)

Découplage strict pour tenir **G_allowlist_no_crowdsec_dep** : le package
`automation` n'importe **ni** `crowdsec` **ni** `allowlist`. On injecte une
interface, comme `DedupeChecker` (`trigger.go:117-134`) :

```go
// AllowlistChecker reports whether srcIP is exempt from auto-ban
// for the given category. Nil checker ⇒ no exemptions.
type AllowlistChecker interface {
    IsAllowlisted(srcIP string, cat Category) bool
}
```

`Category` : nouveau type dans `automation` (block/throttle/audit). Dérivation
depuis `Source` via une méthode `Source.Category() Category` dans `rules.go`
(mapping D4 : préfixe `waf-`→block, `throttle-`→throttle, `auth-`→audit).

**Point d'insertion** : `trigger.go:533`, immédiatement après
`scenario := k.Source.Scenario()` et **avant** le check cooldown (le plus tôt
possible — une IP exemptée ne doit déclencher aucune machinerie) :

```go
scenario := k.Source.Scenario()

if e.cfg.AllowlistChecker != nil &&
   e.cfg.AllowlistChecker.IsAllowlisted(k.SrcIP, k.Source.Category()) {
    e.cfg.Logger.Info("automation: ban skipped (allowlisted)",
        "src_ip", k.SrcIP, "scenario", scenario)
    continue
}
```

Wiring : adapter dans `cmd/arenet` (comme `automation_adapters.go` pour
`HasActiveDecision`) qui branche `allowlist.Resolver` sur l'interface. Le trigger
reste testable avec un fake checker → **aucun** import crowdsec dans le test.

### 4.4 API REST (`internal/api`)

CRUD standard, monté dans `routes.go`. Lecture viewer, écriture admin (comme
`/settings/automation/*`). Chaque route documentée dans
`internal/api/openapi/*.yaml` avec `x-arenet-role` (cf. mémoire
`openapi-route-must-be-documented`, sinon `openapi_test` casse).

| Méthode | Route | Rôle | Effet |
|---------|-------|------|-------|
| GET | `/security/allowlists` | viewer | liste (avec count + aperçu entrées + scope) |
| GET | `/security/allowlists/{slug}` | viewer | détail + entrées |
| POST | `/security/allowlists` | admin | créer (nom, desc, scope, entrées) → `Rebuild()` |
| PUT | `/security/allowlists/{slug}` | admin | éditer → `Rebuild()` |
| DELETE | `/security/allowlists/{slug}` | admin | supprimer (cascade entrées) → `Rebuild()` |

Toute mutation émet un événement **audit** (`internal/audit`, comme les autres
changements de config sécurité) et déclenche `Resolver.Rebuild()`.

Chaque endpoint reçoit un **test wire** (JSON littéral) — cf. mémoire
`test-the-wire-not-the-struct`.

---

## 5. Architecture frontend

### 5.1 Route & sidebar

- Nouveau item sidebar section Sécurité : `{ href: '/security/allowlists',
  labelKey: 'sidebar.navAllowlists', icon: 'allowlist' }`, placé juste après WAF.
- Clé i18n `sidebar.navAllowlists` en **FR + EN** (parité `index.test.ts`).
- Page `web/frontend/src/routes/security/allowlists/+page.svelte`.
- Module API `web/frontend/src/lib/api/allowlists.ts` (client centralisé).

### 5.2 Page liste

Table : **Nom** | **Entrées** (count + aperçu 2-3 CIDR) | **Portée** (badges
block/throttle/audit) | **Actif** (toggle) | **Dernière édition** | **Actions**
(éditer / supprimer).

- **État vide** : message explicatif (« Aucune allowlist. Créez-en une pour
  exempter des IP de confiance des bans automatiques AreNET. ») + rappel de la
  limitation origin=arenet.
- **Suppression** : confirmation (pas de `confirm()` natif — modal in-app).

### 5.3 Formulaire création / édition

- **Nom** (→ slug validé, D-SLUG), **Description** libre.
- **Textarea entrées** : une IP/CIDR par ligne, **validation live** (parse
  `netip`-équivalent côté client, marque les lignes invalides ; la validation
  serveur reste l'autorité).
- **3 checkboxes Portée** (block / throttle / audit) — toutes cochées par défaut.
- **Toggle Actif**.

Tout texte via i18n FR + EN. ARIA labels sur les contrôles.

---

## 6. Mapping scénarios → catégories (D4, source de vérité)

| Catégorie (checkbox) | Sources `automation` | Scénarios LAPI |
|----------------------|----------------------|----------------|
| **block** | `waf-sqli`, `waf-xss`, `waf-rce`, `waf-lfi`, `waf-protocol`, `waf-other` | `arenet/waf-*` |
| **throttle** | `throttle-tier1`, `throttle-tier2` | `arenet/throttle-tier*` |
| **audit** | `auth-burst` | `arenet/auth-burst` |

`Source.Category()` est l'implémentation unique de ce mapping (testée).

---

## 7. Guards (tests, RED d'abord — skill `guard`)

| Guard | Scénario | Attendu |
|-------|----------|---------|
| **G_allowlist_match** | IP allowlistée active, scope couvre la catégorie du scénario | **skip** intent + log INFO `ban skipped (allowlisted)` |
| **G_allowlist_scope** | IP allowlistée **block only**, intent de catégorie **throttle** | **PAS** de skip (intent émis) |
| **G_allowlist_inactive** | Allowlist marquée **inactive** | skip ignoré (intent émis) |
| **G_allowlist_cidr_match** | IP dans un **CIDR** allowlisté (pas IP exacte) | **skip** |
| **G_allowlist_no_crowdsec_dep** | — | le test du trigger utilise un **fake** `AllowlistChecker` ; aucun import `crowdsec` ni `allowlist` dans `automation` (vérifiable par `go list -deps`) |

Guards additionnels recommandés (non demandés, mais la spec les pose) :

| Guard | Scénario | Attendu |
|-------|----------|---------|
| G_allowlist_category_map | `Source.Category()` sur les 9 sources | mapping D4 exact (table pinnée) |
| G_allowlist_cidr_validation | entrées invalides (`300.1.1.1`, `10.0.0.0/33`, texte) | rejet API par ligne |
| G_allowlist_rebuild_on_mutation | CRUD → `Resolver` reflète le changement | nouveau set actif après swap |
| G_allowlist_wire | GET/POST JSON littéral | shape camelCase conforme |
| G_allowlist_degraded | `security.db` illisible (D-DEGRADED) | set vide + WARN, trigger ban normalement |

Le hook trigger touche l'émission d'intent : **golden/non-régression** — un
trigger **sans** `AllowlistChecker` (nil) doit produire un comportement
**byte-identique** à v2.84.5 (aucun intent perdu). Assertion explicite.

---

## 8. Limitation à documenter (doc opérateur)

Texte verbatim à placer dans l'UI (état vide + aide formulaire) **et** la doc
opérateur (`docs/operations/` + wiki-seed) :

> **AreNET Allowlist couvre uniquement les bans émis par AreNET Security
> Automation (`origin=arenet`).** Pour exempter une IP des décisions CrowdSec
> natives, de la Community Blocklist ou des bans ajoutés via `cscli`, utilisez
> `cscli allowlist` côté CrowdSec.

---

## 9. Backup / migration (D-BACKUP, CLAUDE.md Lesson 8)

- `internal/backup` export/import étendu pour `security.db` (aucun secret →
  pas de sentinelle). Test round-trip.
- Migration boot idempotente via le `schema_version` du nouveau store. Fresh
  install : tables vides, zéro exemption, comportement identique à aujourd'hui.

---

## 10. Livrables (après GO spec)

1. Plan d'implémentation (`docs/superpowers/plans/2026-11-23-allowlist-ui.md`).
2. Tests G_* en **RED** d'abord.
3. Backend : package `internal/allowlist` (store + resolver), `Source.Category()`,
   interface `AllowlistChecker` + hook trigger, adapter `cmd/arenet`, API + openapi.
4. Frontend : page, module API, sidebar, i18n FR+EN.
5. Doc : smoke (`docs/smoke-test-allowlist.md`), doc utilisateur (créer une
   allowlist), doc opérateur (limitation origin=arenet), wiki-seed.
6. PR unique (plusieurs commits logiques), CI verte.
7. Dogfood AreNET-test en v2.85.0.
8. Après merge : fermer #364 avec commentaire (PR + release).

**Bascule prod** : srv2009298 reste en v2.82.0 ; bascule unique sur **v2.85.0**
(avec #364), faite ensemble après validation. Pas de bascule sur v2.84.5.

---

## 11. Validation empirique (gates)

- `go build ./... && go vet ./... && go test -race ./...` verts.
- `go list -deps ./internal/automation` ne contient **ni** crowdsec **ni**
  allowlist (G_allowlist_no_crowdsec_dep mécanisé).
- `caddy.Validate` : N/A (aucun JSON Caddy nouveau — l'allowlist ne touche pas le
  data plane).
- Frontend `npm run check && npm test` verts, parité i18n OK.
- Dogfood : burst RCE depuis une IP allowlistée (scope block) → **aucun** ban
  `arenet/waf-rce`, log INFO `ban skipped (allowlisted)` ; même burst depuis une
  IP non-allowlistée → ban normal (non-régression du pipeline v2.84.5).
