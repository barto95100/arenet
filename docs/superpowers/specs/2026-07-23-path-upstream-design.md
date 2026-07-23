# Upstream par PATH (path-based routing) — Design

**Status:** brainstormé avec l'opérateur 2026-07-23, 5 décisions verrouillées.
Branche `feature/path-upstream`. Version cible **v2.23.0** (minor — nouvelle
feature). Fait suite au path-based-rules v1 (v2.21.0, PR#51) qui était
protection-only.

**One-line:** Une `PathRule` cesse d'être *protection-only* et devient
*routage + protection* : elle gagne un **pool d'upstreams optionnel** ; quand
il est présent, les requêtes qui matchent ce path sont proxyfiées vers **ce**
pool au lieu du pool de la route. Équivalent NGINX `location { proxy_pass }` /
Traefik path-router-with-service.

## Décisions (Q1–Q5)

| # | Décision | Pourquoi |
|---|----------|----------|
| Q1 | Un path-rule gagne un **pool d'upstreams** (URLs+poids) + **health-check propre** + **politique LB propre**. Pas d'UI transport TLS. | Un `/api/v1/*` vers 2 backends API = cas canonique du path-routing. Dans Caddy le HC et le LB vivent DANS le `reverse_proxy` du pool → un pool propre a mécaniquement son HC/LB propre. Le transport n'est pas un réglage cosmétique mais déduit du schéma d'URL → pas d'UI, mais logique d'émission à gérer. |
| Q2 | Le schéma (`http`/`https`) d'un pool de path est **indépendant** de celui de la route ; transport **déduit par pool**. | Rend la feature réellement utile pour des backends hétérogènes (route `http://` interne, `/legacy → https://vieux-service`). |
| Q3 | Une path-rule est **valide si elle déclare au moins UN** de {basic-auth, IP-filter actif, upstream non-vide}. | L'upstream compte comme "contenu" : le routage pur (`/v1/* → backend-A` sans protection) est un cas de première classe. Élargit la validation v1 "must declare at least one protection" ([[path_rule_empty_500]]). |
| Q4 | Le proxy d'un path **réutilise le `handle_response` de branding de la route** (même page d'erreur brandée partout). | L'opérateur ne veut pas une page d'erreur brute sur `/v1` et brandée sur `/api`. Coût technique faible : on factorise la construction du `handle_response`. |
| Q5 | UI = **disclosure "Upstream spécifique (optionnel)" repliée par défaut**, qui **réutilise le composant pool existant de la route** (A+C). Badge `→ N backends` sur la carte repliée. | Carte compacte tant que l'opérateur ne s'en sert pas ; zéro nouveau composant de saisie ; le badge donne la lisibilité d'un coup d'œil. |

## 1. Modèle

`PathRule` devient routage+protection. Pool absent (défaut) → comportement v1
strictement inchangé (la règle suit l'upstream de la route). Pool présent → les
requêtes du path vont vers ce pool.

## 2. Storage — `PathRule` étendu

Ajout de **3 champs optionnels** à `PathRule` (`internal/storage/routes.go:99`),
tous `omitempty` → migration-free, un config sans upstream-par-path reste
byte-identique à v2.22.0 :

```go
type PathRule struct {
    PathPrefix  string                `json:"path_prefix"`
    BasicAuth   *BasicAuthRouteConfig `json:"basic_auth,omitempty"`
    IPFilter    *IPFilter             `json:"ip_filter,omitempty"`
    // NOUVEAU (v2.23.0) :
    Upstreams   []Upstream            `json:"upstreams,omitempty"`    // pool propre ; vide = hérite de la route
    LBPolicy    string                `json:"lb_policy,omitempty"`    // défaut round_robin si pool non-vide
    HealthCheck *HealthCheckConfig    `json:"health_check,omitempty"` // HC propre au pool du path
}
```

**Réutilise les types existants** `Upstream` (routes.go:187) et
`HealthCheckConfig` — zéro nouveau type, cohérence totale avec le pool de la
route.

**Validation** (`PathRule.Validate`, routes.go:124) :
- Valide si **au moins un** de {BasicAuth, IPFilter actif, Upstreams non-vide} (Q3).
- Si `Upstreams` non-vide : chaque URL valide + **même-schéma-dans-le-pool**
  (réutilise `validateSameSchemePool`, routes.go:741) ; le schéma du path est
  **indépendant** de la route (Q2).
- `LBPolicy` défaut `round_robin` quand pool non-vide ; ignoré/nettoyé si pool vide.
- `HealthCheck` renseigné sans pool → champ mort, nettoyé.

**Wire API** ([[route_wire_field_gap_regression]]) : les 3 champs doivent
traverser les 4 points du mapping du sous-objet path-rule — request struct,
create-map, update-map, response — sinon 400 "unknown field". C'est le mapping
du sous-objet path-rule qu'on étend, pas le `routeRequest` racine.

## 3. Émission Caddy (cœur)

**Problème actuel :** la construction du `proxyHandler` (upstreams → transport
déduit du schéma → LB → health-check → `handle_response` branding) est un bloc
monolithique inline dans `buildConfigJSON` (`manager.go` ~1254–1630). Chaque
path-rule réutilise ce `proxyHandler` unique.

**Refacto :** extraire cette construction en une fonction réutilisable :

```go
// buildReverseProxyHandler assemble un handler reverse_proxy complet pour un
// pool donné : upstreams + transport (déduit du schéma) + LB + HC + le
// handle_response de branding partagé.
func buildReverseProxyHandler(
    pool []storage.Upstream,
    lbPolicy string,
    hc *storage.HealthCheckConfig,
    sharedHandleResponse []map[string]any,
) (map[string]any, error)
```

Le bloc monolithique actuel (`manager.go` ~1312–1630) assemble, dans l'ordre :
`upstreams` (dial de chaque URL), `load_balancing.selection_policy` (+ `weights`
si `weighted_round_robin`), préservation du Host header client, `transport` si
schéma `https://`, `flush_interval:-1` pour le streaming, `health_checks`
actif/passif, puis `handle_response` de branding. Le plan d'implémentation
extraira la liste exacte des paramètres à partir de ce bloc ; ce qui est
INVARIANT entre route et path (host header, flush, branding) est partagé, ce qui
est PAR POOL (upstreams, LB, transport, HC) devient paramètre.

- La route appelle ça avec son pool → `proxyHandler(route)` (identique).
- Chaque path-rule avec `Upstreams` non-vide appelle ça avec **son** pool →
  `proxyHandler(path)`.
- Le `handle_response` de branding (Q4) est construit **une fois** et
  **partagé** en argument → même page d'erreur brandée partout.
- Le **transport TLS est déduit par pool** (Q2) : si les URLs du path sont
  `https://`, ce proxy émet son `transport:{tls:{}}`, indépendamment de la route.

`buildPathRulesSubroute` (`path_rules_emit.go:65`) change : au lieu de toujours
appender le `proxyHandler` partagé, chaque règle appende **son** proxy si elle a
un pool, sinon celui de la route :

```go
handle = append(handle, resolveProxyForRule(pr, routeProxy)) // pr.Upstreams vide → routeProxy
```

Le catch-all final garde `routeProxy` (paths sans règle → upstream de la route).

**Ordre interne préservé** (v1) : `[IP-block?] → [basic-auth?] → proxy(path|route)`.
Une règle routage-pur (upstream sans protection) → route interne = `[proxy(path)]` seul.

### 3.1 Garde de non-régression byte-identité (NON-NÉGOCIABLE)

La refacto touche le chemin d'émission par lequel passe **100 % du trafic de
chaque route**, y compris les routes qui n'utilisent jamais d'upstream-par-path.
Contrat : **une route sans upstream-par-path doit produire un JSON Caddy
byte-identique à v2.22.0.**

Test dédié : un jeu de routes représentatif *sans* upstream-par-path → JSON émis
par le code factorisé comparé **octet pour octet** à la sortie de référence.
Tant que ce test passe, la refacto n'a rien cassé pour l'existant. Même
discipline que le "0 path-rule = config byte-identique" de v1, appliquée à la
refacto elle-même.

### 3.2 Piège du data-race ([[caddymgr_race_test_gate]])

Cette feature reproduit exactement le combo qui a fait rougir la CI en v1 : une
subroute imbriquée (path-rule) contenant maintenant **son propre `reverse_proxy`
avec health-check actif**. Le race est INTERNE à Caddy v2.11.3
(`doActiveHealthCheck` goroutine × `Subroute.Provision`), pas dans notre code.

Contraintes fermes :
1. `go test -race ./internal/caddymgr/` **obligatoire avant PR** (la CI le lance).
2. Dans le fixture canonique `TestBuildConfigJSON_LoadsCleanly` (un seul
   `caddy.Validate` par package — ne jamais en ajouter un 2e), **ne pas** mettre
   un HC-actif-par-path sur la route qui a déjà des subroutes lourdes — garder
   séparé, comme le fix 1b93a96 de v1.

## 4. UI/UX — disclosure "Upstream spécifique"

Dans chaque carte path-rule (`PathRulesSection.svelte`), sous les toggles
IP-filter et basic-auth existants, une section repliée par défaut :

```
▸ Upstream spécifique (optionnel)          ← FERMÉ par défaut, chevron
```

**Ajustement Q5-C (constaté à l'écriture du plan) :** le pool d'upstreams de la
route N'EST PAS un composant réutilisable — il est inline dans
`routes/+page.svelte` (~500 lignes) et couplé à la machinerie de test d'upstream
(bouton "Tester", état par index, API `testUpstream`) propre à la route. Décision
opérateur : construire des **champs légers dans `PathRulesSection.svelte`**
(URL+poids repeater + select LB + toggle health-check) qui calquent la FORME du
pool route SANS la machinerie de test d'upstream. Bénéfice : l'éditeur de route
reste intact (zéro régression sur le chemin critique 100%-trafic), et le
composant path-rule reste autonome. (Pas d'extraction d'un composant partagé —
ce serait un gros refactor de l'éditeur de route avec son propre risque.)

Déplié — champs upstream **inline dans `PathRulesSection.svelte`** (URLs+poids,
sélecteur LB, toggle health-check), calqués sur la forme du pool route :

```
▾ Upstream spécifique (optionnel)
   Par défaut, ce path suit l'upstream de la route.
   [ URL backend ............ ] Poids [ 1 ] [✕]
   [+ Ajouter un backend]
   Politique LB : (round_robin | least_conn | …)
   ☐ Health-check actif (path, interval, …)
```

**Comportement :**
- Fermé / pool vide = la règle hérite de la route (défaut v1). Badge "hérité"
  optionnel quand vide.
- Déplié avec ≥1 URL = routage vers ce pool. **Badge `→ N backends`** sur la
  carte repliée pour la lisibilité d'un coup d'œil.
- `sanitizePathRules` (frontend) compte un pool non-vide comme "contenu" (Q3) :
  une règle avec juste un upstream n'est plus droppée comme "morte".
- **i18n EN+FR** : nouvelles clés (label disclosure, hint "suit l'upstream de la
  route", badge "hérité"/"→ N backends"). Parité EN/FR obligatoire (garde i18n).
- **Garde-fou UX (repris de v1) :** pool avec URLs invalides + aucune protection
  → 400 backend explicite (pas 500). Le frontend valide les URLs avant envoi et
  affiche l'erreur dans la carte, comme le pool de la route.

## 5. Tests & process

**Backend (caddymgr) :**
- **Byte-identité (§3.1)** : routes sans upstream-par-path → JSON == référence
  v2.22.0, octet pour octet.
- `buildReverseProxyHandler` isolé : pool mono/multi, transport `http` vs
  `https`, LB policy, HC présent/absent, `handle_response` partagé réappliqué.
- Émission path-rule avec upstream : proxy du path a le bon pool ; règle sans
  upstream → catch-all + route interne utilisent le proxy de la route ; règle
  routage-pur → route interne = `[proxy(path)]` seul.
- Transport hétérogène : route `http://` + path `https://` → chaque proxy porte
  son propre transport (Q2).
- `caddy.Validate` : path-rule-avec-upstream passe la validation, **sans**
  HC-actif-par-path sur une route déjà subroute-lourde (§3.2).
- `go test -race ./internal/caddymgr/` **avant PR**.

**Storage :**
- `PathRule.Validate` : valide avec upstream seul / rejette la règle 100%-vide /
  rejette pool multi-schéma / accepte schéma path ≠ route.
- Wire round-trip : les 3 champs traversent create/update/response.

**Frontend :**
- `sanitizePathRules` : pool non-vide = contenu (pas droppé) ; pool + LB/HC mais
  préfixe supprimé = nettoyé.
- `PathRulesSection` : disclosure replié par défaut, badge `→ N backends` quand
  pool non-vide, hint "hérité" quand vide.

**Process :** FULL subagent-driven (comme v1). Ordre : storage → wire → **refacto
émission** (revue DÉDIÉE opus — chemin critique + garde byte-identité) →
path-rule upstream émission (revue DÉDIÉE opus — transport-par-pool +
handle_response partagé + fail-closed IP-filter préservé) → UI → i18n.
**Smoke live obligatoire** (comme les 7/7 de v1) : router `/v1→A`, `/api→route`,
vérifier le branding d'erreur sur les deux, qu'un backend `https` sur path
fonctionne. Revue finale opus whole-branch.

**Version :** v2.23.0 (minor). Tag après go opérateur.

## Non concerné (YAGNI / backlog)
- Pas d'UI transport TLS (déduit du schéma).
- Forward-auth per path, WAF/rate-limit per path → backlog séparé
  ([[path_based_rules_v1_shipped]] v2 backlog).
- `trusted_proxies` plumbing pour filtrage XFF → backlog indépendant.
