<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Fournisseurs DNS multi-types (DNS-01) — Design

**Status:** brainstormé avec l'opérateur 2026-09-21, décisions verrouillées.
Branche `feature/dns-providers-multi-type`. Version cible **v2.26.0** (minor).
Première brique de la « vague 1 » issue de l'analyse concurrentielle
(CaddyUI : 8 fournisseurs, Caddy Proxy Manager : ~18 ; Arenet : OVH seul).

**One-line:** Passer d'un modèle DNS-provider câblé OVH (3 champs secrets à
plat) à un **registre de types** + une **map de credentials générique**, et
livrer 9 types : OVH (existant) + Cloudflare, Hetzner, DigitalOcean, Porkbun,
Gandi, Scaleway, Infomaniak, Route53 — avec un **bouton « Tester la
connexion »** pour que l'utilisateur valide lui-même ses identifiants.

## Contrainte structurante : l'opérateur ne peut tester qu'OVH

L'opérateur n'a de compte que chez OVH. Aucun smoke test réel n'est possible
pour les 8 nouveaux types. Conséquences de design :

1. **La justesse des noms de champs est prouvée par test automatisé**, pas par
   smoke : `caddy.Validate()` provisionne le module DNS et **rejette tout champ
   inconnu** (vérifié, voir §Faits empiriques #3). Un test qui remplit chaque
   entrée du registre et passe `caddy.Validate()` garantit la cohérence
   registre ↔ module upstream.
2. **Le bouton « Tester la connexion »** donne à l'utilisateur final un retour
   immédiat sur ses identifiants (lecture seule), ce qui compense l'absence de
   smoke mainteneur.
3. Documentation : OVH = chemin de référence testé ; les autres types sont
   marqués « validés automatiquement, non testés en réel par le mainteneur ».

## Décisions

| # | Décision | Pourquoi |
|---|----------|----------|
| Q1 | **9 types** : ovh, cloudflare, hetzner, digitalocean, porkbun, gandi, scaleway, infomaniak, route53. | Couvre le homelab mondial (Cloudflare, Hetzner, DO, Porkbun), l'Europe/France (Gandi, Scaleway, Infomaniak, OVH) et l'entreprise (Route53). |
| Q2 | **Map générique + registre** : `DNSProviderConfig.Credentials map[string]string` ; un registre Go décrit chaque type (champs, secret ou non, requis, enum, défaut). | Ajouter un type = 1 entrée de registre + 1 import. Backup/sentinelles/redaction deviennent génériques (itération sur les champs `secret`). |
| Q3 | **Formulaire piloté par le backend** : `GET /settings/dns-providers/types` expose le registre ; le frontend génère les champs. | Une seule source de vérité. |
| Q4 | **Test de connexion dans ce lot** : `POST /settings/dns-providers/{id}/test`. | Compense l'impossibilité de smoke mainteneur. |

## Faits empiriques vérifiés (2026-09-21)

Sonde temporaire dans `internal/caddymgr` (supprimée), Caddy v2.11.4 :

1. **Compatibilité** : les 8 modules s'ajoutent sans conflit ; tous sont sur
   libdns v1.x (comme `libdns/ovh` actuel). `caddy-dns/scaleway@v0.2.2` exige
   Caddy **v2.11.4** → bump patch de v2.11.3 (le `go get` le fait). Route53
   tire le SDK AWS v2 (déjà présent en indirect, montée de versions mineures).
2. **Champs JSON** (lus dans le source upstream `type Provider struct`) :

   | Type | Module | Champs (★ = secret) |
   |---|---|---|
   | ovh | `caddy-dns/ovh@v1.1.0` | `endpoint` (enum), ★`application_key`, ★`application_secret`, ★`consumer_key` |
   | cloudflare | `caddy-dns/cloudflare@v0.2.4` → `libdns/cloudflare@v0.2.2` | ★`api_token` (requis), ★`zone_token` (optionnel) |
   | hetzner | `caddy-dns/hetzner/v2@v2.0.1` → `libdns/hetzner/v2` | ★`api_token` (token **Hetzner Cloud**, la v2 utilise la nouvelle API DNS Cloud) |
   | digitalocean | `caddy-dns/digitalocean@v0.0.0-20250606074528` | ★`auth_token` |
   | porkbun | `caddy-dns/porkbun@v0.3.1` → `libdns/porkbun@v1.0.1` | ★`api_key`, ★`api_secret_key` |
   | gandi | `caddy-dns/gandi@v1.1.0` | ★`bearer_token` (Personal Access Token) |
   | scaleway | `caddy-dns/scaleway@v0.2.2` → `libdns/scaleway@v0.3.1` | ★`secret_key`, `organization_id` |
   | infomaniak | `caddy-dns/infomaniak@v1.0.2` | ★`api_token` |
   | route53 | `caddy-dns/route53@v1.6.2` | `region`, `access_key_id`, ★`secret_access_key`, `hosted_zone_id` (optionnel) |

3. **`caddy.Validate()` provisionne le provider DNS et décode en strict** :
   un champ mal orthographié (`api_tokn`) → `json: unknown field "api_tokn"` ;
   un token Cloudflare mal formé → erreur de Provision. Les 9 types passent
   `Validate` avec des valeurs factices bien formées.
4. **Les 9 modules implémentent `libdns.RecordGetter`** après
   `caddy.GetModule(...).New()` + `json.Unmarshal` + `Provision` → le test de
   connexion peut instancier le module Caddy lui-même, sans importer les
   packages libdns individuellement. Cloudflare et Hetzner implémentent aussi
   `libdns.ZoneLister` (non utilisé en v1).
5. **⚠️ Fuite de secret** : le `Provision` Cloudflare renvoie
   `API token '<TOKEN EN CLAIR>' appears invalid…`
   (`caddy-dns/cloudflare@v0.2.4/cloudflare.go`, fonction `Provision`). Cette
   erreur remonte à travers `caddy.Load` → `ReloadFromStore` →
   `h.logger.Error("caddy reload…", "err", err)` (`internal/api/routes.go:1525`,
   `:2077`) → **journald**. Doit être redacted (§4).
6. **Placeholders** : tous les `Provision` appliquent `caddy.NewReplacer()` aux
   credentials (`{env.X}`, `{file.X}`). Comportement identique à OVH
   aujourd'hui ; conservé (permet `{env.CF_API_TOKEN}`), documenté. Seul un
   admin peut écrire ces valeurs.

## 1. Modèle de données (storage)

```go
type DNSProviderConfig struct {
    ID          string            `json:"id"`
    Label       string            `json:"label"`
    Type        string            `json:"type"`
    Credentials map[string]string `json:"credentials"`
}
```

- Les champs à plat `Endpoint`, `ApplicationKey`, `ApplicationSecret`,
  `ConsumerKey` **disparaissent** de la struct.
- **Rétro-compat de décodage** : `DNSProviderConfig.UnmarshalJSON` replie les
  anciennes clés `endpoint` / `application_key` / `application_secret` /
  `consumer_key` dans `Credentials` quand elles sont présentes et que
  `Credentials` ne contient pas déjà la clé. Couvre en un seul point : les
  lignes BoltDB existantes, **les anciens fichiers de backup**, et la
  migration legacy singleton (`dns_provider_migration.go`).
- **Migration au boot** `migrateDNSProviderCredentialsMap` : réécrit chaque
  ligne au nouveau format (idempotente ; une ligne déjà au nouveau format est
  réécrite à l'identique). Type vide → `ovh` (comportement actuel de
  `CreateDNSProvider`).
- `validate()` devient piloté par le registre : type connu, chaque champ
  `required` non vide, valeurs d'enum valides, **aucune clé inconnue** dans
  `Credentials` (miroir du décodage strict de Caddy — une clé inconnue ferait
  échouer `caddy.Load`).
- `UpdateDNSProvider` : preserve-on-edit générique — pour chaque champ
  `secret` du type, valeur vide = on garde l'existant. **Si le type change**,
  aucun secret n'est préservé (les clés ne correspondent plus).

## 2. Registre (`internal/storage/dns_provider_types.go`)

```go
type DNSProviderField struct {
    Key      string   // clé JSON Caddy, ex. "api_token"
    Label    string   // libellé EN par défaut (le frontend traduit par clé i18n)
    Secret   bool     // jamais renvoyé par l'API, redacted en audit/backup/logs
    Required bool
    Enum     []string // optionnel (OVH endpoint)
    Default  string   // optionnel
}

type DNSProviderType struct {
    Type    string // "cloudflare" == suffixe du module dns.providers.<Type>
    Label   string // "Cloudflare"
    DocsURL string // page de création du token chez le fournisseur
    Fields  []DNSProviderField
}
```

- Vit dans `storage` (validate en dépend) ; exporté pour `api` et `caddymgr`.
- `DNSProviderTypeByName(t) (DNSProviderType, bool)`, `DNSProviderTypesList()`
  (ordre stable : OVH puis alphabétique).
- Helpers : `ProviderConfigured(c) bool` (tous les `Required` non vides —
  remplace `dnsProviderConfigured` caddymgr, `dnsProviderComplete` api, et la
  boucle de `cmd/arenet/main.go:1936`) ; `SecretValues(c) []string`
  (pour la redaction).

## 3. Émission Caddy (`caddymgr`)

`buildACMEPolicy` : `provider = {"name": c.Type} ∪ Credentials` (clés non
vides uniquement — un champ optionnel vide n'est pas émis). Le JSON émis pour
une config OVH existante reste **identique octet pour octet**
(non-régression, test dédié).

Imports blank des 8 nouveaux modules dans `cmd/arenet/main.go` **et** dans
`internal/caddymgr/manager_test.go` (même contrat que `caddy-dns/ovh`).

## 4. Redaction des secrets dans les erreurs

- `caddymgr.applyLocked` : si `caddy.Load` échoue, l'erreur est passée par
  `redactSecrets(err, providers)` qui remplace chaque valeur secrète
  (≥ 4 caractères) par `[REDACTED]` avant d'être wrappée/renvoyée. Couvre
  tous les appelants de `ReloadFromStore`.
- Même helper appliqué au message d'erreur du test de connexion (§5).
- Test : un token Cloudflare invalide contenant un marqueur → l'erreur de
  `ReloadFromStore` ne contient pas le marqueur.

## 5. API

| Verbe | Chemin | Changement |
|---|---|---|
| GET | `/settings/dns-providers/types` | **Nouveau.** Renvoie le registre (types + champs, sans valeurs). viewer+ |
| GET/POST/PUT/DELETE | `/settings/dns-providers[/{id}]` | Wire générique (ci-dessous) |
| POST | `/settings/dns-providers/{id}/test` | **Nouveau.** admin. Test de connexion |

**Requête POST/PUT :**
```json
{ "label": "Cloudflare perso", "type": "cloudflare",
  "credentials": { "api_token": "…" } }
```
Rétro-compat : pour `type == "ovh"` (ou vide), les anciennes clés camelCase
`endpoint` / `applicationKey` / `applicationSecret` / `consumerKey` sont
repliées dans `credentials` (clients API/Ansible existants).

**Vue :**
```json
{ "id": "…", "label": "…", "type": "cloudflare", "configured": true,
  "fields": { "zone_token": "" },          // valeurs des champs NON secrets
  "secretsSet": { "api_token": true, "zone_token": false },
  "usedBy": ["example.com"],
  "endpoint": "ovh-eu" }                    // conservé pour OVH (rétro-compat)
```

**Test de connexion** — body `{ "zone": "example.com" }` (optionnel : défaut =
apex du premier managed domain qui référence ce provider ; sinon 400
`zone_required`). Implémentation : `caddy.GetModule("dns.providers."+type)` →
`New()` → `json.Unmarshal(credentials)` → `Provision(caddy.NewContext(...))` →
`libdns.RecordGetter.GetRecords(ctx, zone+".")`, timeout **15 s**.
Réponse `200 { "ok": true, "records": N }` ou
`200 { "ok": false, "error": "<redacted>" }`. **Lecture seule** : aucun
enregistrement n'est créé/modifié. Pas d'audit (aucune mutation) ; log `slog`
Info avec type + zone + ok, jamais les credentials.

Guards existants inchangés : delete-in-use (managed domains), route DNS-01
refusée sans provider configuré (via `ProviderConfigured`), rétro-compat
`provider:"ovh"` des managed domains (`managed_domain.go:165`).

## 6. Backup / restore

- Export : `sentinel.go` remplace **chaque valeur de champ `secret`** de
  `Credentials` par `SentinelLiteral` (générique, via le registre).
- Import : `resolve(...)` appelé par clé secrète (`"dns_providers", id, key`)
  avec fallback sur la valeur live de même id **si le type est identique**.
- `validate.go` : placeholder `incomplete-restore-placeholder` par clé secrète
  effacée.
- Anciens backups (champs à plat) : décodés via `UnmarshalJSON` (§1) —
  test avec une fixture de snapshot pré-v2.26.

## 7. Frontend (`DNSProvidersSection.svelte`)

- Charge `GET /settings/dns-providers/types` une fois.
- Formulaire : sélecteur de type (création uniquement ; en édition le type est
  affiché, changer de type = supprimer + recréer, plus simple et évite la
  perte de secrets implicite) → champs générés depuis le registre :
  `type="password"` pour les secrets avec placeholder « inchangé » en édition
  si `secretsSet[key]`, `<select>` pour les enums, marqueur requis.
- Lien « Où créer ce token ? » vers `DocsURL`.
- Bouton **« Tester la connexion »** par provider (admin), champ zone
  pré-rempli (apex du 1er managed domain lié), résultat inline
  (✓ N enregistrements / ✗ message).
- Liste : badge du type (nom du fournisseur).
- i18n FR + EN : `settings.dnsProviders.types.<type>.fields.<key>.label`
  (+ `.help`), avec repli sur le `Label` EN du registre. Test de parité
  i18n inchangé.
- Types TS dans `lib/api/types.ts`, client dans `lib/api/settings.ts`.

## 8. Tests (portes de validation)

Backend :
1. **Registre ↔ Caddy** (le test clé) : pour chaque type du registre, remplir
   tous les champs avec des valeurs factices bien formées → `buildConfigJSON`
   → `caddy.Validate()` doit passer. Échoue si un nom de champ diverge de
   l'upstream (décodage strict).
2. Non-régression OVH : JSON émis identique octet pour octet à v2.25.1 pour
   une fixture OVH.
3. `UnmarshalJSON` legacy → `Credentials` ; migration boot idempotente.
4. `validate()` : requis manquant, enum invalide, clé inconnue, type inconnu.
5. Preserve-on-edit générique ; changement de type sans préservation.
6. Redaction : erreur `ReloadFromStore` avec token Cloudflare invalide ne
   contient pas le secret.
7. API : wire générique, rétro-compat camelCase OVH, `/types`, `/test`
   (provider factice en test via un module Caddy de test enregistré sous
   `dns.providers.arenettest` implémentant `RecordGetter`), 400
   `zone_required`, RBAC (viewer ne peut pas tester).
8. Backup : sentinelles par clé secrète, import ancien format, resolve live.

Frontend (Vitest) : génération du formulaire depuis le registre, secrets en
password + placeholder, bouton test (succès/échec), parité i18n.

Mesure : taille du binaire avant/après (attendu : +10–20 Mo, surtout SDK AWS et
Scaleway) — notée dans la PR.

## Non-goals (verrouillés)

- ❌ Sélection du provider **par route** (reste `defaultDNSProvider` ; les
  managed domains dispatchent déjà par `ProviderID`).
- ❌ Réglages de propagation DNS-01 (`resolvers`, `propagation_timeout`,
  `propagation_delay`) → backlog (utile pour Cloudflare/split-horizon).
- ❌ Test de connexion sur des credentials **non enregistrés** (on teste un
  provider sauvegardé).
- ❌ Chiffrement au repos des credentials → vague 2 (même frontière que
  aujourd'hui : BoltDB 0o600).
- ❌ Autres types (Namecheap, GoDaddy, deSEC, IONOS, DuckDNS…) → ajout
  trivial ultérieur via le registre si demandé.
- ❌ Changement de type en édition.

## Livraison

Commits indicatifs : (1) registre + modèle + migration + validate,
(2) caddymgr émission + imports + redaction, (3) API wire + `/types` +
`/test`, (4) backup, (5) frontend + i18n, (6) docs (wiki-seed
DNS-Providers EN/FR, smoke `docs/smoke-test-dns-providers.md` : smoke réel OVH
par l'opérateur + validation automatique pour les autres), bump v2.26.0.
