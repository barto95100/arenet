# Multi-config DNS providers (OVH multi-comptes, extensible multi-type)

**Date**: 2026-07-12
**Status**: Design approved, pending implementation plan
**Target version**: v2.11.x (additive, no MAJOR schema bump)

## 1. Symptôme observé par l'opérateur

Un opérateur qui gère plusieurs zones DNS chez OVH avec des **comptes / jeux de credentials différents** (ex. domaine A sur un compte perso, domaine B sur un compte pro, chacun avec son `application_key` / `application_secret` / `consumer_key`) ne peut aujourd'hui déclarer qu'**une seule** configuration OVH. Tous les certificats wildcard (`*.A`, `*.B`, …) sont donc forcés d'utiliser le même et unique compte OVH global — impossible d'émettre des wildcards ACME DNS-01 sur des zones appartenant à des comptes OVH distincts.

Le menu **Certificats → « + Wildcard apex »** présente un champ « DNS provider » sous forme de `<select>`, mais il ne contient qu'une seule option codée en dur (`OVH`) et ne liste aucune configuration réelle.

### État actuel vérifié (citations)

- **Storage singleton** : `internal/storage/dns_provider.go:72` — clé fixe `const dnsProviderKeyOVH = "ovh"`. Méthodes `GetDNSProviderOVH` / `PutDNSProviderOVH` / `DeleteDNSProviderOVH` (pas de `List`, pas d'`id`). Struct `DNSProviderConfig{Endpoint, ApplicationKey, ApplicationSecret, ConsumerKey}` — aucun champ identité.
- **Managed domains = collection** : `internal/storage/managed_domain.go` — un enregistrement par apex, champ `Provider string` (vaut `"ovh"`, un *type*).
- **Caddy config globale** : `internal/caddymgr/manager.go:559` charge `GetDNSProviderOVH(ctx)` une fois ; `manager.go:2230-2231` ignore le nom du provider par domaine et utilise toujours le singleton `opts.DNSProvider`. Commentaire `manager.go:2227-2229` : *« When future providers land, this switch becomes a per-Provider dispatch. »*
- **API singleton** : `internal/api/routes.go:355-356` — `GET`/`PUT /settings/dns-providers/ovh` (chemin littéral `/ovh`, pas de `/{id}`).
- **Wizard mono-option** : `web/frontend/src/lib/components/certs/WildcardApexWizard.svelte:133-140` — `<option value="ovh">OVH</option>` en dur ; type `ManagedDomainProvider = 'ovh'` (`types.ts:803`).
- **Backup** : `internal/backup/export.go:73-99` exporte déjà `DNSProviders` comme une **liste** (via `GetDNSProviderOVH`, ligne 34) ; `SchemaVersion = "1.0.0"` avec règle MAJOR-equal à l'import (`types.go:59`, `sentinel.go:174`) ; `import.go:180` réinjecte via `GetDNSProviderOVH`.

## 2. Périmètre

**Dans le périmètre (v2.11.x)** :
- Plusieurs configurations DNS provider, chacune identifiée par un UUID + libellé libre.
- Un type par config (`type: "ovh"` seul supporté en v1, champ présent pour l'extension future).
- Chaque wildcard (managed domain) référence **une** config par son id.
- Migration transparente de la config OVH singleton existante.
- CRUD complet : storage, API REST, UI Settings, wizard.

**Hors périmètre (V3 backlog)** :
- Endpoint `POST /settings/dns-providers/{id}/test` (test de connexion OVH réel). N'existe pas aujourd'hui pour OVH (vérifié : seuls `alerting/channels/{id}/test` et `alerting/rules/{id}/test` existent, `routes.go:478,493`). Modèle à suivre : le pattern alerting. Découplé car implique un appel API externe (timeout, erreurs réseau) = incrément autonome.
- Autres types de providers (Cloudflare, Route53). Le champ `type` et l'icône du dropdown préparent le terrain, mais aucun module Caddy DNS supplémentaire n'est câblé.
- Cert.B drill-down : **non modifié** (pas de trace ProviderID).

## 3. Design

### 3.1 Modèle de données

`DNSProviderConfig` devient une entité identifiée :

```go
DNSProviderConfig {
    ID        string  // UUID (uuid.NewString()), généré à la création
    Label     string  // libellé libre, non-vide requis, NON-unique
    Type      string  // "ovh" (v1) — const list fermée, rejet sinon
    Endpoint  string  // ovh-eu, ovh-ca, ovh-us, … (spécifique OVH)
    ApplicationKey    string  // SECRET — jamais renvoyé/audité
    ApplicationSecret string  // SECRET
    ConsumerKey       string  // SECRET
}
```

`ManagedDomain` : le champ `Provider string` (un *type*) devient `ProviderID string` (un *id* de config). Rétro-compat lecture : un input `provider: "ovh"` reste toléré à jamais (résolu vers la config par défaut migrée).

### 3.2 Storage (BoltDB)

Bucket `dns_providers` réutilisé, **clé = UUID** au lieu de la clé fixe `"ovh"`. Nouvelles méthodes collection (miroir de `managed_domains`) :

```
ListDNSProviders(ctx)          → []DNSProviderConfig   (NON trié — tri côté API/frontend)
GetDNSProvider(ctx, id)        → DNSProviderConfig | ErrNotFound
CreateDNSProvider(ctx, cfg)    → assigne l'UUID, écrit
UpdateDNSProvider(ctx, id, cfg)→ preserve-on-edit des secrets (vide = conserve)
DeleteDNSProvider(ctx, id)     → ErrProviderInUse si un ManagedDomain.ProviderID == id ;
                                 ErrNotFound si id absent
```

- Concurrence : BoltDB sérialise déjà les write-tx ; pas de version field (scénario low-write).
- Validation (`ValidateDNSProvider` étendu) : `Label` non-vide, `Type` ∈ const list, endpoint OVH valide (validation existante conservée).
- Anciennes méthodes `GetDNSProviderOVH` / `PutDNSProviderOVH` / `DeleteDNSProviderOVH` supprimées (sauf usage interne migration).

### 3.3 Migration one-shot (au boot)

Exécutée au démarrage, idempotente **par état** :
- Condition : le bucket `dns_providers` contient encore la clé legacy `"ovh"` (une valeur **sans** champ `ID`).
- Action, dans une seule transaction :
  1. Créer une entrée `{ID: <uuid généré une fois>, Label: "OVH (default)", Type: "ovh", Endpoint, …secrets}` à partir de la valeur legacy.
  2. Supprimer la clé `"ovh"`.
  3. Repointer tous les `ManagedDomain` dont `Provider == "ovh"` vers `ProviderID = <uuid>`.
- Idempotence : une fois migré, la clé `"ovh"` n'existe plus → la migration ne fait rien aux boots suivants. Pas besoin d'UUID reproductible (détection par présence de la clé legacy, pas par id calculé).
- Écriture directe (pas `CreateDNSProvider`, qui régénérerait un UUID) — pattern des migrations atomiques existantes (`PutManagedDomainWithRouteMigration`, `managed_domain.go:323`).

### 3.4 API REST

Collection en miroir de `managed-domains`. L'ancien `/settings/dns-providers/ovh` (singleton) est supprimé.

```
GET    /settings/dns-providers        → liste ; chaque entrée porte usedBy: [<apex>] (via 1 ListManagedDomains). Secrets jamais sérialisés.
POST   /settings/dns-providers        → 201 {config sans secrets} | 400 (label vide / type inconnu / endpoint invalide)
GET    /settings/dns-providers/{id}   → config sans secrets | 404
PUT    /settings/dns-providers/{id}   → preserve-on-edit | 404 si absent | 400 validation
DELETE /settings/dns-providers/{id}   → 204 | 409 (nomme les wildcards) | 404 si absent
```

- Audit : chaque mutation émet `TargetType: "dns_provider"`, `TargetID: <uuid>`, **jamais** de secret dans `AfterJSON` (précaution existante `dns_provider.go:176`).
- `managed-domains` API : accepte `providerId` (UUID) ; valide via `GetDNSProvider(providerId)`. Rétro-compat : `provider: "ovh"` toléré → résolu vers la config par défaut.
- Pas de rate-limit dédié : `rateLimiter.Middleware()` global (`routes.go:116`) + `RequireAdminMiddleware()` (`routes.go:334`) couvrent déjà.

### 3.5 Backup / Restore

- Export : passe de `GetDNSProviderOVH` (singleton) à `ListDNSProviders`. Le format snapshot est déjà une liste (`export.go:73-99`) → changement minime.
- Import : `import.go:180` adapté à la collection. Un backup pre-v2.11 (format legacy) est ré-appliqué puis passé par la même migration one-shot au boot suivant.
- `SchemaVersion` reste `1.x` (pas de MAJOR bump) : les anciens backups restent lisibles.

### 3.6 Frontend

- **Client API `settings.ts`** : `getDNSProviderOVH`/`putDNSProviderOVH` → `listDNSProviders` / `getDNSProvider` / `createDNSProvider` / `updateDNSProvider` / `deleteDNSProvider`. Type TS `DNSProviderConfig { id, label, type, endpoint, configured, usedBy[] }` (sans secrets).
- **`WildcardApexWizard.svelte`** : `<select>` mono-option → **dropdown custom** (libellé + icône de type — choix Q2 option A) alimenté par `listDNSProviders()`. Envoie `providerId`. Empty state : liste vide → avertissement + lien « Configurer un provider dans Settings ».
- **`/settings` section DNS Providers** : formulaire unique → **table** (choix Q3 option B). Colonnes : **Libellé | Type | Endpoint | Statut | Utilisé par | Actions (✎ 🗑)**. Modal Ajouter/Éditer (libellé, endpoint, 3 secrets preserve-on-edit). Suppression → confirm ; 409 → toast nommant les wildcards bloquants. Empty state : « + Ajouter votre premier provider ».
- **i18n EN/FR** : toutes les nouvelles chaînes via `t()`.

## 4. Matrice des décisions verrouillées

| # | Décision | Choix |
|---|----------|-------|
| S1-1 | UUID migration | Aléatoire + idempotence par état (présence clé legacy) |
| S1-2 | Label | Libre, non-unique, non-vide requis |
| S1-3 | Type | Const list `{"ovh"}`, rejet sinon |
| S1-4 | Backup/restore | Migration au restore, SchemaVersion 1.x préservé |
| S1-5 | `Provider`→`ProviderID` | Renommage sur ManagedDomain, rétro-compat lecture |
| S2-1 | Tri | Storage non-trié, tri API/frontend |
| S2-2 | Delete id absent | `ErrNotFound` → 404 |
| S2-3 | Concurrence | Mutex natif BoltDB, pas de version field |
| S2-4 | Migration | Écriture directe atomique, pas `CreateDNSProvider` |
| S2-5 | Suppression anciennes méthodes | Oui (clean refactor) |
| S3-1 | `usedBy[]` dans GET liste | Adopté (1 ListManagedDomains) |
| S3-2 | Rétro-compat `provider="ovh"` | Keep forever (défensif, coût nul) |
| S3-3 | Rate-limit POST | Skip (global + admin-gated) |
| S3-4 | Endpoint `/test` | V3 backlog |
| S4-Q1 | Empty states | CTA sur les deux (wizard + settings) |
| S4-Q2 | Dropdown wizard | Libellé + icône de type (extensible) |
| S4-Q3 | Layout settings | Table listing |
| S4-Q4 | Scope frontend | Wizard + Settings table + client API (Cert.B exclu) |
| S4-+ | Colonne table | « Endpoint » (pas « Région ») — universel multi-type |

## 5. V3 backlog

- **Endpoint `/test`** : `POST /settings/dns-providers/{id}/test` — test de connexion OVH réel, sur le modèle `alerting/channels/{id}/test`. Retourne `200 {ok, error?}`.
- **Multi-type** : Cloudflare, Route53. Nécessite câblage des modules Caddy DNS correspondants + credentials spécifiques par type + dispatch dans `buildManagedDomainPolicies` (`manager.go:2230`).

## 6. Portes de validation empirique

- **Backend (Go)** : tests storage (List/Get/Create/Update preserve-on-edit/Delete 409+404), migration one-shot (idempotence : 2 boots), API (codes 201/400/404/409, secrets jamais renvoyés, audit sans secret), caddymgr (dispatch par `ProviderID`, `caddy.Validate()` sur le JSON émis + handler-IDs résolvables — pattern CLAUDE.md §Empirical verification).
- **Frontend (vitest)** : wizard (dropdown alimenté, empty state, envoi `providerId`), settings table (rendu liste, modal add/edit, delete 409 → toast), client API (méthodes/paths/bodies).
- **E2E smoke (vrai binaire)** : configurer 2 comptes OVH, créer 2 wildcards sur des comptes distincts, vérifier le JSON Caddy émis (2 policies DNS-01 distinctes) ; migration : booter avec une DB pre-v2.11 → config auto-migrée + wildcards repointés.

## 7. Migration path opérateur

Transparente et idempotente : au premier boot de v2.11.x, la config OVH existante devient « OVH (default) », les wildcards existants restent fonctionnels sans coupure ACME, aucune action requise. Un restore d'un backup antérieur suit le même chemin.

## 8. Scope estimé

- **Backend** : storage (~5 méthodes + migration), API (~5 handlers + adaptation managed-domains), caddymgr (dispatch par id), backup export/import.
- **Frontend** : client API, wizard (dropdown custom), settings (table + modal CRUD), i18n EN/FR.
- **Tests** : storage + API + caddymgr + frontend + smoke E2E.
- **Docs** : mise à jour de la doc /settings et wildcard si elle mentionne le provider unique.
