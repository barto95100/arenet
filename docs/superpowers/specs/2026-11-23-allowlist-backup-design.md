<!-- Arenet spec — Allowlist backup/restore integration (#372). AGPL-3.0. © 2026 The Arenet Authors. -->

# Spec — Allowlist backup/restore integration (#372)

- **Issue**: #372 (follow-up of #364)
- **Target release**: v2.85.0 — **BLOCKING**: do not tag v2.85.0 without this merged.
- **Branche**: `feat/allowlist-backup` (basée sur `main`, isolation)
- **Date**: 2026-11-23
- **Statut**: SPEC — en attente de GO opérateur avant plan + implémentation

---

## 1. Problème

#364 persiste les allowlists dans un fichier SQLite **dédié** `data/security.db`.
Le backup AreNET (`internal/backup`) est un **Snapshot logique** sourcé du
`Storer` BoltDB ; il ne couvre donc **pas** `security.db`. Aujourd'hui, un
export ne contient pas les allowlists, et un restore ne les recrée pas — la
config opérateur serait **silencieusement perdue** sur un restore.

## 2. Dépendance de séquencement

L'implémentation de #372 **référence le package `internal/allowlist`** (types
`Allowlist`/`Entry`, le store) livré par **#373**. Comme cette branche est basée
sur `main` pour l'isolation (demande opérateur), le code ne compilera qu'une fois
**#373 mergé dans `main`** (puis cette branche mise à jour depuis `main`). La
**spec** (ce document) et les **tests RED** peuvent être écrits avant, mais l'impl
GREEN attend le merge de #373. Aucun risque de conflit : `internal/backup` et
`internal/allowlist` sont disjoints.

## 3. Scope (minimal)

- `SnapshotExtras` gagne un champ `Allowlists []allowlist.Allowlist` (JSON
  `omitempty`, rétrocompatible : absent d'un backup pré-v2.85.0).
- Une **source** d'allowlists est fournie au backup. Décision D-SRC (ci-dessous).
- Les **4 sites d'appel** `backup.Export/Import` reçoivent la source :
  `cmd/arenet/backup_cli.go`, `internal/autobackup/service.go`,
  `internal/api/backup_handlers.go` (export ×2 + import).
- **Restore** : applique les allowlists dans `security.db` (remplacement complet
  transactionnel), puis déclenche `Resolver.Rebuild` pour que le live trigger
  prenne effet sans restart.
- **Pas de sentinelle K.3** : les allowlists ne contiennent aucun secret → pas
  de redaction, diff complet dans l'audit/backup.

## 4. Décisions à trancher (sign-off opérateur)

| ID | Question | Recommandation |
|----|----------|----------------|
| **D-SRC** | Comment le backup accède-t-il aux allowlists ? | Ajouter une **petite interface** `AllowlistSource`/`AllowlistSink` au package `backup` (ex. `List(ctx)` / `ReplaceAll(ctx, []Allowlist)`), satisfaite par `*allowlist.Store`. Les signatures `Export`/`Import` gagnent un paramètre **nil-tolérant** (nil = pas d'allowlists dans le snapshot, pour les tests + chemin dégradé). Garde `backup` découplé de `allowlist` derrière une interface locale. |
| **D-SIG** | Étendre les signatures `Export`/`Import` (4 sites) vs. option struct | Étendre les signatures (paramètre explicite nil-tolérant). C'est le pattern déjà en place (`store Storer, users UserStorer`). 4 sites à toucher, tous mécaniques. |
| **D-RESTORE** | Sémantique restore allowlists | **Remplacement complet** (comme les autres extras résolus) : le restore reflète le snapshot. `security.db` indisponible au restore → **échec clair** de l'étape allowlist, sans corrompre le reste (fail-safe, cohérent D-DEGRADED). |
| **D-REBUILD** | Rebuild après restore | L'API/CLI restore déclenche `Resolver.Rebuild` après succès (comme une mutation CRUD). |

## 5. Cas à couvrir (tests, RED d'abord)

| Guard | Scénario | Attendu |
|-------|----------|---------|
| G_backup_allowlist_roundtrip | export N allowlists → import sur instance vierge | N restaurées à l'identique (slug, scope, entrées normalisées, enabled) |
| G_backup_allowlist_backcompat | backup **pré-v2.85.0** (sans section allowlists) restauré sur v2.85.0 | `security.db` reste **vide proprement**, zéro erreur, automation bannit normalement |
| G_backup_allowlist_replace | import sur une instance ayant déjà des allowlists | remplacement complet (pas de merge/doublon) |
| G_backup_allowlist_degraded | restore avec `security.db` indisponible | erreur claire de l'étape allowlist, le reste du restore non corrompu |
| G_backup_allowlist_nosecret | export d'une allowlist | aucune sentinelle/redaction (diff complet), pas de faux secret |
| G_backup_nonregression | Snapshot sans allowlists | compteurs extras + byte-identité inchangés vs. aujourd'hui |

## 6. Non-goals

- Aucun secret (pas de sentinelle K.3).
- Pas de changement du schéma allowlist ni de l'UI #364.
- Pas de bundle de fichier DB brut : on reste sur le Snapshot logique.

## 7. Livrables (après GO spec + merge #373)

1. Plan (`docs/superpowers/plans/2026-11-23-allowlist-backup.md`).
2. Tests G_* en RED.
3. Interface `AllowlistSource`/`Sink` + champ `SnapshotExtras.Allowlists` + les 4
   sites d'appel + restore + rebuild.
4. Mise à jour doc backup (`docs/operations/backup.md` + wiki Backup-Restore).
5. PR (branche à jour depuis `main` post-#373), CI verte, ping review.
6. Après merge #373 + #372 + dogfood : release v2.85.0.
