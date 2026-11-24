<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Propagation `cscli decisions delete` → mirror AreNET = ≤ 30s (mesurée)

Date: 2026-11-24
Status: WORKS AS DESIGNED — #360 fermée `wontfix`, aucun code livré
Related tickets: #360 (fermée), connexe #355, #359 (même famille
« reframe invalidé par mesure »)

## Hypothèse d'origine

#360 affirmait : « `cscli decisions delete` côté LAPI prend **5-7 min** à se
propager au mirror local AreNET (`decision_event`) », avec un workaround
« restart du service (resync au boot nettoie le mirror) ». Diagnostic réputé
nécessiter du SQL manuel + attente. Propositions : raccourcir le poll (A),
endpoint resync (B), CLI (C), doc (D). La cause racine avait été notée comme le
faux-positif « 0 ban » des dogfoods v2.84.0/v2.84.1.

## Ce que le code dit (vérifié)

- Le consumer mirror AreNET poll LAPI à **60s** (`SleepInterval`, cadence
  recommandée — `internal/crowdsec/stream.go:199`, câblé `cmd/arenet/main.go:1269`).
- À réception du delta `deleted[]`, `Tombstone(uuid)` →
  `MarkDecisionExpired(uuid)` pose **`expires_at = NOW`** immédiatement
  (`internal/crowdsec/sink.go:318`, `internal/observability/storage.go:1401`).
- `HasActiveDecision` lit `WHERE expires_at > now`
  (`internal/observability/storage.go:1443`) → cesse de voir la row active dès
  le tombstone absorbé.
- **Aucune logique de reconcile au boot** : `startup=true` liste les actives
  (`new[]`), pas les suppressions ; rien ne diff le mirror contre le set actif
  LAPI. Le « restart nettoie le mirror » n'a donc pas de mécanisme — c'est le
  temps écoulé qui nettoie.

Côté AreNET, le mirror se nettoie donc en ≤ 60s **après réception** du
`deleted[]`. Tout délai supérieur serait côté LAPI (surfaçage du `deleted[]`).

## Protocole de test (AreNET-test, poll forcé à 15s pour la mesure)

1. T0 création de la décision : 13:28:39 UTC.
2. T1 `cscli decisions delete` : 13:29:44 UTC.
3. Polling du mirror toutes les 15s, lecture de `expires_at` de la row.

## Mesures

| Instant | État mirror |
|---|---|
| T1 + 15s | row encore active (`expires_at` à +7119s dans le futur) |
| **T1 + 30s** | `expires_at` = 13:30:06 UTC (passé) → **tombstone absorbé** |

**Propagation totale `cscli delete` → mirror AreNET = ≤ 30s.** Décomposition :
~2s propagation LAPI (write → `deleted[]` surfacé) + ≤60s `SleepInterval` (ici
polled ~20s après) + ~0s `MarkDecisionExpired`.

## Décision

**Works as designed. Rien à corriger.** L'hypothèse des 5-7 min était un
faux-positif par corrélation temporelle (autre action en parallèle lors du
dogfood d'origine). #360 fermée `wontfix`, retirée du milestone v2.87.0.

Verdict sur les propositions : **A** (raccourcir le poll) gagnerait ~30s sur 30s
— inutile ; **B/C** (resync + reconcile) résolvent un problème inexistant et
demanderaient une vraie logique de reconcile absente aujourd'hui — overkill ;
**D** (doc) sans objet puisqu'il n'y a pas de gotcha réel.

## Leçon

Deuxième reframe de la vague observability invalidé par la mesure (après #359).
Une « gotcha » mémorisée reste une hypothèse tant qu'elle n'est pas re-mesurée :
ici 30 minutes de test empirique ont évité un endpoint de reconcile inutile. La
propagation réelle **≤ 30s** est désormais la référence — cf la mémoire projet
`automation-ban-observability-backlog`.

## Références

- `internal/crowdsec/stream.go:199` — `SleepInterval = 60s`
- `cmd/arenet/main.go:1269` — câblage `TickerInterval: SleepInterval`
- `internal/crowdsec/sink.go:309` — `absorbTombstone` → `MarkDecisionExpired`
- `internal/observability/storage.go:1394` — `MarkDecisionExpired` (`expires_at = NOW`)
- `internal/observability/storage.go:1443` — `HasActiveDecision` (`expires_at > now`)
- `internal/crowdsec/live_source.go:197/243` — split `new[]` / `deleted[]`, pas de reconcile
