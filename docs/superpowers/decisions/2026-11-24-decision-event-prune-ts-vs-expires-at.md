<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# `decision_event` est pruné par `ts`, pas par `expires_at` — works as designed

Date: 2026-11-24
Status: WORKS AS DESIGNED — #359 fermée `wontfix`, aucun code livré
Related tickets: #359 (reframe puis clôture), connexe #355, #356, #358, #360 ;
famille dédup `automation-threshold-per-tick` (fix v2.83.1)

## Contexte

L'issue #359 (workstream observabilité des bans, v2.84.x) partait de la
prémisse : « la table `decision_event` dans `metrics.db` n'est jamais purgée
après expiration → croissance indéfinie », et proposait un housekeeping
périodique purgeant par `expires_at`, configurable via
`ARENET_DECISION_EVENT_RETENTION_DAYS`, avec log INFO.

L'investigation v2.87.0 (2026-11-24) a d'abord **reframé** l'issue en
« bug latent de fiabilité » : le prune existant filtre par `ts` (temps
d'insertion), pas par `expires_at`, et l'upsert `ON CONFLICT(uuid)` ne
rafraîchit pas `ts` — donc une décision longue encore active pourrait être
supprimée du mirror après 30 j d'observation, cassant la dédup et provoquant
un doublon de ban. Une spec et 8 guards avaient été proposés sur cette base.

**L'analyse complète des consommateurs de `decision_event` a invalidé ce
reframe avant tout code.** Ce document en garde la trace.

## Finding (2 preuves décisives)

### 1. Le prune par `ts` est un choix de design délibéré, testé et documenté

`internal/observability/decision_event_prune_test.go:156`
(`TestPruneDecisionEventsOlderThan_PrunesByTsNotByExpiresAt`) assure
explicitement que la rétention est **par temps d'observation**, pas par durée
de ban LAPI. Rationale citée dans le test :

> *retention is by OBSERVATION time, not by LAPI ban duration. […] community
> blocklists can carry multi-year durations and we don't want them to crowd
> out the operator's forensic view of recent activity.*

`decision_event` est un **journal forensique borné par le temps d'observation**.
Passer le prédicat à `expires_at` ferait persister un ban community-blocklist de
5 ans pendant 5 ans dans le mirror — exactement ce que ce test protège.

### 2. Le « doublon de ban » est explicitement toléré par le design

La dédup via `HasActiveDecision` (`cmd/arenet/automation_adapters.go:242`) lit le
mirror (`QueryDecisionEvents{OnlyActive:true}` → `WHERE expires_at > now`,
`internal/observability/storage.go:1443`). C'est une **optimisation** pour
éviter un aller-retour HTTP LAPI redondant, **pas** une garantie de correction.
Le checker le dit lui-même (`automation_adapters.go:244`) :

> *Degraded-mode: no mirror to read → assume not active. The push goes through;
> LAPI itself stacks duplicates harmlessly.*

Un push en double est **inoffensif et auto-réparant** : LAPI empile les
duplicatas sans dommage, et le re-push re-peuple le mirror. Côté trigger, un
skip manqué ne fait qu'un intent de plus (`internal/automation/trigger.go:581`),
borné par la cooldown et le D8 re-emit guard.

### 3. La croissance disque est un non-problème

La table est **déjà bornée** à ~30 j par le `RetentionRunner` (tick horaire +
rattrapage boot, `internal/observability/retention.go:234` →
`storage.go:1480`). Les 5,7 Mo observés sur AreNET-test = toute `metrics.db`
(bucket_1m/1h, waf_event, throttle_event, cert_event…), pas `decision_event`
seule. La feature automation étant récente (~v2.84), le plateau des 30 j
n'était pas encore atteint — d'où l'impression de croissance continue.

## Décision

**Garder le prune par `ts`. Rien à corriger — l'implémentation est conforme à
l'intent.** #359 est fermée `wontfix`, retirée du milestone v2.87.0. Aucune
spec ni guard n'est livré ; la spec d'investigation initiale est repliée dans
ce document.

Le log INFO du nombre de rows purgées (Option C envisagée) est sorti du scope
de #359 et, s'il est jugé utile, fera l'objet d'une issue dédiée couvrant
**tous** les pruners du `RetentionRunner`, pas seulement `decision_event`.

## Leçon

Un reframe d'issue reste une hypothèse tant que les **consommateurs** du
mécanisme n'ont pas été lus. Ici, un test existant encodait l'intention inverse
de celle supposée (skill guard §5 : « a warning comment is a missing test » —
ici le test *était* là) et un commentaire du code déclarait le symptôme
inoffensif. Vérifier avant de coder a évité de régresser un comportement testé.

## Références

- `internal/observability/decision_event_prune_test.go:156` — test du prédicat `ts`
- `internal/observability/retention.go:234` — appel du prune (horaire + boot)
- `internal/observability/storage.go:1476` — `PruneDecisionEventsOlderThan` (`DELETE … WHERE ts < ?`)
- `internal/observability/storage.go:1443` — `QueryDecisionEvents` `OnlyActive` (`expires_at > now`)
- `cmd/arenet/automation_adapters.go:242` — `HasActiveDecision` (dédup via mirror)
- `internal/automation/trigger.go:581` — consommateur dédup côté trigger
