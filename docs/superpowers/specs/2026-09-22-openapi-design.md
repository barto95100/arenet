<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Documentation OpenAPI de l'API — Design

**Status:** brainstormé avec l'opérateur 2026-09-22, décisions verrouillées.
Vague 2 de l'analyse concurrentielle (CaddyUI / CPM : « OpenAPI docs »).
Cible : **v2.39.0**.

**One-line :** une description OpenAPI 3.1 de toute l'API d'administration
(145 opérations), embarquée dans le binaire, servie en JSON et lisible
dans une page « Documentation API » d'Arenet ; un test empêche un
endpoint d'exister sans être documenté.

## Décisions

| # | Décision | Pourquoi |
|---|----------|----------|
| O1 | **Fichiers YAML écrits à la main** dans le dépôt (`internal/api/openapi/*.yaml`, un par domaine), fusionnés au démarrage, servis en JSON. | Choix opérateur ; pas d'outil de génération ; les schémas reflètent le vrai fil (lu dans les handlers). |
| O2 | **Test de couverture** : les routes enregistrées (`chi.Walk` sur le vrai routeur) = les opérations documentées, dans les deux sens ; `$ref` résolus ; paramètres de chemin déclarés. | Un endpoint ajouté sans doc fait échouer la CI ; une doc orpheline aussi. |
| O3 | **Page dans Arenet** (« Documentation API ») + `GET /api/v1/openapi.json`. | Choix opérateur. |
| O4 | **Visionneuse écrite en Svelte**, sans dépendance : Swagger UI / Redoc embarquent React, Scalar embarque Vue — interdit par CLAUDE.md. | Contrainte projet. |
| O5 | Tout documenter ; **détail complet** (schémas, exemples) pour ce qu'on automatise : routes, WAF, certificats, sauvegardes, CrowdSec, comptes de service / jetons, réglages principaux ; description plus courte pour l'interne (topologie, WebSocket, métriques UI). | Choix opérateur. |
| O6 | `openapi.json` réservé aux utilisateurs connectés (viewer compris) ; « Essayer » réutilise la session (même client que l'UI, CSRF compris). | Pas de surface publique nouvelle. |
| O7 | Authentification documentée : cookie de session (UI) et **`Authorization: Bearer <jeton>`** de compte de service (scripts), avec rôle requis par opération (`x-arenet-role: viewer|admin`). | Ce que l'opérateur utilise pour automatiser. |

## Format

- OpenAPI **3.1.0** ; `info.version` = version d'Arenet (remplacée au
  service par la version du binaire).
- `openapi/base.yaml` : info, serveurs (`/api/v1` relatif), `securitySchemes`
  (`sessionCookie`, `bearerToken`), tags, schémas communs (`Error` =
  `{error, code?, params?}`), réponses communes (400/401/403/404/409/500).
- Un fragment par domaine (`paths` + `components.schemas`) ; la fusion
  refuse un chemin ou un schéma défini deux fois.
- Chemins sans le préfixe `/api/v1` (porté par `servers`) ; `/healthz` et
  `/system/health` dans un fragment « système » avec `servers: [/]`.

## Visionneuse (`/api-docs`)

Colonne de gauche : thèmes (tags) et opérations (méthode colorée + chemin),
recherche. Droite : résumé, description, rôle requis, paramètres, corps
(schéma dépliable + exemple), réponses. **Essayer** : formulaire des
paramètres + corps JSON pré-rempli avec l'exemple, envoi avec la session,
réponse affichée (statut + JSON) ; confirmation avant une méthode qui
modifie (POST/PUT/PATCH/DELETE). Lien de téléchargement du JSON. FR / EN
pour l'interface (le contenu OpenAPI est en anglais, comme le code).

## Tests

Couverture (O2), fusion (doublons refusés), `$ref` / paramètres,
endpoint (`version` injectée, 401 sans session), visionneuse (liste,
recherche, détail, essai avec confirmation), smoke binaire réel
(téléchargement + un appel avec un jeton de compte de service décrit
par la doc).

## Non-goals

- ❌ Génération de clients SDK.
- ❌ Documentation publique hors authentification.
- ❌ Traduction du contenu OpenAPI.
