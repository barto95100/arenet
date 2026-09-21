# WAF (Web Application Firewall)

[English](WAF) · **🌐 Français**

Arenet embarque [Coraza v3.7](https://coraza.io) — un moteur WAF Go-native compatible avec le format de règles ModSecurity — pré-chargé avec **OWASP CRS v4.25** (Core Rule Set). Chaque route peut opt-in à la protection WAF à l'un des trois niveaux :

| Mode | Comportement |
| ---- | ------------ |
| `off` | Handler WAF pas dans la chain. Zéro overhead. |
| `detect` | Le WAF évalue chaque requête, émet un `waf_event` dans `/security` pour chaque match, mais **laisse la requête continuer** vers l'upstream. À utiliser pour observation / triage. |
| `block` | Le WAF évalue, émet l'événement, et **rejette** la requête avec `403 Forbidden` quand le score d'anomalie dépasse le threshold de blocage. |

---

## Quick start : activer WAF sur une route

1. Sidebar → **Routes**
2. Clique ta route → **Edit**
3. **WAF mode** → choisis `detect` (recommandé pour le premier déploiement)
4. Save

En 5 secondes le WAF est actif. Envoie un probe pour tester :

```bash
curl "https://your-route.example.com/?id=1' OR '1'='1"
# En detect mode : la requête atteint ton backend ET un événement SQLi land dans /security
# En block mode : 403 Forbidden, la requête n'atteint pas le backend
```

Ouvre `/security` dans l'UI : tu verras l'événement listé avec catégorie `SQLi`, l'ID de règle CRS qui a matché (942100 pour libinjection), IP source + GeoIP, l'échantillon de payload qui a matché.

---

## Anatomie d'un événement WAF

Chaque match émet une ligne dans la table SQLite `waf_event` avec :

- `ts` — timestamp
- `route_id` — quelle route a triggered
- `rule_id` — ID de règle CRS (ex. `942100`, `920170`)
- `category` — classification Arenet (SQLi / XSS / RCE / LFI / RFI / PROTOCOL / METHOD / SCANNER / SESSION / DATA_LEAK / ...) — dérivée du range d'ID de règle, voir `internal/waf/category.go`
- `severity` — CRITICAL / ERROR / WARNING / NOTICE
- `src_ip` — IP distante
- `request_path` — `{method} {uri}`
- `payload_sample` — premiers 256 chars de la data qui a matché
- `action` — `BLOCK` (block mode + score ≥ threshold) ou `DETECT` (detect mode OU block mode + score < threshold)
- `status_code` — `403` pour blocked, `200` pour detect/observed

La page `/security` rend ces événements avec filtre par route + catégorie + niveau. Le drilldown `/security/<routeId>` ajoute les liens de doc des règles CRS + une affordance "Exclude this rule on this route" pour le triage de faux positifs.

---

## Gérer les faux positifs

Quand le WAF bloque une requête légitime (un faux positif connu), tu as **trois portes de sortie** à appliquer par route, par scope croissant :

### Option (a) — Désactiver CRS entièrement sur la route

À utiliser quand : la route sert du trafic interne de confiance (outil d'admin sur LAN), ou le backend est tellement bruyant que CRS produit 90% de faux positifs.

1. Édite la route → section **WAF** → **Disable OWASP CRS on this route** ✅
2. Un dialogue de confirmation (ADR D4) prévient des implications sécurité
3. Save

Le handler WAF reste dans la chain (le dashboard compte toujours les événements à 0), mais les includes CRS sont strippés. Coût d'évaluation CRS à zéro.

### Option (c) — Exclure des IDs de règles CRS spécifiques

À utiliser quand : une règle précise (ex. `942100` SQLi libinjection) fire sur un payload légitime.

1. Édite la route → **WAF exclusions** → **Excluded rule IDs**
2. Liste séparée par virgules : `942100, 920170, 911100`
3. Save

La règle est retirée de l'évaluation CRS pour cette route. Les autres règles de la même famille s'appliquent toujours.

### Option (e) — Exclure des familles de tags CRS entières

À utiliser quand : une famille de règles entière est bruyante sur cette route. Exemple : `attack-protocol` (range de règles 911-921) trip sur l'usage légitime de WebDAV / méthodes HTTP non-standard.

1. Édite la route → **WAF exclusions** → **Excluded tags**
2. Choisis dans le dropdown autocomplete : `attack-protocol`, `attack-sqli`, `attack-rce`, `language-php`, `paranoia-level/3`, ...
3. Save

Toute la famille de tags est exclue. Les règles avec ce tag sont retirées de l'évaluation CRS pour cette route. Plus cheap à maintenir que de lister 15 IDs de règles.

---

## CRS paranoia levels

OWASP CRS supporte quatre paranoia levels (PL1–PL4) qui contrôlent la strictness :

- **PL1** (défaut) : règles avec faible taux de faux positifs, adapté à la plupart des web apps publics
- **PL2** : ajoute des règles qui peuvent tripper sur des edge cases légitimes
- **PL3** : agressif, attends-toi à des FPs sur des apps à contenu riche
- **PL4** : maximum, pour endpoints hardenés uniquement

Arenet émet actuellement **PL1 par défaut** pour chaque route. La configuration paranoia level par route n'est pas exposée dans l'UI dès v2.9.3 ; si tu as besoin de PL2+ sur une route spécifique, le workaround est des directives Coraza custom via la config WAF de la route (avancé, pas exposé UI).

---

## Considérations de performance

- Le handler WAF tourne **avant** le handler reverse-proxy donc un rejet block-mode n'atteint jamais l'upstream
- Les instances WAF sont poolées par leur SHA de directives-string — N routes avec une config WAF identique partagent **une seule instance Coraza WAF** en mémoire (voir la clé de pool dans `internal/waf/module.go`)
- L'inspection de body (multipart, XML, JSON) est le chemin le plus lourd. Pour les routes qui handle des gros uploads (serveurs de fichiers, Docker registry), active le **Upload streaming mode** sur la route qui skip l'inspection de body et demande à Caddy de flush les bytes sans buffering RAM
- Le moteur Coraza lui-même est Go-native (pas de cgo), donc pas d'overhead de thread par requête

---

## Patterns communs de faux positifs + fixes

| Symptôme | Cause probable | Fix |
| -------- | -------------- | --- |
| GET avec body retourne 403 sur API REST | `920170` (attack-protocol) | Exclure règle 920170 ou tag `attack-protocol` |
| PUT/DELETE retourne 403 sur API admin | `911100` (METHOD-ENFORCEMENT) | Exclure règle 911100 ou tag `attack-protocol` |
| Tout ce qui contient `--` dans l'URL retourne 403 | `942100` (SQLi libinjection FP sur UUIDs / version strings) | Exclure règle 942100 ou, plus étroit, exclure uniquement sur la route spécifique |
| Upload multipart retourne 403 | `922xxx` (attaques multipart) | Exclure tag `attack-multipart` ou activer Upload Streaming Mode |
| Authentik / Keycloak `/api/v1/auth/oidc/callback` retourne 403 | Plusieurs règles CRS tripent sur les params OAuth state/code | Exclure tags `attack-protocol` + `attack-sqli` sur la route IdP, OU set le WAF de la route IdP à `off` |

---

## Monitoring : rester en avant des faux positifs

Le workflow recommandé pour ajouter une nouvelle route :

1. Set WAF mode à **`detect`** d'abord
2. Utilise la route normalement pendant 24-48h (ton vrai trafic exercise le set de règles CRS)
3. Ouvre `/security/<routeId>` → review les événements générés
4. Identifie les FPs : événements où le payload qui a matché est de la donnée user légitime, pas une attaque
5. Ajoute les exclusions (IDs de règles ou tags) pour les FPs
6. Switch WAF mode à **`block`**
7. Câble une alerte ([Alerting](Alerting)) sur `waf_event_rate > 10 / 5min` pour catcher les spikes inattendus

---

## Observabilité cross-route

Le dashboard `/dashboard` montre les **taux WAF detect/block** par top-N routes. La page `/security` agrège les événements à travers toutes les routes avec filtres. Le `/logs` unifié montre les événements WAF à côté des événements auth + rate-limit + cert pour corrélation ("est-ce que cette IP a tenté N probes WAF ET échoué auth N fois ET trip rate-limit ?").

---

## See also

- [Routes](Routes-FR) — où trouver les settings WAF dans l'UI
- [CrowdSec](CrowdSec-FR) — bannit les IPs WAF-triggering les plus égregious à la couche réseau (avant qu'elles atteignent le WAF)
- [Alerting](Alerting) — alerte sur les spikes de `waf_event_rate`
- [Custom Error Pages](Custom-Error-Pages) — brande la page 403 que le WAF retourne
- [Documentation OWASP CRS](https://coreruleset.org/docs/) — référence des règles + taxonomie des tags
- [Documentation Coraza](https://coraza.io/docs/) — internes du moteur WAF
- `internal/waf/category.go` — mapping ID de règle Arenet → catégorie
- `internal/caddymgr/manager.go` (lignes ~1400-2550) — emit du handler WAF + shape SecAction par route
