# Rate Limit

[English](Rate-Limit) · **🌐 Français**

Throttling de requêtes par route via le module [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit). Chaque route peut déclarer sa propre policy de rate-limit : `N événements par fenêtre de temps keyée par X`.

À utiliser quand : protéger des endpoints prone-à-brute-force (`/api/login`, `/admin`), throttler les scrapers abusifs, ou enforcer des quotas par API key sur des APIs publiques.

---

## Quick start

1. Sidebar → **Routes** → clique ta route → **Edit**
2. Déploie la section **Limitation de débit** (Rate Limit)
3. Toggle **Activé** ✅
4. **Événements** : combien de requêtes sont autorisées par fenêtre (ex. `60`)
5. **Fenêtre** : la fenêtre de temps (ex. `1m`, `30s`, `1h`) — format duration Go
6. **Clé** : la clé de rate-limit. Défaut `{http.request.remote.host}` = par IP. Autres clés utiles :
   - `{http.request.remote.host}` — par IP source
   - `{http.request.header.X-API-Key}` — par API key (quand les clients en envoient une)
   - `{http.request.header.Authorization}` — par JWT / Bearer token
   - `{http.request.cookie.session}` — par session
7. **Save**

En 5s le rate limit est actif. Teste en hammerant la route :

```bash
for i in {1..100}; do curl -s -o /dev/null -w "%{http_code}\n" https://your-route.example.com/api/ping; done | sort | uniq -c
# Attendu après la 60ème requête : 200 (60 fois) puis 429 (40 fois)
```

---

## Comment ça marche

Le module `caddy-ratelimit` maintient un compteur in-memory par tuple (zone, key). Quand le count excède `events` pendant `window`, les requêtes suivantes reçoivent **429 Too Many Requests** avec un header `Retry-After`.

La fenêtre slide continuellement (pas alignée sur des buckets). Après que la fenêtre passe, le compteur décroît naturellement.

Les compteurs sont **in-process** — ils ne persistent pas entre restarts et ne synchronisent pas entre instances Arenet (pas de support multi-instance encore).

---

## Anatomie d'un emit de rate limit

Config JSON Caddy (simplifiée) :

```json
{
  "handler": "rate_limit",
  "rate_limits": {
    "route-<uuid>": {
      "match": [...],
      "key": "{http.request.remote.host}",
      "window": "1m",
      "max_events": 60
    }
  }
}
```

Arenet émet une zone par route avec rate-limit activé, keyée par UUID de route. Le nom de zone suit la convention `route-<uuid>` pour que le handler d'événement rate-limit (Step Z) puisse mapper les zones vers les IDs de routes dans le `/logs` unifié.

---

## Observabilité

Chaque 429 émet une ligne `rate_limit_event` dans SQLite :

- `ts` — timestamp
- `route_id` — quelle route (dérivée du nom de zone)
- `zone` — le nom de zone Caddy
- `src_ip` — IP distante
- `wait_ms` — combien de temps jusqu'à ce que le compteur décroisse assez (hint Retry-After)

La page `/logs` rend ces événements avec le badge RATE-LIMIT (orange). La page d'observabilité par route `/observability/<routeId>` montre la timeseries rate-limit à côté des req/s + 4xx + 5xx.

Le compteur **rate_limit_count** du dashboard (bucket par route) incrémente à chaque 429.

---

## Catalogue de patterns

### Protection brute-force login

```
Events: 5
Window: 5m
Key: {http.request.remote.host}
```

5 tentatives login par 5 minutes par IP. Après la 6ème, 429 avec Retry-After ≈ 5min. Combine avec des scenarios [CrowdSec](CrowdSec-FR) qui auto-ban après N 429s.

### Quota par token API publique

```
Events: 1000
Window: 1h
Key: {http.request.header.X-API-Key}
```

1k req/heure par API key. Facile à bumper pour des tiers payants (routes différentes avec limites différentes).

### Receveur de webhook

```
Events: 30
Window: 1m
Key: {http.request.remote.host}
```

30 webhooks/min par source. Les webhooks burstent généralement puis idle ; ça empêche une source qui misbehave de noyer ton downstream.

### Anti-scraper pour contenu public

```
Events: 300
Window: 1m
Key: {http.request.remote.host}
```

5 req/sec moyennes par IP. Les browsers restent bien en-dessous ; les scrapers agressifs hit le mur vite.

---

## Edge cases

### Derrière un CDN / reverse proxy externe

Si Arenet est derrière Cloudflare / nginx / un proxy d'entreprise, `{http.request.remote.host}` résout à l'IP du proxy, pas du vrai client. **Chaque client apparaît comme la même IP** → rate limit trigger pour tout le monde après N requêtes.

Fix : set la passthrough de header de requête de la route pour inclure `X-Forwarded-For`, configure les `trusted_proxies` Caddy pour reconnaître l'IP du front proxy, et utilise `{http.request.header.X-Forwarded-For}` comme clé (la logique split-on-comma dans Caddy gère la chaîne comma-joined).

Une future release Arenet pourrait exposer un setting `trustedProxies` par route ; actuellement seule la config au niveau du listener existe.

### Perte de compteurs au restart

Les compteurs in-memory reset au restart d'Arenet. Un attaquant qui track l'uptime d'Arenet pourrait timer ses tentatives de brute-force pour coïncider avec des restarts. **Mitigation** : combine rate-limit (fenêtre courte) avec CrowdSec (décisions persistantes survivant aux restarts).

### Partage /64 IPv6

Les opérateurs mobiles partagent souvent un /64 à travers plusieurs users. Keyer par IP complète fonctionne ; keyer par prefix d'IP (bloc `/64`) n'est actuellement pas exposé — le module Caddy supporte les placeholders `key` mais l'UI Arenet ship le défaut full-IP placeholder.

---

## Référence API

```bash
curl -b /tmp/jar -X PUT -H "Content-Type: application/json" \
  -d '{
    ...other route fields...,
    "rateLimit": {
      "events": 60,
      "window": "1m",
      "key": "{http.request.remote.host}"
    }
  }' \
  http://localhost:8001/api/v1/routes/<route-id>
```

Set `rateLimit: null` pour désactiver.

---

## See also

- [Routes](Routes-FR) — où trouver la section Rate Limit dans l'UI
- [WAF](WAF-FR) — defense en couches ; rate limit catche l'abus, WAF catche les signatures d'attaque
- [CrowdSec](CrowdSec-FR) — auto-ban sur des hits rate-limit persistants via scenarios
- [Alerting](Alerting) — alerte quand les événements rate-limit spike
- [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) — référence du module upstream
- `internal/ratelimit/` — emit + sink + handler d'Arenet
