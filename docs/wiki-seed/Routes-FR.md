# Routes

[English](Routes) · **🌐 Français**

Une **route** dans Arenet fait correspondre un `host` (FQDN) entrant à un ou plusieurs `upstreams` (backends). Chaque route porte aussi sa config TLS, WAF, auth, rate-limit, country-block et health-check.

Cette page couvre le cycle de vie d'une route : créer, configurer, aliaser, débugger.

---

## Créer ta première route

1. Ouvre l'UI d'admin : `http://<ton-host>:8001`
2. Barre latérale → **Routes**
3. Clique sur **+ Add route**
4. Remplis :
   - **Host** : le hostname public, ex. `vault.example.com`
   - **Upstreams** : un ou plusieurs backends. Clique sur **+ Add upstream** pour en ajouter. Format : `http://<ip-lan>:<port>` ou `https://<host>:<port>` pour les backends HTTPS. Chaque upstream a un `weight` (utilisé quand la policy LB est weighted-round-robin).
   - **LB Policy** : `round_robin` (défaut) ou `weighted_round_robin`
   - **TLS** : coche ✅ pour activer HTTPS + auto-cert via ACME. Choisis le **challenge ACME** : `http-01` (défaut, marche pour n'importe quel domaine qui pointe vers ton host) ou `dns-01` (requis pour les certs wildcard, nécessite des creds DNS provider dans Settings).
5. Clique sur **Save**

En ~5 secondes, Caddy recharge et la route est live :
- Les requêtes HTTP vers `http://vault.example.com` redirigent vers `https://`
- Les requêtes HTTPS reçoivent un cert Let's Encrypt auto-émis (la première requête peut prendre 5-15s le temps qu'ACME termine)
- La requête est reverse-proxifiée vers ton upstream

---

## Anatomie d'une route

Chaque route stocke les champs suivants (bucket BoltDB `routes`) :

| Champ | Défaut | Usage |
| ----- | ------- | ------- |
| `host` | — (requis) | Matcher FQDN principal |
| `aliases` | `[]` | FQDNs additionnels qui matchent la même route |
| `upstreams[]` | — (requis) | Pool de backends (`url` + `weight`) |
| `lbPolicy` | `round_robin` | Policy de load balancing |
| `tlsEnabled` | `false` | Auto-HTTPS via ACME |
| `redirectToHttps` | `false` | Si TLS, force la redirection HTTP→HTTPS |
| `acmeChallenge` | `http-01` | `http-01` / `dns-01` / `inherited` (depuis un apex managé) |
| `useDedicatedCert` | `false` | Forcer un cert par-route plutôt que le cert apex wildcard |
| `insecureSkipVerify` | `false` | Faire confiance aux certs self-signed de l'upstream |
| `uploadStreamingMode` | `false` | Ne pas bufferiser les corps d'upload (gros PUT de fichier, push registry) |
| `requestHeaders` | `{}` | Headers additionnels transmis à l'upstream |
| `responseHeaders` | `{}` | Headers additionnels ajoutés à la réponse client |
| `wafMode` | `off` | `off` / `detect` / `block` ([voir WAF](WAF)) |
| `wafDisableCRS` | `false` | Ne pas charger l'OWASP CRS sur cette route |
| `wafExcludeRules[]` | `[]` | IDs de règles CRS à exclure |
| `wafExcludeTags[]` | `[]` | Familles de tags CRS à exclure |
| `authMode` | `none` | `none` / `basic` / `forward` ([voir OIDC-SSO](OIDC-SSO)) |
| `countryBlock` | `{mode:off}` | Liste allow/deny GeoIP |
| `rateLimit` | `null` | Throttle par route |
| `healthCheck` | `{enabled:false}` | Health checks actifs (URI + status + regex sur le body) |
| `errorPageTemplateId` | `""` | Template de pages d'erreur personnalisées |
| `errorPageOverrides` | `{}` | Surcharges HTML par code de statut |

Le schéma complet vit dans `internal/storage/routes.go`.

---

## Aliases : une route, plusieurs hostnames

Utilise les aliases quand tu as plusieurs FQDNs qui doivent taper sur le même backend avec la même config (WAF, auth, TLS).

Exemple : un seul backend Traefik derrière Arenet qui sert 20 apps *arr-stack* :
- **Host** : `traefik.example.com`
- **Aliases** : `sonarr.example.com`, `radarr.example.com`, `prowlarr.example.com`, ...

Caddy acquiert automatiquement un cert SAN couvrant tous les aliases. Le dashboard `/topology` les groupe visuellement comme un seul conteneur avec N nodes alias.

---

## Certificats wildcard

Pour une route comme `*.example.com`, il te faut un **apex managé** :

1. Barre latérale → **Certificates** (`/certs`)
2. Section **Wildcard policies per apex** → **+ Wildcard apex**
3. Apex : `example.com`
4. DNS provider : OVH (d'autres providers sont prévus) — colle tes clés API
5. Save

Les routes dont le host tombe sous `*.example.com` (ex. `vault.example.com`, `cloud.example.com`) hériteront automatiquement du cert wildcard. Mets leur `acmeChallenge` sur `inherited` pour une déclaration explicite, ou laisse le défaut et Caddy choisira le cert wildcard via SNI matching au handshake.

---

## Health checks

Les health checks actifs surveillent chaque upstream et retirent les mauvais du pool. Pour activer :

1. Édite une route → section **Health check**
2. **Enabled** ✅
3. **URI** : le path que Caddy va GET sur l'upstream, ex. `/healthz` ou `/api/health`
4. **Method** : défaut `GET`
5. **Interval** : défaut `30s`
6. **Timeout** : défaut `5s` (doit être `<` interval)
7. **Expected status** : défaut `0` = "n'importe quel 2xx est OK", ou pin sur ex. `200`
8. **Expected body** (regex) : optionnel, ex. `^\\{"status":"ok"\\}` pour un healthz JSON
9. **Passes** : checks consécutifs requis pour marquer healthy (défaut `1`)
10. **Fails** : checks consécutifs requis pour marquer unhealthy (défaut `1`)

Les upstreams unhealthy sont skippés par le load balancer ; le dashboard `/topology` les montre en état dimmed.

---

## Route states (Active / Maintenance / Disabled)

Chaque route a un **contrôle de cycle de vie à 3 états**, affiché comme un segmented control icon-only sur la liste `/routes` — play (▶, vert) = **Active**, wrench (🔧, ambre) = **Maintenance**, power (⏻, rouge) = **Disabled**. Survole un segment pour son tooltip ; clique dessus pour changer d'état.

| État | Trafic | TLS / `:443` | Config |
| ----- | ------- | ------------- | ------ |
| **Active** | Reverse-proxy normal vers le pool d'upstreams | Conservé si `tlsEnabled` | — |
| **Maintenance** | 503 + page de maintenance brandée + header `Retry-After` pour tout le monde, sauf les IPs bypass qui atteignent le vrai upstream | **Conservé** — host/TLS restent servis | Upstreams/WAF/etc. intacts, juste enveloppés |
| **Disabled** | Route totalement retirée de Caddy ; le host tombe sur le catch-all (404) | Supprimé ; désactiver la **dernière** route HTTPS active supprime le listener `:443` (un dialogue de confirmation t'avertit avant) | **Préservée** pour une ré-activation en un clic |

Si une route porte à la fois un flag `disabled` et un `maintenanceConfig`, **Disabled gagne** — c'est l'état "ne sert aucun trafic du tout" le plus fort. Priorité : **Disabled → 404** (gagne) > **Maintenance → 503** > **Active**.

### Disabled (v2.15.0)

Désactiver une route sert pour les **fenêtres de maintenance où tu ne veux pas du tout que l'app soit joignable**, ou pour mettre de côté une route que tu ne veux pas supprimer (sa config host/upstreams/TLS/WAF/aliases est préservée dans BoltDB — rien n'est perdu). Une route désactivée est filtrée avant la construction de la config Caddy, donc :

- Le host arrête de résoudre via Arenet — une requête dessus tombe sur le **catch-all** (404, voir [Custom Error Pages](Custom-Error-Pages-FR#catch-all-hôte-non-configuré)).
- Si c'était la **dernière route avec `tlsEnabled` + active**, la désactiver supprime aussi le listener HTTPS `:443` — toute autre URL HTTPS servie par Arenet échouera en connection refused jusqu'à ce que tu ré-actives une route ou en ajoutes une nouvelle en HTTPS. L'UI détecte ce cas et affiche un dialogue de confirmation dédié ("Disable the last HTTPS route?") avant que tu confirmes.
- Ré-activer c'est un clic (ou `POST /routes/{id}/enable`) — mêmes upstreams, TLS, WAF, tout revient exactement comme configuré.

### Maintenance (v2.17.0)

Le mode maintenance sert pour le cas « je dois couper l'app un moment, mais je veux quand même pouvoir la taper moi-même pour vérifier ». Contrairement à Disabled, la route **reste servie** — Caddy garde le host + le cert TLS actifs — mais chaque requête reçoit :

- **HTTP 503**
- La **page de maintenance globale** (personnalisable dans Settings → Error Pages → onglet Maintenance, voir [Custom Error Pages](Custom-Error-Pages-FR#page-de-maintenance))
- Un header **`Retry-After`** (secondes, configurable par route)

... **sauf** les requêtes venant des IPs/CIDRs sur la **liste bypass** de la route, qui sont transmises directement au vrai upstream comme si la route était Active. Ça te permet de valider que l'app est vraiment de retour avant de basculer tout le monde.

Configure la maintenance dans le **formulaire d'édition** de la route, section **Maintenance** (affichée pour toute route, pas seulement celles actuellement en maintenance, pour que tu puisses pré-remplir avant de basculer le contrôle d'état) :

- **Retry-After** — choisis un **nombre + une unité** (secondes / minutes / heures / jours) au lieu de convertir à la main en secondes. La valeur est envoyée dans le header de réponse `Retry-After` (toujours en secondes, conformément à la RFC 9110 — les navigateurs et robots lisent des secondes) et substituée dans la page de maintenance via le placeholder `{arenet.maintenance.retry_after}`. La valeur `0` omet le header. Défaut `5 minutes` (300 s) la première fois qu'une route entre en maintenance. _(Le sélecteur d'unité n'est qu'un confort d'UI — la valeur stockée/wire est toujours en secondes.)_
- **Bypass IPs / CIDRs** — un répéteur d'IPs nues (`10.0.0.5`) ou de plages CIDR (`192.168.1.0/24`). Ajoutes-en autant que nécessaire.

Le check de bypass matche l'**IP réelle du client** (le matcher `client_ip` de Caddy), pas le header `X-Forwarded-For` — donc il ne peut pas être spoofé par un header de requête comme le serait un check `X-Forwarded-For`.

- **Message de maintenance (v2.18.1)** — un message **par route**, affiché sur la page de maintenance de cette route via le placeholder `{arenet.maintenance.message}`. Laisse-le vide pour retomber sur le message **global** (**Settings → Error Pages → onglet Maintenance**, au-dessus de l'éditeur HTML), qui est le défaut partagé pour les routes qui n'ont pas le leur. Le message est du texte brut : échappé en HTML, retours à la ligne → `<br>` au rendu (pas d'injection de markup), et les placeholders Caddy `{env.*}` / `{file.*}` sont neutralisés pour ne pas fuiter de secrets/fichiers dans le 503 public.

**Résolution :** message de la route si défini, sinon le message global, sinon rien (la page par défaut affiche alors sa phrase générique).

**Auto-refresh (v2.18.1).** La page de maintenance par défaut intégrée inclut une balise `<meta http-equiv="refresh">` construite depuis le Retry-After de la route, pour que le navigateur du visiteur se recharge une fois la fenêtre censée terminée. Quand Retry-After vaut `0`, aucune balise n'est émise (un `content="0"` rechargerait en boucle instantanément). Ça ne concerne que la **page par défaut intégrée** — une page personnalisée peut l'activer en ajoutant son propre `<meta http-equiv="refresh" content="{arenet.maintenance.retry_after}">`. Note : c'est un *confort navigateur* — l'en-tête `Retry-After` lui-même est indicatif (bots/crawlers le respectent ; les navigateurs ne rechargent pas automatiquement dessus).

Basculer le contrôle d'état vers/depuis Maintenance est idempotent et immédiat — ré-entrer en maintenance sur une route déjà en maintenance garde ta config Retry-After/bypass existante (ça ne reset pas aux défauts) ; en sortir efface la config de maintenance à nil, donc la prochaine fois que tu entres en maintenance ça repart des défauts (`300`s).

### Référence API (contrôle d'état)

```bash
# Disable / re-enable
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/disable
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/enable

# Entrer / sortir de maintenance (la config — retryAfter/bypassIps — se règle via l'update PUT normal de la route)
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/maintenance
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/maintenance/off
```

Les quatre endpoints sont idempotents : désactiver une route déjà désactivée, ou entrer en maintenance sur une route déjà en maintenance, renvoie `200` sans erreur.

---

## Per-route security knobs (antisèche)

Les combinaisons de configuration les plus courantes :

### Site public en lecture seule

```
TLS: ✅ enabled, http-01
WAF: detect mode (observer les attaques, ne pas bloquer les utilisateurs légitimes)
Rate limit: 60 req/min par IP distante
Country block: off
Auth: none
```

### Outil d'admin interne (Vault, Proxmox, Grafana)

```
TLS: ✅ enabled, dns-01 wildcard
WAF: off (ou detect avec attack-protocol exclu si le backend est REST-bruyant)
Rate limit: off
Country block: allow [FR, BE, CH] (tes pays "maison")
Auth: forward (Authelia / Authentik) OU OIDC SSO au niveau de la route
```

### Endpoint API public

```
TLS: ✅ enabled
WAF: block mode
Rate limit: 100 req/min par clé API
Country block: deny [CN, RU, ...] ou allow [pays-de-tes-clients]
Auth: forward (ta gateway API) ou basic
```

### Récepteur de webhook (source à faible confiance)

```
TLS: ✅ enabled
WAF: block mode + paranoia level 2
Rate limit: 10 req/min par IP distante
Country block: allow seulement le pays de la source du webhook
upload streaming mode: ✅ (gros payloads ; skip le buffering body du WAF)
```

---

## Interception des erreurs upstream

Quand un upstream renvoie une réponse 4xx ou 5xx, Arenet remplace automatiquement le body brut de l'upstream par la page d'erreur configurée sur la route (voir [Custom Error Pages](Custom-Error-Pages-FR)). Ça garde une expérience visuelle cohérente — les opérateurs voient le 404 brandé Arenet plutôt que, par exemple, le 404 par défaut de nginx.

### Auto-passthrough sur les challenges d'auth

Deux codes de statut sont **intentionnellement PAS interceptés** : **401 Unauthorized** et **407 Proxy Authentication Required**. La réponse complète de l'upstream — y compris le header `WWW-Authenticate` / `Proxy-Authenticate` portant le challenge — passe jusqu'au client sans y toucher.

C'est nécessaire pour tout flow d'auth où le client retente avec des credentials après avoir lu le header de challenge. Remplacer le body par un 401 HTML générique retirerait le header de challenge et casserait complètement la négociation.

Si tu veux une page 401 brandée pour un de TES propres gates d'auth (BasicAuth, ForwardAuth, OIDC au niveau Arenet), ceux-là servent quand même le body brandé — ils lèvent leur 401 AVANT que la requête n'atteigne l'upstream, donc l'auto-passthrough n'est pas sur le chemin. Seuls les 401/407 originaires de l'upstream traversent le passthrough.

### Codes interceptés

`400, 402, 403, 404, 405, 406, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451` (4xx sans 401+407) et `500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511` (plage 5xx complète).

Pour chaque code intercepté, Arenet renvoie sa propre réponse construite depuis le template de page d'erreur de la route, la surcharge par route, ou le défaut intégré Arenet (dans cet ordre de priorité).

---

## Hot-reload

Chaque changement de route s'applique en **< 5 secondes** sans couper les connexions en cours. Caddy garde l'ancienne config active jusqu'à ce que la nouvelle soit entièrement provisionnée, puis bascule de façon atomique.

Si l'émission de la config échoue (ex. regex malformée dans `wafExcludeRules`), l'appel API renvoie 400 avec l'erreur, la route N'EST PAS sauvegardée, et la config Caddy live reste inchangée. Loud-fail.

---

## Référence API

Pour l'automatisation (Ansible, Terraform, scripts), les mêmes opérations sont disponibles via REST :

```bash
# Liste
curl -b /tmp/jar http://localhost:8001/api/v1/routes

# Création
curl -b /tmp/jar -X POST -H "Content-Type: application/json" \
  -d '{"host":"vault.example.com","upstreams":[{"url":"http://192.168.1.50:8200","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true}' \
  http://localhost:8001/api/v1/routes

# Mise à jour
curl -b /tmp/jar -X PUT -H "Content-Type: application/json" \
  -d '{...}' http://localhost:8001/api/v1/routes/<route-id>

# Suppression
curl -b /tmp/jar -X DELETE http://localhost:8001/api/v1/routes/<route-id>
```

Auth : le cookie jar (`/tmp/jar`) doit porter une session obtenue via `/api/v1/auth/login` (Content-Type `application/json`, body `{"username","password"}`).

---

## Voir aussi

- [Topology](Topology) — visualiser tes routes comme un graphe live (page EN — pas encore de traduction FR)
- [WAF](WAF) — protéger tes routes contre les attaques OWASP (page EN — pas encore de traduction FR)
- [Custom Error Pages](Custom-Error-Pages-FR) — brander les pages 4xx/5xx par route ; couvre aussi la [page de maintenance](Custom-Error-Pages-FR#page-de-maintenance) globale
- [Rate Limit](Rate-Limit) — throttler les clients abusifs (page EN — pas encore de traduction FR)
- [Country Block](Country-Block) — geo-fencing par route (page EN — pas encore de traduction FR)
- [OIDC SSO](OIDC-SSO) — single sign-on pour les outils d'admin (page EN — pas encore de traduction FR)
