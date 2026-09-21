# CrowdSec

[English](CrowdSec) · **🌐 Français**

[CrowdSec](https://www.crowdsec.net) est un service de réputation IP community-powered : un IDS collaboratif qui laisse tes hosts partager du threat intelligence. Arenet ship un [bouncer CrowdSec](https://github.com/hslatman/caddy-crowdsec-bouncer) natif qui bloque les requêtes depuis les IPs que la communauté CrowdSec a flaguées.

**L'agent CrowdSec lui-même tourne séparément** (typiquement comme un container Docker ou service systemd sur le même host). Arenet embarque uniquement le *bouncer* — le composant qui query la Local API (LAPI) de l'agent et enforce les décisions.

---

## Architecture

```
┌─────────────────┐       ┌─────────────────┐       ┌──────────────────┐
│  Arenet         │ ────▶ │  CrowdSec       │ ◀──── │  CrowdSec Hub    │
│  (bouncer)      │ LAPI  │  agent          │       │  (blocklists     │
│                 │ poll  │  (ton host)     │       │   communauté)    │
└─────────────────┘       └─────────────────┘       └──────────────────┘
   │                          │
   │ si IP dans decision      │ scenarios triggerent
   │ → reject avec 403        │ sur les lignes de log parsées
   ▼                          ▼
   Client                     Décisions locales
                              (IPs bannies)
```

L'agent parse tes logs locaux (auth, serveur web, etc.), trigger sur des scenarios (brute-force, scanning, exploitation), et crée des **décisions** (ban X pour Y minutes). Le bouncer poll l'agent toutes les N secondes et enforce.

Tu reçois aussi des **décisions communauté** gratuitement : l'agent fetch la blocklist curated du hub CrowdSec, des IPs actuellement abusives dans la communauté globale. Effectivement une blocklist temps réel maintenue par des milliers d'opérateurs dans le monde.

---

## Quick start

### 1. Install + run l'agent CrowdSec

Run l'agent sur le même host qu'Arenet (ou un host LAN reachable). Docker est le plus facile :

```bash
docker run -d --name crowdsec \
  -e GID="$(getent group docker | cut -d: -f3)" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /var/log:/var/log:ro \
  -v crowdsec-db:/var/lib/crowdsec/data \
  -v crowdsec-config:/etc/crowdsec \
  -p 8080:8080 \
  crowdsecurity/crowdsec
```

La LAPI de l'agent est maintenant sur `http://<host>:8080`.

### 2. Enregistre le bouncer Arenet

```bash
docker exec crowdsec cscli bouncers add arenet
```

La commande print une API key — copie-la.

### 3. Configure Arenet

1. Sidebar → **Settings** → section **CrowdSec**
2. **LAPI URL** : `http://127.0.0.1:8080` (ou l'adresse de ton agent)
3. **API key** : colle la key de l'étape 2
4. **Bouncer name** : `arenet` (correspond à la registration cscli)
5. **Timeout** : `5s` (défaut ; combien de temps le bouncer attend la réponse LAPI)
6. **Test connection** → devrait retourner ✅
7. **Save**

En ~30 secondes le bouncer est actif. Toute requête inbound dont l'IP source est dans la decision list actuelle de CrowdSec retourne **403 Forbidden** avant d'atteindre le WAF / les handlers de route.

Depuis la **v2.26.0**, un visiteur bloqué reçoit la **page d'erreur personnalisée** d'Arenet au lieu d'une réponse vide : une décision `ban` sert la page **403** de la route, une décision `throttle` sa page **429** (avec un en-tête `Retry-After` égal à la durée de la décision). C'est la page choisie pour la route dans ses réglages de pages d'erreur, ou celle d'Arenet par défaut — les mêmes pages que pour le filtre IP et les erreurs d'upstream (voir [Pages d'erreur personnalisées](Custom-Error-Pages-FR)).

---

## Ce qui se fait bloquer

Le bouncer enforce **les décisions que l'agent a**. Les scenarios par défaut (après `cscli scenarios install crowdsecurity/http-cve` etc.) incluent :

- Brute-force sur SSH / pages d'auth web
- Scanning (nmap, masscan, scanners web vuln)
- Tentatives d'exploit connues (scenarios tagués CVE)
- Blocklist communauté : IPs actuellement abusives à travers le réseau CrowdSec

Tu peux étendre avec des scenarios custom — voir [docs CrowdSec](https://docs.crowdsec.net/docs/scenarios/intro).

---

## Observabilité

Chaque block CrowdSec émet une ligne `decision_event` dans la table SQLite `decision_event` :

- `ts` — timestamp
- `src_ip` — IP bannie
- `reason` — nom du scenario (ex. `crowdsecurity/http-bf`)
- `duration` — longueur du ban
- `origin` — `local` (scenarios de ton agent) ou `crowdsec` (blocklist communauté)

La page `/security/decisions` rend ces événements avec filtre par origin + scenario + temps. Le `/logs` unifié les montre à côté des événements WAF / auth / rate-limit.

---

## Vérifier que l'intégration est live

```bash
# Trouve une IP actuellement bannie dans la decision list de ton agent
docker exec crowdsec cscli decisions list

# Choisis une IP de l'output, puis essaie de hit n'importe laquelle de tes routes depuis cette IP
# (ou, plus facile, run depuis une VM avec cette IP)
# Attendu : la route retourne 403 avant d'atteindre le WAF
```

Tu peux aussi bannir manuellement ta propre IP pour une minute comme smoke test :

```bash
docker exec crowdsec cscli decisions add --ip "$(curl -s ifconfig.me)" --duration 60s
```

Essaie de hit n'importe quelle route depuis chez toi → 403. Après 60s le ban expire, la route fonctionne à nouveau.

---

## Tuning : que faire quand CrowdSec bloque des users légitimes

CrowdSec est communautaire — parfois une IP se fait bannir globalement pour un comportement que tes users locaux ne font pas. Tu as deux soupapes de sécurité :

### Whitelist une IP spécifique

```bash
docker exec crowdsec cscli decisions delete --ip <your-user-ip>
docker exec crowdsec cscli postoverflows install crowdsecurity/whitelists
# Puis édite /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
# pour ajouter l'IP / CIDR de ton user
```

### Désactiver le bouncer par route

Actuellement CrowdSec est **global** dans Arenet (toutes les routes ou aucune). Si tu as besoin de bypass sur une route spécifique, le workaround est de mettre cette route sur une instance Arenet différente OU de whitelister les IPs source à la couche agent CrowdSec.

Un toggle CrowdSec par route est dans le backlog V3 ; ouvre une issue si tu trouverais ça utile.

---

## Comportement fallback (LAPI down)

Quand l'agent est unreachable (blip réseau, crash agent, restart), le bouncer **fail open par défaut** — les requêtes passent comme si CrowdSec était désactivé. C'est le contrat de degraded-mode AC #13 : le client LAPI propre d'Arenet ne bloque jamais du trafic légitime parce que l'agent a une mauvaise journée.

La card CrowdSec du dashboard montre le status de l'agent (✅ reachable / ⚠️ unreachable + timestamp du dernier success). Câble une règle d'[Alerting](Alerting) sur `system_health == degraded` pour recevoir un ping Discord/email quand l'agent drop.

---

## See also

- [WAF](WAF-FR) — defense en couches ; le WAF catche ce que CrowdSec ne catche pas
- [Country Block](Country-Block-FR) — couche geo-fence au-dessus de CrowdSec
- [Alerting](Alerting) — pager quand l'agent est down
- [Docs officielles CrowdSec](https://docs.crowdsec.net) — install agent, scenarios, hub
- [hslatman/caddy-crowdsec-bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer) — le module Caddy qu'Arenet utilise
- `internal/crowdsec/` — wrapping d'Arenet (sink, adaptateur d'observabilité)
