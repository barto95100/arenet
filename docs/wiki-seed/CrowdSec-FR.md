# CrowdSec

[English](CrowdSec) · **🌐 Français**

[CrowdSec](https://www.crowdsec.net) est un service de réputation IP community-powered : un IDS collaboratif qui laisse tes hosts partager du threat intelligence. Arenet ship un [bouncer CrowdSec](https://github.com/hslatman/caddy-crowdsec-bouncer) natif qui bloque les requêtes depuis les IPs que la communauté CrowdSec a flaguées.

**L'agent CrowdSec lui-même tourne séparément** — en service Linux installé depuis le dépôt CrowdSec, ou en conteneur Docker. Les deux sont couverts ci-dessous. Arenet n'embarque que le *bouncer* : le composant qui interroge l'API locale (LAPI) de l'agent et applique ses décisions.

---

## Architecture

```
┌─────────────────┐       ┌─────────────────┐       ┌──────────────────┐
│  Arenet         │ ────▶ │  CrowdSec       │ ◀──── │  CrowdSec Hub    │
│  (bouncer)      │ LAPI  │  agent          │       │  (blocklists     │
│                 │ LAPI  │  (votre hôte)   │       │   communauté)    │
└─────────────────┘       └─────────────────┘       └──────────────────┘
   │                          │
   │ si IP dans decision      │ scenarios triggerent
   │ → reject avec 403        │ sur les lignes de log parsées
   ▼                          ▼
   Client                     Décisions locales
                              (IPs bannies)
```

L'agent analyse vos journaux locaux (authentification, serveur web…), se déclenche sur des scénarios (force brute, balayage, exploitation) et crée des **décisions** : bannir telle IP pendant tel temps. Le bouncer interroge l'agent toutes les N secondes et applique ces décisions.

Tu reçois aussi des **décisions communauté** gratuitement : l'agent fetch la blocklist curated du hub CrowdSec, des IPs actuellement abusives dans la communauté globale. Effectivement une blocklist temps réel maintenue par des milliers d'opérateurs dans le monde.

---

## Quick start

### 1. Installer et démarrer l'agent CrowdSec

L'agent tourne sur la même machine qu'Arenet, ou sur n'importe quelle
machine qu'Arenet peut joindre. Choisissez la voie qui correspond à la
façon dont Arenet lui-même est installé.

#### Paquet Linux — Arenet en service systemd ou en binaire

```bash
curl -s https://install.crowdsec.net | sudo sh   # ajoute le dépôt CrowdSec
sudo apt install crowdsec                        # Debian / Ubuntu
# sudo yum install crowdsec                      # RHEL / CentOS / Fedora
sudo systemctl enable --now crowdsec
```

Le paquet démarre l'agent et son API locale. Vérifiez qu'elle écoute :

```bash
ss -tlnp | grep 8080
# tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("crowdsec",pid=…))
```

La configuration se trouve dans `/etc/crowdsec/`, la base dans
`/var/lib/crowdsec/data/`. Journaux de l'agent :
`sudo journalctl -u crowdsec -f`.

Voir le [guide d'installation Linux officiel](https://docs.crowdsec.net/u/getting_started/installation/linux/)
pour les autres distributions.

#### Docker — Arenet en conteneur

```bash
docker run -d --name crowdsec \
  -e GID="$(getent group docker | cut -d: -f3)" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /var/log:/var/log:ro \
  -v crowdsec-db:/var/lib/crowdsec/data \
  -v crowdsec-config:/etc/crowdsec \
  -p 127.0.0.1:8080:8080 \
  crowdsecurity/crowdsec
```

Dans les deux cas, l'API locale de l'agent est maintenant sur
`http://127.0.0.1:8080`.

> **Toutes les commandes `cscli` de cette page sont écrites pour
> l'installation par paquet.** Avec l'agent en Docker, préfixez-les par
> `docker exec crowdsec` : `sudo cscli decisions list` devient
> `docker exec crowdsec cscli decisions list`.

### 2. Déclarer le bouncer Arenet

```bash
sudo cscli bouncers add arenet
```

La commande affiche une clé d'API — copiez-la.

### 3. Configure Arenet

1. Sidebar → **Settings** → section **CrowdSec**
2. **LAPI URL** : `http://127.0.0.1:8080` (ou l'adresse de ton agent)
3. **Clé d'API** : collez la clé obtenue à l'étape 2
4. **Bouncer name** : `arenet` (correspond à la registration cscli)
5. **Timeout** : `5s` (défaut ; combien de temps le bouncer attend la réponse LAPI)
6. **Test connection** → devrait retourner ✅
7. **Save**

Le bouncer est actif en une trentaine de secondes. Toute requête entrante dont l'IP source figure dans les décisions courantes de CrowdSec reçoit un **403 Forbidden** avant même d'atteindre le WAF ou les gestionnaires de route.

Depuis la **v2.26.0**, un visiteur bloqué reçoit la **page d'erreur personnalisée** d'Arenet au lieu d'une réponse vide : une décision `ban` sert la page **403** de la route, une décision `throttle` sa page **429** (avec un en-tête `Retry-After` égal à la durée de la décision). C'est la page choisie pour la route dans ses réglages de pages d'erreur, ou celle d'Arenet par défaut — les mêmes pages que pour le filtre IP et les erreurs d'upstream (voir [Pages d'erreur personnalisées](Custom-Error-Pages-FR)).

---

## Ce qui se fait bloquer

Le bouncer applique **les décisions dont l'agent dispose**. Les scénarios installés par défaut (après `cscli scenarios install crowdsecurity/http-cve`, par exemple) couvrent :

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

## Vérifier que l'intégration fonctionne

Bannissez votre propre IP une minute et regardez une route vous refuser.

**1. Trouvez votre adresse — depuis la machine avec laquelle vous allez
naviguer, pas depuis le serveur.**

`curl -s ifconfig.me` lancé *sur l'hôte Arenet* retourne l'adresse
publique **du serveur**, pas celle avec laquelle votre navigateur arrive.
La bannir revient à bannir le serveur. Lancez la commande là où vous
êtes assis :

```bash
curl -s https://ifconfig.me        # sur votre poste, PAS sur le serveur
curl -4 -s https://ifconfig.me     # votre IPv4, précisément
curl -6 -s https://ifconfig.me     # votre IPv6, précisément
```

Si votre navigateur atteint le site en IPv6, bannissez l'adresse IPv6 :
un bannissement sur la mauvaise famille d'adresses ne fait absolument
rien, et c'est la raison la plus fréquente pour laquelle ce test semble
échouer.

**2. Bannissez-la, sur l'hôte Arenet :**

```bash
sudo cscli decisions add --ip <l-adresse-de-l-etape-1> --duration 60s
sudo cscli decisions list          # vérifiez que Scope:Value est bien celle attendue
```

**3. Chargez une de vos routes configurées** depuis cette machine →
**403**. Au bout de 60 s le bannissement expire et la route répond de
nouveau normalement.

> **Un 404 au lieu d'un 403 n'est pas un échec.** Le bouncer s'exécute
> dans la chaîne de chaque route, il ne voit donc que les requêtes qui
> correspondent à une route que vous avez configurée. Tout le reste — un
> hôte inconnu, un chemin qui n'appartient à aucune route — est traité
> par le 404 attrape-tout d'Arenet avant que CrowdSec ne soit consulté.
> Testez sur une route qui existe.

---

## Réglage : que faire quand CrowdSec bloque des utilisateurs légitimes

CrowdSec est communautaire — il arrive qu'une IP soit bannie globalement
pour un comportement que vos propres utilisateurs n'ont pas. Vous avez
deux soupapes.

### Mettre une IP en liste blanche

```bash
sudo cscli decisions delete --ip <ip-de-l-utilisateur>
sudo cscli postoverflows install crowdsecurity/whitelists
# Puis éditer /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
# pour y ajouter l'IP ou le CIDR de l'utilisateur.
# En Docker, ce fichier est dans le volume crowdsec-config :
#   docker exec -it crowdsec vi /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
```

### Désactiver le bouncer sur une route

CrowdSec est aujourd'hui **global** dans Arenet : toutes les routes ou
aucune. Pour l'écarter sur une route précise, il faut soit placer cette
route sur une autre instance d'Arenet, soit mettre les IP source en liste
blanche au niveau de l'agent CrowdSec.

Un toggle CrowdSec par route est dans le backlog V3 ; ouvre une issue si tu trouverais ça utile.

---

## Comportement fallback (LAPI down)

Quand l'agent est injoignable — coupure réseau, plantage, redémarrage — le bouncer **laisse passer par défaut** : les requêtes circulent comme si CrowdSec était désactivé. C'est délibéré (`enable_hard_fails: false`) : le trafic légitime ne doit pas tomber parce que l'agent a une mauvaise journée.

La carte CrowdSec du tableau de bord indique l'état de l'agent (✅ joignable / ⚠️ injoignable, avec l'horodatage du dernier succès). Ajoutez une règle d'[alerte](Alerting) sur `system_health == degraded` pour être prévenu par Discord ou courriel quand l'agent décroche.

---

## See also

- [WAF](WAF-FR) — defense en couches ; le WAF catche ce que CrowdSec ne catche pas
- [Country Block](Country-Block-FR) — couche geo-fence au-dessus de CrowdSec
- [Alerting](Alerting) — pager quand l'agent est down
- [Docs officielles CrowdSec](https://docs.crowdsec.net) — install agent, scenarios, hub
- [hslatman/caddy-crowdsec-bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer) — le module Caddy qu'Arenet utilise
- `internal/crowdsec/` — wrapping d'Arenet (sink, adaptateur d'observabilité)
