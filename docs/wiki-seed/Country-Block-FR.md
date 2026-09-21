# Country Block

[English](Country-Block) · **🌐 Français**

Filtrage géographique par route utilisant la base **MaxMind GeoLite2-City**. Allow-list ou deny-list de n'importe quelle combinaison de codes pays ISO 3166 pour n'importe quelle route.

À utiliser quand : l'audience visée par ton homelab est géographiquement bornée (ex. services famille France-only) et tu veux dropper le trafic hors de la bulle avant qu'il n'atteigne le WAF ou ton backend.

---

## Quick start

1. Sidebar → **Routes** → clique ta route → **Edit**
2. Déploie la section **Pays bloqués** (Country Block)
3. Choisis un mode :
   - **Désactivé** (off) — défaut, pas de filtrage
   - **Allow** — seulement les pays listés peuvent accéder
   - **Deny** — les pays listés sont bloqués, tout le monde passe
4. Tape un nom de pays dans l'autocomplete (ex. `France`, `Brazil`) — les picks résolvent en codes ISO (`FR`, `BR`) ; chaque suggestion et chaque chip affiche le drapeau du pays (v2.22.0)
5. Clique chaque entrée pour l'ajouter à la liste de chips ; clique le ✕ du chip pour retirer
6. **Save**

En 5s le filtre pays est actif. Les requêtes depuis les pays bloqués reçoivent **403 Forbidden** avec la page d'erreur brandée de la route (ou la page d'erreur Arenet par défaut).

---

## Continents et exceptions (v2.27.0)

La section s'appelle désormais **Filtrage géographique**. À côté des pays, tu peux :

- **Cocher des continents** (Europe, Asie, Afrique, Amérique du Nord, Amérique du Sud, Océanie, Antarctique). Un continent compte exactement comme un pays de la liste : en **Deny** ses visiteurs sont bloqués, en **Allow** seuls les pays *et* continents listés passent.
- En mode **Deny**, ajouter des **exceptions** : des pays **toujours autorisés**, même dans un continent bloqué — ex. *bloquer l'Asie, sauf le Japon*.

| Configuration | Tokyo | Pékin | Paris | New York |
| ------------- | ----- | ----- | ----- | -------- |
| Deny **Asie** | 403 | 403 | ✓ | ✓ |
| Deny **Asie**, exception **Japon** | ✓ | 403 | ✓ | ✓ |
| Allow **Europe** | 403 | 403 | ✓ | 403 |

Règles : les exceptions n'existent qu'en mode Deny (l'API les refuse sinon), un pays ne peut pas être à la fois bloqué et en exception, et une liste Allow exige au moins un pays **ou** un continent. Le continent vient de la même base GeoLite2-City — rien de plus à installer. Les requêtes bloquées sont journalisées avec le pays résolu, comme avant.

---

## Quand utiliser Allow vs Deny

| Stratégie | Idéal pour |
| --------- | ---------- |
| **Allow** (whitelist) | Services personnels / famille, domotique, outils d'admin internes — ton audience EST géographiquement bornée |
| **Deny** (blacklist) | Services publics avec audience globale mais des régions connues comme mauvaises que tu veux dropper |

Allow est plus safe (posture default-deny). Deny est plus permissif mais plus facile à maintenir (pas de risque de te locker out accidentellement quand tu voyages — ajoute juste ton pays transient temporairement).

---

## Comment la résolution pays fonctionne

Pour chaque requête :

1. Get l'IP source (après trust X-Forwarded-For si configuré)
2. Look up l'IP dans la DB MaxMind GeoLite2-City
3. Match le code pays résolu contre la liste allow/deny de la route
4. Décision : pass-through ou 403

La DB MaxMind est **fournie par l'opérateur**, pas embarquée dans le binaire : Arenet la lit au chemin indiqué par `ARENET_GEOIP_MMDB` (défaut `/var/lib/arenet/GeoLite2-City.mmdb`). Une fois chargée, les lookups sont locaux — pas d'appel API externe, pas de coût réseau par requête. Voir [Réglages → GeoIP](#update-de-la-base-geolite2) plus bas pour mettre le fichier en place, y compris le téléchargement automatique.

---

## Ce qui se fait bloquer

Le block fire **avant les handlers WAF et reverse-proxy** dans la chain. Une requête bloquée :
- Retourne 403 Forbidden
- Émet une ligne `decision_event` (visible dans `/security/decisions`)
- Ne compte PAS contre les rate limits (elle ne les atteint jamais)
- N'apparaît PAS dans les événements WAF (elle n'atteint jamais Coraza)

---

## Edge cases

### IP inconnue (privée, réservée, CGNAT)

Le GeoLite2 de MaxMind ne couvre pas les IPs privées (RFC1918), réservées, ou CGNAT. Pour celles-ci, le code pays résout à `""` (vide).

**Mode Allow** : pays vide est **rejeté** (l'IP n'est pas dans la liste allow). Comportement utile pour les routes publiques — des IPs de range privé atteignant une route publique est suspect.

**Mode Deny** : pays vide est **passé** (pas dans la liste deny).

Si ta route est censée être LAN-only ET que tu veux autoriser les ranges privés en mode Allow, le workaround est de bind cette route à un listener spécifique sur l'interface LAN uniquement (avancé, pas exposé UI). Le pattern standard est de garder les routes LAN-only entièrement hors du listener public.

### IPv6

Entièrement supporté — MaxMind GeoLite2 couvre les ranges IPv6.

### Proxies anonymes / VPNs

Le GeoLite2 gratuit de MaxMind ne flag pas les proxies anonymes. Si tu as besoin de ça, la [DB MaxMind GeoIP2 Anonymous IP payante](https://www.maxmind.com/en/geoip2-anonymous-ip-database) s'intègre séparément (pas exposée actuellement dans l'UI Arenet ; config manuelle requise).

Pour la plupart des cas d'usage homelab, layerer Country Block + [CrowdSec](CrowdSec-FR) (qui DOES flag les nodes de sortie VPN connus via scenarios communauté) te donne ~90% de la valeur d'une DB anonymous-IP payante.

---

## Observabilité

Chaque requête bloquée émet un `decision_event` avec `origin=country_block`. La page `/security/decisions` filtre ces événements. Le `/logs` unifié les montre avec le badge COUNTRY.

La **GeoIP World Map** du dashboard visualise la distribution live du trafic bloqué par pays — utile pour comprendre ce que tes routes voient sans plonger dans les événements individuels.

---

## Référence API

```bash
# Update le country block d'une route via API
curl -b /tmp/jar -X PUT -H "Content-Type: application/json" \
  -d '{
    ...other route fields...,
    "countryBlock": {
      "mode": "allow",
      "countryList": ["FR", "BE", "CH", "LU"]
    }
  }' \
  http://localhost:8001/api/v1/routes/<route-id>
```

Modes disponibles : `"off"` (ou vide), `"allow"`, `"deny"`. Les codes pays sont 2-letter ISO 3166-1 alpha-2, uppercase.

---

## Update de la base GeoLite2

La base est **fournie par l'opérateur**, pas embarquée dans le binaire Arenet. Arenet la lit depuis `ARENET_GEOIP_MMDB` (défaut `/var/lib/arenet/GeoLite2-City.mmdb`) — à toi d'y placer un fichier `.mmdb` et de le garder à jour.

Le plus simple est **Réglages → GeoIP** : saisis ton [account ID + license key MaxMind](https://www.maxmind.com/en/accounts/current/license-key) (gratuits), puis active la mise à jour automatique hebdomadaire ou clique **Mettre à jour maintenant** pour télécharger/rafraîchir la base immédiatement. Arenet stocke les identifiants, télécharge la DB au chemin configuré et la recharge sans redémarrage.

Si tu préfères gérer le fichier toi-même (pas de compte MaxMind, host air-gapped, etc.), dépose manuellement un `GeoLite2-City.mmdb` au chemin configuré — Arenet prend en compte les changements de ce fichier sans avoir besoin de la mise à jour automatique.

---

## See also

- [Routes](Routes-FR) — où trouver la section Country Block dans l'UI
- [CrowdSec](CrowdSec-FR) — réputation IP communautaire, layered avec country blocking
- [WAF](WAF-FR) — détection d'attaque layer 7 après pass-through country + CrowdSec
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) — la base upstream
- `internal/countryblock/` — implémentation Arenet
- `internal/geo/` — lecteur MaxMind (rechargeable à chaud) + lookup IP
