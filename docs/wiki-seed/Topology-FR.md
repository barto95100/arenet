# Topology

[English](Topology) · **🌐 Français**

La page `/topology` rend tes routes en **graphe live force-directed** avec des particules de trafic en temps réel qui flow des clients vers les upstreams. SvelteKit + [Svelte Flow](https://svelteflow.dev) pour le graphe, D3.js pour les particle physics, WebSocket pour le feed de données live.

Utile pour : vérification at-a-glance que chaque route est healthy, debug visuel des patterns de trafic, démos pour les stakeholders non-techniques.

---

## Ce que tu vois

```
              ┌──────────┐
              │ Internet │
              └────┬─────┘
                   │ (particules flow ici = requêtes inbound)
              ┌────▼─────┐
              │  Caddy   │  ← node hub central
              └────┬─────┘
                   │
       ┌───────────┼───────────┐
       │           │           │
   ┌───▼──┐   ┌───▼──┐   ┌───▼──┐
   │ FQDN │   │ FQDN │   │ FQDN │  ← un node par host primaire de route
   │route1│   │route2│   │route3│
   └───┬──┘   └───┬──┘   └───┬──┘
       │          │          │
       │  (aliases clusterent dans un "container" si N>0)
       │          │          │
   ┌───▼──┐   ┌───▼──┐   ┌───▼──┐
   │ Pool │   │ Pool │   │ Pool │  ← backends upstream, un cluster par route
   └──────┘   └──────┘   └──────┘
```

Chaque connexion (edge) porte des **particules animées** dont la densité est proportionnelle aux req/s. Une route servant 100 req/s montre ~10x plus de particules qu'une route servant 10 req/s.

---

## Types de nodes

| Node | Sens |
| ---- | ---- |
| **Caddy Hub** | Le node central, sizé par le total req/s agrégé sur toutes les routes |
| **FQDN** | Le host primaire d'une route. Color-codé par status (vert=healthy, dim=idle, rouge=upstream down) |
| **Alias** | Un hostname alias d'une route. Visuellement clusterisé dans un container "RouteGroup" avec son FQDN primaire |
| **Backend Cluster / Upstream** | Le pool upstream de la route. Un node par URL d'upstream dans le pool ; clusterisé visuellement en "pool" |

Les nodes idle (pas de trafic dans les N dernières secondes) apparaissent en **dimmed state** — surface toujours rendue, juste visuellement reculée. Assure-toi que tes tokens de thèmes light + dark sont populés (voir [Troubleshooting](Troubleshooting) si les nodes idle apparaissent dark sur thème light — c'était un hotfix v2.8.4).

---

## Feed de données live

La page subscribe à un WebSocket sur `/api/v1/topology/stream` qui push des updates par seconde :

```json
{
  "ts": "2026-06-24T07:30:00Z",
  "routes": [
    { "id": "uuid-1", "host": "vault.example.com", "reqPerSec": 12.3, "upstreamHealthy": [true] },
    { "id": "uuid-2", "host": "ha.example.com", "reqPerSec": 0.5, "upstreamHealthy": [true] },
    ...
  ],
  "hub": { "reqPerSec": 12.8 }
}
```

La boucle de rendu D3.js lit les updates et ajuste la densité des particules en temps réel. Cible ~60fps.

---

## Interactions

- **Drag d'un node** : repositionne manuellement ; le force layout re-stabilise
- **Click sur un node** : sélectionne + highlight ses edges
- **Double-click sur un container RouteGroup** : collapse/expand le cluster d'aliases (pratique quand une route a 20+ aliases)
- **Scroll** : zoom in/out
- **Right-click** (prévu) : menu contextuel avec "Edit route" / "View security events" / "Test connection"

---

## Considérations de performance

- Les particle physics tournent dans le navigateur ; ~50 routes avec 10 req/s en moyenne chacune est confortable sur un laptop moderne (Chrome / Firefox / Safari)
- Feed WebSocket throttlé server-side à 1Hz (une update par seconde) ; le smoothing graphique sub-seconde est client-side
- Mobile : la page se rend mais les interactions (drag, zoom) sont clunky en touch. Le mobile est officiellement read-only dès v2.9.x.

---

## Quand le graphe a l'air faux

| Symptôme | Cause probable | Fix |
| -------- | -------------- | --- |
| Tous les nodes idle même avec du trafic live | Connexion WebSocket droppée | Refresh la page ; check la console navigateur pour les erreurs WS |
| Toutes les edges d'un FQDN sont rouges | Upstream marqué unhealthy par les health checks actifs | Check `/observability/<routeId>` ; vérifie que l'upstream est reachable + que l'URI HC retourne le status attendu |
| Aliases qui ne clusterent pas dans le FQDN parent | Refresh de route après édit récent | Refresh la page ; le layout recompute au prochain tick de données |
| Nodes apparaissent dark sur thème light | Token de thème manquant | Était un hotfix v2.8.4 ; si tu vois ça sur une version plus récente, [ouvre une issue](https://github.com/barto95100/arenet/issues) |
| Les particules ne flow pas sur une route que je viens de créer | Cold-start : pas encore de data req/s | Envoie quelques requêtes à la route ; les particules devraient apparaître en 5s |

---

## Référence API (read-only)

```bash
# Snapshot de l'état topologique courant (pas de WebSocket)
curl -b /tmp/jar http://localhost:8001/api/v1/topology/snapshot

# Métriques par host agrégées sur les N dernières secondes
curl -b /tmp/jar "http://localhost:8001/api/v1/metrics/per-host?windowSecs=60"
```

Le stream WebSocket est auth-gated via le même cookie de session ; pas de token séparé.

---

## See also

- [Routes](Routes-FR) — où tu crées les routes qui apparaissent sur le graphe
- [`docs/api/topology.md`](https://github.com/barto95100/arenet/blob/main/docs/api/topology.md) — protocole WebSocket complet + shape JSON
- `internal/api/topology/` — agrégateur backend par host
- `web/frontend/src/routes/topology/` — la page SvelteKit + composants Svelte Flow
