<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Services TCP / UDP (niveau 4)

[English](TCP-Services) · **🌐 Français**

Une **route** relaie du HTTP : Arenet termine le TLS, lit la requête, applique le WAF, choisit un backend. Un **service TCP / UDP** fait tout autre chose — il transfère des octets sans les lire. Arenet ne déchiffre jamais ce trafic : le chiffrement est négocié de bout en bout entre le client et le backend.

C'est ce qui le rend utile pour tout ce que le HTTP ne sait pas porter : un serveur de messagerie, une base de données, SSH, RDP, WireGuard, DNS, syslog, un serveur de jeu.

---

## Ce qui s'applique et ce qui ne s'applique pas

| | Route (HTTP) | Service TCP / UDP |
|---|---|---|
| WAF, règles guidées, SecLang | ✅ | ❌ |
| Pages d'erreur, page de maintenance | ✅ | ❌ |
| Blocage par pays | ✅ | ❌ |
| Règles par chemin, en-têtes | ✅ | ❌ |
| Filtrage d'IP source | ✅ | ✅ |
| Décisions CrowdSec | ✅ | ✅ |
| Contrôle de santé | requête HTTP | connexion TCP (pas en UDP) |
| Certificats | portés par Arenet | portés par le **backend** |

Le formulaire le dit aussi. Un relais n'est pas une route avec moins d'options : c'est autre chose.

---

## En créer un

**Services TCP / UDP → + Nouveau service**. Pars d'un modèle : il remplit le protocole, le port standard, et — c'est ce qui compte — **si le service doit être joignable de partout**.

PostgreSQL, MySQL, Redis, MongoDB, SSH, RDP, VNC, DNS et syslog arrivent avec le **filtrage d'IP source déjà armé** : une base de données ouverte sur Internet est exactement l'erreur que ces modèles existent pour empêcher. Le courrier entrant arrive avec le filtre **désactivé**, parce que le restreindre reviendrait à refuser le courrier des autres serveurs.

Renseigne ensuite le backend (`hôte:port`) et enregistre. L'adresse d'écoute est vérifiée **avant** tout enregistrement : un port dont Arenet a besoin est refusé nommément, un port déjà pris par un autre service est refusé en nommant les deux, et un port sous 1024 que le processus ne peut pas ouvrir est refusé avec la ligne exacte à ajouter à l'unité systemd.

---

## Le PROXY protocol — à lire

Sans lui, **ton backend voit l'adresse d'Arenet à la place de celle du client**. Sur un serveur de messagerie, ça casse les vérifications SPF, rend l'antispam aveugle et vide de sens les limites par IP. Ailleurs, ça ruine tes journaux et tes propres bannissements.

Arenet envoie l'en-tête quand tu choisis **v2** (ou v1, en TCP seulement — la v1 ne transporte pas d'adresse UDP).

**Le backend doit être configuré pour l'attendre**, et c'est là le piège : si un seul des deux côtés est réglé, **les connexions échouent en silence**. Aucun des deux ne signale d'erreur ; ça ne marche simplement pas.

| Backend | Ce qu'il faut régler |
|---|---|
| Stalwart | `proxyTrustedNetworks` = l'IP d'Arenet (Settings → Network) |
| HAProxy | `accept-proxy` sur la ligne `bind` |
| NGINX | `proxy_protocol` sur la ligne `listen`, plus `set_real_ip_from` |
| Postfix | `postscreen_upstream_proxy_protocol = haproxy` |
| Dovecot | `haproxy_trusted_networks` + `haproxy = yes` sur l'écouteur |

Le formulaire affiche l'adresse à déclarer, et le bouton **Tester les backends** ouvre une vraie connexion pour vérifier l'autre bout avant de faire confiance au relais. Un test réussi prouve que le backend accepte les connexions — il ne peut pas prouver qu'il attend l'en-tête, d'où la note qui reste affichée.

---

## Publier le port

**Installation native.** L'unité systemd embarque `AmbientCapabilities=CAP_NET_BIND_SERVICE`, donc les ports sous 1024 fonctionnent d'emblée. Si tu as écrit ta propre unité, ajoute cette ligne — Arenet te le dira au moment où tu essaieras.

**Docker.** Un relais écoute **à l'intérieur** du conteneur : le port doit donc aussi être publié dans `docker-compose.yml`. Sans ça, le service s'affiche en vert dans l'interface et rien ne l'atteint jamais :

```yaml
ports:
  - "993:993"          # IMAPS
  - "51820:51820/udp"  # WireGuard — noter le /udp
```

---

## Le surveiller

Le trafic de niveau 4 ne traverse aucune chaîne HTTP : il n'apparaît dans aucune métrique de route, aucune ligne de journal, aucune tuile du tableau de bord. La colonne **Trafic** de la liste est la vue : connexions acceptées, connexions ouvertes en ce moment, octets dans chaque sens, et connexions que le relais n'a pas pu mener à bien — presque toujours un backend qui refuse ou qui ne répond pas.

Les mêmes compteurs sont disponibles sur `GET /api/v1/tcp-services/metrics`.

---

## Cas concret : un serveur de messagerie sur une autre machine

Stalwart (ou Postfix + Dovecot) sur une VM d'un autre réseau, Arenet devant.

**Les ports.** Le 25 pour le courrier qui arrive des autres serveurs — ce n'est jamais un port client. Le 465 et le 993 pour les téléphones et Outlook, en TLS implicite. Le 587 pour les clients qui font encore du STARTTLS. Le 4190 pour ManageSieve, restreint à ton LAN ou à ton VPN.

**Les certificats restent sur le serveur de messagerie**, puisque Arenet ne déchiffre pas. Mais Arenet occupe le port 80, donc un renouvellement HTTP-01 depuis le serveur de messagerie ne peut pas aboutir seul. Deux sorties : du DNS-01 côté serveur de messagerie, ou une **route** Arenet pour le nom d'hôte du mail, avec une règle par chemin qui lui envoie `/.well-known/acme-challenge/*`.

**Le courrier sortant ne passe pas par Arenet.** Un relais de niveau 4 ne porte que l'entrant. Ton enregistrement MX pointe sur l'IP d'Arenet, mais **le SPF et le reverse DNS doivent couvrir l'adresse par laquelle le serveur de messagerie sort**. Se tromper là-dessus envoie ton courrier en indésirable pendant des semaines sans cause évidente.

---

## Cas concret : une base de données joignable depuis le LAN

PostgreSQL sur une autre machine, atteignable depuis ton poste à travers Arenet.

Prends le modèle : il arrive avec le filtrage armé. Mets-y ta plage LAN (`192.168.1.0/24`). Laisse le PROXY protocol désactivé, sauf si ton PostgreSQL est configuré pour — contrairement au mail, rien ici ne dépend de voir l'IP du client.

Active le contrôle de santé : au niveau 4 c'est une connexion TCP, et c'est exactement comme ça que tu apprendras que la base ne répond plus.

Et garde en tête ce que dit le formulaire : **aucun WAF ne protège ceci**. La barrière, c'est le filtrage d'IP source et CrowdSec, rien d'autre.
