# Listes d'autorisation

[English](Allowlists) · **🌐 Français**

**Depuis v2.85.0.** Les listes d'autorisation AreNET exemptent des IP/CIDR de
confiance des bans émis par **AreNET Security Automation** (décisions d'origine
`arenet`). Utilisez-les pour les sondes uptime, les plages de bureau ou les
scanners internes — tout ce qui peut déclencher une règle WAF / throttle / auth
mais ne doit jamais être banni automatiquement.

---

## Où

**Barre latérale → Sécurité → Allowlists** (`/security/allowlists`). Le rôle
admin est requis pour créer, éditer ou supprimer ; les viewers peuvent lire.

## Contenu d'une liste

- **Nom** + description facultative (un slug stable est dérivé du nom).
- **Entrées** — une IP ou un CIDR par ligne. Une IP nue devient `/32` (IPv4) ou
  `/128` (IPv6). Une note facultative peut suivre l'adresse après un espace.
- **Portée** — trois cases, toutes cochées par défaut :
  - **Block** — exempte des bans WAF (`arenet/waf-*`).
  - **Throttle** — exempte des bans throttle (`arenet/throttle-tier*`).
  - **Audit** — exempte des bans auth (`arenet/auth-*`).
- **Active** — une liste inactive n'exempte personne (conservée, pas supprimée).

Quand une IP allowlistée aurait été bannie automatiquement, AreNET journalise en
INFO :

```
automation: ban skipped (allowlisted) src_ip=198.51.100.10 scenario=arenet/waf-rce
```

Les changements prennent effet immédiatement — pas de redémarrage.

## ⚠️ Limitation — origin=arenet uniquement

La liste d'autorisation AreNET ne couvre **que** les bans émis par AreNET
Security Automation (`origin=arenet`). Elle n'affecte **pas** les décisions
CrowdSec natives, la Community Blocklist, ni les bans ajoutés via `cscli`. Pour
exempter une IP de ceux-ci, utilisez `cscli allowlist` côté CrowdSec.

C'est voulu : AreNET applique l'exemption dans son propre trigger, avant de
pousser vers la LAPI. CrowdSec n'a pas d'API **write** d'allowlist publiée, donc
un design « CrowdSec source de vérité » n'est pas constructible aujourd'hui.

## Stockage & sauvegarde

Les listes vivent dans un fichier SQLite dédié, `data/security.db`, séparé du
`metrics.db` purgé par rétention. S'il ne peut pas être ouvert au boot, AreNET
est **fail-closed** : aucune exemption ne s'applique (l'automation continue de
bannir) et un WARN est journalisé.
