<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Import d'un Caddyfile — Design

**Status:** brainstormé avec l'opérateur 2026-09-22, décisions verrouillées.
Dernier élément de la vague 2 (CaddyUI / NPM : « import »).
Cible : **v2.40.0**.

**One-line :** le bouton « Importer un Caddyfile » de la page Routes (présent
mais désactivé depuis les premières versions, infobulle « pas encore
branché ») ouvre un import en deux temps : analyse et aperçu, puis création
des routes cochées, avec le détail de ce qui n'a pas pu être repris.

## Décisions

| # | Décision | Pourquoi |
|---|----------|----------|
| I1 | **Caddyfile seulement** (coller ou déposer un fichier), analysé avec **le parseur de Caddy** (`caddyconfig/caddyfile.Parse` + `Dispenser`), déjà embarqué. | Choix opérateur ; même lecture que Caddy (jetons, blocs, snippets), pas de parseur maison. |
| I2 | **Importer et signaler** : la route est créée avec ce qui est compris ; l'aperçu liste ligne par ligne ce qui a été ignoré. | Choix opérateur. |
| I3 | **Conflit d'hôte : ignoré par défaut** et marqué « déjà présente » ; une case permet de remplacer. | Choix opérateur ; ne jamais écraser en silence des réglages Arenet (WAF, géo, limites). |
| I4 | **Deux temps** : `preview` n'écrit rien, `import` ne crée que les hôtes cochés. | Un import est irréversible côté Caddy ; l'opérateur voit d'abord. |
| I5 | Import **admin uniquement**, audité par route créée (`route_created`), un seul rechargement Caddy à la fin. | Comme le reste des écritures de routes. |

## Correspondances (v1)

| Caddyfile | Arenet |
|---|---|
| adresses du bloc (`app.example.com, www.example.com`) | `host` = la première, le reste en `aliases` ; `http://` → TLS off ; `https://` ou sans schéma → TLS on |
| `reverse_proxy <upstreams...>` | `upstreams` (poids 1) |
| `reverse_proxy` + `lb_policy` | `lbPolicy` quand la politique existe chez Arenet |
| `health_uri`, `health_interval`, `health_timeout`, `health_status` | `healthCheck` |
| `header_up` / `header_down` | `requestHeaders` / `responseHeaders` |
| `transport http { tls_insecure_skip_verify }` | `insecureSkipVerify` |
| `reverse_proxy /chemin/* <upstreams>`, `handle_path /chemin*`, `handle /chemin*`, `route /chemin*` contenant un `reverse_proxy` | règle par chemin (`pathRules`) avec son propre pool |
| `tls <email>` ou absent | ACME `http-01` |
| `tls { dns <provider> ... }` | ACME `dns-01` + avertissement nommant le fournisseur (ses identifiants ne sont jamais importés) |
| `tls internal` | avertissement (certificat interne non géré par route) |
| `tls <cert> <key>` | avertissement (téléverser le certificat dans Certificats) |
| `encode`, `log` | ignorés en silence (Arenet les gère globalement) |
| `basic_auth` / `basicauth` | avertissement : hachage Caddy (bcrypt) non réutilisable, à ressaisir |
| `redir`, `respond`, `file_server`, `root`, `php_fastcgi`, `templates`, `rewrite`, `forward_auth`, `rate_limit`, autres | avertissement « non repris », avec la ligne |
| bloc d'options globales, `import <fichier>`, snippets non résolus | avertissement en tête du rapport |

Un bloc sans `reverse_proxy` (ni au niveau racine ni dans un `handle`)
n'est pas importable : il est listé, non cochable, avec la raison.

## API

- `POST /routes/import/caddyfile/preview` `{caddyfile}` → `{globalWarnings[],
  candidates[{host, aliases, tlsEnabled, upstreams[], lbPolicy, healthCheck,
  requestHeaders, responseHeaders, insecureSkipVerify, pathRules[],
  acmeChallenge, importable, conflict, warnings[{line, text}]}]}`.
  N'écrit rien.
- `POST /routes/import/caddyfile` `{caddyfile, hosts[], replace[]}` → analyse à
  nouveau (le client ne renvoie pas d'objets), crée / remplace les hôtes
  demandés, **un seul** `ReloadFromStore` ; en cas de refus de Caddy, tout est
  annulé (routes créées supprimées, remplacées restaurées) et 500.
  Réponse : `{created[], replaced[], skipped[{host, reason}]}`.
- 64 Kio de Caddyfile au maximum, 200 blocs.

## UI

Le bouton n'est plus désactivé : il ouvre une fenêtre.
1. Coller le texte ou déposer un `.caddyfile` / `Caddyfile` → **Analyser**.
2. Aperçu : une ligne par bloc (hôte, backends, badges TLS / chemins), case à
   cocher (décochée si non importable), badge « déjà présente » + case
   « remplacer », avertissements dépliables avec le numéro de ligne.
3. **Importer N routes** → toast, fermeture, rechargement de la liste.

FR + EN.

## Tests

Analyse (chaque correspondance du tableau, avertissements avec ligne,
blocs multi-adresses, chemins, Caddyfile invalide → 400), API (aperçu
sans écriture, import partiel, conflit ignoré / remplacé, annulation si
Caddy refuse), front (fenêtre, sélection, avertissements), smoke binaire
réel avec un Caddyfile représentatif.

## Non-goals

- ❌ Nginx / Nginx Proxy Manager (décision opérateur).
- ❌ Export d'un Caddyfile depuis Arenet.
- ❌ Reprise de l'hébergement statique (`file_server`, `php_fastcgi`).
