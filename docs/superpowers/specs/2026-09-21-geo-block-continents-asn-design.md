<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Filtrage géographique : continents, ASN et exceptions — Design

**Status:** brainstormé avec l'opérateur 2026-09-21 (maquettes validées),
décisions verrouillées. Vague 1 de l'analyse concurrentielle (Caddy Proxy
Manager bloque par pays / continent / ASN / CIDR avec des règles allow
prioritaires). Livraison en **deux PR** :

- **PR A — v2.27.0** : continents + exceptions pays (aucune nouvelle base).
- **PR B — v2.28.0** : ASN (base GeoLite2-ASN, mise à jour auto, index des
  noms, recherche, bloc UI, exceptions ASN).

**One-line:** La section « Pays bloqués » d'une route devient « Filtrage
géographique » : un mode (Désactivé / Allow / Deny) appliqué à trois listes
— continents, pays, ASN — plus, en mode Deny, des **exceptions** qui passent
toujours.

## Décisions (brainstorm)

| # | Décision | Pourquoi |
|---|----------|----------|
| D1 | **3 blocs dans une section** : Continents (7 cases), Pays (autocomplete actuel), ASN (autocomplete). | Chaque type a la saisie qui lui va ; tout est visible d'un coup d'œil (maquette validée). |
| D2 | **Un mode + des exceptions** : le mode s'applique aux 3 listes ; en **Deny**, une liste d'exceptions (pays, ASN) est toujours autorisée et gagne sur tout. | « Tout l'Asie sauf le Japon », « DigitalOcean sauf mon VPS ». Modèle de Caddy Proxy Manager. |
| D3 | **Recherche ASN par nom ou numéro** (« ovh », « 16276 » → AS16276 OVH SAS). | Personne ne connaît les numéros par cœur. |
| D4 | Exceptions **uniquement en mode Deny** (bloc masqué sinon). | En Allow, une exception = une entrée de plus dans la liste ; inutile et source de confusion. |
| D5 | Exceptions = **pays + ASN** (pas de continent). | Les cas réels excluent un pays d'un continent ou un réseau d'un bloc ; « Deny Europe sauf Asie » n'a pas de sens. |

## Faits vérifiés

1. La base actuelle **GeoLite2-City** contient le continent de chaque IP
   (`geoip2.City.Continent.Code`, `oschwald/geoip2-golang v1.9.0`) → PR A ne
   demande aucune nouvelle base. Codes : `AF AN AS EU NA OC SA`.
2. L'ASN est dans une **base séparée, GeoLite2-ASN** (même compte MaxMind,
   même clé de licence, gratuite) : `geoip2.Reader.ASN(ip)` →
   `AutonomousSystemNumber`, `AutonomousSystemOrganization`.
3. Le téléchargeur (`internal/geoipupdate/updater.go:345`) ne gère qu'**une**
   édition et **rejette** explicitement les bases non-City (garde
   d'édition) → PR B l'étend à une seconde édition avec sa propre garde.
4. Le module `arenet_country_block` résout le pays via l'interface
   `CountryLookup` (`internal/countryblock/module.go:54`) ; la décision
   (`matcher.go:90 Evaluate`) suit des couches ordonnées : IP de confiance →
   LAN → mode off → GeoIP indisponible (fail-open, AC #18 de l'étape W) →
   mode.
5. `maxminddb-golang` permet d'itérer tous les réseaux d'une base
   (`Reader.Networks()`) → index ASN → nom construit au chargement.

## 1. Modèle (`countryblock.Config`)

Champs ajoutés, tous `omitempty` → **aucune migration** : une route
existante se comporte à l'identique et émet le même JSON Caddy.

```go
type Config struct {
    Mode        Mode     `json:"mode"`
    CountryList []string `json:"countryList"`
    Continents  []string `json:"continents,omitempty"`  // PR A — AF AN AS EU NA OC SA
    ASNs        []uint32 `json:"asns,omitempty"`        // PR B
    Exceptions  *Exceptions `json:"exceptions,omitempty"` // PR A (pays), PR B (ASN)
    StatusCode  int      `json:"statusCode,omitempty"`
}

type Exceptions struct {
    Countries []string `json:"countries,omitempty"`
    ASNs      []uint32 `json:"asns,omitempty"` // PR B
}
```

Validation :
- continents ∈ les 7 codes, sans doublon ; ASN ∈ [1, 4294967295], sans doublon ;
- **Allow avec les 3 listes vides** → rejeté (même garde-fou que
  `ErrAllowListEmpty`, étendu aux 3 listes) ;
- **exceptions non vides hors mode Deny** → rejeté (D4) ;
- un pays à la fois dans la liste et dans les exceptions → rejeté
  (incohérent).

## 2. Évaluation (`Evaluate`)

L'IP est résolue une seule fois en `{country, continent, asn}`. Couches :

1. IP de confiance → accepté (inchangé).
2. LAN / loopback → accepté (inchangé).
3. Mode off → accepté (inchangé).
4. **Deny + exception** : pays ∈ exceptions.countries **ou** asn ∈
   exceptions.asns → accepté, raison `exception`.
5. Correspondance = continent ∈ continents **ou** pays ∈ countryList **ou**
   asn ∈ asns.
   - Deny : correspondance → bloqué (`deny-match`), sinon accepté.
   - Allow : correspondance → accepté (`allow-match`), sinon bloqué.
6. **GeoIP indisponible** : si aucune info n'est résolue pour les types
   configurés → accepté (`lookup-failed`, fail-open comme aujourd'hui).
   Une base ASN absente n'empêche pas les règles pays / continent de
   s'appliquer ; seules les règles ASN tombent en fail-open (log WARN une
   fois).

La raison du blocage précise ce qui a correspondu (`continent:AS`,
`country:RU`, `asn:14061`) dans l'événement country-block → visible dans
**Logs** sans changement de schéma (le champ `reason` existe déjà).

## 3. Interface (maquette validée)

```
▾ Filtrage géographique (deny · 2 continents, 1 pays, 2 ASN, 1 exception)
  Mode : ( ) Désactivé  ( ) Allow  (•) Deny
  Continents   [x] Asie  [ ] Europe  [ ] Afrique  [ ] Am. Nord
               [x] Am. Sud  [ ] Océanie  [ ] Antarctique
  Pays         [ Rechercher un pays… ]   (🇷🇺 Russie ✕)
  ASN          [ Nom ou numéro… ]        (AS14061 DigitalOcean ✕)     ← PR B
  Exceptions (toujours autorisées)                                     ← mode Deny
               [ Pays… ] (🇯🇵 Japon ✕)   [ ASN… ] (AS12345 … ✕)          ← ASN en PR B
  Statut du blocage : [403 ▾]
```

- Le titre résume les compteurs par type.
- Continents : libellés traduits FR/EN, grille de cases à cocher accessible
  (fieldset + legend).
- Le bloc ASN n'apparaît qu'en PR B ; sans base ASN chargée, il affiche un
  avertissement avec un lien vers Réglages → GeoIP.

## 4. ASN (PR B)

- **Base** : `ARENET_GEOIP_ASN_MMDB` (défaut `/var/lib/arenet/GeoLite2-ASN.mmdb`),
  lecteur rechargeable à chaud comme la base City.
- **Mise à jour** : le téléchargeur gère une liste d'éditions (City + ASN)
  avec les mêmes identifiants ; garde d'édition par type ; Réglages → GeoIP
  affiche l'état des deux bases.
- **Index des noms** : au chargement, itération des réseaux → map
  `asn → organisation` (≈ 80 000 entrées). Mesurer mémoire et temps de
  chargement réels avant de figer (cible : quelques Mo, < 2 s).
- **API** : `GET /api/v1/geo/asn?q=ovh&limit=20` → `[{asn, name}]`
  (recherche par préfixe de numéro ou sous-chaîne du nom, insensible à la
  casse). Admin, comme l'édition des routes.

## Tests

- `Evaluate` : table couvrant chaque couche, continents, exceptions qui
  gagnent, fail-open par type, compatibilité d'une config pays seule.
- Non-régression : une route pays-seule émet un JSON **identique** à v2.26.
- Validation : les nouveaux cas d'erreur.
- Frontend : cases continents, exceptions visibles seulement en Deny,
  résumé du titre, parité i18n.
- Smoke : résolution de continent réelle sur une IP publique connue
  (base City locale) ; PR B : recherche ASN et blocage sur une IP d'un
  hébergeur connu.

## Non-goals

- ❌ CIDR / IP dans ce filtre (le filtrage IP source par route et par chemin
  existe déjà, v2.21).
- ❌ Exceptions par continent ; règles allow et deny mélangées à égalité.
- ❌ Filtrage géo par chemin (les règles par chemin ne portent que basic
  auth, IP et upstream).
- ❌ Carte / tableaux de bord par ASN (backlog : ASN dans Logs et la carte).
