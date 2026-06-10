# CrowdSec & Security UI — Backlog

État : Day 8 (2026-06-10) après v1.8.0-step-cs3 tagged + pushed + Task 1/2/3 follow-ups (#R-WAF-BLOCKS-MUTATING-METHODS resolved)

═══════════════════════════════════════════════════════
OPEN — non-bloquant, à traiter dans futurs steps polish
═══════════════════════════════════════════════════════

## #R-CROWDSEC-audit-updated-at-zero (low) — OPEN
Audit log "After" snapshot pour crowdsec_updated AND crowdsec_configured 
capture updated_at=0001-01-01T00:00:00Z (Go zero time). Le snapshot 
devrait être pris APRÈS que le storage layer assigne 
updated_at = time.Now(), ou capturer le résultat persisté plutôt que 
le request payload.

Cosmétique — n'affecte pas le runtime bouncer behavior.

## #R-CADDY-graceful-shutdown-too-long (low) — OPEN 2026-06-10
Arenet's embedded Caddy uses "eternal grace period" pour les 
HTTP/2 streaming connections during shutdown. Combiné avec les 
browser tabs actifs (polling /security?tab=crowdsec every 30s, 
metrics websocket), le shutdown peut hang jusqu'à 90s timeout 
systemd avant SIGKILL.

Fix options :
  - Configure Caddy avec graceful_shutdown timeout court (~5s)
  - OR systemd unit : TimeoutStopSec=10 + KillMode=mixed
  - OR cancel context properly avant Caddy.Stop()

Painful avec multiple redeploys (vu pendant CS.3 smoke).

## #R-CS2C-anchor-link (low) — OPEN
Le link "Settings → Security Automation" depuis le 412 state du 
tab Scenarios ramène en haut de /settings au lieu de scroller à la 
section.

Fix : ajouter id="security-automation" sur la section + href modifié 
/settings#security-automation. ~5 min frontend.

## #R-CSS-settings-section-spacing (low) — OPEN
Section "CrowdSec bouncer" (CS.1) manque margin-top pour séparation 
visuelle d'avec OIDC SSO précédent. Cohérence visuelle.

Fix : ajouter margin-top dans le parent flex/grid de /settings 
+page.svelte. ~5 min frontend.

═══════════════════════════════════════════════════════
RESOLVED — fixed during CS.2 / CS.3 / Day-8 follow-ups
═══════════════════════════════════════════════════════

## #R-WAF-BLOCKS-MUTATING-METHODS — RESOLVED 2026-06-10
Découvert en investiguant #R-AUTOMATION-CREDS-403.

Empirical root cause (triangulated per ENGINEERING-PRACTICES Lesson 1) :
  - Operator curl evidence: PUT direct sur 127.0.0.1:8001 → 200, 
    PUT via https://arenet.worldgeekwide.fr → 403 Server:Caddy
  - Boot log: "waf handler provisioned route_id=b2a1a41e-... 
    host=arenet.worldgeekwide.fr mode=block load_owasp_crs=true"
  - Live Caddy config dump shows arenet_waf attached to the self-
    route admin chain (routemetrics → crowdsec → arenet_waf → 
    reverse_proxy)

L'opérateur a créé un self-route admin (host=arenet.worldgeekwide.fr → 
127.0.0.1:8001) pour TLS + CrowdSec bouncer + country-block sur 
l'admin UI. WAFMode=block + OWASP CRS chargé → CRS rule 911100 
(PROTOCOL_ENFORCEMENT method check) rejette PUT/DELETE/PATCH 
(default tx.allowed_methods = "GET HEAD POST OPTIONS").

L'exclusion Item 1 (commit a6276a8, narrow UUID regex 
/api/v1/(routes|settings)/{uuid}) ne couvrait PAS les literal-named 
admin paths (/api/v1/settings/crowdsec, /api/v1/settings/automation/
credentials, etc.).

Fix : commit 00c93dd. Widened exclusion regex à ^/api/v1(/.*)?$ 
pour couvrir toute la management plane. Same mechanism (phase:1 
SecRule + ctl:ruleRemoveById on 911* + 930* + 931* + 949*), same 
trade-off shape as Item 1, just wider URL space.

Architecture rationale: docs/superpowers/decisions/2026-06-10-waf-
excludes-management-plane.md (commit 0bad842).

Tests: 9 admin-exclusion cases (3 legacy Item 1 UUID-path + 1 
renamed user-route LFI + 5 new regression guards covering literal 
PUT crowdsec / DELETE automation / PATCH / deep-nested / user 
route 911 still blocks).

Trade-offs explicitly accepted: user apps qui exposent leur API 
sous /api/v1/ (e.g. Home Assistant) auront 911* + 930* + 931* + 
949* stripped sur ce path. Mitigation = WAFMode=detect sur la 
route affected + tuning cscli. Documenté dans la decision doc.

Empirical repro per Lesson 4: temporary TestRepro_* probed 
PUT /api/v1/settings/crowdsec pre-fix (upstream NOT reached, 
2 WAF events) → post-fix (upstream reached, 200, 0 events). 
Probe deleted after confirmation; replaced by 4 regression guards.

## #R-AUTOMATION-CREDS-403 — RESOLVED 2026-06-10
Découvert pendant CS.3 Gate 5 attempt. Initial symptom: PUT 
/api/v1/settings/automation/credentials → 403 Server:Caddy 
content-length:0 + no slog line.

Initial hypotheses (CSRF / endpoint wiring / permission gate) 
were all WRONG. Root cause empirically pinned: same as 
#R-WAF-BLOCKS-MUTATING-METHODS — CRS 911100 blocked the PUT on 
the self-route admin Caddy chain.

Resolution: fixed transitively by the WAF exclusion widening 
(commit 00c93dd). The Reset Security Automation button (commit 
73157c9, separate ship) provides the operator-facing DELETE 
path with audit row automation_reset; combined with the WAF 
fix, the full "clear watcher creds via UI through Caddy" flow 
now works end-to-end.

See #R-WAF-BLOCKS-MUTATING-METHODS above for the full root-
cause analysis + decision doc reference.

## #R-CS3-required-alert-fields — RESOLVED 2026-06-10
HF on Commit C (7302a3a → 20910ac). LAPI POST /v1/alerts required 
scenario_hash + scenario_version + simulated fields per CrowdSec 
swagger spec. Added to payload + 3 pin tests.

## #R-CS2C-since-param-format — RESOLVED 2026-06-09
HF on CS.2.C Commit A (0ffc3b6 → 75fa166). CrowdSec LAPI 1.7.8 
requires Go duration format ("24h0m0s") for since param, not 
RFC3339 absolute timestamp. Fixed + pin tests at -race -count=30.

## #R-CS2C-modal-esc-key — RESOLVED 2026-06-09
Bundled with Commit B (0ffb175 — sidebar /audit + modal Esc polish). 
Modal des scenarios ferme maintenant sur Esc en plus de backdrop + ×.

## #R-NAV-direct-links — RESOLVED 2026-06-09
Addressed by Commit B (0ffb175). /audit ajouté à sidebar 
Administration section. /security/decisions reste hidden per R.4 D8 
design (intentional, surfaced via posture entry-point card avant CS.3 
qui a migré vers /sécurité → CrowdSec tab).

## #R-CROWDSEC-clear-config-button — RESOLVED 2026-06-09
Addressed by Commit C (f1fe919). Reset bouncer configuration button 
+ ConfirmDialog + DELETE /api/v1/settings/crowdsec + audit row 
crowdsec_reset. CS.1 Gate 1 ambiguity now resolvable cleanly.

## #R-CROWDSEC-lapi-version-in-badge — RESOLVED (wontfix) 2026-06-09
CrowdSec 1.7.8 doesn't emit X-Crowdsec-Version HTTP header. Version 
exposed via cs_info Prometheus metric only. Couplage prometheus.enabled 
pas worth pour un badge cosmétique. May revisit si upstream re-adds.

## #R-WAF-EVENT-LABEL-BLOCK-VS-200 (low) — OPEN 2026-06-10

Découvert pendant le smoke Day 8 (Gate 4 du fix #R-WAF-BLOCKS-MUTATING-METHODS).

Symptôme :
  Sur admin path /api/v1/routes avec payload SQLi → HTTP 200 retourné (admin trust 
  via exclusion), MAIS l'event /observability/logs est tagué "BLOCK 403" pour 
  WAF rule 942100. Le label de l'event ne reflète pas l'action réelle.

Hypothèses :
  - Cosmétique : l'event log montre l'action "intended" du rule, pas celle 
    effectivement appliquée après l'admin exclusion → tag devrait être DETECT 
    ou LOG_ONLY
  - Anomaly scoring : rule 942100 seul n'atteint pas le threshold global (949110 
    n'a pas firé), donc même hors admin path ça n'aurait pas bloqué → label 
    BLOCK 403 viendrait du rule individual severity
  - Bug de labelling dans event sink

Impact : confusion forensique. Un opérateur scrutant `/observability/logs` 
pourrait croire qu'un attaquant a été bloqué alors que la requête a passé.

Fix à scoper : auditer internal/waf/event.go (ou équivalent) — voir si on label 
"action_intended" vs "action_applied", clarifier la sémantique.

## #R-DASHBOARD-WAF-COUNTERS-ZERO (medium) — OPEN 2026-06-10

Découvert pendant smoke Day 8 post-WAF fix.

Symptôme :
  - Dashboard /apercu — card "WAF BLOCKS / H" = 0
  - Dashboard — Top routes col "WAF BLOCKS" = 0 toutes routes
  - Page /sécurité/waf — toutes catégories CRS = 0 blocks/24h
  - Page /sécurité/waf — counter "BLOCKED" = 0
  - MAIS feed dashboard "WAF events — recent" affiche les 5 events 
    récents (smoke Gates 3+4 Day 8)

Hypothèse :
  Aggregator metrics lit pas la même source que l'events feed, ou 
  filtre uniquement les events de routes en wafMode=block (ignore 
  les detect events). Pipeline incohérent.

À investiguer :
  - internal/observability/waf_sink.go : counter increment dépendant 
    du wafMode ou du action de l'event ?
  - SQL query peuplant les categories /sécurité/waf : SELECT count(*) 
    GROUP BY rule_family WHERE time > now-24h sur metrics.db, comparer 
    avec l'UI

Impact : perte de signal observabilité WAF agrégé.

## #R-WAF-EVENT-LABEL-INCONSISTENT (low) — OPEN 2026-06-10

Découvert pendant smoke Day 8.

Symptôme :
  Même event WAF labellé différemment selon la vue :
  - /observability/logs → "DETECT" (route wafMode=detect) ✅
  - Dashboard feed "WAF events — recent" → "BLOCK 403" ❌

Hypothèse :
  Le composant dashboard feed lit uniquement le HTTP status code (403) 
  sans considérer le wafMode de la route ou le champ action de l'event.

À investiguer :
  - Frontend : <WafEventRow> dashboard vs page logs
  - Backend : /api/v1/observability/events vs /api/v1/observability/logs

Note : à consolider avec #R-WAF-EVENT-LABEL-BLOCK-VS-200 — même 
famille de bug (label semantics mal gérés à différents endroits).

## #F-UPSTREAM-TEST-ENDPOINT (medium) — RESOLVED 2026-06-10 (commit f119116)

Endpoint POST /api/v1/routes/test-upstream + bouton UI "Tester la 
connexion" différé hors du bundle initial #R-PROXMOX-HTTPS-LOOP 
(scope-cut pour réduire blast radius du fix critique).

Shipped in commit `f119116` after smoke green on commits 1+1b+2. 
Final spec landed slightly enriched vs the deferred draft:
  - POST /api/v1/routes/test-upstream — admin-only
  - Body : {"url": "https://...", "insecureSkipVerify": false}
  - Probe : GET / (not HEAD — many homelab upstreams return 405 
    on HEAD even when healthy)
  - Redirects NOT followed (301 is a legit datapoint)
  - Response shape (enriched vs draft) :
      reachable, statusCode, latencyMs, tlsHandshakeMs,
      cert{commonName, issuer, selfSigned},
      serverHeader, bodyPreview (4KB → 200 chars sanitised),
      error
  - Timeout strict 5s, max URL length 2048, scheme allowlist 
    http/https only
  - Frontend : per-row "Tester" button + chip, "Tester tous" 
    pool-level button parallélisant via Promise.all
  - 16 backend tests + 7 frontend tests

SSRF posture explicit-non-decision : pas de RFC 1918 blocking. 
Trust model "admin = root-equiv for proxy targets" — un admin 
peut déjà CONFIGURE une route vers n'importe quelle IP interne 
via createRoute; ce endpoint n'ajoute aucune capacité, juste 
une boucle de diagnostic plus rapide. Documenté en détail dans 
docs/superpowers/decisions/2026-06-10-https-upstream-tls-
transport.md §SSRF posture.

## #R-PROXMOX-HTTPS-LOOP — RESOLVED 2026-06-10 (commits a69880d + 37f38a5 + f119116)

Operator-reproduced Day-8 review : routes avec upstreams 
`https://` (Proxmox, Synology DSM, ESXi, UniFi) produisaient 
des boucles de redirect 301 infinies car Caddy proxyfiait en 
plain HTTP vers l'upstream.

Root cause : `caddymgr/manager.go` upstreamDial parsait le 
scheme pour calculer le port par défaut (`:443`/`:80`) mais 
le DROPPAIT ensuite — le champ `dial` ne portait que 
`host:port`, aucun `transport.tls` block émis, Caddy 
basculait sur le transport HTTP par défaut.

Fix shipping en 3 commits scope-distincts :

- `a69880d` (commit 1+1b squash) :
    Storage `Route.InsecureSkipVerify bool` + 
    `PoolUsesHTTPS()` + `validateSameSchemePool`. 
    Caddymgr buildConfigJSON émet le transport.tls block 
    quand `r.PoolUsesHTTPS()`. Wire layer : 
    `routeRequest.InsecureSkipVerify *bool` (preserve-on-
    omit) + `routeResponse.InsecureSkipVerify bool` 
    (always emitted). HTTP-only self-heal silencieux 
    + warn-log côté backend, mirror du `RedirectToHTTPS` 
    self-heal à routes.go:1273-1275. Surface l'erreur du 
    décodeur dans le 400 ("invalid JSON body: <reason>") 
    pour createRoute + updateRoute uniquement — sweep 
    des ~16 autres sites trackée séparément 
    (#R-API-PUT-ROUTE-GENERIC-400). 21 tests (13 storage 
    + caddymgr + 8 wire layer) verts.

- `37f38a5` (commit 2) :
    Frontend — validation inline scheme http/https avec 
    rejet pool mixte, disclosure conditionnel "Options 
    avancées TLS upstream" visible uniquement sur pool 
    all-https, toggle "Ignorer la vérification du 
    certificat upstream" avec helper text pédagogique, 
    hint IP privée (RFC 1918 + 4193 + loopback), 
    warning chemin non-root non-bloquant (valeur 
    préservée). Self-heal frontend en `$effect` reset 
    le toggle false sur transition https→http 
    (alignement avec backend self-heal). Payload 
    submit ship insecureSkipVerify UNIQUEMENT sur 
    poolScheme === 'https'; OMIS sur http (preserve-
    on-omit). 8 tests vitest verts.

- `f119116` (commit 3) :
    Test-upstream endpoint + UI button — voir 
    #F-UPSTREAM-TEST-ENDPOINT.

Decision doc complet : docs/superpowers/decisions/
2026-06-10-https-upstream-tls-transport.md.

Smoke browser confirmé Day-8 sur Proxmox à 
proxmox.worldgeekwide.fr : page login Proxmox visible, 
plus de 502 ni de boucle 301. Régression check 
ha.worldgeekwide.fr OK depuis Mac + via loopback SNI forcé.

## #R-API-PUT-ROUTE-GENERIC-400 (low) — OPEN 2026-06-10

Découvert pendant le smoke commit 1 du fix 
#R-PROXMOX-HTTPS-LOOP. PUT /api/v1/routes/{id} retournait 
400 "invalid JSON body" en générique, masquant la cause 
réelle (le wire layer manquait `InsecureSkipVerify` côté 
`routeRequest`, et `dec.DisallowUnknownFields()` rejetait 
le champ silencieusement).

Le smoke aurait diagnostiqué la cause en une seule curl 
si le message d'erreur avait surfacé la raison du décodeur 
dès le départ.

Fix partiel landed en commit `a69880d` : createRoute + 
updateRoute surfacent maintenant l'erreur du décodeur 
("invalid JSON body: json: unknown field \"xyz\"" ou 
"invalid JSON body: invalid character..."). C'est la 
forme correcte pour ces deux sites.

Sweep restant (~16 autres handlers utilisent le même 
pattern `writeError(w, http.StatusBadRequest, "invalid 
JSON body")` à grain sec dans :
  - internal/api/automation_handlers.go (2 sites)
  - internal/api/auth_handlers.go (5 sites)
  - internal/api/crowdsec_manual_ban.go
  - internal/api/crowdsec_settings.go (2 sites)
  - internal/api/forward_auth_provider.go (2 sites)
  - internal/api/dns_provider.go
  - internal/api/managed_domain.go
  - internal/api/server_position_handler.go
  - internal/api/oidc.go (2 sites)

À traiter en un seul commit de balayage : remplacer 
chaque appel par `writeError(w, http.StatusBadRequest, 
"invalid JSON body: "+err.Error())`. Trivial mais 
ennuyeux à faire ligne par ligne — peut être scripté 
en `sed -i` avec relecture.

Impact bas : seuls les opérateurs faisant du curl 
manuel souffrent du masquage; le frontend n'envoie 
jamais de JSON malformé. Mais c'est un signal de 
debug perdu pour les futures sessions.

Lesson capturée : storage struct ≠ wire struct. Quand 
on étend un schema (Route, ProviderConfig, etc.), 
vérifier les DEUX axes (storage + routeRequest/Response). 
`DisallowUnknownFields` transforme un champ wire 
oublié en générique 400 qui masque la cause. À ajouter 
à ENGINEERING-PRACTICES.md comme Lesson 5 (operator 
request).