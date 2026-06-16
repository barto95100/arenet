# CrowdSec & Security UI — Backlog

État : Day 8 (2026-06-10) après v1.8.0-step-cs3 tagged + pushed + Task 1/2/3 follow-ups (#R-WAF-BLOCKS-MUTATING-METHODS resolved)

═══════════════════════════════════════════════════════
OPEN — non-bloquant, à traiter dans futurs steps polish
═══════════════════════════════════════════════════════

## #R-CROWDSEC-audit-updated-at-zero — RESOLVED 2026-06-11
Audit log "After" snapshot pour crowdsec_updated AND 
crowdsec_configured capturait updated_at=0001-01-01T00:00:00Z 
(Go zero time) parce que le snapshot était pris depuis la 
struct `merged` côté handler — alors que 
`PutCrowdSecConfig` assigne `UpdatedAt = time.Now()` 
dedans (storage/crowdsec_config.go:262).

Fix shipped : ajout d'un re-fetch via `GetCrowdSecConfig` 
juste après `PutCrowdSecConfig` succeed, et utilisation du 
`persisted` résultat pour le hot-reload, l'audit AfterJSON, 
ET le response wire. La réponse à l'opérateur surface 
désormais l'état canonique persisté plutôt qu'un merge 
côté handler.

Test `TestPutCrowdSecSettings_Audit_CapturesPersistedUpdatedAt` 
verifies absent de `0001-01-01` dans l'audit AfterJSON ET 
présence du prefix RFC 3339 de la valeur réellement stockée 
(via Format au lieu de comparaison exacte pour éviter le 
coupling à la précision time.Time MarshalJSON).

Si le re-fetch échoue (impossible en pratique vu que le Put 
vient de réussir), fallback sur `merged` + warn-log plutôt 
que d'aborter — graceful degradation, l'écriture est de 
toute façon persistée.

## #R-CADDY-graceful-shutdown-too-long — RESOLVED 2026-06-11
Arenet's embedded Caddy uses "eternal grace period" pour les 
HTTP/2 streaming connections during shutdown. Combiné avec les 
browser tabs actifs (polling /security?tab=crowdsec every 30s, 
metrics websocket), le shutdown peut hang jusqu'à 90s timeout 
systemd avant SIGKILL.

Fix shipped : ajout `"grace_period": "5s"` dans la map 
`apps.http` émise par `caddymgr/manager.go buildConfigJSON`. 
Caddy's default (0 = eternal, modules/caddyhttp/app.go:132) 
remplacé par un cap opérateur-friendly. Test 
`TestBuildConfigJSON_GracePeriod_Bounded` pin la valeur dans 
le JSON émis ; le pipeline existant 
`TestBuildConfigJSON_LoadsCleanly` confirme que Caddy 
Validate accepte le champ. 5s est :
  - assez large pour drainer une requête HTTP/1.1 normale
  - assez court pour qu'une connexion long-poll idle ne 
    bloque qu'un seul cycle avant l'exit du process
  - bien sous le timeout systemd 90s (plus de SIGKILL forcé)

Alternative options du brief original (systemd 
TimeoutStopSec, cancel context plus tôt) non nécessaires — 
le fix Caddy-side suffit.

## #R-CS2C-anchor-link — CLOSED 2026-06-16 (Day 14 EOD)
Le link "Settings → Security Automation" depuis le 412 state du 
tab Scenarios + le BanIPModal 412 CTA ramenait en haut de /settings 
au lieu de scroller à la section.

Fix shipped en 3 parties (Day 9-10) :
  - Part 1 (commit 1f84d07) : ajout `id="security-automation"` sur 
    le wrapper de la section + href modifié en 
    `/settings#security-automation` dans les 2 sites 
    (CrowdSecDecisionsPanel.svelte:850, BanIPModal.svelte:289).
    Test BanIPModal mis à jour pour pin le nouveau target.
  - Part 2 (commit d703754) : afterNavigate handler dans 
    routes/settings/+page.svelte qui scrollIntoView le target 
    une tick après hydration (le browser hard-load le hash AVANT 
    le premier render Svelte, donc le anchor n'existait pas 
    encore — scroll silently abandonné). 
  - Part 3 (commit 14b4159) : scroll-padding-top sur <html> dans 
    app.css = calc(var(--tb-height) + 16px) pour clearer le 
    Topbar sticky qui couvrait le titre de section post-scroll.

Closed empirically Day 14 EOD :
  - id="security-automation" présent sur le wrapper 
    (routes/settings/+page.svelte:899)
  - Les 2 href cibles utilisent /settings#security-automation 
    (CrowdSecDecisionsPanel:832,850 + BanIPModal:289)
  - afterNavigate + scrollIntoView présents (settings/+page.svelte:574-580)
  - app.css scroll-padding-top calc(--tb-height + 16px) présent (line 100)
Les 3 layers de fix sont intactes dans le bundle actuel.

## #R-CSS-settings-section-spacing — RESOLVED 2026-06-11 (commit 4b2d1ed)
Section "CrowdSec bouncer" (CS.1) manquait margin-top pour 
séparation visuelle d'avec OIDC SSO précédent.

Déjà fixé par commit `4b2d1ed` (2026-06-09) qui a ajouté le 
wrapper `<div class="mb-6">` autour de `OIDCSettingsSection`. 
L'entry backlog n'avait juste pas été flippée. Confirmed 
visually post-deploy 2026-06-11 — no code change needed in 
current bundle.

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

## #R-AUTOMATION-CREDS-403 — CLOSED 2026-06-16 (Day 14 EOD)
Découvert pendant CS.3 Gate 5 attempt. Initial symptom: PUT 
/api/v1/settings/automation/credentials → 403 Server:Caddy 
content-length:0 + no slog line.

Initial hypotheses (CSRF / endpoint wiring / permission gate) 
were all WRONG. Root cause empirically pinned: same as 
#R-WAF-BLOCKS-MUTATING-METHODS — CRS 911100 blocked the PUT on 
the self-route admin Caddy chain.

Resolution (Day 10): fixed transitively by the WAF exclusion 
widening (commit 00c93dd). The Reset Security Automation button 
(commit 73157c9, separate ship) provides the operator-facing 
DELETE path with audit row automation_reset; combined with the 
WAF fix, the full "clear watcher creds via UI through Caddy" 
flow worked end-to-end.

Re-tested empirically 2026-06-16 (Day 14 EOD) via curl avec 
cookies admin valides :
  - PUT /api/v1/settings/automation/credentials → 200 OK
  - PUT /api/v1/settings/crowdsec → 200 OK
Bug fixé entre Day 9 et Day 14, probablement collatéralement 
à un commit de refactor middleware non spécifiquement identifié 
(la WAF exclusion widening de Day 10 reste la résolution 
canonique du root cause).

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

## #R-WAF-EVENT-LABEL-BLOCK-VS-200 (medium) — OPEN 2026-06-10 (re-classified low→medium 2026-06-11)

Découvert pendant le smoke Day 8 (Gate 4 du fix #R-WAF-BLOCKS-MUTATING-METHODS).

Symptôme :
  Sur admin path /api/v1/routes avec payload SQLi → HTTP 200 retourné (admin trust 
  via exclusion), MAIS l'event /observability/logs est tagué "BLOCK 403" pour 
  WAF rule 942100. Le label de l'event ne reflète pas l'action réelle.

Impact : confusion forensique. Un opérateur scrutant `/observability/logs` 
pourrait croire qu'un attaquant a été bloqué alors que la requête a passé.

═══════════════════════════════════════════════════
EMPIRICAL FINDINGS — probe Day 9 (2026-06-11)
═══════════════════════════════════════════════════

Lesson 3 (read library source) probe on the proposed fix
shape revealed that the initial 1-line "use Disruptive()
instead of h.Mode" approach was WRONG. The probe saved us
from shipping incorrect code.

Coraza MatchedRule.Disruptive() semantic, verified at
vendor `coraza/v3@v3.7.0/internal/corazawaf/transaction.go:584-591`:

```go
for _, a := range r.actions {
    if a.Function.Type() == plugintypes.ActionTypeDisruptive {
        mr.DisruptiveAction_ = corazarules.DisruptiveActionMap[a.Name]
        mr.Disruptive_ = tx.RuleEngine == types.RuleEngineOn
        break
    }
}
```

`Disruptive_ = true` means:
  - The rule HAS a disruptive action declared (block / pass / allow / redirect)
  - AND the engine is in RuleEngineOn (not DetectionOnly)

It does NOT mean "this transaction will actually interrupt".
At `onMatch` callback time (phase 1/2), `tx.Interruption()`
is NOT yet decided — finalized later in phase processing.

Concrete reproduction trace :
  1. Route in block mode → handler instantiates Coraza
     with `SecRuleEngine On`
  2. Admin path → ctl:ruleRemoveById strips 911/930/931/949
     (anomaly aggregator + LFI/PE families), but NOT 942 (SQLi)
  3. 942100 fires on the payload, onMatch callback runs
  4. `mr.Disruptive() = true` (rule has block action + engine on)
  5. Existing filter at `internal/waf/module.go:386`:
     ```go
     case "block":
         if !mr.Disruptive() { return }
     ```
     → 942100 passes the filter, event emitted with
     `Action=BLOCK, StatusCode=403`
  6. Phase 2 continues. 949* aggregator is excluded →
     no `tx.Interrupt()` called
  7. Handler at `module.go:560` reads `it == nil`,
     falls through to `next.ServeHTTP(w, r)` (chi router)
  8. Response = HTTP 200, but the event log says BLOCK/403

═══════════════════════════════════════════════════
CORRECT FIX SHAPE (design before code)
═══════════════════════════════════════════════════

Per-transaction event buffering + post-verdict flush:

  1. Each handler invocation creates a per-tx event buffer
     (slice of pending Events).
  2. `onMatch` callback pushes to the buffer instead of
     calling sink.Emit directly.
  3. At handler exit (deferred, after `processRequest`
     returns + interruption decision is made), read
     `tx.Interruption()`:
       - != nil + mode=block → flush buffer with Action=BLOCK
         + actual StatusCode from interruption
       - otherwise → flush buffer with Action=DETECT,
         StatusCode=0
  4. Mechanism for passing per-tx state to the callback:
     Coraza's `WithErrorCallback(fn)` is a fixed signature
     (no context arg) → can't pass tx state directly. Two
     options:
       (a) `sync.Map[*tx → *buffer]` keyed by tx pointer,
           callback looks up its buffer
       (b) install a per-tx closure callback at NewTransaction
           time that captures the buffer reference. Verify
           Coraza supports rebinding the callback per-tx
           (probe needed) — most likely WAF-level so we'd
           need (a).

Test surface (non-trivial):
  - Block-mode route + non-interrupting match (admin path
    SQLi) → event Action=DETECT (the bug repro)
  - Block-mode route + actually-interrupting match (any
    full match path) → event Action=BLOCK + status
  - Detect-mode route → unchanged (Action=DETECT)
  - LRU dedup interaction with buffer flush (sink already
    dedupes at Emit; buffer flush sends N Emits — should
    work transparently but worth a regression test)
  - Concurrent transactions on the same handler instance —
    no buffer cross-contamination (the sync.Map keying
    must be correct)

Estimated effort: medium-substantial (refactor onMatch +
add per-tx state + sync mechanism + ~4-5 new tests).
Standalone workstream; do NOT bundle.

═══════════════════════════════════════════════════
Status: OPEN — design doc needed before code.
═══════════════════════════════════════════════════

## #R-DASHBOARD-WAF-COUNTERS-ZERO — RESOLVED 2026-06-10

Découvert pendant smoke Day 8 post-WAF fix.

Symptôme :
  - Dashboard /apercu — card "WAF BLOCKS / H" = 0
  - Dashboard — Top routes col "WAF BLOCKS" = 0 toutes routes
  - Page /sécurité/waf — toutes catégories CRS = 0 blocks/24h
  - Page /sécurité/waf — counter "BLOCKED" = 0
  - MAIS feed dashboard "WAF events — recent" affiche les 5 events 
    récents (smoke Gates 3+4 Day 8)

Investigation (triangulation Lesson 1 + audit empirique 287 events 
sur AreNET-test) :

CAUSE A — sink filter intentionnel :
  internal/waf/sink.go absorb() bumpe BumpWafBlocks UNIQUEMENT sur 
  events ActionBlock (commit W.bugfix Fix #1). Détect events restent 
  dans waf_event mais n'incrémentent jamais le bucket counter.

CAUSE B — fenêtre summary 1 minute :
  metrics_handlers.go metricsSummary lit le bucket "just-closed 
  minute" et la frontend projette × 60 ("/H") ou × 60×24 ("/24h"). 
  Sur trafic discontinu homelab, > 60s après l'event = 0 partout 
  même pour les BLOCK. Tracking séparé : 
  `#R-WAF-METRICS-WINDOW-1MIN-PROJECTION` (deferred post-Step T 
  car blast radius wire-contract).

Fix CAUSE A — split detect/block counters (Option 1) :

Backend :
  - Migration v8→v9 : ALTER TABLE bucket_1m/bucket_1h ADD COLUMN 
    waf_detect_count INTEGER NOT NULL DEFAULT 0
  - WafEvent.WafDetects (TickDelta) + Aggregator.BumpWafDetects 
    symmétrique à BumpWafBlocks
  - waf.Sink.absorb dispatche par e.Action : ActionBlock → 
    BumpWafBlocks (preserved), ActionDetect → BumpWafDetects 
    (new). Bump-then-suppress AVANT LRU dedup (AC #3 — volume 
    d'attaque, pas dedupliqué)
  - 4 sites SQL bucket (Insert / Query / QueryAggregated / 
    retention) lisent la nouvelle colonne
  - summary endpoint expose TotalWafDetectedPerMin + 
    WafDetectsByCategory parallel aux block fields ; 
    summaryRoute.WafDetectedPerMin parallel à WafBlockedPerMin
  - Sémantique resserrée : WafBlocksByCategory désormais filtre 
    action=BLOCK strict (était silently aggregated pre-fix — c'est 
    le bug que ce fix corrige). WafDetectsByCategory pour DETECT.

Frontend :
  - Dashboard /apercu : 2 cards parallèles BLOQUÉ (rouge) + 
    DÉTECTÉ (amber), data-testid="kpi-waf-blocked|detected"
  - Top routes table : nouvelle colonne "WAF detect"
  - Page /sécurité/waf : 2 tiles Blocked + Detected, et chaque 
    row catégorie CRS rend 2 chiffres (block24h rouge + 
    detect24h amber)

Bundle : fix #R-WAF-EVENT-LABEL-INCONSISTENT inclus dans le même 
commit (même thème detect ≠ block, mêmes composants frontend).

Tests :
  - Backend : 5 nouveaux (3 storage migration + 4 API summary + 
    1 sink AC#3-detect)
  - Frontend : 9 nouveaux vitest (6 dashboard + 3 waf page)
  - go test ./... : 20 packages green
  - npm run test : 521/521 (was 512 → +9)
  - npm run check : 0 errors 0 warnings sur 733 fichiers

Smoke à valider sur AreNET-test post-deploy :
  1. Régression Block route arenet (140 events historiques 
     mode=block) : "WAF bloqué / h" non-zero après nouveau block
  2. Smoke detect route ha (mode=detect) : "WAF détecté / h" 
     non-zero après LFI/SQLi
  3. Catégories CRS : 2 chiffres par row (block / detect)
  4. Label fix : feed dashboard sur event detect → "detect" 
     amber + statusCode rendered as "—", pas "BLOCK 403"

## #R-WAF-EVENT-LABEL-INCONSISTENT — RESOLVED 2026-06-10

Découvert pendant smoke Day 8.

Symptôme :
  Même event WAF labellé différemment selon la vue :
  - /observability/logs → "DETECT" (route wafMode=detect) ✅
  - Dashboard feed "WAF events — recent" → "BLOCK 403" ❌

Cause confirmée par audit (Lesson 3 — read source) :
  web/frontend/src/routes/dashboard/+page.svelte hardcodait 
  "block" + "BLOCK" + "403" littéralement à 2 sites (lignes 305 
  + 384-385 pre-fix), ignorant le champ ev.action déjà présent 
  sur le wire (cf types.ts:1175). WafEventList.svelte 
  (composant logs) n'avait pas le bug — la sémantique action 
  était déjà respectée là.

Fix bundlé dans le commit #R-DASHBOARD-WAF-COUNTERS-ZERO 
(même thème detect ≠ block, mêmes composants frontend) :

  - Site 1 (recentEvents card) : pill bad rouge si BLOCK, 
    pill warn amber si DETECT. Lit ev.action.
  - Site 2 (live tail feed) : log-lvl class block/detect 
    selon ev.action. Status code rendu ev.statusCode || '—' 
    pour que detect events (status=0) affichent "—" — 
    operator-honest "no value" answer.
  - CSS : ajout .pill.warn + .log-lvl.detect (palette 
    status-warn amber, parallèle aux .pill.bad + .log-lvl
    .block existantes status-down rouge)

Tests pinnés (web/frontend/src/routes/dashboard/page.test.ts) :
  - renders BLOCK label + statusCode on action=BLOCK events
  - renders DETECT label + "—" on action=DETECT events  
  - mixed events both labels correct in same feed

Note : à consolider avec #R-WAF-EVENT-LABEL-BLOCK-VS-200 — même 
famille de bug (label semantics mal gérés à différents endroits 
côté backend cette fois ; le frontend est maintenant clean).

## #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — RESOLVED 2026-06-11

Découvert pendant l'investigation #R-DASHBOARD-WAF-COUNTERS-ZERO 
(Day 8). Cause B de la triangulation : la window 1-min côté 
summary endpoint était une cause structurelle de la confusion 
opérateur. Le ticket a été reframed pendant l'implémentation : 
le scope élargi à TOUS les fields du summary (pas seulement WAF) 
parce que le mensonge "rate-projection-from-1-minute" était 
identique pour totalReq, totalThrottle, totalCrowdSecDecisions, 
etc. — pas spécifique au WAF.

Fix shipped (Option 2a — widen window) :

Backend (internal/api/metrics_handlers.go) :
  - Window : just-closed-minute → 24h rolling, ancré au début 
    de l'heure courante (hourTs := now.Truncate(time.Hour) ; 
    from := hourTs.Add(-24h) ; to := hourTs).
  - Per-route loop : Granularity1m → Granularity1h. Lit 24 
    rows par route via metrics.Query, SUM in-handler. Coût 
    typique homelab ≤ 2400 indexed SELECTs.
  - Sentinel routes (throttle, crowdsec) : même switch 
    Granularity1m → Granularity1h, SUM over the 24 rows.
  - Categories : nouveau aggregator server-side 
    observability.AggregateWafEventsByCategory(action, route, 
    from, to). Remplace l'iteration row-by-row sous 
    wafEventLimitCap=100 (qui ne pouvait pas servir un 24h 
    window sur un jour chargé). Deux queries par summary 
    (BLOCK + DETECT) au lieu d'une iteration.
  - Auth scan cap : summary-spécifique 10000 (le 
    /security/auth-failures recent-feed cap=200 reste 
    inchangé). Hit-cap log Debug pour signal de growth.
  - GlobalP95LatencyMs : weighted avg req_count × p95 across 
    all hourly rows, all routes (preserve la sémantique).

Wire contract — rename additif → rename total (drop PerMin 
suffix) :
  - summary.totalReqPerMin            → totalReq
  - summary.totalFourXxPerMin         → totalFourXx
  - summary.totalFiveXxPerMin         → totalFiveXx
  - summary.totalWafBlockedPerMin     → totalWafBlocked
  - summary.totalWafDetectedPerMin    → totalWafDetected
  - summary.totalThrottlePerMin       → totalThrottle
  - summary.totalAuthFailuresPerMin   → totalAuthFailures
  - summary.totalCrowdSecDecisionsPerMin → totalCrowdSecDecisions
  - summary.topRoutes[].reqsPerMin    → reqs
  - summary.topRoutes[].fourxxPerMin  → fourxx
  - summary.topRoutes[].fivexxPerMin  → fivexx
  - summary.topRoutes[].wafBlockedPerMin → wafBlocked
  - summary.topRoutes[].wafDetectedPerMin → wafDetected
  - summary.windowSeconds : 60 → 86400 (le wire signal 
    documenté pour les consumers)
  - wafBlocksByCategory, wafDetectsByCategory, 
    activeCrowdSecIpsUnique, attackerIpsUnique, 
    globalP95LatencyMs : inchangés (déjà window-agnostic)

Pattern industrie : Prometheus / Datadog / Grafana ne mettent 
jamais la fenêtre dans le nom de métrique. Le nom dit QUOI, 
la fenêtre est une dimension de requête (lue via 
windowSeconds). Convention propre + future-proof si on ajoute 
un user selector (1h/24h/7d). Pré-1.0 + 2 consumers internes 
uniques (dashboard/+page.svelte + waf/+page.svelte) = coût 
rename négligeable, TypeScript a attrappé chaque référence 
orpheline à compile-time.

Frontend :
  - Dashboard tiles WAF bloqué / WAF détecté : label "/ 24h" 
    (était "/ h"), valeurs raw (pas de × 60).
  - Top Routes columns "Req / 4xx / 5xx / WAF block / 
    WAF detect" (était "Req/min / ..."), valeurs raw.
  - Page sécurité/waf KPI Blocked + Detected : valeurs raw 
    (pas de × 60 × 24).
  - Catégories CRS : chaque row lit block24h + detect24h 
    raw depuis les maps.
  - Footer "summed over rolling 24h window" remplace 
    "projected from current rate".

Tests (Go + TS, tous verts -race) :
  - 4 nouveaux observability tests (AggregateWafEventsByCategory : 
    grouping, action filter, empty window, route filter)
  - Tous les TestMetricsSummary_* + TestSecurity_*Summary_* tests 
    migrés : Granularity1m → Granularity1h, prevMinute/prevMin → 
    prevHour, field renames complets
  - Test TotalAuthFailures_FromAuditScan adapté pour vérifier 
    la 24h window au lieu du 1min window
  - Frontend dashboard + waf tests adaptés : assertions sur 
    raw values (pas projetées)

Verification :
  - go test ./... -race : 20 packages verts (~210s sur api)
  - go vet ./... : clean
  - npm run check : 0 errors 0 warnings sur 733 files
  - npx vitest run : 521/521 across 38 files, exit 0
  - Smoke historique : les 287 events sur 8 jours sur 
    AreNET-test seront immédiatement visibles après deploy 
    sur les cards et catégories, validation empirique sans 
    fresh smoke

Lessons :
  - Cause B était structurelle, pas WAF-spécifique. 
    L'investigation Cause A (split detect/block) a 
    initialement caché la cause root car le symptôme 
    s'affichait sur les fields WAF. Réviser le scope 
    pendant l'implémentation a évité de laisser un fix 
    incomplet.
  - Le rename total a été le bon move plutôt qu'additif : 
    mixed windows dans la même réponse aurait été 
    exactement la mendacité qu'on est en train de fixer.

Follow-up patch shipped après smoke 579f695 sur AreNET-test :

Smoke diff détecté : totalWafDetected (26) ne matchait pas 
wafDetectsByCategory.sum (51). Root cause : BumpWafDetects 
a été ajouté en e7e2905, donc les events DETECT antérieurs 
n'ont jamais bumped bucket_1h.waf_detect_count. Asymétrie 
historique avec BumpWafBlocks (qui existait depuis Step M.1 
en 9032b6f).

Décision opérateur : source unique = waf_event pour TOUS 
les compteurs WAF. Pas de moitié-fix asymétrique — switch 
les block reads aussi pour zéro chance de drift futur.

Implementation :
  - Nouvelle storage method AggregateWafEventsByRoute(from, to) 
    → map[routeID]{Block, Detect}. SQL : 
    `SELECT route_id, action, COUNT(*) FROM waf_event 
    WHERE ts BETWEEN ? AND ? GROUP BY route_id, action`. 
    Index existant `idx_waf_event_route_ts` couvre.
  - metricsSummary : ajout d'un overlay step après le 
    bucket_1h per-route loop. La per-route loop ne lit 
    plus row.WafBlockCount / row.WafDetectCount ; les 
    counters sont chargés en un seul GROUP BY query 
    depuis waf_event et overlay-ed sur byID. Grand totals 
    sommés sur le map complet (pas seulement les routes 
    présentes dans byID — events sur routes supprimées 
    contribuent au système-wide total comme dans 
    wafBlocksByCategory).
  - Bucket columns bucket_1h.waf_{block,detect}_count 
    restent (additive deprecation). Sink continue à 
    bumper les counters via BumpWafBlocks / BumpWafDetects 
    — colonnes maintenues côté write pour rollback safety. 
    Suppression éventuelle dans un workstream futur.
  - 4 nouveaux storage tests (BlocksAndDetects, 
    EmptyWindow, WindowFilter, UnknownActionsDropped).
  - 3 tests existants migrés du seed bucket counter au 
    seed waf_event row (TestMetricsSummary_WafDetected_
    FromBucketColumn renommé en FromWafEvent, 
    TestMetricsSummary_WafBlockAndDetectStayIndependent, 
    TestMetricsSummary_WafFields_IndependentFrom4xx5xx, 
    TestMetricsSummary_TopAttackedRoute_SortsAcrossAll
    RoutesByWafBlocks).
  - fakeWafEventReader gained aggregateRouteFn.

Smoke post-fix attendu sur AreNET-test :
  - totalWafBlocked == sum(wafBlocksByCategory) ✓
  - totalWafDetected == sum(wafDetectsByCategory) ✓
  - sum(topRoutes[].wafBlocked) == totalWafBlocked
  - sum(topRoutes[].wafDetected) == totalWafDetected
  - 26 → 51 sur totalWafDetected (match du wire smoke)

Verification :
  - go test ./... -race : 20 packages verts (api: 234s)
  - go vet : clean
  - npm run check : 0/0 sur 733 files
  - npx vitest run : 521/521 across 38 files (frontend 
    inchangé — même wire shape, même field names)

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

## #R-API-PUT-ROUTE-GENERIC-400 — RESOLVED 2026-06-10

Découvert pendant le smoke commit 1 du fix 
#R-PROXMOX-HTTPS-LOOP. PUT /api/v1/routes/{id} retournait 
400 "invalid JSON body" en générique, masquant la cause 
réelle (le wire layer manquait `InsecureSkipVerify` côté 
`routeRequest`, et `dec.DisallowUnknownFields()` rejetait 
le champ silencieusement).

Le smoke aurait diagnostiqué la cause en une seule curl 
si le message d'erreur avait surfacé la raison du décodeur 
dès le départ.

Fix complet shipped en deux temps :

1. Partiel — commit `a69880d` (workstream #R-PROXMOX-HTTPS-LOOP) :
   createRoute + updateRoute concaténaient l'erreur brute du 
   décodeur dans le message ("invalid JSON body: json: unknown 
   field \"xyz\""). Suffisant pour débloquer le smoke en cours 
   mais brut côté UX (le `json:` prefix, les guillemets 
   échappés, le numéro d'offset noyé dans la chaîne).

2. Complet — commit ci-après : helper `translateDecodeError` 
   dans `internal/api/decode_errors.go` qui classifie 
   l'erreur par type Go (`io.EOF`, `*json.SyntaxError`, 
   `*json.UnmarshalTypeError`, unknown-field via substring 
   match parce que stdlib < 1.21 n'a pas de type dédié) et 
   émet un message structuré :

   | Type Go                       | Message émis                                |
   |-------------------------------|---------------------------------------------|
   | `io.EOF` / `ErrUnexpectedEOF` | `JSON body is required`                     |
   | `*json.SyntaxError`           | `malformed JSON at offset N`                |
   | `*json.UnmarshalTypeError`    | `field "X": expected T, got U`              |
   | unknown field strict-mode     | `unknown field "X"`                         |
   | default                       | `invalid JSON body: <raw>`                  |

   Sweep des 22 sites d'appel (les 2 partiels routes.go + 
   le partiel routes_test_upstream.go + les 18 sites bruts 
   dans 12 fichiers) via le helper. Tests unit sur le helper 
   (6 cas, dont 1 nil-safety défensif) — couvrent les 22 
   call sites par transitivité car ils sont tous 
   byte-identical (`writeError(w, http.StatusBadRequest, 
   translateDecodeError(err))`).

Anti-régression : un seul test du package pinait 
`strings.Contains(body, "invalid JSON")` 
(auth_handlers_test.go:310, sur le path POST /api/v1/auth
/setup). Mis à jour pour pinner `"malformed JSON"` à la 
place, ce qui matche le nouveau classifier du 
*json.SyntaxError. Aucun autre test ne dépendait du 
literal.

Lesson capturée : storage struct ≠ wire struct → 
ENGINEERING-PRACTICES.md Lesson 8 (commit `2eaaf94`).
Ce sweep est l'opérationnel counter-measure : quand un 
futur dev oublie d'étendre la wire struct, l'erreur 
nommera le champ manquant au lieu de masquer.