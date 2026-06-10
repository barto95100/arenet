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