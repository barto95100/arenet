<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step T — Certificates runtime metadata + UX refactor (Spec — draft, to be frozen at v1.2.0-step-t-spec)

## 0. Executive summary

**Goal.** Turn `/certs` from a configuration viewer into a runtime
certificate tracker. Operators today see what is *configured* (managed
domain apex entries + TLS-enabled route list); they cannot see what
certmagic actually holds in memory — issuer, SAN list, expiry,
validity status. This step ships per-certificate runtime metadata
exposure, a unified domain table replacing the two parallel lists, a
force-renewal action (global + per-cert), and a managed-domain
reframe that finally makes the wildcard-vs-specific distinction
self-evident in the UI.

**What changes.**

- **Backend**: new `internal/certinfo` package that bridges certmagic's
  per-cert runtime state into a `CertRuntimeInfo` wire shape, plus a
  new force-renewal control surface (`POST /api/certificates/renew`).
  Reuses the Stage B Caddy-events subscription pattern (commit
  `1926f78`) — empirically verified: certmagic v0.25.3 emits
  `cert_obtained` / `cert_failed` / `cert_obtaining` events through
  the standard Caddy events App.
- **API**: new `GET /api/certificates` returning the unified runtime
  view (one row per cert), and `POST /api/certificates/renew` with an
  optional `{domain}` filter (empty body = renew-all-eligible).
- **Frontend**: `/certs` rebuilt as a unified `Domaines` table with
  tabs (`Tous` / `Wildcard` / `Expirent bientôt`), per-row Force-renew
  action, header global Force-renew, status badges colored by the
  same `--status-*` tokens Topology and Routes use. The managed-
  domain reframe lands here: "Managed domains" → "Politiques wildcard
  par apex" with explanatory copy. Per-cert specific certs auto-
  provision at route creation (existing behavior, no manual flow).

**What stays.**

- Pack A's auto-renewal info card (commit `06ba97a`) — operationally
  still the right top-of-page reassurance. Stays as-is, positioned
  the same.
- ACME issuer: Let's Encrypt only (locked decision §1.1). No ZeroSSL
  fallback wiring.
- DNS provider: OVH only (locked decision §1.5). The `DNSProvider`
  abstraction stays clean for future providers, but none ship in T.
- All Pack A backend endpoints (`settingsApi.listManagedDomains` etc.)
  unchanged — Step T extends, never breaks.

**What defers.**

- **ACME events log** (subscribe → persist last N per domain → UI
  panel/page). Forward-compatible storage schema is required of
  Step T but the log surface itself is the Step T+1 scope. See §1.3.
- **ZeroSSL fallback issuer**. Backlog item, post-T+N.
- **Multi-DNS-provider** (Cloudflare, Gandi, etc.). Backlog item.
- **Pack C visual redesign per the original mock**. The Step T UX
  refactor delivers the unified table + reframe + actions; full
  visual polish per a separate mock is its own step.

**Sub-task count.** 7 sub-tasks (T.1 backend cert-info bridge, T.2
force-renewal endpoint, T.3 force-renewal storage + rate limiting,
T.4 frontend unified table + tabs, T.5 frontend reframe + "+
Domaine" wizard, T.6 audit annotations + backlog seeding, T.7 live
smoke). Estimated wall-clock 12–18 h of focused work, weighted
toward T.1 (certmagic integration probe) and T.4 (frontend rebuild).

**Risk summary.**

- **certmagic API surface** (§3.4): `caddytls.certCache` is package-
  unexported, so direct Go-call access from Arenet is blocked.
  Locked workaround in §1.7 (event-driven cache + on-disk
  reconcile); empirical detail in §3.4 + §9.
- **Force-renewal DOS surface**: an admin who spam-clicks the global
  Force-renew during a Let's Encrypt rate-limit window could trip
  the 50-certs-per-week ceiling. Mitigation in §6.
- **Event-driven warm-up**: a cert that was obtained BEFORE the
  events listener started has no observability event to "replay" —
  T.1 must reconcile against the on-disk certmagic storage at boot,
  not rely solely on events. Same shape as the Stage B HC tracker
  bootstrap prime (commit `37f9927`); reuses that pattern.

---

## 1. Locked decisions

Decisions taken before the spec is frozen; not to be reopened during
implementation without amending this section.

### 1.1 Issuer scope — Let's Encrypt only

Step T does NOT modify the ACME issuer config. The Caddy / certmagic
default Let's Encrypt issuer continues to be the sole supported
provider for both HTTP-01 (per-route) and DNS-01 (wildcard apex via
OVH) issuance paths. ZeroSSL as a fallback issuer would require:

1. Wiring an additional `issuers[]` entry in every emitted ACME
   policy (caddymgr).
2. Per-issuer rate-limit awareness in the force-renewal endpoint.
3. UI affordance to distinguish issuers in the new unified table.

None of those land in Step T. The `Issuer` column in the unified
table (§3.3) will always show `"Let's Encrypt"` in v1.2 — the column
exists in the wire schema so a future T+N ZeroSSL step can populate
it without a wire-shape breaking change.

### 1.2 Force-renewal scope — global + per-cert

Two affordances, one backend endpoint:

- **Global**: header action `Forcer renouvellement` on `/certs`.
  Renews all certs that are NeedsRenewal-true OR expiring within a
  configurable threshold (§3.2 default: 30 days).
- **Per-cert**: row action on every cert in the unified table.
  Renews exactly that cert regardless of expiry posture.

The backend endpoint is `POST /api/certificates/renew` with an
optional JSON body `{"domain": "<name>"}`:

- Empty body → renew-all-eligible (global).
- Body with `domain` → renew that one cert (per-cert).

Single endpoint reduces API surface; the eligibility filter lives on
the server. Per-cert renewal of an already-fresh cert is permitted
(operator-initiated → trust the operator) but logged at info level.

### 1.3 ACME events log — DEFERRED to Step T+1

Subscribing to certmagic's events bus (`cert_obtaining`,
`cert_obtained`, `cert_failed`, `cached_managed_cert`,
`cached_unmanaged_cert`), persisting the last N per domain, and
exposing a UI panel/page is OUT OF SCOPE for Step T.

Step T MUST NOT preclude T+1. Two forward-compatibility requirements:

- **Event subscription**: Step T's `internal/certinfo` package
  subscribes to the same certmagic events to drive the runtime
  cache (§3.4). The subscription is reusable — T+1 adds a second
  event consumer for the log, doesn't replace T's consumer.
- **Storage schema**: any BoltDB bucket Step T introduces for
  per-cert state SHOULD anticipate future event-log rows (don't
  bake the schema into "only-current-state" assumptions). §3.1
  pins the schema with explicit forward-compat notes.

### 1.4 Managed-domain reframe — wildcard apex policies + unified table

The operator surfaced the actual UX inconsistency that drives the
"Managed domains" rename: the label and the "Declare managed domain"
button do NOT convey that this is the **wildcard-mode activation**
switch. Operators don't realize they're choosing between two cert
strategies (per-route specific vs. apex-level wildcard).

Renames (final strings, locked 2026-06-04 per operator review of
the §1.6 open questions):

- **Section heading**: `Managed domains` → `Politiques wildcard par
  apex` (FR-leaning, matches the rest of `/certs` copy).
- **Button**: `Declare managed domain` → `+ Wildcard apex`. Compact,
  same vocabulary as the table type badge. The button label IS
  the action contract — no separate "+ Domaine" ambiguity.
- **Section lead copy**: explicit about the choice — "Un *wildcard
  apex* émet UN certificat couvrant `*.apex.tld` via DNS-01, partagé
  par toutes les routes en sous-domaine. Sans wildcard apex, chaque
  route avec TLS reçoit son propre certificat (mode par défaut)."

Table merge: the two existing `/certs` tables (`Managed domains` +
`TLS-enabled routes`) collapse into ONE `Domaines` table with a
**type** column / sub-line:

- `wildcard · DNS-01` — issued under a wildcard apex policy
- `apex · DNS-01` or `apex · HTTP-01` — explicit-apex policy (the
  `includeApex: true` flag case)
- `spécifique` — per-route cert (default mode)

Tabs filter the same dataset: `Tous` / `Wildcard` / `Expirent
bientôt`. Rationale: operator sees the complete cert landscape on
one screen and can intuit at a glance whether routes are sharing
wildcards or fanning out into per-route certs.

### 1.5 Deferred items (§1.3 + others)

Recorded explicitly so the spec is honest about its boundary :

- **ACME events log** — see §1.3. Step T+1.
- **ZeroSSL fallback issuer** — see §1.1. Backlog, post-T+N.
- **Multi-DNS-provider** (Cloudflare, Gandi, ACME-DNS, etc.) —
  caddy-dns/* ecosystem support beyond OVH. Backlog. Step T keeps
  the `DNSProvider` Caddy-config seam clean (one provider per
  managed-domain row, as Pack A already does); a future step adds
  the multi-provider catalog.
- **Pack C full visual redesign** per the original cert-page mock.
  Backlog. Step T delivers the unified table + tabs + actions but
  not the broader visual treatment.
- **Per-cert "Revoke"** action. Certmagic supports revoke; we don't
  expose it in T because most operators won't need it and the
  surface adds confusion alongside delete-managed-domain. Backlog.
- **Cert key rotation** UI. Same triage rationale as revoke.
- **Per-domain ACME challenge override** (route configured for
  DNS-01 but using a different DNS provider than the managed apex
  uses). Multi-provider precondition. Backlog.

### 1.6 Open questions — RESOLVED (2026-06-04)

All five open questions surfaced in the original draft were
resolved on 2026-06-04 per operator review. The resolutions are
promoted into the spec body:

- Original §1.6.A (certmagic Cache access path) → locked in
  the new **§1.7** below.
- Original §1.6.B + §1.6.D (UI strings for the reframe + the
  `+ Wildcard apex` button label) → locked in **§1.4**.
- Original §1.6.C (force-renew rate-limit posture) → locked in
  the new **§1.8** below.
- Original §1.6.E (status badge palette) → locked in **AC #10**
  (§2).

No further operator decisions outstanding for the spec freeze.

### 1.7 Locked architecture: certmagic Cache strategy

This subsection is the locked contract for T.1's data-source
design.

**Constraint**: `caddytls.certCache` is a package-level
**unexported** symbol in
`modules/caddytls/tls.go:47` of Caddy v2.11.3. Arenet's Go
import path cannot call `Cache.AllMatchingCertificates` on it
directly. The two alternatives that were on the table (synthetic
TLS handshake replay per subject; Caddy admin API + filesystem
hybrid) were both rejected:

- Synthetic handshake is slow and only reaches certs Caddy
  currently serves.
- Filesystem-only is too tightly coupled to certmagic's on-disk
  layout convention without any push-based signal.

**Locked design**: event-driven in-memory cache + on-disk
reconcile at boot.

1. **Subscription** to the certmagic events that propagate
   through Caddy's events App. Empirically present in
   certmagic v0.25.3 (verified during recon, citations at the
   bottom of this subsection):

   - `cert_obtaining` (about to attempt issuance)
   - `cert_obtained` (issuance succeeded — populates
     CertRuntimeInfo entries)
   - `cert_failed` (issuance failed — populates the volatile
     `failures` map keyed by domain, drives status
     `OBTAIN_FAILED`)
   - `cached_managed_cert` (a managed cert was loaded into the
     in-memory cache — observed at boot AND on rotate)
   - `cached_unmanaged_cert` (operator-loaded cert, NOT a
     normal Arenet code path but subscribed for completeness)

   Subscription via a `events.handlers.arenet_cert_runtime`
   Caddy module registered into the emitted JSON config — same
   pattern as `events.handlers.arenet_topology_hc` from Stage
   B (commits `1926f78`, `3b371d8`). T.1 verifies the
   originating-module filter (`tls.issuance.acme` vs the wider
   `tls` ancestor) **empirically** in the source, NOT
   inferentially. The Stage B Bug 1 lesson stands: read the
   source for the actual `Emit(ctx, ...)` call site, do not
   guess the module ID from the logger name.

2. **In-memory cache** in Arenet — `Tracker` struct in
   `internal/certinfo/tracker.go`. Holds
   `map[domain]CertRuntimeInfo`. Read by
   `GET /api/certificates`. Mutated only via the event handler
   + the boot reconcile. Concurrency: `sync.RWMutex` (mirrors
   `caddyhc.HCStatusTracker`).

3. **Boot reconcile** seeds the tracker before events flow,
   because:

   - Certs obtained BEFORE the events listener registered
     (the typical case on every Arenet boot) have no replay
     channel — events are not persisted by Caddy.
   - Without reconcile, the tracker would report `UNKNOWN` for
     every existing cert until the next obtain or renewal —
     unacceptable UX after a restart.

   Reconcile path: walk certmagic's on-disk storage directory
   (default `$XDG_DATA_HOME/caddy/certificates/<ca>/<domain>/
   <domain>.crt`), parse each leaf PEM via
   `x509.ParseCertificate` (stdlib), populate the tracker. The
   on-disk layout is documented by certmagic; if a future
   release shifts the layout, the reconcile path degrades
   gracefully — affected domains become `UNKNOWN` until the
   first runtime event, wire-shape stays valid.

4. **Forward-compat with Step T+1** (deferred per §1.3). The
   same event subscription that T.1 ships will be the
   data-source for T+1's ACME events log. T+1's persister
   attaches to the tracker's `Subscribe(handler EventHandler)`
   seam (declared in T.1, no-op fan-out in T) without modifying
   T's runtime cache. AC #18 pins this contract.

**Empirical citations** (Caddy / certmagic at the versions
pinned in `go.mod`):

- certmagic v0.25.3, `certificates.go:261`:
  `cfg.emit(ctx, "cached_managed_cert", map[string]any{"sans": cert.Names})`
- certmagic v0.25.3, `config.go:605`:
  `cfg.emit(ctx, "cert_obtaining", map[string]any{"identifier": name})`
- certmagic v0.25.3, `config.go:728`:
  `cfg.emit(ctx, "cert_obtained", ...)`
- certmagic v0.25.3, `config.go:693` and `:983`:
  `cfg.emit(ctx, "cert_failed", ...)`
- Caddy v2.11.3, `modules/caddytls/tls.go:47`:
  `var ( certCache *certmagic.Cache; certCacheMu sync.RWMutex )`
  — package-level, unexported (the constraint).

T.1 RE-RUNS `go list -m -versions github.com/caddyserver/certmagic`
before locking the event-name list. If certmagic moves past
v0.25.3 between this spec freeze and T.1, the implementer
re-verifies the event names + on-disk layout in the source — no
silent assumptions.

### 1.8 Locked rate-limit posture: soft frontend cooldown

Soft client-side cooldown only; no server-side throttle in
Step T.

**Locked design**:

- **Soft frontend cooldown** of 60 seconds per target after a
  successful force-renew dispatch.
  - Per-row Force-renew: cooldown keyed on the row's domain.
    Button disabled + label changes to "Cooldown 58s…"
    (countdown) for the cooldown window.
  - Header global Force-renew: cooldown keyed on the literal
    string `"__global__"`. Button disabled for the same window
    so a spammed global click doesn't enqueue a re-trigger
    before the previous batch completes.
- **No server-side rate limit** in Step T. A Step Q
  `internal/throttle` integration was considered and
  explicitly DEFERRED to a future step (backlog seed in
  `docs/backlog-step-t.md` per T.6).
- **Risk acceptance**: the operator is authenticated; the
  remaining backstop is Let's Encrypt's own rate limit (~5
  renewals per cert per week before LE 429s). This is
  documented in the UI: the auto-renewal info card carries the
  reminder, and the per-cooldown tooltip points at the LE
  rate-limit doc.

**Wire-shape note**: the response from
`POST /api/certificates/renew` already returns
`{"triggered": [<domain>...]}` — that response is sufficient
data for the frontend to start its cooldown clock without an
extra round-trip. No new wire fields needed.

**T.7 smoke verification**: the live smoke (§7 Phase B) MUST
include a spam-click test that confirms the cooldown holds for
60 s on both the per-row and the global affordance, AND that
clicking the still-cooldown button does not fire an HTTP
request (the disabled state is real, not cosmetic).

---

## 2. Acceptance criteria

The numbered criteria below are the authoritative checklist for the
T.7 smoke and the `v1.2.0-step-t` tag. Each must end the step as
PASS, PARTIAL with a documented caveat, or N/A with justification.

**AC #1 — Runtime metadata exposed.** `GET /api/certificates` returns
an array of `CertRuntimeInfo` objects, one per certmagic-managed
certificate. Each row carries: `domain` (primary subject), `sanList`
(string array), `issuer` (string, e.g. "Let's Encrypt"), `notBefore`
(RFC 3339), `notAfter` (RFC 3339), `status` (enum, AC #2),
`source` (enum: `wildcard` / `apex` / `specific`),
`managedDomainApex` (nullable string; populated when source is
wildcard or apex).

**AC #2 — Status string vocabulary.** Status enum values:

- `VALID` — cert is current, not within the renewal window.
- `RENEWAL_PENDING` — cert is within `notAfter - 30d` window OR
  certmagic's `NeedsRenewal()` returns true.
- `EXPIRED` — `notAfter < now`.
- `OBTAIN_FAILED` — most recent `cert_obtaining` event for this
  domain ended with a `cert_failed` event in the last 24h.
- `UNKNOWN` — no information available (e.g. domain expected but
  no on-disk cert + no recent event).

**AC #3 — Force-renew endpoint.** `POST /api/certificates/renew`
accepts an optional `{"domain": "<name>"}` body. Empty body →
trigger renewal on all certs where `status ∈ {RENEWAL_PENDING,
EXPIRED, OBTAIN_FAILED}`. Domain-scoped body → trigger that one
cert. Response is `{"triggered": [<domain>...]}` — the list of
domains for which a renewal task was enqueued. 404 if the
domain-scoped request names a cert the system doesn't know about.

**AC #4 — Single source of truth.** A wildcard apex policy and the
routes it covers appear in the same `/api/certificates` response as
the per-route specific certs. No parallel endpoint, no
client-side merge of two lists.

**AC #5 — Unified Domaines table.** Frontend `/certs` renders one
table titled `Domaines` with the columns from AC #1, plus a per-row
action menu. The previous two-table layout (`Managed domains` +
`TLS-enabled routes`) is gone. The auto-renewal info card from
Pack A stays.

**AC #6 — Tabs filter.** Three tabs above the table: `Tous`
(default) / `Wildcard` / `Expirent bientôt`. Tab state filters the
table rows in place; the API response is fetched once and filtered
client-side (homelab cardinality).

**AC #7 — Per-row Force-renew.** Each row has a `Forcer
renouvellement` action (icon button or kebab-menu item — UI choice
in T.4). Click dispatches `POST /api/certificates/renew` with the
row's domain.

**AC #8 — Global Force-renew header action.** The page header
carries a `Forcer renouvellement` button. Click dispatches
`POST /api/certificates/renew` with empty body. Button surfaces a
toast on success with the count of triggered renewals.

**AC #9 — "+ Wildcard apex" wizard.** The header's primary action
button opens a modal/wizard for wildcard apex declaration. The
wizard reuses Pack A's existing form fields (apex domain input,
DNS provider select, includeApex checkbox) — same validation, same
backend endpoint (`POST /api/settings/managed-domains`). Submitting
the wizard adds a wildcard row to the unified table.

**AC #10 — Status badge palette (LOCKED).** Status pills use the
existing shared `--status-*` token vocabulary declared in
`web/frontend/src/lib/styles/tokens.css`:

- `VALID` → `status-up` (green)
- `RENEWAL_PENDING` → `status-warn` (amber)
- `EXPIRED` → `status-down` (red)
- `OBTAIN_FAILED` → `status-down` (red, same token as EXPIRED)
  PLUS an error-detail tooltip on the row carrying the last
  error message + timestamp from `CertRuntimeInfo.lastError` /
  `lastErrorAt` (§3.1). The badge LABEL distinguishes the two:
  "EXPIRED" vs "OBTAIN_FAILED".
- `UNKNOWN` → `neutral` (gray). Only observable at bootstrap
  before the on-disk reconcile (§1.7) populates the tracker —
  steady-state should never show `UNKNOWN`.

T.4 verifies that the rendered pill colors match the
`--status-*` tokens already used by Topology + Routes (visual
consistency across pages: same hue = same state, app-wide).

**AC #11 — Reframe copy (LOCKED).** Section heading is
`Politiques wildcard par apex`. Section lead copy reads
verbatim from §1.4 ("Un *wildcard apex* émet UN certificat
couvrant `*.apex.tld` via DNS-01, partagé par toutes les routes
en sous-domaine. Sans wildcard apex, chaque route avec TLS
reçoit son propre certificat (mode par défaut)."). Header
primary-action button label is `+ Wildcard apex`. Pack A's
`Declare managed domain` button label is gone from the
codebase.

**AC #12 — Delete-with-revertTo modal preserved.** Pack A's delete
flow (the spec O.4 AC #21 modal with the post-revert challenge
dropdown + the HTTP-01 rate-limit warning) keeps its contract.
Triggered by the per-row delete action on a wildcard apex row in
the unified table.

**AC #13 — Auto-renewal info card preserved.** Pack A's accent-
tinted "Renouvellement automatique" card remains. Position is
the operator's call in T.4 (top-of-content or moved nearer the
Force-renew header action for thematic grouping). Copy is
unchanged.

**AC #14 — Frontend tests pass.** `npm run check` clean (0 errors,
0 warnings) and `npm test` green. The Pack A certs test file
(`web/frontend/src/routes/certs/page.test.ts`) gets updated to
match the new table shape; new tests cover the runtime-metadata
columns, the tab filter, the per-row + global Force-renew calls,
and the wizard submission.

**AC #15 — Backend tests pass.** `go test -race -count=1 ./...`
green across all packages. New tests in `internal/certinfo/`
cover the certmagic-event consumer, the on-disk reconcile path,
and the force-renewal endpoint (with a stub backend that records
trigger calls, not a live cert-obtain).

**AC #16 — Lint / vet / format clean.** `gofmt`, `go vet`, and the
frontend linter report no issues.

**AC #17 — Bundle budget.** `npm run build` completes within the
bundle budget. The new table layout is ~5kB gz max expected
delta (no new component primitives added — same `Card`, `Modal`,
`Badge` already imported by Pack A).

**AC #18 — Forward-compat with T+1.** The `internal/certinfo`
package's event-consumer hook is structured so T+1's ACME-event-
log consumer can subscribe alongside without rewriting any T
storage code. The §3.4 "Forward-compat note" specifies the seam.

---

## 3. Architecture

### 3.1 Backend data model

New package `internal/certinfo/` (parallel to `internal/caddyhc/`,
same shape).

```go
// internal/certinfo/types.go

type CertStatus string

const (
    CertStatusValid          CertStatus = "VALID"
    CertStatusRenewalPending CertStatus = "RENEWAL_PENDING"
    CertStatusExpired        CertStatus = "EXPIRED"
    CertStatusObtainFailed   CertStatus = "OBTAIN_FAILED"
    CertStatusUnknown        CertStatus = "UNKNOWN"
)

type CertSource string

const (
    CertSourceWildcard CertSource = "wildcard"  // *.apex via DNS-01
    CertSourceApex     CertSource = "apex"      // apex.tld direct (includeApex)
    CertSourceSpecific CertSource = "specific"  // per-route HTTP-01 or DNS-01
)

// CertRuntimeInfo is the wire shape returned by GET /api/certificates.
// One row per certmagic-managed certificate. Field-by-field mirror of
// the frontend CertRow interface so the JSON is directly assignable
// on the client — no adapter layer.
type CertRuntimeInfo struct {
    Domain            string     `json:"domain"`             // primary subject
    SANList           []string   `json:"sanList"`            // full DNS names list
    Issuer            string     `json:"issuer"`             // e.g. "Let's Encrypt"
    NotBefore         time.Time  `json:"notBefore"`          // RFC 3339
    NotAfter          time.Time  `json:"notAfter"`           // RFC 3339
    Status            CertStatus `json:"status"`
    Source            CertSource `json:"source"`
    ManagedDomainApex string     `json:"managedDomainApex,omitempty"` // wildcard/apex source
    LastError         string     `json:"lastError,omitempty"`         // populated on OBTAIN_FAILED
    LastErrorAt       *time.Time `json:"lastErrorAt,omitempty"`
}
```

**Tracker shape** (mirrors `caddyhc.HCStatusTracker`):

```go
type Tracker struct {
    mu       sync.RWMutex
    byDomain map[string]*CertRuntimeInfo
    failures map[string]failureRecord // last cert_failed per domain
    now      func() time.Time         // injectable for tests
}
```

**Storage** (BoltDB, optional bucket — Step T uses in-memory only
because runtime metadata regenerates on boot; T+1's event log will
add a bucket). Forward-compat note for §1.3 / AC #18:

- Bucket name reserved: `cert_events` (T does NOT create it). T+1
  uses it for event-log persistence. T's in-memory cache is the
  source of truth for current-state.
- Tracker's `failures` map is volatile by design — only certmagic
  events from the current process lifetime populate it. A failure
  that happened before the last restart is observable via the cert
  itself being absent (status `UNKNOWN`) but not as a specific
  `OBTAIN_FAILED` annotation. Documented limitation; T+1's
  persistent event log fixes it.

### 3.2 API contracts

`GET /api/certificates`:

```json
[
  {
    "domain": "api.example.com",
    "sanList": ["api.example.com"],
    "issuer": "Let's Encrypt",
    "notBefore": "2026-04-12T10:00:00Z",
    "notAfter": "2026-07-11T10:00:00Z",
    "status": "VALID",
    "source": "specific"
  },
  {
    "domain": "*.example.com",
    "sanList": ["*.example.com", "example.com"],
    "issuer": "Let's Encrypt",
    "notBefore": "2026-05-01T10:00:00Z",
    "notAfter": "2026-07-30T10:00:00Z",
    "status": "VALID",
    "source": "apex",
    "managedDomainApex": "example.com"
  }
]
```

Sorted by `notAfter` ascending (closest-to-expiry first) so the
default `/certs` view surfaces what needs attention. Tab `Expirent
bientôt` filters this same sort.

`POST /api/certificates/renew`:

Request body (optional):
```json
{ "domain": "api.example.com" }
```

Response body (200):
```json
{ "triggered": ["api.example.com"] }
```

Response body (200, empty-request global renew):
```json
{ "triggered": ["api.example.com", "*.example.com"] }
```

Error responses:
- 400 — malformed body.
- 404 — domain-scoped request names a cert the system doesn't know.
- 429 — not used in Step T. The locked cooldown posture (§1.8)
  is client-side only; the server has no app-level throttle
  to surface a 429 from. Reserved in the wire vocabulary so a
  future server-side cooldown (backlog, not Step T) can adopt
  it without a wire shape break.
- 500 — certmagic-internal error during the renewal trigger.

### 3.3 Frontend page structure

`/certs/+page.svelte` rebuilt as :

```
┌─────────────────────────────────────────────────────────┐
│ PageHeader: Certificates · Sécurité Certificats         │
│ [Forcer renouvellement]  [+ Wildcard apex]              │← header actions
├─────────────────────────────────────────────────────────┤
│ Auto-renewal info card (Pack A, unchanged)              │
├─────────────────────────────────────────────────────────┤
│ KPI row (4 cards): Managed domains / TLS-enabled        │
│   routes / ACME method / Issuer (unchanged from Pack A) │
├─────────────────────────────────────────────────────────┤
│ Tabs: [Tous]  [Wildcard]  [Expirent bientôt]            │
├─────────────────────────────────────────────────────────┤
│ Domaines table                                          │
│ ┌────────────┬───────┬───────┬─────┬────────┬────────┐  │
│ │ Domaine    │ ÉMET. │ SAN # │ ÉMIS│ EXPIRE │ ÉTAT   │  │
│ │            │       │       │ LE  │ DANS   │  + ⋮  │  │
│ │ *.x.com    │ LE    │ 2     │ 5d  │ 90d    │ VALID  │  │
│ │   wildcard │       │       │     │        │        │  │
│ │ api.x.com  │ LE    │ 1     │ 3d  │ 28d    │ RENEW_ │  │
│ │   spécif.  │       │       │     │        │ PENDING│  │
│ └────────────┴───────┴───────┴─────┴────────┴────────┘  │
└─────────────────────────────────────────────────────────┘
```

The "Politiques wildcard par apex" reframe lives BELOW the table as
a small explanatory card describing the wildcard mode + a hint
button "+ Wildcard apex" that mirrors the header action. The
section provides context for operators encountering wildcards for
the first time; the header button handles the action for operators
who already know what they want.

The Pack A inline list + form + delete modal is REPLACED by:
- Add: wizard modal (per-spec wildcard apex declaration).
- Delete: kebab-menu item on a wildcard row → opens Pack A's
  existing revertTo modal (verbatim port).

### 3.4 Wildcard apex policy semantics + certmagic integration

**Type detection.** For each cert in the runtime cache:

1. If primary subject starts with `*.` AND a managed-domain row
   exists for the same apex → `source = wildcard`.
2. If primary subject equals a managed-domain apex AND that row has
   `includeApex: true` → `source = apex`.
3. Otherwise → `source = specific`.

**Edge case**: an operator declares a managed domain for `*.x.com`
but ALSO has an individual route `api.x.com` configured for
per-route HTTP-01 before the managed domain was declared. Caddy's
TLS app prefers the wildcard at serve-time, but the per-route cert
may still exist on disk. Step T's `source` detection respects
which cert Caddy SERVES (via the wildcard policy match), not which
cert exists on disk. T.1 verifies this against
`t.HasCertificateForSubject(subject)` and the per-policy subject
list emitted by caddymgr.

**certmagic event subscription** (per the empirical recon at the
top of this draft). T.1 implements a Caddy events handler module
following the same pattern as `internal/caddyhc/listener.go`:

- Module ID: `events.handlers.arenet_cert_runtime`.
- Subscribes to: `cert_obtaining`, `cert_obtained`, `cert_failed`,
  `cached_managed_cert`, `cached_unmanaged_cert`.
- Filter: `modules:
  ["http.handlers.reverse_proxy.health_checker"]` is the
  caddyhc pattern; the certmagic events emit from
  `tls.issuance.acme` (the Caddy ACME issuer module). T.1
  empirically confirms the module ID against
  `modules/caddytls/acmeissuer.go` before locking the filter.
- Handler delegates into `*certinfo.Tracker` (package-level
  singleton, same install pattern as caddyhc).

**Boot reconcile**: on Arenet boot, `internal/certinfo` reads the
certmagic on-disk storage (default
`$XDG_DATA_HOME/caddy/certificates/`) and seeds the tracker with
every PEM it finds. The PEM is parsed via `x509.ParseCertificate`
(stdlib) — no certmagic-private API needed. Forward-compat: if a
future certmagic release changes the on-disk layout, the
reconcile path degrades gracefully (status `UNKNOWN` per-domain
until the first event arrives), so the wire shape stays valid.

**Forward-compat note for T+1** (AC #18). The Tracker exposes a
`Subscribe(handler EventHandler)` method (no-op in T, the seam for
T+1's event log). T+1 attaches its log-persister via this seam
without modifying T's runtime cache. Same pattern as the `caddyhc`
package's `SetTracker` singleton — public API surface, stable
across implementations.

---

## 4. Sub-tasks

| Sub-task | Scope | Estimated effort |
|---|---|---|
| **T.1** | `internal/certinfo` package: tracker + event handler module + boot reconcile against certmagic on-disk storage. Unit + race tests. | 3–4 h |
| **T.2** | API endpoints: `GET /api/certificates` + `POST /api/certificates/renew`. Wires the tracker as a `CertRuntimeReader` interface on the `Handler`. Mirrors the Stage B `SetHCStatusReader` pattern. Unit tests. | 2–3 h |
| **T.3** | Force-renewal storage + soft client cooldown. Server-side renewal trigger calls into certmagic's `cfg.RenewCert` (or the Manage() interface that performs the same work). | 1–2 h |
| **T.4** | Frontend `/certs` unified table + tabs + per-row + global Force-renew actions. Drop the two-table layout. Keep the auto-renewal card. Updated test file. | 3–4 h |
| **T.5** | Frontend reframe + "+ Wildcard apex" wizard modal. Locked copy strings from §1.4. Wildcard policies explanatory card below the table. | 1–2 h |
| **T.6** | Backlog cleanup: mark `#R-6` Pack A's "Pack B deferred to Step T" note as DONE; seed Step T's own deferred items (ZeroSSL, multi-DNS-provider, revoke, ACME event log Step T+1) into a new `docs/backlog-step-t.md`. | 0.5 h |
| **T.7** | Live smoke session against the T.1–T.6 build: every AC exercised, findings recorded, verdict emitted, smoke doc written. Hotfix any blocking findings before tag. | 2–3 h |

Total estimated effort: **12–18 hours** of focused work. T.1 and T.4
dominate; the rest is glue.

Sub-task ordering follows the data-flow direction: T.1 (data
producer) → T.2 (API surface) → T.3 (mutation surface) → T.4 (UI
consumer) → T.5 (UI polish/reframe) → T.6 (docs cleanup) → T.7
(smoke). T.4 can begin in parallel with T.3 against a hand-written
fixture JSON if needed.

---

## 5. Implementation details per sub-task

### 5.1 T.1 — `internal/certinfo` package

**Files**:
- `internal/certinfo/types.go` — `CertStatus`, `CertSource`,
  `CertRuntimeInfo` (per §3.1).
- `internal/certinfo/tracker.go` — `Tracker` struct + `Record*`
  methods + `List() []CertRuntimeInfo` + `Status(domain) CertStatus`
  helpers.
- `internal/certinfo/listener.go` — Caddy events handler module
  (`events.handlers.arenet_cert_runtime`), package-singleton wiring
  pattern from `internal/caddyhc/listener.go`.
- `internal/certinfo/reconcile.go` — boot-time on-disk PEM scan +
  parse + seed-into-tracker.
- `internal/certinfo/*_test.go` — table tests for status derivation,
  source detection, reconcile against a fixture certmagic storage
  directory, race tests on the tracker map.

**Caddymgr integration**: side-effect import in
`internal/caddymgr/manager.go` (mirrors `_
"github.com/barto95100/arenet/internal/caddyhc"` from Stage B), so
the module registers before `caddy.Load`.

**buildConfigJSON change**: emit `apps.events.subscriptions[]` entry
for the cert events (sibling of the caddyhc subscription Stage B
introduced).

**Tests**: `internal/certinfo/listener_test.go` covers every event
name we subscribe to; `tracker_test.go` covers concurrent
RecordObtain + Status under `-race`; `reconcile_test.go` builds a
testdata fixture certmagic dir + asserts the parsed runtime metadata.

### 5.2 T.2 — API endpoints

**Files**:
- `internal/api/certificates.go` (new) — `listCertificates`,
  `renewCertificates` handlers.
- `internal/api/handler.go` — new `certRuntime CertRuntimeReader`
  field + `SetCertRuntimeReader` setter (matches the `hcStatus`
  pattern from Stage B).
- `internal/api/routes.go` — route registrations:
  `r.Get("/certificates", h.listCertificates)` +
  `r.Post("/certificates/renew", h.renewCertificates)`.

**Wire**: `cmd/arenet/main.go` constructs the tracker before
`mgr.Start` (Stage B pattern), calls
`apiHandler.SetCertRuntimeReader(certTracker)`.

**Tests**: `internal/api/certificates_test.go` covers wire shape,
sort order (closest-expiry first), domain-scoped renew vs global
renew, 404 on unknown domain, 400 on malformed body.

### 5.3 T.3 — Renewal trigger

**Files**:
- `internal/certinfo/renew.go` — `Trigger(domain string) error` and
  `TriggerAll(eligibleOnly bool) ([]string, error)`. Calls into the
  certmagic instance via the Caddy events App or the configured
  TLS app's `Manage()` method (T.1 picks the seam; T.3 uses it).
- `internal/api/certificates.go` — handler wires the trigger to the
  endpoint.

**Frontend cooldown**: `web/frontend/src/routes/certs/+page.svelte`
holds a `lastRenewAt: Date | null` per-domain in component state;
the per-row Force-renew button is disabled for 60 s post-click.

### 5.4 T.4 — Frontend unified table

**Files**:
- `web/frontend/src/routes/certs/+page.svelte` — table rebuild.
- `web/frontend/src/lib/api/certs.ts` (new, or extension of
  existing `settings.ts`) — `listCertificates` + `renewCertificates`
  API client functions.
- `web/frontend/src/lib/api/types.ts` — `CertRuntimeInfo`,
  `CertStatus`, `CertSource` types (camelCase mirrors of the Go
  wire shape).
- `web/frontend/src/routes/certs/page.test.ts` — updated for the
  new table layout + tab filter + Force-renew actions.

**Component reuse**: existing `Badge`, `Button`, `Modal`, `Spinner`,
`PageHeader`. No new component primitives.

### 5.5 T.5 — Reframe + wizard

**Files**:
- `web/frontend/src/routes/certs/+page.svelte` — copy updates per
  §1.4 (locked strings) + the wizard modal
  for "+ Wildcard apex".

**Wizard structure**: single-page modal (no multi-step needed for
3 fields). Mirrors Pack A's existing form fields verbatim — same
validation, same backend endpoint. Mounts via the header `+
Wildcard apex` button. Closes on submit-success → table reload.

### 5.6 T.6 — Backlog cleanup

**Files**:
- `docs/backlog-step-r.md` — annotate `#R-6`'s "Pack B deferred"
  note as DONE-in-Step-T (or kept open if T.7 surfaces a regression).
- `docs/backlog-step-t.md` (new) — seed deferred items per §1.5
  (ZeroSSL, multi-DNS-provider, revoke, T+1 ACME event log).

### 5.7 T.7 — Live smoke

**Plan**: §7 of this spec, executed at the close of T.5 against a
build that includes T.1–T.5. Findings → hotfix commits before the
`v1.2.0-step-t` tag.

---

## 6. Threat model

### 6.1 Force-renewal DOS

**Vector**: an authenticated admin spams the global Force-renew
button. Each click enqueues N renewals (N = certs with status ∈
{RENEWAL_PENDING, EXPIRED, OBTAIN_FAILED}).

**Let's Encrypt rate-limit awareness** (the real backstop, not
the app's). LE applies a per-cert *Duplicate Certificate* rate
limit of 5 identical (same SAN list) renewals per week. Once
tripped, LE returns 429 for ~7 days from the first hit — long
enough that an operator who spammed-then-actually-needed a renew
has lost their issuance window. A homelab with ~10 routes and a
single-click "renew all eligible" lands one renewal per
eligible cert; the trip risk is the rapid-fire repetition of
that click within the LE 1-week window, not a single click.

**Mitigation (locked per §1.8)**:

- **Frontend cooldown: 60 s between clicks per-target.** Per-row
  cooldown keyed on the row's domain; header global cooldown
  keyed on `"__global__"`. UI disables the button + shows a
  countdown ("Cooldown 58s…"). No HTTP request fires during
  the cooldown — the disabled state is real, T.7 smoke
  confirms.
- **No server-side rate limit in Step T.** The Step Q
  `internal/throttle` integration that would have provided one
  is explicitly deferred to backlog. Operator-accepted risk per
  the §1.8 lock — homelab scale, authenticated-admin only.
- **UI surfaces the LE ceiling**. The cooldown tooltip on the
  Force-renew button cites the LE 5/week ceiling so an operator
  who scripts force-renew calls (bypassing the cooldown
  client-side) does so with the rate-limit consequence visible.
  Does not prevent the abuse; documents the boundary.

### 6.2 Information disclosure

**Disclosed in the wire shape**: domain, SAN list, issuer,
notBefore, notAfter, status, source. All known to the operator
already (the operator created the routes). No private key
material, no cert PEM body, no certmagic storage path.

**Untouched**: certmagic's on-disk PEM files (mode 0600,
process-user-owned by default). Step T reads them only at boot to
seed the tracker; no API surface streams them. Revoke and key-
rotation are out of scope (§1.5).

### 6.3 certmagic API surface assumptions

§1.7 documents the locked event-driven + on-disk-reconcile
workaround for the unexported-cache constraint. The locked
strategy relies on:

- **certmagic events**: `cert_obtaining`, `cert_obtained`,
  `cert_failed`, `cached_managed_cert`, `cached_unmanaged_cert`.
  Empirically present in v0.25.3 (`certificates.go:261`,
  `config.go:605/693/728`). Subscription path via Caddy events App
  is the same one Stage B uses for HC — stable.
- **On-disk storage layout**: documented in certmagic README;
  `<storage>/certificates/<ca>/<domain>/<domain>.crt` PEM-encoded
  leaf + chain. If a future certmagic release changes this layout,
  Step T's boot reconcile degrades to `UNKNOWN` per-domain until
  the first event arrives — wire-shape-safe, just less complete
  metadata. T.7 smoke confirms behavior under the current
  v0.25.3 layout.

### 6.4 Empirical-verification reminder

Per `CLAUDE.md` §"Empirical verification of external dependencies":
T.1 implementation re-runs `go list -m -versions
github.com/caddyserver/certmagic` before locking the event-name
list. If certmagic moves past v0.25.3 between spec freeze and
T.1, the implementer re-verifies the event names + on-disk layout
empirically — no silent assumptions.

---

## 7. Smoke test plan (skeleton, filled at T.7)

### Phase 0 — Setup

- Operator runs a build at the T.6 tip.
- BoltDB at default location; clean install with 3-4 routes pre-
  configured (mix of TLS-enabled per-route + wildcard-covered).
- ACME against LE **staging** (`acme-staging-v02.api.letsencrypt.org`)
  to avoid production rate limits.

### Phase A — Regression of Pack A

- AC #12 (delete-with-revertTo modal): trigger from the new
  table's row kebab → confirm Pack A's exact dialog opens, exact
  warning text, exact behavior.
- AC #13 (auto-renewal info card): visible on `/certs`. Copy
  byte-identical to Pack A.
- Pack A `POST /api/settings/managed-domains` flow (now wrapped in
  the new wizard) still creates a managed-domain row. Existing
  `/api/settings/managed-domains` GET + POST + DELETE unchanged.

### Phase B — New Step T features (AC by AC)

- **AC #1, #2, #4** — exercise `GET /api/certificates`. Pre-condition:
  certmagic has obtained at least 2 certs (one per-route, one
  wildcard). Inspect the JSON response: every field matches, no
  extra/missing keys, sort order is by expiry ascending.
- **AC #3, #7, #8** — global vs per-row Force-renew. Click both,
  observe `triggered[]` contents, confirm certmagic actually runs
  the renewal task (LE staging log + new `notBefore` post-renew).
- **AC #5, #6** — unified table renders both wildcards and
  specifics, tabs filter correctly, "Expirent bientôt" surfaces
  the closest-expiry rows.
- **AC #9** — "+ Wildcard apex" wizard opens, submission creates
  the row, table reloads.
- **AC #10** — color palette: the locked `--status-*` mapping
  from AC #10 itself + the OBTAIN_FAILED tooltip.
- **AC #11** — reframe strings present, "Declare managed domain"
  label is gone.

### Phase C — AC validation matrix

One row per AC #1–#18. Each records PASS / PARTIAL / FAIL.
AC #14–#17 verified by running gates directly (`npm test`,
`go test`, `gofmt`/`go vet`, `npm run build`).

### Phase D — Forward-compat smoke (AC #18)

- Inspect `internal/certinfo/tracker.go` for the `Subscribe(handler
  EventHandler)` seam. The seam exists, callable from T+1's
  package without modifying T's code. Validated by an in-test
  ghost subscriber (`tracker_subscribe_test.go`).

---

## 8. Ship plan

- **Spec freeze tag**: `v1.2.0-step-t-spec` — annotated tag posted
  on the freeze commit (the §1.6 open questions were resolved
  by the operator on 2026-06-04 and promoted into §1.4 / §1.7 /
  §1.8 / AC #10 by the same commit).
- **Ship tag**: `v1.2.0-step-t` — annotated, posted after T.7
  smoke PASS + any hotfix commits land. Continues the v1.1.x →
  v1.2.x line started by Pack A (Pack A landed on the v1.1.x
  line; Step T is a feature-meaningful enough step to bump the
  minor).

No intermediate tags between spec freeze and ship; per-sub-task
commits live on `main`. The T.6 backlog seeds reference the spec's
own §1.5 deferral list verbatim.

**Sequence with the broader backlog**:

- Step T+1 (ACME event log) likely follows. Spec'd separately —
  this Step T's §1.3 + §3.4 forward-compat notes are the
  preconditions, no spec dependency in the other direction.
- ZeroSSL fallback and multi-DNS-provider are independent backlog
  items, not Step T+1 prerequisites.

---

## 9. Implementation notes

Vigilance notes for the implementer, distinct from any narrative
already in §5 / §6.

- **caddytls.certCache is unexported** (§1.7). Do NOT attempt to
  reach it via reflection or build-time linker tricks. The
  locked design is the event-driven cache with on-disk
  reconcile — full citations + the rejected-alternatives
  rationale in §1.7 + §6.3.
- **certmagic event filter selector** in `apps.events.subscriptions`:
  the brief assumes `tls.issuance.acme` is the module ID emitted
  by certmagic. T.1 verifies empirically against
  `modules/caddytls/acmeissuer.go` and `caddytls/connpolicy.go`
  before locking the filter — same discipline as the Stage B
  `http.handlers.reverse_proxy.health_checker` verification
  surfaced the wrong filter on first deploy (Bug 1 in the Stage B
  debug round). Read the source, don't infer.
- **Force-renew calls certmagic.RenewCert** (or the equivalent
  via the Caddy TLS app). The package's documented entry-point
  for "renew this specific cert now" needs T.1 verification: in
  v0.25.3, `*Config.RenewCert(ctx, domain string, interactive
  bool)` is on the Config struct. Whether that's reachable from
  Arenet via `caddy.GetApp("tls").(*caddytls.TLS).manage(...)` or
  via a different seam is the T.3 reconnaissance question.
  Document the chosen seam inline.
- **No tests should hit Let's Encrypt** — not even staging. Unit
  tests use a fixture certmagic storage dir + a stub event
  source. T.7 (live smoke) is the only path that hits LE staging,
  and it does so explicitly.
- **The Pack A `settingsApi.listManagedDomains` endpoint is
  preserved** — Step T's `/api/certificates` is ADDITIVE, not
  replacing. Pack A's tests still pass; the new tests cover the
  new endpoint only. If a future cleanup merges the two surfaces,
  that's a separate step (likely Pack C visual or a wider IA
  cleanup).

---

