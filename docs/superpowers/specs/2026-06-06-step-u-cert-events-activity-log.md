<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step U — Cert events in Activity log

**Tag**: `v1.3.0-step-u-spec` (to be created post-merge by the operator)
**Status**: FROZEN
**Discovery**: `docs/superpowers/discovery/2026-06-06-step-t-plus-1-cert-events-logs.md` (commit `27b110a`)

## 0. Executive summary

Cert lifecycle events (`cert_obtained`, `cert_failed`,
`cert_ocsp_revoked`) flow from the certinfo Tracker's existing
Subscribe seam (AC #18 of Step T, commit `1350777`) into a new
sink that persists rows to `metrics.db`, exposed via a new
`GET /api/v1/observability/cert-events` endpoint. The frontend
Logs page — already a unified-table aggregator over WAF /
throttle / auth-failure — gains a fourth mapper to render cert
rows. The page is renamed "Activity log" to reflect the
widened scope. The auto-renewal info card on `/certs` then
correctly points operators at a stream that actually carries
the cert events it promises.

No new Caddy event subscription is needed (Step T's
`arenet_cert_info` handler already ingests all three certmagic
events); no UI redesign is needed (the unified-table pattern
absorbs the new source). The work is mechanically additive
across the stack and follows the established sink + reader +
handler pattern (WAF / throttle / decision precedents).

## 1. Goals

- Surface ACME cert lifecycle events
  (`cert_obtained` / `cert_failed` / `cert_ocsp_revoked`) in
  the operator-facing Logs page.
- Honor the existing unified-table aggregator pattern (zero UI
  rework for filter / badge / level controls).
- Reuse Step T's `Tracker.Subscribe` seam — no new Caddy
  subscription, no changes to the existing `events`
  subscription block in `caddymgr/manager.go`.
- Establish boot-log visibility for the new sink, generalizing
  the HF4 pattern (commit `30418ea`) from `purger_present` to
  `cert_event_sink_present`.
- Resolve the operator-facing copy gap on `/certs`: the
  auto-renewal info card already references "page Logs" but
  cert events have not been in that stream until now.

## 2. Non-goals (explicit)

- **WebSocket real-time delivery.** Existing Logs page polls
  every 10s; cert events are bursty but a 10s lag is
  operationally fine. WS migration is a future-step concern.
- **`cert_obtaining` persistence.** High-volume retry noise;
  `obtained` / `failed` already capture every outcome. The
  Subscribe seam still fires `EventCertObtaining` for any
  future real-time consumer; only the sink filters it out.
- **`cached_managed_cert` / `cached_unmanaged_cert`
  persistence.** Informational only, fire on every cert cache
  load (boot + every reload).
- **`EventCertRemoved` persistence.** The operator action that
  triggered the removal is already in the audit log per spec
  D2.B (commit `e4177e4`'s deleteManagedDomain handler
  appends `ActionManagedDomainDeleted` ahead of the tracker
  purge).
- **Force-renewal UI.** Still deferred per
  `docs/step-t-spec-amendment.md` (Caddy v2.11.3's
  `getConfigForName` is unexported; revisit conditions
  documented in `#R-CERTS-force-renew`).
- **Cross-table search.** The Logs page already searches
  across the union via the textbox; no need to add a backend
  full-text index. SQLite `LIKE` on the per-table query is
  enough for the cardinality involved.

## 3. Locked decisions

All eight decisions below are the spec's response to the
discovery doc §5 open questions. Operator approved all eight
recommendations.

### §3.1 Storage: new `cert_event` table in `metrics.db`

Sink-pattern uniformity with `waf_event` / `throttle_event` /
`decision_event`. No import cycle (audit-bucket-reuse Option B
would have required reversing the existing `api` → `audit`
direction). Query layer mirrors the existing
`Query*Events(ctx, filter)` readers.

Schema v5 DDL (sketch — full migration in U.1):

```sql
CREATE TABLE cert_event (
    id            INTEGER PRIMARY KEY,
    ts            INTEGER NOT NULL,          -- epoch ms (uniform with other tables)
    kind          TEXT NOT NULL,             -- 'obtained' | 'failed' | 'ocsp_revoked'
    domain        TEXT NOT NULL,
    is_renewal    INTEGER NOT NULL,          -- 0/1, meaningful only when kind='obtained'
    issuer        TEXT,                      -- populated when kind='obtained'
    challenge     TEXT,                      -- 'DNS-01' | 'HTTP-01' | NULL (heuristic)
    error         TEXT                       -- populated when kind='failed'
);
CREATE INDEX idx_cert_event_ts        ON cert_event(ts);
CREATE INDEX idx_cert_event_domain_ts ON cert_event(domain, ts);
CREATE INDEX idx_cert_event_kind_ts   ON cert_event(kind, ts);
```

### §3.2 Retention: 90 days

Matches the Let's Encrypt certificate lifecycle (90 days),
which covers one complete renewal cycle for troubleshooting.
Reuses the existing retention sweep mechanism (the same
goroutine that prunes `waf_event` / `throttle_event` /
`decision_event` per the per-table TTL config).

### §3.3 `cert_obtaining` is NOT persisted

Redundant with `obtained` / `failed`, which capture every
outcome. certmagic's exponential retry on a failing domain
would generate dozens of `cert_obtaining` rows per day with
no operator-visible value. The Subscribe-seam fan-out still
emits `EventCertObtaining` for any future real-time consumer
(WS upgrade, AC #18 forward-compat); only the persistence
path filters it.

### §3.4 Page rename: "Security events" → "Activity log"

Scope widens past "security" with cert events. "Activity log"
stays operator-friendly without being overly generic.
Subtitle copy updates to reflect WAF + throttle + auth +
certs (exact phrasing decided in U.6, but the title is locked
to "Activity log").

### §3.5 `cached_managed_cert` / `cached_unmanaged_cert`: skip

Informational only. Fires on every cert cache load (boot +
every reload). T.1 already ignores them on the read-path;
U.1 ignores them on the persistence path. No DB row, no
operator-visible footprint.

### §3.6 `cert_ocsp_revoked`: INCLUDED, level=ERROR

Security-relevant signal: a previously-issued cert was
revoked upstream (often indicates key compromise or
intentional revocation). Low-volume, high-value. Adds a new
`EventCertOCSPRevoked` kind to the certinfo Subscribe enum
(extends `internal/certinfo/types.go`'s `EventKind`).

The certmagic emit site is `maintain.go:375` with payload
`{identifier, certificate}` (verified empirically during
discovery). T.1 did not subscribe to this event; U.2
extends the caddymgr subscription's `events` array to
include `"cert_ocsp_revoked"` and adds the corresponding
event-name dispatch in `internal/certinfo/listener.go`.

### §3.7 Delivery: polling only (v1)

Simpler implementation, smaller attack surface, consistent
with the existing four data sources on the Logs page (all
poll every 10s). WS migration possible if a future spec
needs live tail.

### §3.8 `EventCertRemoved`: NOT persisted to `cert_event`

The operator action that triggered the removal is already in
the audit log (commit `e4177e4`'s `deleteManagedDomain`
handler appends `ActionManagedDomainDeleted` BEFORE invoking
the tracker purge). Duplicating it as a `cert_event` would
mix system-emitted events with operator-driven action
signals, muddying the operational distinction the audit
bucket exists to preserve.

The Subscribe seam still fires `EventCertRemoved` for any
future consumer (and the existing
`TestTracker_Remove_FanOut` test pins that contract); only
the U.1 sink ignores it on the persistence path.

## 4. Architecture

The discovery doc carries the full architecture mapping
with file:line citations. Summary of the U-introduced
components:

1. **New `internal/observability/cert_events.go`** —
   schema migration v4 → v5 (add `cert_event` table),
   `InsertCertEventBatch(ctx, events)`,
   `QueryCertEvents(ctx, filter)`, retention-sweep
   integration. Mirrors `waf_events.go` shape.

2. **New `internal/certinfo/sink.go`** — channel + batcher
   goroutine implementing `certinfo.EventHandler`. Subscribes
   via `tracker.Subscribe(sink)` at boot. Filters per §3.3,
   §3.5, §3.8 (drops `EventCertObtaining` and
   `EventCertRemoved` on the persistence path). Flush
   policy: every 1s OR every 256 events (sized like
   `internal/throttle/sink.go`).

3. **caddymgr update** — extend the existing `tls` event
   subscription's `events` array to include
   `"cert_ocsp_revoked"`. ONE-line addition to the existing
   block in `internal/caddymgr/manager.go`. No new
   subscription block.

4. **`internal/certinfo/listener.go` update** — extend the
   event-name dispatch to handle `cert_ocsp_revoked` (call
   `tracker.RecordRevoked(domain)` or equivalent — exact
   method name decided in U.1; preserves the existing
   `cert_obtained` / `cert_failed` / `cert_obtaining`
   dispatch paths verbatim).

5. **`internal/certinfo/tracker.go` update** — new
   `RecordRevoked(domain)` method that fans out an
   `EventCertOCSPRevoked` event without mutating tracker
   state (the cert may still appear VALID until certmagic
   replaces it). Same shape as `RecordObtaining`.

6. **New `internal/api/cert_events.go`** — reader
   interface (`CertEventReader`), `securityCertEvents`
   handler, registered in `routes.go` under the
   admin-auth chi group. AC #13 degraded mode: nil reader
   → `200 {events: [], total: 0, hasMore: false}`.

7. **Frontend additive** — `lib/api/types.ts` gains
   `CertEvent` + `CertEventsResponse`; `lib/api/security.ts`
   gains `fetchCertEvents`; `routes/logs/+page.svelte`
   gains a `mapCert` function in the existing
   parallel-load aggregator. NO new components, NO new
   filter UI.

8. **Page copy rename** — `PageHeader` title and subtitle
   on `routes/logs/+page.svelte` updated per §3.4.

9. **Boot log** — `cmd/arenet/main.go` emits
   `msg="cert event sink wired" present=true` immediately
   after the sink is constructed and subscribed. Mirrors
   HF4's `purger_present=true` pattern (commit `30418ea`)
   and seeds the `#R-API-boot-log-audit` backlog item's
   reference implementation for the future sweep.

## 5. API contract

### 5.1 `GET /api/v1/observability/cert-events`

Admin-auth gated (same `HardAuthMiddleware` group as the
other `/security/*` and `/observability/*` endpoints).

Query parameters (all optional):

| Param | Type | Default | Notes |
|---|---|---|---|
| `limit` | int | `100` | Max `1000`; values above are clamped down (per existing pattern). |
| `since` | RFC 3339 string | unset | Inclusive lower bound on `ts`. |
| `until` | RFC 3339 string | unset | Exclusive upper bound on `ts`. |
| `level` | string | unset | Comma-separated subset of `info,error`. Empty / unset = all. |
| `search` | string | unset | Substring match on `domain`, `issuer`, `error`. SQLite `LIKE` with leading `%` (anchored-suffix indexable case handled in U.1 if profiling demands it). |

### 5.2 Response (200 OK)

```json
{
    "events": [
        {
            "timestamp": "2026-06-06T01:34:56.123Z",
            "level": "INFO",
            "eventType": "cert_obtained",
            "domain": "*.example.com",
            "issuer": "Let's Encrypt",
            "challenge": "DNS-01",
            "renewal": false,
            "error": "",
            "details": ""
        },
        {
            "timestamp": "2026-06-06T01:32:11.456Z",
            "level": "ERROR",
            "eventType": "cert_failed",
            "domain": "test.local",
            "issuer": "",
            "challenge": "",
            "renewal": false,
            "error": "subject 'test.local' does not qualify for a public certificate",
            "details": ""
        }
    ],
    "total": 142,
    "hasMore": false
}
```

JSON field-name convention is camelCase (consistent with the
Step T `CertRuntimeInfo` wire shape and the existing
security-events responses). Timestamp is RFC 3339 with
millisecond precision (the same format
`internal/api/handler.go`'s `timestampFormat` constant
defines).

### 5.3 Degraded mode (AC #13 of Step T carried forward)

If `h.certEvents` is `nil` (sink boot-failure, missing wire
in `cmd/arenet/main.go`, or a future refactor that drops the
setter), the endpoint returns:

```json
{ "events": [], "total": 0, "hasMore": false }
```

with HTTP 200. No `5xx`. Same degraded-mode contract every
other observability endpoint already honors.

## 6. Acceptance criteria

**AC #1**: `cert_obtained` event persists with `level=INFO`,
`renewal=false` on the first obtain for a domain,
`renewal=true` on subsequent obtains (certmagic disambiguates
via the `renewal` payload field — verified empirically in T.1
recon).

**AC #2**: `cert_failed` event persists with `level=ERROR`,
carrying the raw certmagic error string in `error`. When the
payload includes a `remaining` attempt count, it's appended
to `details` (defensive — the field is present in
`certmagic/config.go:693, :983` payloads).

**AC #3**: `cert_ocsp_revoked` event persists with
`level=ERROR`. The caddymgr `events` array gains
`"cert_ocsp_revoked"` in U.2; the listener dispatches to a
new `tracker.RecordRevoked(domain)` which fans out
`EventCertOCSPRevoked`.

**AC #4**: `cert_obtaining` event is NOT persisted (sink
filters it on the persistence path). The Subscribe seam
still fires it for any future real-time consumer.

**AC #5**: `cached_managed_cert` / `cached_unmanaged_cert`
events are NOT persisted. T.1 never subscribed to them; U.2
does not change that.

**AC #6**: `EventCertRemoved` (commit `e4177e4`'s synthetic
event) is NOT persisted to `cert_event`. The audit-log path
(`ActionManagedDomainDeleted` appended ahead of the purge in
`deleteManagedDomain`) remains the canonical record of the
operator action.

**AC #7**: `cert_event` rows older than 90 days are pruned
by the existing observability retention sweep, configured
via the same TTL mechanism that prunes WAF / throttle /
decision tables.

**AC #8**: `GET /api/v1/observability/cert-events` honors
`limit`, `since`, `until`, `level`, `search` per §5.1. A
bad parameter (unparseable timestamp, invalid level value)
returns `400` with the canonical error envelope (per the
existing security-handlers pattern).

**AC #9**: Activity log page title and subtitle reflect the
widened scope — no more "Security events" branding visible
in the frontend. Exact subtitle copy is U.6's
operator-gated polish.

**AC #10**: Cert events render in the existing unified
table with mapping:
- `TIMESTAMP` ← `event.timestamp`
- `LEVEL` ← `info` (cyan) or `block` (red) per
  `event.level`
- `CODE` ← `CERT-OK` / `CERT-FAIL` / `CERT-REVOKED`
  (consistent with `403` / `429` / `401` short codes)
- `SOURCE` ← `cert` (new value alongside `waf` / `throttle` /
  `auth`)
- `REQUEST` (method+path repurposed) ← `ACME` + `<domain>`
- `SOURCE IP` ← `—` (cert events have no remote IP)

**AC #11**: The existing search textbox already searches
across `path` + `srcIp` + `detail`. Cert events populate
`path=<domain>` and `detail=cert <kind> · issuer=<issuer>`,
so operator searches for `cert`, `certificat`,
`Let's Encrypt`, `DNS-01`, or a domain name naturally
match. No new filter UI required.

**AC #12**: Boot log emits
`msg="cert event sink wired" present=true` immediately after
the sink is subscribed (HF4 pattern generalization,
commit `30418ea`). A future regression that drops the
subscribe call surfaces as `present=false` in `journalctl`
instead of silent degradation.

**AC #13**: Reader interface honors the AC #13 degraded-mode
convention from Step T: nil reader → `200` with empty
events array, `total=0`, `hasMore=false`. No `5xx` for
boot-time wiring failures.

**AC #14**: Backend tests pass. `go test -race -count=1
./...` green across all packages. New tests in
`internal/observability/cert_events_test.go`,
`internal/certinfo/sink_test.go`, and
`internal/api/cert_events_test.go` cover the schema
migration, the sink batcher, the GET endpoint shape, and
the degraded-mode path.

**AC #15**: Frontend tests pass. `npm run check` clean
(0 errors, 0 warnings), `npm test` green. The
`routes/logs/page.test.ts` (or equivalent) test file
extends to include a cert-event fixture, asserts the row
renders into the unified table, and asserts the search
matches at least one cert-vocabulary query.

**AC #16**: Lint / vet / format clean. `gofmt -s`,
`go vet ./...`, the frontend linter all report no issues
on touched files.

## 7. Sub-tasks

| Sub-task | Scope | Estimated effort |
|---|---|---|
| **U.1** | Backend schema v5 migration + `cert_event` table + `InsertCertEventBatch` / `QueryCertEvents` + retention integration. Tests: round-trip insert/query, migration v4→v5. | 2-3h |
| **U.2** | Backend Subscribe wiring: `internal/certinfo/sink.go` (channel + batcher), `internal/certinfo/listener.go` extension for `cert_ocsp_revoked`, `internal/certinfo/tracker.go` `RecordRevoked` + `EventCertOCSPRevoked` enum entry, `caddymgr/manager.go` events-array extension. Tests: sink filters `obtaining`/`removed`, panic recovery, batch flush. | 2-3h |
| **U.3** | Backend reader interface + handler + GET endpoint registration. `cmd/arenet/main.go` wire-up + boot log per AC #12. Tests: handler shape, query-param validation, degraded-mode path, real-Sink E2E (mirror HF4's `TestManagedDomain_DELETE_PurgesRealTracker` pattern). | 1-2h |
| **U.4** | Frontend API client: `lib/api/types.ts` adds `CertEvent` + `CertEventsResponse`; `lib/api/security.ts` adds `fetchCertEvents`. Tests: client mock + type-check. | 0.5h |
| **U.5** | Frontend Logs page integration: extend `routes/logs/+page.svelte` parallel-load block with `fetchCertEvents`, add `mapCert` mapper. Tests: cert-fixture renders, search matches cert vocabulary. | 1-1.5h |
| **U.6** | Frontend copy rename: page title and subtitle from "Security events" to "Activity log" + subtitle reflecting WAF + throttle + auth + certs. | 0.25-0.5h |
| **U.7** | Live smoke on AreNET-test + tag `v1.3.0-step-u`. Procedure mirror of T.7. | 1-2h |

Each sub-task lands as one scope-distinct commit (Step T's
shipping discipline) with the corresponding AC numbers in the
commit body.

## 8. Effort estimate

Per discovery doc §4 + sub-task breakdown above:

- **Backend total**: ~5-8h (U.1 + U.2 + U.3)
- **Frontend total**: ~2-2.5h (U.4 + U.5 + U.6)
- **Smoke + tag**: ~1-2h (U.7)
- **Total: 9-13h**

Comparable to Step T's T.4 + T.5 combined (~6-8h ship), with
a slightly heavier backend component (schema migration +
sink + extension of the existing listener).

## 9. References

- **Discovery**:
  `docs/superpowers/discovery/2026-06-06-step-t-plus-1-cert-events-logs.md`
  (commit `27b110a`).
- **Step T spec**:
  `docs/superpowers/specs/2026-06-04-step-t-certificates-runtime-refactor.md`
  (tagged `v1.2.0-step-t-spec` at commit `9a34eb1`).
- **Step T amendment**: `docs/step-t-spec-amendment.md`
  (commits `c62d657` + `9566846`).
- **Step T release notes**:
  `docs/release-notes/v1.2.0-step-t.md`.
- **Step T backlog**: `docs/backlog-step-t.md` —
  `#R-API-boot-log-audit` is the reference implementation
  pattern for AC #12.
- **T.1 forward-compat seam**: commit `1350777` (AC #18
  ghost-subscriber test in `internal/certinfo/tracker_test.go`).
- **HF4 boot log pattern**: commit `30418ea`
  (`HasCertInfoPurger()` getter +
  `msg="api handler wired with cert tracker"
  purger_present=true` boot line).
- **Step T amendment force-renew deferral**:
  `docs/step-t-spec-amendment.md` — the rationale for why
  this spec does NOT introduce a force-renewal action even
  though it touches the cert lifecycle UI.
