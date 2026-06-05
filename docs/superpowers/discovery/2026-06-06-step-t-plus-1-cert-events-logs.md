<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step T+1 — Discovery: Cert events in the Logs page

**Status**: discovery only — read-only audit of the existing
tree, no implementation. Operator review gates the spec freeze.

**Driver**: The auto-renewal info card on `/certs` (Pack A,
preserved through T.4) references "Les logs de renouvellement
sont disponibles dans la page Logs." but `/logs` currently
streams only WAF / throttle / auth-failure events — no cert
events. Step T.1 (commit `1350777`) shipped the certinfo
tracker with a deliberate `Subscribe()` seam (AC #18) for
exactly this T+1 consumer. The seam exists; this doc maps how
to wire it.

---

## 1. Architecture mapping (today's state)

### 1.1 — Frontend Logs page

**File**: `web/frontend/src/routes/logs/+page.svelte` (449 lines).

The page is already a **unified-table aggregator**: it fetches
three event sources independently, normalises each into a
`UnifiedRow`, then renders one filterable table. Adding a
fourth source is mechanically additive.

Current sections (render order):

1. PageHeader + filter card (search input, level segmented
   control `all / block / warn / info`, pause toggle).
2. Unified table (6 columns: Timestamp / Level / Code /
   Source / Request / Source IP).
3. 10-second poll loop (`REFRESH_MS = 10_000`).

Row shape (lines 52–62):

```ts
interface UnifiedRow {
    key: string;
    ts: string;          // RFC 3339
    level: LevelTag;     // 'block' | 'warn' | 'info'
    code: string;        // '403' (WAF) / '429' (throttle) / '401' (auth)
    source: string;      // 'waf' / 'throttle' / 'auth'
    method: string;
    path: string;
    detail: string;
    srcIp: string;
}
```

API consumption (lines 38–41):

```ts
import { fetchEvents, fetchThrottleEvents, fetchAuthFailures } from '$lib/api/security';
```

Mappers `mapWaf` / `mapThrottle` / `mapAuth` (lines 86–134)
each translate a typed event into `UnifiedRow`. The pattern
adapts cleanly to a fourth `mapCert` function.

### 1.2 — Frontend API client

**File**: `web/frontend/src/lib/api/security.ts`.

Existing methods (no certificate-related entry):

| Function | Endpoint |
|---|---|
| `fetchEvents` | `GET /security/events` |
| `fetchEventsByRule` | `GET /security/events/by-rule` |
| `fetchThrottleEvents` | `GET /security/throttle-events` |
| `fetchAuthFailures` | `GET /security/auth-failures` |
| `fetchAttackersSummary` | `GET /security/attackers-summary` |
| `fetchDecisions` | `GET /security/decisions` |

Event-record types live in `lib/api/types.ts` (WafEvent,
ThrottleEvent, AuthFailureRecentEvent, DecisionEvent).
Timestamp shape across all four is RFC 3339 strings.

### 1.3 — Backend security-events handlers

**File**: `internal/api/security_handlers.go`.

Each handler is a thin wrapper around a reader interface that
queries `metrics.db` (SQLite via `internal/observability/`):

| Handler | Reader | Endpoint |
|---|---|---|
| `securityEvents` | `WafEventReader` | `GET /api/v1/security/events` |
| `securityEventsByRule` | `WafEventReader` | `GET /api/v1/security/events/by-rule` |
| `securityThrottleEvents` | `ThrottleEventReader` | `GET /api/v1/security/throttle-events` |
| `securityAuthFailures` | `AuthFailureReader` | `GET /api/v1/security/auth-failures` |
| `securityDecisions` | `DecisionReader` | `GET /api/v1/security/decisions` |

All five honour the AC #13 degraded-mode contract: when the
reader is nil (boot failure, missing wire-up), the endpoint
returns `200` with `{disabled: true, ...empty payload}`
instead of `5xx`.

### 1.4 — Storage layer (observability/metrics.db)

**Directory**: `internal/observability/`.

**Schema definitions**: `internal/observability/migrate.go`.

Current event tables (schema v4):

| Table | Columns | Indexes |
|---|---|---|
| `waf_event` | `id, ts, route_id, rule_id, category, severity, src_ip, request_method, request_path, payload_sample` | `ts`, `(route_id, ts)`, `(category, ts)` |
| `throttle_event` | `id, ts, tier, src_ip, attempted_username, blocked_until, block_duration_seconds` | `ts`, `(src_ip, ts)` |
| `decision_event` | `id, uuid (UNIQUE), ts, scope, value, type, scenario, expires_at, duration_seconds` | `ts`, `(value, ts)`, `(scenario, ts)` |

Insertion APIs (batched):

- `InsertWafEventBatch(ctx, events)` — `storage.go:393`
- `InsertThrottleEventBatch(ctx, events)` — `storage.go:585`
- `InsertDecisionEventBatch(ctx, decisions)` — `storage.go:958`

Query APIs (range scan with filter):

- `QueryWafEvents(ctx, filter)` — `storage.go:444`
- `QueryThrottleEvents(ctx, filter)` — `storage.go:628`
- `QueryDecisionEvents(ctx, filter)` — `storage.go:1035`

**Important exception**: auth failures are NOT in `metrics.db`.
They live in the **separate audit log SQLite** (per spec
D2.B + D4.B single-source-of-truth rationale). The
`AuthFailureReader.QueryByActionRange` reads the audit bucket
directly. This means cert events have two architectural
choices (see §3.1).

### 1.5 — Event injection points

Each event class flows through a sink pattern: producer →
channel → batcher goroutine → bulk insert. Wiring happens in
`cmd/arenet/main.go`:

| Source | Sink file | Wiring line | Storage call |
|---|---|---|---|
| WAF | `internal/waf/sink.go` | `main.go:396` | `InsertWafEventBatch` |
| Throttle | `internal/throttle/sink.go` | `main.go:429` | `InsertThrottleEventBatch` |
| Auth failure | (audit append, not a sink) | `main.go:641` | audit bucket |
| CrowdSec decision | `internal/crowdsec/sink.go` | `main.go:475` | `InsertDecisionEventBatch` |

The sink pattern absorbs producer-side bursts and amortises
SQLite write cost. CrowdSec's sink has an LRU-dedupe pass
upstream of the batcher (Step N specific, because LAPI
re-emits every poll).

### 1.6 — Cert events forward-compat seam

**File**: `internal/certinfo/tracker.go` lines 329–346 (Subscribe), 358–376 (fanOut + dispatch).

The seam Step T.1 shipped for exactly this purpose:

```go
// Subscribe attaches an EventHandler to the fan-out. Returns
// an unsubscribe function the caller invokes on shutdown.
func (t *Tracker) Subscribe(h EventHandler) func()

// EventHandler interface (types.go:189)
type EventHandler interface {
    HandleCertEvent(e Event)
}
```

Event shape (`internal/certinfo/types.go` lines 170–177):

```go
type Event struct {
    Kind      EventKind  // see below
    Domain    string
    IsRenewal bool       // only when Kind=cert_obtained
    Issuer    string     // populated on cert_obtained
    Error     string     // populated on cert_failed
    At        time.Time
}
```

EventKind enum (`types.go` lines 155–177):

| Kind | Source | Notes |
|---|---|---|
| `EventCertObtaining` | certmagic `cert_obtaining` | About to attempt; outcome unknown. |
| `EventCertObtained` | certmagic `cert_obtained` | Renewal disambiguated by `IsRenewal=true`. NO separate `cert_renewed` event exists in v0.25.3. |
| `EventCertFailed` | certmagic `cert_failed` | `Error` carries the raw message. |
| `EventCertRemoved` | **synthetic** — emitted by `tracker.Remove()` on managed-domain DELETE. Caddy/certmagic emit no removal event (HF3 / `e4177e4`). |

Dispatch guarantees (`tracker.go:371-376`):

- **Synchronous** — handler runs in the tracker's writer
  goroutine.
- **Panic-recovered** per dispatch — one buggy consumer can't
  take down the tracker.
- **Must be non-blocking** — any T+1 handler must hand off to
  its own goroutine (or batcher) and return immediately, OR
  the tracker's `RecordCert` / `RecordFailure` / `Remove`
  paths stall.

Test coverage of the seam:

- `TestTracker_Subscribe` — 3-event roundtrip.
- `TestTracker_Subscribe_Unsubscribe` — unsub closure stops fan-out.
- `TestTracker_Subscribe_PanicRecovery` — panic doesn't propagate.
- `TestTracker_Remove_FanOut` — EventCertRemoved fires on purge.

---

## 2. Caddy/certmagic cert events available

Verified empirically against vendored `certmagic@v0.25.3`
and `caddy/v2@v2.11.3` on 2026-06-06.

| Event | Emit sites | Payload | Used by T.1? |
|---|---|---|---|
| `cert_obtaining` | `config.go:605, :891` | `{identifier}` | ✅ |
| `cert_obtained` | `config.go:728, :1019` | `{renewal, identifier, issuer, storage_path, certificate_path, private_key_path, metadata_path, csr_pem}` | ✅ |
| `cert_failed` | `config.go:693, :983` | `{renewal, identifier, [remaining], issuers, error}` | ✅ |
| `cert_ocsp_revoked` | `maintain.go:375` | `{identifier, certificate}` (OCSP-revocation specific) | ❌ |
| `cached_managed_cert` | `certificates.go:261` | `{sans}` | ❌ (informational) |
| `cached_unmanaged_cert` | `certificates.go:322, :358, :376, :407` | `{sans, [replacement]}` | ❌ (informational) |

**Origin module** (caddytls): `"tls"` — the top-level
`caddytls.TLS` app (modules/caddytls/tls.go:156). T.1's
subscription filter is correct (filter `"tls"` or empty;
descendants would never match).

**`cert_renewed` does not exist as a separate event** —
renewal is `cert_obtained` with `renewal: true`. Documented
in T.1's empirical recon (commit `1350777` body) and the
EventKind enum in `types.go`.

**`EventCertRemoved` is AreNET-synthetic**, not a Caddy/
certmagic emission. The HF3 hotfix (`e4177e4`) synthesises
it from `Tracker.Remove()` so consumers see purges through
the same Subscribe channel as obtain/fail.

---

## 3. Proposed integration shape

### 3.1 — Architectural choice: where do cert events live?

Two viable patterns, summarised:

| Option | Storage | Endpoint | Wiring pattern |
|---|---|---|---|
| **A. New `cert_event` table in metrics.db** | new table sibling to `waf_event` / `throttle_event` / `decision_event` | new `GET /api/v1/security/cert-events` | sink: certinfo → channel → batcher → `InsertCertEventBatch` |
| **B. Reuse audit bucket (BoltDB)** | new audit `Action` values: `cert_obtaining`, `cert_obtained`, `cert_failed`, `cert_removed` | extend `securityAuthFailures` or add `securityCertEvents` reading via `audit.Reader.QueryByActionRange` | direct audit append from certinfo Subscribe handler (no sink) |

**Recommendation: Option A.**

Rationale:
- WAF / throttle / decision all live in `metrics.db` and use
  the **sink + batcher** pattern. Cert events are operationally
  the same shape — bursty (multi-domain reload), worth
  amortising. Following the established pattern keeps the
  mental model uniform.
- The audit bucket is the canonical record of **operator-
  initiated actions** (per spec D2.B). Cert events are
  **certmagic-initiated**, not operator-initiated; mixing them
  into the audit bucket muddies that distinction.
- Auth failures are the audit-bucket exception because they're
  driven by the same handler that already writes audit rows
  (login failure → audit append + auth-failure surface);
  reusing the bucket avoids double-write. No equivalent
  natural double-write exists for cert events.
- Option A keeps the certinfo package's tracker decoupled from
  the audit subsystem (audit currently imports certinfo
  transitively via api/handler.go; reversing the direction
  would create a cycle that requires interface plumbing).

### 3.2 — Backend implementation sketch (Option A)

**New package** (or extend `internal/certinfo/`):

```
internal/certinfo/
├── sink.go         (new — channel + batcher goroutine)
├── tracker.go      (existing — already exposes Subscribe)
└── types.go        (existing)

internal/observability/
├── migrate.go      (extend — add schema v5 with cert_event table)
└── cert_events.go  (new — Insert + Query)

internal/api/
└── cert_events.go  (new — handler + reader interface)
```

**Schema v5** (sketch):

```sql
CREATE TABLE cert_event (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,         -- epoch ms (consistent with other tables)
    kind TEXT NOT NULL,          -- 'obtaining' / 'obtained' / 'failed' / 'removed'
    domain TEXT NOT NULL,
    is_renewal INTEGER NOT NULL, -- 0/1, only meaningful when kind='obtained'
    issuer TEXT,                 -- populated when kind='obtained'
    error TEXT                   -- populated when kind='failed'
);
CREATE INDEX idx_cert_event_ts ON cert_event(ts);
CREATE INDEX idx_cert_event_domain_ts ON cert_event(domain, ts);
```

**Sink contract** (mirrors `internal/throttle/sink.go`):

```go
// internal/certinfo/sink.go
type CertEventInserter interface {
    InsertCertEventBatch(ctx context.Context, events []CertEventRecord) error
}

type sink struct {
    inserter CertEventInserter
    in       chan Event   // certinfo.Event
    batch    []CertEventRecord
    // ... batcher loop
}

func NewSink(inserter CertEventInserter, logger *slog.Logger) *Sink
func (s *Sink) HandleCertEvent(e Event)   // satisfies certinfo.EventHandler
func (s *Sink) Run(ctx context.Context)
func (s *Sink) Stop()
```

The sink's `HandleCertEvent` is the bridge that satisfies the
T.1 Subscribe seam **and** marshals into the channel. Buffered
channel + batch flush every N ms or N events (sized like
throttle sink: 256 buffer, 1s flush).

**Wire-up in `cmd/arenet/main.go`** (sketch, between current
certTracker construction and SetCertInfoReader):

```go
certSink := certinfo.NewSink(obsStore, logger)
unsub := certTracker.Subscribe(certSink)
go certSink.Run(ctx)
defer func() { unsub(); certSink.Stop() }()
```

The `unsub` closure must run before `certSink.Stop()` so the
tracker stops sending into a closed channel.

**API surface** (one new handler):

```go
// GET /api/v1/security/cert-events?limit=&domain=&kind=&since=
func (h *Handler) securityCertEvents(w http.ResponseWriter, r *http.Request)
```

Response shape mirrors the existing security endpoints:

```json
{
    "disabled": false,
    "events": [
        {
            "id": 123,
            "ts": "2026-06-06T...",
            "kind": "failed",
            "domain": "*.test.local",
            "isRenewal": false,
            "issuer": "",
            "error": "subject does not qualify for a public certificate"
        },
        ...
    ]
}
```

AC #13 degraded mode: nil reader → `200 {disabled: true, events: []}`.

### 3.3 — Frontend implementation sketch

**Additive changes only** — no rewrite, no contract break.

`web/frontend/src/lib/api/security.ts`:

```ts
export interface CertEvent {
    id: number;
    ts: string;
    kind: 'obtaining' | 'obtained' | 'failed' | 'removed';
    domain: string;
    isRenewal: boolean;
    issuer: string;
    error: string;
}

export interface CertEventsResponse {
    disabled?: boolean;
    events: CertEvent[];
}

export const fetchCertEvents = (params?: { limit?: number; domain?: string; kind?: string })
    : Promise<CertEventsResponse> => ...
```

`web/frontend/src/routes/logs/+page.svelte` — add the fourth
fetcher to the parallel-load block and a fourth mapper:

```ts
function mapCert(e: CertEvent): UnifiedRow {
    const levelByKind: Record<CertEvent['kind'], LevelTag> = {
        obtaining: 'info',
        obtained: 'info',
        failed: 'block',
        removed: 'info',
    };
    return {
        key: `cert-${e.id}`,
        ts: e.ts,
        level: levelByKind[e.kind],
        code: e.kind === 'failed' ? 'CERT-FAIL' : 'CERT',
        source: 'cert',
        method: 'ACME',
        path: e.domain,
        detail: e.kind === 'failed'
            ? `cert ${e.kind} · ${e.error}`
            : e.kind === 'obtained'
                ? `cert ${e.isRenewal ? 'renewed' : 'obtained'} · issuer=${e.issuer}`
                : `cert ${e.kind}`,
        srcIp: '—',
    };
}
```

**Search-textbox behavior**: `filteredRows` already searches
across `path`, `srcIp`, `detail` (lines 74–84). Cert events
populate `path=<domain>` and `detail=cert <kind> ...issuer`,
so operator searches for "cert", "certificat", "Let's Encrypt"
naturally match without code change.

**Level segmented control**: existing `all / block / warn /
info`. `cert failed` maps to `block` (red), the rest to
`info` — consistent with WAF=block, throttle=warn, auth=info.

**Page subtitle**: today the page is titled simply "Logs"
(verify). If the subtitle says "Security events", it should
move to "Activity log" or "Events" to reflect the widened
scope — operator decides the exact copy.

### 3.4 — Tests

Backend (mirroring the existing event-source test shape):

- `internal/certinfo/sink_test.go` — channel buffering, batch
  flush, panic-recovery (the existing certinfo Subscribe seam
  recovers panics, but the sink shouldn't even propagate the
  outer error if InsertCertEventBatch fails).
- `internal/observability/cert_events_test.go` — round-trip
  insert + query, schema migration from v4 → v5.
- `internal/api/cert_events_test.go` — GET endpoint shape,
  degraded mode (nil reader → 200 disabled).

Frontend:

- Extend `web/frontend/src/routes/logs/page.test.ts` with a
  cert-event fixture, assert it renders into the unified
  table, assert search matches "cert" and "let's encrypt".

---

## 4. Effort estimation

| Phase | Scope | Hours |
|---|---|---|
| Backend schema migration v4 → v5 | `migrate.go` + tests | 1 |
| `internal/certinfo/sink.go` | Sink + batcher + Subscribe wiring + tests | 2–3 |
| `internal/observability/cert_events.go` | Insert + Query + tests | 1–2 |
| `internal/api/cert_events.go` + routes registration | Handler + reader interface + tests + boot wire-up | 1–2 |
| `cmd/arenet/main.go` wire-up | Subscribe + Run + boot log + nil-tolerance test | 0.5–1 |
| Frontend: API client + types | `security.ts` + `types.ts` | 0.5 |
| Frontend: Logs page mapper + 4th fetcher | `+page.svelte` + test extensions | 1–1.5 |
| Frontend: subtitle / page copy | Operator-gated; trivial | 0.25 |
| Doc updates (CLAUDE.md mentions, release notes for the future v1.3 step) | | 0.5 |
| Smoke + verification | Full sweep on AreNET-test | 1 |
| **Total** | | **~9–13 hours** |

Comparable to T.4 (~3–4h frontend) + a thin backend slice
(metrics.db is already established; we follow the throttle
sink pattern verbatim).

---

## 5. Open questions for operator decision

Before spec freeze, resolve these:

1. **Storage choice — A or B?** Option A (new cert_event table
   in metrics.db) is recommended above; operator may prefer
   reusing the audit bucket for the operational-record-of-
   truth single-source argument. If B, the implementation
   shape changes — drop the sink, add audit Action values,
   query through the existing `audit.Reader`.

2. **Retention**. WAF/throttle/decision tables have an
   automatic retention runner (24h hot / 30d cold buckets
   plus event-table TTL). Cert events are far lower volume
   (~tens per day per domain, max) — should they share the
   same retention or get a longer TTL? Suggested default:
   90 days (long enough that an operator investigating a
   renewal storm has the history).

3. **Should `cert_obtaining` be persisted?** It's
   informational ("about to attempt"); every successful
   obtain produces an obtaining+obtained pair. Persisting
   both doubles the row count without operator-visible value.
   Two options:
   - **Drop obtaining at the sink** (don't write to DB), keep
     `obtaining` only on the live Subscribe seam for any
     future real-time consumer.
   - **Keep all four kinds**, let the operator filter by kind
     via the search box.

   Recommendation: **drop obtaining** unless the operator
   wants the full ACME chatter.

4. **Subtitle rename**. The page is `/logs`; if its current
   subtitle says "Security events" it understates the new
   scope. Candidates: "Activity log", "Events", "Logs &
   events", or leave as "Security & cert events" (compromise).
   Decide alongside the icon-/menu-entry shape.

5. **`cached_managed_cert` / `cached_unmanaged_cert` events**.
   These fire on every cert cache load (boot, every reload).
   They are noisy. Should they be persisted? Recommended:
   **NO** — purely informational, no operational value in the
   log. T.1 already ignores them.

6. **`cert_ocsp_revoked` events**. Distinct certmagic event
   (`maintain.go:375`). Should the T+1 scope include them?
   Recommended: **YES, as a fifth EventKind** —
   `cert_ocsp_revoked` is a security-relevant signal (an
   issued cert was revoked upstream by the issuer for a
   reason, often compromise). Low-volume, high-value.

7. **Live-streaming via WebSocket?** Existing Logs page polls
   every 10s. Cert events are bursty (reload triggers a fan
   of obtaining → obtained over a few seconds) but
   operationally a 10s lag is fine. Recommended: **stay
   polling for v1**; WS upgrade only if a future spec needs
   live tail (matches the existing pattern).

8. **EventCertRemoved persistence**. Synthetic event, fires
   when the operator deletes a managed-domain apex via the
   Wizard. The audit log already has an
   `audit.ActionManagedDomainDeleted` row for the same user
   action (managed_domain.go:330–334). Persisting
   `cert_removed` in metrics.db would double-record from the
   operator's perspective. Two options:
   - **Persist as a low-priority informational kind** —
     accept the double-record (cert_event row + audit row),
     they have different consumers (Logs page vs audit
     surface).
   - **Skip persisting `EventCertRemoved`** — the audit log
     is the system-of-record for operator actions; this kind
     stays internal to the Subscribe stream.

   Recommendation: **skip persisting** to avoid the double-
   record; the audit log already covers it.

---

## 6. References

- T.1 ship: commit `1350777` (the tracker + Subscribe seam).
- T.5 ship: commit `6b03f1c` (the wizard wiring referenced
  in §3.3).
- HF3: commit `e4177e4` (`EventCertRemoved` introduction).
- HF4: commit `30418ea` (boot-time wire-up visibility
  pattern — Step T+1's sink should follow the same
  `purger_present=true` boot log shape per
  `#R-API-boot-log-audit` in `docs/backlog-step-t.md`).
- Step T spec freeze: `v1.2.0-step-t-spec` (`9a34eb1`).
- Step T amendment: `docs/step-t-spec-amendment.md`.
- Step T release notes: `docs/release-notes/v1.2.0-step-t.md`.
- Backlog entries this discovery interacts with:
  `#R-CERTS-reconcile-from-managed-domains`,
  `#R-API-boot-log-audit` (both in
  `docs/backlog-step-t.md`).

This document is a **discovery output**, not a spec. The
spec freeze (`v1.3.0-step-t-plus-1-spec` or similar)
follows operator answers to §5.
