<!-- Arenet — implementation plan. AGPL-3.0-or-later. See LICENSE. -->

# Plan — route health notifications

Spec: `docs/superpowers/specs/2026-10-17-route-health-notifications-design.md`
Target: **v2.75.0**

## Prerequisite already landed

The shared SSRF guard the spec's D9 calls for shipped ahead of this
feature in #320: `internal/netguard` (`ErrBlocked`, `Blocked`,
`NewDialer`), with the webhook and Discord senders already dialling
through it. Nothing in this plan re-touches the guard; the channel
senders are SSRF-safe before the first route-health message is sent.

## The three open questions the spec left, now decided

- **Where the per-route setting lives → a field on `storage.Route`.**
  `HealthNotify HealthNotifyConfig` (value, not pointer, so a zero value
  is a valid "off" and no nil-check litters the callers), beside
  `HealthCheck` (`storage/routes.go:797`). A field rides the route CRUD
  and the backup/restore walk for free; a side table would need its own
  migration, its own backup pass, and a join on every read. The config
  is `{Enabled bool, ChannelID string, ReminderMinutes int}` — a channel
  **ID**, never a URL (spec D2/D11).

- **The route→upstream mapping the notifier needs → a snapshot
  refreshed at each Caddy reload.** The tracker is keyed by upstream
  address; the notifier must know which routes (and their notify config)
  a flipping address belongs to. The manager already calls
  `caddyhc` `Reset()` before every `caddy.Load` — the same seam refreshes
  the notifier's index from the routes just emitted. No per-request
  storage read on the event path.

- **Multi-upstream "down" timing → the route's aggregate state,
  recomputed on each member transition.** A route is **down** when every
  one of its upstreams is unhealthy, **degraded** when some-but-not-all
  are, **healthy** when any is healthy and none was down. The notifier
  holds the route's last aggregate state and the timestamp it entered a
  non-healthy state, and notifies only on an aggregate edge — so one
  upstream of three flapping is a single `degraded`, not a `down`.

## v2.75.0 — the notifier

**T1. Tracker transition hook + down-since, test first.**
`caddyhc/tracker.go` today stores `map[addr]status`. Add
`map[addr]time.Time` for the transition instant and an optional
`OnTransition func(addr, old, new string, at time.Time)` the tracker
invokes **only when `set` actually changes the status** (compare before
write, under the lock, fire after unlock). Test: a repeated
`RecordUnhealthy` fires the callback once; `since` is the first-edge
time, not the latest event. This is the only change to a hot-path type —
keep `Status()` byte-identical so the topology snapshot is unaffected.

**T2. The route index.**
A `routeHealthIndex` the notifier owns: `addr → []routeRef` and
`routeRef → {routeID, host, upstreamAddrs, HealthNotifyConfig}`, built
from the emitted routes. `Refresh(routes []storage.Route)` rebuilds it
under a write lock. Test: an address shared by three routes maps to all
three; a route with notify disabled is absent.

**T3. The notifier — aggregate edges, grouping, reminder.**
`internal/alerting` (or a new `internal/routehealth` consuming
`alerting.Dispatcher` — decide at T3 by where the import graph stays
acyclic). On a tracker transition: recompute every affected route's
aggregate state; for each route whose aggregate **edged** and whose
notify is enabled, enqueue a pending event. Coalesce the queue over a
bounded window (default 3s) keyed by **upstream address**, so N routes
on one dead backend emit one message listing them. Severity per spec
D10 (down=Critical, degraded=Warning, recovered=Info). `recovered`
carries the outage duration via `formatRetryAfterHuman`
(`maintenance.go:151`, seconds → words — reused, not reinvented).
Reminder: while a route stays down, re-dispatch every
`ReminderMinutes` using the `cooldown.go` interval mechanism; recovery
cancels it. Build the `AlertEvent` in Go (no Caddy replacer — spec's
no-placeholder-sink point) and call `Dispatcher.Dispatch`.

**T4. Storage axis — the field, the migration, the backup.**
Add `HealthNotify` to `storage.Route` with its JSON tag; a boot
migration defaults existing rows to `{Enabled:false}` (silent-on would
spam every install — spec D3); include it in the backup/restore round
per ENGINEERING-PRACTICES Lesson 8. It holds **no secret** (channel ID
only), so no secret-codec / backup-seal entry — assert that in a test so
a future URL-bearing field can't be added here unnoticed.

**T5. API axis — wire shape, validation, audit, the wire test.**
Carry `healthNotify` on the route create/update payload. Validate:
`channelId` must resolve to an existing channel when `enabled`;
`reminderMinutes` in a bounded range (0 = off). Audit the create/modify
of the setting (spec D12). One **literal-JSON** test per the endpoint
(`[[test-the-wire-not-the-struct]]`): the camelCase shape in, the same
back out, and **no channel URL** anywhere in the response — the secret
never rides the route.

**T6. Wiring in `cmd/arenet/main.go`.**
Construct the notifier with the channel lookup + `Dispatcher`; register
its `OnTransition` on the `caddyhc` tracker; call `index.Refresh` from
the manager's post-emit / pre-`Load` seam (same place `Reset` is
called). No new Caddy JSON — assert `buildConfigJSON` byte-identical.

**T7. Frontend — the per-route control + hydration.**
Route form (`routes/…` edit panel): a "Notify on health change" toggle,
a channel `<select>` (populated from the channels API), and the reminder
field, all behind the toggle. The channel **Test** button already exists
on the channels page (reused, now SSRF-guarded). i18n FR+EN (both
locales, parity test). Component test: toggle on → pick channel → the
payload carries `{enabled:true, channelId}`; and the create→API→reload
hydration shows the same values back
(`[[2026-10-13-settings-tabs-keep-typed-input-design]]` — the recent
drift class).

## The test matrix (the spec's empirical gates)

Each gate from the spec maps to a named test, failing-first then fixed:

| Gate | Test |
| --- | --- |
| Edge not level | up→down→up on one upstream → exactly 2 dispatches (down, recovered w/ duration) |
| Grouping | 3 routes, 1 shared upstream flips → 1 message naming all 3 within the window |
| Degraded vs down | 2-upstream route: 1 down → Warning `degraded`; both down → Critical `down` |
| Reminder cadence | sustained down re-notifies on `ReminderMinutes`, not faster; recovery stops it |
| Secret never leaks | route GET, logs, audit rows carry no channel URL (literal-JSON) |
| SSRF refused | covered by #320's `netguard` + sender tests; add a notifier-path assertion that dispatch uses the guarded senders |
| Hydration parity | T7 component test |
| Non-regression | `buildConfigJSON` byte-identical; `Status()` unchanged; `go test -race ./...` + `caddy.Validate` clean |

## Deliberately deferred

- **Global defaults** for the reminder interval and coalescing window:
  V1 is per-route `ReminderMinutes` with a package-constant window. A
  settings-level default is a later, additive change.
- **Flap damping** beyond Caddy's own passes/fails (spec D5). If an
  operator's health-check thresholds are too twitchy, that is tuned on
  the health check, not here.
- **A notification for the admin plane / AreNET-itself** being down —
  that is the `system_health` source's job, already shipped.
