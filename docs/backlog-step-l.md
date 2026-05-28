# Step L — Backlog

Items deferred from Step L work. Inspired by the per-step backlog
convention used in `docs/backlog-step-j.md`.

## 1. From L.2 review (2026-05-28)

### Finding #L.2-1 — Pre-existing staticcheck warning: `oidc.go pathJoin` unused

Surfaced by the L.2 close-out `staticcheck ./internal/api/...`
run. Predates Step L (introduced in commit `1d7bc19d`, Step K.2
work). Not touched in L.2 because it is outside the L.2 surface
and the user explicitly flagged it as backlog ("vérifier que
c'est cosmétique et pas un vrai souci de construction d'URL
OIDC").

**Symptom:**

```
internal/api/oidc.go:1006:6: func pathJoin is unused (U1000)
```

**Question to answer:** Is `pathJoin` actually unused (so just
delete it), or is there an OIDC-callback URL-construction code
path that should call it instead of `path.Join` directly /
string concatenation? A find-references sweep over OIDC URL
construction sites should answer this in <10 min.

**Action:**
- If genuinely dead: delete the function.
- If a caller was missed: wire it back into the relevant URL
  construction site.

**Triage:** cosmetic vs URL-encoding bug — the former is
ignore-able; the latter would be a P1 OIDC reliability finding.
Resolve before tagging `v0.8.0-step-l` (L.5 smoke).

### Finding #L.2-2 — Last bucket of historical timeline lags up to 1 minute

By design: the aggregator flushes at the minute boundary, so the
current (in-progress) minute is not yet persisted to
`bucket_1m`. The `/metrics/timeseries` endpoint returns the dense
window ending at the **next** bucket boundary — the very last
slot is gap-filled (0 or null) until the next flush.

For the historical timeline this is correct behaviour (no
partial buckets), but the L.3 dashboard MUST NOT render the
last slot as a real data point — it would draw a fake "traffic
dropped to zero" cliff on every chart.

**Action for L.3:**
- Either trim the last slot client-side (display the window as
  ending at `now - bucketSize` so the lag is hidden).
- Or merge the live Step E tick into the last slot for the
  current minute (more complex; only useful if the dashboard
  also shows live values).

The live `reqPerSec` WebSocket pipeline (Step E topology view)
remains real-time and is unaffected — L.3 dashboard can layer
the live tick on top of the history when wired.

**Triage:** UX-only; no code change in L.2 scope.

