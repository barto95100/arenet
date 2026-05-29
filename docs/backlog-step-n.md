# Step N — Backlog

Items deferred from Step N work. Same convention as
`docs/backlog-step-q.md` / `docs/backlog-step-m.md`.

## 1. Dependency-pinning constraints

### Finding #N.2-1 — Forced pinning of CrowdSec ecosystem trio

N.2 wires `github.com/crowdsecurity/go-cs-bouncer` as a direct
dependency to run Arenet's parallel `StreamBouncer` consumer
alongside the embedded `caddy-crowdsec-bouncer` enforcement loop.

The initial `go get github.com/crowdsecurity/go-cs-bouncer` (no
version constraint) resolved to `v0.0.21`, which pulled
`github.com/crowdsecurity/crowdsec v1.7.6` and
`github.com/crowdsecurity/go-cs-lib v0.0.24` transitively. Both
broke the build because `caddy-crowdsec-bouncer v0.12.1` was
compiled against an older `version.DetectOS()` signature (2-value
return) that crowdsec/go-cs-lib bumped to 3-value in v1.7.x /
v0.0.24.

**Pinned to compatible matrix** in N.2 `go.mod`:

```
github.com/crowdsecurity/crowdsec       v1.6.3   // direct (pulled by go-cs-bouncer indirectly)
github.com/crowdsecurity/go-cs-bouncer  v0.0.15
github.com/crowdsecurity/go-cs-lib      v0.0.15  // indirect, but constrained
github.com/hslatman/caddy-crowdsec-bouncer v0.12.1
```

**Secondary surface drift** : `go-cs-bouncer v0.0.15` exposes
`StreamBouncer.Run(ctx)` with NO return value, while `v0.0.21`
returns `error`. `internal/crowdsec/live_source.go` adapts to
the v0.0.15 shape with an inline comment flagging the
"if-upgrade restore the err return + slog wrap" path.

**Why not fix during N.2.** Resolving the upstream compatibility
matrix is a multi-repo coordination problem outside Arenet's
scope: either (a) hslatman cuts a `caddy-crowdsec-bouncer
v0.13.x` re-targeted at crowdsec v1.7.x + go-cs-lib v0.0.24+, or
(b) we wait for go-cs-bouncer to settle on a release that's
compatible with both the v0.12.x bouncer ABI and the newer
crowdsec model package. Either pathway is upstream work; pinning
here keeps Arenet's Step N shippable.

**Revisit when.**

- A newer `caddy-crowdsec-bouncer` release notes a tested matrix
  with crowdsec >= 1.7.x.
- OR a go-cs-bouncer release notes backward compatibility with
  crowdsec v1.6.3 AND forward compatibility with the
  ecosystem's current head.
- Validation gate: `go test -race ./...` MUST stay green on all
  12 packages after any single-line bump. The dependency drift
  surface area is broad — Arenet's existing `caddymgr`,
  `internal/crowdsec`, and `cmd/arenet` all build against
  three crowdsec-org packages with overlapping symbol surfaces.

**Triage.** Pinning is the conservative ship discipline; not a
regression. Tracked here so a future upgrade-attempt PR has
context on the matrix Arenet relies on.

### Finding #N.2-2 — `StreamBouncer.Run` error-return ergonomics

Per #N.2-1: `live_source.go` cannot wrap `bouncer.Run(ctx)`'s
error path because the v0.0.15 surface doesn't expose one. The
underlying StreamBouncer's `log.Errorf(...)` calls land on the
process-default logger (not Arenet's `slog.Logger` with
structured fields). Operators reading arenet logs will see two
log formats interleaved during a LAPI outage: the slog JSON
lines from our consumer + a few unstructured logrus lines from
go-cs-bouncer's internals.

**Fix path post-upgrade.** When the ecosystem allows us off the
v0.0.15 pin, restore the err-return:

```go
go func() {
    defer close(s.done)
    if err := s.bouncer.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
        s.logger.Error("crowdsec live source: StreamBouncer.Run exited with error",
            slog.String("err", err.Error()),
        )
    }
}()
```

(That exact snippet was in the N.2 first-draft before the
v0.0.15 pin forced the simpler shape. Restoring it is a 6-line
diff.)

**Triage.** Cosmetic logging consistency, no functional impact.
