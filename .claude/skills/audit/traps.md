# Traps this repository invites

Every one of these cost real time. They are listed once so the next
pass does not rediscover them.

## Tooling

**`npx prettier` reformats the whole file.** There is no prettier config
and prettier is not a dependency, so `npx` fetches one with its own
defaults (2-space, double quotes) against a repo written with tabs and
single quotes. One run turned a 190-line addition into a 1200-line diff.
Match the file's existing style by hand.

**`go test -update` re-blesses every golden in the package.** The flag
is declared once (`reverse_proxy_emit_test.go:34`) and read by each
golden test. Running it to make a failure go away makes the regression
the new expectation, permanently and silently.

**`git checkout -- <file>` discards uncommitted work.** It restores from
HEAD. Same family as `reset --hard`. During fault injection, restore
only from a `cp` backup, and commit before injecting.

**`find … | head -1` takes the first match for the only match.** The Go
module cache holds both `coraza-coreruleset@v0.0.0-2024…` (a stale
pre-`/v4` path) and `coraza-coreruleset/v4@v4.25.0`. Picking the first
produced a confident, wrong claim that a cited version was fabricated.

**`gofmt -s -l internal/ cmd/` lists ~37 pre-existing files.** CI gates
`go vet` and `go test -race`, not `gofmt`, so the drift is invisible and
is not yours. Check your own files only.

## Silence

**An unused CSS selector is never reported.** Renaming a class in a
`<style>` block and leaving the markup alone gives 0 errors and 0
warnings from `svelte-check` and nothing from the build. A class-name
refactor across the markup/style boundary has no gate.

**A Svelte Flow edge with no `<Handle>` on its endpoint is silently
dropped.** No console warning, no fallback to the node box. The edge is
in the graph and simply never drawn.

**jsdom has no layout engine.** No Vitest test can prove a flex column
bounds, that a panel scrolls, or what a contrast ratio renders as. Say
so rather than writing a test that pretends.

**Unrecognised Caddy placeholders are printed, not dropped.**
`static_response` expands its body with `repl.ReplaceKnown`
(v2.11.4 `staticresp.go:208`), documented as "Unrecognized placeholders
will remain in the output". Removing a sentinel's substitution puts the
literal `{arenet.…}` on a public page.

## Shape

**`PUT` on a route or a TCP service is a full replace.** The handler
decodes into a fresh struct and carries over almost nothing. A form that
builds its payload by hand destroys every field it forgot. Build the
payload by overlaying the loaded object instead: list what to replace,
not what to keep, so forgetting one leaves the stored value alone.

**Percentiles are not summable, averageable or maximisable.**
`max(p95(a), p95(b)) ≠ p95(a ∪ b)`. Summing histogram bucket counts is
exact; anything else is a new number with a familiar name.

**`Via` is a proxy-only header.** `reverseproxy.go` adds it, so a
redirect served by `static_response` carries only `Server`. Testing for
`Via` to decide whether Caddy answered gives a false negative on every
redirect.

**Zero is not a sentinel.** A sub-microsecond measurement, an empty
bypass list, a `Retry-After` of 0 — each is a real value that the code
has at some point mistaken for "unset".

## Facts about the deployment, not the code

**Some `*.hacf.fr` names still resolve to an old proxy, not Arenet.**
Check `dig +short <host>` and look for `server: Caddy` before
investigating anything inside Arenet.

**A GitHub job reported as fail with conclusion `cancelled` is often the
platform.** Check `githubstatus.com` before the code. Two tells: no
steps recorded, or a duration wildly unlike a twin matrix job's.

**Two releases can have byte-identical binary sizes.** ELF section
padding absorbs a sub-4 KB `.rodata` delta. Probe the embedded strings
to check an artefact, never the size.
