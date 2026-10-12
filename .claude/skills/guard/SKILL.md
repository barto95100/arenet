---
name: guard
description: The proof discipline for an Arenet fix — capture the golden before any code change, write the test so it fails first, and reinject the defect to show the guard bites. Use when fixing a defect, adding a regression test, or asked to prove a change is safe.
---

# Guard

A green test proves nothing. A test seen to fail for its own reason
proves something. This is the order that gets there.

## 1. The golden comes first, before any code change

If the fix touches shared emission — Caddy config, a payload builder, a
serialiser — capture the before state **on unmodified code** and commit
it in its own commit.

```
git checkout -B fix/<thing> origin/main      # nothing else yet
# write the fixture + the byte-identity test
go test ./internal/<pkg>/ -run <Golden> -update -count=1
git add testdata/ <the new test>             # commit before touching code
```

Captured afterwards it proves only that the new code agrees with itself.

**Size is not coverage.** `route_emission_golden.json` is 170 KB and
pins six routes that all carry `WAFMode: "off"` with no path rules, no
headers and no gates. It would have passed through the entire
maintenance-bypass change without noticing. Read the fixture before
trusting the golden.

**Never run `-update` to turn a red test green.** One invocation
re-blesses every golden in the package. A diff of `testdata/` belongs in
every review of a fix like this.

## 2. The test fails first

Write the assertion against the defect, run it, watch it fail, then fix.
If it passes before the fix, it is not testing the defect.

Assert on **what the user receives**, not on what the code holds. Three
defects in one week were valid JSON and wrong data, invisible to a
green suite: a payload that dropped five stored fields, an edge that
existed in the graph with no handle to render it, a page that said
"Retry in 86400s". Each had tests nearby. None had a test on the output.

## 3. Reinject the defect, and only that defect

For each guard, restore the old behaviour and confirm the test fails —
and that **its siblings still pass**. One mechanism, one test, no
overlap. If two injections fail the same test, one of the mechanisms is
untested.

```
cp internal/pkg/file.go /tmp/file.keep     # ALWAYS cp, never git
# inject, run, watch it fail
cp /tmp/file.keep internal/pkg/file.go
diff -q /tmp/file.keep internal/pkg/file.go && echo RESTORED
```

**Never `git checkout -- <file>` to undo an injection.** It restores
from HEAD and takes every uncommitted change with it. That destroyed
five replayed patches here on 2026-10-08. Commit before injecting.

## 4. A test that cannot fail is worse than no test

Delete it. Real examples from this repo:

- counted occurrences of `stroke-dasharray` — `getAttribute('style')`
  returns CSSOM-normalised text, which deduplicates, so a doubled
  declaration was invisible and the assertion unfalsifiable
- `expect(rows.length).toBeGreaterThanOrEqual(0)`
- a handle-stub that rendered nothing, so a component with zero handles
  and one with three produced identical DOM
- closing the create form and reopening it to "prove" a `{#key
  editingId}` remount — `editingId` is null both times, so the key never
  fired and the panel closing did the work

The last one passed. Ask of every new test: what change would make this
fail, and is that the change I am guarding against?

## 5. A warning comment is a missing test

If the fix adds a comment describing a hazard, write the assertion
instead. `tcp-services/+page.svelte` carried "a new field that is not
listed here is silently dropped on save with a success toast — that is
how the v2.46 path redirect was lost". The class was named, the
precedent was named, no test was written, and it then destroyed five
more fields.

## 6. Non-regression is a claim that needs an instrument

"I did not break anything" is not reviewable. Make it so:

- byte-identity on everything the change does not intend to touch
- `caddy.Validate` on any newly-shaped Caddy JSON — a matcher set, a
  handler, a transport this codebase has not emitted before
- a tripwire across a language boundary, where neither side can see the
  other: a Go test over the struct's JSON tags when a TypeScript form
  owns the payload

The mistakes this repository specifically invites are listed once, in
`.claude/skills/audit/traps.md`. Read it before a fix that touches
emission, a payload builder, or anything with a golden. One copy on
purpose: two would drift.
