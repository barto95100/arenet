---
name: audit
description: Hunt for real defects in Arenet, read-only, with a file:line citation and a reproduction for every claim. Use when asked to audit, sweep, review for bugs, or check whether something is actually broken — not when asked to implement or fix.
---

# Audit

Find defects. Do not fix them. Report what is true.

A 37-PR sweep of this codebase in October 2026 found six real defects
and made eight false claims. The findings were worth keeping; the
discipline was not. This skill is the difference.

## The mandate

**Read-only.** No edits, no commits, no `git checkout`, no `git stash`,
no formatter. If a fix is obvious, write it down and move on — stopping
to fix is how a sweep becomes one bug deep and ten wide short.

**Scope comes from the caller.** If it was not given, ask for one. "Audit
everything" produces a list nobody reads. Useful cuts, in rough order of
what they cost when wrong:

- every place a save can lose data
- every state the UI shows that does not come from a data source
- every destructive action with no confirmation
- operator docs against the code they describe
- i18n: strings reachable from one locale that are written in another

## Count, do not reason

This is the one technique that beat reasoning in practice. The sweep's
strongest findings were the mechanical ones — 352 hardcoded strings
tallied per file, three undefined CSS properties out of every `var(--x)`
in the tree, contrast ratios recomputed from the tokens. Its weakest
were the judgements.

So: enumerate, compare counts, diff two lists. Prefer a number a reader
can re-derive over an adjective.

## Every claim carries three things

1. **A citation.** `internal/caddymgr/manager.go:2161` — the file and the
   line, read, not recalled. Cite `origin/main` via
   `git show origin/main:<path>` when the worktree is on a branch.
2. **How it was verified.** "I read the handler", "I ran the probe",
   "I counted with this command". A claim whose verification cannot be
   named is a guess.
3. **The sequence that triggers it.** Not "X is broken" but "open the
   panel on route A, change A's state from its row, save — now the
   maintenance is gone". A defect without a reproduction cannot be
   prioritised, and half the time writing the sequence reveals the
   precondition is narrower than it looked.

## Three verdicts, never two

- **CONFIRMED** — citation and reproduction in hand.
- **FALSE** — the code says otherwise; say what it actually does.
- **NOT VERIFIABLE HERE** — and why. Runtime behaviour with no
  environment, a merged tree that does not exist, a rendered contrast
  ratio. Saying so is the finding.

Never present an inference as a measurement. A sweep in this repo
reported a table headed "Measured on Docker 29.9" while its sibling PR
stated there was no Docker on the machine. One sentence like that
discredits thirty real findings.

## Severity is about reach, not depth

Rank by what it costs and how easily it is reached. A defect that fires
on every save of a form outranks one that needs a specific order of
clicks, even when the second sounds worse. Say which is which — the
precondition is part of the finding.

## Before reporting

Re-read your own claims against the code once more. In this session's
audit the reviewer's own calibration example was wrong — a `find | head
-1` had matched a stale module path, and the version it "disproved" was
correct. Taking the first match for the only match is the most common
way an audit lies.

See `traps.md` for the mistakes this repository specifically invites.
