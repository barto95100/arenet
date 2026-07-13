# GeoIP Auto-Update — Brick 1: Swappable Reader (Hot-Reload) — Design

**Date:** 2026-07-13
**Status:** Approved (design validated by operator)

## Context

The operator wants **auto-update** of the MaxMind GeoIP database (instead of
manual download + restart). MaxMind ships an importable Go client
(`github.com/maxmind/geoipupdate/v8/client`, Apache/MIT, stable v8) that
downloads the MMDB programmatically. The full feature decomposes into 4
independently shippable bricks:

1. **Swappable reader / hot-reload** ← THIS SPEC (the technical prerequisite)
2. MaxMind credentials storage + CRUD API + settings UI
3. The downloader/updater (uses the client, writes the mmdb, triggers reload)
4. Settings UI panel + wiki-doc corrections

This spec covers **Brick 1 only**: make the in-process GeoIP reader
replaceable at runtime, so a freshly-downloaded database takes effect
**without an Arenet restart** and **without changing any consumer**.

## Problem

Today `internal/geo/lookup.go` opens the MMDB once at boot
(`geoip2.Open`, `lookup.go:75`) and holds the `*geoip2.Reader` by a plain
field (`lookup.go:59`). If the `.mmdb` file is replaced on disk, Arenet
keeps the old mmap'd reader until restart. Three subsystems share one
`*geo.Lookup` — the event **enricher**, **server-position/topology**, and
**country-block** — all by direct pointer. There is no reload path.

## Goal

Add `Lookup.Reload(newPath string) error` that atomically swaps in a new
reader, so all existing consumers see the new database transparently — with
no use-after-close crash on in-flight lookups and no lock on the read
hot-path.

## Decisions (from brainstorming)

1. **`*geo.Lookup` owns the swap internally** via an
   `atomic.Pointer[geoip2.Reader]`. Consumers keep their existing
   `*geo.Lookup` and are unchanged (one swap point, fully encapsulated).
2. **Swap-then-delayed-close**: `Reload` opens the new reader, atomically
   swaps the pointer, then closes the old reader after a short grace period
   so in-flight lookups (a `City()` call is microseconds) finish first.
   Reads take **no lock** (max hot-path performance).

## Design

Change the `Lookup` type in `internal/geo/lookup.go`:

```go
type Lookup struct {
	reader atomic.Pointer[geoip2.Reader]
	// path is the currently-open MMDB path; guarded by pathMu because
	// Reload updates it off the hot path. Reads via Path().
	pathMu sync.Mutex
	path   string
}
```

- The `reader *geoip2.Reader` + `mu sync.Mutex` + `closed bool` fields are
  replaced by the `atomic.Pointer`. The old `closed` flag is no longer
  needed: a closed/absent reader is represented by a nil pointer, which
  every read path already tolerates.

### `NewLookup` (signature unchanged)

Opens the MMDB, stores the reader via `reader.Store(r)`, sets `path`. Same
error contract (empty path / missing / corrupt → error; caller may proceed
with a nil `*Lookup`). A nil `*Lookup` receiver stays a valid degraded mode.

### `LookupIP` (signature + contract unchanged, now lock-free on the reader)

```go
func (l *Lookup) LookupIP(ip net.IP) Location {
	if l == nil {
		return Location{Found: false}
	}
	if ip == nil || ip.IsUnspecified() {
		return Location{Found: false}
	}
	if isLAN(ip) {
		return Location{Country: "LAN", Found: false}
	}
	r := l.reader.Load()
	if r == nil {
		return Location{Found: false}
	}
	rec, err := r.City(ip)
	// ... unchanged mapping to Location ...
}
```

`geoip2.Reader` is safe for concurrent reads (read-only mmap), so
`r.City(ip)` needs no lock; the `atomic.Load` publishes the current reader.

### `Reload(newPath string) error` (NEW)

```go
// Reload opens the MMDB at newPath and atomically swaps it in as the
// active reader. In-flight lookups continue against whichever reader
// they already loaded; the previous reader is closed after a short
// grace period so those lookups (microseconds each) finish first.
//
// On open error the current reader is left in place — a failed download
// or corrupt file never degrades a working lookup. A nil receiver
// returns an error (nothing to reload into).
func (l *Lookup) Reload(newPath string) error {
	if l == nil {
		return errors.New("geo: reload on nil Lookup")
	}
	if newPath == "" {
		return errors.New("geo: reload path is empty")
	}
	nr, err := geoip2.Open(newPath)
	if err != nil {
		return fmt.Errorf("geo: reload open mmdb %q: %w", newPath, err)
	}
	old := l.reader.Swap(nr)
	l.pathMu.Lock()
	l.path = newPath
	l.pathMu.Unlock()
	if old != nil {
		// Delayed close: let in-flight City() calls that already
		// loaded `old` return before the mmap is unmapped.
		go func(r *geoip2.Reader) {
			time.Sleep(closeGracePeriod)
			_ = r.Close()
		}(old)
	}
	return nil
}
```

Constant (package-level, well-named per CLAUDE.md):

```go
// closeGracePeriod is how long Reload waits before closing the previous
// reader, so concurrent in-flight lookups (each a microsecond-scale
// City() call) finish against the old mmap before it is unmapped.
const closeGracePeriod = 5 * time.Second
```

### `Path()` / `Close()`

- `Path()`: returns `l.path` under `pathMu` (nil receiver → "").
- `Close()`: `l.reader.Swap(nil)` then `Close()` the returned reader if
  non-nil. Idempotent (second call swaps nil → nothing to close). Nil
  receiver → no-op. Shutdown-time, so no grace period needed.

## Concurrency correctness

- **Pointer race:** eliminated by `atomic.Pointer` — readers `Load()` a
  consistent reader; `Reload` `Swap()`s.
- **Use-after-close:** a lookup that `Load()`ed `old` just before the swap
  runs `old.City(ip)` (microseconds); the `closeGracePeriod` (5 s) far
  exceeds that, so `old.Close()` happens long after any such call returns.
  This is the standard swap-then-delayed-close pattern for a read-only
  mmap. (A pathological lookup pausing >5 s mid-`City()` is not realistic;
  the risk is a use-after-close panic, and the grace window makes it
  effectively impossible. If we ever wanted a hard guarantee we'd add
  refcounting — deliberately out of scope as overkill here.)
- **Read hot-path:** one atomic load, no mutex. `pathMu` guards only the
  rarely-read `path` string, off the lookup path.

## Testing

**Constraint (documented honestly):** the repo has **no `.mmdb` fixture**
(the DB is operator-supplied, ~60 MB, not committable), and no mmdb-writer
lib is available. So Brick 1 tests cannot assert "a lookup returns data
from the newly-loaded real DB." That end-to-end assertion is deferred to
**Brick 3** (the updater), verified at runtime against a real MaxMind DB on
the operator VM. Brick 1 tests cover everything testable without a real DB
— the swap **semantics**:

Without a real MMDB, `geoip2.Open` always fails, so tests exercise the swap
**control flow** — nil-reader state, error preservation, atomic swap,
delayed close, and `-race` safety — not decoded geo results. Every test
below needs only `Reload` with a bad/empty path (returns error) and the
nil-reader degraded path; none needs a real DB.

`internal/geo/lookup_test.go` (extend the existing file; keep its
error/LAN/nil tests green):
1. **Reload with an empty path** returns an error and does not change the
   reader (a `&Lookup{}` stays nil-reader → `LookupIP` still degraded, no
   panic).
2. **Reload with a nonexistent/invalid path** returns a wrapped error
   (mentions "reload open mmdb") and leaves the reader untouched — the
   current reader is never dropped on a failed reload. Assert on a
   `&Lookup{}`: reader stays nil, `LookupIP` degraded, no panic.
3. **`Reload` on a nil `*Lookup`** returns an error (not a panic).
4. **Concurrency / `-race` (load-bearing):** spawn N goroutines calling
   `LookupIP(publicIP)` in a tight loop while the main goroutine calls
   `Reload(invalidPath)` repeatedly. Every `LookupIP` must return without
   panic/race and every `Reload` returns its error; the `atomic.Pointer`
   Load/Swap and the (no-op here, since swaps fail) close path are
   exercised concurrently. Run the package under `go test -race`. Even
   though the reloads fail-open (reader stays nil), the test proves the
   `atomic.Pointer` read/write path is race-free — the actual bug class
   we're guarding against.
5. **`Path()` reflects a successful path change synchronously** — since we
   can't `Open` a real DB, assert the inverse: a *failed* `Reload` does NOT
   change `Path()` (it stays whatever it was), proving path is only updated
   after a successful open.
6. Nil receiver → degraded, unchanged (existing test stays green).

**Deferred to Brick 3 (documented, not a gap):** "a successful `Reload`
installs a working reader and subsequent `LookupIP` returns data from the
new DB" requires a real MMDB. Brick 3 (the updater) verifies this at
runtime against a real MaxMind DB on the operator VM. If Brick 3 introduces
a small checked-in MMDB test fixture, these tests can be upgraded to assert
a real post-reload lookup — a follow-up, not a Brick 1 blocker.

## Runtime verification

Brick 1 has no operator-facing surface on its own (no consumer calls
`Reload` yet — that's Brick 3). Verification is:
- `go test -race ./internal/geo/` green (the concurrency test is the real
  proof).
- `go build ./...` clean; the enricher / server-position / country-block
  consumers compile unchanged against the new `Lookup` type.

Full end-to-end hot-reload (download → swap → live lookups use the new DB)
is verified in Brick 3 on the operator's real-DB VM.

## Non-goals (YAGNI)

- No downloader, no credentials, no scheduling, no UI (Bricks 2-4).
- No refcounting on the reader (the grace-period close is sufficient).
- No change to any consumer (enricher, server-position, country-block) —
  they keep their `*geo.Lookup` and see swaps transparently.
- No change to `LookupIP`'s result contract or the `Location` shape.

## Files summary

| Action | File |
| --- | --- |
| Modify | `internal/geo/lookup.go` (atomic.Pointer reader, `Reload`, `closeGracePeriod`, adjust `NewLookup`/`LookupIP`/`Path`/`Close`) |
| Modify | `internal/geo/lookup_test.go` (swap-semantics + `-race` concurrency tests; keep existing error/LAN/nil tests green) |

## Global constraints (from CLAUDE.md)

- `gofmt -s` clean, `go vet ./...`, `staticcheck ./...` clean; no panic.
- No magic numbers — `closeGracePeriod` is a named package constant.
- AGPL header already present (no new files).
- The `oschwald/geoip2-golang` reader is retained (no dependency change in
  this brick; the MaxMind `geoipupdate/v8/client` dependency arrives in
  Brick 3).
