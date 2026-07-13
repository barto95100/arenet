# GeoIP Swappable Reader (Hot-Reload) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `internal/geo.Lookup`'s reader replaceable at runtime via `atomic.Pointer[geoip2.Reader]` + a `Reload(newPath)` method (open new → atomic swap → delayed close of old), so a freshly-downloaded MMDB takes effect without a restart and without changing any consumer.

**Architecture:** Replace the `Lookup`'s plain `reader *geoip2.Reader` + `mu`/`closed` fields with an `atomic.Pointer[geoip2.Reader]`; reads become lock-free. `Reload` swaps atomically and closes the previous reader after a grace period (no use-after-close). Consumers (enricher, server-position, country-block) keep their `*geo.Lookup` and are untouched.

**Tech Stack:** Go 1.25, `github.com/oschwald/geoip2-golang v1.9.0` (`geoip2.Open` → `*geoip2.Reader`, concurrent-read-safe mmap).

**Spec:** `docs/superpowers/specs/2026-07-13-geoip-swappable-reader-design.md`

## Global Constraints

- `gofmt -s` clean, `go vet ./...`, `staticcheck ./...` clean; no panic.
- `closeGracePeriod` is a named package constant (no magic numbers).
- No consumer changes (enricher, server-position, country-block keep `*geo.Lookup`).
- No `LookupIP` result-contract or `Location`-shape change.
- No new dependency in this brick (MaxMind client arrives in Brick 3).
- Backend: `go build ./...`, `go test -race ./internal/geo/`.

---

### Task 1: Swappable reader + Reload

**Files:**
- Modify: `internal/geo/lookup.go`
- Modify: `internal/geo/lookup_test.go`

**Interfaces:**
- Produces (consumed by later bricks): `func (l *Lookup) Reload(newPath string) error`. `NewLookup`, `LookupIP`, `Path`, `Close` keep their existing signatures.

- [ ] **Step 1: Write the failing tests**

Add to `internal/geo/lookup_test.go` (keep all existing error/LAN/nil tests). These need no real MMDB — they exercise the swap control flow.

**Import note:** the test file currently imports `net`, `os`, `path/filepath`, `strings`, `testing`. The concurrency test needs `sync` (for `sync.WaitGroup`) — add it to the import block.

```go
func TestReload_EmptyPath_ReturnsErrorNoChange(t *testing.T) {
	l := &Lookup{} // nil reader
	if err := l.Reload(""); err == nil {
		t.Fatal("Reload(\"\") = nil; want error")
	}
	// reader untouched → still degraded, no panic
	if got := l.LookupIP(net.ParseIP("8.8.8.8")); got.Found {
		t.Errorf("LookupIP after failed reload = %+v; want Found=false", got)
	}
}

func TestReload_InvalidPath_PreservesReader(t *testing.T) {
	l := &Lookup{}
	missing := filepath.Join(t.TempDir(), "nope.mmdb")
	err := l.Reload(missing)
	if err == nil {
		t.Fatal("Reload(missing) = nil; want error")
	}
	if !strings.Contains(err.Error(), "reload open mmdb") {
		t.Errorf("error = %v; want wrapped 'reload open mmdb'", err)
	}
	// current (nil) reader preserved; lookups still safe
	if got := l.LookupIP(net.ParseIP("8.8.8.8")); got.Found {
		t.Errorf("LookupIP after failed reload = %+v; want Found=false", got)
	}
}

func TestReload_NilReceiver_ReturnsError(t *testing.T) {
	var l *Lookup
	if err := l.Reload("/whatever"); err == nil {
		t.Fatal("nil *Lookup Reload = nil; want error")
	}
}

func TestReload_FailedReload_DoesNotChangePath(t *testing.T) {
	l := &Lookup{}
	l.setPathForTest("original.mmdb") // see helper below
	_ = l.Reload(filepath.Join(t.TempDir(), "missing.mmdb"))
	if got := l.Path(); got != "original.mmdb" {
		t.Errorf("Path after failed reload = %q; want unchanged 'original.mmdb'", got)
	}
}

func TestReload_Concurrent_RaceSafe(t *testing.T) {
	l := &Lookup{}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	// readers
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = l.LookupIP(net.ParseIP("8.8.8.8"))
				}
			}
		}()
	}
	// reloader (reloads fail-open since no real DB; still exercises Swap path)
	missing := filepath.Join(t.TempDir(), "missing.mmdb")
	for i := 0; i < 50; i++ {
		_ = l.Reload(missing)
	}
	close(stop)
	wg.Wait()
}
```

Add a tiny test-only helper in the same file (it sets the unexported `path` — same package, so allowed):

```go
// setPathForTest sets the unexported path field for tests that assert
// Path() behavior without a real MMDB.
func (l *Lookup) setPathForTest(p string) {
	l.pathMu.Lock()
	l.path = p
	l.pathMu.Unlock()
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/geo/ -run 'Reload' -v`
Expected: compile error — `Reload` undefined, `pathMu` field undefined, `setPathForTest` references a field that doesn't exist yet. (Compile failure IS the red state here.)

- [ ] **Step 3: Rewrite the `Lookup` type + methods**

In `internal/geo/lookup.go`:

**3a. Imports** — add `sync/atomic` and `time`; keep `sync` (still used by `pathMu`):

```go
import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
)
```

**3b. The type** — replace the struct (currently `reader *geoip2.Reader` + `mu sync.Mutex` + `closed bool`):

```go
// Lookup wraps a MaxMind GeoLite2-City reader. Safe for concurrent
// use: the underlying reader is a read-only mmap (goroutine-safe for
// reads), published via an atomic pointer so Reload can swap it in at
// runtime without a lock on the lookup hot path.
//
// A nil *Lookup is a valid degraded-mode receiver: LookupIP returns
// Location{Found: false} and Close/Reload are safe.
type Lookup struct {
	reader atomic.Pointer[geoip2.Reader]

	// pathMu guards path, updated by Reload off the hot path.
	pathMu sync.Mutex
	path   string
}

// closeGracePeriod is how long Reload waits before closing the previous
// reader, so concurrent in-flight lookups (each a microsecond-scale
// City() call) finish against the old mmap before it is unmapped.
const closeGracePeriod = 5 * time.Second
```

**3c. `NewLookup`** — store via the atomic pointer:

```go
func NewLookup(mmdbPath string) (*Lookup, error) {
	if mmdbPath == "" {
		return nil, errors.New("geo: mmdb path is empty")
	}
	reader, err := geoip2.Open(mmdbPath)
	if err != nil {
		return nil, fmt.Errorf("geo: open mmdb %q: %w", mmdbPath, err)
	}
	l := &Lookup{path: mmdbPath}
	l.reader.Store(reader)
	return l, nil
}
```

**3d. `Path`** — read under `pathMu`:

```go
func (l *Lookup) Path() string {
	if l == nil {
		return ""
	}
	l.pathMu.Lock()
	defer l.pathMu.Unlock()
	return l.path
}
```

**3e. `LookupIP`** — lock-free reader load (replace the `l.mu`/`closed` block + `l.reader.City`):

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
	if err != nil || rec == nil {
		return Location{Found: false}
	}
	loc := Location{
		Country:     rec.Country.IsoCode,
		CountryName: rec.Country.Names["en"],
		City:        rec.City.Names["en"],
		Lat:         rec.Location.Latitude,
		Lon:         rec.Location.Longitude,
	}
	loc.Found = loc.Country != "" || loc.Lat != 0 || loc.Lon != 0
	return loc
}
```

**3f. `Reload`** (NEW):

```go
// Reload opens the MMDB at newPath and atomically swaps it in as the
// active reader. In-flight lookups continue against whichever reader
// they already loaded; the previous reader is closed after a grace
// period so those lookups finish first.
//
// On open error the current reader is left in place — a failed download
// or corrupt file never degrades a working lookup. A nil receiver or
// empty path returns an error.
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
		go func(r *geoip2.Reader) {
			time.Sleep(closeGracePeriod)
			_ = r.Close()
		}(old)
	}
	return nil
}
```

**3g. `Close`** — swap nil, close the returned reader:

```go
// Close releases the MMDB file handle. Safe to call on nil, safe to
// call multiple times.
func (l *Lookup) Close() error {
	if l == nil {
		return nil
	}
	if r := l.reader.Swap(nil); r != nil {
		return r.Close()
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/geo/ -run 'Reload' -v`
Expected: PASS (all 5 Reload tests). Then the whole package including the existing error/LAN/nil tests:
Run: `go test ./internal/geo/`
Expected: PASS.

- [ ] **Step 5: Run the package under -race**

Run: `go test -race ./internal/geo/`
Expected: PASS, no race reports. This is the load-bearing safety proof for the atomic swap under concurrent lookups.

- [ ] **Step 6: Confirm consumers still compile unchanged**

Run: `go build ./...`
Expected: clean — the enricher (`internal/geo/enricher.go`), server-position (`internal/geo/server_position.go`), and country-block adapter (`cmd/arenet/geo_forwarders.go`) use `NewLookup`/`LookupIP`/`Path`/`Close` (unchanged signatures) and must compile without edits.

- [ ] **Step 7: gofmt + vet + staticcheck + commit**

```bash
gofmt -s -w internal/geo/lookup.go internal/geo/lookup_test.go
go vet ./internal/geo/
staticcheck ./internal/geo/ || true   # report; don't block if tool absent
git add internal/geo/lookup.go internal/geo/lookup_test.go
git commit -m "feat(geo): swappable reader via atomic.Pointer + Reload (hot-reload)

Replace Lookup's plain *geoip2.Reader (+ mu/closed) with
atomic.Pointer[geoip2.Reader]; reads are now lock-free. Add
Reload(newPath): open the new MMDB, atomically swap it in, and close the
previous reader after a grace period so in-flight lookups finish first
(no use-after-close). On open error the current reader is preserved — a
failed download never degrades a working lookup. Consumers (enricher,
server-position, country-block) keep their *geo.Lookup unchanged.

Brick 1 of the GeoIP auto-update feature. Test coverage is swap-semantics
+ -race (no mmdb fixture in the repo; end-to-end real-DB reload verified
in brick 3)."
```

---

## Self-Review

**Spec coverage:** atomic.Pointer reader + lock-free reads → Task 1 Step 3b/3e. `Reload` open→swap→delayed-close, error preserves reader → Step 3f. `closeGracePeriod` constant → Step 3b. `NewLookup`/`Path`/`Close` adjusted, signatures unchanged → Steps 3c/3d/3g. Consumers unchanged → Step 6. Tests (empty-path, invalid-path-preserves, nil-receiver, path-unchanged-on-failure, -race) → Step 1; nil/LAN/error existing tests kept → Step 1 note + Step 4. Runtime verification (`-race` + build) → Steps 5-6. All spec sections covered.

**Placeholder scan:** No TBD/TODO; full before/after code for every method. The `setPathForTest` helper is real, defined inline. The deferred "real-DB post-reload lookup" is explicitly a Brick 3 item, not a placeholder.

**Type consistency:** `atomic.Pointer[geoip2.Reader]` stores `*geoip2.Reader`; `geoip2.Open` returns `*geoip2.Reader` (verified), `Load()`/`Swap(nr)`/`Store(reader)` all use `*geoip2.Reader`; `r.City(ip)` and `r.Close()` are pointer methods (verified). `Reload(newPath string) error` signature identical in the spec, the type method, and the test calls. `closeGracePeriod` referenced only in `Reload`.
