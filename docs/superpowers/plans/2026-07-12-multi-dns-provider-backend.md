# Multi-config DNS providers — Backend (v2.11.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the singleton OVH DNS provider config into a UUID-keyed collection so operators can register multiple OVH accounts, each wildcard managed-domain referencing one — backend only (storage, migration, REST API, caddymgr dispatch, backup).

**Architecture:** Reuse the existing `dns_providers` bucket, re-keyed from the fixed `"ovh"` key to per-config UUIDs. `DNSProviderConfig` gains `ID`/`Label`/`Type`. `ManagedDomain.Provider` (a type) becomes `ProviderID` (a config id). A one-shot idempotent boot migration converts the legacy singleton. The REST API becomes a standard collection mirroring `managed-domains`. caddymgr dispatches per-`ProviderID`.

**Tech Stack:** Go 1.25, BoltDB (`go.etcd.io/bbolt`), `github.com/google/uuid`, chi router, embedded Caddy v2, `log/slog`.

## Global Constraints

- AGPL header on every Go file (see CLAUDE.md).
- `gofmt -s` clean, `go vet ./...`, `staticcheck ./...` pass.
- Every I/O function takes `ctx context.Context` first.
- Wrap errors: `fmt.Errorf("context: %w", err)`. No `panic` outside `main`.
- Secrets (`ApplicationKey`/`ApplicationSecret`/`ConsumerKey`) NEVER serialized in API responses, audit JSON, or slog.
- Any claim about Caddy runtime behaviour verified empirically (`caddy.Validate()` on emitted JSON + handler-ID resolvability) — CLAUDE.md §Empirical verification.
- Backup `SchemaVersion` stays `1.x` (no MAJOR bump).
- Provider type value space is the closed set `{"ovh"}` in v1; unknown types rejected.

---

## File Structure

- `internal/storage/dns_provider.go` — struct + collection CRUD + validation (MODIFY, largest change).
- `internal/storage/dns_provider_migration.go` — one-shot boot migration (CREATE).
- `internal/storage/managed_domain.go` — `Provider` → `ProviderID` field rename + validator (MODIFY).
- `internal/storage/errors.go` — add `ErrProviderInUse` (MODIFY).
- `internal/api/dns_provider.go` — 5 collection handlers (MODIFY, replaces the 2 singleton handlers).
- `internal/api/routes.go` — collection routes (MODIFY).
- `internal/api/managed_domains.go` (or wherever managed-domain create/update lives) — accept `providerId` (MODIFY).
- `internal/caddymgr/manager.go` — per-`ProviderID` dispatch + load all providers into `buildOpts` (MODIFY).
- `internal/backup/export.go` + `internal/backup/import.go` — collection export/import (MODIFY).
- `cmd/arenet/main.go` — call the migration at boot (MODIFY).

---

### Task 1a: Storage — DNSProviderConfig struct + collection CRUD

**Files:**
- Modify: `internal/storage/dns_provider.go`
- Modify: `internal/storage/errors.go`
- Test: `internal/storage/dns_provider_test.go`

**Interfaces:**
- Produces:
  - `type DNSProviderConfig struct { ID, Label, Type, Endpoint, ApplicationKey, ApplicationSecret, ConsumerKey string }`
  - `const DNSProviderTypeOVH = "ovh"`; `var DNSProviderTypes = []string{DNSProviderTypeOVH}`
  - `func (s *Store) ListDNSProviders(ctx context.Context) ([]DNSProviderConfig, error)`
  - `func (s *Store) GetDNSProvider(ctx context.Context, id string) (DNSProviderConfig, error)`
  - `func (s *Store) CreateDNSProvider(ctx context.Context, c DNSProviderConfig) (DNSProviderConfig, error)` (assigns UUID, validates, persists)
  - `func (s *Store) UpdateDNSProvider(ctx context.Context, id string, c DNSProviderConfig) (DNSProviderConfig, error)` (preserve-on-edit secrets)
  - `func (s *Store) DeleteDNSProvider(ctx context.Context, id string) error` (`ErrProviderInUse` / `ErrNotFound`)
  - `var ErrProviderInUse = errors.New("storage: dns provider is referenced by one or more managed domains")`
- Consumes: `s.db` (bbolt), `bucketDNSProviders`, `withTimeout`, `ErrNotFound`, `uuid.NewString`, `s.ListManagedDomains` (for the in-use check).

- [ ] **Step 1: Add `ErrProviderInUse` to errors.go**

In `internal/storage/errors.go`, add alongside the existing sentinels:

```go
// ErrProviderInUse is returned by DeleteDNSProvider when at least one
// managed domain still references the provider by its ProviderID.
// The API maps it to 409 Conflict.
var ErrProviderInUse = errors.New("storage: dns provider is referenced by one or more managed domains")
```

- [ ] **Step 2: Write the failing test for the struct + Create/Get/List**

Append to `internal/storage/dns_provider_test.go`:

```go
func TestDNSProvider_CreateGetList(t *testing.T) {
	s := newStoreForTest(t) // existing helper in this package's tests
	ctx := context.Background()

	in := DNSProviderConfig{
		Label:             "OVH perso",
		Type:              DNSProviderTypeOVH,
		Endpoint:          "ovh-eu",
		ApplicationKey:    "ak",
		ApplicationSecret: "as",
		ConsumerKey:       "ck",
	}
	created, err := s.CreateDNSProvider(ctx, in)
	if err != nil {
		t.Fatalf("CreateDNSProvider: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateDNSProvider did not assign an ID")
	}
	if created.Label != "OVH perso" || created.Type != "ovh" {
		t.Errorf("round-trip mismatch: %+v", created)
	}

	got, err := s.GetDNSProvider(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetDNSProvider: %v", err)
	}
	if got.ApplicationKey != "ak" {
		t.Errorf("secret not persisted: %+v", got)
	}

	list, err := s.ListDNSProviders(ctx)
	if err != nil {
		t.Fatalf("ListDNSProviders: %v", err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Errorf("list = %+v, want 1 entry with id %s", list, created.ID)
	}
}

func TestDNSProvider_GetMissing_ReturnsErrNotFound(t *testing.T) {
	s := newStoreForTest(t)
	if _, err := s.GetDNSProvider(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
```

> Note: confirm the exact test-store constructor name used elsewhere in `dns_provider_test.go` (e.g. `newStoreForTest(t)` or an inline `NewStore(filepath.Join(t.TempDir(), "arenet.db"))`) and match it.

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/storage/ -run TestDNSProvider_CreateGetList -v`
Expected: FAIL — `undefined: DNSProviderTypeOVH` / `s.CreateDNSProvider undefined`.

- [ ] **Step 4: Extend the struct + type enum**

In `internal/storage/dns_provider.go`, replace the struct with:

```go
type DNSProviderConfig struct {
	ID                string `json:"id"`
	Label             string `json:"label"`
	Type              string `json:"type"` // one of DNSProviderTypes
	Endpoint          string `json:"endpoint"`
	ApplicationKey    string `json:"application_key"`    // SECRET — never echoed by the API or audit
	ApplicationSecret string `json:"application_secret"` // SECRET — never echoed by the API or audit
	ConsumerKey       string `json:"consumer_key"`       // SECRET — never echoed by the API or audit
}

// DNSProviderTypeOVH is the only provider type wired in v1. The
// closed enum below is the forward-compat extension point for
// cloudflare / route53.
const DNSProviderTypeOVH = "ovh"

// DNSProviderTypes is the closed set of accepted Type values.
var DNSProviderTypes = []string{DNSProviderTypeOVH}
```

- [ ] **Step 5: Extend `validate` for Label + Type**

In `dns_provider.go`, update `(c *DNSProviderConfig) validate()` to add, before the endpoint check:

```go
	if c.Label == "" {
		return errors.New("dns_provider: label must not be empty")
	}
	typeOK := false
	for _, t := range DNSProviderTypes {
		if c.Type == t {
			typeOK = true
			break
		}
	}
	if !typeOK {
		return fmt.Errorf("dns_provider: type %q is not a recognised provider type", c.Type)
	}
```

- [ ] **Step 6: Implement collection CRUD**

Add to `dns_provider.go` (and REMOVE the old `GetDNSProviderOVH`/`PutDNSProviderOVH`/`DeleteDNSProviderOVH` + `dnsProviderKeyOVH` const — the migration in Task 1b reads the legacy key directly via a local literal):

```go
// ListDNSProviders returns all configured providers, unordered
// (bbolt iteration order). The API/frontend sorts by Label.
func (s *Store) ListDNSProviders(ctx context.Context) ([]DNSProviderConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	out := []DNSProviderConfig{}
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketDNSProviders))
		return b.ForEach(func(_, raw []byte) error {
			var c DNSProviderConfig
			if err := json.Unmarshal(raw, &c); err != nil {
				return fmt.Errorf("unmarshal dns provider: %w", err)
			}
			out = append(out, c)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetDNSProvider returns the provider with the given id, or
// ErrNotFound.
func (s *Store) GetDNSProvider(ctx context.Context, id string) (DNSProviderConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out DNSProviderConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketDNSProviders)).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return DNSProviderConfig{}, err
	}
	return out, nil
}

// CreateDNSProvider assigns a fresh UUID, validates, and persists.
func (s *Store) CreateDNSProvider(ctx context.Context, c DNSProviderConfig) (DNSProviderConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	c.ID = uuid.NewString()
	if c.Type == "" {
		c.Type = DNSProviderTypeOVH
	}
	if err := c.validate(); err != nil {
		return DNSProviderConfig{}, err
	}
	buf, err := json.Marshal(c)
	if err != nil {
		return DNSProviderConfig{}, fmt.Errorf("marshal dns provider: %w", err)
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketDNSProviders)).Put([]byte(c.ID), buf)
	})
	if err != nil {
		return DNSProviderConfig{}, err
	}
	return c, nil
}

// UpdateDNSProvider applies preserve-on-edit secret semantics: any of
// the three secret fields left blank in `c` keeps the stored value;
// a non-empty field replaces it. Label/Type/Endpoint always overwrite.
func (s *Store) UpdateDNSProvider(ctx context.Context, id string, c DNSProviderConfig) (DNSProviderConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out DNSProviderConfig
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketDNSProviders))
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var existing DNSProviderConfig
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("unmarshal dns provider: %w", err)
		}
		merged := c
		merged.ID = id
		if merged.ApplicationKey == "" {
			merged.ApplicationKey = existing.ApplicationKey
		}
		if merged.ApplicationSecret == "" {
			merged.ApplicationSecret = existing.ApplicationSecret
		}
		if merged.ConsumerKey == "" {
			merged.ConsumerKey = existing.ConsumerKey
		}
		if merged.Type == "" {
			merged.Type = existing.Type
		}
		if err := merged.validate(); err != nil {
			return err
		}
		buf, err := json.Marshal(merged)
		if err != nil {
			return fmt.Errorf("marshal dns provider: %w", err)
		}
		out = merged
		return b.Put([]byte(id), buf)
	})
	if err != nil {
		return DNSProviderConfig{}, err
	}
	return out, nil
}

// DeleteDNSProvider removes the provider, but only if no managed
// domain references it. Returns ErrProviderInUse otherwise, ErrNotFound
// if the id doesn't exist.
func (s *Store) DeleteDNSProvider(ctx context.Context, id string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	mds, err := s.ListManagedDomains(ctx)
	if err != nil {
		return err
	}
	for _, md := range mds {
		if md.ProviderID == id {
			return ErrProviderInUse
		}
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketDNSProviders))
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}
```

> `DeleteDNSProvider` references `md.ProviderID` — that field lands in Task 1c-pre (managed_domain rename, Step below). Sequence Task 1a Step 6 AFTER the `ProviderID` rename if the compiler complains; the rename is small and listed first in Task 1b's file set. To keep 1a compilable standalone, do the `Provider`→`ProviderID` rename (Task 1b Step 1) FIRST, then this step.

- [ ] **Step 7: Ensure imports** — add `"github.com/google/uuid"` to `dns_provider.go` imports if not present.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `go test ./internal/storage/ -run 'TestDNSProvider_' -v`
Expected: PASS.

- [ ] **Step 9: Write preserve-on-edit + delete-in-use tests**

```go
func TestDNSProvider_UpdatePreservesBlankSecrets(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	created, _ := s.CreateDNSProvider(ctx, DNSProviderConfig{
		Label: "OVH", Type: "ovh", Endpoint: "ovh-eu",
		ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: "ck",
	})
	// Edit label only; leave all secrets blank.
	updated, err := s.UpdateDNSProvider(ctx, created.ID, DNSProviderConfig{
		Label: "OVH renamed", Type: "ovh", Endpoint: "ovh-eu",
	})
	if err != nil {
		t.Fatalf("UpdateDNSProvider: %v", err)
	}
	if updated.Label != "OVH renamed" {
		t.Errorf("label = %q", updated.Label)
	}
	if updated.ApplicationKey != "ak" || updated.ConsumerKey != "ck" {
		t.Errorf("blank secrets were not preserved: %+v", updated)
	}
}

func TestDNSProvider_DeleteInUse_ReturnsErrProviderInUse(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p, _ := s.CreateDNSProvider(ctx, DNSProviderConfig{
		Label: "OVH", Type: "ovh", Endpoint: "ovh-eu",
		ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: "ck",
	})
	if err := s.PutManagedDomain(ctx, ManagedDomain{Apex: "example.com", ProviderID: p.ID}); err != nil {
		t.Fatalf("PutManagedDomain: %v", err)
	}
	if err := s.DeleteDNSProvider(ctx, p.ID); !errors.Is(err, ErrProviderInUse) {
		t.Errorf("err = %v, want ErrProviderInUse", err)
	}
}
```

- [ ] **Step 10: Run all storage tests**

Run: `go test ./internal/storage/ -v 2>&1 | tail -20`
Expected: PASS (the old singleton tests referencing `GetDNSProviderOVH` will fail to compile — update/delete them in the same commit; they are superseded).

- [ ] **Step 11: Commit**

```bash
git add internal/storage/dns_provider.go internal/storage/dns_provider_test.go internal/storage/errors.go internal/storage/managed_domain.go
git commit -m "feat(storage): DNS provider collection CRUD (UUID-keyed, multi-config)"
```

---

### Task 1b: Storage — ManagedDomain ProviderID rename + one-shot migration

**Files:**
- Modify: `internal/storage/managed_domain.go`
- Create: `internal/storage/dns_provider_migration.go`
- Modify: `cmd/arenet/main.go`
- Test: `internal/storage/dns_provider_migration_test.go`

**Interfaces:**
- Produces:
  - `ManagedDomain.ProviderID string` (json `provider_id`), replacing `Provider`.
  - `func (s *Store) MigrateLegacyDNSProvider(ctx context.Context) (migrated bool, err error)`
- Consumes: `bucketDNSProviders`, `bucketManagedDomains`, `uuid.NewString`, `DNSProviderTypeOVH`.

- [ ] **Step 1: Rename `Provider` → `ProviderID` on ManagedDomain**

In `internal/storage/managed_domain.go`, change the struct field:

```go
	// ProviderID references the DNSProviderConfig.ID whose credentials
	// caddymgr uses for the DNS-01 challenge. Empty means "no provider
	// assigned" (wildcard falls back to the internal CA). Replaces the
	// pre-v2.11 `Provider` (a type string); the boot migration repoints
	// legacy "ovh" values to the migrated config's UUID.
	ProviderID string `json:"provider_id"`
```

Update the managed-domain validator: it previously checked `Provider` against `ManagedDomainProviders`. Replace that with: `ProviderID` may be empty (unassigned) OR any non-empty string (existence is validated at the API layer against `GetDNSProvider`, not in storage — storage stays referential-integrity-free like the rest of the bucket layer). Remove the now-unused `ManagedDomainProviderOVH` / `ManagedDomainProviders` if nothing else references them (grep first; caddymgr Task 1d also updates its reference).

- [ ] **Step 2: Write the failing migration test**

Create `internal/storage/dns_provider_migration_test.go`:

```go
package storage

import (
	"context"
	"encoding/json"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestMigrateLegacyDNSProvider_ConvertsAndRepoints(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	// Seed the legacy singleton row under the fixed "ovh" key +
	// a managed domain referencing the legacy "ovh" type.
	legacy := DNSProviderConfig{Endpoint: "ovh-eu", ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: "ck"}
	buf, _ := json.Marshal(legacy)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte(bucketDNSProviders)).Put([]byte("ovh"), buf); err != nil {
			return err
		}
		md := ManagedDomain{Apex: "example.com", IncludeApex: true}
		// legacy row still uses the old "provider" json key:
		mdRaw := []byte(`{"apex":"example.com","include_apex":true,"provider":"ovh"}`)
		return tx.Bucket([]byte(bucketManagedDomains)).Put([]byte(md.Apex), mdRaw)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	migrated, err := s.MigrateLegacyDNSProvider(ctx)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !migrated {
		t.Fatal("expected migrated=true on first run")
	}

	// Legacy "ovh" key gone; exactly one UUID-keyed provider now.
	list, _ := s.ListDNSProviders(ctx)
	if len(list) != 1 {
		t.Fatalf("providers = %d, want 1", len(list))
	}
	newID := list[0].ID
	if newID == "ovh" || newID == "" {
		t.Errorf("provider not re-keyed to a UUID: %q", newID)
	}
	if list[0].Label != "OVH (default)" || list[0].Type != "ovh" {
		t.Errorf("migrated provider = %+v", list[0])
	}
	if list[0].ApplicationKey != "ak" {
		t.Errorf("secrets not carried over: %+v", list[0])
	}

	// Managed domain repointed to the new UUID.
	md, _ := s.GetManagedDomain(ctx, "example.com")
	if md.ProviderID != newID {
		t.Errorf("managed domain ProviderID = %q, want %q", md.ProviderID, newID)
	}

	// Idempotence: a second run is a no-op.
	migrated2, err := s.MigrateLegacyDNSProvider(ctx)
	if err != nil {
		t.Fatalf("migrate #2: %v", err)
	}
	if migrated2 {
		t.Error("second migration ran again; expected no-op")
	}
	list2, _ := s.ListDNSProviders(ctx)
	if len(list2) != 1 {
		t.Errorf("providers after 2nd run = %d, want 1", len(list2))
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/storage/ -run TestMigrateLegacyDNSProvider -v`
Expected: FAIL — `s.MigrateLegacyDNSProvider undefined`.

- [ ] **Step 4: Implement the migration**

Create `internal/storage/dns_provider_migration.go` (with AGPL header):

```go
package storage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// legacyDNSProviderKey is the fixed bucket key used by the pre-v2.11
// singleton OVH provider. Kept only for the one-shot migration.
const legacyDNSProviderKey = "ovh"

// MigrateLegacyDNSProvider converts the pre-v2.11 singleton OVH config
// (stored under the fixed "ovh" key) into a UUID-keyed collection entry
// labelled "OVH (default)", and repoints every managed domain that used
// the legacy provider="ovh" value to the new config's UUID.
//
// Idempotent BY STATE: it runs only while the legacy "ovh" key is
// present. Once migrated the key is gone, so subsequent boots no-op.
// Returns migrated=true only when it actually did work.
func (s *Store) MigrateLegacyDNSProvider(ctx context.Context) (bool, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	migrated := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		pb := tx.Bucket([]byte(bucketDNSProviders))
		raw := pb.Get([]byte(legacyDNSProviderKey))
		if raw == nil {
			return nil // already migrated / fresh install
		}
		var legacy DNSProviderConfig
		if err := json.Unmarshal(raw, &legacy); err != nil {
			return fmt.Errorf("unmarshal legacy dns provider: %w", err)
		}
		newID := uuid.NewString()
		legacy.ID = newID
		legacy.Label = "OVH (default)"
		legacy.Type = DNSProviderTypeOVH
		buf, err := json.Marshal(legacy)
		if err != nil {
			return fmt.Errorf("marshal migrated dns provider: %w", err)
		}
		if err := pb.Put([]byte(newID), buf); err != nil {
			return err
		}
		if err := pb.Delete([]byte(legacyDNSProviderKey)); err != nil {
			return err
		}

		// Repoint managed domains: read each row, if its raw JSON
		// still carries provider=="ovh" (or provider_id empty with a
		// legacy provider key), set provider_id to newID.
		mb := tx.Bucket([]byte(bucketManagedDomains))
		type legacyMD struct {
			Apex        string `json:"apex"`
			IncludeApex bool   `json:"include_apex"`
			Provider    string `json:"provider"`
			ProviderID  string `json:"provider_id"`
		}
		return mb.ForEach(func(k, v []byte) error {
			var md legacyMD
			if err := json.Unmarshal(v, &md); err != nil {
				return fmt.Errorf("unmarshal managed domain %q: %w", k, err)
			}
			if md.ProviderID == "" && md.Provider == legacyDNSProviderKey {
				out := ManagedDomain{Apex: md.Apex, IncludeApex: md.IncludeApex, ProviderID: newID}
				ob, err := json.Marshal(out)
				if err != nil {
					return fmt.Errorf("marshal repointed managed domain: %w", err)
				}
				if err := mb.Put(k, ob); err != nil {
					return err
				}
			}
			return nil
		})
	})
	if err != nil {
		return false, err
	}
	// Determine migrated flag by re-checking: if legacy key is now
	// absent AND we just deleted it. Simplest: re-open a view.
	_ = migrated
	err = s.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte(bucketDNSProviders)).Get([]byte(legacyDNSProviderKey)) == nil {
			return nil
		}
		return nil
	})
	// Recompute migrated by whether the legacy key existed at entry.
	// Cleaner: track inside the Update. See Step 5 refinement.
	return migrated, err
}
```

- [ ] **Step 5: Refine the `migrated` flag (track inside the txn)**

The draft above leaves `migrated` always false. Fix by setting it inside the `Update` closure right after the legacy key is found:

```go
		raw := pb.Get([]byte(legacyDNSProviderKey))
		if raw == nil {
			return nil
		}
		migrated = true   // <-- add this line
```

Then delete the second `s.db.View` block and `return migrated, nil` directly. Final tail of the function:

```go
	if err != nil {
		return false, err
	}
	return migrated, nil
```

- [ ] **Step 6: Run the migration test**

Run: `go test ./internal/storage/ -run TestMigrateLegacyDNSProvider -v`
Expected: PASS (both first-run and idempotence assertions).

- [ ] **Step 7: Wire the migration at boot**

In `cmd/arenet/main.go`, after the store is opened and before caddymgr builds its first config, add:

```go
	if migrated, err := store.MigrateLegacyDNSProvider(ctx); err != nil {
		logger.Error("dns provider migration failed", "err", err)
		// non-fatal: continue with whatever is in storage
	} else if migrated {
		logger.Info("migrated legacy OVH DNS provider config to multi-config format")
	}
```

> Locate the exact spot by searching `main.go` for where `store` is created and where the caddy manager is constructed; insert between them.

- [ ] **Step 8: Build to confirm main.go compiles**

Run: `go build ./cmd/arenet`
Expected: no output (success).

- [ ] **Step 9: Commit**

```bash
git add internal/storage/managed_domain.go internal/storage/dns_provider_migration.go internal/storage/dns_provider_migration_test.go cmd/arenet/main.go
git commit -m "feat(storage): one-shot legacy OVH provider migration + ProviderID"
```

---

### Task 1c: API — DNS provider collection endpoints + managed-domain providerId

**Files:**
- Modify: `internal/api/dns_provider.go`
- Modify: `internal/api/routes.go`
- Modify: the managed-domain create/update handler file (grep `createManagedDomain` / `putManagedDomain` in `internal/api/`)
- Test: `internal/api/dns_provider_test.go`

**Interfaces:**
- Produces (wire, all JSON):
  - `GET /api/v1/settings/dns-providers` → `[]dnsProviderView{id,label,type,endpoint,configured,usedBy}` (no secrets)
  - `POST /api/v1/settings/dns-providers` → 201 `dnsProviderView`
  - `GET /api/v1/settings/dns-providers/{id}` → `dnsProviderView` | 404
  - `PUT /api/v1/settings/dns-providers/{id}` → `dnsProviderView` | 404 | 400
  - `DELETE /api/v1/settings/dns-providers/{id}` → 204 | 409 | 404
- Consumes: storage methods from 1a; `h.appendAudit`; existing `writeJSON`/`writeError`; chi `URLParam`.

- [ ] **Step 1: Write the failing handler test (create + list hides secrets)**

Append to `internal/api/dns_provider_test.go`:

```go
func TestDNSProviders_CreateThenListHidesSecrets(t *testing.T) {
	env := newAdminTestEnv(t) // existing helper: authed admin router + store
	body := map[string]string{
		"label": "OVH perso", "type": "ovh", "endpoint": "ovh-eu",
		"applicationKey": "ak", "applicationSecret": "as", "consumerKey": "ck",
	}
	rec := postJSONAuthed(t, env, "POST", "/api/v1/settings/dns-providers", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body)
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created["id"] == "" || created["id"] == nil {
		t.Fatal("no id in create response")
	}
	for _, secret := range []string{"applicationKey", "application_key", "applicationSecret", "consumerKey"} {
		if v, ok := created[secret]; ok && v != "" {
			t.Errorf("secret %q leaked in response: %v", secret, v)
		}
	}

	rec = getAuthed(t, env, "/api/v1/settings/dns-providers")
	var list []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0]["configured"] != true {
		t.Errorf("list = %+v, want 1 configured entry", list)
	}
}

func TestDNSProviders_DeleteInUse_Returns409(t *testing.T) {
	env := newAdminTestEnv(t)
	rec := postJSONAuthed(t, env, "POST", "/api/v1/settings/dns-providers", map[string]string{
		"label": "OVH", "type": "ovh", "endpoint": "ovh-eu",
		"applicationKey": "ak", "applicationSecret": "as", "consumerKey": "ck",
	})
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)
	// attach a managed domain to this provider directly in storage
	_ = env.store.PutManagedDomain(context.Background(), storage.ManagedDomain{Apex: "a.com", ProviderID: id})

	rec = deleteAuthed(t, env, "/api/v1/settings/dns-providers/"+id)
	if rec.Code != http.StatusConflict {
		t.Errorf("delete status = %d, want 409; body=%s", rec.Code, rec.Body)
	}
}
```

> Match the actual test-env helper names in this package (`newAdminTestEnv`, `postJSONAuthed`, `getAuthed`, `deleteAuthed`) — grep `_test.go` in `internal/api/` and adapt. If a helper is missing, add a thin one following the existing pattern.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/api/ -run TestDNSProviders_ -v`
Expected: FAIL — routes 404 / handlers undefined.

- [ ] **Step 3: Implement the view type + handlers**

Rewrite `internal/api/dns_provider.go` handlers. The response view (secrets stripped, `configured` derived, `usedBy` from managed domains):

```go
type dnsProviderView struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Type      string   `json:"type"`
	Endpoint  string   `json:"endpoint"`
	Configured bool    `json:"configured"`
	UsedBy    []string `json:"usedBy"`
}

func toDNSProviderView(c storage.DNSProviderConfig, usedBy []string) dnsProviderView {
	return dnsProviderView{
		ID: c.ID, Label: c.Label, Type: c.Type, Endpoint: c.Endpoint,
		Configured: c.ApplicationKey != "" && c.ApplicationSecret != "" && c.ConsumerKey != "",
		UsedBy:     usedBy,
	}
}

// usedByIndex builds providerID -> [apex...] from managed domains.
func (h *Handler) usedByIndex(ctx context.Context) (map[string][]string, error) {
	mds, err := h.store.ListManagedDomains(ctx)
	if err != nil {
		return nil, err
	}
	idx := map[string][]string{}
	for _, md := range mds {
		if md.ProviderID != "" {
			idx[md.ProviderID] = append(idx[md.ProviderID], md.Apex)
		}
	}
	return idx, nil
}

func (h *Handler) listDNSProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := h.store.ListDNSProviders(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	idx, err := h.usedByIndex(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]dnsProviderView, 0, len(list))
	for _, c := range list {
		out = append(out, toDNSProviderView(c, idx[c.ID]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	writeJSON(w, http.StatusOK, out)
}

type dnsProviderRequest struct {
	Label             string `json:"label"`
	Type              string `json:"type"`
	Endpoint          string `json:"endpoint"`
	ApplicationKey    string `json:"applicationKey"`
	ApplicationSecret string `json:"applicationSecret"`
	ConsumerKey       string `json:"consumerKey"`
}

func (h *Handler) createDNSProvider(w http.ResponseWriter, r *http.Request) {
	var req dnsProviderRequest
	if err := decodeJSONStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	cfg := storage.DNSProviderConfig{
		Label: strings.TrimSpace(req.Label), Type: req.Type, Endpoint: req.Endpoint,
		ApplicationKey: req.ApplicationKey, ApplicationSecret: req.ApplicationSecret, ConsumerKey: req.ConsumerKey,
	}
	created, err := h.store.CreateDNSProvider(r.Context(), cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.appendAudit(r, audit.Event{
		Action: audit.ActionDNSProviderCreated, TargetType: "dns_provider", TargetID: created.ID,
	})
	writeJSON(w, http.StatusCreated, toDNSProviderView(created, nil))
}

func (h *Handler) getDNSProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	c, err := h.store.GetDNSProvider(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "dns provider not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	idx, _ := h.usedByIndex(r.Context())
	writeJSON(w, http.StatusOK, toDNSProviderView(c, idx[c.ID]))
}

func (h *Handler) updateDNSProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req dnsProviderRequest
	if err := decodeJSONStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	cfg := storage.DNSProviderConfig{
		Label: strings.TrimSpace(req.Label), Type: req.Type, Endpoint: req.Endpoint,
		ApplicationKey: req.ApplicationKey, ApplicationSecret: req.ApplicationSecret, ConsumerKey: req.ConsumerKey,
	}
	updated, err := h.store.UpdateDNSProvider(r.Context(), id, cfg)
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "dns provider not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.appendAudit(r, audit.Event{
		Action: audit.ActionDNSProviderUpdated, TargetType: "dns_provider", TargetID: id,
	})
	writeJSON(w, http.StatusOK, toDNSProviderView(updated, nil))
}

func (h *Handler) deleteDNSProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.store.DeleteDNSProvider(r.Context(), id)
	switch {
	case errors.Is(err, storage.ErrProviderInUse):
		idx, _ := h.usedByIndex(r.Context())
		writeError(w, http.StatusConflict, "dns provider is in use by: "+strings.Join(idx[id], ", "))
		return
	case errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "dns provider not found")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.appendAudit(r, audit.Event{
		Action: audit.ActionDNSProviderDeleted, TargetType: "dns_provider", TargetID: id,
	})
	w.WriteHeader(http.StatusNoContent)
}
```

> Confirm helper names actually in this package: `decodeJSONStrict` (or the inline `json.NewDecoder(...).DisallowUnknownFields()` used by `setup`), `translateDecodeError`, `writeJSON`, `writeError`, and the chi import alias. Match them. Add the three `audit.Action*` constants (Step 4).

- [ ] **Step 4: Add audit action constants**

In the audit package (grep `ActionSetupAdminCreated` to find the file), add:

```go
	ActionDNSProviderCreated = "dns_provider_created"
	ActionDNSProviderUpdated = "dns_provider_updated"
	ActionDNSProviderDeleted = "dns_provider_deleted"
```

(Match the existing `Action` type + naming convention verbatim.)

- [ ] **Step 5: Replace the routes**

In `internal/api/routes.go`, replace the two lines at ~355-356:

```go
				r.Get("/settings/dns-providers", h.listDNSProviders)
				r.Post("/settings/dns-providers", h.createDNSProvider)
				r.Get("/settings/dns-providers/{id}", h.getDNSProvider)
				r.Put("/settings/dns-providers/{id}", h.updateDNSProvider)
				r.Delete("/settings/dns-providers/{id}", h.deleteDNSProvider)
```

- [ ] **Step 6: Adapt managed-domain create/update to accept `providerId`**

In the managed-domain handler, change the request field from `provider` to `providerId`, keep a defensive fallback: if `providerId` is empty but a legacy `provider == "ovh"` is present, resolve it to the single migrated provider (look it up via `ListDNSProviders` and pick the one whose Type is ovh if exactly one exists). Validate that a non-empty `providerId` matches an existing provider via `GetDNSProvider`, else 400.

```go
	// providerId references a configured DNS provider. Legacy input
	// provider:"ovh" is tolerated (resolved to the sole migrated
	// provider) for backward compatibility.
	providerID := strings.TrimSpace(req.ProviderID)
	if providerID == "" && req.Provider == "ovh" {
		if list, err := h.store.ListDNSProviders(r.Context()); err == nil && len(list) == 1 {
			providerID = list[0].ID
		}
	}
	if providerID != "" {
		if _, err := h.store.GetDNSProvider(r.Context(), providerID); errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "providerId does not reference a configured DNS provider")
			return
		}
	}
	// ...then set md.ProviderID = providerID before Put.
```

- [ ] **Step 7: Run the API tests**

Run: `go test ./internal/api/ -run 'TestDNSProviders_' -v`
Expected: PASS.

- [ ] **Step 8: Run the full api package to catch fallout from removed singleton handlers**

Run: `go test ./internal/api/ 2>&1 | tail -20`
Expected: PASS (delete/update any old `getDNSProviderOVH` tests in the same commit).

- [ ] **Step 9: Commit**

```bash
git add internal/api/dns_provider.go internal/api/routes.go internal/api/dns_provider_test.go internal/api/<managed_domains_handler>.go internal/audit/<actions_file>.go
git commit -m "feat(api): DNS provider collection endpoints + managed-domain providerId"
```

---

### Task 1d: caddymgr — per-ProviderID dispatch

**Files:**
- Modify: `internal/caddymgr/manager.go`
- Test: `internal/caddymgr/manager_test.go`

**Interfaces:**
- Consumes: `store.ListDNSProviders`, `ManagedDomain.ProviderID`, existing `buildOpts`, `buildACMEPolicy`, `dnsProviderConfigured`.
- Produces: `buildOpts.DNSProviders map[string]storage.DNSProviderConfig` (keyed by id) replacing the single `DNSProviders`/`DNSProvider` field for managed-domain lookup. Per-route DNS-01 (non-wildcard) keeps using a designated default provider (the sole one, or none).

- [ ] **Step 1: Write a failing test — two managed domains, two providers, two DNS-01 policies**

Add to `internal/caddymgr/manager_test.go`:

```go
func TestBuildManagedDomainPolicies_PerProviderDispatch(t *testing.T) {
	p1 := storage.DNSProviderConfig{ID: "id-1", Label: "A", Type: "ovh", Endpoint: "ovh-eu", ApplicationKey: "k1", ApplicationSecret: "s1", ConsumerKey: "c1"}
	p2 := storage.DNSProviderConfig{ID: "id-2", Label: "B", Type: "ovh", Endpoint: "ovh-ca", ApplicationKey: "k2", ApplicationSecret: "s2", ConsumerKey: "c2"}
	opts := buildOpts{
		DNSProviders: map[string]storage.DNSProviderConfig{"id-1": p1, "id-2": p2},
		ManagedDomains: []storage.ManagedDomain{
			{Apex: "a.com", IncludeApex: false, ProviderID: "id-1"},
			{Apex: "b.org", IncludeApex: false, ProviderID: "id-2"},
		},
	}
	policies := buildManagedDomainPolicies(opts)
	if len(policies) != 2 {
		t.Fatalf("policies = %d, want 2", len(policies))
	}
	// Both must be ACME DNS-01 (not internal), each subjects the right apex.
	for _, pol := range policies {
		subs, _ := pol["subjects"].([]string)
		if len(subs) != 1 {
			t.Errorf("subjects = %v", subs)
		}
		if _, hasIssuers := pol["issuers"]; !hasIssuers {
			t.Errorf("policy missing issuers: %v", pol)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/caddymgr/ -run TestBuildManagedDomainPolicies_PerProviderDispatch -v`
Expected: FAIL — `buildOpts` has no `DNSProviders map` field / uses single `DNSProvider`.

- [ ] **Step 3: Add the map to buildOpts + load it**

In `manager.go`, change the `buildOpts` field:

```go
	// DNSProviders maps DNSProviderConfig.ID -> config, for
	// per-managed-domain DNS-01 dispatch (multi-account). Replaces
	// the pre-v2.11 single DNSProvider.
	DNSProviders map[string]storage.DNSProviderConfig
```

Where the config is loaded (~manager.go:559, currently `GetDNSProviderOVH`), replace with:

```go
	provList, err := m.store.ListDNSProviders(ctx)
	if err != nil {
		return fmt.Errorf("read dns providers: %w", err)
	}
	provByID := make(map[string]storage.DNSProviderConfig, len(provList))
	for _, p := range provList {
		provByID[p.ID] = p
	}
```

and set `DNSProviders: provByID` in the `buildOpts` literal (~manager.go:609).

- [ ] **Step 4: Update `buildManagedDomainPolicies` to dispatch by id**

Replace the check at ~manager.go:2230:

```go
	for _, md := range opts.ManagedDomains {
		var subjects []string
		if md.IncludeApex {
			subjects = []string{"*." + md.Apex, md.Apex}
		} else {
			subjects = []string{"*." + md.Apex}
		}
		prov, ok := opts.DNSProviders[md.ProviderID]
		if ok && dnsProviderConfigured(prov) {
			out = append(out, buildACMEPolicy(subjects, opts, &prov))
		} else {
			out = append(out, map[string]any{
				"subjects": subjects,
				"issuers":  []map[string]any{{"module": "internal"}},
			})
		}
	}
```

> If `buildACMEPolicy`'s signature takes `opts` and a `*storage.DNSProviderConfig`, this matches. Verify the signature; if it reads `opts.DNSProvider` internally, thread the per-provider config through instead (pass `prov` explicitly). For per-route DNS-01 (non-managed) at ~manager.go:2174, choose the sole provider if `len(provByID)==1`, else skip (document the limitation with a `log()`).

- [ ] **Step 5: Run the caddymgr test + the JSON-validates test**

Run: `go test ./internal/caddymgr/ -run 'TestBuildManagedDomainPolicies_PerProviderDispatch|TestBuildConfigJSON_LoadsCleanly|TestBuildConfigJSON_HandlersAllResolvable' -v`
Expected: PASS (the `LoadsCleanly` test runs `caddy.Validate()` on the emitted JSON — the empirical gate from CLAUDE.md).

- [ ] **Step 6: Run the whole caddymgr package**

Run: `go test ./internal/caddymgr/ 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/caddymgr/manager.go internal/caddymgr/manager_test.go
git commit -m "feat(caddymgr): per-ProviderID DNS-01 dispatch for managed domains"
```

---

### Task 1e: Backup/restore — collection export/import

**Files:**
- Modify: `internal/backup/export.go`
- Modify: `internal/backup/import.go`
- Test: `internal/backup/export_test.go`, `internal/backup/import_test.go`

**Interfaces:**
- Consumes: `store.ListDNSProviders` (replaces `GetDNSProviderOVH` at export.go:34/74 and import.go:180).
- Produces: snapshot `DNSProviders []DNSProviderConfig` continues to be a list (already is); import re-applies the collection.

- [ ] **Step 1: Update the `Storer` interface + export**

In `export.go`, replace the `GetDNSProviderOVH` method in the `Storer` interface (line 34) with `ListDNSProviders(ctx context.Context) ([]storage.DNSProviderConfig, error)`. Replace the export body (lines 73-74):

```go
	dnsList, err := store.ListDNSProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("export dns providers: %w", err)
	}
```

- [ ] **Step 2: Update import to re-apply the collection**

In `import.go` (line 180 area), replace the `GetDNSProviderOVH`-based read with `ListDNSProviders`, and in the apply path use `CreateDNSProvider` per entry OR a direct bucket reset (mirror how the other collections restore — grep `resetAndFill` in `backup_apply.go:82`). Since `backup_apply.go:82` already resets `bucketDNSProviders` from `in.DNSProviders`, ensure each `DNSProviderConfig` carries its `ID` as the bucket key.

- [ ] **Step 3: Write the roundtrip test**

```go
func TestBackup_DNSProviders_Roundtrip(t *testing.T) {
	src := newStoreForTest(t)
	ctx := context.Background()
	_, _ = src.CreateDNSProvider(ctx, storage.DNSProviderConfig{Label: "A", Type: "ovh", Endpoint: "ovh-eu", ApplicationKey: "k", ApplicationSecret: "s", ConsumerKey: "c"})
	_, _ = src.CreateDNSProvider(ctx, storage.DNSProviderConfig{Label: "B", Type: "ovh", Endpoint: "ovh-ca", ApplicationKey: "k2", ApplicationSecret: "s2", ConsumerKey: "c2"})

	snap, err := Export(ctx, src, /*users*/nil, "v2.11.0", true)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(snap.DNSProviders) != 2 {
		t.Fatalf("exported %d providers, want 2", len(snap.DNSProviders))
	}

	dst := newStoreForTest(t)
	if _, err := Import(ctx, dst, /*users*/nil, snap); err != nil {
		t.Fatalf("Import: %v", err)
	}
	list, _ := dst.ListDNSProviders(ctx)
	if len(list) != 2 {
		t.Errorf("imported %d providers, want 2", len(list))
	}
}
```

> Match the real `Export`/`Import` signatures (the users param, return types) — grep the package.

- [ ] **Step 4: Run to verify RED then GREEN after edits**

Run: `go test ./internal/backup/ -run TestBackup_DNSProviders_Roundtrip -v`
Then the whole package: `go test ./internal/backup/ 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/backup/export.go internal/backup/import.go internal/backup/export_test.go internal/backup/import_test.go
git commit -m "feat(backup): DNS providers export/import as a collection"
```

---

### Task 1f: Full backend verification + empirical smoke

**Files:** none (verification only).

- [ ] **Step 1: Full suite + vet + staticcheck**

Run:
```bash
go build ./... && go vet ./... && go test ./... 2>&1 | tail -30
```
Expected: all PASS, no vet warnings. (Run `staticcheck ./...` if installed.)

- [ ] **Step 2: Empirical smoke — migration from a pre-v2.11 DB**

Build, seed a legacy DB (or reuse a real one), boot, and confirm migration via HTTP:

```bash
go build -o /tmp/arenet-smoke ./cmd/arenet
DD=$(mktemp -d)
# (If you have a v2.10.x data dir with an OVH config, copy it into $DD first.)
ARENET_HIBP_DISABLED=true ARENET_ADMIN_BIND=127.0.0.1:8001 /tmp/arenet-smoke --dev --data-dir "$DD" >/tmp/smoke.log 2>&1 &
sleep 2
grep -i "migrated legacy OVH" /tmp/smoke.log || echo "(fresh install: no migration expected)"
```

- [ ] **Step 3: Empirical smoke — CRUD via curl**

After completing /setup to get a session cookie (or reuse the setup token flow), exercise:

```bash
# create two providers
curl -s -b cookies -X POST http://127.0.0.1:8001/api/v1/settings/dns-providers \
  -H 'Content-Type: application/json' \
  -d '{"label":"OVH perso","type":"ovh","endpoint":"ovh-eu","applicationKey":"ak","applicationSecret":"as","consumerKey":"ck"}'
curl -s -b cookies -X POST http://127.0.0.1:8001/api/v1/settings/dns-providers \
  -H 'Content-Type: application/json' \
  -d '{"label":"OVH pro","type":"ovh","endpoint":"ovh-ca","applicationKey":"ak2","applicationSecret":"as2","consumerKey":"ck2"}'
# list — verify 2 entries, secrets absent, configured:true
curl -s -b cookies http://127.0.0.1:8001/api/v1/settings/dns-providers | python3 -m json.tool
```
Expected: 2 entries, no secret fields, `configured: true`, `usedBy: []`.

- [ ] **Step 4: Empirical smoke — delete-in-use 409**

Create a managed domain referencing a provider (via the managed-domains endpoint with `providerId`), then attempt to delete that provider:
```bash
curl -s -o /dev/null -w "%{http_code}\n" -b cookies -X DELETE http://127.0.0.1:8001/api/v1/settings/dns-providers/<id>
```
Expected: `409`.

- [ ] **Step 5: Clean up smoke processes/dirs**

```bash
pkill -f arenet-smoke; rm -rf /tmp/arenet-smoke /tmp/smoke.log "$DD" cookies
```

- [ ] **Step 6: Tag readiness note**

Backend complete. Do NOT tag from this plan — tagging `v2.11.0` on `main` happens after the PR is merged (per the workstream's tag-after-merge policy). Record the smoke results in the PR description.

---

## Self-Review

- **Spec coverage**: §3.1 data model → Tasks 1a/1b; §3.2 storage → 1a; §3.3 migration → 1b; §3.4 API → 1c; §3.5 backup → 1e; caddymgr dispatch (§1 state + manager.go:2230) → 1d. i18n §3.7 and frontend §3.6 are **Plan 2** (out of scope here, by design). ✓
- **Placeholder scan**: no TBD/TODO; every code step shows the code. The two "confirm helper name" notes are verification instructions, not placeholders — the code is present and correct against the current signatures read during planning. ✓
- **Type consistency**: `DNSProviderConfig{ID,Label,Type,...}`, `ManagedDomain.ProviderID`, `ListDNSProviders`, `GetDNSProvider`, `CreateDNSProvider`, `UpdateDNSProvider`, `DeleteDNSProvider`, `ErrProviderInUse`, `MigrateLegacyDNSProvider`, `buildOpts.DNSProviders map[string]…`, `dnsProviderView` — used identically across tasks. ✓
- **Sequencing note**: the `Provider`→`ProviderID` rename (Task 1b Step 1) must land before Task 1a Step 6 compiles (it references `md.ProviderID`). Do 1b-Step-1 first, then 1a. Flagged inline in 1a Step 6.
