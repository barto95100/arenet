// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

// Package storage provides a BoltDB-backed persistence layer for Arenet.
package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bucket names used inside the BoltDB file.
const (
	bucketRoutes   = "routes"
	bucketUsers    = "users"
	bucketSessions = "sessions"
	bucketAudit    = "audit"
	// Step J.4 — instance-level DNS provider configurations, keyed
	// by provider name (v1.0: only "ovh"). Parallel to the existing
	// settings storage rather than mixed in, so the secret scan is
	// isolated. See dns_provider.go.
	bucketDNSProviders = "dns_providers"
	// Step K.1 — instance-level forward-auth provider configurations,
	// keyed by provider name (slug-shaped). See forward_auth_provider.go.
	bucketForwardAuthProviders = "forward_auth_providers"
	// Step K.2 — instance-level OIDC SSO config (single row,
	// keyed "default"). Future-proof for multi-IdP without a
	// schema rewrite. See oidc_config.go.
	bucketOIDCConfig = "oidc_config"
	// Step O.1 — instance-level wildcard-certificate managed-domain
	// declarations, keyed by apex (e.g. "example.com"). One row per
	// managed domain; multiple domains coexist (spec D6.A). See
	// managed_domain.go.
	bucketManagedDomains = "managed_domains"
	// Step P.1 — instance-level auto-classify (write-side LAPI)
	// configuration: the watcher credentials (machine-id + password)
	// + the per-category rule set. Single bucket, two keys
	// ("credentials" + "rules"). See automation_config.go.
	bucketAutomation = "automation"
	// Step V.4 — instance-level server geographic position
	// (where the Mercator is centered + the central pin is
	// placed on the /map page). Single row, keyed "default" —
	// same convention as bucketOIDCConfig. See
	// server_position.go.
	bucketServerPosition = "server_position"
	// Step CS.1 — instance-level CrowdSec bouncer config
	// (LAPI URL + API key + name + timeout). Single row,
	// keyed "default" — same convention as bucketOIDCConfig.
	// See crowdsec_config.go.
	bucketCrowdSecConfig = "crowdsec_config"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("storage: record not found")

// ErrConflict is returned when an operation would violate a
// uniqueness constraint at the storage layer (e.g. creating a
// ForwardAuthProvider with a Name that already exists).
var ErrConflict = errors.New("storage: conflict")

// Store is the BoltDB-backed persistence layer for Arenet.
type Store struct {
	db *bolt.DB
}

// NewStore opens (or creates) a BoltDB database at dbPath and ensures
// all required buckets exist.
func NewStore(dbPath string) (*Store, error) {
	if dbPath == "" {
		return nil, errors.New("storage: dbPath must not be empty")
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("storage: create data dir: %w", err)
	}

	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("storage: open bbolt %q: %w", dbPath, err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{
			[]byte(bucketRoutes),               // Step B/C
			[]byte(bucketUsers),                // Step D
			[]byte(bucketSessions),             // Step D
			[]byte(bucketAudit),                // Step D
			[]byte(bucketDNSProviders),         // Step J.4
			[]byte(bucketForwardAuthProviders), // Step K.1
			[]byte(bucketOIDCConfig),           // Step K.2
			[]byte(bucketManagedDomains),       // Step O.1
			[]byte(bucketAutomation),           // Step P.1
			[]byte(bucketServerPosition),       // Step V.4
			[]byte(bucketCrowdSecConfig),       // Step CS.1
		} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("create bucket %q: %w", name, err)
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: init buckets: %w", err)
	}

	// Step I.4 boot migration: convert pre-I.4 routes' WAFEnabled
	// bool into the new WAFMode string enum. Runs idempotently —
	// already-migrated rows are left as-is, so re-running on every
	// boot after the first is a cheap no-op.
	if err := migrateWAFEnabledToWAFMode(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: migrate route schema: %w", err)
	}

	// Step J.1 boot migration: convert pre-J.1 routes' UpstreamURL
	// string into the new Upstreams pool + LBPolicy enum. Same
	// shape-based idempotency as Step I.4 (sentinel: Upstreams
	// non-empty ⇒ already migrated).
	//
	// ORDER MATTERS — DO NOT REORDER: migrateUpstreamURLToPool MUST
	// run AFTER migrateWAFEnabledToWAFMode. The J.1 migration does a
	// full-Route round-trip through json.Unmarshal, which silently
	// drops every key absent from the current Route struct — including
	// the legacy `waf_enabled` field that Step I.4 still needs to read.
	// If J.1 ran first on a doubly-legacy row (waf_enabled + upstream_url,
	// no waf_mode + no upstreams), the re-marshal would drop waf_enabled
	// before Step I.4 ever saw it, leaving waf_mode silently set to "off"
	// — i.e. the WAF would be turned off without anyone noticing. The
	// chained-migration test in migrate_test.go pins this ordering.
	if err := migrateUpstreamURLToPool(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: migrate upstream pool: %w", err)
	}

	// Step K.1 boot migration: replace the flat BasicAuthEnabled /
	// BasicAuthUsername / BasicAuthPasswordHash fields with the
	// nested BasicAuth struct under a new AuthMode enum. Passthrough-
	// map per the backlog rule (this migration REMOVES legacy keys,
	// not just adds them).
	//
	// Ordering: runs LAST. Both I.4 (waf_enabled → waf_mode) and J.1
	// (upstream_url → upstreams pool) are pure restructurings of
	// different keys; this migration touches only the basic_auth_*
	// triplet, so the ordering is independent. Placed last for
	// chronological clarity.
	if err := migrateBasicAuthToAuthMode(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: migrate auth mode: %w", err)
	}

	// Step K.2 boot migration: add AuthSource + Role + OIDCSub
	// to every user row. Pure-additions migration on a different
	// bucket (users) — independent of the routes bucket
	// migrations above. Passthrough-map per §6 (defence-in-depth
	// for forward-compat across downgrade cycles).
	if err := migrateUsersAuthSourceAndRole(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: migrate users role: %w", err)
	}

	return &Store{db: db}, nil
}

// DB returns the underlying bbolt handle. Reserved for the auth and
// audit packages, which share the same database file per bbolt's
// single-writer constraint. Other consumers MUST NOT call this and
// MUST use the typed methods on Store.
func (s *Store) DB() *bolt.DB {
	return s.db
}

// Close releases the underlying BoltDB file.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// withTimeout returns ctx unchanged if it already has a deadline;
// otherwise it wraps it with a 5 second timeout to bound DB calls.
func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, 5*time.Second)
}
