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

package storage

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// migrateWAFEnabledToWAFMode is the Step I.4 boot migration.
//
// Pre-Step-I.4 routes were persisted with a `waf_enabled` bool;
// Step I.4 replaces that with a three-valued `waf_mode` string
// ("off" / "detect" / "block"). This one-shot read-modify-write
// converts every row and is safe to run on each boot — already-
// migrated rows (WAFMode non-empty) are left untouched.
//
// Mapping (decision L7 in Step I spec §1.3):
//
//   - WAFEnabled=true  → WAFMode="block"
//     The pre-I.4 semantic was "WAF on" = "block on every match",
//     so the equivalent post-migration value is the strict mode.
//
//   - WAFEnabled=false → WAFMode="off"
//
// Defaults for the other I.1-I.6 fields are NOT touched here: nil
// slices / maps and zero-value bools are valid wire shapes; the API
// layer's toResponse normalizes them on the way out. Earlier drafts
// of this migration set RedirectToHTTPS = TLSEnabled, but that was a
// spec-§6.1 mistake — RedirectToHTTPS is a user-facing toggle since
// Step I.1 and must not be auto-derived from another field.
//
// Idempotency: a route whose WAFMode is already populated (non-empty
// string) is left as-is, so re-running the migration on every boot
// after the first one is a no-op. This is essential for crash-safe
// upgrades: a partial run that's interrupted mid-bucket still
// produces a coherent state, and the next boot completes whatever
// rows were missed.
//
// Pattern (Step J.1 rewrite): passthrough via map[string]any rather
// than a full-Route round-trip. The original Step I.4 implementation
// did `Unmarshal -> Route -> mutate -> Marshal`, which silently drops
// any JSON key that no longer exists on the current Route struct.
// Once Step J.1 removed Route.UpstreamURL, that round-trip ate
// `upstream_url` on every pre-Step-J.1 row that Step I.4 touched,
// and the J.1 migration that ran next found nothing to migrate.
// The chained-migration test TestMigrate_ChainedOrder_WAFThenUpstream
// pins this regression. The fix is to read into map[string]any, set
// the new key, delete the old one, and re-marshal — every other key
// in the row passes through verbatim, regardless of whether the
// current Route struct knows about it. See backlog-step-j.md for
// the broader "full-Route round-trip migrations are fragile" debt.
func migrateWAFEnabledToWAFMode(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketRoutes))
		if b == nil {
			// Buckets are created by NewStore before this migration
			// runs; reaching this branch means a programming error.
			return nil
		}
		// Collect keys + new values first, then write inside the same
		// transaction. bbolt forbids modifying the bucket while a
		// cursor is open on it (Cursor.Next mid-Put has undefined
		// behavior), so we buffer the writes.
		type pending struct {
			key []byte
			val []byte
		}
		var writes []pending

		if err := b.ForEach(func(k, v []byte) error {
			// Decode into a generic map so every key in the stored
			// row is preserved verbatim — including fields the
			// current Route struct no longer carries (e.g. legacy
			// `upstream_url` which Step J.1 rewrites in its own
			// migration). The original full-Route round-trip ate
			// such fields silently; see the comment block above.
			var row map[string]any
			if err := json.Unmarshal(v, &row); err != nil {
				return fmt.Errorf("migrate route %s: unmarshal probe: %w", k, err)
			}
			if mode, ok := row["waf_mode"].(string); ok && mode != "" {
				return nil // already migrated; idempotent no-op
			}

			enabled, _ := row["waf_enabled"].(bool)
			if enabled {
				row["waf_mode"] = "block"
			} else {
				row["waf_mode"] = "off"
			}
			delete(row, "waf_enabled")

			buf, err := json.Marshal(row)
			if err != nil {
				return fmt.Errorf("migrate route %s: marshal: %w", k, err)
			}
			writes = append(writes, pending{key: append([]byte(nil), k...), val: buf})
			return nil
		}); err != nil {
			return err
		}

		for _, w := range writes {
			if err := b.Put(w.key, w.val); err != nil {
				return fmt.Errorf("migrate route %s: put: %w", w.key, err)
			}
		}
		return nil
	})
}

// migrateUpstreamURLToPool is the Step J.1 boot migration.
//
// Pre-Step-J.1 routes were persisted with a single `upstream_url`
// string; Step J.1 replaces that with an `upstreams` pool (one
// Upstream per backend) plus an `lb_policy` enum. This one-shot
// read-modify-write converts every row and is safe to run on each
// boot — already-migrated rows (Upstreams non-empty) are left
// untouched.
//
// Mapping (spec §5.1, §6.1):
//
//   - upstream_url: "X"   →  upstreams: [{url: "X", weight: 1}]
//   - lb_policy           →  "round_robin"
//   - upstream_url key    →  dropped (the post-J.1 Route struct has
//     no UpstreamURL field, so the full-route
//     re-marshal at the end naturally omits
//     it).
//
// Predicate is shape-based, same pattern as Step I.4 but inverted:
// "already migrated" means len(legacy.Upstreams) > 0 (the new field
// is present and non-empty); "needs migration" means
// legacy.UpstreamURL != "" AND len(legacy.Upstreams) == 0. A row
// with neither (a row a future Arenet wrote with a different shape,
// or a corrupted decode) is left alone — the predicate skips
// forward-compat unknowns rather than rewriting them.
//
// The bbolt two-phase write pattern from migrateWAFEnabledToWAFMode
// is reproduced verbatim: collect writes during ForEach, apply them
// after the cursor closes, in the same Update transaction. See the
// matching comment block above.
//
// Idempotency: a route whose Upstreams is already populated is left
// as-is, so re-running on every boot after the first is a no-op.
// Same crash-safety property as Step I.4: a run interrupted
// mid-bucket leaves the DB coherent and the next boot completes
// whatever rows were missed.
func migrateUpstreamURLToPool(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketRoutes))
		if b == nil {
			// Buckets are created by NewStore before this migration
			// runs; reaching this branch means a programming error.
			return nil
		}
		// Same two-phase pattern as migrateWAFEnabledToWAFMode: bbolt
		// forbids Put while a cursor is open on the bucket, so we
		// buffer the writes and apply them after the ForEach.
		type pending struct {
			key []byte
			val []byte
		}
		var writes []pending

		if err := b.ForEach(func(k, v []byte) error {
			// PASSTHROUGH-MAP per the backlog rule: this migration
			// was originally full-Route round-trip (the Step J spec
			// noted Step J only added fields). Step K.1 REMOVES the
			// legacy basic_auth_* keys from Route, so a full-Route
			// round-trip here would silently drop those keys before
			// K.1's migration ever reads them — exactly the I.4 → J.1
			// trap that justified the backlog rule. Refactored to
			// map[string]any for K.1's sake.
			var row map[string]any
			if err := json.Unmarshal(v, &row); err != nil {
				return fmt.Errorf("migrate route %s: unmarshal probe: %w", k, err)
			}
			// Already-migrated sentinel: upstreams array present + non-empty.
			if arr, ok := row["upstreams"].([]any); ok && len(arr) > 0 {
				return nil
			}
			legacyURL, _ := row["upstream_url"].(string)
			if legacyURL == "" {
				// Neither the legacy field nor the new pool — leave
				// the row untouched (forward-compat: a future Arenet
				// might have written a shape we don't recognise).
				return nil
			}

			row["upstreams"] = []map[string]any{
				{"url": legacyURL, "weight": 1},
			}
			row["lb_policy"] = LBPolicyRoundRobin
			delete(row, "upstream_url")

			buf, err := json.Marshal(row)
			if err != nil {
				return fmt.Errorf("migrate route %s: marshal: %w", k, err)
			}
			writes = append(writes, pending{key: append([]byte(nil), k...), val: buf})
			return nil
		}); err != nil {
			return err
		}

		for _, w := range writes {
			if err := b.Put(w.key, w.val); err != nil {
				return fmt.Errorf("migrate route %s: put: %w", w.key, err)
			}
		}
		return nil
	})
}

// migrateBasicAuthToAuthMode is the Step K.1 boot migration.
//
// Pre-Step-K routes carried three flat fields for Basic Auth:
// `basic_auth_enabled` (bool), `basic_auth_username` (string), and
// `basic_auth_password_hash` (string). Step K.1 replaces them with
// an explicit `auth_mode` enum + a nested `basic_auth` struct +
// an empty `forward_auth` struct (filled in by the forward_auth
// configuration UX, not by this migration).
//
// Mapping (spec §6.4):
//
//   - basic_auth_enabled: true  →  auth_mode: "basic", basic_auth.{username, password_hash} from legacy keys
//   - basic_auth_enabled: false →  auth_mode: "none", basic_auth: {} (empty values), forward_auth: {} (empty)
//   - legacy keys (basic_auth_enabled, basic_auth_username, basic_auth_password_hash) → dropped
//
// REMOVE-FIELDS migration → passthrough-map pattern is REQUIRED
// per the backlog rule (full-Route round-trip would silently
// eat any key the current Route struct doesn't carry). The post-
// K Route struct doesn't have BasicAuthEnabled / BasicAuthUsername
// / BasicAuthPasswordHash anymore — the round-trip would erase
// the legacy keys' values before this migration could read them.
// We use map[string]any verbatim.
//
// Predicate is shape-based: "already migrated" means `auth_mode`
// is a non-empty string in the stored row. "Needs migration"
// means the row has at least the legacy `basic_auth_enabled` key
// (or any of its siblings). A row with neither (a future Arenet
// wrote a different shape) is left alone.
func migrateBasicAuthToAuthMode(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketRoutes))
		if b == nil {
			return nil
		}
		type pending struct {
			key []byte
			val []byte
		}
		var writes []pending

		if err := b.ForEach(func(k, v []byte) error {
			var row map[string]any
			if err := json.Unmarshal(v, &row); err != nil {
				return fmt.Errorf("migrate route %s: unmarshal probe: %w", k, err)
			}
			if mode, ok := row["auth_mode"].(string); ok && mode != "" {
				return nil // already migrated; idempotent no-op
			}

			// Derive AuthMode from the legacy enabled bool. Missing
			// legacy keys (a row that wasn't on Step I.5 — pre-I.5)
			// produce auth_mode = "none", which is the correct
			// inherited default.
			enabled, _ := row["basic_auth_enabled"].(bool)
			username, _ := row["basic_auth_username"].(string)
			passwordHash, _ := row["basic_auth_password_hash"].(string)
			if enabled {
				row["auth_mode"] = RouteAuthBasic
				row["basic_auth"] = map[string]any{
					"username":      username,
					"password_hash": passwordHash,
				}
			} else {
				row["auth_mode"] = RouteAuthNone
				row["basic_auth"] = map[string]any{
					"username":      "",
					"password_hash": "",
				}
			}
			// Initialise forward_auth as zero-values so a migrated
			// row's JSON shape matches a post-K Route created via
			// the API. Empty provider_name means "no provider
			// referenced", correct for auth_mode in {none, basic}.
			row["forward_auth"] = map[string]any{
				"provider_name": "",
			}

			// Drop the three legacy keys.
			delete(row, "basic_auth_enabled")
			delete(row, "basic_auth_username")
			delete(row, "basic_auth_password_hash")

			buf, err := json.Marshal(row)
			if err != nil {
				return fmt.Errorf("migrate route %s: marshal: %w", k, err)
			}
			writes = append(writes, pending{key: append([]byte(nil), k...), val: buf})
			return nil
		}); err != nil {
			return err
		}

		for _, w := range writes {
			if err := b.Put(w.key, w.val); err != nil {
				return fmt.Errorf("migrate route %s: put: %w", w.key, err)
			}
		}
		return nil
	})
}
