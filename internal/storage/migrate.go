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
			// Peek at the JSON without committing to the full Route
			// type: we only need WAFEnabled (legacy) and WAFMode
			// (post-migration sentinel).
			var legacy struct {
				WAFEnabled bool   `json:"waf_enabled"`
				WAFMode    string `json:"waf_mode"`
			}
			if err := json.Unmarshal(v, &legacy); err != nil {
				return fmt.Errorf("migrate route %s: unmarshal probe: %w", k, err)
			}
			if legacy.WAFMode != "" {
				return nil // already migrated; idempotent no-op
			}

			// Full-route round-trip preserves every field — we don't
			// want to silently drop newer-than-this-codebase fields
			// that a future Arenet version might have written.
			var r Route
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("migrate route %s: unmarshal full: %w", k, err)
			}
			if legacy.WAFEnabled {
				r.WAFMode = "block"
			} else {
				r.WAFMode = "off"
			}
			buf, err := json.Marshal(r)
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
