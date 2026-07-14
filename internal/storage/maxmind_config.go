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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Brick 2 Task 1 — MaxMind GeoIP account credentials, used by the
// geoipupdate client (Task 3) to download/refresh the local GeoIP2/
// GeoLite2 database. Single row, bucket "maxmind_config" keyed
// "default" — same convention as CrowdSecConfig.
//
// LicenseKey is a SECRET, same storage/at-rest boundary as
// CrowdSecConfig.APIKey: cleartext at-rest, file-perm boundary on
// the bbolt file. NEVER echoed by the GET path, NEVER in audit
// before/after, NEVER in slog.
type MaxMindConfig struct {
	// AccountID is the numeric MaxMind account ID
	// (https://www.maxmind.com/en/my_license_key). Required,
	// must be > 0.
	AccountID int `json:"account_id"`
	// LicenseKey is the MaxMind license key paired with
	// AccountID. SECRET — never echoed by the API GET path.
	LicenseKey string `json:"license_key"`
	// EditionID is the GeoIP database edition to download
	// (e.g. "GeoLite2-City", "GeoLite2-Country",
	// "GeoIP2-City"). Defaults to "GeoLite2-City" when left
	// blank.
	EditionID string `json:"edition_id"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const maxMindConfigKey = "default"

// defaultMaxMindEdition is the free-tier database used when the
// operator does not specify an EditionID.
const defaultMaxMindEdition = "GeoLite2-City"

// GetMaxMindConfig returns the single persisted MaxMind config row,
// or ErrNotFound when no row exists (fresh install / not yet
// configured).
func (s *Store) GetMaxMindConfig(ctx context.Context) (MaxMindConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out MaxMindConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketMaxMindConfig)).Get([]byte(maxMindConfigKey))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return MaxMindConfig{}, err
	}
	return out, nil
}

// PutMaxMindConfig persists / replaces the MaxMind config row.
//
// Preserve-on-edit secret semantics: an empty LicenseKey on the
// wire is merged with the previously stored value (the UI sends ""
// to mean "unchanged" since the SECRET is never echoed by the GET
// response). EditionID defaults to "GeoLite2-City" when blank.
// Validation runs AFTER the merge/default step, so a blank
// LicenseKey with nothing to inherit (fresh install) is rejected,
// as is AccountID <= 0. CreatedAt is preserved from the previous
// row when present; UpdatedAt is refreshed.
func (s *Store) PutMaxMindConfig(ctx context.Context, c MaxMindConfig) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	now := time.Now().UTC()
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketMaxMindConfig))

		var existing MaxMindConfig
		hasExisting := false
		if raw := b.Get([]byte(maxMindConfigKey)); raw != nil {
			if err := json.Unmarshal(raw, &existing); err == nil {
				hasExisting = true
			}
		}

		if c.LicenseKey == "" {
			c.LicenseKey = existing.LicenseKey
		}
		if c.EditionID == "" {
			c.EditionID = defaultMaxMindEdition
		}

		if c.AccountID <= 0 {
			return fmt.Errorf("maxmind_config: account_id must be > 0")
		}
		if c.LicenseKey == "" {
			return fmt.Errorf("maxmind_config: license_key must not be empty")
		}

		c.UpdatedAt = now
		if hasExisting && !existing.CreatedAt.IsZero() {
			c.CreatedAt = existing.CreatedAt
		} else {
			c.CreatedAt = now
		}

		buf, err := json.Marshal(c)
		if err != nil {
			return fmt.Errorf("marshal maxmind_config: %w", err)
		}
		return b.Put([]byte(maxMindConfigKey), buf)
	})
}

// DeleteMaxMindConfig removes the persisted MaxMind config row.
// Returns nil on a fresh install (row already absent) — idempotent
// so callers don't need a prior existence check.
func (s *Store) DeleteMaxMindConfig(ctx context.Context) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketMaxMindConfig))
		if b.Get([]byte(maxMindConfigKey)) == nil {
			return nil
		}
		return b.Delete([]byte(maxMindConfigKey))
	})
}

// MaxMindConfigEverConfigured reports whether the MaxMind config
// bucket has ever held a row. Errors are surfaced (not swallowed)
// so callers can decide how to treat a storage failure distinctly
// from "never configured".
func (s *Store) MaxMindConfigEverConfigured(ctx context.Context) (bool, error) {
	_, err := s.GetMaxMindConfig(ctx)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return false, err
}
