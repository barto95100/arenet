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
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Step V.4 — server geographic position persistence. Single row
// keyed "default" inside bucketServerPosition (mirror of the
// OIDC config + DNS provider conventions). One row per Arenet
// instance; future multi-instance / multi-region deployments
// can switch to a multi-key bucket without a schema rewrite.
//
// The persisted record drives boot behavior: a manual override
// wins over auto-detection so an operator's choice survives a
// restart, and a successful auto-detect opportunistically
// persists so the next boot can skip the ipify call if the
// network is briefly unreliable (the cached row is still a
// reasonable map center).

// ServerPositionRecord is the storage-flat shape of one
// persisted position. Field-for-field parallel of
// geo.ServerPosition — declared here so the storage package
// does not depend on internal/geo. cmd/arenet bridges between
// the two via thin translators in main.go (same pattern as the
// waf / throttle / decision adapters).
type ServerPositionRecord struct {
	Lat        float64   `json:"lat"`
	Lon        float64   `json:"lon"`
	City       string    `json:"city"`
	Country    string    `json:"country"`
	Mode       string    `json:"mode"`     // "auto" | "manual"
	SourceIP   string    `json:"sourceIp"` // populated when Mode=="auto"
	DetectedAt time.Time `json:"detectedAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// serverPositionKey is the single-row key inside
// bucketServerPosition. Forward-compat shape: future
// multi-region deployments can switch to a per-region key
// (e.g. "eu-west", "us-east") without renaming the bucket.
const serverPositionKey = "default"

// GetServerPosition returns the single persisted server-
// position row, or ErrNotFound when no row exists (fresh
// install — cmd/arenet falls back to V.1's
// DetectFromPublicIP path on first boot).
//
// Pure read; safe to call concurrently with writes (BoltDB's
// MVCC handles the consistency).
func (s *Store) GetServerPosition(ctx context.Context) (ServerPositionRecord, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out ServerPositionRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketServerPosition)).Get([]byte(serverPositionKey))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return ServerPositionRecord{}, err
	}
	return out, nil
}

// PutServerPosition persists / replaces the server-position
// row. UpdatedAt is always refreshed; DetectedAt is preserved
// from the caller (it's the time the position was MEASURED,
// not when it was WRITTEN, so the caller fills it).
//
// The caller is expected to:
//   - For manual overrides: set Mode="manual", SourceIP="",
//     DetectedAt=time.Now().
//   - For auto-detect results: set Mode="auto", SourceIP to
//     the ipify-returned address, DetectedAt to the moment
//     the lookup succeeded.
//
// Storage trusts the caller's field shape — validation lives
// at the api layer where 400s are returned to the operator.
func (s *Store) PutServerPosition(ctx context.Context, rec ServerPositionRecord) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	rec.UpdatedAt = time.Now().UTC()
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		buf, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshal server_position: %w", err)
		}
		return tx.Bucket([]byte(bucketServerPosition)).Put([]byte(serverPositionKey), buf)
	})
}

// DeleteServerPosition removes the persisted row. Forces
// auto-detect on the next boot. Not wired to an endpoint
// today (V.4 has no DELETE) but ships now so the storage
// surface is symmetric — a future "reset to auto-detect"
// admin action can call this without a schema migration.
func (s *Store) DeleteServerPosition(ctx context.Context) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketServerPosition)).Delete([]byte(serverPositionKey))
	})
}
