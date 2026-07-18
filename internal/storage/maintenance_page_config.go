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

	bolt "go.etcd.io/bbolt"
)

// MaintenancePageConfig is the single global HTML template served on
// maintenance 503s. Empty HTML = serve the branded default. Singleton,
// same convention as GeoIPUpdateConfig / update_check_config.
type MaintenancePageConfig struct {
	HTML string `json:"html,omitempty"`
	// Message is the global operator-authored line rendered inside the
	// maintenance 503 body via the {arenet.maintenance.message}
	// placeholder (v2.18.0). Stored verbatim (plain text) — it is
	// HTML-escaped at emission, not here, so a message can't inject
	// markup into every route's 503. Empty = the built-in default's
	// generic sentence stands alone. omitempty keeps pre-v2.18.0 rows
	// migration-free.
	Message string `json:"message,omitempty"`
}

// maintenancePageKey is the fixed single-row key in
// bucketMaintenancePage (same singleton convention as geoIPUpdateKey).
const maintenancePageKey = "config"

// GetMaintenancePageConfig returns the persisted page, or a zero value
// (empty HTML) with nil error on a fresh install — callers serve the
// branded default when HTML is empty.
func (s *Store) GetMaintenancePageConfig(ctx context.Context) (MaintenancePageConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	var out MaintenancePageConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketMaintenancePage)).Get([]byte(maintenancePageKey))
		if raw == nil {
			return nil // fresh install → zero value (default)
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return MaintenancePageConfig{}, err
	}
	return out, nil
}

// PutMaintenancePageConfig upserts the singleton page.
func (s *Store) PutMaintenancePageConfig(ctx context.Context, c MaintenancePageConfig) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal maintenance page config: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketMaintenancePage)).Put([]byte(maintenancePageKey), buf)
	})
}
