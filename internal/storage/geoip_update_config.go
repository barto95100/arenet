// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package storage

import (
	"context"
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// GeoIPUpdateConfig is the opt-in GeoIP auto-update scheduler settings
// row (a single row under a fixed key). Enabled defaults to false —
// Arenet makes no automatic GeoIP database refresh without the
// operator's explicit consent, mirroring UpdateCheckConfig.
// IntervalOverride is an optional Go-duration string; an empty value
// means "use the scheduler's default cadence". Kept separate from
// MaxMindConfig so the scheduler toggles independently of the
// credentials.
type GeoIPUpdateConfig struct {
	Enabled          bool   `json:"enabled"`
	IntervalOverride string `json:"intervalOverride"`
}

// geoIPUpdateKey is the fixed single-row key in bucketGeoIPUpdate (same
// singleton convention as update_check_config / oidc_config).
const geoIPUpdateKey = "config"

// GetGeoIPUpdateConfig returns the persisted config, or a zero-value
// config (Enabled=false) with a nil error on a fresh install — the
// scheduler relies on this to read "disabled" cleanly without
// special-casing ErrNotFound.
func (s *Store) GetGeoIPUpdateConfig(ctx context.Context) (GeoIPUpdateConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out GeoIPUpdateConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketGeoIPUpdate)).Get([]byte(geoIPUpdateKey))
		if raw == nil {
			return nil // fresh install → zero value (disabled)
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return GeoIPUpdateConfig{}, err
	}
	return out, nil
}

// PutGeoIPUpdateConfig upserts the singleton config.
func (s *Store) PutGeoIPUpdateConfig(ctx context.Context, c GeoIPUpdateConfig) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal geoip update config: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketGeoIPUpdate)).Put([]byte(geoIPUpdateKey), buf)
	})
}
