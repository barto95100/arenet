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

// UpdateCheckConfig is the opt-in update-checker settings row (a single
// row under a fixed key). Enabled defaults to false — Arenet makes no
// external call to GitHub without the operator's explicit consent
// (v2.12.3 D1). IntervalOverride is an optional Go-duration string; an
// empty value means "use the env/default cadence".
type UpdateCheckConfig struct {
	Enabled          bool   `json:"enabled"`
	IntervalOverride string `json:"intervalOverride"`
}

// updateCheckKey is the fixed single-row key in bucketUpdateCheck (same
// singleton convention as oidc_config / crowdsec_config).
const updateCheckKey = "config"

// GetUpdateCheckConfig returns the persisted config, or a zero-value
// config (Enabled=false) with a nil error on a fresh install — the boot
// path relies on this to read "disabled" cleanly without special-casing
// ErrNotFound.
func (s *Store) GetUpdateCheckConfig(ctx context.Context) (UpdateCheckConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out UpdateCheckConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketUpdateCheck)).Get([]byte(updateCheckKey))
		if raw == nil {
			return nil // fresh install → zero value (disabled)
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return UpdateCheckConfig{}, err
	}
	return out, nil
}

// PutUpdateCheckConfig upserts the singleton config.
func (s *Store) PutUpdateCheckConfig(ctx context.Context, c UpdateCheckConfig) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal update check config: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketUpdateCheck)).Put([]byte(updateCheckKey), buf)
	})
}
