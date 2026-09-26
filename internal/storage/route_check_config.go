// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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

const (
	bucketRouteCheck = "route_check"
	routeCheckKey    = "config"
)

// RouteCheckConfig toggles the post-apply check of routes (v2.35): a
// probe through Caddy after each save, with rollback of a change that
// broke a working route.
type RouteCheckConfig struct {
	Enabled bool `json:"enabled"`
}

// GetRouteCheckConfig returns the config; a fresh install (no row) has
// the check ENABLED — safe by default.
func (s *Store) GetRouteCheckConfig(ctx context.Context) (RouteCheckConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	out := RouteCheckConfig{Enabled: true}
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketRouteCheck)).Get([]byte(routeCheckKey))
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return RouteCheckConfig{}, err
	}
	return out, nil
}

// PutRouteCheckConfig stores the config.
func (s *Store) PutRouteCheckConfig(ctx context.Context, c RouteCheckConfig) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal route check config: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketRouteCheck)).Put([]byte(routeCheckKey), buf)
	})
}
