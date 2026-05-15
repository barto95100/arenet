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
	"sort"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// Route is a proxied virtual host served by Arenet.
type Route struct {
	ID          string    `json:"id"`
	Host        string    `json:"host"`
	UpstreamURL string    `json:"upstream_url"`
	TLSEnabled  bool      `json:"tls_enabled"`
	WAFEnabled  bool      `json:"waf_enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// validate checks the user-supplied fields of a Route.
func (r *Route) validate() error {
	if r.Host == "" {
		return errors.New("route: host must not be empty")
	}
	if r.UpstreamURL == "" {
		return errors.New("route: upstream_url must not be empty")
	}
	return nil
}

// CreateRoute persists a new Route. The ID, CreatedAt and UpdatedAt fields
// are assigned by the store and the populated Route is returned.
func (s *Store) CreateRoute(ctx context.Context, r Route) (Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := r.validate(); err != nil {
		return Route{}, err
	}

	now := time.Now().UTC()
	r.ID = uuid.NewString()
	r.CreatedAt = now
	r.UpdatedAt = now

	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketRoutes))
		buf, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal route: %w", err)
		}
		return b.Put([]byte(r.ID), buf)
	}); err != nil {
		return Route{}, err
	}
	return r, nil
}

// GetRoute returns the Route identified by id, or ErrNotFound.
func (s *Store) GetRoute(ctx context.Context, id string) (Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return Route{}, errors.New("route: id must not be empty")
	}

	var out Route
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketRoutes)).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return Route{}, err
	}
	return out, nil
}

// ListRoutes returns all stored routes, sorted by CreatedAt ascending.
func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out []Route
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketRoutes)).ForEach(func(_, v []byte) error {
			var r Route
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("unmarshal route: %w", err)
			}
			out = append(out, r)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// UpdateRoute replaces an existing Route. The CreatedAt timestamp is preserved
// from the stored record and UpdatedAt is refreshed.
func (s *Store) UpdateRoute(ctx context.Context, r Route) (Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if r.ID == "" {
		return Route{}, errors.New("route: id must not be empty")
	}
	if err := r.validate(); err != nil {
		return Route{}, err
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketRoutes))
		raw := b.Get([]byte(r.ID))
		if raw == nil {
			return ErrNotFound
		}
		var existing Route
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("unmarshal existing route: %w", err)
		}
		r.CreatedAt = existing.CreatedAt
		r.UpdatedAt = time.Now().UTC()
		buf, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal route: %w", err)
		}
		return b.Put([]byte(r.ID), buf)
	})
	if err != nil {
		return Route{}, err
	}
	return r, nil
}

// DeleteRoute removes the Route identified by id. Returns ErrNotFound if it
// does not exist.
func (s *Store) DeleteRoute(ctx context.Context, id string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return errors.New("route: id must not be empty")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketRoutes))
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}

// RestoreRoute re-inserts an existing Route exactly as supplied, preserving
// the provided ID, CreatedAt and UpdatedAt timestamps.
//
// This method exists ONLY for the rollback path of internal/api when a Caddy
// reload fails after a DELETE. It bypasses the normal CreateRoute lifecycle
// (no UUID generation, no timestamp refresh) precisely to make rollback
// fidelity possible. Do NOT use it for business logic — use CreateRoute or
// UpdateRoute.
//
// RestoreRoute is an unconditional upsert: if the key already exists it is
// overwritten without error. By design, the rollback always wins the
// conflict — this is safe under the current single-writer flow (bbolt
// serialises writes and the HTTP handler processes mutations sequentially).
// Revisit if real concurrency on routes is introduced later.
func (s *Store) RestoreRoute(ctx context.Context, r Route) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if r.ID == "" {
		return errors.New("route: id must not be empty")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		buf, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal route: %w", err)
		}
		return tx.Bucket([]byte(bucketRoutes)).Put([]byte(r.ID), buf)
	})
}
