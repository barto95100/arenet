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
	"regexp"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Step K.1 — forward-auth provider configuration, instance-level.
// One row per provider, keyed by Name. Routes reference a provider
// by name (Route.ForwardAuth.ProviderName).
//
// The ClientSecret is the IdP-issued credential Arenet replays at
// every sub-request (when the IdP requires authenticated calls
// from the relying party). Treated as a SECRET on the same posture
// as Step J.4 DNS provider credentials and Step I.5 BasicAuth
// hashes — never echoed in API responses or audit log; stored
// cleartext in BoltDB (file-perm boundary).
//
// Kind drives the UI's per-kind presets / hints (e.g. Authelia's
// default verify URL, Authentik's typical scopes); the generator
// itself does NOT branch on Kind — the four fields (VerifyURL,
// AuthRequestURI, CopyHeaders, ClientSecret) are enough to emit
// the Caddy forward_auth subroute pattern for any of them.
type ForwardAuthProvider struct {
	Name           string    `json:"name"` // unique key, slug-shaped
	Kind           string    `json:"kind"` // "authelia"|"authentik"|"keycloak"|"generic"
	VerifyURL      string    `json:"verify_url"`
	AuthRequestURI string    `json:"auth_request_uri"`
	CopyHeaders    []string  `json:"copy_headers"`
	ClientSecret   string    `json:"client_secret"` // SECRET — never echoed by the API or audit
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ForwardAuthProviderKinds enumerates the four supported provider
// kinds at the storage layer. The API may add presentational
// metadata (default URLs, default copy headers per kind) on top,
// but the storage enum is the source of truth.
var ForwardAuthProviderKinds = []string{
	"authelia",
	"authentik",
	"keycloak",
	"generic",
}

// providerNameRE matches a slug-shaped provider name: lowercase
// alnum + dash, 1-32 chars. The API rejects anything else with a
// friendlier message; storage stays a pure grid.
var providerNameRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// validate runs the strict last-line-of-defence checks. Pure
// grid (no mutation), same pattern as DNSProviderConfig.validate
// and HealthCheck.validate.
func (p *ForwardAuthProvider) validate() error {
	if !providerNameRE.MatchString(p.Name) {
		return fmt.Errorf("forward_auth_provider: name %q must match %s", p.Name, providerNameRE.String())
	}
	ok := false
	for _, k := range ForwardAuthProviderKinds {
		if p.Kind == k {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("forward_auth_provider: kind %q is not a recognised provider kind", p.Kind)
	}
	if p.VerifyURL == "" {
		return errors.New("forward_auth_provider: verify_url must not be empty")
	}
	if p.AuthRequestURI == "" {
		return errors.New("forward_auth_provider: auth_request_uri must not be empty")
	}
	if p.AuthRequestURI[0] != '/' {
		return fmt.Errorf("forward_auth_provider: auth_request_uri %q must start with /", p.AuthRequestURI)
	}
	// CopyHeaders may be empty (some providers don't need any
	// headers copied — generic case). Per-header shape validation
	// (RFC 7230 token) lives at the API layer for friendlier
	// messages; storage trusts the API.
	// ClientSecret may be empty (a forward-auth provider that
	// doesn't require RP authentication, e.g. some basic Authelia
	// setups). The API layer documents this; storage stays
	// permissive.
	return nil
}

// CreateForwardAuthProvider persists a new provider. Returns
// ErrConflict if Name already exists (the routes-bucket pattern
// uses UUIDs to avoid this; provider Name is operator-supplied
// and uniqueness is meaningful).
func (s *Store) CreateForwardAuthProvider(ctx context.Context, p ForwardAuthProvider) (ForwardAuthProvider, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := p.validate(); err != nil {
		return ForwardAuthProvider{}, err
	}
	now := time.Now().UTC()
	p.CreatedAt = now
	p.UpdatedAt = now

	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketForwardAuthProviders))
		if existing := b.Get([]byte(p.Name)); existing != nil {
			return ErrConflict
		}
		buf, err := json.Marshal(p)
		if err != nil {
			return fmt.Errorf("marshal forward_auth_provider: %w", err)
		}
		return b.Put([]byte(p.Name), buf)
	})
	if err != nil {
		return ForwardAuthProvider{}, err
	}
	return p, nil
}

// GetForwardAuthProvider returns the provider keyed by name, or
// ErrNotFound.
func (s *Store) GetForwardAuthProvider(ctx context.Context, name string) (ForwardAuthProvider, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if name == "" {
		return ForwardAuthProvider{}, errors.New("forward_auth_provider: name must not be empty")
	}
	var out ForwardAuthProvider
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketForwardAuthProviders)).Get([]byte(name))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return ForwardAuthProvider{}, err
	}
	return out, nil
}

// ListForwardAuthProviders returns every provider, sorted by
// CreatedAt ascending. Same shape as ListRoutes.
func (s *Store) ListForwardAuthProviders(ctx context.Context) ([]ForwardAuthProvider, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out []ForwardAuthProvider
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketForwardAuthProviders)).ForEach(func(_, v []byte) error {
			var p ForwardAuthProvider
			if err := json.Unmarshal(v, &p); err != nil {
				return fmt.Errorf("unmarshal forward_auth_provider: %w", err)
			}
			out = append(out, p)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// UpdateForwardAuthProvider replaces an existing provider keyed by
// Name. CreatedAt is preserved from the stored row; UpdatedAt is
// refreshed.
func (s *Store) UpdateForwardAuthProvider(ctx context.Context, p ForwardAuthProvider) (ForwardAuthProvider, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := p.validate(); err != nil {
		return ForwardAuthProvider{}, err
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketForwardAuthProviders))
		raw := b.Get([]byte(p.Name))
		if raw == nil {
			return ErrNotFound
		}
		var existing ForwardAuthProvider
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("unmarshal existing forward_auth_provider: %w", err)
		}
		p.CreatedAt = existing.CreatedAt
		p.UpdatedAt = time.Now().UTC()
		buf, err := json.Marshal(p)
		if err != nil {
			return fmt.Errorf("marshal forward_auth_provider: %w", err)
		}
		return b.Put([]byte(p.Name), buf)
	})
	if err != nil {
		return ForwardAuthProvider{}, err
	}
	return p, nil
}

// DeleteForwardAuthProvider removes a provider keyed by Name.
// Returns ErrNotFound if it does not exist.
//
// The reference-guarded delete contract is enforced at the API
// layer (which can list routes and produce the offending IDs in
// the 409 response per §1.3 decision 14). Storage exposes the
// raw delete; do not call this from a handler without the
// reference check first.
func (s *Store) DeleteForwardAuthProvider(ctx context.Context, name string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if name == "" {
		return errors.New("forward_auth_provider: name must not be empty")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketForwardAuthProviders))
		if b.Get([]byte(name)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(name))
	})
}
