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

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// Step J.4 — DNS-01 ACME provider configuration, instance-level (one
// per Arenet, not per route). v1.0 supports OVH only; the storage
// key is fixed at "ovh" so the lookup is shape-compatible with a
// future multi-provider extension that would key by provider name.
//
// The three Key/Secret fields are SECRETS — stored verbatim (not
// hashed) because Arenet must present them to the OVH HTTP API at
// every ACME renewal. The at-rest threat model (§5.4) is the BoltDB
// file's POSIX permissions: the operator owns the file 0o600 and is
// responsible for not making it world-readable. At-rest encryption
// of the BoltDB file is out of scope v1.0 (backlog item).
//
// Redaction discipline mirrors Step I.5 BasicAuthPasswordHash:
//   - API GET responses emit the three secrets as empty strings
//     (see internal/api). A single config-level `configured: bool`
//     flag tells the UI whether all three are non-empty in storage.
//   - Audit `dns_provider_updated` event emits the three secrets as
//     empty strings in BeforeJSON / AfterJSON.
//   - No slog call ever logs the struct whole; callers must strip.
type DNSProviderConfig struct {
	ID                string `json:"id"`
	Label             string `json:"label"`
	Type              string `json:"type"` // one of DNSProviderTypes
	Endpoint          string `json:"endpoint"`
	ApplicationKey    string `json:"application_key"`    // SECRET — never echoed by the API or audit
	ApplicationSecret string `json:"application_secret"` // SECRET — never echoed by the API or audit
	ConsumerKey       string `json:"consumer_key"`       // SECRET — never echoed by the API or audit
}

// DNSProviderTypeOVH is the only provider type wired in v1. The
// closed enum below is the forward-compat extension point for
// cloudflare / route53.
const DNSProviderTypeOVH = "ovh"

// DNSProviderTypes is the closed set of accepted Type values.
var DNSProviderTypes = []string{DNSProviderTypeOVH}

// OVHEndpoints lists the seven endpoint identifiers accepted by the
// go-ovh SDK (see github.com/ovh/go-ovh@v1.7.0/ovh/ovh.go:40-48).
// Treated as a hard enum at the API layer; raw endpoint URLs (also
// accepted by go-ovh) are a backlog item.
var OVHEndpoints = []string{
	"ovh-eu",
	"ovh-ca",
	"ovh-us",
	"kimsufi-eu",
	"kimsufi-ca",
	"soyoustart-eu",
	"soyoustart-ca",
}

// validate runs the strict last-line-of-defence checks on a
// DNSProviderConfig. The API layer is expected to handle the
// preserve-on-edit secret semantics BEFORE this function runs;
// storage only sees the final to-be-persisted row. A row reaching
// validate with any of the four fields blank is a programming error
// and is rejected here.
//
// Pure grid — no mutation, identical pattern to Route.validate /
// HealthCheck.validate (Step J.1, J.2).
// ValidateDNSProvider is the Step K.3 exported shim — internal/backup
// re-validates the snapshot's DNS provider before commit.
func ValidateDNSProvider(c DNSProviderConfig) error {
	return c.validate()
}

func (c *DNSProviderConfig) validate() error {
	if c.Label == "" {
		return errors.New("dns_provider: label must not be empty")
	}
	typeOK := false
	for _, t := range DNSProviderTypes {
		if c.Type == t {
			typeOK = true
			break
		}
	}
	if !typeOK {
		return fmt.Errorf("dns_provider: type %q is not a recognised provider type", c.Type)
	}
	if c.Endpoint == "" {
		return errors.New("dns_provider: endpoint must not be empty")
	}
	ok := false
	for _, e := range OVHEndpoints {
		if c.Endpoint == e {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("dns_provider: endpoint %q is not a recognised OVH region", c.Endpoint)
	}
	if c.ApplicationKey == "" {
		return errors.New("dns_provider: application_key must not be empty")
	}
	if c.ApplicationSecret == "" {
		return errors.New("dns_provider: application_secret must not be empty")
	}
	if c.ConsumerKey == "" {
		return errors.New("dns_provider: consumer_key must not be empty")
	}
	return nil
}

// ListDNSProviders returns all configured providers, unordered
// (bbolt iteration order). The API/frontend sorts by Label.
func (s *Store) ListDNSProviders(ctx context.Context) ([]DNSProviderConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	out := []DNSProviderConfig{}
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketDNSProviders))
		return b.ForEach(func(_, raw []byte) error {
			var c DNSProviderConfig
			if err := json.Unmarshal(raw, &c); err != nil {
				return fmt.Errorf("unmarshal dns provider: %w", err)
			}
			out = append(out, c)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetDNSProvider returns the provider with the given id, or
// ErrNotFound.
func (s *Store) GetDNSProvider(ctx context.Context, id string) (DNSProviderConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out DNSProviderConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketDNSProviders)).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return DNSProviderConfig{}, err
	}
	return out, nil
}

// CreateDNSProvider assigns a fresh UUID, validates, and persists.
func (s *Store) CreateDNSProvider(ctx context.Context, c DNSProviderConfig) (DNSProviderConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	c.ID = uuid.NewString()
	if c.Type == "" {
		c.Type = DNSProviderTypeOVH
	}
	if err := c.validate(); err != nil {
		return DNSProviderConfig{}, err
	}
	buf, err := json.Marshal(c)
	if err != nil {
		return DNSProviderConfig{}, fmt.Errorf("marshal dns provider: %w", err)
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketDNSProviders)).Put([]byte(c.ID), buf)
	})
	if err != nil {
		return DNSProviderConfig{}, err
	}
	return c, nil
}

// UpdateDNSProvider applies preserve-on-edit secret semantics: any of
// the three secret fields left blank in `c` keeps the stored value;
// a non-empty field replaces it. Label/Type/Endpoint always overwrite
// (Type falls back to the existing value only when left blank).
// Returns ErrNotFound if no provider has the given id.
func (s *Store) UpdateDNSProvider(ctx context.Context, id string, c DNSProviderConfig) (DNSProviderConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out DNSProviderConfig
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketDNSProviders))
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var existing DNSProviderConfig
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("unmarshal dns provider: %w", err)
		}
		merged := c
		merged.ID = id
		if merged.ApplicationKey == "" {
			merged.ApplicationKey = existing.ApplicationKey
		}
		if merged.ApplicationSecret == "" {
			merged.ApplicationSecret = existing.ApplicationSecret
		}
		if merged.ConsumerKey == "" {
			merged.ConsumerKey = existing.ConsumerKey
		}
		if merged.Type == "" {
			merged.Type = existing.Type
		}
		if err := merged.validate(); err != nil {
			return err
		}
		buf, err := json.Marshal(merged)
		if err != nil {
			return fmt.Errorf("marshal dns provider: %w", err)
		}
		out = merged
		return b.Put([]byte(id), buf)
	})
	if err != nil {
		return DNSProviderConfig{}, err
	}
	return out, nil
}

// DeleteDNSProvider removes the provider, but only if no managed
// domain references it. Returns ErrProviderInUse otherwise,
// ErrNotFound if the id doesn't exist.
func (s *Store) DeleteDNSProvider(ctx context.Context, id string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	mds, err := s.ListManagedDomains(ctx)
	if err != nil {
		return err
	}
	for _, md := range mds {
		if md.ProviderID == id {
			return ErrProviderInUse
		}
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketDNSProviders))
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}
