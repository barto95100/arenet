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
	"slices"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// DNSProviderConfig is one DNS-01 ACME provider account. Step J.4
// introduced it as an OVH-only singleton; v2.11 made it a UUID-keyed
// collection; v2.26 made it multi-type: Type selects a registry entry
// (dns_provider_types.go) and Credentials holds that type's fields,
// keyed by their Caddy JSON key.
//
// Secret credential values are stored verbatim (not hashed) because
// Arenet must present them to the provider API at every ACME renewal.
// The at-rest threat model is the BoltDB file's POSIX permissions
// (0o600); at-rest encryption is a backlog item.
//
// Redaction discipline (registry-driven, see Field.Secret):
//   - API views never carry secret values, only a per-key "set" flag.
//   - Audit rows use WithoutSecrets.
//   - Backup exports replace each secret value with the sentinel.
//   - No slog call ever logs the struct whole; callers must strip.
type DNSProviderConfig struct {
	ID          string            `json:"id"`
	Label       string            `json:"label"`
	Type        string            `json:"type"` // a registry Type
	Credentials map[string]string `json:"credentials"`
}

// legacyDNSProviderConfig is the pre-v2.26 on-disk shape: the OVH
// credentials were flat fields. Kept only for decoding.
type legacyDNSProviderConfig struct {
	ID                string            `json:"id"`
	Label             string            `json:"label"`
	Type              string            `json:"type"`
	Credentials       map[string]string `json:"credentials"`
	Endpoint          string            `json:"endpoint"`
	ApplicationKey    string            `json:"application_key"`
	ApplicationSecret string            `json:"application_secret"`
	ConsumerKey       string            `json:"consumer_key"`
}

// UnmarshalJSON decodes both the current shape and the pre-v2.26 flat
// OVH shape, folding the legacy fields into Credentials (an existing
// Credentials entry wins). This single decode path covers BoltDB rows
// written by older versions, pre-v2.26 backup snapshots, and the
// pre-v2.11 singleton migration. An empty Type decodes as OVH, the
// only type that existed before v2.26.
func (c *DNSProviderConfig) UnmarshalJSON(data []byte) error {
	var l legacyDNSProviderConfig
	if err := json.Unmarshal(data, &l); err != nil {
		return err
	}
	creds := l.Credentials
	if creds == nil {
		creds = map[string]string{}
	}
	for k, v := range map[string]string{
		ovhKeyEndpoint:          l.Endpoint,
		ovhKeyApplicationKey:    l.ApplicationKey,
		ovhKeyApplicationSecret: l.ApplicationSecret,
		ovhKeyConsumerKey:       l.ConsumerKey,
	} {
		if v == "" {
			continue
		}
		if _, exists := creds[k]; !exists {
			creds[k] = v
		}
	}
	if l.Type == "" {
		l.Type = DNSProviderTypeOVH
	}
	*c = DNSProviderConfig{ID: l.ID, Label: l.Label, Type: l.Type, Credentials: creds}
	return nil
}

// hasLegacyDNSProviderFields reports whether a raw stored row still
// carries any pre-v2.26 flat OVH key.
func hasLegacyDNSProviderFields(raw []byte) (bool, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return false, err
	}
	for _, k := range []string{ovhKeyEndpoint, ovhKeyApplicationKey, ovhKeyApplicationSecret, ovhKeyConsumerKey} {
		if _, ok := m[k]; ok {
			return true, nil
		}
	}
	return false, nil
}

// ValidateDNSProvider is the Step K.3 exported shim — internal/backup
// re-validates the snapshot's DNS providers before commit.
func ValidateDNSProvider(c DNSProviderConfig) error {
	return c.validate()
}

// normalize drops empty credential values so optional fields left blank
// are not emitted to Caddy nor stored.
func (c *DNSProviderConfig) normalize() {
	creds := make(map[string]string, len(c.Credentials))
	for k, v := range c.Credentials {
		if v != "" {
			creds[k] = v
		}
	}
	c.Credentials = creds
}

// validate runs the strict last-line-of-defence checks on the final
// to-be-persisted row (the API resolves preserve-on-edit before). It
// mirrors Caddy's strict module decoding: an undeclared credential key
// would fail caddy.Load, so it is rejected here.
func (c *DNSProviderConfig) validate() error {
	if c.Label == "" {
		return errors.New("dns_provider: label must not be empty")
	}
	pt, ok := DNSProviderTypeByName(c.Type)
	if !ok {
		return fmt.Errorf("dns_provider: type %q is not a recognised provider type", c.Type)
	}
	for k := range c.Credentials {
		if _, ok := pt.field(k); !ok {
			return fmt.Errorf("dns_provider: field %q is not valid for type %q", k, c.Type)
		}
	}
	for _, f := range pt.Fields {
		v := c.Credentials[f.Key]
		if v == "" {
			if f.Required {
				return fmt.Errorf("dns_provider: %s must not be empty", f.Key)
			}
			continue
		}
		if len(f.Enum) > 0 && !slices.Contains(f.Enum, v) {
			return fmt.Errorf("dns_provider: %s %q is not one of %v", f.Key, v, f.Enum)
		}
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
			if err := s.decodeRow(bucketDNSProviders, raw, &c); err != nil {
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
		return s.decodeRow(bucketDNSProviders, raw, &out)
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
	c.normalize()
	if err := c.validate(); err != nil {
		return DNSProviderConfig{}, err
	}
	buf, err := s.encodeRow(bucketDNSProviders, c)
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

// UpdateDNSProvider applies preserve-on-edit secret semantics: a secret
// credential left blank in `c` keeps the stored value when the type is
// unchanged; a non-empty value replaces it. Non-secret fields always
// overwrite. Changing the type preserves nothing (the keys no longer
// correspond). Type falls back to the existing value when left blank.
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
		if err := s.decodeRow(bucketDNSProviders, raw, &existing); err != nil {
			return fmt.Errorf("unmarshal dns provider: %w", err)
		}
		merged := c
		merged.ID = id
		if merged.Type == "" {
			merged.Type = existing.Type
		}
		merged.normalize()
		if merged.Type == existing.Type {
			for _, k := range SecretKeys(merged.Type) {
				if _, set := merged.Credentials[k]; !set && existing.Credentials[k] != "" {
					merged.Credentials[k] = existing.Credentials[k]
				}
			}
		}
		if err := merged.validate(); err != nil {
			return err
		}
		buf, err := s.encodeRow(bucketDNSProviders, merged)
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
