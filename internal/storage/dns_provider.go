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
	Endpoint          string `json:"endpoint"`
	ApplicationKey    string `json:"application_key"`    // SECRET — never echoed by the API or audit
	ApplicationSecret string `json:"application_secret"` // SECRET — never echoed by the API or audit
	ConsumerKey       string `json:"consumer_key"`       // SECRET — never echoed by the API or audit
}

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

// dnsProviderKeyOVH is the fixed bucket key under which the single
// OVH provider config lives. The bucket layout is "key → JSON blob"
// keyed by provider name, ready to accept additional providers in a
// later step without a schema rewrite.
const dnsProviderKeyOVH = "ovh"

// validate runs the strict last-line-of-defence checks on a
// DNSProviderConfig. The API layer is expected to handle the
// preserve-on-edit secret semantics BEFORE this function runs;
// storage only sees the final to-be-persisted row. A row reaching
// validate with any of the four fields blank is a programming error
// and is rejected here.
//
// Pure grid — no mutation, identical pattern to Route.validate /
// HealthCheck.validate (Step J.1, J.2).
func (c *DNSProviderConfig) validate() error {
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

// GetDNSProviderOVH returns the persisted OVH DNS provider
// configuration. Returns ErrNotFound when no row exists (fresh
// install) — callers MUST distinguish that case from a real I/O
// error so the UI can render the "not configured" status without a
// spurious 500.
func (s *Store) GetDNSProviderOVH(ctx context.Context) (DNSProviderConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out DNSProviderConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketDNSProviders))
		raw := b.Get([]byte(dnsProviderKeyOVH))
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

// DeleteDNSProviderOVH removes the persisted OVH DNS provider row.
// Returns nil on a fresh install (row already absent) — the call
// is idempotent so the API "PUT with all four fields blank"
// erasure path is safe to invoke without a prior existence check.
//
// Step J.4 §5.4 design: the recon described `delete = PUT with
// all fields blank`. The API layer (putDNSProviderOVH)
// distinguishes the "PUT with all four blank" erasure from the
// "PUT with some non-empty fields" merge-and-preserve path, and
// calls this method on the erasure path. There is no `DELETE`
// HTTP endpoint — the v1.0 lifecycle decision keeps the single
// PUT verb (§5.4 "no delete endpoint").
func (s *Store) DeleteDNSProviderOVH(ctx context.Context) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketDNSProviders))
		if b.Get([]byte(dnsProviderKeyOVH)) == nil {
			return nil
		}
		return b.Delete([]byte(dnsProviderKeyOVH))
	})
}

// PutDNSProviderOVH persists the OVH DNS provider configuration as
// the canonical row at key "ovh", overwriting any previous value
// (upsert). validate() runs first so a partial / malformed row is
// never written.
//
// Preserve-on-edit semantics — empty secret fields preserve the
// stored value — are the API layer's responsibility: this function
// trusts that the caller has merged the new payload with the
// existing row before passing the final config in. Storage is the
// final commit point, not the merge point (same separation Step I.5
// BasicAuth uses).
func (s *Store) PutDNSProviderOVH(ctx context.Context, c DNSProviderConfig) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := c.validate(); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		buf, err := json.Marshal(c)
		if err != nil {
			return fmt.Errorf("marshal dns provider: %w", err)
		}
		return tx.Bucket([]byte(bucketDNSProviders)).Put([]byte(dnsProviderKeyOVH), buf)
	})
}
