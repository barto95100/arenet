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

// Step P.1 — auto-classify watcher credentials. Distinct from
// the Step N read-side bouncer API key (which lives outside the
// BoltDB, in env vars only): writes to LAPI require a watcher
// (machine_id + password) per CrowdSec's auth model — confirmed
// by source read at crowdsec@v1.6.3/pkg/apiserver/controllers/
// controller.go:115-129 (write endpoints under jwtAuth, not
// apiKeyAuth). Spec P D1.A locks the dedicated-watcher path.
//
// SECRECY: same J.4 discipline as DNSProviderConfig. The
// Password field is the secret — emitted as "" by the API
// GET; preserve-on-edit on PUT (empty submit keeps the stored
// value); never logged whole; audit BeforeJSON/AfterJSON
// blank the field via watcherCredentialsForAudit (API layer).
type WatcherCredentials struct {
	// LAPIURL is the CrowdSec LAPI base URL (e.g.
	// http://127.0.0.1:8080/). May reuse the same URL as the
	// read-side bouncer config, but stored separately so the
	// operator can point the write surface at a different
	// LAPI host (rare; for HA setups).
	LAPIURL string `json:"lapi_url"`
	// MachineID is the cscli-issued watcher identifier
	// (from `cscli machines add arenet-writer`). Non-secret
	// in the sense that it doesn't authenticate alone, but
	// not echoed in logs anyway for cleanliness.
	MachineID string `json:"machine_id"`
	// Password is the secret half of the watcher credential.
	// Never echoed by GET; preserve-on-edit on PUT; redacted
	// in audit.
	Password string `json:"password"`
}

// automationKeyCredentials is the BoltDB key for the single
// watcher credentials row. One credential set per Arenet
// instance.
const automationKeyCredentials = "credentials"

// automationKeyRules is the BoltDB key for the auto-classify
// rule set. The value is stored as an opaque JSON blob so
// storage doesn't depend on internal/automation (would invert
// the dependency direction documented in spec §3.9). The API
// layer + main.go marshal/unmarshal automation.RuleSet.
const automationKeyRules = "rules"

// validate runs strict last-line-of-defence shape checks on
// WatcherCredentials. The API layer handles the preserve-on-
// edit merge BEFORE this function — by the time validate runs
// the row is the final to-be-persisted shape. A row reaching
// validate with any of the three fields blank is a programming
// error.
func (c *WatcherCredentials) validate() error {
	if c.LAPIURL == "" {
		return errors.New("watcher_credentials: lapi_url must not be empty")
	}
	if c.MachineID == "" {
		return errors.New("watcher_credentials: machine_id must not be empty")
	}
	if c.Password == "" {
		return errors.New("watcher_credentials: password must not be empty")
	}
	return nil
}

// ValidateWatcherCredentials is the exported shim for callers
// outside this package that need the validation rule without
// hitting the BoltDB write path. Same pattern as
// ValidateDNSProvider.
func ValidateWatcherCredentials(c WatcherCredentials) error {
	return c.validate()
}

// WatcherCredentialsConfigured reports whether all three fields
// of the watcher credentials are non-empty — the bar for
// considering the auto-classify trigger engine "ready to run".
// Mirrors dnsProviderConfigured (J.4).
func WatcherCredentialsConfigured(c WatcherCredentials) bool {
	return c.LAPIURL != "" && c.MachineID != "" && c.Password != ""
}

// GetWatcherCredentials reads the persisted watcher credentials
// row. Returns ErrNotFound on fresh install — callers MUST
// distinguish that case from a real I/O error (the API layer
// renders the "not configured" status without a spurious 500).
func (s *Store) GetWatcherCredentials(ctx context.Context) (WatcherCredentials, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out WatcherCredentials
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketAutomation))
		raw := b.Get([]byte(automationKeyCredentials))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return WatcherCredentials{}, err
	}
	return out, nil
}

// PutWatcherCredentials persists the watcher credentials. The
// validator runs first; a partial / malformed row is never
// written.
//
// Preserve-on-edit semantics — empty Password field preserves
// the stored value — are the API layer's responsibility: this
// function trusts the caller has merged the new payload with
// the existing row. Storage is the commit point, not the merge
// point (same separation as DNS-provider / OIDC config).
func (s *Store) PutWatcherCredentials(ctx context.Context, c WatcherCredentials) error {
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
			return fmt.Errorf("marshal watcher_credentials: %w", err)
		}
		return tx.Bucket([]byte(bucketAutomation)).Put([]byte(automationKeyCredentials), buf)
	})
}

// DeleteWatcherCredentials removes the persisted watcher
// credentials row. Idempotent — returns nil if the row is
// absent (operator's "erase all" path on PUT-all-blank, same
// shape as DeleteDNSProviderOVH).
func (s *Store) DeleteWatcherCredentials(ctx context.Context) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketAutomation))
		if b.Get([]byte(automationKeyCredentials)) == nil {
			return nil
		}
		return b.Delete([]byte(automationKeyCredentials))
	})
}

// GetAutomationRulesRaw returns the persisted rule-set as
// raw JSON bytes. ErrNotFound on fresh install — the caller
// (API layer + main.go) materialises automation.DefaultRuleSet()
// in that case rather than seeding a "default" row at bucket
// init (avoids drift: the default value lives in one place,
// internal/automation/rules.go).
//
// Storage holds the JSON blob opaquely — does NOT import
// internal/automation (would invert the dependency direction
// documented in spec §3.9: automation → storage, not the
// reverse). The blob shape MUST match automation.RuleSet's
// MarshalJSON; the API layer + boot wiring enforce that via
// type-aware decode at the consumption point.
func (s *Store) GetAutomationRulesRaw(ctx context.Context) (json.RawMessage, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out json.RawMessage
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketAutomation))
		raw := b.Get([]byte(automationKeyRules))
		if raw == nil {
			return ErrNotFound
		}
		// Copy: BoltDB-owned bytes are invalidated after the
		// txn ends. Tests caught this once on a different
		// bucket; the discipline applies here too.
		out = append(out, raw...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PutAutomationRulesRaw persists the rule-set as opaque JSON.
// The caller has already validated the parsed RuleSet (via
// automation.RuleSet.Validate); storage's role is the commit
// point. Empty / malformed JSON is rejected with a shape
// check (must be non-empty + start with `{`).
func (s *Store) PutAutomationRulesRaw(ctx context.Context, raw json.RawMessage) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if len(raw) == 0 {
		return errors.New("automation_rules: payload must not be empty")
	}
	// Defensive shape check — must look like a JSON object
	// to catch a programming error where the caller passed
	// a stringified value or a bare array.
	if raw[0] != '{' {
		return fmt.Errorf("automation_rules: payload must be a JSON object (starts with '{'), got first byte %q", raw[0])
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Copy to a fresh slice — the caller's RawMessage may
		// be backed by a temporary buffer; we want to own the
		// bytes we persist.
		buf := make([]byte, len(raw))
		copy(buf, raw)
		return tx.Bucket([]byte(bucketAutomation)).Put([]byte(automationKeyRules), buf)
	})
}

// DeleteAutomationRulesRaw removes the persisted rule-set
// row. Idempotent (no-op when absent). Operator-facing
// "reset to defaults" path; the next GetAutomationRulesRaw
// returns ErrNotFound and the API layer seeds
// automation.DefaultRuleSet().
func (s *Store) DeleteAutomationRulesRaw(ctx context.Context) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketAutomation))
		if b.Get([]byte(automationKeyRules)) == nil {
			return nil
		}
		return b.Delete([]byte(automationKeyRules))
	})
}
