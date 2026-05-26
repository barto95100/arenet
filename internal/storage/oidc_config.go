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
	"net/url"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Step K.2 — OIDC SSO instance-level configuration. Single row,
// bucket "oidc_config" keyed "default" (future-proof for multi-
// IdP without a schema rewrite — today only "default").
//
// The break-glass invariant (§1.3 decisions 4-6) means this
// config is NEVER consulted by the local-credential login path.
// Storing the config is purely a configuration surface; turning
// it on only enables the OIDC HANDLERS, never replaces local
// login.
//
// ClientSecret is a SECRET — replayed to the IdP on every token
// exchange. Stored verbatim (cleartext, file-perm boundary same
// as Step J.4 OVH credentials). Never echoed by the API GET path,
// never in audit before/after, never in slog.
type OIDCConfig struct {
	Enabled           bool                  `json:"enabled"`
	IssuerURL         string                `json:"issuer_url"`
	ClientID          string                `json:"client_id"`
	ClientSecret      string                `json:"client_secret"` // SECRET — never echoed
	Scopes            []string              `json:"scopes"`
	RedirectURL       string                `json:"redirect_url"`
	AllowedIdentities []OIDCAllowedIdentity `json:"allowed_identities"`
	CreatedAt         time.Time             `json:"created_at"`
	UpdatedAt         time.Time             `json:"updated_at"`
}

// OIDCAllowedIdentity is one entry in the allowlist
// (§1.3 decision 13 — identity-per-entry, keyed by email at
// create time + canonicalised to Sub post-login).
//
// Lifecycle:
//   - Operator invites by email (Sub == ""). Listed as
//     "Pending first login".
//   - First successful OIDC login for that email canonicalises
//     Sub (validated against the token's `email_verified == true`
//     guard — §5.2 Δ7). FirstLoginAt records the timestamp.
//   - Subsequent logins match by Sub directly (Email becomes a
//     cosmetic identifier).
type OIDCAllowedIdentity struct {
	Email        string    `json:"email"`         // operator-supplied, required, unique
	DisplayName  string    `json:"display_name"`  // operator-supplied, optional
	Sub          string    `json:"sub"`           // OIDC subject; empty before first login
	AddedAt      time.Time `json:"added_at"`
	FirstLoginAt time.Time `json:"first_login_at,omitempty"`
}

const oidcConfigKey = "default"

// validate runs the strict last-line-of-defence checks on an
// OIDCConfig. Empty IssuerURL / ClientID are accepted in the
// disabled state (a fresh-install row before the operator has
// configured anything). When Enabled is true, the four core
// fields must be populated.
func (c *OIDCConfig) validate() error {
	if !c.Enabled {
		// Disabled state: storage trusts the API to have provided
		// a coherent row, but doesn't enforce non-empty fields —
		// the operator may have configured the IdP partially then
		// flipped Enabled off temporarily.
		return nil
	}
	if c.IssuerURL == "" {
		return errors.New("oidc_config: issuer_url must not be empty when enabled")
	}
	u, err := url.Parse(c.IssuerURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("oidc_config: issuer_url %q is not a valid URL", c.IssuerURL)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("oidc_config: issuer_url scheme %q must be http or https", u.Scheme)
	}
	if c.ClientID == "" {
		return errors.New("oidc_config: client_id must not be empty when enabled")
	}
	if c.ClientSecret == "" {
		return errors.New("oidc_config: client_secret must not be empty when enabled")
	}
	if c.RedirectURL == "" {
		return errors.New("oidc_config: redirect_url must not be empty when enabled")
	}
	if _, err := url.Parse(c.RedirectURL); err != nil {
		return fmt.Errorf("oidc_config: redirect_url %q is not a valid URL", c.RedirectURL)
	}
	if len(c.Scopes) == 0 {
		return errors.New("oidc_config: scopes must not be empty when enabled")
	}
	return nil
}

// GetOIDCConfig returns the single persisted OIDC config row, or
// ErrNotFound when no row exists (fresh install). Callers MUST
// treat ErrNotFound as "OIDC not configured" and render the
// not-configured shape — same pattern as J.4 DNSProviderConfig.
//
// SECURITY: this function MUST NOT be called from the local-
// credential login path. The break-glass invariant (§1.3 #5)
// requires that local login NEVER depend on OIDC code or
// storage. The handler that emits `login_break_glass` audits
// uses a "best-effort, swallow errors" read that doesn't fail
// the login on storage error — see the API layer for the
// pattern.
func (s *Store) GetOIDCConfig(ctx context.Context) (OIDCConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out OIDCConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketOIDCConfig)).Get([]byte(oidcConfigKey))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return OIDCConfig{}, err
	}
	return out, nil
}

// PutOIDCConfig persists / replaces the OIDC config row. Storage
// validate runs first; a row that does not pass is never written.
// CreatedAt is preserved from the previous row when present;
// UpdatedAt is refreshed.
//
// Caller responsibilities:
//   - Implement preserve-on-edit secret semantics (empty
//     ClientSecret on the wire keeps the previously stored
//     value) — storage trusts the API to have merged before
//     calling here.
//   - Emit audit `oidc_configured` (first PUT) or `oidc_updated`
//     (subsequent PUT) with secrets scrubbed.
func (s *Store) PutOIDCConfig(ctx context.Context, c OIDCConfig) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := c.validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	c.UpdatedAt = now
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketOIDCConfig))
		// Preserve CreatedAt from the existing row if present.
		if raw := b.Get([]byte(oidcConfigKey)); raw != nil {
			var existing OIDCConfig
			if err := json.Unmarshal(raw, &existing); err == nil && !existing.CreatedAt.IsZero() {
				c.CreatedAt = existing.CreatedAt
			}
		}
		buf, err := json.Marshal(c)
		if err != nil {
			return fmt.Errorf("marshal oidc_config: %w", err)
		}
		return b.Put([]byte(oidcConfigKey), buf)
	})
}

// OIDCConfigEverConfigured reports whether the OIDC config bucket
// has ever held a row (regardless of current Enabled state). Used
// by the local-credential login path to decide whether to emit a
// `login_break_glass` audit event in addition to the regular
// `login_success` (§1.3 decision 6).
//
// SAFE TO CALL FROM THE LOCAL LOGIN PATH — but the caller MUST
// treat errors as "could not determine; assume not configured"
// and NOT fail the login. The break-glass audit emission is
// observability; it never gates the login flow itself.
func (s *Store) OIDCConfigEverConfigured(ctx context.Context) (bool, error) {
	_, err := s.GetOIDCConfig(ctx)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return false, err
}
