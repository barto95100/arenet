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
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Step CS.1 — CrowdSec bouncer instance-level configuration.
// Single row, bucket "crowdsec_config" keyed "default" — same
// convention as bucketOIDCConfig / bucketServerPosition.
//
// Lifecycle:
//   - Boot reads env (ARENET_CROWDSEC_API_URL +
//     ARENET_CROWDSEC_API_KEY) AS BOOTSTRAP DEFAULTS for first
//     boot / emergency override. Once the operator saves anything
//     via the Settings UI, the stored row becomes source of truth
//     (settings > env). See cmd/arenet/main.go for the precedence
//     decision.
//   - The bouncer module
//     (github.com/hslatman/caddy-crowdsec-bouncer v0.12.1) has NO
//     Go API for hot-reload (audit at CS.1 confirmed manager.go:988-992
//     comment). Settings change → mgr.SetCrowdSecConfig +
//     mgr.ReloadFromStore → buildConfigJSON re-emits apps.crowdsec
//     with the new creds → caddy.Load swaps the running config.
//
// APIKey is a SECRET. Storage same boundary as OVHCredentials
// (Step J.4) + OIDCConfig.ClientSecret: cleartext at-rest,
// file-perm boundary on the bbolt file. NEVER echoed by the
// GET path (handler scrubs to fixed-length sentinel), NEVER
// in audit before/after, NEVER in slog.
type CrowdSecConfig struct {
	// LAPIURL is the bouncer's LAPI endpoint. Accepts ANY
	// http(s) URL the operator's deployment exposes — apt
	// systemd service on the same host as Arenet (typically
	// http://127.0.0.1:8080), Docker container with ports
	// mapping (http://127.0.0.1:8080), or sibling container
	// in the same compose network (http://crowdsec:8080).
	// Arenet does NOT assume any deployment topology — only
	// that the URL is reachable from the Arenet process.
	LAPIURL string `json:"lapi_url"`
	// APIKey is the bouncer API key generated via
	// `cscli bouncers add arenet`. SECRET — never echoed by
	// the API GET path. See doc string above.
	APIKey string `json:"api_key"`
	// BouncerName is the cosmetic identifier the operator
	// chose at `cscli bouncers add <name>`. Default "arenet".
	// Used only as an audit-trail / UI display field; the
	// bouncer module identifies itself to LAPI via the
	// APIKey, not the name. Storing it here lets the UI
	// echo the operator's chosen value back as a
	// confirmation that the key they're holding matches the
	// bouncer they registered.
	BouncerName string `json:"bouncer_name"`
	// TimeoutSeconds caps the per-request timeout used by
	// the Test Connection probe + the future CS.2 LAPI
	// proxy endpoints. Defaults to 5s — long enough for a
	// loopback or LAN LAPI to respond, short enough to
	// fail fast when the operator typed the wrong URL.
	// Range guard: [1, 60]. Below 1 risks spurious failures
	// on a busy LAPI; above 60 makes the UI feel broken on
	// a typo.
	TimeoutSeconds int `json:"timeout_seconds"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const crowdSecConfigKey = "default"

// crowdSecDefaultLAPIURL is the documented apt-install default.
// Used as a placeholder hint in the UI and as the implicit URL
// when the operator provides an APIKey but leaves LAPIURL blank
// (see ValidateCrowdSecConfig).
const crowdSecDefaultLAPIURL = "http://127.0.0.1:8080"

const crowdSecDefaultBouncerName = "arenet"
const crowdSecDefaultTimeoutSec = 5
const crowdSecMaxTimeoutSec = 60
const crowdSecMinTimeoutSec = 1

// ValidateCrowdSecConfig runs the strict last-line-of-defence
// checks. Exported so the API layer can pre-validate the request
// payload before merging secret-preserve fields (mirror of
// ValidateOIDCConfig at oidc_config.go:122).
func ValidateCrowdSecConfig(c CrowdSecConfig) error {
	return c.validate()
}

func (c *CrowdSecConfig) validate() error {
	// An empty APIKey is the "not configured" sentinel — same
	// shape as the env-driven AC #13 fail-open at boot (see
	// internal/caddymgr/manager.go SetCrowdSecConfig docs).
	// We accept an all-empty row so the operator can save a
	// clear-it-out PUT (UI "Disable" path); validate only the
	// configured state.
	if strings.TrimSpace(c.APIKey) == "" {
		// LAPIURL + BouncerName + Timeout fields are ignored
		// in the not-configured state, but we still range-
		// guard Timeout if the operator typed something —
		// avoids storing nonsense that would bite on
		// re-enable.
		if c.TimeoutSeconds != 0 {
			if c.TimeoutSeconds < crowdSecMinTimeoutSec || c.TimeoutSeconds > crowdSecMaxTimeoutSec {
				return fmt.Errorf("crowdsec_config: timeout_seconds %d must be in [%d, %d]", c.TimeoutSeconds, crowdSecMinTimeoutSec, crowdSecMaxTimeoutSec)
			}
		}
		return nil
	}

	// Configured state. URL is optional in the wire payload
	// (the UI may default-elide it) — if blank, we treat as
	// the documented default. The PutCrowdSecConfig path
	// normalises blank → default before persisting so the
	// stored row is always explicit.
	effURL := strings.TrimSpace(c.LAPIURL)
	if effURL == "" {
		effURL = crowdSecDefaultLAPIURL
	}
	u, err := url.Parse(effURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("crowdsec_config: lapi_url %q is not a valid URL", c.LAPIURL)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("crowdsec_config: lapi_url scheme %q must be http or https", u.Scheme)
	}

	if c.TimeoutSeconds != 0 && (c.TimeoutSeconds < crowdSecMinTimeoutSec || c.TimeoutSeconds > crowdSecMaxTimeoutSec) {
		return fmt.Errorf("crowdsec_config: timeout_seconds %d must be in [%d, %d]", c.TimeoutSeconds, crowdSecMinTimeoutSec, crowdSecMaxTimeoutSec)
	}

	// BouncerName: 1..64 chars, alphanumerics + dash +
	// underscore. Matches what `cscli bouncers add` accepts
	// (CrowdSec rejects names with whitespace / non-printables
	// at LAPI registration time). We range-guard here so an
	// operator typo doesn't silently roundtrip.
	if name := strings.TrimSpace(c.BouncerName); name != "" {
		if len(name) > 64 {
			return fmt.Errorf("crowdsec_config: bouncer_name %q exceeds 64 chars", name)
		}
		for _, r := range name {
			ok := (r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') ||
				r == '-' || r == '_' || r == '.'
			if !ok {
				return fmt.Errorf("crowdsec_config: bouncer_name %q contains forbidden char %q (allowed: A-Z a-z 0-9 - _ .)", name, r)
			}
		}
	}

	return nil
}

// CrowdSecConfigDefaults returns the canonical defaults used by
// the API GET fallback (no row in store) and by main.go's first-
// boot env-bootstrap path. Centralised so the UI and the
// boot-time fallback can stay in lockstep without copy-paste.
func CrowdSecConfigDefaults() CrowdSecConfig {
	return CrowdSecConfig{
		LAPIURL:        crowdSecDefaultLAPIURL,
		BouncerName:    crowdSecDefaultBouncerName,
		TimeoutSeconds: crowdSecDefaultTimeoutSec,
	}
}

// GetCrowdSecConfig returns the single persisted CrowdSec config
// row, or ErrNotFound when no row exists (fresh install).
// Callers MUST treat ErrNotFound as "not configured" and render
// the not-configured shape (typically: the env-bootstrap row
// merged with defaults) — same pattern as GetOIDCConfig.
func (s *Store) GetCrowdSecConfig(ctx context.Context) (CrowdSecConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out CrowdSecConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketCrowdSecConfig)).Get([]byte(crowdSecConfigKey))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return CrowdSecConfig{}, err
	}
	return out, nil
}

// PutCrowdSecConfig persists / replaces the CrowdSec config row.
// Storage validate runs first; a row that does not pass is
// never written. CreatedAt is preserved from the previous row
// when present; UpdatedAt is refreshed.
//
// Caller responsibilities (same contract as PutOIDCConfig):
//   - Implement preserve-on-edit secret semantics: an empty
//     APIKey on the wire MUST be merged with the previously
//     stored value (the UI sends "" to mean "unchanged" so the
//     SECRET never leaves the server in the GET response, then
//     comes back blank on PUT). Storage trusts the API has
//     merged before calling here — see internal/api/crowdsec_settings.go.
//   - Emit audit `crowdsec_configured` (first PUT) /
//     `crowdsec_updated` (subsequent PUT) with secrets scrubbed.
//   - Call mgr.SetCrowdSecConfig + mgr.ReloadFromStore AFTER
//     a successful PutCrowdSecConfig so the embedded Caddy
//     picks up the new creds (the bouncer module exposes no
//     hot-reload API; the full re-emit through applyLocked is
//     the only viable mechanism).
func (s *Store) PutCrowdSecConfig(ctx context.Context, c CrowdSecConfig) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := c.validate(); err != nil {
		return err
	}

	// Normalise: trim, fill defaults so the stored row is
	// always explicit (no implicit-default surprises if the
	// CrowdSecConfigDefaults() function later changes).
	c.LAPIURL = strings.TrimSpace(c.LAPIURL)
	c.APIKey = strings.TrimSpace(c.APIKey)
	c.BouncerName = strings.TrimSpace(c.BouncerName)
	if c.APIKey != "" {
		if c.LAPIURL == "" {
			c.LAPIURL = crowdSecDefaultLAPIURL
		}
		if c.BouncerName == "" {
			c.BouncerName = crowdSecDefaultBouncerName
		}
		if c.TimeoutSeconds == 0 {
			c.TimeoutSeconds = crowdSecDefaultTimeoutSec
		}
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
		b := tx.Bucket([]byte(bucketCrowdSecConfig))
		if raw := b.Get([]byte(crowdSecConfigKey)); raw != nil {
			var existing CrowdSecConfig
			if err := json.Unmarshal(raw, &existing); err == nil && !existing.CreatedAt.IsZero() {
				c.CreatedAt = existing.CreatedAt
			}
		}
		buf, err := json.Marshal(c)
		if err != nil {
			return fmt.Errorf("marshal crowdsec_config: %w", err)
		}
		return b.Put([]byte(crowdSecConfigKey), buf)
	})
}

// DeleteCrowdSecConfig removes the persisted CrowdSec config
// row. Returns nil on a fresh install (row already absent) —
// idempotent so the API "Reset" path is safe to invoke
// without a prior existence check.
//
// Step CS.2 follow-up: clean erasure path distinct from the
// J.4 "PUT all-blank" convention. Operator-pressed Reset
// button in the Settings UI calls DELETE /api/v1/settings/
// crowdsec which lands here. The all-blank PUT path on
// PutCrowdSecConfig is still accepted (legacy callers, env
// override) but no longer the operator-recommended way to
// disable the bouncer — DELETE is.
//
// SECURITY note: the bouncer creds being erased here are the
// READ-side bouncer API key (CS.1). The Security Automation
// watcher credentials (separate BoltDB row, bucket
// "automation") are NOT touched — those persist across a
// bouncer reset so the operator's auto-classify config + the
// Scenarios tab keep working. If the operator also wants to
// wipe Security Automation, that's a separate action via
// Settings → Security Automation submitting all-blank.
func (s *Store) DeleteCrowdSecConfig(ctx context.Context) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketCrowdSecConfig))
		if b.Get([]byte(crowdSecConfigKey)) == nil {
			return nil
		}
		return b.Delete([]byte(crowdSecConfigKey))
	})
}

// CrowdSecConfigEverConfigured reports whether the CrowdSec
// config bucket has ever held a row. Used by main.go's boot
// precedence: if true → trust the stored row (settings > env);
// if false → fall back to env-bootstrap defaults.
//
// Errors are treated the same as a "never configured" by callers
// (best-effort, swallow errors path); we surface the error so
// the boot path can warn-log it without failing the entire
// startup.
func (s *Store) CrowdSecConfigEverConfigured(ctx context.Context) (bool, error) {
	_, err := s.GetCrowdSecConfig(ctx)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return false, err
}
