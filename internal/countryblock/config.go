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

// Package countryblock implements the Step W per-route country
// allow/deny gate. See docs/superpowers/specs/2026-06-07-step-w-country-block.md
// (commit f038316) for the locked architecture.
//
// W.1 ships three files:
//   - config.go: Mode enum + Config + Validate (this file).
//   - matcher.go: pure-Go Evaluate (no HTTP, no Caddy, no globals).
//   - module.go: Caddy middleware + ServeHTTP + atomic.Pointer globals.
//
// Cross-cutting wiring (storage schema, caddymgr emit, geo sink,
// env vars, frontend) is W.2..W.5.
package countryblock

import (
	"errors"
	"fmt"
)

// Mode is the per-route country-gate operating mode.
//
// Per spec §D2:
//   - ModeOff (or zero value "") — the country-block handler is not
//     even emitted in the per-route chain (caddymgr skip-emission
//     optimization). Zero per-request cost.
//   - ModeAllow — whitelist. Only requests resolving to a country
//     code in CountryList pass. Empty CountryList + ModeAllow is
//     the §D2 footgun and is rejected by Validate.
//   - ModeDeny — blacklist. Requests resolving to a country code
//     in CountryList are blocked. Empty CountryList + ModeDeny is
//     a legal no-op (Validate accepts; the caller may log Warn).
type Mode string

const (
	// ModeOff disables country-block evaluation for the route.
	// Caddymgr SHOULD skip handler emission for ModeOff routes;
	// the matcher still honors ModeOff defensively (returns
	// Decision{Accepted: true, Reason: "off"}) so that a stray
	// emit doesn't silently change behavior.
	ModeOff Mode = "off"

	// ModeAllow is the whitelist mode: accept only countries in
	// CountryList; reject everything else (subject to bypass
	// rules — trusted IPs, RFC1918, degraded lookup).
	ModeAllow Mode = "allow"

	// ModeDeny is the blacklist mode: reject countries in
	// CountryList; accept everything else.
	ModeDeny Mode = "deny"
)

// Config is the per-route country-block configuration. Caddymgr
// emits it as the "config" object inside the arenet_country_block
// handler JSON; the storage Route schema (W.2) embeds an identical
// shape via Route.CountryBlock.
type Config struct {
	// Mode selects the gate operating mode. Validate accepts the
	// empty string as a synonym for ModeOff (so zero-value
	// decoding of pre-W rows yields a valid disabled config).
	Mode Mode `json:"mode"`

	// CountryList is the set of ISO 3166-1 alpha-2 country codes
	// the gate references. Codes MUST be uppercase 2-char ASCII
	// (e.g. "FR", "DE", "RU"). Lowercase / 3-letter / numeric
	// inputs are rejected by Validate; operators are expected to
	// canonicalize at the API layer (W.2).
	CountryList []string `json:"countryList"`

	// StatusCode is the per-route status override. 0 means "use
	// the process-wide default" (ARENET_COUNTRY_BLOCK_STATUS,
	// defaulting to 403). Allowed non-zero values are 403, 451,
	// 444 — anything else is rejected by Validate. Per spec
	// §D3 the env-level override is the primary lever; per-route
	// override is a Step W+1 affordance shipped early because
	// the field is trivially additive.
	StatusCode int `json:"statusCode,omitempty"`
}

// ErrAllowListEmpty is returned by Validate when Mode == ModeAllow
// and CountryList is empty. Per spec §D2 this is the operator-
// facing footgun: an empty allow-list would block ALL traffic
// from non-RFC1918 sources (since no country could possibly match).
// Rejected at the API layer (W.2) with a 400; defense-in-depth
// here ensures a hand-crafted JSON config doesn't sneak past.
var ErrAllowListEmpty = errors.New(
	"countryblock: mode=allow requires at least one country in countryList " +
		"(would otherwise block all non-RFC1918 traffic)",
)

// allowedStatusCodes is the §D3 enum of accepted HTTP status
// codes for a country-block response. Values outside this set
// are rejected by Validate; the env-var parser in cmd/arenet
// (W.3) follows the same enum but warns + falls back to 403
// on invalid input rather than erroring (per spec §D3).
var allowedStatusCodes = map[int]struct{}{
	403: {}, // canonical "you can't access this"
	451: {}, // RFC 7725 — legal-reasons block
	444: {}, // nginx convention — close without response
}

// Validate enforces the spec §D2 / §D3 rules on a Config. Called
// from the API layer (W.2) at PUT /routes/{id} time AND from the
// module's Provision (defense-in-depth at Caddy load time).
//
// Returns the first violation found; the API layer is expected
// to surface the message in the 400 body so the operator can
// fix their input without trial-and-error.
//
// Validation rules:
//   - Mode must be one of {"", ModeOff, ModeAllow, ModeDeny}.
//     Empty is accepted as a synonym for ModeOff.
//   - Each CountryList[i] matches /^[A-Z]{2}$/ (uppercase ASCII).
//   - CountryList contains no duplicates.
//   - Mode == ModeAllow && len(CountryList) == 0 — the §D2 footgun.
//   - Mode == ModeDeny && len(CountryList) == 0 — accepted (legal
//     no-op); caller may log Warn.
//   - StatusCode is 0 (use default) or one of {403, 451, 444}.
func (c *Config) Validate() error {
	switch c.Mode {
	case "", ModeOff, ModeAllow, ModeDeny:
		// ok
	default:
		return fmt.Errorf(
			"countryblock: mode %q is not one of %q, %q, %q",
			c.Mode, ModeOff, ModeAllow, ModeDeny,
		)
	}

	seen := make(map[string]struct{}, len(c.CountryList))
	for _, code := range c.CountryList {
		if !isISOAlpha2Upper(code) {
			return fmt.Errorf(
				"countryblock: country code %q must be uppercase 2-char ISO 3166-1 alpha-2",
				code,
			)
		}
		if _, dup := seen[code]; dup {
			return fmt.Errorf(
				"countryblock: country code %q appears more than once in countryList",
				code,
			)
		}
		seen[code] = struct{}{}
	}

	if c.Mode == ModeAllow && len(c.CountryList) == 0 {
		return ErrAllowListEmpty
	}

	if c.StatusCode != 0 {
		if _, ok := allowedStatusCodes[c.StatusCode]; !ok {
			return fmt.Errorf(
				"countryblock: statusCode %d must be 0 (use default) or one of 403, 451, 444",
				c.StatusCode,
			)
		}
	}

	return nil
}

// isISOAlpha2Upper reports whether s is exactly two uppercase
// ASCII letters. Inlined to avoid a regexp.MustCompile on a
// 4-character pattern (the hot path here is API validation +
// Caddy Provision, both rare events; speed isn't the motive
// — single-line clarity is).
func isISOAlpha2Upper(s string) bool {
	if len(s) != 2 {
		return false
	}
	return s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}
