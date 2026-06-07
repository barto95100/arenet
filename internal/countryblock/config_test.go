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

package countryblock

import (
	"errors"
	"strings"
	"testing"
)

// TestValidate_Mode_AllowEmpty_RejectsWithFootgunError pins the spec
// §D2 footgun rule. An empty allow list would block ALL non-RFC1918
// traffic — operators who land this configuration via a typo would
// lock themselves out. Validate must return the named
// ErrAllowListEmpty so the API layer (W.2) can surface a tailored
// error message in the 400 body.
func TestValidate_Mode_AllowEmpty_RejectsWithFootgunError(t *testing.T) {
	c := Config{Mode: ModeAllow, CountryList: nil}
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate accepted mode=allow with empty CountryList; want error")
	}
	if !errors.Is(err, ErrAllowListEmpty) {
		t.Errorf("Validate returned %v; want errors.Is(err, ErrAllowListEmpty)", err)
	}
}

// TestValidate_Mode_DenyEmpty_NoError pins the spec §D2 deny-empty
// "legal no-op" carve-out. A deny list with no entries is a valid
// (if pointless) configuration — Validate accepts; the caller may
// log Warn.
func TestValidate_Mode_DenyEmpty_NoError(t *testing.T) {
	c := Config{Mode: ModeDeny, CountryList: nil}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate(mode=deny, empty list) = %v; want nil (legal no-op)", err)
	}
}

// TestValidate_Mode_OffEmpty_NoError pins the spec §D2 disabled state.
// Mode=off with no countries is the canonical "gate disabled"
// configuration and the default for pre-W rows.
func TestValidate_Mode_OffEmpty_NoError(t *testing.T) {
	c := Config{Mode: ModeOff}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate(mode=off, empty list) = %v; want nil", err)
	}
}

// TestValidate_Mode_EmptyEmpty_NoError pins the zero-value contract.
// A pre-W Route row decodes Mode as "" (Go default); this must
// validate as a synonym for ModeOff so adding the field doesn't
// retro-invalidate existing routes.
func TestValidate_Mode_EmptyEmpty_NoError(t *testing.T) {
	c := Config{Mode: "", CountryList: nil}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate(zero-value Config) = %v; want nil", err)
	}
}

// TestValidate_Mode_UnknownValue_Rejects pins the enum boundary.
// A typo like "block" or "DENY" must be rejected at validation
// rather than silently treated as ModeOff.
func TestValidate_Mode_UnknownValue_Rejects(t *testing.T) {
	cases := []Mode{"block", "DENY", "Allow", "drop", "x"}
	for _, m := range cases {
		c := Config{Mode: m, CountryList: []string{"FR"}}
		err := c.Validate()
		if err == nil {
			t.Errorf("Validate(mode=%q) = nil; want enum error", m)
			continue
		}
		if !strings.Contains(err.Error(), "mode") {
			t.Errorf("Validate(mode=%q) error %v; want message mentioning 'mode'", m, err)
		}
	}
}

// TestValidate_CountryList_LowercaseRejected pins the canonical-form
// requirement. Operators MUST canonicalize to uppercase at the API
// layer; "fr" reaching the matcher would never match the MMDB's
// uppercase output and would silently no-op.
func TestValidate_CountryList_LowercaseRejected(t *testing.T) {
	c := Config{Mode: ModeAllow, CountryList: []string{"fr"}}
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate accepted lowercase country code; want error")
	}
	if !strings.Contains(err.Error(), "fr") {
		t.Errorf("Validate error %v; want message mentioning the bad code", err)
	}
}

// TestValidate_CountryList_ThreeLetterRejected pins the 2-char rule.
// "FRA" is ISO 3166-1 alpha-3 — not what the MMDB returns; would
// silently never match.
func TestValidate_CountryList_ThreeLetterRejected(t *testing.T) {
	c := Config{Mode: ModeAllow, CountryList: []string{"FRA"}}
	if err := c.Validate(); err == nil {
		t.Fatal("Validate accepted 3-letter code; want error")
	}
}

// TestValidate_CountryList_NumericRejected pins the alphabetic-only
// rule. "12" is the ISO 3166-1 numeric-code form for Algeria; the
// MMDB returns alpha-2 strings, so numeric codes would silently
// no-op.
func TestValidate_CountryList_NumericRejected(t *testing.T) {
	c := Config{Mode: ModeAllow, CountryList: []string{"12"}}
	if err := c.Validate(); err == nil {
		t.Fatal("Validate accepted numeric code; want error")
	}
}

// TestValidate_CountryList_DuplicateRejected pins the no-dup rule.
// A duplicate would never cause a wrong decision but would clutter
// the per-route JSON and confuse the W.5 UI's chip count.
func TestValidate_CountryList_DuplicateRejected(t *testing.T) {
	c := Config{Mode: ModeAllow, CountryList: []string{"FR", "DE", "FR"}}
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate accepted duplicate country code; want error")
	}
	if !strings.Contains(err.Error(), "FR") {
		t.Errorf("Validate error %v; want message naming the duplicate", err)
	}
}

// TestValidate_CountryList_HappyPath pins the working case.
func TestValidate_CountryList_HappyPath(t *testing.T) {
	c := Config{Mode: ModeAllow, CountryList: []string{"FR", "DE", "BE", "LU"}}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate happy path = %v; want nil", err)
	}
}

// TestValidate_StatusCode_Zero_OK pins the "use default" sentinel.
// Per spec §D3 the per-route override is opt-in; 0 means "fall
// through to ARENET_COUNTRY_BLOCK_STATUS".
func TestValidate_StatusCode_Zero_OK(t *testing.T) {
	c := Config{Mode: ModeDeny, CountryList: []string{"RU"}, StatusCode: 0}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate(StatusCode=0) = %v; want nil (sentinel for 'use default')", err)
	}
}

// TestValidate_StatusCode_AcceptedValues pins the §D3 enum.
func TestValidate_StatusCode_AcceptedValues(t *testing.T) {
	for _, code := range []int{403, 451, 444} {
		c := Config{Mode: ModeDeny, CountryList: []string{"RU"}, StatusCode: code}
		if err := c.Validate(); err != nil {
			t.Errorf("Validate(StatusCode=%d) = %v; want nil", code, err)
		}
	}
}

// TestValidate_StatusCode_RejectedValues pins the §D3 rejection
// boundary. Other 4xx/5xx codes are NOT accepted — operators
// who want a custom status must pick from the enum (the W.6
// operator doc explains why: scanners + caches behave
// predictably on the 3 we accept, unpredictably on others).
func TestValidate_StatusCode_RejectedValues(t *testing.T) {
	for _, code := range []int{200, 301, 400, 401, 404, 418, 500, 502, 999} {
		c := Config{Mode: ModeDeny, CountryList: []string{"RU"}, StatusCode: code}
		if err := c.Validate(); err == nil {
			t.Errorf("Validate(StatusCode=%d) = nil; want enum error", code)
		}
	}
}

// TestValidate_OrderOfChecks pins the "Mode first, country second,
// statusCode third" ordering. An invalid Mode AND an invalid
// country code should surface the Mode error first — operators
// fix one thing at a time, and a Mode typo is more catastrophic
// (it changes the semantic of the entire field).
func TestValidate_OrderOfChecks(t *testing.T) {
	c := Config{Mode: "junk", CountryList: []string{"fr"}, StatusCode: 999}
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate accepted all-bad config; want error")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Errorf("Validate first error = %v; want mode-related error first", err)
	}
}

// TestValidate_LongCountryList pins that a reasonably large list
// (operator wants to allow all of EU + UK + Norway/Switzerland)
// validates without quadratic blow-up. 30 entries; ~900 string
// compares for the duplicate check. Should be well under 1ms.
func TestValidate_LongCountryList(t *testing.T) {
	c := Config{
		Mode: ModeAllow,
		CountryList: []string{
			"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
			"DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
			"PL", "PT", "RO", "SK", "SI", "ES", "SE", "GB", "NO", "CH",
		},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate(30-entry list) = %v; want nil", err)
	}
}
