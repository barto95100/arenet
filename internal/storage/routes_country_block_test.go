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
	"errors"
	"reflect"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/barto95100/arenet/internal/countryblock"
)

// TestRoute_CountryBlock_RoundTrip — write a Route carrying a
// non-trivial CountryBlock through CreateRoute, read it back via
// GetRoute, assert the field survives the JSON serialization
// round-trip with byte-equivalent CountryList ordering.
func TestRoute_CountryBlock_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	in := Route{
		Host:      "blocked.example.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		CountryBlock: countryblock.Config{
			Mode:        countryblock.ModeDeny,
			CountryList: []string{"RU", "KP", "CN"},
			StatusCode:  451,
		},
	}
	created, err := s.CreateRoute(ctx, in)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	got, err := s.GetRoute(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if !reflect.DeepEqual(got.CountryBlock, in.CountryBlock) {
		t.Errorf("round-trip CountryBlock mismatch\ngot:  %+v\nwant: %+v",
			got.CountryBlock, in.CountryBlock)
	}
}

// TestRoute_CountryBlock_UpdatePreservesAcrossEdits — operators
// editing unrelated fields (host, upstreams) MUST NOT lose their
// stored country-block config. Mirrors the WAFMode preserve-on-
// edit invariant.
func TestRoute_CountryBlock_UpdatePreservesAcrossEdits(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateRoute(ctx, Route{
		Host:      "edit-me.example.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		CountryBlock: countryblock.Config{
			Mode:        countryblock.ModeAllow,
			CountryList: []string{"FR", "DE"},
		},
	})
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	// Edit the host only — full Route round-trip (the storage
	// UpdateRoute takes a full Route, the API layer is the one
	// that implements the "preserve previous on nil ptr" UX).
	created.Host = "edit-me-2.example.com"
	updated, err := s.UpdateRoute(ctx, created)
	if err != nil {
		t.Fatalf("UpdateRoute: %v", err)
	}
	want := countryblock.Config{
		Mode:        countryblock.ModeAllow,
		CountryList: []string{"FR", "DE"},
	}
	if !reflect.DeepEqual(updated.CountryBlock, want) {
		t.Errorf("CountryBlock dropped on update\ngot:  %+v\nwant: %+v",
			updated.CountryBlock, want)
	}
}

// TestRoute_DecodePreWRow_HasZeroCountryBlock — pre-W rows have no
// `country_block` key in their stored JSON; standard
// json.Unmarshal must decode that missing key to the zero-value
// Config{Mode: ""}, which validates as "off". Mirror of the J.2-
// era TestRoute_DecodeJ1EraRow_HasZeroHealthCheck pattern: seed a
// pre-W JSON literal directly into bbolt, read back through the
// public API, prove the decode path is silent.
func TestRoute_DecodePreWRow_HasZeroCountryBlock(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Hand-crafted JSON without a `country_block` key — exactly
	// the shape an Arenet binary pre-Step-W (v1.5.0-step-v1 and
	// earlier) would have written.
	preWRow := []byte(`{` +
		`"id":"r-pre-w",` +
		`"host":"pre-w.example.com",` +
		`"upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],` +
		`"lb_policy":"round_robin",` +
		`"tls_enabled":false,` +
		`"redirect_to_https":false,` +
		`"aliases":null,` +
		`"auth_mode":"none",` +
		`"basic_auth":{"username":"","password_hash":""},` +
		`"forward_auth":{"provider_name":""},` +
		`"request_headers":null,` +
		`"response_headers":null,` +
		`"waf_mode":"off",` +
		`"acme_challenge":"http-01",` +
		`"health_check":{"enabled":false,"uri":"","method":"","interval":"","timeout":"","expect_status":0,"expect_body":"","passes":0,"fails":0},` +
		`"created_at":"2026-06-01T00:00:00Z",` +
		`"updated_at":"2026-06-01T00:00:00Z"` +
		`}`)
	if err := s.DB().Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("routes")).Put([]byte("r-pre-w"), preWRow)
	}); err != nil {
		t.Fatalf("seed pre-W row: %v", err)
	}

	got, err := s.GetRoute(ctx, "r-pre-w")
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}

	// The whole point: a missing country_block key decodes to
	// zero-value Config{Mode: ""}; validate accepts "" as
	// synonym for "off"; W.3 caddymgr skips the handler emit.
	if got.CountryBlock.Mode != "" {
		t.Errorf("CountryBlock.Mode = %q; want \"\" (zero-value from absent key)",
			got.CountryBlock.Mode)
	}
	if len(got.CountryBlock.CountryList) != 0 {
		t.Errorf("CountryBlock.CountryList len = %d; want 0", len(got.CountryBlock.CountryList))
	}
	if got.CountryBlock.StatusCode != 0 {
		t.Errorf("CountryBlock.StatusCode = %d; want 0", got.CountryBlock.StatusCode)
	}
	// And the zero-value validates without error — pre-W routes
	// remain editable after an in-place binary upgrade.
	if err := got.CountryBlock.Validate(); err != nil {
		t.Errorf("zero-value CountryBlock.Validate() = %v; want nil", err)
	}
}

// TestRoute_Validate_RejectsCountryBlockFootgun — the storage
// validator must reject the §D2 footgun (allow + empty list).
// This is the last line of defence; the API layer rejects with
// a clearer 400 message, but a direct CreateRoute / UpdateRoute
// call (test seed, future internal caller) cannot smuggle a
// footgun config into bbolt.
func TestRoute_Validate_RejectsCountryBlockFootgun(t *testing.T) {
	r := Route{
		Host:      "footgun.example.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		CountryBlock: countryblock.Config{
			Mode:        countryblock.ModeAllow,
			CountryList: nil,
		},
	}
	err := r.validate()
	if err == nil {
		t.Fatal("validate accepted the allow+empty footgun; want error")
	}
	if !errors.Is(err, countryblock.ErrAllowListEmpty) {
		t.Errorf("validate returned %v; want errors.Is(err, countryblock.ErrAllowListEmpty)", err)
	}
}

// TestRoute_Validate_AcceptsCountryBlockOff — the canonical Off
// state validates cleanly. Pin against a future refactor that
// might add stricter rules to the Off branch (it shouldn't —
// Off means "no gate, no checks").
func TestRoute_Validate_AcceptsCountryBlockOff(t *testing.T) {
	cases := []countryblock.Config{
		{}, // zero-value Mode==""
		{Mode: countryblock.ModeOff},
		{Mode: countryblock.ModeOff, CountryList: []string{}},
	}
	for _, cb := range cases {
		r := Route{
			Host:         "off.example.com",
			Upstreams:    []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:     LBPolicyRoundRobin,
			CountryBlock: cb,
		}
		if err := r.validate(); err != nil {
			t.Errorf("validate(Mode=%q, list=%v) = %v; want nil", cb.Mode, cb.CountryList, err)
		}
	}
}

// TestRoute_Validate_AcceptsCountryBlockDenyEmpty — per spec §D2,
// deny + empty list is a legal no-op (validates clean; the API
// layer logs a Warn but persists). Pin so a future tightening
// doesn't regress this carve-out without a spec change.
func TestRoute_Validate_AcceptsCountryBlockDenyEmpty(t *testing.T) {
	r := Route{
		Host:      "deny-empty.example.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		CountryBlock: countryblock.Config{
			Mode:        countryblock.ModeDeny,
			CountryList: nil,
		},
	}
	if err := r.validate(); err != nil {
		t.Errorf("validate(deny+empty) = %v; want nil (legal no-op)", err)
	}
}
