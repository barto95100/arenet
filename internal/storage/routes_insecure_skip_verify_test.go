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
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// #R-PROXMOX-HTTPS-LOOP tests — Route.InsecureSkipVerify
// field + same-scheme pool validate + PoolUsesHTTPS helper.
//
// Pins:
//   - Roundtrip of InsecureSkipVerify (true and false)
//   - Mixed-scheme pools rejected by validate
//   - All-http and all-https pools accepted
//   - PoolUsesHTTPS predicate
//   - Pre-fix rows (no insecure_skip_verify key) decode to
//     the operator-safer false default

func TestRoute_InsecureSkipVerify_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "pve.local",
		Upstreams: []Upstream{
			{URL: "https://192.168.1.60:8006", Weight: 1},
		},
		LBPolicy:           LBPolicyRoundRobin,
		AuthMode:           "none",
		InsecureSkipVerify: true,
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	r = created
	got, err := s.GetRoute(ctx, r.ID)
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if !got.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify = false after roundtrip; want true")
	}
}

func TestRoute_InsecureSkipVerify_DefaultsFalse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Operator does not pass InsecureSkipVerify — zero-value
	// false should persist (strict default; operator must
	// opt in to bypass cert validation).
	r := Route{
		Host: "pve.local",
		Upstreams: []Upstream{
			{URL: "https://192.168.1.60:8006", Weight: 1},
		},
		LBPolicy: LBPolicyRoundRobin,
		AuthMode: "none",
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	r = created
	got, _ := s.GetRoute(ctx, r.ID)
	if got.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify = true on default Route; want false (strict default)")
	}
}

func TestRoute_DecodePreFixRow_HasZeroInsecureSkipVerify(t *testing.T) {
	// Pre-#R-PROXMOX-HTTPS-LOOP rows have no
	// `insecure_skip_verify` key in their stored JSON;
	// standard json.Unmarshal must decode the missing key
	// to false (strict). Mirror of
	// TestRoute_DecodePreWRow_HasZeroCountryBlock.
	s := newTestStore(t)
	ctx := context.Background()

	preFixRow := []byte(`{` +
		`"id":"r-pre-fix",` +
		`"host":"pre-fix.example.com",` +
		`"upstreams":[{"url":"https://10.0.0.5:8006","weight":1}],` +
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
		`"country_block":{"mode":"","country_list":null,"status_code":0,"trusted_ips":null},` +
		`"created_at":"2026-06-01T00:00:00Z",` +
		`"updated_at":"2026-06-01T00:00:00Z"` +
		`}`)
	if err := s.DB().Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("routes")).Put([]byte("r-pre-fix"), preFixRow)
	}); err != nil {
		t.Fatalf("seed pre-fix row: %v", err)
	}

	got, err := s.GetRoute(ctx, "r-pre-fix")
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if got.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify = true on pre-fix row; want false (strict default)")
	}
}

// --- Same-scheme pool invariant -------------------------------

func TestRoute_Validate_AcceptsAllHTTPPool(t *testing.T) {
	r := Route{
		Host: "ha.example.com",
		Upstreams: []Upstream{
			{URL: "http://10.0.0.10:8123", Weight: 1},
			{URL: "http://10.0.0.11:8123", Weight: 1},
		},
		LBPolicy: LBPolicyRoundRobin,
		AuthMode: "none",
	}
	if err := r.validate(); err != nil {
		t.Errorf("validate: %v (all-http pool should validate)", err)
	}
}

func TestRoute_Validate_AcceptsAllHTTPSPool(t *testing.T) {
	r := Route{
		Host: "pve.example.com",
		Upstreams: []Upstream{
			{URL: "https://10.0.0.20:8006", Weight: 1},
			{URL: "https://10.0.0.21:8006", Weight: 1},
		},
		LBPolicy:           LBPolicyRoundRobin,
		AuthMode:           "none",
		InsecureSkipVerify: true,
	}
	if err := r.validate(); err != nil {
		t.Errorf("validate: %v (all-https pool should validate)", err)
	}
}

func TestRoute_Validate_RejectsMixedSchemePool(t *testing.T) {
	r := Route{
		Host: "mixed.example.com",
		Upstreams: []Upstream{
			{URL: "http://10.0.0.10:8000", Weight: 1},
			{URL: "https://10.0.0.11:8000", Weight: 1},
		},
		LBPolicy: LBPolicyRoundRobin,
		AuthMode: "none",
	}
	err := r.validate()
	if err == nil {
		t.Fatal("validate accepted mixed-scheme pool; want error")
	}
	if !strings.Contains(err.Error(), "same scheme") {
		t.Errorf("error message = %q; want mention of 'same scheme'", err.Error())
	}
}

func TestRoute_Validate_RejectsMixedSchemePool_ReverseOrder(t *testing.T) {
	// Same as above but https first, http second — ensure
	// the iteration doesn't accidentally accept based on
	// declaration order.
	r := Route{
		Host: "mixed-rev.example.com",
		Upstreams: []Upstream{
			{URL: "https://10.0.0.11:8000", Weight: 1},
			{URL: "http://10.0.0.10:8000", Weight: 1},
		},
		LBPolicy: LBPolicyRoundRobin,
		AuthMode: "none",
	}
	if err := r.validate(); err == nil {
		t.Fatal("validate accepted mixed-scheme pool (reverse order); want error")
	}
}

// --- PoolUsesHTTPS helper -------------------------------------

func TestRoute_PoolUsesHTTPS(t *testing.T) {
	for _, tt := range []struct {
		name string
		pool []Upstream
		want bool
	}{
		{
			"all-http",
			[]Upstream{{URL: "http://1.1.1.1:80", Weight: 1}},
			false,
		},
		{
			"all-https",
			[]Upstream{{URL: "https://1.1.1.1:443", Weight: 1}},
			true,
		},
		{
			"all-https-uppercase",
			[]Upstream{{URL: "HTTPS://1.1.1.1:443", Weight: 1}},
			true,
		},
		{
			"empty-pool",
			nil,
			false,
		},
		{
			"scheme-less-string",
			[]Upstream{{URL: "1.1.1.1:80", Weight: 1}},
			false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := Route{Upstreams: tt.pool}
			if got := r.PoolUsesHTTPS(); got != tt.want {
				t.Errorf("PoolUsesHTTPS = %v, want %v", got, tt.want)
			}
		})
	}
}
