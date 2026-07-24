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

package caddymgr

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// updateGolden, when set (`go test -update`), rewrites the golden
// snapshot from the CURRENT emitter output instead of asserting against
// it. This is the pre-refactor snapshot mechanism required by Task 3:
// run once against pre-refactor code to capture the byte-for-byte truth,
// commit the golden, then the refactor is proven byte-identical because
// the plain (no -update) run must still pass.
var updateGolden = flag.Bool("update", false, "rewrite golden testdata files")

// representativeRoutes covers the proxyHandler shape variants whose
// emission must stay byte-identical across the buildReverseProxyHandler
// extraction: plain http pool, multi-upstream weighted, https pool
// (transport.tls), https pool + insecure_skip_verify, active health
// check, and upload-streaming (flush_interval). NO per-path upstream —
// this is the pre-per-path-upstream surface that carries 100% of every
// route's traffic.
//
// NOTE: the health-check route (r4) is the ONLY route with an active
// health check, and it has no subroute-heavy fixture siblings, so this
// set does NOT trip the known active-HC x subroute Caddy-internal data
// race (see caddymgr_race_test_gate memory). WAFMode is left "off" and
// no auth/path-rules are attached, keeping each route a plain
// [metrics, reverse_proxy] chain.
func representativeRoutes() []storage.Route {
	return []storage.Route{
		{
			ID:        "r1",
			Host:      "plain.example.com",
			Upstreams: []storage.Upstream{{URL: "http://a:8080", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
		},
		{
			ID:   "r2",
			Host: "multi.example.com",
			Upstreams: []storage.Upstream{
				{URL: "http://a:8080", Weight: 2},
				{URL: "http://b:8080", Weight: 3},
			},
			LBPolicy: storage.LBPolicyWeightedRoundRobin,
			WAFMode:  "off",
		},
		{
			ID:        "r3",
			Host:      "secure.example.com",
			Upstreams: []storage.Upstream{{URL: "https://a:8443", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
		},
		{
			ID:                 "r3b",
			Host:               "insecure.example.com",
			Upstreams:          []storage.Upstream{{URL: "https://a:8443", Weight: 1}},
			LBPolicy:           storage.LBPolicyRoundRobin,
			InsecureSkipVerify: true,
			WAFMode:            "off",
		},
		{
			ID:        "r4",
			Host:      "hc.example.com",
			Upstreams: []storage.Upstream{{URL: "http://a:8080", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			HealthCheck: storage.HealthCheck{
				Enabled:  true,
				URI:      "/health",
				Method:   "GET",
				Interval: "10s",
				Timeout:  "5s",
				Passes:   1,
				Fails:    1,
			},
		},
		{
			ID:                  "r5",
			Host:                "upload.example.com",
			Upstreams:           []storage.Upstream{{URL: "http://a:8080", Weight: 1}},
			LBPolicy:            storage.LBPolicyRoundRobin,
			UploadStreamingMode: true,
			WAFMode:             "off",
		},
	}
}

// readGolden reads the byte-for-byte golden snapshot. Local to this test
// file — the package has no shared golden helper (managed-domain fixture
// uses its own bespoke loader).
func readGolden(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readGolden %s: %v (run `go test -update` against pre-refactor code to snapshot it)", path, err)
	}
	return b
}

// TestBuildReverseProxyHandler_RouteEmissionByteIdentical is the byte-
// identity guard for the buildReverseProxyHandler extraction. The golden
// in testdata/route_emission_golden.json was captured from the
// PRE-refactor emitter; a passing run proves the refactor emits the
// exact same bytes for every representative route shape.
func TestBuildReverseProxyHandler_RouteEmissionByteIdentical(t *testing.T) {
	routes := representativeRoutes()
	got, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	goldenPath := filepath.Join("testdata", "route_emission_golden.json")
	if *updateGolden {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("writeGolden %s: %v", goldenPath, err)
		}
		t.Logf("wrote golden snapshot (%d bytes) to %s", len(got), goldenPath)
		return
	}

	golden := readGolden(t, goldenPath)
	if string(got) != string(golden) {
		t.Fatalf("route emission changed — refactor is NOT byte-identical.\n got: %s\nwant: %s", got, golden)
	}
}
