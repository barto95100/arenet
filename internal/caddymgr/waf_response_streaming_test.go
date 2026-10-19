// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"

	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
)

func respStreamRoute(streaming bool) []storage.Route {
	return []storage.Route{{
		ID: "r1", Host: "app.local", WAFMode: "block",
		Upstreams:             []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:              storage.LBPolicyRoundRobin,
		ResponseStreamingMode: streaming,
	}}
}

// TestBuildConfigJSON_ResponseStreamingMode (issue #317, T3) proves the
// route flag reaches the emitted config: the WAF handler carries
// skip_response_body_inspection and the reverse_proxy gets
// flush_interval=-1 so Caddy flushes each chunk. OFF carries neither.
func TestBuildConfigJSON_ResponseStreamingMode(t *testing.T) {
	on, err := buildConfigJSON(respStreamRoute(true), buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON (on): %v", err)
	}
	off, err := buildConfigJSON(respStreamRoute(false), buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON (off): %v", err)
	}

	if !strings.Contains(string(on), "skip_response_body_inspection") {
		t.Error("streaming ON: WAF handler must carry skip_response_body_inspection")
	}
	if strings.Contains(string(off), "skip_response_body_inspection") {
		t.Error("streaming OFF: the field must be absent")
	}
	if !strings.Contains(string(on), "flush_interval") {
		t.Error("streaming ON: reverse_proxy must set flush_interval=-1 (else the chunk is re-buffered)")
	}
	if strings.Contains(string(off), "flush_interval") {
		t.Error("streaming OFF: no flush_interval expected")
	}

	// Gate #3: the emitted config validates against the embedded Caddy.
	// The metrics handler is first on every route and needs a registry
	// (same harness requirement as TestBuildConfigJSON_LoadsCleanly).
	metrics.SetRegistry(metrics.NewRegistry())
	var parsed caddy.Config
	if err := json.Unmarshal(on, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := caddy.Validate(&parsed); err != nil {
		t.Fatalf("caddy.Validate with response streaming: %v", err)
	}
}

// TestBuildConfigJSON_ResponseStreamingOff_ByteIdentical is gate #4: a
// route with the flag explicitly false emits byte-for-byte the same config
// as one that never set it — unchanged for every non-streaming route.
func TestBuildConfigJSON_ResponseStreamingOff_ByteIdentical(t *testing.T) {
	unset := []storage.Route{{
		ID: "r1", Host: "app.local", WAFMode: "block",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}
	explicitFalse := respStreamRoute(false)

	a, err := buildConfigJSON(unset, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("unset: %v", err)
	}
	b, err := buildConfigJSON(explicitFalse, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("explicit-false: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("ResponseStreamingMode=false diverged from unset — non-streaming routes must be byte-identical")
	}
}
