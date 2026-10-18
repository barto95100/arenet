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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/barto95100/arenet/internal/caddyhc"
)

// TestHCEvents_EndToEnd_UnhealthyReachesTracker is the end-to-end check
// the pipeline never had: a real reverse_proxy active health check
// against a 502 backend must drive Caddy to emit an "unhealthy" event
// that the apps.events subscription routes to the arenet_topology_hc
// handler, flipping the tracker. The operator saw a down upstream stay
// green with this exact shape; this reproduces (or clears) it.
func TestHCEvents_EndToEnd_UnhealthyReachesTracker(t *testing.T) {
	// A backend that always answers 502 — like the operator's radarr
	// behind a broken proxy.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer backend.Close()
	dial := backend.Listener.Addr().String() // host:port

	// Fresh tracker wired as the package singleton the handler finds.
	tr := caddyhc.NewTracker()
	caddyhc.SetTracker(tr)
	t.Cleanup(func() { caddyhc.SetTracker(nil) })

	// A free port for Caddy's own listener (unused by the probe, but the
	// http app needs a server to provision the reverse_proxy handler).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := fmt.Sprintf(`{
	  "admin": {"disabled": true},
	  "logging": {"logs": {"default": {"level": "ERROR"}}},
	  "apps": {
	    "http": {"servers": {"t": {
	      "listen": ["127.0.0.1:%d"],
	      "routes": [{"handle": [{
	        "handler": "reverse_proxy",
	        "upstreams": [{"dial": %q}],
	        "health_checks": {"active": {
	          "uri": "/health", "interval": "1s", "timeout": "2s",
	          "passes": 1, "fails": 1, "expect_status": 200
	        }}
	      }]}]
	    }}},
	    "events": {"subscriptions": [{
	      "events": ["healthy", "unhealthy"],
	      "modules": ["http.handlers.reverse_proxy"],
	      "handlers": [{"handler": "arenet_topology_hc"}]
	    }]}
	  }
	}`, port, dial)

	if err := caddy.Load([]byte(cfg), true); err != nil {
		t.Fatalf("caddy.Load: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	// The first probe fires almost immediately and fails; with fails=1 it
	// should transition the fresh upstream healthy→unhealthy and emit.
	// Poll up to a few intervals.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if tr.Status(dial) == caddyhc.StatusUnhealthy {
			return // pipeline works
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("tracker never saw unhealthy for %s after 8s of a 502 backend; "+
		"Status=%q — the Caddy health-check event is not reaching the handler",
		dial, tr.Status(dial))
}
