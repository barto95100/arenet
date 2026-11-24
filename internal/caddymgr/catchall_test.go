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
	"testing"

	"github.com/barto95100/arenet/internal/errorvars"
	"github.com/barto95100/arenet/internal/storage"
)

// The catch-all had NO test until v2.49 — which is how a change to it
// could have shipped with a green suite. These pin the shape D8 depends
// on.
//
// What is NOT asserted here, deliberately: that a banned source really
// gets 403 and an unbanned one really gets 404, and that a dead LAPI
// still yields 404. Those need a live bouncer talking to a real LAPI,
// and CrowdSec is kept out of caddy.Validate precisely because
// provisioning it dials LAPI. They belong to the smoke procedure, and
// the spec's gate G5 says so.

func TestCatchAllRoute_NoCrowdSecWhenUnconfigured(t *testing.T) {
	route := catchAllRoute(nil, false)

	// #367: arenet_error_vars (sets {arenet.request.*}) then the 404.
	if len(route.Handle) != 2 {
		t.Fatalf("want [arenet_error_vars, static_response], got %d handlers: %v", len(route.Handle), route.Handle)
	}
	if route.Handle[0]["handler"] != errorvars.HandlerName {
		t.Fatalf("Handle[0] must be arenet_error_vars, got %v", route.Handle[0])
	}
	sr := staticResponseHandler(route)
	if sr == nil {
		t.Fatalf("no static_response handler: %v", route.Handle)
	}
	if sr["status_code"] != 404 {
		t.Fatalf("status_code: got %v", sr["status_code"])
	}
	// The catch-all must stay unmatched, or it stops being one.
	if len(route.Match) != 0 {
		t.Fatalf("the catch-all must match everything, got %v", route.Match)
	}
}

// With a bouncer configured, a banned source is refused here too rather
// than being handed the 404 that used to come back before CrowdSec was
// ever consulted.
func TestCatchAllRoute_CrowdSecFirstThen404(t *testing.T) {
	route := catchAllRoute(nil, true)

	// #367: [crowdsec, arenet_error_vars, static_response]. crowdsec
	// still first (refuse banned source before anything); arenet_error_vars
	// immediately before static_response (sets {arenet.request.*}).
	if len(route.Handle) != 3 {
		t.Fatalf("want [crowdsec, arenet_error_vars, static_response], got %v", route.Handle)
	}
	if route.Handle[0]["handler"] != "crowdsec" {
		t.Fatalf("crowdsec must come first, got %v", route.Handle[0])
	}
	if route.Handle[1]["handler"] != errorvars.HandlerName {
		t.Fatalf("arenet_error_vars must precede static_response, got %v", route.Handle[1])
	}
	// Order is the whole point: after the static_response the answer is
	// already written and the bouncer could refuse nothing.
	if route.Handle[2]["handler"] != "static_response" {
		t.Fatalf("the 404 must remain last, got %v", route.Handle[2])
	}
	if route.Handle[2]["status_code"] != 404 {
		t.Fatalf("status_code: got %v", route.Handle[2]["status_code"])
	}
	if len(route.Match) != 0 {
		t.Fatalf("the catch-all must match everything, got %v", route.Match)
	}
}

// Non-regression: an installation without CrowdSec must emit exactly
// what it emitted before v2.49, body included.
func TestCatchAllRoute_BodyUnchanged(t *testing.T) {
	templates := map[string]storage.ErrorPageTemplate{}
	plain := catchAllRoute(templates, false)
	gated := catchAllRoute(templates, true)

	plainSR := staticResponseHandler(plain)
	gatedSR := staticResponseHandler(gated)
	body := plainSR["body"]
	if body == nil || body == "" {
		t.Fatal("the catch-all must carry a body")
	}
	// Adding the bouncer must not change what the 404 says.
	if gatedSR["body"] != body {
		t.Fatalf("the body changed when CrowdSec was enabled:\n plain: %v\n gated: %v",
			body, gatedSR["body"])
	}
	if gatedSR["headers"] == nil {
		t.Fatal("the Content-Type header must survive")
	}
}
