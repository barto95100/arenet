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

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRouteHealthNotify_WireRoundTrip_NoSecret pins T5 of the route
// health feature: the healthNotify setting round-trips through the API in
// its camelCase shape, and the route's API surface never carries a
// channel URL — the route references a channel by ID only (spec D2/D11,
// [[test-the-wire-not-the-struct]]).
func TestRouteHealthNotify_WireRoundTrip_NoSecret(t *testing.T) {
	env := newTestEnv(t, false)
	ch := seedWebhookChannel(t, env.store) // its Config carries a webhook URL + a bearer token

	body := `{"host":"n.local","upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],` +
		`"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"off",` +
		`"healthNotify":{"enabled":true,"channelId":"` + ch.ID + `","reminderMinutes":15}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body)
	}

	// Literal-JSON assertions on the create response.
	created := rec.Body.String()
	for _, want := range []string{`"healthNotify":`, `"enabled":true`, `"channelId":"` + ch.ID + `"`, `"reminderMinutes":15`} {
		if !strings.Contains(created, want) {
			t.Errorf("create response missing %s:\n%s", want, created)
		}
	}

	// The whole route surface must never carry the channel's URL or token.
	var resp routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	get := httptest.NewRequest(http.MethodGet, "/api/v1/routes/"+resp.ID, nil)
	grec := httptest.NewRecorder()
	env.router.ServeHTTP(grec, get)
	if grec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", grec.Code, grec.Body)
	}
	readBack := grec.Body.String()
	if !strings.Contains(readBack, `"channelId":"`+ch.ID+`"`) {
		t.Errorf("GET did not round-trip the channel ID:\n%s", readBack)
	}
	// The channel's own config secrets must never appear on the route.
	for _, secret := range []string{"webhook.example.com", "super-secret-token"} {
		if strings.Contains(readBack, secret) {
			t.Errorf("route surface leaked channel secret %q — the route must carry an ID only:\n%s", secret, readBack)
		}
	}
	// And the healthNotify block itself carries no URL/token (the route's
	// own upstream URL legitimately has a scheme, so scope this to the
	// block, not the whole payload).
	var decoded map[string]json.RawMessage
	_ = json.Unmarshal(grec.Body.Bytes(), &decoded)
	hn := strings.ToLower(string(decoded["healthNotify"]))
	for _, marker := range []string{"://", "http", "webhook", "token", "secret", "url"} {
		if strings.Contains(hn, marker) {
			t.Errorf("healthNotify block contains %q — it must hold a channel ID only: %s", marker, hn)
		}
	}
}

// TestRouteHealthNotify_EnabledUnknownChannel_400 pins the existence
// check the API layer owns (storage validates shape only).
func TestRouteHealthNotify_EnabledUnknownChannel_400(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"n2.local","upstreams":[{"url":"http://10.0.0.51:5000","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],` +
		`"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"off",` +
		`"healthNotify":{"enabled":true,"channelId":"does-not-exist","reminderMinutes":0}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST with unknown channel: %d %s; want 400", rec.Code, rec.Body)
	}

	// And it was not persisted.
	routes, _ := env.store.ListRoutes(context.Background())
	for _, r := range routes {
		if r.Host == "n2.local" {
			t.Error("a route with an unresolvable health-notify channel must not be stored")
		}
	}
}
