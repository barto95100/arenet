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

package storage

import (
	"strings"
	"testing"
)

// Caddy runs operator header values and static_response Location targets
// through its replacer (headers.go ReplaceKnown, staticresp.go
// ReplaceAll, caddy v2.11.4), so a {env.SECRET} lands as the process
// environment variable and a {file./etc/passwd} as the file's contents —
// in a response the public receives. These are refused at storage, the
// one place every write path (API and backup restore) passes through.
//
// Request-derived placeholders are not dangerous and must keep working:
// X-Real-IP: {http.request.remote.host} is an ordinary thing to set.

func TestValidate_RefusesEnvPlaceholderInResponseHeader(t *testing.T) {
	r := minimalRoute("app.example.com", "http://u:1")
	r.ResponseHeaders = map[string]string{"X-Debug": "{env.ARENET_SECRET}"}
	err := r.validate()
	if err == nil {
		t.Fatal("a response header value with {env.*} must be refused — Caddy expands it into the public response")
	}
	if !strings.Contains(err.Error(), "env") {
		t.Errorf("the message must name what it refused: %v", err)
	}
}

func TestValidate_RefusesFilePlaceholderInRequestHeader(t *testing.T) {
	r := minimalRoute("app.example.com", "http://u:1")
	r.RequestHeaders = map[string]string{"X-Leak": "{file./etc/passwd}"}
	if err := r.validate(); err == nil {
		t.Fatal("a request header value with {file.*} must be refused — Caddy reads the host file")
	}
}

func TestValidate_RefusesPlaceholderInRouteRedirectTarget(t *testing.T) {
	r := routeWithRedirect(&RedirectConfig{Target: "https://new.example.com/{env.ARENET_SECRET}"})
	if err := r.validate(); err == nil {
		t.Fatal("a route redirect target carrying {env.*} must be refused — it is emitted into a Location header Caddy expands")
	}
}

func TestValidate_RefusesPlaceholderInPathRedirectTarget(t *testing.T) {
	r := routeWithPathRule(PathRule{
		PathPrefix: "/go",
		Redirect:   &PathRedirect{Target: "/{file./etc/shadow}"},
	})
	if err := r.validate(); err == nil {
		t.Fatal("a path redirect target carrying {file.*} must be refused")
	}
}

// The guard must not catch legitimate request-derived placeholders, or it
// breaks a normal reverse-proxy header the operator relies on.
func TestValidate_AllowsRequestPlaceholderInHeader(t *testing.T) {
	r := minimalRoute("app.example.com", "http://u:1")
	r.RequestHeaders = map[string]string{"X-Real-IP": "{http.request.remote.host}"}
	r.ResponseHeaders = map[string]string{"X-Host": "{http.request.host}"}
	if err := r.validate(); err != nil {
		t.Fatalf("a request-derived placeholder is safe and must pass: %v", err)
	}
}
