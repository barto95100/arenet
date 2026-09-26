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

package caddyimport

import (
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// byHost finds a candidate, failing the test when it is missing.
func byHost(t *testing.T, res Result, host string) Candidate {
	t.Helper()
	for _, c := range res.Candidates {
		if c.Host == host {
			return c
		}
	}
	t.Fatalf("no candidate for %q (got %d)", host, len(res.Candidates))
	return Candidate{}
}

// warned reports whether any warning mentions substr.
func warned(c Candidate, substr string) bool {
	for _, w := range c.Warnings {
		if strings.Contains(w.Text, substr) {
			return true
		}
	}
	return false
}

const sample = `{
	email admin@example.com
}

(common) {
	encode gzip
}

app.example.com, www.app.example.com {
	import common
	reverse_proxy 10.0.0.10:8080 10.0.0.11:8080 {
		lb_policy least_conn
		health_uri /healthz
		health_interval 15s
		health_status 2xx
		header_up X-Real-IP {remote_host}
		header_down -Server
		transport http {
			tls_insecure_skip_verify
		}
	}
	header Strict-Transport-Security "max-age=31536000"
	log
}

http://legacy.example.com {
	reverse_proxy old-box:80
	basic_auth {
		alice $2a$14$hash
	}
}

api.example.com {
	reverse_proxy /v1/* 10.0.0.20:9000
	handle_path /static/* {
		reverse_proxy files:8080
	}
	reverse_proxy 10.0.0.21:9000
	tls {
		dns ovh
	}
}

static.example.com {
	root * /srv/www
	file_server
}

vault.example.com:8443 {
	reverse_proxy https://10.0.0.30:8200 {
		transport http {
			tls_insecure_skip_verify
		}
	}
	tls internal
}
`

func TestParse_Sample(t *testing.T) {
	res, err := Parse(sample)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Caddy's parser expands snippets itself, so only the global
	// options block is reported.
	if len(res.GlobalWarnings) != 1 || !strings.Contains(res.GlobalWarnings[0].Text, "global options") {
		t.Errorf("global warnings = %+v", res.GlobalWarnings)
	}

	app := byHost(t, res, "app.example.com")
	if !app.Importable || app.Route == nil {
		t.Fatalf("app: %+v", app)
	}
	r := app.Route
	if len(r.Aliases) != 1 || r.Aliases[0] != "www.app.example.com" {
		t.Errorf("aliases = %v", r.Aliases)
	}
	if !r.TLSEnabled || r.ACMEChallenge != storage.ACMEChallengeHTTP01 {
		t.Errorf("tls = %v challenge = %q", r.TLSEnabled, r.ACMEChallenge)
	}
	if len(r.Upstreams) != 2 || r.Upstreams[0].URL != "http://10.0.0.10:8080" || r.Upstreams[1].Weight != 1 {
		t.Errorf("upstreams = %+v", r.Upstreams)
	}
	if r.LBPolicy != storage.LBPolicyLeastConn {
		t.Errorf("lbPolicy = %q", r.LBPolicy)
	}
	if !r.InsecureSkipVerify {
		t.Error("tls_insecure_skip_verify not imported")
	}
	if r.RequestHeaders["X-Real-IP"] != "{remote_host}" {
		t.Errorf("request headers = %v", r.RequestHeaders)
	}
	if r.ResponseHeaders["Strict-Transport-Security"] != "max-age=31536000" {
		t.Errorf("response headers = %v", r.ResponseHeaders)
	}
	if !r.HealthCheck.Enabled || r.HealthCheck.URI != "/healthz" || r.HealthCheck.Interval != "15s" || r.HealthCheck.ExpectStatus != 200 {
		t.Errorf("health check = %+v", r.HealthCheck)
	}
	if !warned(app, "header -Server") && !warned(app, "not imported") {
		t.Errorf("the removed header should be reported: %+v", app.Warnings)
	}

	legacy := byHost(t, res, "legacy.example.com")
	if !legacy.Importable || legacy.Route.TLSEnabled {
		t.Errorf("http:// must import with TLS off: %+v", legacy.Route)
	}
	if !warned(legacy, "basic auth") {
		t.Errorf("basic auth must be reported: %+v", legacy.Warnings)
	}

	api := byHost(t, res, "api.example.com")
	if !api.Importable {
		t.Fatalf("api not importable: %s", api.Reason)
	}
	if len(api.Route.Upstreams) != 1 || api.Route.Upstreams[0].URL != "http://10.0.0.21:9000" {
		t.Errorf("site-wide pool = %+v", api.Route.Upstreams)
	}
	if len(api.Route.PathRules) != 2 {
		t.Fatalf("path rules = %+v", api.Route.PathRules)
	}
	prefixes := []string{api.Route.PathRules[0].PathPrefix, api.Route.PathRules[1].PathPrefix}
	if prefixes[0] != "/v1" || prefixes[1] != "/static" {
		t.Errorf("prefixes = %v", prefixes)
	}
	if api.Route.PathRules[1].Upstreams[0].URL != "http://files:8080" {
		t.Errorf("handle_path pool = %+v", api.Route.PathRules[1].Upstreams)
	}
	if api.Route.ACMEChallenge != storage.ACMEChallengeDNS01 || !warned(api, "ovh provider") {
		t.Errorf("dns-01 = %q warnings = %+v", api.Route.ACMEChallenge, api.Warnings)
	}

	static := byHost(t, res, "static.example.com")
	if static.Importable || static.Reason == "" {
		t.Errorf("a file_server-only block is not importable: %+v", static)
	}
	if !warned(static, "file_server") || !warned(static, "root") {
		t.Errorf("static warnings = %+v", static.Warnings)
	}

	vault := byHost(t, res, "vault.example.com")
	if !vault.Importable || vault.Route.Upstreams[0].URL != "https://10.0.0.30:8200" {
		t.Errorf("vault = %+v", vault.Route)
	}
	if !warned(vault, "port 8443") || !warned(vault, "tls internal") {
		t.Errorf("vault warnings = %+v", vault.Warnings)
	}
}

func TestParse_WarningsCarryTheirLine(t *testing.T) {
	res, err := Parse("app.example.com {\n\treverse_proxy 10.0.0.1:80\n\tphp_fastcgi unix//run/php.sock\n}\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := byHost(t, res, "app.example.com")
	if len(c.Warnings) != 1 || c.Warnings[0].Line != 3 || !strings.Contains(c.Warnings[0].Text, "php_fastcgi") {
		t.Fatalf("warnings = %+v, want php_fastcgi on line 3", c.Warnings)
	}
}

func TestParse_Rejects(t *testing.T) {
	if _, err := Parse("app.example.com {\n\treverse_proxy\n"); err == nil {
		t.Error("an unbalanced block must be refused")
	}
	if _, err := Parse(strings.Repeat("a", MaxBytes+1)); err == nil {
		t.Error("an oversized Caddyfile must be refused")
	}
	res, err := Parse(":8080 {\n\treverse_proxy 10.0.0.1:80\n}\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Candidates) != 1 || res.Candidates[0].Importable {
		t.Errorf("a port-only block is not importable: %+v", res.Candidates)
	}
}

func TestParse_UnixAndPlaceholderUpstreams(t *testing.T) {
	res, err := Parse("app.example.com {\n\treverse_proxy unix//run/app.sock\n}\n\nb.example.com {\n\treverse_proxy {http.request.host}:8080\n}\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	a := byHost(t, res, "app.example.com")
	if a.Importable || !warned(a, "HTTP(S) only") {
		t.Errorf("unix socket: %+v", a)
	}
	b := byHost(t, res, "b.example.com")
	if b.Importable || !warned(b, "placeholders") {
		t.Errorf("placeholder upstream: %+v", b)
	}
}

// Smoke-caught: the provider name of `tls { dns ovh }` was read as
// another tls option and produced a spurious warning.
func TestParse_DNSProviderArgumentsConsumed(t *testing.T) {
	res, err := Parse("a.example.com {\n\treverse_proxy 10.0.0.1:80\n\ttls {\n\t\tdns ovh {\n\t\t\tapplication_key KEY\n\t\t}\n\t\tresolvers 1.1.1.1\n\t}\n}\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := byHost(t, res, "a.example.com")
	if c.Route.ACMEChallenge != storage.ACMEChallengeDNS01 {
		t.Fatalf("challenge = %q", c.Route.ACMEChallenge)
	}
	if !warned(c, "ovh provider") {
		t.Errorf("the provider name should be in the warning: %+v", c.Warnings)
	}
	for _, w := range c.Warnings {
		if strings.Contains(w.Text, `"ovh"`) || strings.Contains(w.Text, `"application_key"`) || strings.Contains(w.Text, `"1.1.1.1"`) {
			t.Errorf("arguments read as tls options: %q", w.Text)
		}
	}
	if !warned(c, `tls option "resolvers"`) {
		t.Errorf("a real unsupported option must still be reported: %+v", c.Warnings)
	}
}
