// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package main

import (
	"testing"
	"time"
)

// attrsToMap flattens the alternating key/value slog attr slice into a
// map for assertion convenience.
func attrsToMap(attrs []any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, _ := attrs[i].(string)
		m[k] = attrs[i+1]
	}
	return m
}

func TestEffectiveConfigLogAttrs_ValuesAndSecrets(t *testing.T) {
	// Non-secret vars log their value; secret vars log set/unset only.
	t.Setenv("ARENET_ACME_EMAIL", "ops@example.com")
	t.Setenv("ARENET_CROWDSEC_API_KEY", "super-secret-key")
	t.Setenv("ARENET_TRUSTED_PROXIES", "10.0.0.0/8")
	t.Setenv("ARENET_UPDATE_CHECK_INTERVAL", "12h")

	attrs := effectiveConfigLogAttrs(
		"127.0.0.1:8001",  // adminBind
		"/var/lib/arenet", // dataDir
		":80", ":443",     // http, https
		true, "12h", // updateEnabled, updateInterval
	)
	m := attrsToMap(attrs)

	if m["admin_bind"] != "127.0.0.1:8001" {
		t.Errorf("admin_bind = %v", m["admin_bind"])
	}
	if m["data_dir"] != "/var/lib/arenet" {
		t.Errorf("data_dir = %v", m["data_dir"])
	}
	if m["http"] != ":80" || m["https"] != ":443" {
		t.Errorf("ports = %v / %v", m["http"], m["https"])
	}
	if m["update_check"] != "enabled" {
		t.Errorf("update_check = %v; want enabled", m["update_check"])
	}
	if m["update_interval"] != "12h" {
		t.Errorf("update_interval = %v", m["update_interval"])
	}
	// Non-secret var present → value shown.
	if m["acme_email"] != "set" {
		t.Errorf("acme_email = %v; want set (presence flag, email is contact info)", m["acme_email"])
	}
	// Trusted proxies present → "set".
	if m["trusted_proxies"] != "set" {
		t.Errorf("trusted_proxies = %v; want set", m["trusted_proxies"])
	}
	// SECRET: value must NEVER appear anywhere in the attrs.
	for _, v := range m {
		if v == "super-secret-key" {
			t.Fatalf("crowdsec api key VALUE leaked into log attrs: %v", m)
		}
	}
	if m["crowdsec_api_key"] != "set" {
		t.Errorf("crowdsec_api_key = %v; want set (never the value)", m["crowdsec_api_key"])
	}
}

func TestHumanizeDuration(t *testing.T) {
	cases := map[string]string{
		"12h0m0s": "12h",
		"24h0m0s": "24h",
		"1h0m0s":  "1h",
		"90m0s":   "1h30m", // Go normalizes 90m → 1h30m in String()
		"1h30m0s": "1h30m",
		"45s":     "45s",
	}
	for in, want := range cases {
		d, err := time.ParseDuration(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		if got := humanizeDuration(d); got != want {
			t.Errorf("humanizeDuration(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestEffectiveConfigLogAttrs_UnsetSecretsAndDisabled(t *testing.T) {
	// Ensure a clean env for the vars we assert on.
	t.Setenv("ARENET_CROWDSEC_API_KEY", "")
	t.Setenv("ARENET_ACME_EMAIL", "")
	t.Setenv("ARENET_TRUSTED_PROXIES", "")

	attrs := effectiveConfigLogAttrs("127.0.0.1:8001", "/var/lib/arenet", ":80", ":443", false, "24h")
	m := attrsToMap(attrs)

	if m["update_check"] != "disabled" {
		t.Errorf("update_check = %v; want disabled", m["update_check"])
	}
	if m["crowdsec_api_key"] != "unset" {
		t.Errorf("crowdsec_api_key = %v; want unset", m["crowdsec_api_key"])
	}
	if m["acme_email"] != "unset" {
		t.Errorf("acme_email = %v; want unset", m["acme_email"])
	}
	if m["trusted_proxies"] != "unset" {
		t.Errorf("trusted_proxies = %v; want unset", m["trusted_proxies"])
	}
}
