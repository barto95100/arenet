// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import (
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

func TestMapPathRuleReqs_UpstreamPoolMapped(t *testing.T) {
	reqs := []pathRuleReq{{
		PathPrefix: "/v1",
		Upstreams:  []upstreamReq{{URL: "http://api-a:8080", Weight: 1}},
		LBPolicy:   "round_robin",
	}}
	out, err := mapPathRuleReqs(reqs, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(out) != 1 || len(out[0].Upstreams) != 1 || out[0].Upstreams[0].URL != "http://api-a:8080" {
		t.Fatalf("upstream pool not mapped: %+v", out)
	}
	if out[0].LBPolicy != "round_robin" {
		t.Fatalf("lb policy not mapped: %q", out[0].LBPolicy)
	}
}

func TestMapPathRuleReqs_UpstreamWeightAndLBDefaulted(t *testing.T) {
	// Weight 0 → 1; empty LBPolicy with a non-empty pool → round_robin.
	reqs := []pathRuleReq{{
		PathPrefix: "/v1",
		Upstreams:  []upstreamReq{{URL: "http://a:8080"}}, // weight omitted
	}}
	out, err := mapPathRuleReqs(reqs, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out[0].Upstreams[0].Weight != 1 {
		t.Fatalf("weight not defaulted to 1: %d", out[0].Upstreams[0].Weight)
	}
	if out[0].LBPolicy != "round_robin" {
		t.Fatalf("lb policy not defaulted: %q", out[0].LBPolicy)
	}
}

func TestMapPathRuleReqs_HealthCheckMapped(t *testing.T) {
	reqs := []pathRuleReq{{
		PathPrefix:  "/v1",
		Upstreams:   []upstreamReq{{URL: "http://a:8080", Weight: 1}},
		LBPolicy:    "round_robin",
		HealthCheck: &healthCheckReq{Enabled: true, URI: "/health"},
	}}
	out, err := mapPathRuleReqs(reqs, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out[0].HealthCheck == nil || !out[0].HealthCheck.Enabled || out[0].HealthCheck.URI != "/health" {
		t.Fatalf("health check not mapped: %+v", out[0].HealthCheck)
	}
	// Defaults must be materialised (Method/Interval/Timeout/Passes/Fails).
	if out[0].HealthCheck.Method == "" || out[0].HealthCheck.Interval == "" {
		t.Fatalf("health check defaults not materialised: %+v", out[0].HealthCheck)
	}
}

func TestToPathRulesResp_EchoesUpstreamNotSecrets(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/v1",
		Upstreams:  []storage.Upstream{{URL: "http://a:8080", Weight: 2}},
		LBPolicy:   "round_robin",
		BasicAuth:  &storage.BasicAuthRouteConfig{Username: "u", PasswordHash: "$argon2id$secret"},
	}}
	out := toPathRulesResp(rules)
	if len(out) != 1 || len(out[0].Upstreams) != 1 || out[0].Upstreams[0].URL != "http://a:8080" {
		t.Fatalf("upstream not echoed: %+v", out)
	}
	if out[0].Upstreams[0].Weight != 2 || out[0].LBPolicy != "round_robin" {
		t.Fatalf("lb/weight not echoed: %+v", out)
	}
	if out[0].BasicAuth != nil && out[0].BasicAuth.Password != "" {
		t.Fatalf("password must never be echoed")
	}
}

func TestMapPathRuleReqs_InsecureSkipVerifyMapped(t *testing.T) {
	reqs := []pathRuleReq{{
		PathPrefix:         "/legacy",
		Upstreams:          []upstreamReq{{URL: "https://old:8443", Weight: 1}},
		LBPolicy:           "round_robin",
		InsecureSkipVerify: true,
	}}
	out, err := mapPathRuleReqs(reqs, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !out[0].InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify not mapped: %+v", out[0])
	}
}

func TestToPathRulesResp_EchoesInsecureSkipVerify(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix:         "/legacy",
		Upstreams:          []storage.Upstream{{URL: "https://old:8443", Weight: 1}},
		LBPolicy:           "round_robin",
		InsecureSkipVerify: true,
	}}
	out := toPathRulesResp(rules)
	if !out[0].InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify not echoed: %+v", out[0])
	}
}
