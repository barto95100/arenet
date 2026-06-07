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

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/geo"
)

// Step V.1.3 — env-parser tests.

func TestParseNormalTrafficSamplePct(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    int
		wantErr string
	}{
		{"empty → 0 (V.1 disabled default)", "", 0, ""},
		{"whitespace-only → 0", "   ", 0, ""},
		{"0 explicit", "0", 0, ""},
		{"5 (spec recommended default)", "5", 5, ""},
		{"100 (always-emit ceiling)", "100", 100, ""},
		{"surrounding whitespace trimmed", "  42  ", 42, ""},
		{"negative rejected", "-1", 0, "out of range"},
		{"101 over ceiling rejected", "101", 0, "out of range"},
		{"non-integer rejected", "abc", 0, "not an integer"},
		{"float rejected", "5.5", 0, "not an integer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseNormalTrafficSamplePct(c.raw)
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (value=%d)", c.wantErr, got)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Errorf("error = %v; want substring %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestParseNormalTrafficCooldown(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    time.Duration
		wantErr string
	}{
		{"empty → 30s default", "", 30 * time.Second, ""},
		{"whitespace-only → 30s default", "   ", 30 * time.Second, ""},
		{"30s explicit", "30s", 30 * time.Second, ""},
		{"5 minutes", "5m", 5 * time.Minute, ""},
		{"1 hour", "1h", time.Hour, ""},
		{"compound: 1m30s", "1m30s", 90 * time.Second, ""},
		{"0s disables cooldown gate", "0s", 0, ""},
		{"negative accepted (also disables)", "-1s", -time.Second, ""},
		{"invalid format rejected", "garbage", 0, "not a valid Go duration"},
		{"missing unit rejected", "30", 0, "not a valid Go duration"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseNormalTrafficCooldown(c.raw)
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (value=%v)", c.wantErr, got)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Errorf("error = %v; want substring %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseNormalTrafficExcludePaths(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty → nil", "", nil},
		{"whitespace-only → nil", "   ", nil},
		{"single entry", "/foo", []string{"/foo"}},
		{"multiple", "/foo,/bar,/baz", []string{"/foo", "/bar", "/baz"}},
		{"surrounding whitespace trimmed per entry", " /foo , /bar ", []string{"/foo", "/bar"}},
		{"empty middle entry dropped", "/foo,,/bar", []string{"/foo", "/bar"}},
		{"trailing comma dropped", "/foo,/bar,", []string{"/foo", "/bar"}},
		{"leading comma dropped", ",/foo", []string{"/foo"}},
		{"duplicates deduped (first wins)", "/foo,/bar,/foo", []string{"/foo", "/bar"}},
		{"all-empty entries → nil", ",,,", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseNormalTrafficExcludePaths(c.raw)
			if !slicesEqual(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// Step V.1.3 — geoForwardingNormalSink passthrough test.
//
// Spec §3.3 + V.1.3 brief: the wrapper is intentionally a
// passthrough. Pin the contract so a future regression
// (e.g. someone "optimizing" the wrapper by stripping
// fields out of Submit) surfaces immediately.

type captureNormalSink struct {
	status int
	srcIP  string
	route  string
	closes int
}

func (c *captureNormalSink) Submit(status int, srcIP, routeID string) {
	c.status = status
	c.srcIP = srcIP
	c.route = routeID
}

func (c *captureNormalSink) Close() error {
	c.closes++
	return nil
}

func TestGeoForwardingNormalSink_Passthrough(t *testing.T) {
	inner := &captureNormalSink{}
	wrapper := geoForwardingNormalSink{inner: inner}
	wrapper.Submit(200, "203.0.113.42", "r-99")
	if inner.status != 200 || inner.srcIP != "203.0.113.42" || inner.route != "r-99" {
		t.Errorf("passthrough mismatch: status=%d srcIP=%q route=%q", inner.status, inner.srcIP, inner.route)
	}
}

func TestGeoForwardingNormalSink_NilInner_NoCrash(t *testing.T) {
	// The wrapper guards against a nil inner (V.1.3 boot
	// path: if SetNormalSubmitter was called with the
	// wrapper before the inner sink was constructed,
	// Submit must not panic).
	wrapper := geoForwardingNormalSink{inner: nil}
	wrapper.Submit(200, "203.0.113.42", "r-99")
	if err := wrapper.Close(); err != nil {
		t.Errorf("nil-inner Close() = %v, want nil", err)
	}
}

func TestGeoForwardingNormalSink_Close_DelegatesToInner(t *testing.T) {
	inner := &captureNormalSink{}
	wrapper := geoForwardingNormalSink{inner: inner}
	if err := wrapper.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	if inner.closes != 1 {
		t.Errorf("inner Close calls = %d, want 1", inner.closes)
	}
}

// Compile-time check: geoForwardingNormalSink satisfies
// the structural geo.NormalSink interface (the wrapper's
// `inner` field is geo.NormalSink, so this is implicit,
// but pinning it as a build assertion catches a future
// API drift between the V.1.1 sink interface and the
// V.1.3 wrapper.
var _ geo.NormalSink = geoForwardingNormalSink{}

// slicesEqual compares two []string slices element-wise.
// Returns true if both are nil OR same length + same
// elements at every index. Local helper to keep the test
// file self-contained.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
