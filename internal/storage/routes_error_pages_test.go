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

package storage

import (
	"strings"
	"testing"
)

// Step R — Route.ErrorPageTemplateID + ErrorPageOverrides
// validation tests. Mirror the per-feature pattern established by
// routes_country_block_test.go : pin both the happy path
// (accepted shapes) and the rejection paths so a future refactor
// can't loosen the contract without flagging here.

func validRouteWithErrorPages(overrides map[int]string, templateID string) Route {
	return Route{
		Host:                "example.com",
		Upstreams:           []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:            LBPolicyRoundRobin,
		ErrorPageTemplateID: templateID,
		ErrorPageOverrides:  overrides,
	}
}

func TestRoute_Validate_AcceptsErrorPagesUnconfigured(t *testing.T) {
	// Zero state : no template ref, no overrides. Routes pre-R
	// decode this way ; the validator must NOT trip on the absence.
	r := validRouteWithErrorPages(nil, "")
	if err := r.validate(); err != nil {
		t.Errorf("zero-state error pages validate() = %v; want nil", err)
	}
}

func TestRoute_Validate_AcceptsValidOverrides(t *testing.T) {
	// All 8 supported codes with non-empty bodies — operator-
	// maximum config. Must validate cleanly.
	overrides := map[int]string{
		401: "<h1>401</h1>",
		403: "<h1>403</h1>",
		404: "<h1>404</h1>",
		429: "<h1>429</h1>",
		500: "<h1>500</h1>",
		502: "<h1>502</h1>",
		503: "<h1>503</h1>",
		504: "<h1>504</h1>",
	}
	r := validRouteWithErrorPages(overrides, "template-uuid-123")
	if err := r.validate(); err != nil {
		t.Errorf("full-override validate() = %v; want nil", err)
	}
}

func TestRoute_Validate_AcceptsTemplateRefWithoutOverrides(t *testing.T) {
	// Common case : operator picks a template, no per-route
	// overrides. The reference is NOT checked for existence at
	// storage time (storage stays a pure grid).
	r := validRouteWithErrorPages(nil, "template-uuid-abc")
	if err := r.validate(); err != nil {
		t.Errorf("template-only validate() = %v; want nil", err)
	}
}

func TestRoute_Validate_RejectsUnsupportedOverrideCode(t *testing.T) {
	cases := []struct {
		name string
		code int
	}{
		{"200 OK is not error-customisable", 200},
		{"418 teapot is not in the supported set", 418},
		{"451 unavailable-for-legal is not customisable in V1", 451},
		{"999 garbage", 999},
		{"zero", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validRouteWithErrorPages(map[int]string{tc.code: "<h1>x</h1>"}, "")
			err := r.validate()
			if err == nil {
				t.Fatalf("validate accepted unsupported code %d; want error", tc.code)
			}
			if !strings.Contains(err.Error(), "unsupported status code") {
				t.Errorf("error message = %q; want 'unsupported status code' substring", err.Error())
			}
		})
	}
}

func TestRoute_Validate_RejectsOversizedOverrideBody(t *testing.T) {
	// 1 MiB + 1 must trip. Same cap as the template-side validator.
	r := validRouteWithErrorPages(map[int]string{500: strings.Repeat("a", (1<<20)+1)}, "")
	err := r.validate()
	if err == nil {
		t.Fatal("validate accepted oversized override body; want error")
	}
	if !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Errorf("error message = %q; want 'exceeds 1 MiB' substring", err.Error())
	}
}
