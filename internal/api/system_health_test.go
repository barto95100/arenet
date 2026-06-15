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

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barto95100/arenet/internal/systemhealth"
)

// Step AL.3a — /system/health endpoint integration tests.
// Pin the four observable contracts:
//   1. healthy → HTTP 200 + JSON body Status=healthy
//   2. degraded → HTTP 200 + JSON body Status=degraded
//   3. unhealthy → HTTP 503 + JSON body Status=unhealthy
//   4. nil checker → HTTP 200 + degraded body (no 500)
//
// Plus the no-auth contract pin: the endpoint must be
// reachable without a session cookie. The existing /healthz
// endpoint follows the same convention; AL.3a inherits it.

// fakeSystemHealthChecker implements SystemHealthChecker
// with a fixed Report. Tests bind the Report shape they
// want to verify directly — no goroutines, no timing
// dependencies.
type fakeSystemHealthChecker struct {
	report systemhealth.Report
}

func (f *fakeSystemHealthChecker) Run(_ context.Context) systemhealth.Report {
	return f.report
}

func TestSystemHealth_HealthyReturns200(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetSystemHealthChecker(&fakeSystemHealthChecker{
		report: systemhealth.Report{
			Status: systemhealth.StatusHealthy,
			Components: []systemhealth.NamedReport{
				{Name: "caddy", ComponentStatus: systemhealth.ComponentStatus{Status: systemhealth.StatusHealthy}},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/system/health", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 on healthy", rec.Code)
	}
	var body systemhealth.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if body.Status != systemhealth.StatusHealthy {
		t.Errorf("body.Status = %q; want healthy", body.Status)
	}
}

func TestSystemHealth_DegradedReturns200(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetSystemHealthChecker(&fakeSystemHealthChecker{
		report: systemhealth.Report{
			Status: systemhealth.StatusDegraded,
			Components: []systemhealth.NamedReport{
				{Name: "crowdsec", ComponentStatus: systemhealth.ComponentStatus{Status: systemhealth.StatusDegraded, Message: "lapi unreachable"}},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/system/health", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 on degraded (HTTP 200 means 'still serving traffic')", rec.Code)
	}
	var body systemhealth.Report
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Status != systemhealth.StatusDegraded {
		t.Errorf("body.Status = %q; want degraded", body.Status)
	}
}

func TestSystemHealth_UnhealthyReturns503(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetSystemHealthChecker(&fakeSystemHealthChecker{
		report: systemhealth.Report{
			Status: systemhealth.StatusUnhealthy,
			Components: []systemhealth.NamedReport{
				{Name: "caddy", ComponentStatus: systemhealth.ComponentStatus{Status: systemhealth.StatusUnhealthy, Message: "admin endpoint not reachable"}},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/system/health", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d; want 503 on unhealthy", rec.Code)
	}
	var body systemhealth.Report
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Status != systemhealth.StatusUnhealthy {
		t.Errorf("body.Status = %q; want unhealthy", body.Status)
	}
}

func TestSystemHealth_NilCheckerReturns200Degraded(t *testing.T) {
	// Wiring incomplete — handler must surface a coherent
	// degraded response, NOT a 500. This is the boot-
	// degraded contract from the ADR (D2): the
	// monitoring scrape always parses cleanly.
	env := newTestEnv(t, false)
	// Intentionally NOT calling SetSystemHealthChecker.

	req := httptest.NewRequest(http.MethodGet, "/system/health", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 even on nil checker", rec.Code)
	}
	var body systemhealth.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if body.Status != systemhealth.StatusDegraded {
		t.Errorf("body.Status = %q; want degraded on nil checker", body.Status)
	}
}

func TestSystemHealth_NoAuthRequired(t *testing.T) {
	// The endpoint is mounted OUTSIDE /api/v1 so it must
	// be reachable without a session cookie. Pin this so a
	// future refactor that accidentally moves it under the
	// auth subtree breaks the test loudly.
	env := newTestEnv(t, false)
	env.handler.SetSystemHealthChecker(&fakeSystemHealthChecker{
		report: systemhealth.Report{Status: systemhealth.StatusHealthy},
	})

	// Anonymous request — no Cookie, no Authorization.
	req := httptest.NewRequest(http.MethodGet, "/system/health", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("anon request status = %d; want 200 (endpoint must be auth-free for external monitoring)", rec.Code)
	}
}

func TestSystemHealth_ContentTypeAndCacheControl(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetSystemHealthChecker(&fakeSystemHealthChecker{
		report: systemhealth.Report{Status: systemhealth.StatusHealthy},
	})

	req := httptest.NewRequest(http.MethodGet, "/system/health", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q; want application/json; charset=utf-8", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store (stale cache on monitoring would mislead the operator)", cc)
	}
}
