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

package systemhealth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- CaddyCheck -----------------------------------------------------------

func TestCaddyCheck_HealthyOn200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &CaddyCheck{AdminURL: srv.URL}
	got := c.Check(context.Background())
	if got.Status != StatusHealthy {
		t.Errorf("got %q; want healthy (server returned 200)", got.Status)
	}
}

func TestCaddyCheck_UnhealthyOnConnectionRefused(t *testing.T) {
	// Bind a server briefly to get a free port, then close
	// it — the subsequent dial will be refused.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := &CaddyCheck{AdminURL: url}
	got := c.Check(context.Background())
	if got.Status != StatusUnhealthy {
		t.Errorf("got %q; want unhealthy on connection refused", got.Status)
	}
}

func TestCaddyCheck_UnhealthyOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &CaddyCheck{AdminURL: srv.URL}
	got := c.Check(context.Background())
	if got.Status != StatusUnhealthy {
		t.Errorf("got %q; want unhealthy on HTTP 500", got.Status)
	}
}

// --- BoltDBCheck ----------------------------------------------------------

type fakeRoutesCounter struct {
	count int
	err   error
}

func (f *fakeRoutesCounter) CountRoutes(_ context.Context) (int, error) {
	return f.count, f.err
}

func TestBoltDBCheck_HealthyWithCount(t *testing.T) {
	c := &BoltDBCheck{Counter: &fakeRoutesCounter{count: 6}}
	got := c.Check(context.Background())
	if got.Status != StatusHealthy {
		t.Errorf("status = %q; want healthy", got.Status)
	}
	if !strings.Contains(got.Message, "6 routes") {
		t.Errorf("message %q should contain '6 routes'", got.Message)
	}
}

func TestBoltDBCheck_UnhealthyOnReadError(t *testing.T) {
	c := &BoltDBCheck{Counter: &fakeRoutesCounter{err: errors.New("bbolt corrupted")}}
	got := c.Check(context.Background())
	if got.Status != StatusUnhealthy {
		t.Errorf("status = %q; want unhealthy on read error", got.Status)
	}
}

func TestBoltDBCheck_UnhealthyOnNilCounter(t *testing.T) {
	c := &BoltDBCheck{}
	got := c.Check(context.Background())
	if got.Status != StatusUnhealthy {
		t.Errorf("status = %q; want unhealthy on nil counter", got.Status)
	}
}

// --- MetricsCheck ---------------------------------------------------------

type fakeMetricsProber struct {
	version int
	err     error
	delay   time.Duration
}

func (f *fakeMetricsProber) SchemaVersion(ctx context.Context) (int, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return f.version, f.err
}

func TestMetricsCheck_HealthyOnFastRead(t *testing.T) {
	c := &MetricsCheck{Prober: &fakeMetricsProber{version: 9}}
	got := c.Check(context.Background())
	if got.Status != StatusHealthy {
		t.Errorf("status = %q; want healthy", got.Status)
	}
	if !strings.Contains(got.Message, "v9") {
		t.Errorf("message %q should mention schema v9", got.Message)
	}
}

func TestMetricsCheck_DegradedOnNilProber(t *testing.T) {
	c := &MetricsCheck{}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on nil prober (AC #13 boot-degraded)", got.Status)
	}
}

func TestMetricsCheck_DegradedOnReadError(t *testing.T) {
	c := &MetricsCheck{Prober: &fakeMetricsProber{err: errors.New("locked")}}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on read error", got.Status)
	}
}

// --- CrowdSecCheck --------------------------------------------------------

type fakeCrowdSecConfig struct {
	url, key   string
	configured bool
	err        error
}

func (f *fakeCrowdSecConfig) GetCrowdSecConfig(_ context.Context) (string, string, bool, error) {
	return f.url, f.key, f.configured, f.err
}

func TestCrowdSecCheck_HealthyOn2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &CrowdSecCheck{
		Config: &fakeCrowdSecConfig{
			url:        srv.URL,
			key:        "secret",
			configured: true,
		},
	}
	got := c.Check(context.Background())
	if got.Status != StatusHealthy {
		t.Errorf("status = %q; want healthy on 200", got.Status)
	}
}

func TestCrowdSecCheck_DegradedOnNotConfigured(t *testing.T) {
	c := &CrowdSecCheck{
		Config: &fakeCrowdSecConfig{configured: false},
	}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded when not configured", got.Status)
	}
}

func TestCrowdSecCheck_DegradedOnLAPIUnreachable(t *testing.T) {
	// Use a port that's not in use by binding briefly + closing.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := &CrowdSecCheck{
		Config: &fakeCrowdSecConfig{url: url, key: "secret", configured: true},
	}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on unreachable LAPI", got.Status)
	}
}

func TestCrowdSecCheck_DegradedOnAuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &CrowdSecCheck{
		Config: &fakeCrowdSecConfig{url: srv.URL, key: "wrong", configured: true},
	}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on 401", got.Status)
	}
	if !strings.Contains(got.Message, "auth") {
		t.Errorf("message %q should mention auth", got.Message)
	}
}

// --- CertmagicCheck -------------------------------------------------------

type fakeCertLister struct {
	entries []CertEntry
}

func (f *fakeCertLister) ListCertEntries() []CertEntry { return f.entries }

func TestCertmagicCheck_HealthyOnNoExpiry(t *testing.T) {
	c := &CertmagicCheck{
		Lister: &fakeCertLister{
			entries: []CertEntry{
				{Domain: "a.example", NotAfter: time.Now().Add(60 * 24 * time.Hour), StatusValid: true},
				{Domain: "b.example", NotAfter: time.Now().Add(45 * 24 * time.Hour), StatusValid: true},
			},
		},
	}
	got := c.Check(context.Background())
	if got.Status != StatusHealthy {
		t.Errorf("status = %q; want healthy (no certs in warning window)", got.Status)
	}
}

func TestCertmagicCheck_DegradedOnExpiryWindow(t *testing.T) {
	c := &CertmagicCheck{
		Lister: &fakeCertLister{
			entries: []CertEntry{
				{Domain: "soon.example", NotAfter: time.Now().Add(10 * 24 * time.Hour), StatusValid: true},
				{Domain: "far.example", NotAfter: time.Now().Add(60 * 24 * time.Hour), StatusValid: true},
			},
		},
	}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded (1 cert in 14d window)", got.Status)
	}
}

func TestCertmagicCheck_DegradedOnObtainFailed(t *testing.T) {
	c := &CertmagicCheck{
		Lister: &fakeCertLister{
			entries: []CertEntry{
				{Domain: "fail.example", StatusObtainFailed: true},
			},
		},
	}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on obtain-failed cert", got.Status)
	}
	if !strings.Contains(got.Message, "failed") {
		t.Errorf("message %q should mention failure", got.Message)
	}
}

func TestCertmagicCheck_DegradedOnNoCerts(t *testing.T) {
	c := &CertmagicCheck{Lister: &fakeCertLister{}}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on empty cert list (no HTTPS routes)", got.Status)
	}
}
