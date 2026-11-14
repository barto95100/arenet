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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/automation"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// scrape registers the collector in a fresh registry and returns the
// exposition body, exactly as the /metrics handler would serve it.
func scrape(t *testing.T, snap automationSnapshot) string {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(newAutomationCollector(snap))
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(
		rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	return string(body)
}

// hasLine reports whether body contains want as a WHOLE line. Checking a
// whole line, not a substring, matters for the gauge: its `# HELP` text
// begins "1 when the auto-classify…", so a substring match on
// "…login_failed 1" is satisfied by the HELP comment regardless of the
// real value — a test that cannot fail. A sample line never starts with
// '#', so an exact-line check separates value from documentation.
func hasLine(body, want string) bool {
	for _, ln := range strings.Split(body, "\n") {
		if strings.TrimRight(ln, "\r") == want {
			return true
		}
	}
	return false
}

// The operator-facing contract: a writer in login-failed state flips the
// gauge to 1, and the three push results each appear with their count.
//
// Reinjection: hardcoding loginFailed to 0 in Collect, or dropping a
// result label, fails this.
func TestPrometheusMetrics_ExposesAutomationHealth(t *testing.T) {
	body := scrape(t, func() (automation.HealthSnapshot, bool) {
		return automation.HealthSnapshot{
			WriterConfigured:  true,
			WriterLoginFailed: true,
			PushSuccess:       5,
			PushPermanent:     2,
			PushDropped:       1,
		}, true
	})

	want := []string{
		"arenet_automation_writer_login_failed 1",
		`arenet_automation_pushes_total{result="success"} 5`,
		`arenet_automation_pushes_total{result="permanent"} 2`,
		`arenet_automation_pushes_total{result="dropped"} 1`,
		// The TYPE lines prove the metric kinds a scraper relies on.
		"# TYPE arenet_automation_writer_login_failed gauge",
		"# TYPE arenet_automation_pushes_total counter",
	}
	for _, w := range want {
		if !hasLine(body, w) {
			t.Errorf("missing whole line %q in:\n%s", w, body)
		}
	}
}

// A healthy writer reports the gauge as 0 — the common case, and the one
// an alert on `== 1` must NOT fire on.
func TestPrometheusMetrics_HealthyWriterGaugeZero(t *testing.T) {
	body := scrape(t, func() (automation.HealthSnapshot, bool) {
		return automation.HealthSnapshot{WriterConfigured: true, WriterLoginFailed: false}, true
	})
	if !hasLine(body, "arenet_automation_writer_login_failed 0") {
		t.Fatalf("gauge not 0 for a healthy writer:\n%s", body)
	}
}

// Boot-degraded path: no manager registered. The series must still exist
// at 0 — an absent series cannot be alerted on, so "automation never
// configured" and "automation broke" must not look identical by absence.
func TestPrometheusMetrics_NoManagerEmitsZeros(t *testing.T) {
	body := scrape(t, func() (automation.HealthSnapshot, bool) {
		return automation.HealthSnapshot{}, false
	})
	for _, w := range []string{
		"arenet_automation_writer_login_failed 0",
		`arenet_automation_pushes_total{result="permanent"} 0`,
	} {
		if !hasLine(body, w) {
			t.Errorf("missing whole line %q in:\n%s", w, body)
		}
	}
}
