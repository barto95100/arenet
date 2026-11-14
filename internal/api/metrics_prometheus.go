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

// metrics_prometheus.go serves GET /metrics in Prometheus text format for
// external monitoring (Zabbix / Nagios / Datadog / Prometheus).
//
// v1 scope (v2.82.0) is the auto-classify writer's health — the one thing
// that fails silently today (see internal/automation/health.go). The
// endpoint is authenticated (HardAuthMiddleware in routes.go), unlike
// /healthz: metrics carry operational data and this ships to every
// install. A read-only service-account token scrapes it with an
// `Authorization: Bearer <token>` header.
//
// A dedicated registry (not prometheus.DefaultRegisterer) keeps Arenet's
// series isolated from any library's global registrations and from the Go
// runtime collectors. More Arenet metrics can register here later.

import (
	"net/http"
	"sync"

	"github.com/barto95100/arenet/internal/automation"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// automationSnapshot is the read function the collector calls per scrape.
// Returns (snapshot, true) when a manager implementing HealthReporter is
// registered, or (zero, false) in the boot-degraded path (no watcher
// credentials → no manager). The zero snapshot still yields a 0 gauge so
// an alert on `== 1` always has a series to evaluate.
type automationSnapshot func() (automation.HealthSnapshot, bool)

// automationSnapshotFromGlobal reads the process-wide automation manager.
func automationSnapshotFromGlobal() (automation.HealthSnapshot, bool) {
	mgr := automation.GetManager()
	if mgr == nil {
		return automation.HealthSnapshot{}, false
	}
	hr, ok := mgr.(automation.HealthReporter)
	if !ok {
		return automation.HealthSnapshot{}, false
	}
	return hr.HealthSnapshot(), true
}

// automationCollector turns an automationSnapshot into Prometheus series.
// It holds no state of its own beyond the descriptors — every value is
// read live from the snapshot function at Collect time.
type automationCollector struct {
	snapshot    automationSnapshot
	loginFailed *prometheus.Desc
	pushes      *prometheus.Desc
}

func newAutomationCollector(snapshot automationSnapshot) *automationCollector {
	return &automationCollector{
		snapshot: snapshot,
		loginFailed: prometheus.NewDesc(
			"arenet_automation_writer_login_failed",
			"1 when the auto-classify writer's last CrowdSec LAPI login failed (automatic banning has stopped until the operator fixes the machine credential), else 0.",
			nil, nil,
		),
		pushes: prometheus.NewDesc(
			"arenet_automation_pushes_total",
			"Auto-classify decisions pushed to CrowdSec LAPI, by result: success, permanent (dropped on a non-retryable error — bad credential or rejected payload, the signal that needs a human), dropped (retry-exhausted against an unreachable LAPI).",
			[]string{"result"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *automationCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.loginFailed
	ch <- c.pushes
}

// Collect implements prometheus.Collector. Reads one snapshot and emits
// the gauge + the three counters. When no manager is registered it still
// emits zeros, so the series exist (absent series cannot be alerted on).
func (c *automationCollector) Collect(ch chan<- prometheus.Metric) {
	snap, _ := c.snapshot()

	loginFailed := 0.0
	if snap.WriterLoginFailed {
		loginFailed = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.loginFailed, prometheus.GaugeValue, loginFailed)
	ch <- prometheus.MustNewConstMetric(c.pushes, prometheus.CounterValue, float64(snap.PushSuccess), "success")
	ch <- prometheus.MustNewConstMetric(c.pushes, prometheus.CounterValue, float64(snap.PushPermanent), "permanent")
	ch <- prometheus.MustNewConstMetric(c.pushes, prometheus.CounterValue, float64(snap.PushDropped), "dropped")
}

var (
	metricsOnce    sync.Once
	metricsHandler http.Handler
)

// prometheusHTTPHandler builds (once) the dedicated registry + its HTTP
// handler. The collector reads the global automation manager live, so the
// handler needs no per-request wiring.
func prometheusHTTPHandler() http.Handler {
	metricsOnce.Do(func() {
		reg := prometheus.NewRegistry()
		reg.MustRegister(newAutomationCollector(automationSnapshotFromGlobal))
		metricsHandler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	})
	return metricsHandler
}

// prometheusMetrics is the GET /metrics handler. Auth is applied by the
// HardAuthMiddleware group in routes.go — reaching here means the caller
// presented a valid session or service-account token.
func (h *Handler) prometheusMetrics(w http.ResponseWriter, r *http.Request) {
	prometheusHTTPHandler().ServeHTTP(w, r)
}
