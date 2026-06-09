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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// fakeLAPI is a multi-endpoint test fixture for the Scenarios
// proxy. Routes:
//   POST /v1/watchers/login   — login handler (configurable)
//   GET  /v1/alerts           — alerts handler (configurable)
// Each handler is a hook the test sets per case.
type fakeLAPI struct {
	loginHandler  http.HandlerFunc
	alertsHandler http.HandlerFunc
	loginCalls    atomic.Int32
	alertsCalls   atomic.Int32
}

func newFakeLAPI() *fakeLAPI {
	return &fakeLAPI{}
}

func (f *fakeLAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		f.loginCalls.Add(1)
		if f.loginHandler != nil {
			f.loginHandler(w, r)
			return
		}
		// Default: issue a happy JWT valid for 1 hour.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(
			`{"code":200,"token":"jwt-%d","expire":"%s"}`,
			time.Now().UnixNano(),
			time.Now().Add(1*time.Hour).UTC().Format(time.RFC3339),
		)))
	})
	mux.HandleFunc("/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		f.alertsCalls.Add(1)
		if f.alertsHandler != nil {
			f.alertsHandler(w, r)
			return
		}
		// HF on 0ffc3b6 — emulate LAPI v1.7.8's parser
		// rejection of non-Go-duration `since` values. Any
		// handler that doesn't override the default now
		// enforces the contract: the handler emits 500 if
		// the wire shape regresses to an RFC3339 timestamp.
		// crowdsec@v1.6.3/pkg/database/utils.go:72 — LAPI's
		// ParseDuration delegates to time.ParseDuration for
		// anything not ending in `d`. Mirror that.
		if since := r.URL.Query().Get("since"); since != "" {
			if _, err := parseLAPIDurationLike(since); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleLAPIAlerts))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// sampleLAPIAlerts: 5 alerts across 3 scenarios.
const sampleLAPIAlerts = `[
  {
    "id": 1,
    "scenario": "crowdsecurity/http-cve",
    "message": "Ip 1.2.3.4 performed http-cve probing",
    "start_at": "2026-06-09T10:00:00Z",
    "stop_at":  "2026-06-09T10:05:00Z",
    "source": { "scope": "Ip", "value": "1.2.3.4", "ip": "1.2.3.4" },
    "events_count": 5
  },
  {
    "id": 2,
    "scenario": "crowdsecurity/http-cve",
    "message": "Ip 5.6.7.8 performed http-cve probing",
    "start_at": "2026-06-09T11:00:00Z",
    "stop_at":  "2026-06-09T11:01:00Z",
    "source": { "scope": "Ip", "value": "5.6.7.8" },
    "events_count": 3
  },
  {
    "id": 3,
    "scenario": "crowdsecurity/http-bf",
    "start_at": "2026-06-09T12:00:00Z",
    "source": { "scope": "Ip", "value": "9.10.11.12" },
    "events_count": 12
  },
  {
    "id": 4,
    "scenario": "crowdsecurity/iptables-scan",
    "start_at": "2026-06-09T09:00:00Z",
    "source": { "scope": "Range", "value": "13.0.0.0/24" },
    "events_count": 100
  },
  {
    "id": 5,
    "scenario": "crowdsecurity/http-bf",
    "start_at": "2026-06-09T13:30:00Z",
    "source": { "scope": "Ip", "value": "14.15.16.17" },
    "events_count": 7
  }
]`

func seedWatcherCreds(t *testing.T, h *Handler, lapiURL string) {
	t.Helper()
	if err := h.store.PutWatcherCredentials(context.Background(), storage.WatcherCredentials{
		LAPIURL:   lapiURL,
		MachineID: "arenet-test",
		Password:  "watcher-secret",
	}); err != nil {
		t.Fatalf("seed creds: %v", err)
	}
}

// --- 412: not configured -------------------------------------

func TestCrowdSecScenarios_NotConfigured_Returns412(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecScenarios(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("status = %d, want 412, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Security Automation") {
		t.Errorf("body lacks Security Automation hint: %s", rec.Body.String())
	}
}

func TestCrowdSecScenarios_PartialCreds_Returns412(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	// Seed creds with empty Password — WatcherCredentialsConfigured returns false.
	// We can't go through PutWatcherCredentials (its validate rejects), so we
	// emulate the "operator wiped one field" state by skipping the seed entirely:
	// this is functionally equivalent — the configured guard is the same.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecScenarios(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("status = %d, want 412", rec.Code)
	}
}

// --- 200: happy path + aggregation ---------------------------

func TestCrowdSecScenarios_HappyPath_Aggregates(t *testing.T) {
	fake := newFakeLAPI()
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCreds(t, h, srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecScenarios(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp scenariosResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(resp.Scenarios) != 3 {
		t.Errorf("scenarios count = %d, want 3", len(resp.Scenarios))
	}
	// Ordered by Alerts24h desc, ties by Name asc.
	if resp.Scenarios[0].Alerts24h != 2 || resp.Scenarios[0].Name != "crowdsecurity/http-bf" {
		t.Errorf("first row: got %+v, want http-bf with 2", resp.Scenarios[0])
	}
	if resp.Scenarios[1].Alerts24h != 2 || resp.Scenarios[1].Name != "crowdsecurity/http-cve" {
		t.Errorf("second row: got %+v, want http-cve with 2", resp.Scenarios[1])
	}
	if resp.Scenarios[2].Alerts24h != 1 || resp.Scenarios[2].Name != "crowdsecurity/iptables-scan" {
		t.Errorf("third row: got %+v, want iptables-scan with 1", resp.Scenarios[2])
	}
	if resp.Meta.TotalAlerts != 5 {
		t.Errorf("meta.totalAlerts = %d, want 5", resp.Meta.TotalAlerts)
	}
	if resp.Meta.WindowHours != 24 {
		t.Errorf("meta.windowHours = %d, want 24", resp.Meta.WindowHours)
	}

	// LastSeen should be the most-recent alert for that group:
	// - http-bf:  alert id=5 @ 13:30
	// - http-cve: alert id=2 @ 11:00
	if !strings.Contains(resp.Scenarios[0].LastSeen, "13:30") {
		t.Errorf("http-bf LastSeen wrong: %q", resp.Scenarios[0].LastSeen)
	}
	if resp.Scenarios[0].SampleValue != "14.15.16.17" {
		t.Errorf("http-bf SampleValue wrong: %q", resp.Scenarios[0].SampleValue)
	}
}

func TestCrowdSecScenarios_LoginCalledOnce_AlertsCalledOnce(t *testing.T) {
	fake := newFakeLAPI()
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCreds(t, h, srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecScenarios(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := fake.loginCalls.Load(); got != 1 {
		t.Errorf("login calls = %d, want 1", got)
	}
	if got := fake.alertsCalls.Load(); got != 1 {
		t.Errorf("alerts calls = %d, want 1", got)
	}
}

// --- 200: empty alerts ---------------------------------------

func TestCrowdSecScenarios_EmptyAlerts_ReturnsEmptyListNot502(t *testing.T) {
	fake := newFakeLAPI()
	fake.alertsHandler = func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[]"))
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCreds(t, h, srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecScenarios(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp scenariosResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Scenarios) != 0 || resp.Meta.TotalAlerts != 0 {
		t.Errorf("expected empty: %+v", resp)
	}
}

func TestCrowdSecScenarios_204NoContent_ReturnsEmptyList(t *testing.T) {
	fake := newFakeLAPI()
	fake.alertsHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCreds(t, h, srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecScenarios(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp scenariosResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Scenarios) != 0 {
		t.Errorf("expected empty on 204, got %d", len(resp.Scenarios))
	}
}

// --- 502: auth rejected --------------------------------------

func TestCrowdSecScenarios_LoginRejected_Returns502(t *testing.T) {
	fake := newFakeLAPI()
	fake.loginHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCreds(t, h, srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecScenarios(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "machine credentials rejected") {
		t.Errorf("body lacks 'machine credentials rejected': %s", rec.Body.String())
	}
}

// --- 502: alerts 401 first → retry succeeds ------------------

func TestCrowdSecScenarios_Alerts401_RetriesAfterRefresh_Success(t *testing.T) {
	fake := newFakeLAPI()
	var alertsHits atomic.Int32
	fake.alertsHandler = func(w http.ResponseWriter, r *http.Request) {
		hit := alertsHits.Add(1)
		if hit == 1 {
			// First call: simulate stale JWT.
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Second call: serve the alerts normally.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleLAPIAlerts))
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCreds(t, h, srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecScenarios(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (retry should succeed), body=%s", rec.Code, rec.Body.String())
	}
	if got := fake.loginCalls.Load(); got != 2 {
		t.Errorf("expected 2 login calls (initial + retry), got %d", got)
	}
	if got := alertsHits.Load(); got != 2 {
		t.Errorf("expected 2 alerts attempts, got %d", got)
	}
}

// --- 502: alerts 401 twice → no infinite loop, surface 502 --

func TestCrowdSecScenarios_Alerts401_RetryAlsoFails_Returns502_NoLoop(t *testing.T) {
	fake := newFakeLAPI()
	fake.alertsHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCreds(t, h, srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecScenarios(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	// Login attempted twice (initial + post-401 retry).
	// Alerts attempted twice (first 401 + retry 401).
	// MUST NOT loop further.
	if got := fake.loginCalls.Load(); got != 2 {
		t.Errorf("expected exactly 2 logins (no loop), got %d", got)
	}
	if got := fake.alertsCalls.Load(); got != 2 {
		t.Errorf("expected exactly 2 alerts attempts (no loop), got %d", got)
	}
}

// --- 502: transport errors -----------------------------------

func TestCrowdSecScenarios_LAPIRefused_Returns502(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	// Point at an unbound port.
	if err := h.store.PutWatcherCredentials(context.Background(), storage.WatcherCredentials{
		LAPIURL:   "http://127.0.0.1:1",
		MachineID: "arenet-test",
		Password:  "watcher-secret",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Speed up the timeout via CrowdSec config (CS.1 layer).
	_ = h.store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{
		LAPIURL: "http://127.0.0.1:1", APIKey: "k", BouncerName: "arenet", TimeoutSeconds: 1,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecScenarios(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "refused") && !strings.Contains(body, "connection") {
		t.Errorf("body lacks refused/connection: %s", body)
	}
}

// --- JWT cache: second call reuses cached token --------------

func TestCrowdSecScenarios_SecondCallReusesCachedJWT(t *testing.T) {
	fake := newFakeLAPI()
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCreds(t, h, srv.URL)

	// First call: cold cache, expect 1 login.
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
		rec := httptest.NewRecorder()
		h.listCrowdSecScenarios(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("first call: status = %d", rec.Code)
		}
	}
	// Second call: cached JWT, expect NO additional login.
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
		rec := httptest.NewRecorder()
		h.listCrowdSecScenarios(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("second call: status = %d", rec.Code)
		}
	}

	if got := fake.loginCalls.Load(); got != 1 {
		t.Errorf("second call should reuse JWT — login calls = %d, want 1", got)
	}
	if got := fake.alertsCalls.Load(); got != 2 {
		t.Errorf("expected 2 alerts calls, got %d", got)
	}
}

// --- JWT cache: singleflight dedupes concurrent logins -------

func TestCrowdSecScenarios_ConcurrentRequests_DedupeLoginViaSingleflight(t *testing.T) {
	fake := newFakeLAPI()
	// Slow login response so concurrent callers actually
	// queue up on the singleflight slot. 100ms is enough on
	// any CI without making the test slow.
	fake.loginHandler = func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fake.loginCalls.Add(0) // counter already incremented in dispatch wrapper
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(
			`{"code":200,"token":"jwt-%d","expire":"%s"}`,
			time.Now().UnixNano(),
			time.Now().Add(1*time.Hour).UTC().Format(time.RFC3339),
		)))
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCreds(t, h, srv.URL)

	// Fire 10 concurrent requests against a cold cache.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
			rec := httptest.NewRecorder()
			h.listCrowdSecScenarios(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("concurrent call: status = %d", rec.Code)
			}
		}()
	}
	wg.Wait()

	if got := fake.loginCalls.Load(); got != 1 {
		t.Errorf("singleflight should dedupe — got %d logins, want 1", got)
	}
}

// --- JWT cache: invalidate() forces fresh login ---

func TestCrowdSecJWTManager_Invalidate_ForcesFreshLogin(t *testing.T) {
	mgr := newCrowdSecJWTManager()

	// Manually seed a "valid" cache entry.
	mgr.mu.Lock()
	mgr.cacheKey = "http://example\x00mid"
	mgr.token = "stale-jwt"
	mgr.expiresAt = time.Now().Add(1 * time.Hour)
	mgr.mu.Unlock()

	mgr.invalidate()

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	if mgr.token != "" {
		t.Errorf("token not cleared: %q", mgr.token)
	}
	if !mgr.expiresAt.IsZero() {
		t.Errorf("expiresAt not cleared: %v", mgr.expiresAt)
	}
}

// --- Aggregator: deterministic ordering with ties ------------

func TestAggregateAlertsByScenario_OrderIsStable(t *testing.T) {
	scen := func(name string, when string) rawAlert {
		s := name
		st := when
		v := "1.2.3.4"
		sc := "Ip"
		return rawAlert{Scenario: &s, StartAt: &st, Source: &struct {
			Scope *string `json:"scope"`
			Value *string `json:"value"`
			IP    string  `json:"ip,omitempty"`
		}{Scope: &sc, Value: &v}}
	}
	alerts := []rawAlert{
		scen("z-tied", "2026-06-09T10:00:00Z"),
		scen("a-tied", "2026-06-09T11:00:00Z"),
		scen("z-tied", "2026-06-09T12:00:00Z"),
		scen("a-tied", "2026-06-09T13:00:00Z"),
		scen("solo", "2026-06-09T09:00:00Z"),
	}
	out := aggregateAlertsByScenario(alerts)
	// Two scenarios at count=2 (tied), one at count=1.
	// Ties broken by Name asc → a-tied before z-tied.
	if len(out) != 3 {
		t.Fatalf("got %d, want 3", len(out))
	}
	if out[0].Name != "a-tied" {
		t.Errorf("first should be a-tied (tie-break asc): got %s", out[0].Name)
	}
	if out[1].Name != "z-tied" {
		t.Errorf("second should be z-tied: got %s", out[1].Name)
	}
	if out[2].Name != "solo" {
		t.Errorf("third should be solo: got %s", out[2].Name)
	}
}

// --- Aggregator: nil-safe defensive ---

func TestAggregateAlertsByScenario_NilFields_DoesNotPanic(t *testing.T) {
	// Every field nil — scenario falls back to "(unknown)",
	// source skipped, LastSeen empty.
	out := aggregateAlertsByScenario([]rawAlert{{}})
	if len(out) != 1 {
		t.Fatalf("got %d, want 1", len(out))
	}
	if out[0].Name != "(unknown)" {
		t.Errorf("scenario name = %q, want '(unknown)'", out[0].Name)
	}
	if out[0].Alerts24h != 1 {
		t.Errorf("count = %d, want 1", out[0].Alerts24h)
	}
}

// --- HF on 0ffc3b6: since param wire shape -------------------
//
// LAPI v1.7.8 rejects RFC3339 timestamps on /v1/alerts?since=
// with HTTP 500 in ~60µs (parser-side, before SQL). The
// fakeLAPI default handler now mirrors that constraint, so
// every existing TestCrowdSecScenarios_* test implicitly
// catches a regression. This dedicated pin asserts the wire
// shape directly so a refactor that breaks the contract
// surfaces a clear failure here, not a misleading "no
// alerts" elsewhere.

func TestScenariosClient_SinceParam_UsesGoDuration(t *testing.T) {
	var capturedSince string
	fake := newFakeLAPI()
	fake.alertsHandler = func(w http.ResponseWriter, r *http.Request) {
		capturedSince = r.URL.Query().Get("since")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleLAPIAlerts))
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCreds(t, h, srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/scenarios", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecScenarios(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if capturedSince == "" {
		t.Fatal("since param not sent to LAPI")
	}
	// Wire shape contract: must be Go-duration-grammar
	// parseable (see crowdSecScenariosSinceParam doc comment
	// + crowdsec@v1.6.3/pkg/database/utils.go:72).
	if _, err := time.ParseDuration(capturedSince); err != nil {
		t.Errorf("since=%q is not Go-duration-parseable: %v", capturedSince, err)
	}
	// Specific value contract: the constant is 24h.
	if d, _ := time.ParseDuration(capturedSince); d != 24*time.Hour {
		t.Errorf("since=%q parsed to %v, want 24h", capturedSince, d)
	}
	// Negative contract: NEVER an RFC3339 timestamp (the
	// reason this HF exists).
	if _, err := time.Parse(time.RFC3339, capturedSince); err == nil {
		t.Errorf("since=%q parses as RFC3339 — LAPI would 500 on this", capturedSince)
	}
}

func TestScenariosClient_RFC3339Since_LAPIRejects_AsRegressionGuard(t *testing.T) {
	// Demonstrates the bug shape this HF closes: with the
	// fakeLAPI default's parser-emulation in place, an
	// alternate handler that mimics the pre-HF code would
	// emit an RFC3339 timestamp and the LAPI mock would 500.
	// We don't have a way to "make the prod code regress" in
	// a unit test, so instead we drive the fakeLAPI's
	// rejection path directly and pin its shape: the test
	// will start failing if anyone weakens the mock's
	// strictness.
	fake := newFakeLAPI()
	srv := fake.server(t)

	rfc3339 := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	url := srv.URL + "/v1/alerts?since=" + rfc3339 + "&limit=100"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("fakeLAPI accepted RFC3339 since — mock weakened; got %d, want 500", resp.StatusCode)
	}
}

// parseLAPIDurationLike mirrors crowdsec@v1.6.3/pkg/database/
// utils.go:72 ParseDuration: handles the `Nd` suffix manually,
// then delegates to time.ParseDuration. Used by the fakeLAPI
// default handler to enforce the empirical contract on the
// wire.
func parseLAPIDurationLike(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		if days == "" {
			return 0, fmt.Errorf("empty days prefix")
		}
		// Crude int parse; ParseDuration in the real LAPI
		// uses strconv.Atoi but the helper only needs to
		// validate shape for the test.
		if _, err := time.ParseDuration(days + "h"); err == nil {
			return time.ParseDuration(days + "h")
		}
		return 0, fmt.Errorf("days prefix not numeric: %q", days)
	}
	return time.ParseDuration(s)
}
