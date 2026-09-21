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
	"strings"
	"sync"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/routecheck"
	"github.com/barto95100/arenet/internal/storage"
)

// upstreamProber answers per first upstream URL: listed URLs fail
// (502), the rest are ok.
type upstreamProber struct {
	mu     sync.Mutex
	broken map[string]bool
	calls  []string
}

func (p *upstreamProber) Probe(_ context.Context, r storage.Route) routecheck.Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	u := r.Upstreams[0].URL
	p.calls = append(p.calls, u)
	if p.broken[u] {
		return routecheck.Result{Status: routecheck.StatusFailed, Host: r.Host, HTTPStatus: 502, Detail: "the route answered 502 Bad Gateway"}
	}
	return routecheck.Result{Status: routecheck.StatusOK, Host: r.Host, HTTPStatus: 200}
}

const upA, upB = "http://127.0.0.1:9001", "http://127.0.0.1:9002"

func routeJSON(upstream string) string {
	return `{"host":"app.local","upstreams":[{"url":"` + upstream + `","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"none","wafMode":"off"}`
}

func send(t *testing.T, env *testEnv, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func checkOf(t *testing.T, rec *httptest.ResponseRecorder) routecheck.Result {
	t.Helper()
	var resp struct {
		ID    string             `json:"id"`
		Check *routecheck.Result `json:"check"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Check == nil {
		t.Fatalf("no check in response: %s", rec.Body)
	}
	return *resp.Check
}

func seedRoute(t *testing.T, env *testEnv, upstream string) storage.Route {
	t.Helper()
	r, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "app.local", Upstreams: []storage.Upstream{{URL: upstream, Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return r
}

func TestRouteCheck_CreateIsReportedNeverUndone(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetRouteProber(&upstreamProber{broken: map[string]bool{upA: true}})
	rec := send(t, env, http.MethodPost, "/api/v1/routes", routeJSON(upA))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	if c := checkOf(t, rec); c.Status != routecheck.StatusFailed || c.HTTPStatus != 502 {
		t.Errorf("check %+v", c)
	}
	if routes, _ := env.store.ListRoutes(context.Background()); len(routes) != 1 {
		t.Errorf("a failed creation must be kept, got %d routes", len(routes))
	}
}

func TestRouteCheck_UpdateThatBreaksAWorkingRouteIsUndone(t *testing.T) {
	env := newTestEnv(t, false)
	prober := &upstreamProber{broken: map[string]bool{upB: true}}
	env.handler.SetRouteProber(prober)
	seeded := seedRoute(t, env, upA)

	rec := send(t, env, http.MethodPut, "/api/v1/routes/"+seeded.ID, routeJSON(upB))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), codeRouteCheckRolledBack) {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), seeded.ID)
	if got.Upstreams[0].URL != upA {
		t.Errorf("stored upstream %s, want the previous %s", got.Upstreams[0].URL, upA)
	}
	if strings.Join(prober.calls, ",") != upB+","+upA {
		t.Errorf("probes %v, want new then previous", prober.calls)
	}
	var audited bool
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionRouteUpdateRolledBack && e.TargetID == seeded.ID {
			audited = true
		}
	}
	if !audited {
		t.Error("rollback not audited")
	}
}

func TestRouteCheck_UpdateKeptWhenThePreviousFailsToo(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetRouteProber(&upstreamProber{broken: map[string]bool{upA: true, upB: true}})
	seeded := seedRoute(t, env, upA)

	rec := send(t, env, http.MethodPut, "/api/v1/routes/"+seeded.ID, routeJSON(upB))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	if c := checkOf(t, rec); c.Status != routecheck.StatusFailed {
		t.Errorf("check %+v", c)
	}
	if got, _ := env.store.GetRoute(context.Background(), seeded.ID); got.Upstreams[0].URL != upB {
		t.Errorf("the change must be re-applied, stored %s", got.Upstreams[0].URL)
	}
}

func TestRouteCheck_DisabledSettingSkips(t *testing.T) {
	env := newTestEnv(t, false)
	prober := &upstreamProber{broken: map[string]bool{upB: true}}
	env.handler.SetRouteProber(prober)
	seeded := seedRoute(t, env, upA)

	rec := send(t, env, http.MethodPut, "/api/v1/settings/route-check", `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put setting %d %s", rec.Code, rec.Body)
	}
	if rec := send(t, env, http.MethodGet, "/api/v1/settings/route-check", ""); !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Errorf("get setting %s", rec.Body)
	}
	rec = send(t, env, http.MethodPut, "/api/v1/routes/"+seeded.ID, routeJSON(upB))
	if rec.Code != http.StatusOK || checkOf(t, rec).Status != routecheck.StatusSkipped || len(prober.calls) != 0 {
		t.Errorf("disabled check: %d %s calls=%v", rec.Code, rec.Body, prober.calls)
	}
}

func TestRouteCheck_EnableIsReported(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetRouteProber(&upstreamProber{broken: map[string]bool{upA: true}})
	seeded := seedRoute(t, env, upA)
	if rec := send(t, env, http.MethodPost, "/api/v1/routes/"+seeded.ID+"/disable", ""); rec.Code != http.StatusOK {
		t.Fatalf("disable %d %s", rec.Code, rec.Body)
	}
	rec := send(t, env, http.MethodPost, "/api/v1/routes/"+seeded.ID+"/enable", "")
	if rec.Code != http.StatusOK || checkOf(t, rec).Status != routecheck.StatusFailed {
		t.Fatalf("enable %d %s", rec.Code, rec.Body)
	}
	if got, _ := env.store.GetRoute(context.Background(), seeded.ID); got.Disabled {
		t.Error("re-enabling must never be undone")
	}
}

func TestRouteCheck_NoProberSkips(t *testing.T) {
	env := newTestEnv(t, false)
	rec := send(t, env, http.MethodPost, "/api/v1/routes", routeJSON(upA))
	if rec.Code != http.StatusCreated || checkOf(t, rec).Status != routecheck.StatusSkipped {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
