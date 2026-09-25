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

// TestRouteCheck_ClientGoneDuringReload reproduces the field report: a
// UI reached through Arenet over HTTP/3 loses its connection on every
// Caddy reload (the request context is canceled mid-save). The check
// and the rollback must still run to completion.
func TestRouteCheck_ClientGoneDuringReload(t *testing.T) {
	env := newTestEnv(t, false)
	prober := &upstreamProber{broken: map[string]bool{upB: true}}
	env.handler.SetRouteProber(prober)
	seeded := seedRoute(t, env, upA)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.caddy.onReload = cancel // the connection dies during the first reload

	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+seeded.ID, strings.NewReader(routeJSON(upB))).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	env.router.ServeHTTP(httptest.NewRecorder(), req)
	env.caddy.onReload = nil

	if len(prober.calls) != 2 {
		t.Fatalf("the check must run despite the dead connection, probes: %v", prober.calls)
	}
	if got, _ := env.store.GetRoute(context.Background(), seeded.ID); got.Upstreams[0].URL != upA {
		t.Errorf("the broken change was not undone: stored %s", got.Upstreams[0].URL)
	}
}

// --- v2.43.1 — say which field broke the route -------------------
//
// The rollback message used to be unconditional: "fix the change
// (upstream address, port…)". When the 503 comes from the route's own
// active health check having just marked its upstreams down, that
// sentence points at the one thing that is not wrong. The 2026-09-24
// session followed it and lost an afternoon; the real cause — an
// expected-body regex that did not match the backend's JSON — was
// three fields away in the same form.

// hcStatusStub reports one fixed verdict for every upstream.
type hcStatusStub struct{ verdict string }

func (s hcStatusStub) Status(string) string { return s.verdict }

// serviceUnavailableProber fails the new upstream with a 503, the
// shape a reverse_proxy returns when no upstream is available.
type serviceUnavailableProber struct{ broken string }

func (p serviceUnavailableProber) Probe(_ context.Context, r storage.Route) routecheck.Result {
	if r.Upstreams[0].URL == p.broken {
		return routecheck.Result{
			Status: routecheck.StatusFailed, Host: r.Host,
			HTTPStatus: http.StatusServiceUnavailable,
			Detail:     "the route answered 503 Service Unavailable",
		}
	}
	return routecheck.Result{Status: routecheck.StatusOK, Host: r.Host, HTTPStatus: 200}
}

func routeJSONWithHealthCheck(upstream string) string {
	return `{"host":"app.local","upstreams":[{"url":"` + upstream + `","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],` +
		`"authMode":"none","wafMode":"off",` +
		`"healthCheck":{"enabled":true,"uri":"/healthz","method":"GET","interval":"30s",` +
		`"timeout":"5s","expectStatus":200,"expectBody":"OK","passes":2,"fails":3}}`
}

func rollbackDetails(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body struct {
		Code   string         `json:"code"`
		Error  string         `json:"error"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body: %v (%s)", err, rec.Body)
	}
	out := body.Params
	if out == nil {
		t.Fatalf("no params in %s", rec.Body)
	}
	out["__message"] = body.Error
	return out
}

func TestRouteCheck_RollbackBlamesTheHealthCheckWhenItIsTheCause(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetRouteProber(serviceUnavailableProber{broken: upB})
	env.handler.SetHCStatusReader(hcStatusStub{verdict: "unhealthy"})
	seeded := seedRoute(t, env, upA)

	rec := send(t, env, http.MethodPut, "/api/v1/routes/"+seeded.ID, routeJSONWithHealthCheck(upB))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}

	got := rollbackDetails(t, rec)
	if got["cause"] != causeHealthCheck {
		t.Fatalf("the probe marked every upstream down: cause must name it, got %v", got["cause"])
	}
	msg, _ := got["__message"].(string)
	// The operator must be sent to the fields that decide the probe,
	// not to the address that is fine.
	for _, want := range []string{"health check", "expected body"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message must mention %q: %s", want, msg)
		}
	}
}

// A 503 on a route with no health check is not the probe's doing, and
// blaming it would be its own wrong turn.
func TestRouteCheck_RollbackDoesNotBlameAnAbsentHealthCheck(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetRouteProber(serviceUnavailableProber{broken: upB})
	env.handler.SetHCStatusReader(hcStatusStub{verdict: "unhealthy"})
	seeded := seedRoute(t, env, upA)

	rec := send(t, env, http.MethodPut, "/api/v1/routes/"+seeded.ID, routeJSON(upB))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	if got := rollbackDetails(t, rec); got["cause"] != nil {
		t.Fatalf("no health check configured: nothing to blame, got %v", got["cause"])
	}
}

// The probe is enabled but the tracker has not reported a verdict.
//
// v2.45.1 — this used to assert silence, and the operator's smoke
// showed why that was wrong: pointing a probe at /toto produced a 503
// and the generic "check the upstream address" message, because the
// tracker learns of a transition from a Caddy event that can land
// after the post-apply check has already run — and a freshly changed
// upstream has no history at all, by construction.
//
// So the answer is neither silence nor a confident accusation: name
// both places to look, and say which is which.
func TestRouteCheck_RollbackNamesBothWhenTheProbeHasNotReported(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetRouteProber(serviceUnavailableProber{broken: upB})
	env.handler.SetHCStatusReader(hcStatusStub{verdict: ""})
	seeded := seedRoute(t, env, upA)

	rec := send(t, env, http.MethodPut, "/api/v1/routes/"+seeded.ID, routeJSONWithHealthCheck(upB))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	got := rollbackDetails(t, rec)
	if got["cause"] != causeMaybeHealthCheck {
		t.Fatalf("an unreported probe is a candidate, not a verdict: got %v", got["cause"])
	}
	msg, _ := got["__message"].(string)
	// Both suspects named, neither asserted.
	for _, want := range []string{"backend itself", "health check", "expected body"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message must mention %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "has marked the upstreams down") {
		t.Errorf("no verdict was recorded, so none may be claimed: %s", msg)
	}
}

// --- v2.46 — refusals carry a code the UI can translate ----------
//
// Arenet used to answer refusals as English sentences and the frontend
// printed them verbatim, so an operator working in French met English
// at exactly the moments that matter. The body now carries a stable
// code and its parameters; the sentence stays as the fallback for a
// code the frontend does not know yet.

func TestRouteRefusal_CarriesACodeAndParams(t *testing.T) {
	env := newTestEnv(t, false)

	// A redirect pointing back at the route's own host.
	body := `{"host":"loop.local","upstreams":[{"url":"` + upA + `","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],` +
		`"authMode":"none","wafMode":"off",` +
		`"redirectConfig":{"target":"https://loop.local"}}`
	rec := send(t, env, http.MethodPost, "/api/v1/routes", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}

	var got struct {
		Error  string            `json:"error"`
		Code   string            `json:"code"`
		Params map[string]string `json:"params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Code != "redirect_self_loop" {
		t.Fatalf("code: %q (body %s)", got.Code, rec.Body.String())
	}
	if got.Params["host"] != "loop.local" {
		t.Errorf("the host must travel as a parameter, not only inside the sentence: %v", got.Params)
	}
	// The English sentence stays, so a frontend without the
	// translation still shows something readable.
	if !strings.Contains(got.Error, "loop.local") {
		t.Errorf("the fallback sentence must survive: %q", got.Error)
	}
}

// An uncoded refusal must keep the body it always had: that is what
// makes adopting this one message at a time safe.
func TestRouteRefusal_UncodedKeepsTheOldShape(t *testing.T) {
	env := newTestEnv(t, false)

	rec := send(t, env, http.MethodPost, "/api/v1/routes",
		`{"host":"","upstreams":[],"authMode":"none","wafMode":"off"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if _, hasCode := got["code"]; hasCode {
		t.Errorf("an uncoded refusal must not invent a code: %v", got)
	}
	if _, hasErr := got["error"]; !hasErr {
		t.Errorf("the sentence must still be there: %v", got)
	}
}
