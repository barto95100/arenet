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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/certinfo"
	"github.com/barto95100/arenet/internal/storage"
)

// --- O.3 / Step O managed-domain API tests --------------------------------

// putManagedDomain is the test-side helper that POSTs a new
// managed domain via the public router (so the test exercises
// the full auth + chi routing + handler path).
func putManagedDomain(t *testing.T, env *testEnv, apex string, includeApex bool) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{
		"apex":        apex,
		"includeApex": includeApex,
		"provider":    "ovh",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/managed-domains", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

// TestManagedDomain_POST_Create_201_AndListReturnsIt pins the
// happy-path CRUD: create returns 201 with the wire shape, list
// includes the new row.
func TestManagedDomain_POST_Create_201_AndListReturnsIt(t *testing.T) {
	env := newTestEnv(t, false)

	rec := putManagedDomain(t, env, "example.com", true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s", rec.Code, rec.Body)
	}
	var got managedDomainResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Apex != "example.com" || !got.IncludeApex || got.Provider != "ovh" {
		t.Errorf("POST response = %+v", got)
	}

	// GET list — must include the new row.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/settings/managed-domains", nil)
	getRec := httptest.NewRecorder()
	env.router.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", getRec.Code, getRec.Body)
	}
	var list listManagedDomainsResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(list.Domains) != 1 || list.Domains[0].Apex != "example.com" {
		t.Errorf("GET list = %+v", list.Domains)
	}
}

// TestManagedDomain_POST_NormalisesApex pins that uppercase /
// trailing-dot input is canonicalised server-side.
func TestManagedDomain_POST_NormalisesApex(t *testing.T) {
	env := newTestEnv(t, false)

	rec := putManagedDomain(t, env, "Example.Com.", true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got managedDomainResponse
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Apex != "example.com" {
		t.Errorf("apex not canonicalised: %q", got.Apex)
	}
}

// TestManagedDomain_POST_IncludeApex_Default_True pins the
// D2.C default: when the operator omits `includeApex` from the
// payload, the API uses true.
func TestManagedDomain_POST_IncludeApex_Default_True(t *testing.T) {
	env := newTestEnv(t, false)

	// Send a payload WITHOUT includeApex.
	body := map[string]any{"apex": "example.com", "provider": "ovh"}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/managed-domains", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got managedDomainResponse
	json.Unmarshal(rec.Body.Bytes(), &got)
	if !got.IncludeApex {
		t.Errorf("includeApex default should be true per D2.C, got false")
	}
}

// TestManagedDomain_POST_Provider_Default_OVH pins the D3.B
// default value for the provider field when omitted.
func TestManagedDomain_POST_Provider_Default_OVH(t *testing.T) {
	env := newTestEnv(t, false)

	body := map[string]any{"apex": "example.com", "includeApex": true}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/managed-domains", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got managedDomainResponse
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Provider != "ovh" {
		t.Errorf("provider default should be ovh per D3.B, got %q", got.Provider)
	}
}

// TestManagedDomain_POST_Conflict_DuplicateApex pins the
// uniqueness rule (409).
func TestManagedDomain_POST_Conflict_DuplicateApex(t *testing.T) {
	env := newTestEnv(t, false)

	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("first POST: status=%d body=%s", rec.Code, rec.Body)
	}
	rec := putManagedDomain(t, env, "example.com", true)
	if rec.Code != http.StatusConflict {
		t.Errorf("duplicate apex: status=%d, want 409 — body=%s", rec.Code, rec.Body)
	}
}

// TestManagedDomain_POST_Conflict_Overlap pins the §5 risks
// "multi-domain overlap" rule: declaring a sub-apex when a
// covering wildcard already exists is rejected.
func TestManagedDomain_POST_Conflict_Overlap(t *testing.T) {
	env := newTestEnv(t, false)

	// Declare example.com first.
	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("seed: status=%d body=%s", rec.Code, rec.Body)
	}
	// app.example.com is already covered by *.example.com.
	rec := putManagedDomain(t, env, "app.example.com", true)
	if rec.Code != http.StatusConflict {
		t.Errorf("overlap should be rejected: status=%d body=%s", rec.Code, rec.Body)
	}
}

// TestManagedDomain_POST_Rejects_WildcardForm pins the storage
// validator forwarded as 400 (apex must be the bare domain).
func TestManagedDomain_POST_Rejects_WildcardForm(t *testing.T) {
	env := newTestEnv(t, false)

	rec := putManagedDomain(t, env, "*.example.com", true)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("wildcard form: status=%d, want 400", rec.Code)
	}
}

// TestManagedDomain_POST_Rejects_UnknownProvider pins the D3.B
// enum check at the API layer.
func TestManagedDomain_POST_Rejects_UnknownProvider(t *testing.T) {
	env := newTestEnv(t, false)

	body := map[string]any{"apex": "example.com", "includeApex": true, "provider": "cloudflare"}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/managed-domains", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown provider: status=%d, want 400 — body=%s", rec.Code, rec.Body)
	}
}

// TestManagedDomain_POST_RouteMigration_AtomicInheritedFlip is
// the central D8.A invariant at the API level: creating a
// managed domain rewrites every covered route's ACMEChallenge
// to "inherited" in one atomic operation.
func TestManagedDomain_POST_RouteMigration_AtomicInheritedFlip(t *testing.T) {
	env := newTestEnv(t, false)

	// Seed a route on app.example.com — covered once example.com
	// is declared.
	covered, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	if err != nil {
		t.Fatalf("seed covered: %v", err)
	}
	// Seed an uncovered route too, as a control.
	uncovered, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "other.org",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	if err != nil {
		t.Fatalf("seed uncovered: %v", err)
	}

	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("POST: status=%d body=%s", rec.Code, rec.Body)
	}

	// Verify the covered route was flipped.
	cAfter, _ := env.store.GetRoute(context.Background(), covered.ID)
	if cAfter.ACMEChallenge != storage.ACMEChallengeInherited {
		t.Errorf("covered route ACMEChallenge = %q, want %q",
			cAfter.ACMEChallenge, storage.ACMEChallengeInherited)
	}
	// Uncovered route untouched.
	uAfter, _ := env.store.GetRoute(context.Background(), uncovered.ID)
	if uAfter.ACMEChallenge == storage.ACMEChallengeInherited {
		t.Errorf("uncovered route should NOT be flipped")
	}
}

// TestManagedDomain_DELETE_RevertTo_Default pins AC #21 default:
// no revertTo query param → routes revert to "" (project default
// → HTTP-01 on next reload).
func TestManagedDomain_DELETE_RevertTo_Default(t *testing.T) {
	env := newTestEnv(t, false)

	// Seed a covered route + the managed domain.
	covered, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("seed: status=%d body=%s", rec.Code, rec.Body)
	}

	// DELETE with no revertTo query param.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/settings/managed-domains/example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", rec.Code, rec.Body)
	}
	var delResp deleteManagedDomainResponse
	json.Unmarshal(rec.Body.Bytes(), &delResp)
	if delResp.MutatedRoutes != 1 {
		t.Errorf("mutatedRoutes = %d, want 1", delResp.MutatedRoutes)
	}

	// Covered route should now have ACMEChallenge="".
	cAfter, _ := env.store.GetRoute(context.Background(), covered.ID)
	if cAfter.ACMEChallenge != "" {
		t.Errorf("covered route ACMEChallenge = %q, want \"\" (default revert)", cAfter.ACMEChallenge)
	}
}

// TestManagedDomain_DELETE_RevertTo_DNS01 pins AC #21 explicit
// choice: revertTo=dns-01 lands on the covered routes.
func TestManagedDomain_DELETE_RevertTo_DNS01(t *testing.T) {
	env := newTestEnv(t, false)

	covered, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("seed: status=%d body=%s", rec.Code, rec.Body)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/settings/managed-domains/example.com?revertTo=dns-01", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", rec.Code, rec.Body)
	}
	cAfter, _ := env.store.GetRoute(context.Background(), covered.ID)
	if cAfter.ACMEChallenge != storage.ACMEChallengeDNS01 {
		t.Errorf("covered route ACMEChallenge = %q, want dns-01 (operator-chosen)", cAfter.ACMEChallenge)
	}
}

// TestManagedDomain_DELETE_RevertTo_Unknown_400 pins the AC #21
// input validation: an unknown revertTo value is rejected.
func TestManagedDomain_DELETE_RevertTo_Unknown_400(t *testing.T) {
	env := newTestEnv(t, false)
	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("seed: status=%d body=%s", rec.Code, rec.Body)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/settings/managed-domains/example.com?revertTo=foo", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown revertTo: status=%d, want 400 — body=%s", rec.Code, rec.Body)
	}
}

// TestManagedDomain_DELETE_NotFound_404 pins the absence path.
func TestManagedDomain_DELETE_NotFound_404(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/settings/managed-domains/missing.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("missing managed-domain: status=%d, want 404", rec.Code)
	}
}

// TestManagedDomain_Audit_Created_CountsMutatedRoutes pins the
// audit event shape: ActionManagedDomainCreated carries the
// mutated-route count in the Message field.
func TestManagedDomain_Audit_Created_CountsMutatedRoutes(t *testing.T) {
	env := newTestEnv(t, false)

	for _, host := range []string{"a.example.com", "b.example.com"} {
		if _, err := env.store.CreateRoute(context.Background(), storage.Route{
			Host:      host,
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:8080", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
		}); err != nil {
			t.Fatalf("seed %s: %v", host, err)
		}
	}

	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("POST: status=%d body=%s", rec.Code, rec.Body)
	}

	found := false
	for _, e := range env.audit.events {
		if e.Action == audit.ActionManagedDomainCreated {
			if !strings.Contains(e.Message, "2") {
				t.Errorf("audit message should mention 2 mutated routes, got %q", e.Message)
			}
			if e.TargetID != "example.com" {
				t.Errorf("audit target_id = %q, want example.com", e.TargetID)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("ActionManagedDomainCreated audit event not emitted")
	}
}

// --- O.3 / Step O effectiveCertSource derived field ----------------------

// TestRouteResponse_EffectiveCertSource_ManagedDomain pins
// AC #4: a route covered by a managed domain reports
// "managed-domain:<apex>" on GET /routes/{id}.
func TestRouteResponse_EffectiveCertSource_ManagedDomain(t *testing.T) {
	env := newTestEnv(t, false)

	// Seed managed domain + a covered route. Use TLSEnabled=true
	// so EffectiveCertSource is computed (the field is zero for
	// TLSEnabled=false routes by design).
	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("seed md: status=%d body=%s", rec.Code, rec.Body)
	}
	rt, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host:       "app.example.com",
		Upstreams:  []storage.Upstream{{URL: "http://127.0.0.1:8080", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
		TLSEnabled: true,
	})
	// The managed-domain POST happened BEFORE the route create,
	// so the route's ACMEChallenge is at its default "". The
	// effectiveCertSource derivation uses the coverage predicate
	// (not the stored ACMEChallenge), so the result is the
	// wildcard label regardless.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes/"+rt.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got routeResponse
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.EffectiveCertSource != "managed-domain:example.com" {
		t.Errorf("effectiveCertSource = %q, want managed-domain:example.com",
			got.EffectiveCertSource)
	}
}

// TestRouteResponse_EffectiveCertSource_PerRouteACME pins the
// uncovered-route path: no managed domain → per-route ACME label.
func TestRouteResponse_EffectiveCertSource_PerRouteACME(t *testing.T) {
	env := newTestEnv(t, false)

	rt, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host:          "app.other.com",
		Upstreams:     []storage.Upstream{{URL: "http://127.0.0.1:8080", Weight: 1}},
		LBPolicy:      storage.LBPolicyRoundRobin,
		TLSEnabled:    true,
		ACMEChallenge: storage.ACMEChallengeDNS01,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes/"+rt.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	var got routeResponse
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.EffectiveCertSource != "per-route-acme:dns-01" {
		t.Errorf("effectiveCertSource = %q, want per-route-acme:dns-01",
			got.EffectiveCertSource)
	}
}

// TestRouteResponse_EffectiveCertSource_NoTLS_Empty pins that
// non-TLS routes don't emit the field (omitempty drops it).
func TestRouteResponse_EffectiveCertSource_NoTLS_Empty(t *testing.T) {
	env := newTestEnv(t, false)

	rt, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "app.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		// TLSEnabled: false (zero value).
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes/"+rt.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, `"effectiveCertSource"`) {
		t.Errorf("non-TLS route should not emit effectiveCertSource: %s", body)
	}
}

// TestRouteResponse_EffectiveCertSource_DedicatedOptOut pins
// D1.B: covered route with useDedicatedCert=true reports the
// per-route ACME label, not the wildcard.
func TestRouteResponse_EffectiveCertSource_DedicatedOptOut(t *testing.T) {
	env := newTestEnv(t, false)

	// Per-route dns-01 requires a configured DNS provider —
	// the wire shape is the J.4 cross-rule, not new in O. Seed
	// it so this test can exercise the OPT-OUT path rather than
	// the missing-provider rejection.
	seedDNSProvider(t, env.store)
	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("seed md: %v", rec.Body)
	}
	// Create route via the public API so the reconcileManagedDomainCoverage
	// path runs and the storage row reflects the operator's intent.
	body := map[string]any{
		"host":             "payments.example.com",
		"upstreams":        []map[string]any{{"url": "http://127.0.0.1:8080", "weight": 1}},
		"lbPolicy":         "round_robin",
		"tlsEnabled":       true,
		"acmeChallenge":    "dns-01",
		"useDedicatedCert": true,
	}
	raw, _ := json.Marshal(body)
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/routes", bytes.NewReader(raw))
	postReq.Header.Set("Content-Type", "application/json")
	postRec := httptest.NewRecorder()
	env.router.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusCreated {
		t.Fatalf("create route: status=%d body=%s", postRec.Code, postRec.Body)
	}
	var created routeResponse
	json.Unmarshal(postRec.Body.Bytes(), &created)
	if created.EffectiveCertSource != "per-route-acme:dns-01" {
		t.Errorf("dedicated opt-out: effectiveCertSource = %q, want per-route-acme:dns-01",
			created.EffectiveCertSource)
	}
}

// --- O.3 / Step O reconcileManagedDomainCoverage cross-rules --------------

// TestCreateRoute_CoveredHost_RewritesToInherited pins D8.A at
// the route POST: a covered host's ACMEChallenge is rewritten
// server-side regardless of the operator-supplied value.
func TestCreateRoute_CoveredHost_RewritesToInherited(t *testing.T) {
	env := newTestEnv(t, false)
	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("seed: %v", rec.Body)
	}

	// Operator submits acmeChallenge="dns-01" on a covered host
	// WITHOUT useDedicatedCert. Server rewrites to "inherited".
	body := map[string]any{
		"host":          "app.example.com",
		"upstreams":     []map[string]any{{"url": "http://127.0.0.1:8080", "weight": 1}},
		"lbPolicy":      "round_robin",
		"tlsEnabled":    true,
		"acmeChallenge": "dns-01",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ACMEChallenge != storage.ACMEChallengeInherited {
		t.Errorf("ACMEChallenge = %q, want %q (D8.A rewrite)",
			created.ACMEChallenge, storage.ACMEChallengeInherited)
	}
}

// TestCreateRoute_UncoveredHost_DedicatedOptOut_Rejects pins
// the defensive cross-rule: useDedicatedCert=true without a
// covering managed domain is a config error.
func TestCreateRoute_UncoveredHost_DedicatedOptOut_Rejects(t *testing.T) {
	env := newTestEnv(t, false)

	body := map[string]any{
		"host":             "app.other.com",
		"upstreams":        []map[string]any{{"url": "http://127.0.0.1:8080", "weight": 1}},
		"lbPolicy":         "round_robin",
		"tlsEnabled":       true,
		"acmeChallenge":    "dns-01",
		"useDedicatedCert": true,
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("dedicated opt-out without coverage: status=%d, want 400 — body=%s",
			rec.Code, rec.Body)
	}
}

// --- Step T tracker-purge tests (post-T.5 hotfix) -----------------------

// stubCertInfoPurger captures the Remove() calls the DELETE
// managed-domain handler issues so the test can assert which
// domains were purged. List() just returns whatever was seeded;
// the handler doesn't read it on the delete path.
type stubCertInfoPurger struct {
	removed []string
	present map[string]bool // when set, controls Remove return value
}

func (s *stubCertInfoPurger) List() []*certinfo.CertRuntimeInfo {
	return nil
}
func (s *stubCertInfoPurger) Remove(domain string) bool {
	s.removed = append(s.removed, domain)
	if s.present == nil {
		return true
	}
	return s.present[domain]
}

// TestManagedDomain_DELETE_PurgesTracker_IncludeApex pins the
// post-T.5 hotfix: when an apex with includeApex=true is deleted,
// the handler purges BOTH the wildcard ("*.<apex>") and the bare
// apex ("<apex>") from the certinfo tracker. certmagic / Caddy
// emit no cert-removal event so without this purge the OBTAIN_FAILED
// ghost rows linger in /certs.
func TestManagedDomain_DELETE_PurgesTracker_IncludeApex(t *testing.T) {
	env := newTestEnv(t, false)
	purger := &stubCertInfoPurger{}
	env.handler.SetCertInfoReader(purger)

	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("seed: status=%d body=%s", rec.Code, rec.Body)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/settings/managed-domains/example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", rec.Code, rec.Body)
	}

	wantDomains := []string{"*.example.com", "example.com"}
	if len(purger.removed) != len(wantDomains) {
		t.Fatalf("removed=%v want=%v", purger.removed, wantDomains)
	}
	for i, d := range wantDomains {
		if purger.removed[i] != d {
			t.Errorf("removed[%d]=%q want=%q", i, purger.removed[i], d)
		}
	}
}

// TestManagedDomain_DELETE_PurgesTracker_NoIncludeApex pins that
// when includeApex=false the handler purges ONLY the wildcard,
// not the bare apex (which never had a cert in the first place).
func TestManagedDomain_DELETE_PurgesTracker_NoIncludeApex(t *testing.T) {
	env := newTestEnv(t, false)
	purger := &stubCertInfoPurger{}
	env.handler.SetCertInfoReader(purger)

	if rec := putManagedDomain(t, env, "example.com", false); rec.Code != http.StatusCreated {
		t.Fatalf("seed: status=%d body=%s", rec.Code, rec.Body)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/settings/managed-domains/example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", rec.Code, rec.Body)
	}

	want := []string{"*.example.com"}
	if len(purger.removed) != len(want) || purger.removed[0] != want[0] {
		t.Fatalf("removed=%v want=%v", purger.removed, want)
	}
}

// TestManagedDomain_DELETE_NilPurger_NoCrash pins the
// nil-tolerance contract: when SetCertInfoReader was never called
// (test envs that skip the wiring; degraded prod with cert tracker
// boot failure) the DELETE handler still succeeds — the purge is
// an additive cleanup, not a precondition.
func TestManagedDomain_DELETE_NilPurger_NoCrash(t *testing.T) {
	env := newTestEnv(t, false)
	// Intentionally NOT calling SetCertInfoReader.

	if rec := putManagedDomain(t, env, "example.com", true); rec.Code != http.StatusCreated {
		t.Fatalf("seed: status=%d body=%s", rec.Code, rec.Body)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/settings/managed-domains/example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s (must succeed even without tracker wired)",
			rec.Code, rec.Body)
	}
}
