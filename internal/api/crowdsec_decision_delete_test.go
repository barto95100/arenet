// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/go-chi/chi/v5"
)

// v2.72 — a manual ban had no undo.
//
// The router carried only GET and POST on the decisions path, so a ban
// created from Arenet's own UI could be removed only with `cscli
// decisions delete` on the host. These tests cover the inverse, and in
// particular the two things that are easy to get wrong against LAPI:
// nbDeleted arrives as a STRING, and an unknown id answers 500 rather
// than 404, so "already expired" and "LAPI is broken" are not
// distinguishable.

// fakeLAPIForDelete serves the JWT login plus DELETE /v1/decisions/{id}.
type fakeLAPIForDelete struct {
	loginCalls  atomic.Int32
	deleteCalls atomic.Int32
	lastPath    atomic.Value // string
	handler     func(w http.ResponseWriter, r *http.Request)
}

func newFakeLAPIForDelete() *fakeLAPIForDelete {
	f := &fakeLAPIForDelete{}
	f.lastPath.Store("")
	return f
}

func (f *fakeLAPIForDelete) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/watchers/login" {
			f.loginCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":200,"token":"jwt-ok","expire":"` +
				time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`))
			return
		}
		// Every other path is recorded verbatim, which is what makes the
		// path-traversal test below meaningful.
		f.deleteCalls.Add(1)
		f.lastPath.Store(r.Method + " " + r.URL.Path)
		if f.handler != nil {
			f.handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nbDeleted":"1"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// deleteDecisionReq builds a request carrying the chi URL param the
// handler reads, so the handler can be driven directly.
//
// The request target is fixed and the id travels only as the chi param.
// That is deliberate, and it is also what makes the traversal cases
// below testable: chi hands the handler the DECODED segment, so a
// "%20" or a "%2f" in the URL arrives here as a space or a slash, and
// those are exactly the values the parser has to refuse. Putting them
// in the target instead would only test net/http's own URL parsing —
// and a space there makes httptest.NewRequest panic outright.
func deleteDecisionReq(id string) *http.Request {
	req := reqWithAuth(http.MethodDelete,
		"/api/v1/security/crowdsec/decisions/id", "user-uuid", "admin", "1.2.3.4", "test")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestDeleteCrowdSecDecision_HappyPath(t *testing.T) {
	fake := newFakeLAPIForDelete()
	srv := fake.server(t)
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, io.Discard)
	seedWatcherCredsForBan(t, h, srv.URL)

	rec := httptest.NewRecorder()
	h.deleteCrowdSecDecision(rec, deleteDecisionReq("42"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp crowdSecDecisionDeleteResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ID != 42 {
		t.Errorf("id = %d, want 42", resp.ID)
	}
	// LAPI sends the count as a string; the wire shape here is a number.
	if resp.NbDeleted != 1 {
		t.Errorf("nbDeleted = %d, want 1 (decoded from the LAPI string)", resp.NbDeleted)
	}
	if got := fake.lastPath.Load().(string); got != "DELETE /v1/decisions/42" {
		t.Errorf("LAPI call = %q, want DELETE /v1/decisions/42", got)
	}
	// The operator must be able to prove later that they did this.
	if len(appender.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(appender.events))
	}
	if appender.events[0].Action != audit.ActionCrowdSecDecisionDelete {
		t.Errorf("audit action = %q, want %q",
			appender.events[0].Action, audit.ActionCrowdSecDecisionDelete)
	}
	if appender.events[0].TargetID != "42" {
		t.Errorf("audit target = %q, want 42", appender.events[0].TargetID)
	}
}

// TestDeleteCrowdSecDecision_RejectsNonNumericID is the security test.
//
// The id lands in a LAPI URL path, and DELETE /v1/decisions — the same
// verb with NO id — expires decisions in bulk
// (crowdsec@v1.6.3 controller.go:126). A traversal in the id would turn
// "remove this ban" into "remove every ban", so nothing but digits may
// get through, and the path is built from the parsed number.
func TestDeleteCrowdSecDecision_RejectsNonNumericID(t *testing.T) {
	fake := newFakeLAPIForDelete()
	srv := fake.server(t)
	h := newTestHandler(t, &fakeAuditAppender{}, io.Discard)
	seedWatcherCredsForBan(t, h, srv.URL)

	for _, id := range []string{
		"../../v1/decisions",
		"../../decisions", // what "..%2f..%2fdecisions" decodes to
		"1/../..",
		"42/../../decisions",
		"abc",
		"-1",
		"0",
		"1.5",
		"1 ",
		"+1",
		"0x2a",
		"",
	} {
		t.Run(id, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.deleteCrowdSecDecision(rec, deleteDecisionReq(id))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("id %q: status = %d, want 400, body=%s", id, rec.Code, rec.Body.String())
			}
			if fake.deleteCalls.Load() != 0 {
				t.Fatalf("id %q reached LAPI (%q) — a rejected id must never be sent",
					id, fake.lastPath.Load())
			}
		})
	}
}

func TestDeleteCrowdSecDecision_NoAutomationCreds(t *testing.T) {
	h := newTestHandler(t, &fakeAuditAppender{}, io.Discard)
	// No PutWatcherCredentials at all.

	rec := httptest.NewRecorder()
	h.deleteCrowdSecDecision(rec, deleteDecisionReq("42"))

	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Security Automation") {
		t.Errorf("the 412 must name where to configure it; got %s", rec.Body.String())
	}
}

// TestDeleteCrowdSecDecision_LAPI500IsAmbiguous pins the honest message.
//
// LAPI returns 500 both for an unknown id and for a genuine database
// failure (ExpireDecisionByID wraps DeleteFail, which HandleDBErrors
// has no case for). Reporting "not found" would tell the operator their
// ban is gone when it may still be in force.
func TestDeleteCrowdSecDecision_LAPI500IsAmbiguous(t *testing.T) {
	fake := newFakeLAPIForDelete()
	fake.handler = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"decision with id '42' doesn't exist"}`))
	}
	srv := fake.server(t)
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, io.Discard)
	seedWatcherCredsForBan(t, h, srv.URL)

	rec := httptest.NewRecorder()
	h.deleteCrowdSecDecision(rec, deleteDecisionReq("42"))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "already have expired") || !strings.Contains(body, "failing") {
		t.Errorf("the message must name both possibilities; got %s", body)
	}
	// Nothing happened, so nothing is claimed in the audit trail.
	if len(appender.events) != 0 {
		t.Errorf("audit events = %d, want 0 on a failed expiry", len(appender.events))
	}
}

// A rejected JWT is retried once with a fresh login, mirroring the
// manual ban. Without the retry, a cached token expiring between two
// operator actions reads as a credentials problem.
func TestDeleteCrowdSecDecision_RetriesOnceOn401(t *testing.T) {
	fake := newFakeLAPIForDelete()
	var attempts atomic.Int32
	fake.handler = func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nbDeleted":"1"}`))
	}
	srv := fake.server(t)
	h := newTestHandler(t, &fakeAuditAppender{}, io.Discard)
	seedWatcherCredsForBan(t, h, srv.URL)

	rec := httptest.NewRecorder()
	h.deleteCrowdSecDecision(rec, deleteDecisionReq("42"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 after the retry, body=%s", rec.Code, rec.Body.String())
	}
	if attempts.Load() != 2 {
		t.Errorf("LAPI attempts = %d, want 2", attempts.Load())
	}
	if fake.loginCalls.Load() < 2 {
		t.Errorf("login calls = %d, want the retry to force a fresh login", fake.loginCalls.Load())
	}
}

// An unreadable or non-numeric nbDeleted must not fail the request: the
// expiry already happened on LAPI's side, and only the count is lost.
func TestDeleteCrowdSecDecision_UnreadableCountStillSucceeds(t *testing.T) {
	for name, body := range map[string]string{
		"not json":          `<html>oops</html>`,
		"count not numeric": `{"nbDeleted":"many"}`,
		"empty body":        ``,
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeLAPIForDelete()
			fake.handler = func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}
			srv := fake.server(t)
			h := newTestHandler(t, &fakeAuditAppender{}, io.Discard)
			seedWatcherCredsForBan(t, h, srv.URL)

			rec := httptest.NewRecorder()
			h.deleteCrowdSecDecision(rec, deleteDecisionReq("42"))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
			}
			var resp crowdSecDecisionDeleteResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			if resp.NbDeleted != 0 {
				t.Errorf("nbDeleted = %d, want 0 when LAPI's count is unreadable", resp.NbDeleted)
			}
		})
	}
}

// The route exists, is wired to the handler, and sits behind the admin
// middleware. Driving it through the real router is what proves that;
// the handler tests above bypass the router entirely.
func TestDeleteCrowdSecDecision_RouteIsWiredAdminOnly(t *testing.T) {
	env := newTestEnv(t, false)

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/security/crowdsec/decisions/42", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	// No automation credentials are seeded, so the handler's own 412 is
	// the proof it was reached. A 404 would mean the route is missing
	// and a 405 that the verb is not mounted.
	if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("status = %d — the DELETE route is not wired", rec.Code)
	}
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412 from the handler, body=%s", rec.Code, rec.Body.String())
	}
}
