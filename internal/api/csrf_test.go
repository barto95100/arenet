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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func csrfResult(t *testing.T, build func(*http.Request)) (int, bool) {
	t.Helper()
	reached := false
	h := csrfGuard()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", strings.NewReader(`{"x":1}`))
	build(r)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code, reached
}

// The classic cross-origin CSRF write is an auto-submitted form, which
// can only send a CORS-simple content type and never application/json.
// A cookie-authenticated write with text/plain is refused.
func TestCSRF_CookieAuth_NonJSONBody_Refused(t *testing.T) {
	code, reached := csrfResult(t, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
		r.Header.Set("Content-Type", "text/plain")
	})
	if code != http.StatusUnsupportedMediaType || reached {
		t.Fatalf("a cookie-auth text/plain write must be refused with 415; got %d reached=%v", code, reached)
	}
}

// The real SPA write — cookie + application/json — passes.
func TestCSRF_CookieAuth_JSON_Allowed(t *testing.T) {
	code, reached := csrfResult(t, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
		r.Header.Set("Content-Type", "application/json")
	})
	if code != http.StatusOK || !reached {
		t.Fatalf("a cookie-auth application/json write must pass; got %d reached=%v", code, reached)
	}
}

// A browser that labels the request cross-site is refused even with the
// right content type (defence in depth against a same-site sibling).
func TestCSRF_CookieAuth_CrossSiteFetch_Refused(t *testing.T) {
	code, reached := csrfResult(t, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	})
	if code != http.StatusForbidden || reached {
		t.Fatalf("a cross-site fetch must be refused with 403; got %d reached=%v", code, reached)
	}
}

// A bearer request carries no session cookie, is not CSRF-exposed, and
// programmatic clients do not send JSON content types or Sec-Fetch-Site —
// so it must pass regardless.
func TestCSRF_Bearer_NoCookie_Allowed(t *testing.T) {
	code, reached := csrfResult(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer tok")
		r.Header.Set("Content-Type", "text/plain")
	})
	if code != http.StatusOK || !reached {
		t.Fatalf("a bearer (no-cookie) write must pass; got %d reached=%v", code, reached)
	}
}

// A bodyless cookie-auth request (a plain DELETE) has no payload to
// forge and is not form-reachable, so the content-type rule does not
// apply.
func TestCSRF_CookieAuth_BodylessDelete_Allowed(t *testing.T) {
	reached := false
	h := csrfGuard()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/routes/x", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || !reached {
		t.Fatalf("a bodyless cookie-auth DELETE must pass; got %d reached=%v", rec.Code, reached)
	}
}

// A safe method is never gated.
func TestCSRF_SafeMethod_Allowed(t *testing.T) {
	reached := false
	h := csrfGuard()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || !reached {
		t.Fatalf("a safe GET must never be gated; got %d reached=%v", rec.Code, reached)
	}
}
