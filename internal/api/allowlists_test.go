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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/allowlist"
)

// withSlug attaches a chi route context carrying {slug} to r.
func withSlug(r *http.Request, slug string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("slug", slug)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func newAllowlistHandler(t *testing.T) (*Handler, *allowlist.Store, *int) {
	t.Helper()
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	store, err := allowlist.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("allowlist.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rebuilds := 0
	h.SetAllowlistStore(store, func(context.Context) { rebuilds++ })
	return h, store, &rebuilds
}

// TestAllowlistWire_CreateAndList_G is G_allowlist_wire: it pins the literal
// JSON contract (camelCase keys, entry shape) the SvelteKit client depends
// on — a struct-tag rename would pass a typed round-trip but break the wire.
func TestAllowlistWire_CreateAndList_G(t *testing.T) {
	h, _, rebuilds := newAllowlistHandler(t)

	body := `{"name":"Office","description":"HQ","scopeThrottle":false,"entries":[{"cidr":"10.0.0.0/24","note":"LAN"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/security/allowlists", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.createAllowlist(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if *rebuilds != 1 {
		t.Errorf("rebuild hook called %d times, want 1", *rebuilds)
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	for _, key := range []string{"slug", "name", "description", "enabled", "scopeBlock", "scopeThrottle", "scopeAudit", "entries"} {
		if _, ok := created[key]; !ok {
			t.Errorf("create response missing key %q; got %v", key, created)
		}
	}
	if created["slug"] != "office" {
		t.Errorf("slug = %v, want office", created["slug"])
	}
	// Omitted scope flags default to true; explicit false is honoured.
	if created["scopeBlock"] != true || created["scopeThrottle"] != false || created["scopeAudit"] != true {
		t.Errorf("scope defaults wrong: block=%v throttle=%v audit=%v", created["scopeBlock"], created["scopeThrottle"], created["scopeAudit"])
	}
	entries, _ := created["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	e0, _ := entries[0].(map[string]any)
	if e0["cidr"] != "10.0.0.0/24" || e0["note"] != "LAN" {
		t.Errorf("entry wire shape wrong: %v", e0)
	}

	// List returns {"allowlists":[...]}.
	lreq := httptest.NewRequest(http.MethodGet, "/api/v1/security/allowlists", nil)
	lrec := httptest.NewRecorder()
	h.listAllowlists(lrec, lreq)
	if lrec.Code != http.StatusOK {
		t.Fatalf("GET list status = %d, want 200", lrec.Code)
	}
	var list map[string]any
	if err := json.Unmarshal(lrec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	arr, ok := list["allowlists"].([]any)
	if !ok || len(arr) != 1 {
		t.Fatalf("list.allowlists = %v, want 1-element array", list["allowlists"])
	}
}

// TestAllowlistWire_InvalidCIDR_400_G: an invalid entry is a 400, not a 500.
func TestAllowlistWire_InvalidCIDR_400_G(t *testing.T) {
	h, _, _ := newAllowlistHandler(t)
	body := `{"name":"bad","entries":[{"cidr":"not-an-ip"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/security/allowlists", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.createAllowlist(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAllowlistWire_GetMissing_404_G
func TestAllowlistWire_GetMissing_404_G(t *testing.T) {
	h, _, _ := newAllowlistHandler(t)
	req := withSlug(httptest.NewRequest(http.MethodGet, "/api/v1/security/allowlists/ghost", nil), "ghost")
	rec := httptest.NewRecorder()
	h.getAllowlist(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestAllowlistWire_StoreUnavailable_503_G: a nil store answers 503, not panic.
func TestAllowlistWire_StoreUnavailable_503_G(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	// No SetAllowlistStore → h.allowlists stays nil.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/allowlists", nil)
	rec := httptest.NewRecorder()
	h.listAllowlists(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
