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
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/geo"
)

func asnGet(t *testing.T, env *testEnv, path string) (int, asnSearchResponse) {
	t.Helper()
	rec := getRec(t, env, path)
	var out asnSearchResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestSearchASN_NotLoaded(t *testing.T) {
	env := newTestEnv(t, false)
	code, out := asnGet(t, env, "/api/v1/geo/asn?q=google")
	if code != http.StatusOK || out.Loaded || out.Results == nil || len(out.Results) != 0 {
		t.Errorf("code=%d out=%+v", code, out)
	}
}

func TestSearchASN_WithTestDatabase(t *testing.T) {
	env := newTestEnv(t, false)
	l, err := geo.NewASNLookup("../geoipupdate/testdata/asn.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	for deadline := time.Now().Add(5 * time.Second); !l.IndexReady(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("index not ready")
		}
	}
	env.handler.SetASNLookup(l)

	code, out := asnGet(t, env, "/api/v1/geo/asn?q=google&limit=5")
	if code != http.StatusOK || !out.Loaded || !out.IndexReady || len(out.Results) == 0 || out.Results[0].ASN != 15169 {
		t.Errorf("search: code=%d out=%+v", code, out)
	}
	_, out = asnGet(t, env, "/api/v1/geo/asn?ids=7018,AS15169")
	if len(out.Results) != 2 || out.Results[0].Name != "AT&T Services" || out.Results[1].ASN != 15169 {
		t.Errorf("ids: %+v", out.Results)
	}
	if code, _ := asnGet(t, env, "/api/v1/geo/asn?ids=12,abc"); code != http.StatusBadRequest {
		t.Errorf("bad id: code=%d", code)
	}
}

func TestSearchASN_ViewerRejected(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()
	viewer, err := newTestUserStore(t, env).CreateOIDCUser(ctx, "viewer-asn", "Viewer ASN", "", "sub-viewer-asn")
	if err != nil || viewer.Role != auth.UserRoleViewer {
		t.Fatalf("seed viewer: %v %+v", err, viewer)
	}
	s, err := auth.NewSessionStore(env.store.DB()).Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/geo/asn?q=x", strings.NewReader(""))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer status = %d, want 403", rec.Code)
	}
}
