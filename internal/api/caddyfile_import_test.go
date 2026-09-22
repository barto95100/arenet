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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.40 — Caddyfile import: the preview writes nothing, the import
// creates only what was asked, skips a host already served unless it is
// explicitly replaced, and undoes everything if Caddy refuses.

const importCaddyfile = `app.example.com {
	reverse_proxy 10.0.0.10:8080
}

static.example.com {
	file_server
}

taken.example.com {
	reverse_proxy 10.0.0.11:8080
}
`

func postImport(t *testing.T, env *testEnv, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func TestCaddyfileImport_Preview(t *testing.T) {
	env := newTestEnv(t, false)
	seedWAFRoute(t, env, storage.Route{Host: "taken.example.com"})

	rec := postImport(t, env, "/api/v1/routes/import/caddyfile/preview", map[string]any{"caddyfile": importCaddyfile})
	if rec.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body)
	}
	var resp caddyfilePreviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Candidates) != 3 {
		t.Fatalf("candidates = %d", len(resp.Candidates))
	}
	byHost := map[string]caddyfileCandidate{}
	for _, c := range resp.Candidates {
		byHost[c.Host] = c
	}
	if !byHost["app.example.com"].Importable || byHost["app.example.com"].Conflict {
		t.Errorf("app: %+v", byHost["app.example.com"])
	}
	if byHost["static.example.com"].Importable || byHost["static.example.com"].Reason == "" {
		t.Errorf("static: %+v", byHost["static.example.com"])
	}
	if !byHost["taken.example.com"].Conflict {
		t.Error("an existing host must be flagged as a conflict")
	}
	// Nothing written.
	routes, _ := env.store.ListRoutes(context.Background())
	if len(routes) != 1 {
		t.Errorf("the preview created routes: %d", len(routes))
	}
	if env.caddy.CallCount() != 0 {
		t.Error("the preview reloaded Caddy")
	}

	if rec := postImport(t, env, "/api/v1/routes/import/caddyfile/preview", map[string]any{"caddyfile": "app.example.com {"}); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid Caddyfile: %d, want 400", rec.Code)
	}
	if rec := postImport(t, env, "/api/v1/routes/import/caddyfile/preview", map[string]any{"caddyfile": "  "}); rec.Code != http.StatusBadRequest {
		t.Errorf("empty Caddyfile: %d, want 400", rec.Code)
	}
}

func TestCaddyfileImport_ImportsOnlyWhatWasAsked(t *testing.T) {
	env := newTestEnv(t, false)
	seedWAFRoute(t, env, storage.Route{Host: "taken.example.com", WAFMode: "block"})

	rec := postImport(t, env, "/api/v1/routes/import/caddyfile", map[string]any{
		"caddyfile": importCaddyfile,
		"hosts":     []string{"app.example.com", "static.example.com", "taken.example.com", "ghost.example.com"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body)
	}
	var resp caddyfileImportResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Created) != 1 || resp.Created[0] != "app.example.com" {
		t.Fatalf("created = %v", resp.Created)
	}
	if len(resp.Skipped) != 3 {
		t.Fatalf("skipped = %+v", resp.Skipped)
	}
	reasons := map[string]string{}
	for _, s := range resp.Skipped {
		reasons[s.Host] = s.Reason
	}
	if !strings.Contains(reasons["static.example.com"], "reverse_proxy") ||
		!strings.Contains(reasons["taken.example.com"], "already serves") ||
		!strings.Contains(reasons["ghost.example.com"], "not found") {
		t.Errorf("reasons = %v", reasons)
	}
	if env.caddy.CallCount() != 1 {
		t.Errorf("reloads = %d, want a single one", env.caddy.CallCount())
	}

	routes, _ := env.store.ListRoutes(context.Background())
	var imported storage.Route
	for _, r := range routes {
		if r.Host == "app.example.com" {
			imported = r
		}
		if r.Host == "taken.example.com" && r.WAFMode != "block" {
			t.Error("the existing route was modified")
		}
	}
	if imported.ID == "" || imported.Upstreams[0].URL != "http://10.0.0.10:8080" || imported.WAFMode != "detect" {
		t.Fatalf("imported route = %+v", imported)
	}
	events, _, _ := env.audit.List(context.Background(), audit.Filter{})
	if len(events) != 1 {
		t.Errorf("audit events = %d, want one route_created", len(events))
	}
}

func TestCaddyfileImport_ReplaceAndRollback(t *testing.T) {
	env := newTestEnv(t, false)
	existing := seedWAFRoute(t, env, storage.Route{Host: "taken.example.com", WAFMode: "block"})

	// Replace explicitly.
	rec := postImport(t, env, "/api/v1/routes/import/caddyfile", map[string]any{
		"caddyfile": importCaddyfile,
		"hosts":     []string{"taken.example.com"},
		"replace":   []string{"taken.example.com"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("replace: %d %s", rec.Code, rec.Body)
	}
	var resp caddyfileImportResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Replaced) != 1 {
		t.Fatalf("replaced = %v skipped = %+v", resp.Replaced, resp.Skipped)
	}
	stored, _ := env.store.GetRoute(context.Background(), existing.ID)
	if stored.Upstreams[0].URL != "http://10.0.0.11:8080" || stored.WAFMode != "detect" {
		t.Fatalf("replaced route = %+v", stored)
	}

	// Caddy refuses: everything is undone.
	env.caddy.SetNextErr(errors.New("boom"))
	before, _ := env.store.ListRoutes(context.Background())
	rec = postImport(t, env, "/api/v1/routes/import/caddyfile", map[string]any{
		"caddyfile": importCaddyfile,
		"hosts":     []string{"app.example.com"},
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("refused reload: %d %s", rec.Code, rec.Body)
	}
	after, _ := env.store.ListRoutes(context.Background())
	if len(after) != len(before) {
		t.Fatalf("routes after the rollback = %d, want %d", len(after), len(before))
	}
	if rec := postImport(t, env, "/api/v1/routes/import/caddyfile", map[string]any{"caddyfile": importCaddyfile}); rec.Code != http.StatusBadRequest {
		t.Errorf("no hosts: %d, want 400", rec.Code)
	}
}
