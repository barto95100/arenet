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
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// fixedAccessLogResolver always resolves to one path, ignoring the
// operator choice — which is also what proves the client can never steer
// the read: the handler passes only cfg.Path here, never a query param.
type fixedAccessLogResolver struct{ path string }

func (f fixedAccessLogResolver) ResolveAccessLogPath(string) string { return f.path }

// enableAccessLogAt enables the access log and points the resolver at a
// freshly written log file in a temp dir, returning the file path.
func enableAccessLogAt(t *testing.T, env *testEnv, currentLines []string, gz map[string][]string) string {
	t.Helper()
	dir := t.TempDir()
	cur := filepath.Join(dir, "access.log")
	if err := os.WriteFile(cur, []byte(strings.Join(currentLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write current: %v", err)
	}
	for name, lines := range gz {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		_, _ = w.Write([]byte(strings.Join(lines, "\n") + "\n"))
		_ = w.Close()
		if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
			t.Fatalf("write gz: %v", err)
		}
	}

	cfg := storage.DefaultAccessLogConfig()
	cfg.Enabled = true
	if err := env.store.PutAccessLogConfig(context.Background(), cfg); err != nil {
		t.Fatalf("enable access log: %v", err)
	}
	env.handler.SetAccessLogPathResolver(fixedAccessLogResolver{path: cur})
	return cur
}

func logLine(uuid, ip, uri, denied string) string {
	denField := ""
	if denied != "" {
		denField = fmt.Sprintf(`,"arenet_denied":%q`, denied)
	}
	return fmt.Sprintf(
		`{"ts":1699999999.5,"msg":"handled request","uuid":%q,"request":{"client_ip":%q,"uri":%q,"method":"GET"},"status":403%s}`,
		uuid, ip, uri, denField)
}

func getJSON(t *testing.T, env *testEnv, target string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body (%d): %v — %s", rec.Code, err, rec.Body.String())
		}
	}
	return rec.Code, body
}

// Wire shape of the tail response and of a line row (camelCase keys).
func TestAccessLogTail_Wire(t *testing.T) {
	env := newTestEnv(t, false)
	enableAccessLogAt(t, env, []string{
		logLine("u-1", "10.0.0.1", "/a", ""),
		logLine("u-2", "10.0.0.2", "/b", "waf"),
	}, nil)

	code, body := getJSON(t, env, "/api/v1/admin/access-log/tail?lines=1")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if body["enabled"] != true {
		t.Fatalf("enabled = %v, want true", body["enabled"])
	}
	if _, ok := body["path"].(string); !ok {
		t.Fatalf("missing path key: %v", body)
	}
	lines, ok := body["lines"].([]any)
	if !ok || len(lines) != 1 {
		t.Fatalf("lines = %v, want exactly 1", body["lines"])
	}
	row := lines[0].(map[string]any)
	// The camelCase wire contract — a struct test would not catch a
	// client_ip vs clientIp slip (memory: test-the-wire-not-the-struct).
	for _, key := range []string{"clientIp", "uri", "status", "raw"} {
		if _, ok := row[key]; !ok {
			t.Fatalf("row missing %q: %v", key, row)
		}
	}
	if row["uri"] != "/b" || row["denied"] != "waf" {
		t.Fatalf("tail returned the wrong (or mis-parsed) newest line: %v", row)
	}
}

// Wire shape of the search response, and the cold-tier metadata flag.
func TestAccessLogSearch_Wire_UUIDInGz(t *testing.T) {
	env := newTestEnv(t, false)
	enableAccessLogAt(t, env,
		[]string{logLine("hot-1", "10.0.0.1", "/live", "")},
		map[string][]string{
			"access-2026-11-08T09-00-00.000.log.gz": {logLine("cold-xyz", "10.9.9.9", "/old", "country")},
		})

	code, body := getJSON(t, env, "/api/v1/admin/access-log/search?field=uuid&q=cold-xyz")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	for _, key := range []string{"filesScanned", "bytesScanned", "truncated", "searchedCompressed", "elapsedMs", "field", "query"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("metadata missing %q: %v", key, body)
		}
	}
	if body["searchedCompressed"] != true {
		t.Fatalf("searchedCompressed = %v, want true (hit was in .gz)", body["searchedCompressed"])
	}
	lines := body["lines"].([]any)
	if len(lines) != 1 || lines[0].(map[string]any)["denied"] != "country" {
		t.Fatalf("expected the one cold line with denied=country, got %v", lines)
	}
}

// field is required and validated — an unknown field is a 400.
func TestAccessLogSearch_BadField(t *testing.T) {
	env := newTestEnv(t, false)
	enableAccessLogAt(t, env, []string{logLine("u-1", "10.0.0.1", "/a", "")}, nil)

	code, _ := getJSON(t, env, "/api/v1/admin/access-log/search?field=bogus&q=x")
	if code != http.StatusBadRequest {
		t.Fatalf("field=bogus status = %d, want 400", code)
	}
}

// Log disabled → explicit empty result with a reason, not an error.
func TestAccessLogSearch_Disabled(t *testing.T) {
	env := newTestEnv(t, false)
	// Access log left at its default (disabled); no resolver needed.
	code, body := getJSON(t, env, "/api/v1/admin/access-log/search?field=path&q=/a")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if body["enabled"] != false {
		t.Fatalf("enabled = %v, want false", body["enabled"])
	}
	if body["reason"] != accessLogReasonDisabled {
		t.Fatalf("reason = %v, want %q", body["reason"], accessLogReasonDisabled)
	}
	if lines := body["lines"].([]any); len(lines) != 0 {
		t.Fatalf("lines = %v, want empty", lines)
	}
}

// A client-supplied path query param changes nothing (spec gate §7.7):
// the resolved path stays the server's, and the read still targets it.
func TestAccessLog_PathParamIgnored(t *testing.T) {
	env := newTestEnv(t, false)
	cur := enableAccessLogAt(t, env, []string{logLine("u-1", "10.0.0.1", "/secret-hit", "")}, nil)

	code, body := getJSON(t, env,
		"/api/v1/admin/access-log/search?field=path&q=/secret-hit&path=../../../../etc/passwd")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if body["path"] != cur {
		t.Fatalf("resolved path = %v, want the server path %q (client param leaked)", body["path"], cur)
	}
	if lines := body["lines"].([]any); len(lines) != 1 {
		t.Fatalf("expected the hit from the resolved file, got %v", lines)
	}
}

// Both endpoints are admin-only: a viewer session is rejected 403.
func TestAccessLog_ViewerRejected(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()
	viewer, err := newTestUserStore(t, env).CreateOIDCUser(ctx, "viewer-al", "Viewer AL", "", "sub-viewer-al")
	if err != nil || viewer.Role != auth.UserRoleViewer {
		t.Fatalf("seed viewer: %v %+v", err, viewer)
	}
	s, err := auth.NewSessionStore(env.store.DB()).Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"/api/v1/admin/access-log/tail",
		"/api/v1/admin/access-log/search?field=uuid&q=x",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("viewer %s = %d, want 403", target, rec.Code)
		}
	}
}
