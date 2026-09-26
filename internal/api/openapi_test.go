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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/auth"
)

// v2.39 — the OpenAPI document must match the real router: every
// registered route documented (and nothing more), and each operation's
// x-arenet-role equal to the access level measured by calling it.

const apiPrefix = "/api/v1"

var openAPIMethods = []string{"get", "put", "post", "delete", "patch"}

// fullRouter builds the production router with every optional handler
// wired, so chi.Walk sees all routes.
func fullRouter(env *testEnv) chi.Router {
	ipx, _ := auth.NewIPExtractor("")
	return NewRouter(env.handler, false, ipx, &WSTopologyHandler{}, &SnapshotHandler{}, &StreamHandler{}, &WSGeoEventsHandler{})
}

// registeredOps lists "METHOD /full/path" for every route.
func registeredOps(t *testing.T, r chi.Router) []string {
	t.Helper()
	var out []string
	err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, method+" "+strings.TrimSuffix(route, "/*"))
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	sort.Strings(out)
	return out
}

// docOp is one documented operation.
type docOp struct {
	method, fullPath, docPath string
	op                        map[string]any
	pathItem                  map[string]any
}

// documentedOps lists the operations of the merged document with their
// full path (the path's own servers override, else /api/v1).
func documentedOps(t *testing.T) []docOp {
	t.Helper()
	doc, err := mergedOpenAPI()
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var out []docOp
	for p, raw := range childMap(doc, "paths") {
		item, _ := raw.(map[string]any)
		prefix := apiPrefix
		if servers, ok := item["servers"].([]any); ok && len(servers) > 0 {
			if s, ok := servers[0].(map[string]any); ok && s["url"] == "/" {
				prefix = ""
			}
		}
		for _, m := range openAPIMethods {
			if op, ok := item[m].(map[string]any); ok {
				out = append(out, docOp{strings.ToUpper(m), prefix + p, p, op, item})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].method+out[i].fullPath < out[j].method+out[j].fullPath })
	return out
}

func TestOpenAPI_CoversEveryRoute(t *testing.T) {
	env := newTestEnv(t, false)
	registered := map[string]bool{}
	for _, op := range registeredOps(t, fullRouter(env)) {
		registered[op] = true
	}
	documented := map[string]bool{}
	for _, d := range documentedOps(t) {
		documented[d.method+" "+d.fullPath] = true
	}
	for op := range registered {
		if !documented[op] {
			t.Errorf("route %s is not documented in internal/api/openapi/*.yaml", op)
		}
	}
	for op := range documented {
		if !registered[op] {
			t.Errorf("documented operation %s does not exist in the router", op)
		}
	}
}

var pathParamRe = regexp.MustCompile(`\{([^}]+)\}`)

func TestOpenAPI_OperationsWellFormed(t *testing.T) {
	doc, err := mergedOpenAPI()
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	tags := map[string]bool{}
	for _, tg := range doc["tags"].([]any) {
		tags[tg.(map[string]any)["name"].(string)] = true
	}
	for _, d := range documentedOps(t) {
		name := d.method + " " + d.docPath
		if s, _ := d.op["summary"].(string); s == "" {
			t.Errorf("%s: missing summary", name)
		}
		opTags, _ := d.op["tags"].([]any)
		if len(opTags) == 0 {
			t.Errorf("%s: missing tags", name)
		}
		for _, tg := range opTags {
			if !tags[tg.(string)] {
				t.Errorf("%s: tag %q not declared in base.yaml", name, tg)
			}
		}
		if _, ok := d.op["responses"].(map[string]any); !ok {
			t.Errorf("%s: missing responses", name)
		}
		role, _ := d.op["x-arenet-role"].(string)
		if role != "public" && role != "viewer" && role != "admin" {
			t.Errorf("%s: x-arenet-role = %q, want public|viewer|admin", name, role)
		}
		sec, hasSec := d.op["security"].([]any)
		if role == "public" && (!hasSec || len(sec) != 0) {
			t.Errorf("%s: a public operation needs `security: []`", name)
		}
		if role != "public" && hasSec && len(sec) == 0 {
			t.Errorf("%s: `security: []` on a %s operation", name, role)
		}
		declared := map[string]bool{}
		for _, list := range []any{d.pathItem["parameters"], d.op["parameters"]} {
			params, _ := list.([]any)
			for _, p := range params {
				pm, _ := p.(map[string]any)
				if ref, ok := pm["$ref"].(string); ok {
					pm = resolveRef(doc, ref)
				}
				if pm != nil && pm["in"] == "path" {
					declared[pm["name"].(string)] = true
				}
			}
		}
		for _, m := range pathParamRe.FindAllStringSubmatch(d.docPath, -1) {
			if !declared[m[1]] {
				t.Errorf("%s: path parameter {%s} not declared", name, m[1])
			}
		}
	}
}

// resolveRef follows a local "#/a/b/c" reference.
func resolveRef(doc map[string]any, ref string) map[string]any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	var cur any = doc
	for _, part := range strings.Split(ref[2:], "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	out, _ := cur.(map[string]any)
	return out
}

func TestOpenAPI_RefsResolve(t *testing.T) {
	doc, err := mergedOpenAPI()
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var walk func(v any, where string)
	walk = func(v any, where string) {
		switch x := v.(type) {
		case map[string]any:
			if ref, ok := x["$ref"].(string); ok && resolveRef(doc, ref) == nil {
				t.Errorf("%s: unresolved $ref %q", where, ref)
			}
			for k, e := range x {
				walk(e, where+"/"+k)
			}
		case []any:
			for _, e := range x {
				walk(e, where)
			}
		}
	}
	walk(doc, "")
}

// probeViewers numbers the viewer accounts accessLevel creates;
// probeCalls numbers its requests (one client IP each).
var probeViewers, probeCalls int

// accessLevel measures an operation's access by calling it anonymously
// then as a viewer (fresh session each call: some endpoints end it).
func accessLevel(t *testing.T, env *testEnv, r http.Handler, method, path string) string {
	t.Helper()
	target := pathParamRe.ReplaceAllString(path, "probe")
	call := func(cookie string) (code int, body string) {
		defer func() {
			if recover() != nil { // zero-value WS/stream handlers
				code, body = http.StatusOK, ""
			}
		}()
		req := httptest.NewRequest(method, target, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		// A distinct client IP per call: the /auth rate limiter would
		// otherwise answer 429 and hide the real 401 (probe-caught).
		probeCalls++
		req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1234", probeCalls/65536%256, probeCalls/256%256, probeCalls%256)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	code, _ := call("")
	if code == http.StatusTooManyRequests {
		t.Fatalf("%s %s: rate-limited while probing", method, path)
	}
	if code != http.StatusUnauthorized {
		return "public"
	}
	ctx := context.Background()
	probeViewers++
	name := fmt.Sprintf("probe-viewer-%d", probeViewers)
	viewer, err := newTestUserStore(t, env).CreateOIDCUser(ctx, name, "Viewer", "", "sub-"+name)
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	s, err := auth.NewSessionStore(env.store.DB()).Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatal(err)
	}
	code, body := call(s.ID)
	if code == http.StatusForbidden && strings.Contains(body, "admin role required") {
		return "admin"
	}
	return "viewer"
}

func TestOpenAPI_RolesMatchTheRouter(t *testing.T) {
	env := newTestEnv(t, false)
	r := fullRouter(env)
	for _, d := range documentedOps(t) {
		want, _ := d.op["x-arenet-role"].(string)
		if got := accessLevel(t, env, r, d.method, d.fullPath); got != want {
			t.Errorf("%s %s: x-arenet-role = %q but the router says %q", d.method, d.docPath, want, got)
		}
	}
}

func TestOpenAPI_Endpoint(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetVersion("v9.9.9")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if doc["openapi"] != "3.1.0" || doc["info"].(map[string]any)["version"] != "v9.9.9" {
		t.Fatalf("openapi=%v info=%v", doc["openapi"], doc["info"])
	}
	// The cached document keeps its own version (no mutation).
	cached, _ := mergedOpenAPI()
	if cached["info"].(map[string]any)["version"] == "v9.9.9" {
		t.Fatal("serving mutated the cached document")
	}
	anon := httptest.NewRecorder()
	fullRouter(env).ServeHTTP(anon, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))
	if anon.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", anon.Code)
	}
}

func TestBuildOpenAPI_RefusesDuplicates(t *testing.T) {
	base := []byte("openapi: 3.1.0\ninfo: {title: t, version: v}\npaths: {}\ncomponents: {schemas: {}}\n")
	fsys := fstest.MapFS{
		"openapi/base.yaml": {Data: base},
		"openapi/a.yaml":    {Data: []byte("paths:\n  /x:\n    get: {summary: a}\ncomponents:\n  schemas:\n    S: {type: string}\n")},
		"openapi/b.yaml":    {Data: []byte("paths:\n  /y:\n    get: {summary: b}\n")},
	}
	doc, err := buildOpenAPI(fsys)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(childMap(doc, "paths")) != 2 || childMap(childMap(doc, "components"), "schemas")["S"] == nil {
		t.Fatalf("merged = %+v", doc)
	}
	fsys["openapi/c.yaml"] = &fstest.MapFile{Data: []byte("paths:\n  /x:\n    post: {summary: c}\n")}
	if _, err := buildOpenAPI(fsys); err == nil || !strings.Contains(err.Error(), `"/x" defined twice`) {
		t.Fatalf("duplicate path: err = %v", err)
	}
	delete(fsys, "openapi/c.yaml")
	fsys["openapi/d.yaml"] = &fstest.MapFile{Data: []byte("components:\n  schemas:\n    S: {type: integer}\n")}
	if _, err := buildOpenAPI(fsys); err == nil {
		t.Fatal("duplicate schema accepted")
	}
}

// A plain YAML scalar containing ": " silently becomes a mapping: the
// text after the colon turns into a stray key (lint-caught: 9
// descriptions were split this way). No OpenAPI keyword, property or
// parameter name contains a space or ends with a dot, so such a key is
// always this bug.
// Example payloads are skipped (their keys are data).
func TestOpenAPI_NoSplitText(t *testing.T) {
	for _, name := range []string{"auth-users", "backup-system", "base", "routes", "security", "settings"} {
		doc, err := readOpenAPIFile(openAPIFiles, "openapi/"+name+".yaml")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var walk func(v any, where string)
		walk = func(v any, where string) {
			switch x := v.(type) {
			case map[string]any:
				for k, e := range x {
					if k == "example" || k == "examples" || k == "default" || k == "enum" {
						continue
					}
					if strings.ContainsAny(k, " \t") || strings.HasSuffix(k, ".") {
						t.Errorf("%s.yaml %s: stray key %q — quote the text before it or use a | block", name, where, k)
					}
					walk(e, where+"/"+k)
				}
			case []any:
				for i, e := range x {
					walk(e, fmt.Sprintf("%s[%d]", where, i))
				}
			}
		}
		walk(doc, "")
	}
}

func TestOpenAPI_OperationIDsUnique(t *testing.T) {
	seen := map[string]string{}
	for _, d := range documentedOps(t) {
		id, _ := d.op["operationId"].(string)
		if id == "" {
			t.Errorf("%s %s: no operationId", d.method, d.docPath)
			continue
		}
		if prev, dup := seen[id]; dup {
			t.Errorf("operationId %q used by %s and %s %s", id, prev, d.method, d.docPath)
		}
		seen[id] = d.method + " " + d.docPath
	}
	if got := deriveOperationID("post", "/routes/{id}/waf-test"); got != "postRoutesByIdWafTest" {
		t.Errorf("derive = %q", got)
	}
}
