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
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.42 — TCP (layer 4) services API.
//
// What is pinned: the listen guard refuses before anything is stored,
// a failed reload leaves no half-created service behind, every write
// is audited, and the dial test reports the far side without changing
// anything.

func tcpDo(t *testing.T, env *testEnv, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = strings.NewReader(string(raw))
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

// freePort returns a port nothing is listening on, so the create
// handler's real bind check can succeed.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func tcpServiceBody(t *testing.T, over map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{
		"name":       "stalwart-imaps",
		"listenAddr": "127.0.0.1",
		"listenPort": freePort(t),
		"upstreams":  []map[string]any{{"host": "10.20.0.5", "port": 993}},
	}
	for k, v := range over {
		body[k] = v
	}
	return body
}

func TestTCPService_CreateListAndAudit(t *testing.T) {
	env := newTestEnv(t, false)

	rec := tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services", tcpServiceBody(t, map[string]any{
		"proxyProtocol": "v2",
	}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var created storage.TCPService
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if created.ID == "" || created.ProxyProtocol != storage.ProxyProtocolV2 {
		t.Fatalf("created service: %+v", created)
	}

	// Caddy was reloaded, and the write is in the audit trail.
	if env.caddy.CallCount() == 0 {
		t.Fatal("create must reload Caddy")
	}
	if !auditHasAction(env, audit.ActionTCPServiceCreated) {
		t.Fatalf("no %s audit event", audit.ActionTCPServiceCreated)
	}

	rec = tcpDo(t, env, http.MethodGet, "/api/v1/tcp-services", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", rec.Code)
	}
	var list []storage.TCPService
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("list: %+v", list)
	}
}

// The guard has to fire BEFORE the row exists: an operator who tries
// to take Arenet's own port must not end up with a stored service
// that cannot be applied.
func TestTCPService_ReservedPortRefusedBeforeStoring(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetAdminListen("127.0.0.1:8001")

	for _, port := range []int{80, 443, 8001, 2019} {
		body := tcpServiceBody(t, map[string]any{"listenPort": port})
		rec := tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("port %d: want 400, got %d: %s", port, rec.Code, rec.Body.String())
		}
	}

	list, err := env.store.ListTCPServices(t.Context())
	if err != nil {
		t.Fatalf("ListTCPServices: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("a refused service must not be stored, got %d", len(list))
	}
}

func TestTCPService_ListenConflictRefused(t *testing.T) {
	env := newTestEnv(t, false)

	port := freePort(t)
	first := tcpServiceBody(t, map[string]any{"listenPort": port})
	if rec := tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services", first); rec.Code != http.StatusCreated {
		t.Fatalf("first create: %d %s", rec.Code, rec.Body.String())
	}

	second := tcpServiceBody(t, map[string]any{"name": "other", "listenPort": port})
	rec := tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services", second)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("second create on the same port: want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "listen") {
		t.Fatalf("the refusal must explain the conflict: %s", rec.Body.String())
	}
}

// A service whose apply is refused must leave nothing behind: the
// operator would otherwise see a service that serves nothing.
func TestTCPService_CreateRollsBackWhenCaddyRefuses(t *testing.T) {
	env := newTestEnv(t, false)
	env.caddy.SetNextErr(errors.New("caddy said no"))

	rec := tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services", tcpServiceBody(t, nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d: %s", rec.Code, rec.Body.String())
	}

	list, err := env.store.ListTCPServices(t.Context())
	if err != nil {
		t.Fatalf("ListTCPServices: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("a service whose reload failed must be rolled back, got %+v", list)
	}
	if auditHasAction(env, audit.ActionTCPServiceCreated) {
		t.Fatal("a rolled-back create must not be audited as created")
	}
}

func TestTCPService_UpdateAndDelete(t *testing.T) {
	env := newTestEnv(t, false)

	rec := tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services", tcpServiceBody(t, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created storage.TCPService
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// Updating in place must not trip the conflict check against its
	// own row.
	update := tcpServiceBody(t, map[string]any{
		"name":       "renamed",
		"listenPort": created.ListenPort,
		"listenAddr": created.ListenAddr,
	})
	rec = tcpDo(t, env, http.MethodPut, "/api/v1/tcp-services/"+created.ID, update)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var updated storage.TCPService
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.Name != "renamed" {
		t.Fatalf("update did not apply: %+v", updated)
	}
	if !auditHasAction(env, audit.ActionTCPServiceUpdated) {
		t.Fatal("update must be audited")
	}

	rec = tcpDo(t, env, http.MethodDelete, "/api/v1/tcp-services/"+created.ID, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if !auditHasAction(env, audit.ActionTCPServiceDeleted) {
		t.Fatal("delete must be audited")
	}

	rec = tcpDo(t, env, http.MethodGet, "/api/v1/tcp-services/"+created.ID, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: want 404, got %d", rec.Code)
	}
}

// The test endpoint answers with what a dial found, and repeats the
// PROXY-protocol pairing the operator has to get right on the other
// side — a dial cannot prove that part.
func TestTCPService_TestEndpointReportsBackends(t *testing.T) {
	env := newTestEnv(t, false)

	// One backend that answers, one that does not.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	upHost, upPort, _ := net.SplitHostPort(ln.Addr().String())

	body := tcpServiceBody(t, map[string]any{
		"proxyProtocol": "v2",
		"upstreams": []map[string]any{
			{"host": upHost, "port": atoiForTest(t, upPort)},
			{"host": "127.0.0.1", "port": freePort(t)},
		},
	})
	rec := tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created storage.TCPService
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	rec = tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services/"+created.ID+"/test", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("test: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var report tcpServiceTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(report.Backends) != 2 {
		t.Fatalf("want one result per backend, got %+v", report.Backends)
	}
	if !report.Backends[0].OK {
		t.Fatalf("a listening backend must answer: %+v", report.Backends[0])
	}
	if report.Backends[1].OK || report.Backends[1].Error == "" {
		t.Fatalf("a closed port must be reported with its error: %+v", report.Backends[1])
	}
	if !strings.Contains(report.ProxyProtocolNote, "proxyTrustedNetworks") {
		t.Fatalf("the note must name what to configure on the backend: %q", report.ProxyProtocolNote)
	}
}

func TestTCPService_ValidationRefusedWithReason(t *testing.T) {
	env := newTestEnv(t, false)

	rec := tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services", tcpServiceBody(t, map[string]any{
		"upstreams": []map[string]any{},
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "backend") {
		t.Fatalf("the refusal must name what is wrong: %s", rec.Body.String())
	}

	rec = tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services", tcpServiceBody(t, map[string]any{
		"proxyProtocol": "v3",
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for an unknown proxy protocol, got %d", rec.Code)
	}
}

func atoiForTest(t *testing.T, s string) int {
	t.Helper()
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("not a port: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// auditHasAction reports whether the trail carries that action.
func auditHasAction(env *testEnv, action string) bool {
	for _, e := range env.audit.Events() {
		if e.Action == action {
			return true
		}
	}
	return false
}
