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
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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

// freeUDPPort is freePort's counterpart for a UDP service.
//
// v2.45.3 — needed because the bind probe now follows the service's
// own protocol. A port free for TCP says nothing about UDP, so the
// UDP fixtures were picking numbers that something else on the
// machine already held — a flake by construction, and one the old
// always-TCP probe hid.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
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

// --- v2.43 — the test sends the header it claims to send ---------
//
// Until now the test opened a connection and closed it. That proved
// the backend accepts connections, which is rarely the thing in
// doubt, and said nothing about the pairing that actually breaks
// relays — the operator could watch a green tick while every real
// connection was being refused. Worse, against a backend that *is*
// configured, the bare dial writes a "proxy protocol error / end of
// stream" line into its log on every click.

// proxyProbeServer accepts one connection, records the first bytes it
// receives, and then either lingers or hangs up — the two behaviours
// that separate a backend expecting the header from one that is not.
func proxyProbeServer(t *testing.T, hangUp bool) (host string, port int, first func() []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var got []byte
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(buf)
		mu.Lock()
		got = append(got, buf[:n]...)
		mu.Unlock()
		if hangUp {
			return
		}
		// Expecting the header: consume it and wait for the real
		// client to speak, which an implicit-TLS port never does
		// until the client sends its ClientHello.
		time.Sleep(1500 * time.Millisecond)
	}()

	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, atoiForTest(t, p), func() []byte {
		<-done
		mu.Lock()
		defer mu.Unlock()
		return got
	}
}

func tcpTestReport(t *testing.T, env *testEnv, id string) tcpServiceTestResponse {
	t.Helper()
	rec := tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services/"+id+"/test", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("test: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var report tcpServiceTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	return report
}

func createTCPServiceForTest(t *testing.T, env *testEnv, over map[string]any) storage.TCPService {
	t.Helper()
	rec := tcpDo(t, env, http.MethodPost, "/api/v1/tcp-services", tcpServiceBody(t, over))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created storage.TCPService
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created: %v", err)
	}
	return created
}

func TestTCPService_TestSendsARealProxyHeader(t *testing.T) {
	env := newTestEnv(t, false)
	host, port, first := proxyProbeServer(t, false)

	created := createTCPServiceForTest(t, env, map[string]any{
		"proxyProtocol": "v2",
		"upstreams":     []map[string]any{{"host": host, "port": port}},
	})

	report := tcpTestReport(t, env, created.ID)
	if len(report.Backends) != 1 || !report.Backends[0].OK {
		t.Fatalf("backend must answer: %+v", report.Backends)
	}
	if report.Backends[0].ProxyProtocol != proxyProbeNotRefused {
		t.Fatalf("a backend that lingers must read as not refused: %+v", report.Backends[0])
	}

	// The bytes on the wire, not the claim: PROXY v2 opens with a
	// fixed 12-byte signature, then 0x21 for version 2 / PROXY, then
	// 0x11 for TCP over IPv4. 16 bytes of header + 12 of addresses.
	sig := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
	got := first()
	if len(got) != 28 {
		t.Fatalf("want a 28-byte v2 header for IPv4/TCP, got %d bytes: %x", len(got), got)
	}
	if !bytes.Equal(got[:12], sig) {
		t.Fatalf("PROXY v2 signature missing: %x", got[:12])
	}
	if got[12] != 0x21 || got[13] != 0x11 {
		t.Fatalf("want version/command 0x21 and family 0x11, got %#x %#x", got[12], got[13])
	}
}

func TestTCPService_TestReportsARefusedHeader(t *testing.T) {
	env := newTestEnv(t, false)
	host, port, _ := proxyProbeServer(t, true)

	created := createTCPServiceForTest(t, env, map[string]any{
		"proxyProtocol": "v2",
		"upstreams":     []map[string]any{{"host": host, "port": port}},
	})

	report := tcpTestReport(t, env, created.ID)
	// The dial succeeded — the backend is up. What it did with the
	// header is the separate verdict, and it is the one that matters.
	if !report.Backends[0].OK {
		t.Fatalf("the backend was reachable: %+v", report.Backends[0])
	}
	if report.Backends[0].ProxyProtocol != proxyProbeRefused {
		t.Fatalf("a backend that hangs up must read as refused: %+v", report.Backends[0])
	}
}

// Without a PROXY protocol configured there is nothing to probe, and
// the result must not pretend otherwise.
func TestTCPService_TestSaysNothingWhenNoHeaderIsSent(t *testing.T) {
	env := newTestEnv(t, false)
	host, port, _ := proxyProbeServer(t, false)

	created := createTCPServiceForTest(t, env, map[string]any{
		"upstreams": []map[string]any{{"host": host, "port": port}},
	})

	report := tcpTestReport(t, env, created.ID)
	if report.Backends[0].ProxyProtocol != "" {
		t.Fatalf("no header sent, no verdict: %+v", report.Backends[0])
	}
	if report.ProxyProtocolNote != "" {
		t.Fatalf("no note either: %q", report.ProxyProtocolNote)
	}
}

// A UDP relay has no connection to open. The previous version dialled
// TCP whatever the protocol said, so a healthy WireGuard or DNS relay
// was reported broken — a confident wrong answer, which is worse than
// admitting the question cannot be answered.
func TestTCPService_TestSkipsUDPInsteadOfFailingIt(t *testing.T) {
	env := newTestEnv(t, false)

	created := createTCPServiceForTest(t, env, map[string]any{
		"name":          "wireguard",
		"protocol":      "udp",
		"listenPort":    freeUDPPort(t),
		"proxyProtocol": "v2",
		"upstreams":     []map[string]any{{"host": "127.0.0.1", "port": freeUDPPort(t)}},
	})

	report := tcpTestReport(t, env, created.ID)
	if len(report.Backends) != 1 {
		t.Fatalf("one result per backend: %+v", report.Backends)
	}
	res := report.Backends[0]
	if !res.Skipped {
		t.Fatalf("a UDP backend must be reported as skipped: %+v", res)
	}
	if res.OK {
		t.Fatalf("skipped is not success: %+v", res)
	}
	if !strings.Contains(res.Error, "connectionless") {
		t.Fatalf("the reason must say why, not just that it failed: %q", res.Error)
	}
	// v2 over UDP is legal, so the pairing note still applies.
	if !strings.Contains(report.ProxyProtocolNote, "proxyTrustedNetworks") {
		t.Fatalf("the note must survive the UDP path: %q", report.ProxyProtocolNote)
	}
}

// --- v2.44.1 — the listen check must not trip over itself --------
//
// Found by the operator on the v2.44 smoke, on the very first item:
// create a service, open it to press "Test the backends", press Save,
// and Arenet answers "cannot listen on 0.0.0.0:18080: something else
// on this host already uses it". The something else was Arenet,
// listening for that exact service. Every edit of a live relay was
// refused — the conflict check already excluded the row being
// replaced, but the bind probe knew nothing about it.

func TestTCPService_UpdateOfALiveServiceIsNotRefusedByItsOwnPort(t *testing.T) {
	env := newTestEnv(t, false)

	// Bind the port for real, the way a running Arenet holds it, and
	// keep it held for the whole update.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := atoiForTest(t, portStr)

	// Create it while the port is free — a second listener on the same
	// address would fail, so create against a free port and then move
	// the fixture: simpler is to create with the store directly.
	created := createTCPServiceForTest(t, env, map[string]any{
		"listenAddr": host,
		"listenPort": freePort(t),
		"upstreams":  []map[string]any{{"host": "10.20.0.5", "port": 993}},
	})

	// Now pretend it listens on the held port: store it, then update
	// something unrelated. The address is unchanged between the stored
	// row and the update, so the probe must be skipped.
	stored, err := env.store.GetTCPService(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	stored.ListenAddr, stored.ListenPort = host, port
	if _, err := env.store.UpdateTCPService(t.Context(), stored); err != nil {
		t.Fatalf("seed the held address: %v", err)
	}

	body := map[string]any{
		"name":          stored.Name,
		"listenAddr":    host,
		"listenPort":    port,
		"upstreams":     []map[string]any{{"host": "10.20.0.5", "port": 993}},
		"proxyProtocol": "v2", // the unrelated change
	}
	rec := tcpDo(t, env, http.MethodPut, "/api/v1/tcp-services/"+created.ID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("editing a live service must be allowed: %d %s", rec.Code, rec.Body.String())
	}
}

// Moving a live service onto a port something else holds must still
// be refused: the skip is narrow, not a hole.
func TestTCPService_MovingOntoATakenPortIsStillRefused(t *testing.T) {
	env := newTestEnv(t, false)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())

	created := createTCPServiceForTest(t, env, map[string]any{
		"listenAddr": host,
		"listenPort": freePort(t),
		"upstreams":  []map[string]any{{"host": "10.20.0.5", "port": 993}},
	})

	rec := tcpDo(t, env, http.MethodPut, "/api/v1/tcp-services/"+created.ID, map[string]any{
		"name":       created.Name,
		"listenAddr": host,
		"listenPort": atoiForTest(t, portStr), // held by the listener above
		"upstreams":  []map[string]any{{"host": "10.20.0.5", "port": 993}},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("moving onto a taken port must be refused: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "already uses it") {
		t.Errorf("the message must say the port is taken: %s", rec.Body.String())
	}
}
