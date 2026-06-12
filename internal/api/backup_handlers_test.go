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

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/backup"
	"github.com/barto95100/arenet/internal/storage"
)

// TestBackup_Export_RedactedAndAuditEmitted exercises the admin
// happy path: GET /admin/backup with the auto-auth admin session,
// default redacted, audit event recorded.
func TestBackup_Export_RedactedAndAuditEmitted(t *testing.T) {
	env := newTestEnv(t, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/backup", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"secrets_included": false`) {
		t.Errorf("default export should declare secrets_included=false: %s", body[:200])
	}
	if rec.Header().Get("X-Arenet-Secrets-Included") != "" {
		t.Errorf("default export should NOT set X-Arenet-Secrets-Included header")
	}

	// Audit event present.
	var sawExport bool
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionConfigExported {
			sawExport = true
			if !strings.Contains(e.Message, "secrets_included=false") {
				t.Errorf("audit message missing secrets_included flag: %s", e.Message)
			}
		}
	}
	if !sawExport {
		t.Error("config_exported audit event not emitted")
	}
}

func TestBackup_Export_IncludeSecretsSetsHeader(t *testing.T) {
	env := newTestEnv(t, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/backup?include-secrets=true", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if rec.Header().Get("X-Arenet-Secrets-Included") != "true" {
		t.Errorf("include-secrets=true should set X-Arenet-Secrets-Included: got %q", rec.Header().Get("X-Arenet-Secrets-Included"))
	}
	if !strings.Contains(rec.Body.String(), `"secrets_included": true`) {
		t.Errorf("include-secrets export should declare secrets_included=true")
	}
}

// TestBackup_RequireAdmin_ViewerRejectedOnExport pins the role gate:
// viewer GET /admin/backup → 403. Defence-in-depth — the engine
// validates secrets discipline; the HTTP gate validates the actor.
func TestBackup_RequireAdmin_ViewerRejectedOnExport(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()
	viewer, err := auth.NewUserStore(env.store.DB()).CreateOIDCUser(ctx, "viewer-backup-one", "Viewer One", "", "sub-viewer-backup-one")
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	sess, err := auth.NewSessionStore(env.store.DB()).Create(ctx, viewer.ID, false, "127.0.0.1", "t/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/backup", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("VIEWER ESCALATION REGRESSION: viewer GET /admin/backup returned %d; expected 403", rec.Code)
	}
}

// TestBackup_RequireAdmin_ViewerRejectedOnRestore pins the role gate
// on the destructive path.
func TestBackup_RequireAdmin_ViewerRejectedOnRestore(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()
	viewer, err := auth.NewUserStore(env.store.DB()).CreateOIDCUser(ctx, "viewer-backup-two", "Viewer Two", "", "sub-viewer-backup-two")
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	sess, err := auth.NewSessionStore(env.store.DB()).Create(ctx, viewer.ID, false, "127.0.0.1", "t/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	body := `{"schema_version":"1.0.0","users":[]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/restore", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("VIEWER ESCALATION REGRESSION: viewer POST /admin/restore returned %d; expected 403", rec.Code)
	}
}

// TestBackup_Restore_CaddyReloadFailure_RollsBackBoltDB pins the
// Step K.3 Q4 invariant: if ReloadFromStore fails AFTER the BoltDB
// commit, the handler MUST re-apply the pre-restore snapshot so
// the storage matches what Caddy is still serving from memory.
//
// Test flow:
//  1. Seed live: 1 admin user + 1 route ("original.example.com").
//  2. Build a snapshot replacing that route with a different host
//     ("replaced.example.com") + keeping the live user.
//  3. Prime the fakeReloader to fail on the next reload.
//  4. POST /admin/restore → expect 500 + rollback audit.
//  5. Verify the LIVE store has been rolled back to the original
//     route, NOT the replaced one — ROLLBACK BYPASS REGRESSION
//     assert if the post-state shows "replaced.example.com".
func TestBackup_Restore_CaddyReloadFailure_RollsBackBoltDB(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()

	// Seed live state.
	us := auth.NewUserStore(env.store.DB())
	originalRoute, err := env.store.CreateRoute(ctx, mustCreateRoute("original.example.com"))
	if err != nil {
		t.Fatalf("seed original route: %v", err)
	}
	originalUser, err := us.Create(ctx, "rollback-admin", "Rollback Admin", "", "rollback-pw-15c-xx")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Build a snapshot replacing the route. Same user (keeps
	// the local-admin guard happy).
	snap := backup.Snapshot{
		SchemaVersion:   backup.SchemaVersion,
		SecretsIncluded: true,
		Users:           []auth.User{originalUser},
		Routes: []storage.Route{
			mustCreateRouteWithID("route-replaced-id", "replaced.example.com"),
		},
	}
	body, _ := json.Marshal(snap)

	// Prime the next reload to fail.
	env.caddy.SetNextErr(errReloadBoom)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/restore", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on reload failure, got %d body=%s", rec.Code, rec.Body)
	}

	// The live store MUST have been rolled back to the original
	// route. Failure here means the handler committed a restore
	// AND never undid it on the reload failure — Caddy serving
	// the OLD config + BoltDB on the NEW config = divergent.
	routesAfter, err := env.store.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("list routes after rollback: %v", err)
	}
	if len(routesAfter) != 1 {
		t.Fatalf("ROLLBACK BYPASS REGRESSION: expected 1 route after rollback, got %d: %+v", len(routesAfter), routesAfter)
	}
	if routesAfter[0].ID != originalRoute.ID {
		t.Fatalf("ROLLBACK BYPASS REGRESSION: live route id=%q after rollback; expected pre-restore id=%q", routesAfter[0].ID, originalRoute.ID)
	}
	if routesAfter[0].Host != "original.example.com" {
		t.Fatalf("ROLLBACK BYPASS REGRESSION: live route host=%q after rollback; expected %q (replaced state leaked)", routesAfter[0].Host, "original.example.com")
	}

	// Audit must carry the rolled-back marker.
	var sawRollback bool
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionConfigRestoredRejected &&
			strings.Contains(e.Message, "caddy_reload_failed_rolled_back") {
			sawRollback = true
		}
	}
	if !sawRollback {
		t.Error("audit must carry reason=caddy_reload_failed_rolled_back on the rollback path")
	}
}

// Sentinel reload error reused across tests.
var errReloadBoom = errReload("caddy reload boom")

type errReload string

func (e errReload) Error() string { return string(e) }

// mustCreateRoute returns a minimal valid Route shape for the
// rollback test. The host is the only thing that varies between
// the original and the replacement.
func mustCreateRoute(host string) storage.Route {
	return storage.Route{
		Host:      host,
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  "round_robin",
		AuthMode:  "none",
		WAFMode:   "off",
	}
}

func mustCreateRouteWithID(id, host string) storage.Route {
	r := mustCreateRoute(host)
	r.ID = id
	return r
}

// TestBackup_Restore_RejectsAndEmitsRejectedAudit pins AC #15bis on
// the failure path: a rejected restore (empty users, no bypass)
// returns 400 AND emits config_restored_rejected with the reason
// token. The audit-on-failure discipline is what lets an operator
// trace "did someone try to take over my instance?".
func TestBackup_Restore_RejectsAndEmitsRejectedAudit(t *testing.T) {
	env := newTestEnv(t, false)

	snap := backup.Snapshot{
		SchemaVersion: backup.SchemaVersion,
		// Users empty + no allow-empty-users → reject.
		Users:           []auth.User{},
		SecretsIncluded: true,
	}
	body, _ := json.Marshal(snap)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/restore", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "Two paths forward") {
		t.Errorf("restore reject body must contain 'Two paths forward' guidance: %s", rec.Body)
	}

	var sawRejected bool
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionConfigRestoredRejected {
			sawRejected = true
			if !strings.Contains(e.Message, "reason=empty_users") {
				t.Errorf("audit message missing reason=empty_users: %s", e.Message)
			}
		}
	}
	if !sawRejected {
		t.Error("NEVER SILENT REGRESSION: config_restored_rejected audit event not emitted on a rejected restore")
	}
}
