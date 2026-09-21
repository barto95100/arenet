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
	"encoding/base64"
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

// TestBackup_Export_PlaintextSecretsRefused: the former plaintext
// export with secrets is gone (v2.31) — it must be encrypted.
func TestBackup_Export_PlaintextSecretsRefused(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/backup?include-secrets=true", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), codePassphraseRequired) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

// postEncryptedExport runs POST /admin/backup with passphrase.
func postEncryptedExport(t *testing.T, env *testEnv, passphrase string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"passphrase": passphrase})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/backup", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func postRestoreWithPassphrase(t *testing.T, env *testEnv, file []byte, passphrase string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/restore", strings.NewReader(string(file)))
	req.Header.Set("Content-Type", "application/json")
	if passphrase != "" {
		req.Header.Set(headerBackupPassphrase, base64.StdEncoding.EncodeToString([]byte(passphrase)))
	}
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func TestBackup_EncryptedExportAndRestore(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()
	if _, err := auth.NewUserStore(env.store.DB()).Create(ctx, "enc-admin", "Enc Admin", "", "enc-admin-pw-15c-xx"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := env.store.PutCrowdSecConfig(ctx, storage.CrowdSecConfig{LAPIURL: "http://c:8080/", APIKey: "API-SECRET-KEY"}); err != nil {
		t.Fatalf("seed crowdsec: %v", err)
	}
	const pass = "une phrase de passe 🔐 longue"

	if rec := postEncryptedExport(t, env, "short"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), codePassphraseTooShort) {
		t.Fatalf("short passphrase: %d %s", rec.Code, rec.Body)
	}
	rec := postEncryptedExport(t, env, pass)
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, rec.Body)
	}
	file := rec.Body.Bytes()
	if strings.Contains(string(file), "API-SECRET-KEY") || !strings.Contains(string(file), `"encryption"`) {
		t.Fatalf("export not encrypted: %s", file[:200])
	}
	if rec.Header().Get("X-Arenet-Backup-Encrypted") != "true" {
		t.Errorf("missing X-Arenet-Backup-Encrypted header")
	}

	if rec := postRestoreWithPassphrase(t, env, file, ""); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), codePassphraseRequired) {
		t.Errorf("no passphrase: %d %s", rec.Code, rec.Body)
	}
	if rec := postRestoreWithPassphrase(t, env, file, "wrong passphrase here"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), codePassphraseInvalid) {
		t.Errorf("wrong passphrase: %d %s", rec.Code, rec.Body)
	}
	// Change the live key, then restore: the backup's value comes back.
	_ = env.store.PutCrowdSecConfig(ctx, storage.CrowdSecConfig{LAPIURL: "http://c:8080/", APIKey: "CHANGED"})
	if rec := postRestoreWithPassphrase(t, env, file, pass); rec.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body)
	}
	if cs, _ := env.store.GetCrowdSecConfig(ctx); cs.APIKey != "API-SECRET-KEY" {
		t.Errorf("restored key %q", cs.APIKey)
	}
	var rejected int
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionConfigRestoredRejected && strings.Contains(e.Message, "reason=passphrase_") {
			rejected++
		}
	}
	if rejected != 2 {
		t.Errorf("want 2 passphrase rejections audited, got %d", rejected)
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

// scriptedCrowdSecApplier returns errs[i] on the i-th call (nil past
// the end) and records every call.
type scriptedCrowdSecApplier struct {
	errs  []error
	calls []fakeCrowdSecApplierCall
}

func (s *scriptedCrowdSecApplier) ApplyCrowdSecConfig(_ context.Context, apiURL, apiKey string) error {
	s.calls = append(s.calls, fakeCrowdSecApplierCall{apiURL: apiURL, apiKey: apiKey})
	if i := len(s.calls) - 1; i < len(s.errs) {
		return s.errs[i]
	}
	return nil
}

// extrasRestoreBody builds a restore body carrying the v2.26 extras
// with a CrowdSec row and enabled update / GeoIP schedules.
func extrasRestoreBody(t *testing.T, env *testEnv, crowdSecKey string) []byte {
	t.Helper()
	us := auth.NewUserStore(env.store.DB())
	admin, err := us.Create(context.Background(), "extras-admin", "Extras Admin", "", "extras-admin-pw-15c")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	snap := backup.Snapshot{
		SchemaVersion:   backup.SchemaVersion,
		SecretsIncluded: true,
		Users:           []auth.User{admin},
		Extras: &backup.SnapshotExtras{
			CrowdSecConfig: &storage.CrowdSecConfig{LAPIURL: "http://crowdsec:8080/", APIKey: crowdSecKey},
			UpdateCheck:    &storage.UpdateCheckConfig{Enabled: true},
			GeoIPUpdate:    &storage.GeoIPUpdateConfig{Enabled: true},
		},
	}
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

// TestBackup_Restore_Extras_AppliesRestoredSettings: a restore that
// carries the extras swaps in the restored CrowdSec settings (single
// reload) and re-schedules the update / GeoIP checks.
func TestBackup_Restore_Extras_AppliesRestoredSettings(t *testing.T) {
	env := newTestEnv(t, false)
	applier := &scriptedCrowdSecApplier{}
	env.handler.SetCrowdSecApplier(applier)
	var gotUpdate, gotGeoIP bool
	env.handler.SetUpdateConfigHook(func(c storage.UpdateCheckConfig) { gotUpdate = c.Enabled })
	env.handler.SetGeoIPConfigHook(func(c storage.GeoIPUpdateConfig) { gotGeoIP = c.Enabled })

	body := extrasRestoreBody(t, env, "restored-key")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/restore", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if len(applier.calls) != 1 || applier.calls[0].apiKey != "restored-key" {
		t.Errorf("crowdsec applier calls: %+v", applier.calls)
	}
	if !gotUpdate || !gotGeoIP {
		t.Errorf("hooks not fired: update=%t geoip=%t", gotUpdate, gotGeoIP)
	}
	var resp restoreResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !resp.ExtrasImported {
		t.Errorf("response extrasImported: %+v (%v)", resp, err)
	}
}

// TestBackup_Restore_Extras_ReloadFailure_RestoresCrowdSec: when the
// CrowdSec swap-and-reload fails, the store is rolled back AND the
// pre-restore CrowdSec settings are swapped back into the manager.
func TestBackup_Restore_Extras_ReloadFailure_RestoresCrowdSec(t *testing.T) {
	env := newTestEnv(t, false)
	if err := env.store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{
		LAPIURL: "http://old:8080/", APIKey: "old-key",
	}); err != nil {
		t.Fatalf("seed crowdsec: %v", err)
	}
	applier := &scriptedCrowdSecApplier{errs: []error{errReloadBoom}}
	env.handler.SetCrowdSecApplier(applier)
	hookFired := false
	env.handler.SetUpdateConfigHook(func(storage.UpdateCheckConfig) { hookFired = true })

	body := extrasRestoreBody(t, env, "restored-key")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/restore", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d body=%s", rec.Code, rec.Body)
	}
	if len(applier.calls) != 2 || applier.calls[1].apiKey != "old-key" {
		t.Errorf("want restored key then old key, got %+v", applier.calls)
	}
	if cs, _ := env.store.GetCrowdSecConfig(context.Background()); cs.APIKey != "old-key" {
		t.Errorf("store not rolled back: %+v", cs)
	}
	if hookFired {
		t.Error("settings hooks must not fire on a rolled-back restore")
	}
}
