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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/automation"
	"github.com/barto95100/arenet/internal/storage"
)

// fakeManager is a stand-in for automation.Manager used by
// tests to assert the API handlers correctly drive the
// recreate-and-swap path + RuleSet swap.
type fakeManager struct {
	rules      automation.RuleSet
	creds      automation.WatcherConfig
	configured bool
	credErr    error
	setRulesN  int
	setCredsN  int
	clearN     int
}

func (f *fakeManager) SetRules(rs automation.RuleSet) { f.setRulesN++; f.rules = rs }
func (f *fakeManager) SetCredentials(cfg automation.WatcherConfig) error {
	f.setCredsN++
	if f.credErr != nil {
		return f.credErr
	}
	f.creds = cfg
	f.configured = true
	return nil
}
func (f *fakeManager) ClearCredentials()           { f.clearN++; f.configured = false }
func (f *fakeManager) CredentialsConfigured() bool { return f.configured }

// withFakeManager registers a fakeManager as the global
// automation.Manager for the test's duration. Restores nil
// on cleanup so concurrent / subsequent tests see a clean
// global.
func withFakeManager(t *testing.T) *fakeManager {
	t.Helper()
	m := &fakeManager{}
	automation.SetManager(m)
	t.Cleanup(func() { automation.SetManager(nil) })
	return m
}

// --- GET /settings/automation -------------------------------------------

func TestAutomation_GET_FreshInstall_ReturnsDefaults(t *testing.T) {
	env := newTestEnv(t, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/automation", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got automationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Rules.AnyEnabled() {
		t.Error("fresh-install GET should report all rules disabled")
	}
	if len(got.Rules.Rules) != len(automation.AllSources()) {
		t.Errorf("rules count = %d, want %d (DefaultRuleSet shape)",
			len(got.Rules.Rules), len(automation.AllSources()))
	}
	if got.Credentials.Configured {
		t.Error("fresh-install GET should report Configured=false")
	}
}

func TestAutomation_GET_SecretsRedacted(t *testing.T) {
	env := newTestEnv(t, false)

	// Seed credentials directly via the store.
	creds := mustSeedWatcherCreds(t, env, "secret-not-leaked")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/automation", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, creds.Password) {
		t.Errorf("password leaked in GET response body: %s", body)
	}
	if !strings.Contains(body, `"configured":true`) {
		t.Errorf("expected configured:true in body: %s", body)
	}
	if !strings.Contains(body, `"machineId":"arenet"`) {
		t.Errorf("expected machineId surfaced (non-secret): %s", body)
	}
}

func TestAutomation_GET_ManagerOverridesStorageConfiguredFlag(t *testing.T) {
	// When a Manager is registered, its
	// CredentialsConfigured() takes precedence over the
	// storage-derived flag — reflects the live writer
	// state. This pins the GET response's contract for
	// when the Manager has just been ClearCredentials'd
	// (storage still has the row from before the rotation,
	// but the live writer is nil).
	env := newTestEnv(t, false)
	mustSeedWatcherCreds(t, env, "secret")
	mgr := withFakeManager(t)
	mgr.configured = false // simulate post-ClearCredentials

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/automation", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	var got automationResponse
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Credentials.Configured {
		t.Error("Manager.CredentialsConfigured=false should override storage")
	}
}

// --- PUT /settings/automation/rules -------------------------------------

func TestAutomation_PUTRules_PersistsAndSwapsLive(t *testing.T) {
	env := newTestEnv(t, false)
	mgr := withFakeManager(t)

	rs := automation.DefaultRuleSet()
	r := rs.Rules[automation.SourceWafSQLi]
	r.Enabled = true
	r.Threshold = 2
	r.Window = 60 * time.Second
	r.Duration = 4 * time.Hour
	r.Cooldown = 24 * time.Hour
	rs.Rules[automation.SourceWafSQLi] = r

	body, _ := json.Marshal(putRulesRequest{Rules: rs})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/automation/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if mgr.setRulesN != 1 {
		t.Errorf("Manager.SetRules calls = %d, want 1", mgr.setRulesN)
	}
	if !mgr.rules.AnyEnabled() {
		t.Error("Manager received rule set with no enabled rules — swap failed?")
	}

	// GET round-trip — the new rules should be persisted.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/settings/automation", nil)
	getRec := httptest.NewRecorder()
	env.router.ServeHTTP(getRec, getReq)
	var got automationResponse
	json.Unmarshal(getRec.Body.Bytes(), &got)
	if !got.Rules.AnyEnabled() {
		t.Error("GET after PUT did not reflect persisted rules")
	}
}

func TestAutomation_PUTRules_RejectsInvalid(t *testing.T) {
	env := newTestEnv(t, false)
	withFakeManager(t)

	// Invalid: enabled rule with threshold=0.
	rs := automation.DefaultRuleSet()
	r := rs.Rules[automation.SourceWafSQLi]
	r.Enabled = true
	r.Threshold = 0
	rs.Rules[automation.SourceWafSQLi] = r

	body, _ := json.Marshal(putRulesRequest{Rules: rs})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/automation/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 — body=%s", rec.Code, rec.Body)
	}
}

func TestAutomation_PUTRules_EmitsAuditEvent(t *testing.T) {
	env := newTestEnv(t, false)
	withFakeManager(t)

	rs := automation.DefaultRuleSet()
	r := rs.Rules[automation.SourceWafSQLi]
	r.Enabled = true
	r.Threshold = 2
	r.Window = 60 * time.Second
	r.Duration = 4 * time.Hour
	rs.Rules[automation.SourceWafSQLi] = r

	body, _ := json.Marshal(putRulesRequest{Rules: rs})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/automation/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}

	found := false
	for _, e := range env.audit.events {
		if e.Action == audit.ActionAutomationRuleChanged {
			found = true
			if e.TargetType != "automation_rules" {
				t.Errorf("audit target_type = %q, want automation_rules", e.TargetType)
			}
		}
	}
	if !found {
		t.Error("ActionAutomationRuleChanged audit event not emitted")
	}
}

// --- PUT /settings/automation/credentials -------------------------------

func TestAutomation_PUTCredentials_HappyPath_RecreatesAndSwaps(t *testing.T) {
	env := newTestEnv(t, false)
	mgr := withFakeManager(t)

	body, _ := json.Marshal(putCredentialsRequest{
		LAPIURL:   "http://127.0.0.1:8080",
		MachineID: "arenet",
		Password:  "secret-xyz",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/automation/credentials", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if mgr.setCredsN != 1 {
		t.Errorf("Manager.SetCredentials calls = %d, want 1", mgr.setCredsN)
	}
	if mgr.creds.MachineID != "arenet" || mgr.creds.Password != "secret-xyz" {
		t.Errorf("Manager.SetCredentials got %+v, want {LAPIURL:http://127.0.0.1:8080 MachineID:arenet Password:secret-xyz}",
			mgr.creds)
	}
}

func TestAutomation_PUTCredentials_PreserveOnEmptyPassword(t *testing.T) {
	// J.4 secret discipline: empty Password on PUT
	// preserves the stored value.
	env := newTestEnv(t, false)
	mgr := withFakeManager(t)
	mustSeedWatcherCreds(t, env, "original-password")

	body, _ := json.Marshal(putCredentialsRequest{
		LAPIURL:   "http://127.0.0.1:8080",
		MachineID: "arenet",
		Password:  "", // empty → preserve
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/automation/credentials", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if mgr.creds.Password != "original-password" {
		t.Errorf("preserve-on-edit failed: Manager got Password=%q, want original-password",
			mgr.creds.Password)
	}
}

func TestAutomation_PUTCredentials_AllBlank_Erases(t *testing.T) {
	env := newTestEnv(t, false)
	mgr := withFakeManager(t)
	mustSeedWatcherCreds(t, env, "secret")

	body, _ := json.Marshal(putCredentialsRequest{})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/automation/credentials", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if mgr.clearN != 1 {
		t.Errorf("Manager.ClearCredentials calls = %d, want 1", mgr.clearN)
	}
}

func TestAutomation_PUTCredentials_PasswordRedactedFromAuditLog(t *testing.T) {
	env := newTestEnv(t, false)
	withFakeManager(t)

	body, _ := json.Marshal(putCredentialsRequest{
		LAPIURL:   "http://127.0.0.1:8080",
		MachineID: "arenet",
		Password:  "must-not-leak",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/automation/credentials", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	for _, e := range env.audit.events {
		if e.Action == audit.ActionAutomationRuleChanged {
			if strings.Contains(string(e.BeforeJSON), "must-not-leak") {
				t.Errorf("password leaked in audit BeforeJSON: %s", e.BeforeJSON)
			}
			if strings.Contains(string(e.AfterJSON), "must-not-leak") {
				t.Errorf("password leaked in audit AfterJSON: %s", e.AfterJSON)
			}
		}
	}
}

// --- helpers ------------------------------------------------------------

// mustSeedWatcherCreds writes a fixed watcher credential
// row directly into storage. Returns the seeded struct so
// the test can compare against it.
func mustSeedWatcherCreds(t *testing.T, env *testEnv, password string) automation.WatcherConfig {
	t.Helper()
	creds := storage.WatcherCredentials{
		LAPIURL:   "http://127.0.0.1:8080",
		MachineID: "arenet",
		Password:  password,
	}
	if err := env.store.PutWatcherCredentials(t.Context(), creds); err != nil {
		t.Fatalf("seed watcher creds: %v", err)
	}
	return automation.WatcherConfig{
		LAPIURL: creds.LAPIURL, MachineID: creds.MachineID, Password: creds.Password,
	}
}
