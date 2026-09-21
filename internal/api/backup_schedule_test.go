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
	"path/filepath"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/autobackup"
	"github.com/barto95100/arenet/internal/storage"
)

const schedulePass = "scheduled backup passphrase"

// withAutoBackup wires a real autobackup.Service on a temp data dir.
func withAutoBackup(t *testing.T, env *testEnv) (dataDir string, applied *[]storage.BackupScheduleConfig) {
	t.Helper()
	dataDir = t.TempDir()
	users := auth.NewUserStore(env.store.DB())
	if _, err := users.Create(context.Background(), "sched-admin", "Sched Admin", "", "sched-admin-pw-15c-x"); err != nil {
		t.Fatalf("user: %v", err)
	}
	svc := autobackup.New(autobackup.Config{Store: env.store, Users: users, DataDir: dataDir, Version: "test"})
	applied = &[]storage.BackupScheduleConfig{}
	env.handler.SetAutoBackup(svc, func(c storage.BackupScheduleConfig) { *applied = append(*applied, c) })
	return dataDir, applied
}

func doJSON(t *testing.T, env *testEnv, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func scheduleBody(mutate func(map[string]any)) map[string]any {
	b := map[string]any{
		"enabled": true, "frequency": "daily", "time": "03:00", "weekday": 0, "keep": 5,
		"dir": "", "passphrase": schedulePass, "emailMode": "never", "emailChannelId": "", "alertChannelIds": []string{},
	}
	mutate(b)
	return b
}

func TestBackupSchedule_UnavailableWithoutService(t *testing.T) {
	env := newTestEnv(t, false)
	if rec := doJSON(t, env, http.MethodGet, "/api/v1/settings/backup-schedule", nil); rec.Code != http.StatusConflict {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestBackupSchedule_PutValidation(t *testing.T) {
	env := newTestEnv(t, false)
	withAutoBackup(t, env)
	cases := []struct {
		name   string
		mutate func(map[string]any)
		code   string
	}{
		{"short passphrase", func(b map[string]any) { b["passphrase"] = "short" }, codePassphraseTooShort},
		{"enabled without passphrase", func(b map[string]any) { b["passphrase"] = "" }, codePassphraseRequired},
		{"missing NAS dir", func(b map[string]any) { b["dir"] = filepath.Join(t.TempDir(), "not-mounted") }, codeBackupDirUnwritable},
		{"relative dir", func(b map[string]any) { b["dir"] = "backups" }, "absolute"},
		{"email without channel", func(b map[string]any) { b["emailMode"] = "weekly" }, "email channel"},
		{"bad time", func(b map[string]any) { b["time"] = "25:00" }, "HH:MM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doJSON(t, env, http.MethodPut, "/api/v1/settings/backup-schedule", scheduleBody(tc.mutate))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.code) {
				t.Fatalf("status %d body %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestBackupSchedule_EndToEnd(t *testing.T) {
	env := newTestEnv(t, false)
	dataDir, applied := withAutoBackup(t, env)

	rec := doJSON(t, env, http.MethodPut, "/api/v1/settings/backup-schedule", scheduleBody(func(map[string]any) {}))
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), schedulePass) || !strings.Contains(rec.Body.String(), `"passphraseSet":true`) {
		t.Errorf("passphrase exposed or not flagged: %s", rec.Body)
	}
	if len(*applied) != 1 || !(*applied)[0].Enabled {
		t.Errorf("schedule not applied: %+v", *applied)
	}
	var view backupScheduleResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view.EffectiveDir != filepath.Join(dataDir, "backups") || view.NextRunAt == nil || view.TimeZone == "" {
		t.Errorf("view %+v", view)
	}
	// A second PUT without passphrase keeps the stored one.
	rec = doJSON(t, env, http.MethodPut, "/api/v1/settings/backup-schedule", scheduleBody(func(b map[string]any) { b["passphrase"] = ""; b["keep"] = 3 }))
	if rec.Code != http.StatusOK {
		t.Fatalf("second put: %d %s", rec.Code, rec.Body)
	}
	if cfg, _ := env.store.GetBackupSchedule(context.Background()); cfg.Passphrase != schedulePass || cfg.Keep != 3 {
		t.Errorf("stored %+v", cfg)
	}
	var auditOK bool
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionBackupScheduleUpdated {
			auditOK = true
			if strings.Contains(string(e.BeforeJSON)+string(e.AfterJSON), schedulePass) {
				t.Error("passphrase in the audit log")
			}
		}
	}
	if !auditOK {
		t.Error("no backup_schedule_updated audit event")
	}

	rec = doJSON(t, env, http.MethodPost, "/api/v1/admin/backups/run", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("run: %d %s", rec.Code, rec.Body)
	}
	var res autobackup.Result
	_ = json.Unmarshal(rec.Body.Bytes(), &res)

	rec = doJSON(t, env, http.MethodGet, "/api/v1/admin/backups", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), res.File) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	rec = doJSON(t, env, http.MethodGet, "/api/v1/admin/backups/"+res.File, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"encryption"`) || strings.Contains(rec.Body.String(), schedulePass) {
		t.Fatalf("download: %d", rec.Code)
	}
	for _, bad := range []string{"..%2Farenet.db", "arenet.key", "..%2F..%2Fetc%2Fpasswd"} {
		if rec := doJSON(t, env, http.MethodGet, "/api/v1/admin/backups/"+bad, nil); rec.Code != http.StatusNotFound {
			t.Errorf("traversal %q: %d", bad, rec.Code)
		}
	}

	// Restore from the list uses the stored passphrase.
	_ = env.store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{LAPIURL: "http://c:8080/", APIKey: "added-after-backup"})
	rec = doJSON(t, env, http.MethodPost, "/api/v1/admin/backups/"+res.File+"/restore", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body)
	}
	if _, err := env.store.GetCrowdSecConfig(context.Background()); err == nil {
		t.Error("restore did not bring back the backed-up state (CrowdSec row added later should be gone)")
	}

	if rec := doJSON(t, env, http.MethodDelete, "/api/v1/admin/backups/"+res.File, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := doJSON(t, env, http.MethodGet, "/api/v1/admin/backups/"+res.File, nil); rec.Code != http.StatusNotFound {
		t.Errorf("deleted file still served: %d", rec.Code)
	}
}
