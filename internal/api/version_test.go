// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/internal/updatecheck"
)

// putJSONRaw issues a PUT with a JSON body through the env router.
func putJSONRaw(t *testing.T, env *testEnv, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func TestSystemVersion_ReportsStatus(t *testing.T) {
	env := newTestEnv(t, false)
	chk := updatecheck.New("v2.12.3", nil)
	env.handler.SetUpdateChecker(chk)
	_ = env.store.PutUpdateCheckConfig(context.Background(), storage.UpdateCheckConfig{Enabled: true})

	rec := getRec(t, env, "/api/v1/system/version")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["current"] != "v2.12.3" {
		t.Errorf("current=%v", body["current"])
	}
	if body["enabled"] != true {
		t.Errorf("enabled=%v; want true", body["enabled"])
	}
}

func TestSystemVersion_NilChecker_ReportsDisabled(t *testing.T) {
	env := newTestEnv(t, false)
	// no SetUpdateChecker → nil-tolerant path
	rec := getRec(t, env, "/api/v1/system/version")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["enabled"] != false || body["updateAvailable"] != false {
		t.Errorf("nil checker must report enabled:false updateAvailable:false; got %v", body)
	}
}

func TestSystemVersionConfig_TogglesEnabled(t *testing.T) {
	env := newTestEnv(t, false)
	chk := updatecheck.New("v2.12.3", nil)
	env.handler.SetUpdateChecker(chk)

	body := map[string]any{"enabled": true, "intervalOverride": ""}
	rec := putJSONRaw(t, env, "/api/v1/system/version/config", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("config PUT status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.GetUpdateCheckConfig(context.Background())
	if !got.Enabled {
		t.Error("config PUT did not persist enabled=true")
	}
}

func TestSystemVersionConfig_RejectsShortInterval(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetUpdateChecker(updatecheck.New("v2.12.3", nil))
	rec := putJSONRaw(t, env, "/api/v1/system/version/config", map[string]any{"enabled": true, "intervalOverride": "5m"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d; want 400 for interval below the 1h minimum; body=%s", rec.Code, rec.Body)
	}
}
