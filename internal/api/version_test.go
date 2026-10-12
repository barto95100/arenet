// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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

// v2.72 — the interval survives a toggle of the checkbox.
//
// UpdatesSection.svelte sends `{enabled}` and nothing else, the handler
// built a fresh storage.UpdateCheckConfig from the request, and
// PutUpdateCheckConfig is a bare Put with no read-modify-write. So any
// stored IntervalOverride was erased by the operator clicking "check
// for updates" — the exact shape found in four of the five operator
// forms on 2026-10-12.
//
// Worse than "the form cannot show it": nothing could. There was no GET
// reporting the interval, which openapi/backup-system.yaml stated
// outright, so the field could not be seen, could not be re-entered,
// and was destroyed by an unrelated click. The value reaches the store
// through the admin API or a backup restore.
func TestSystemVersionConfig_IntervalSurvivesAToggle(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetUpdateChecker(updatecheck.New("v2.12.3", nil))

	// An operator (or a restore) sets a custom cadence.
	rec := putJSONRaw(t, env, "/api/v1/system/version/config",
		map[string]any{"enabled": true, "intervalOverride": "24h"})
	if rec.Code != http.StatusOK {
		t.Fatalf("seeding the interval: status=%d body=%s", rec.Code, rec.Body)
	}

	// Then the UI toggles the checkbox, sending only `enabled`.
	rec = putJSONRaw(t, env, "/api/v1/system/version/config",
		map[string]any{"enabled": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle: status=%d body=%s", rec.Code, rec.Body)
	}

	got, err := env.store.GetUpdateCheckConfig(context.Background())
	if err != nil {
		t.Fatalf("GetUpdateCheckConfig: %v", err)
	}
	if got.Enabled {
		t.Error("the toggle did not persist enabled=false")
	}
	if got.IntervalOverride != "24h" {
		t.Errorf("IntervalOverride = %q, want %q — a request that omits the field "+
			"must leave it alone, not erase it", got.IntervalOverride, "24h")
	}
}

// Clearing it has to stay possible, or the fix above just replaces one
// dead end with another: an explicit empty string means "back to the
// default cadence".
func TestSystemVersionConfig_ExplicitEmptyClearsTheInterval(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetUpdateChecker(updatecheck.New("v2.12.3", nil))

	putJSONRaw(t, env, "/api/v1/system/version/config",
		map[string]any{"enabled": true, "intervalOverride": "24h"})
	rec := putJSONRaw(t, env, "/api/v1/system/version/config",
		map[string]any{"enabled": true, "intervalOverride": ""})
	if rec.Code != http.StatusOK {
		t.Fatalf("clear: status=%d body=%s", rec.Code, rec.Body)
	}

	got, _ := env.store.GetUpdateCheckConfig(context.Background())
	if got.IntervalOverride != "" {
		t.Errorf("IntervalOverride = %q, want empty — an explicit \"\" is a clear, "+
			"not a no-op", got.IntervalOverride)
	}
}

// And it has to be readable, which is what let this hide for the whole
// v2 line: a field no response carries cannot be managed by anyone.
func TestSystemVersion_ReportsTheInterval(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetUpdateChecker(updatecheck.New("v2.12.3", nil))

	putJSONRaw(t, env, "/api/v1/system/version/config",
		map[string]any{"enabled": true, "intervalOverride": "24h"})

	rec := getRec(t, env, "/api/v1/system/version")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["intervalOverride"] != "24h" {
		t.Errorf("GET /system/version intervalOverride = %v, want %q", body["intervalOverride"], "24h")
	}
}
