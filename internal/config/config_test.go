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

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// withEnv saves + clears the given env vars for the test body,
// restoring them at the end. ALL ARENET_* vars are cleared so a
// stray host env (e.g. ARENET_DATA_DIR set in the dev shell)
// doesn't leak into the precedence assertions.
func withEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	saved := map[string]string{}
	saw := map[string]bool{}
	// Capture every existing ARENET_ var so we can restore.
	for _, kv := range os.Environ() {
		// kv is "KEY=value"; we only need the key.
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				k := kv[:i]
				if len(k) >= 7 && k[:7] == "ARENET_" {
					saved[k] = kv[i+1:]
					saw[k] = true
				}
				break
			}
		}
	}
	// Clear them all.
	for k := range saved {
		_ = os.Unsetenv(k)
	}
	// Apply the test-specific set.
	for k, v := range vars {
		_ = os.Setenv(k, v)
		saw[k] = true
	}
	t.Cleanup(func() {
		for k := range saw {
			if v, ok := saved[k]; ok {
				_ = os.Setenv(k, v)
			} else {
				_ = os.Unsetenv(k)
			}
		}
	})
}

func TestDefault(t *testing.T) {
	withEnv(t, nil)
	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AdminPort != ":8001" {
		t.Errorf("AdminPort: got %q, want :8001", cfg.AdminPort)
	}
	if cfg.DataDir != "./data" {
		t.Errorf("DataDir: got %q, want ./data", cfg.DataDir)
	}
	if cfg.Dev {
		t.Errorf("Dev: got true, want false")
	}
}

func TestEnvOverridesDefault(t *testing.T) {
	withEnv(t, map[string]string{
		"ARENET_ADMIN_BIND": ":9099",
		"ARENET_DATA_DIR":   "/tmp/arenet-test",
		"ARENET_DEV":        "true",
	})
	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AdminPort != ":9099" {
		t.Errorf("AdminPort: got %q, want :9099", cfg.AdminPort)
	}
	if cfg.DataDir != "/tmp/arenet-test" {
		t.Errorf("DataDir: got %q, want /tmp/arenet-test", cfg.DataDir)
	}
	if !cfg.Dev {
		t.Errorf("Dev: got false, want true")
	}
}

func TestFlagOverridesEnv(t *testing.T) {
	withEnv(t, map[string]string{
		"ARENET_ADMIN_BIND": ":9099",
		"ARENET_DATA_DIR":   "/tmp/arenet-env",
	})
	cfg, err := Load([]string{"--admin-port=:7777", "--data-dir=/tmp/arenet-flag"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AdminPort != ":7777" {
		t.Errorf("AdminPort: got %q, want :7777 (flag wins)", cfg.AdminPort)
	}
	if cfg.DataDir != "/tmp/arenet-flag" {
		t.Errorf("DataDir: got %q, want /tmp/arenet-flag (flag wins)", cfg.DataDir)
	}
}

func TestFileLayer(t *testing.T) {
	withEnv(t, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "arenet.toml")
	body := `
admin-bind = ":4242"
data-dir   = "/srv/arenet"
dev        = true
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load([]string{"--config=" + path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AdminPort != ":4242" {
		t.Errorf("AdminPort: got %q, want :4242 (file)", cfg.AdminPort)
	}
	if cfg.DataDir != "/srv/arenet" {
		t.Errorf("DataDir: got %q, want /srv/arenet (file)", cfg.DataDir)
	}
	if !cfg.Dev {
		t.Errorf("Dev: got false, want true (file)")
	}
	if cfg.ConfigPath != path {
		t.Errorf("ConfigPath: got %q, want %q", cfg.ConfigPath, path)
	}
}

func TestPrecedenceFullStack(t *testing.T) {
	// File sets all three, env overrides AdminPort, flag overrides
	// DataDir. The final config picks the highest-precedence value
	// for each field independently.
	withEnv(t, map[string]string{
		"ARENET_ADMIN_BIND": ":7000", // overrides file
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "arenet.toml")
	body := `
admin-bind = ":4242"
data-dir   = "/file/arenet"
dev        = false
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load([]string{
		"--config=" + path,
		"--data-dir=/flag/arenet", // overrides file (no env for this field)
		"--dev=true",              // overrides file
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AdminPort != ":7000" {
		t.Errorf("AdminPort: got %q, want :7000 (env over file)", cfg.AdminPort)
	}
	if cfg.DataDir != "/flag/arenet" {
		t.Errorf("DataDir: got %q, want /flag/arenet (flag over file)", cfg.DataDir)
	}
	if !cfg.Dev {
		t.Errorf("Dev: got false, want true (flag over file)")
	}
}

func TestFileMissingIsNotError(t *testing.T) {
	withEnv(t, nil)
	cfg, err := Load([]string{"--config=/does/not/exist.toml"})
	if err != nil {
		t.Fatalf("Load: missing file should not be an error, got %v", err)
	}
	if cfg.AdminPort != ":8001" {
		t.Errorf("AdminPort: got %q, want :8001 (default — file silently absent)", cfg.AdminPort)
	}
}

func TestFileMalformedIsError(t *testing.T) {
	withEnv(t, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.toml")
	if err := os.WriteFile(path, []byte("this is = not [valid toml"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := Load([]string{"--config=" + path})
	if err == nil {
		t.Fatalf("Load: malformed TOML should fail, got nil")
	}
}

func TestConfigPathFromEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "via-env.toml")
	body := `admin-bind = ":5555"`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	withEnv(t, map[string]string{
		"ARENET_CONFIG": path,
	})
	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AdminPort != ":5555" {
		t.Errorf("AdminPort: got %q, want :5555 (ARENET_CONFIG picked the file)", cfg.AdminPort)
	}
}

func TestFlagConfigOverridesEnvConfig(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "env.toml")
	flagFile := filepath.Join(dir, "flag.toml")
	if err := os.WriteFile(envFile, []byte(`admin-bind = ":1111"`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(flagFile, []byte(`admin-bind = ":2222"`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	withEnv(t, map[string]string{
		"ARENET_CONFIG": envFile,
	})
	cfg, err := Load([]string{"--config=" + flagFile})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AdminPort != ":2222" {
		t.Errorf("AdminPort: got %q, want :2222 (--config flag wins over ARENET_CONFIG env)", cfg.AdminPort)
	}
}

func TestBackupFlagsParse(t *testing.T) {
	withEnv(t, nil)
	cfg, err := Load([]string{"--export=/tmp/dump.tar", "--include-secrets"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ExportPath != "/tmp/dump.tar" {
		t.Errorf("ExportPath: got %q, want /tmp/dump.tar", cfg.ExportPath)
	}
	if !cfg.IncludeSecrets {
		t.Errorf("IncludeSecrets: got false, want true")
	}
}

func TestHealthcheckFlag(t *testing.T) {
	withEnv(t, nil)
	cfg, err := Load([]string{"--healthcheck=http://127.0.0.1:8001/healthz"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HealthcheckURL != "http://127.0.0.1:8001/healthz" {
		t.Errorf("HealthcheckURL: got %q, want http://127.0.0.1:8001/healthz", cfg.HealthcheckURL)
	}
}
