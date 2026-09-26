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

package main

import (
	"os"
	"path/filepath"
	"testing"

	appconfig "github.com/barto95100/arenet/internal/config"
)

func TestBackupPassphrase(t *testing.T) {
	env := func(k string) string {
		if k == envBackupPassphrase {
			return "from the environment"
		}
		return ""
	}
	cfg := &appconfig.Config{}
	if got, _ := backupPassphrase(cfg, env); got != "from the environment" {
		t.Errorf("env fallback = %q", got)
	}
	file := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(file, []byte("from a file  \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.PassphraseFile = file
	if got, _ := backupPassphrase(cfg, env); got != "from a file  " {
		t.Errorf("file wins, only the line ending is trimmed: %q", got)
	}
	cfg.PassphraseFile = filepath.Join(t.TempDir(), "missing")
	if _, err := backupPassphrase(cfg, env); err == nil {
		t.Error("a missing passphrase file must be an error, not a silent fallback")
	}
}
