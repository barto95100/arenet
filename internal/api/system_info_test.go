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
	"net/http"
	"testing"

	"github.com/barto95100/arenet/internal/sysinfo"
)

// v2.45 — GET /system/info.
//
// Unlike /system/health this one sits behind auth: it names the
// machine, its kernel and its free disk. Nothing catastrophic, but
// nothing an unauthenticated probe needs either.

type stubSystemInfo struct{ snap sysinfo.Snapshot }

func (s stubSystemInfo) Snapshot() sysinfo.Snapshot { return s.snap }

func TestSystemInfo_ReportsTheSnapshot(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetSystemInfoReader(stubSystemInfo{snap: sysinfo.Snapshot{
		Host:   sysinfo.Host{Hostname: "arenet-test", Containerised: true},
		Memory: sysinfo.Memory{TotalBytes: 536870912, Source: sysinfo.SourceContainer},
	}})

	rec := tcpDo(t, env, http.MethodGet, "/api/v1/system/info", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got sysinfo.Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Host.Hostname != "arenet-test" {
		t.Errorf("hostname: %+v", got.Host)
	}
	// The source must survive the wire: without it the UI cannot say
	// whether 512 MiB is the machine or the container's ceiling.
	if got.Memory.Source != sysinfo.SourceContainer {
		t.Errorf("source lost on the wire: %+v", got.Memory)
	}
}

// No reader wired: an honest empty snapshot beats a 500, the same
// posture /system/health already takes.
func TestSystemInfo_WithoutAReaderSaysSo(t *testing.T) {
	env := newTestEnv(t, false)

	rec := tcpDo(t, env, http.MethodGet, "/api/v1/system/info", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got sysinfo.Snapshot
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Unsupported == "" {
		t.Error("an unwired endpoint must say why it is empty")
	}
}
