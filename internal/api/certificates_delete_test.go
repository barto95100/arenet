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
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// seedCertOnDisk creates a fake cert dir under the env's cert storage
// root so the delete handler has something to remove. Returns the leaf
// dir path.
func seedCertOnDisk(t *testing.T, storageDir, issuer, safeDomain string) string {
	t.Helper()
	dir := filepath.Join(storageDir, "certificates", issuer, safeDomain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, safeDomain+".crt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dir
}

func TestDeleteCertificate_Orphan_200(t *testing.T) {
	env := newTestEnv(t, false)
	storageDir := t.TempDir()
	env.handler.SetCertStorageDir(storageDir)
	leaf := seedCertOnDisk(t, storageDir, "local", "orphan.example.com")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/orphan.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	if _, err := os.Stat(leaf); !os.IsNotExist(err) {
		t.Error("cert dir still on disk after delete")
	}
}

func TestDeleteCertificate_BlockedByRouteHost_409(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetCertStorageDir(t.TempDir())
	// A route serves the domain -> not an orphan.
	if _, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "used.example.com",
		Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/used.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s; want 409", rec.Code, rec.Body)
	}
	var resp struct {
		BlockingRoutes []string `json:"blockingRoutes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	found := false
	for _, h := range resp.BlockingRoutes {
		if h == "used.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("blockingRoutes=%v; want it to contain used.example.com", resp.BlockingRoutes)
	}
}

func TestDeleteCertificate_BlockedByDisabledRoute_409(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetCertStorageDir(t.TempDir())
	// A DISABLED route still references the domain -> blocked.
	if _, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "dis.example.com",
		Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		Disabled:  true,
	}); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/dis.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s; want 409 (disabled route still references domain)", rec.Code, rec.Body)
	}
}

func TestDeleteCertificate_GhostRow_Idempotent_200(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetCertStorageDir(t.TempDir()) // empty — no files
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/ghost.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 (idempotent ghost row)", rec.Code, rec.Body)
	}
}

func TestDeleteCertificate_Wildcard_Routes(t *testing.T) {
	env := newTestEnv(t, false)
	storageDir := t.TempDir()
	env.handler.SetCertStorageDir(storageDir)
	seedCertOnDisk(t, storageDir, "acme-v02.api.letsencrypt.org-directory", "wildcard_.darro.ovh")
	// URL-encode the wildcard subject the way the frontend will.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/"+url.PathEscape("*.darro.ovh"), nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 for wildcard", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(storageDir, "certificates", "acme-v02.api.letsencrypt.org-directory", "wildcard_.darro.ovh")); !os.IsNotExist(err) {
		t.Error("wildcard cert dir still present")
	}
}
