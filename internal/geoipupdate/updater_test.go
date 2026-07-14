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

package geoipupdate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/geoipupdate/v8/client"

	"github.com/barto95100/arenet/internal/geo"
	"github.com/barto95100/arenet/internal/storage"
)

// fakeStore is a CredStore test double returning a canned config or error.
type fakeStore struct {
	cfg storage.MaxMindConfig
	err error
}

func (f fakeStore) GetMaxMindConfig(_ context.Context) (storage.MaxMindConfig, error) {
	if f.err != nil {
		return storage.MaxMindConfig{}, f.err
	}
	return f.cfg, nil
}

// okStore returns a fakeStore with valid credentials.
func okStore() fakeStore {
	return fakeStore{cfg: storage.MaxMindConfig{
		AccountID:  1,
		LicenseKey: "k",
		EditionID:  "GeoLite2-City",
	}}
}

// failDownload returns a DownloadFunc that fails the test if invoked —
// used when a test asserts the flow never reaches the download step.
func failDownload(t *testing.T) DownloadFunc {
	t.Helper()
	return func(_ context.Context, _ int, _, _, _ string) (client.DownloadResponse, error) {
		t.Fatal("Download must not be called")
		return client.DownloadResponse{}, nil
	}
}

func newTestUpdater(t *testing.T, store CredStore, dl DownloadFunc, mmdbPath string) *Updater {
	t.Helper()
	u, err := New(Config{
		Store:    store,
		Lookup:   &geo.Lookup{},
		MMDBPath: mmdbPath,
		Download: dl,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return u
}

func TestUpdateOnce_NoCredentials(t *testing.T) {
	store := fakeStore{err: storage.ErrNotFound}
	u := newTestUpdater(t, store, failDownload(t), filepath.Join(t.TempDir(), "db.mmdb"))
	r := u.UpdateOnce(context.Background())
	if r.Status != StatusNoCreds {
		t.Fatalf("status=%q want no_credentials", r.Status)
	}
}

func TestUpdateOnce_UpToDate_NoWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.mmdb")
	// down returns UpdateAvailable:false
	dl := func(_ context.Context, _ int, _, _, _ string) (client.DownloadResponse, error) {
		return client.DownloadResponse{UpdateAvailable: false, Reader: io.NopCloser(bytes.NewReader(nil))}, nil
	}
	u := newTestUpdater(t, okStore(), dl, path)
	r := u.UpdateOnce(context.Background())
	if r.Status != StatusUpToDate {
		t.Fatalf("status=%q want up_to_date", r.Status)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("up_to_date must not write a file")
	}
}

func TestUpdateOnce_DownloadError_PreservesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.mmdb")
	os.WriteFile(path, []byte("OLD-DB"), 0o644)
	dl := func(_ context.Context, _ int, _, _, _ string) (client.DownloadResponse, error) {
		return client.DownloadResponse{}, errors.New("network boom")
	}
	u := newTestUpdater(t, okStore(), dl, path)
	r := u.UpdateOnce(context.Background())
	if r.Status != StatusError {
		t.Fatalf("status=%q want error", r.Status)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "OLD-DB" {
		t.Fatalf("existing DB was clobbered: %q", b)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf(".tmp left behind")
	}
}

func TestUpdateOnce_Bootstrap_PassesEmptyMD5(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.mmdb") // absent
	var gotMD5 string
	dl := func(_ context.Context, _ int, _, _, md5 string) (client.DownloadResponse, error) {
		gotMD5 = md5
		return client.DownloadResponse{UpdateAvailable: false, Reader: io.NopCloser(bytes.NewReader(nil))}, nil
	}
	u := newTestUpdater(t, okStore(), dl, path)
	u.UpdateOnce(context.Background())
	if gotMD5 != "" {
		t.Fatalf("bootstrap md5=%q want empty", gotMD5)
	}
}
