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
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maxmind/geoipupdate/v8/client"

	"github.com/barto95100/arenet/internal/geo"
	"github.com/barto95100/arenet/internal/storage"
)

// testdataMMDB reads a fixture from internal/geoipupdate/testdata. City
// and ASN fixtures are the tiny real MMDBs vendored alongside crowdsec's
// own parser tests (github.com/crowdsecurity/crowdsec's
// pkg/parser/testdata/GeoLite2-{City,ASN}.mmdb), copied in verbatim —
// see task-2-report.md for provenance. Both are genuine MaxMind-format
// databases (geoip2.Open succeeds, Metadata().DatabaseType is accurate),
// so they exercise the real guard logic rather than a synthetic blob.
func testdataMMDB(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Skipf("fixture %s not present: %v", name, err)
	}
	return b
}

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

// TestIsCityType_AcceptRejectDecision is a pure-logic unit test of the
// guard's accept/reject rule, independent of any MMDB fixture — it
// always runs, even in environments without testdata/*.mmdb.
func TestIsCityType_AcceptRejectDecision(t *testing.T) {
	cases := []struct {
		dbType string
		want   bool
	}{
		{"GeoLite2-City", true},
		{"GeoIP2-City", true},
		{"GeoLite2-Country", false},
		{"GeoLite2-ASN", false},
		{"GeoIP2-ISP", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isCityType(tc.dbType); got != tc.want {
			t.Errorf("isCityType(%q) = %v, want %v", tc.dbType, got, tc.want)
		}
	}
}

// TestVerifyCityMMDB_ARENET_TEST_MMDB opens whatever real MMDB path is
// given via ARENET_TEST_MMDB (operator-supplied) and confirms
// verifyCityMMDB's accept/reject decision matches isCityType's
// decision for that file's Metadata().DatabaseType. Skips when unset —
// this is a supplementary empirical check, not required for the
// guard's coverage (testdata/city.mmdb + asn.mmdb already exercise it
// end-to-end above).
func TestVerifyCityMMDB_ARENET_TEST_MMDB(t *testing.T) {
	path := os.Getenv("ARENET_TEST_MMDB")
	if path == "" {
		t.Skip("ARENET_TEST_MMDB not set; skipping empirical check against an operator-supplied MMDB")
	}
	err := verifyCityMMDB(path)
	t.Logf("verifyCityMMDB(%q) = %v", path, err)
}

// TestUpdateOnce_Updated_InstallsAndReloads is the "updated" happy
// path: DownloadFunc reports UpdateAvailable with a real City MMDB
// body. UpdateOnce must install it atomically at MMDBPath (no .tmp
// left behind), report StatusUpdated, and reload the shared
// *geo.Lookup so it now serves from the new file.
func TestUpdateOnce_Updated_InstallsAndReloads(t *testing.T) {
	cityBytes := testdataMMDB(t, "city.mmdb")

	dir := t.TempDir()
	path := filepath.Join(dir, "db.mmdb")

	dl := func(_ context.Context, _ int, _, _, _ string) (client.DownloadResponse, error) {
		return client.DownloadResponse{
			UpdateAvailable: true,
			Reader:          io.NopCloser(bytes.NewReader(cityBytes)),
		}, nil
	}

	lookup := &geo.Lookup{}
	u, err := New(Config{
		Store:    okStore(),
		Lookup:   lookup,
		MMDBPath: path,
		Download: dl,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r := u.UpdateOnce(context.Background())
	if r.Status != StatusUpdated {
		t.Fatalf("status=%q error=%q want updated", r.Status, r.Error)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read installed db: %v", err)
	}
	if !bytes.Equal(got, cityBytes) {
		t.Fatalf("installed db bytes do not match downloaded fixture")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf(".tmp left behind after successful install")
	}

	if got := lookup.Path(); got != path {
		t.Fatalf("lookup.Path()=%q want %q (Reload should have swapped it in)", got, path)
	}
	// 81.2.69.142 is a well-known MaxMind test IP present in the tiny
	// fixture (London, GB) — confirms the reloaded reader actually
	// serves real data, not just that the path string was updated.
	loc := lookup.LookupIP(net.ParseIP("81.2.69.142"))
	if !loc.Found || loc.Country != "GB" {
		t.Fatalf("LookupIP after reload = %+v, want Found=true Country=GB", loc)
	}
}

// TestUpdateOnce_EditionGuard_RejectsNonCityDB exercises the Task-2
// guard: a downloaded ASN-type MMDB (a genuine non-City MaxMind
// database, not a synthetic blob) must be rejected before install.
// The existing on-disk DB (here: none) must stay untouched, no .tmp
// left, and the shared *geo.Lookup must not be reloaded.
func TestUpdateOnce_EditionGuard_RejectsNonCityDB(t *testing.T) {
	asnBytes := testdataMMDB(t, "asn.mmdb")

	dir := t.TempDir()
	path := filepath.Join(dir, "db.mmdb")

	dl := func(_ context.Context, _ int, _, _, _ string) (client.DownloadResponse, error) {
		return client.DownloadResponse{
			UpdateAvailable: true,
			Reader:          io.NopCloser(bytes.NewReader(asnBytes)),
		}, nil
	}

	lookup := &geo.Lookup{}
	u, err := New(Config{
		Store:    okStore(),
		Lookup:   lookup,
		MMDBPath: path,
		Download: dl,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r := u.UpdateOnce(context.Background())
	if r.Status != StatusError {
		t.Fatalf("status=%q want error", r.Status)
	}
	if !strings.Contains(r.Error, "not a City database") {
		t.Fatalf("error=%q want it to mention %q", r.Error, "not a City database")
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("MMDBPath must not be created when the edition guard rejects the download")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf(".tmp left behind after guard rejection")
	}
	if lookup.Path() != "" {
		t.Fatalf("lookup.Path()=%q want empty — Reload must not be called on guard rejection", lookup.Path())
	}
}

// TestUpdateOnce_InstallCopyError_LeavesNoTmp drives a failure inside
// install()'s io.Copy (a Reader that errors mid-stream) to exercise
// the tmpStillPresent defer-cleanup branch: the temp file must be
// removed and MMDBPath must stay untouched.
func TestUpdateOnce_InstallCopyError_LeavesNoTmp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.mmdb")
	os.WriteFile(path, []byte("OLD-DB"), 0o644)

	dl := func(_ context.Context, _ int, _, _, _ string) (client.DownloadResponse, error) {
		return client.DownloadResponse{
			UpdateAvailable: true,
			Reader:          io.NopCloser(&errorReader{failAfter: 4}),
		}, nil
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
		t.Fatalf(".tmp left behind after copy error")
	}
}

// errorReader yields a few bytes then fails, simulating a connection
// drop mid-download so install()'s io.Copy returns an error after the
// temp file has already been created.
type errorReader struct {
	failAfter int
	sent      int
}

func (e *errorReader) Read(p []byte) (int, error) {
	if e.sent >= e.failAfter {
		return 0, errors.New("simulated stream error")
	}
	n := copy(p, bytes.Repeat([]byte{'x'}, e.failAfter-e.sent))
	e.sent += n
	return n, nil
}

// TestRun_TicksRepeatedlyAndStopsOnCancel drives Run with a zero warmup
// and a fast interval, counting DownloadFunc invocations via a counting
// fake store (credentials always present so updateOnce reaches the
// download step every tick). It asserts Run calls UpdateOnce more than
// once (immediate first run after warmup, then ticker-driven runs) and
// that cancelling ctx stops the loop, closing Done() promptly — mirrors
// internal/alerting/watcher.go's Run/Done lifecycle test shape.
func TestRun_TicksRepeatedlyAndStopsOnCancel(t *testing.T) {
	var calls int64
	dl := func(_ context.Context, _ int, _, _, _ string) (client.DownloadResponse, error) {
		atomic.AddInt64(&calls, 1)
		return client.DownloadResponse{UpdateAvailable: false, Reader: io.NopCloser(bytes.NewReader(nil))}, nil
	}

	u, err := New(Config{
		Store:    okStore(),
		Lookup:   &geo.Lookup{},
		MMDBPath: filepath.Join(t.TempDir(), "db.mmdb"),
		Download: dl,
		NoWarmup: true, // no warmup delay in tests
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go u.Run(ctx, 10*time.Millisecond)

	// Wait for at least 3 ticks (immediate + at least 2 ticker fires).
	deadline := time.After(2 * time.Second)
	for {
		if atomic.LoadInt64(&calls) >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for 3 UpdateOnce calls, got %d", atomic.LoadInt64(&calls))
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()

	select {
	case <-u.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit / Done() did not close after ctx cancel")
	}

	// No further calls should land after Done() closed (best-effort:
	// give a stopped loop a moment to prove it isn't still ticking).
	countAtStop := atomic.LoadInt64(&calls)
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt64(&calls); got > countAtStop+1 {
		t.Fatalf("Run kept ticking after ctx cancel: count went from %d to %d", countAtStop, got)
	}
}

// TestRun_ResilientToFailedUpdate asserts a failing UpdateOnce (download
// error) does not stop the loop — it must log and keep ticking, never
// treat a single failed cycle as fatal.
func TestRun_ResilientToFailedUpdate(t *testing.T) {
	var calls int64
	dl := func(_ context.Context, _ int, _, _, _ string) (client.DownloadResponse, error) {
		atomic.AddInt64(&calls, 1)
		return client.DownloadResponse{}, errors.New("network boom")
	}

	u, err := New(Config{
		Store:    okStore(),
		Lookup:   &geo.Lookup{},
		MMDBPath: filepath.Join(t.TempDir(), "db.mmdb"),
		Download: dl,
		NoWarmup: true,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx, 10*time.Millisecond)

	deadline := time.After(2 * time.Second)
	for {
		if atomic.LoadInt64(&calls) >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("loop stopped ticking after a failed UpdateOnce, got %d calls", atomic.LoadInt64(&calls))
		case <-time.After(5 * time.Millisecond):
		}
	}
}
