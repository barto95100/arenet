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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maxmind/geoipupdate/v8/client"

	"github.com/barto95100/arenet/internal/geo"
)

// v2.28 — a second Updater manages GeoLite2-ASN next to the City one.

func newASNUpdater(t *testing.T, dl DownloadFunc, asn *geo.ASNLookup, path string) *Updater {
	t.Helper()
	u, err := New(Config{
		Store:     okStore(),
		Reloader:  asn,
		Verify:    geo.VerifyASNMMDB,
		EditionID: "GeoLite2-ASN",
		Kind:      "ASN",
		MMDBPath:  path,
		Download:  dl,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestASNUpdater_DownloadsASNEditionAndReloads(t *testing.T) {
	asnBytes := testdataMMDB(t, "asn.mmdb")
	var asked string
	dl := func(_ context.Context, _ int, _, edition, _ string) (client.DownloadResponse, error) {
		asked = edition
		return client.DownloadResponse{UpdateAvailable: true, Reader: io.NopCloser(bytes.NewReader(asnBytes))}, nil
	}
	asn := &geo.ASNLookup{}
	u := newASNUpdater(t, dl, asn, filepath.Join(t.TempDir(), "GeoLite2-ASN.mmdb"))
	if r := u.UpdateOnce(context.Background()); r.Status != StatusUpdated {
		t.Fatalf("status=%q error=%q", r.Status, r.Error)
	}
	if asked != "GeoLite2-ASN" {
		t.Errorf("downloaded edition %q, want GeoLite2-ASN (not the stored City edition)", asked)
	}
	if got := asn.LookupASN(net.ParseIP("1.0.0.1")); got.ASN != 15169 {
		t.Errorf("reloaded ASN lookup = %+v", got)
	}
}

func TestASNUpdater_GuardRejectsCityDB(t *testing.T) {
	cityBytes := testdataMMDB(t, "city.mmdb")
	dl := func(context.Context, int, string, string, string) (client.DownloadResponse, error) {
		return client.DownloadResponse{UpdateAvailable: true, Reader: io.NopCloser(bytes.NewReader(cityBytes))}, nil
	}
	u := newASNUpdater(t, dl, &geo.ASNLookup{}, filepath.Join(t.TempDir(), "asn.mmdb"))
	r := u.UpdateOnce(context.Background())
	if r.Status != StatusError || !strings.Contains(r.Error, "not an ASN database") {
		t.Errorf("status=%q error=%q", r.Status, r.Error)
	}
}

func TestGroup_CombinesResults(t *testing.T) {
	cityBytes := testdataMMDB(t, "city.mmdb")
	cityDL := func(context.Context, int, string, string, string) (client.DownloadResponse, error) {
		return client.DownloadResponse{UpdateAvailable: true, Reader: io.NopCloser(bytes.NewReader(cityBytes))}, nil
	}
	asnDL := func(context.Context, int, string, string, string) (client.DownloadResponse, error) {
		return client.DownloadResponse{}, errors.New("network down")
	}
	city := newTestUpdater(t, okStore(), cityDL, filepath.Join(t.TempDir(), "city.mmdb"))
	asn := newASNUpdater(t, asnDL, &geo.ASNLookup{}, filepath.Join(t.TempDir(), "asn.mmdb"))
	g := NewGroup(city, nil, asn)

	r := g.UpdateOnce(context.Background())
	if r.Status != StatusError || !strings.HasPrefix(r.Error, "ASN: ") {
		t.Fatalf("combined = %+v, want error prefixed by the failing kind", r)
	}
	if st := g.Status(); st.Status != StatusError || st.At.IsZero() {
		t.Errorf("Status() = %+v", st)
	}
	if city.Status().Status != StatusUpdated {
		t.Error("a failing member must not prevent the others from updating")
	}
}

func TestGroup_RunStopsOnCancel(t *testing.T) {
	u := newTestUpdater(t, fakeStore{err: errors.New("x")}, failDownload(t), filepath.Join(t.TempDir(), "c.mmdb"))
	u.warmup = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { NewGroup(u).Run(ctx, time.Hour); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Group.Run did not return after cancel")
	}
}
