// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package updatecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
	}{
		{"v2.12.3", "v2.12.4", true},  // patch ahead
		{"v2.12.3", "v2.13.0", true},  // minor ahead
		{"v2.12.3", "v3.0.0", true},   // major ahead
		{"v2.12.3", "v2.12.3", false}, // equal
		{"v2.12.4", "v2.12.3", false}, // latest older
		{"2.12.3", "v2.12.4", true},   // tolerate missing leading v
		{"DEV", "v2.12.4", false},     // dev build never reports update
		{"v2.12.3", "garbage", false}, // unparseable latest
	}
	for _, c := range cases {
		if got := compareSemver(c.current, c.latest); got != c.want {
			t.Errorf("compareSemver(%q,%q)=%v want %v", c.current, c.latest, got, c.want)
		}
	}
}

func TestCheck_NewRelease_SetsUpdateAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Etag", `"abc"`)
		_, _ = w.Write([]byte(`{"tag_name":"v2.12.4","html_url":"https://github.com/x/releases/v2.12.4"}`))
	}))
	defer srv.Close()

	c := New("v2.12.3", srv.Client())
	c.releasesURL = srv.URL
	st := c.Check(context.Background())
	if !st.UpdateAvailable || st.Latest != "v2.12.4" {
		t.Errorf("status=%+v; want UpdateAvailable=true Latest=v2.12.4", st)
	}
	if st.URL == "" || st.LastError != "" {
		t.Errorf("status=%+v; want URL set, no error", st)
	}
	if st.LastChecked.IsZero() {
		t.Error("LastChecked not set")
	}
}

func TestCheck_NotModified_KeepsLatest(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("If-None-Match") == `"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Etag", `"abc"`)
		_, _ = w.Write([]byte(`{"tag_name":"v2.12.4","html_url":"u"}`))
	}))
	defer srv.Close()

	c := New("v2.12.3", srv.Client())
	c.releasesURL = srv.URL
	_ = c.Check(context.Background()) // 200, stores Etag
	st := c.Check(context.Background()) // 304
	if st.Latest != "v2.12.4" {
		t.Errorf("304 path dropped Latest: %+v", st)
	}
	if calls != 2 {
		t.Errorf("calls=%d want 2", calls)
	}
	if st.LastError != "" {
		t.Errorf("304 must clear LastError: %+v", st)
	}
}

func TestCheck_Failure_SetsLastError_NoAlarm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New("v2.12.3", srv.Client())
	c.releasesURL = srv.URL
	st := c.Check(context.Background())
	if st.LastError == "" {
		t.Error("expected LastError on 500")
	}
	if st.UpdateAvailable {
		t.Error("failed check must not report an update")
	}
}

func TestCheck_MalformedBody_SetsLastError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	c := New("v2.12.3", srv.Client())
	c.releasesURL = srv.URL
	st := c.Check(context.Background())
	if st.LastError == "" {
		t.Error("expected LastError on malformed body")
	}
}
