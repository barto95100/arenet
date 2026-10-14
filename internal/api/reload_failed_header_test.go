// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// v2.72 — the six write paths that swallow a failed Caddy reload now
// say so on the response.
//
// They keep answering 2xx on purpose: the store write is committed and
// undoing it would be worse — for a certificate delete it is
// impossible, the files are gone. Fourteen other paths roll back and
// answer 500, and that asymmetry is deliberate per handler. What was
// not deliberate is the silence: the UI read the store back, rendered
// the new value, and put a plain success toast on top.
//
// A header rather than a body field because two of the six answer 204
// with nothing to put a field in.

// failingReloader accepts everything except the reload.
type failingReloader struct{ calls int }

func (f *failingReloader) ReloadFromStore(context.Context) error {
	f.calls++
	return errors.New("caddy.Load: http app module: provision: tls: no DNS provider")
}

func TestMaintenancePage_ReloadRefused_IsReportedOnTheResponse(t *testing.T) {
	env := newTestEnv(t, false)
	fr := &failingReloader{}
	env.handler.caddy = fr

	body := `{"html":"<p>back soon</p>"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/maintenance-page",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.handler.putMaintenancePage(rec, req)

	// The write stands — that is the deliberate part.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a committed write must not be undone, body=%s",
			rec.Code, rec.Body)
	}
	if fr.calls == 0 {
		t.Fatal("the reload was never attempted; this test proves nothing")
	}
	// And the operator is told.
	if got := rec.Header().Get("X-Arenet-Reload-Failed"); got != "1" {
		t.Errorf("X-Arenet-Reload-Failed = %q, want 1", got)
	}
}

func TestMaintenancePage_ReloadAccepted_SaysNothing(t *testing.T) {
	// A caveat on every save would be noise and would train the
	// operator to ignore it.
	env := newTestEnv(t, false)

	body := `{"html":"<p>back soon</p>"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/maintenance-page",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.handler.putMaintenancePage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("X-Arenet-Reload-Failed"); got != "" {
		t.Errorf("X-Arenet-Reload-Failed = %q on a clean save; want it absent", got)
	}
}
