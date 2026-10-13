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

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// v2.51 — a MOVED LAPI address needs a process restart, and the response
// has to say so.
//
// Observed on 2026-09-27: moving a LAPI from 127.0.0.1 to a WireGuard
// address reloaded Caddy, re-provisioned the bouncer with the new URL,
// and the bouncer then logged `address: http://10.66.0.1:8080` while
// every request still went to `http://127.0.0.1:8080`. Something under
// the bouncer retains the previous address until the process restarts.
//
// The reason this needs surfacing rather than documenting: the bouncer
// fails OPEN. For as long as it cannot reach LAPI it blocks nothing at
// all, and no other screen says so. An operator who believes the save
// took effect is unprotected and cannot tell.

func putCrowdSecBody(t *testing.T, h *Handler, body string) crowdSecResponse {
	t.Helper()
	req := reqWithAuth(http.MethodPut, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.putCrowdSecSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var out crowdSecResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v\n%s", err, rec.Body.String())
	}
	return out
}

func TestPutCrowdSecSettings_MovedURL_SignalsRestart(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	// v2.72 — the precondition is now explicit: the applier reports
	// the address the RUNNING bouncer dials. Empty means no bouncer has
	// been provisioned in this process, which is the state of a fresh
	// install and the reason the first PUT claims nothing.
	applier := &fakeCrowdSecApplier{}
	h.SetCrowdSecApplier(applier)

	// First PUT configures; nothing is running yet, so no restart is
	// claimed.
	first := putCrowdSecBody(t, h,
		`{"lapiUrl":"http://127.0.0.1:8080","apiKey":"k1","bouncerName":"arenet","timeoutSeconds":5}`)
	if first.RestartRequired {
		t.Error("the first configuration must not demand a restart — nothing is running yet")
	}

	// The reload provisions the bouncer on that address.
	applier.liveURL = "http://127.0.0.1:8080"

	// Now move the address. The bouncer keeps the old one.
	moved := putCrowdSecBody(t, h,
		`{"lapiUrl":"http://10.66.0.1:8080","apiKey":"","bouncerName":"arenet","timeoutSeconds":5}`)
	if !moved.RestartRequired {
		t.Fatal("moving the LAPI address must signal that a restart is needed")
	}
	// And the operator is warned in the log too, since they may be
	// driving this from the API rather than the UI.
	if !bytes.Contains(logBuf.Bytes(), []byte("LAPI address changed")) {
		t.Errorf("no warning logged when the address moved:\n%s", logBuf.String())
	}
}

// TestGetCrowdSecSettings_StillSignalsRestartAfterAReload is the
// regression this derivation exists for.
//
// restartRequired used to be computed from the PUT's own before/after,
// so it was true exactly once — in that one response. The settings
// component held it in a bare $state that no GET refreshed, so one F5,
// one tab close or a second admin's browser lost the only warning that
// the bouncer was reaching nothing and therefore blocking nothing.
func TestGetCrowdSecSettings_StillSignalsRestartAfterAReload(t *testing.T) {
	h := newTestHandler(t, &fakeAuditAppender{}, io.Discard)
	applier := &fakeCrowdSecApplier{}
	h.SetCrowdSecApplier(applier)

	putCrowdSecBody(t, h,
		`{"lapiUrl":"http://127.0.0.1:8080","apiKey":"k1","bouncerName":"arenet","timeoutSeconds":5}`)
	applier.liveURL = "http://127.0.0.1:8080"
	putCrowdSecBody(t, h,
		`{"lapiUrl":"http://10.66.0.1:8080","apiKey":"","bouncerName":"arenet","timeoutSeconds":5}`)

	// A plain read — what a page reload does.
	getReq := reqWithAuth(http.MethodGet, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	getRec := httptest.NewRecorder()
	h.getCrowdSecSettings(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body=%s", getRec.Code, getRec.Body.String())
	}
	var got crowdSecResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.RestartRequired {
		t.Error("a GET must keep reporting the pending restart — the bouncer is still on the old address")
	}

	// And it stops once the process has restarted onto the new one,
	// which is what a fresh boot looks like: the live address is
	// captured from the stored config.
	applier.liveURL = "http://10.66.0.1:8080"
	getRec2 := httptest.NewRecorder()
	h.getCrowdSecSettings(getRec2, reqWithAuth(http.MethodGet, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test"))
	var after crowdSecResponse
	_ = json.Unmarshal(getRec2.Body.Bytes(), &after)
	if after.RestartRequired {
		t.Error("the warning must clear by itself once the bouncer dials the stored address")
	}
}

// Rotating only the key re-provisions cleanly. Demanding a restart for
// it would teach the operator to ignore the signal.
func TestPutCrowdSecSettings_KeyOnly_NoRestart(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	h.SetCrowdSecApplier(&fakeCrowdSecApplier{})

	putCrowdSecBody(t, h,
		`{"lapiUrl":"http://127.0.0.1:8080","apiKey":"k1","bouncerName":"arenet","timeoutSeconds":5}`)
	rotated := putCrowdSecBody(t, h,
		`{"lapiUrl":"http://127.0.0.1:8080","apiKey":"k2","bouncerName":"arenet","timeoutSeconds":5}`)

	if rotated.RestartRequired {
		t.Error("rotating the key alone must not demand a restart")
	}
	if bytes.Contains(logBuf.Bytes(), []byte("LAPI address changed")) {
		t.Error("a key rotation must not log an address change")
	}
}
