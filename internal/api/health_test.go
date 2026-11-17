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
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/auth"
)

// TestHealthz_Returns200WithStatusOK exercises GET /healthz end-to-end
// through the full chi.Router built by NewRouter (Step H.3). The test
// also implicitly verifies that the endpoint is reachable WITHOUT
// authentication — the assertion would fail with 401/403 if /healthz
// had been mounted inside one of the auth-gated subgroups.
func TestHealthz_Returns200WithStatusOK(t *testing.T) {
	h := newTestHandler(t, &fakeAuditAppender{}, &bytes.Buffer{})
	ipExtractor, err := auth.NewIPExtractor("")
	if err != nil {
		t.Fatalf("NewIPExtractor: %v", err)
	}
	router := NewRouter(h, false, ipExtractor, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}

	var body healthzResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q; want \"ok\"", body.Status)
	}
	// uptime_seconds is captured via time.Since on a startTime set in
	// NewHandler. In a fast unit test the elapsed time is typically
	// 0; the only invariant we can assert is non-negative.
	if body.UptimeSeconds < 0 {
		t.Errorf("uptime_seconds = %d; want >= 0", body.UptimeSeconds)
	}
}

// TestHealthz_ByteIdentical pins the /healthz wire contract that Zabbix
// reads every minute: exactly {"status":"ok","uptime_seconds":N} with
// only N varying — no extra key, no rename. This is a non-goal guard for
// v2.83 (the health work enriches the automation GET, never /healthz). A
// struct-decode test would not notice an added field; a byte/key check
// does.
func TestHealthz_ByteIdentical(t *testing.T) {
	h := newTestHandler(t, &fakeAuditAppender{}, &bytes.Buffer{})
	ipExtractor, err := auth.NewIPExtractor("")
	if err != nil {
		t.Fatalf("NewIPExtractor: %v", err)
	}
	router := NewRouter(h, false, ipExtractor, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Exactly two keys, the expected names, status "ok".
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw) != 2 {
		t.Fatalf("/healthz has %d keys %v, want exactly {status, uptime_seconds}", len(raw), keysOf(raw))
	}
	if _, ok := raw["status"]; !ok {
		t.Error("missing status key")
	}
	if _, ok := raw["uptime_seconds"]; !ok {
		t.Error("missing uptime_seconds key")
	}

	// Raw shape + key order (what a text-matching probe like Zabbix sees).
	got := strings.TrimRight(rec.Body.String(), "\n")
	if !regexp.MustCompile(`^\{"status":"ok","uptime_seconds":\d+\}$`).MatchString(got) {
		t.Errorf("/healthz body = %s, want {\"status\":\"ok\",\"uptime_seconds\":N}", got)
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
