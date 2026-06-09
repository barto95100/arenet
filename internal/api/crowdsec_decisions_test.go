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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// sampleLAPIDecisions is the payload shape LAPI's
// /v1/decisions returns: a JSON array of decision objects.
// Field set mirrors the swagger model — pointers for the
// "Required: true" fields, plain strings for the optional
// `until` / `uuid`.
const sampleLAPIDecisions = `[
  {
    "id": 1,
    "duration": "168h",
    "origin": "CAPI",
    "scenario": "crowdsecurity/community-blocklist",
    "scope": "ip",
    "type": "ban",
    "value": "1.2.3.4",
    "until": "2026-06-16T10:00:00Z"
  },
  {
    "id": 2,
    "duration": "24h",
    "origin": "CAPI",
    "scenario": "crowdsecurity/community-blocklist",
    "scope": "range",
    "type": "ban",
    "value": "5.6.7.0/24",
    "until": "2026-06-10T10:00:00Z"
  },
  {
    "id": 3,
    "duration": "4h",
    "origin": "crowdsec",
    "scenario": "crowdsecurity/http-cve",
    "scope": "ip",
    "type": "ban",
    "value": "10.0.0.5",
    "until": "2026-06-09T14:00:00Z"
  },
  {
    "id": 4,
    "duration": "1h",
    "origin": "cscli",
    "scenario": "manual",
    "scope": "ip",
    "type": "ban",
    "value": "192.0.2.42",
    "until": "2026-06-09T11:00:00Z"
  }
]`

// seedCrowdSecConfig persists a stored row pointing at the
// given LAPI URL, with a known API key. Returns the configured
// handler ready for endpoint calls.
func seedCrowdSecConfig(t *testing.T, h *Handler, lapiURL string) {
	t.Helper()
	if err := h.store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{
		LAPIURL:        lapiURL,
		APIKey:         "test-key",
		BouncerName:    "arenet",
		TimeoutSeconds: 5,
	}); err != nil {
		t.Fatalf("seed crowdsec config: %v", err)
	}
}

func TestCrowdSecDecisions_NotConfigured_Returns404(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not configured") {
		t.Errorf("body lacks 'not configured' message: %s", rec.Body.String())
	}
}

func TestCrowdSecDecisions_HappyPath_ReturnsFullList(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "test-key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleLAPIDecisions))
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedCrowdSecConfig(t, h, lapi.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp lapiDecisionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(resp.Decisions) != 4 {
		t.Errorf("decisions count = %d, want 4", len(resp.Decisions))
	}
	if resp.Meta.Total != 4 {
		t.Errorf("meta.total = %d, want 4", resp.Meta.Total)
	}
	// Origin breakdown over the full response.
	if resp.Meta.TotalByOrigin["CAPI"] != 2 {
		t.Errorf("CAPI count = %d, want 2", resp.Meta.TotalByOrigin["CAPI"])
	}
	if resp.Meta.TotalByOrigin["crowdsec"] != 1 {
		t.Errorf("crowdsec count = %d, want 1", resp.Meta.TotalByOrigin["crowdsec"])
	}
	if resp.Meta.TotalByOrigin["cscli"] != 1 {
		t.Errorf("cscli count = %d, want 1", resp.Meta.TotalByOrigin["cscli"])
	}
}

func TestCrowdSecDecisions_SourceFilter_AppliedClientSide(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// LAPI never receives an `origin` query — we filter
		// AFTER receiving the full list.
		if r.URL.Query().Get("origin") != "" {
			t.Errorf("origin query forwarded to LAPI — expected client-side filter")
		}
		_, _ = w.Write([]byte(sampleLAPIDecisions))
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedCrowdSecConfig(t, h, lapi.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions?source=cscli", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	var resp lapiDecisionsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Meta.Total != 1 {
		t.Errorf("filtered total = %d, want 1", resp.Meta.Total)
	}
	if len(resp.Decisions) != 1 || resp.Decisions[0].Origin != "cscli" {
		t.Errorf("filter didn't slice to cscli only: %+v", resp.Decisions)
	}
	// Breakdown reflects the FULL response, not the filtered slice.
	if resp.Meta.TotalByOrigin["CAPI"] != 2 {
		t.Errorf("breakdown should be over full response, got CAPI=%d", resp.Meta.TotalByOrigin["CAPI"])
	}
}

func TestCrowdSecDecisions_ScopeFilter_ForwardedToLAPI(t *testing.T) {
	scopeSeen := ""
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scopeSeen = r.URL.Query().Get("scope")
		_, _ = w.Write([]byte(sampleLAPIDecisions))
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedCrowdSecConfig(t, h, lapi.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions?scope=range", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	if scopeSeen != "range" {
		t.Errorf("scope param not forwarded to LAPI: got %q, want %q", scopeSeen, "range")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestCrowdSecDecisions_Pagination_AppliedAfterFilter(t *testing.T) {
	// Build a 12-element response so the [offset:offset+limit]
	// slice has something to bite.
	bigList := buildBigDecisionList(12)
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(bigList))
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedCrowdSecConfig(t, h, lapi.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions?limit=5&offset=3", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	var resp lapiDecisionsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Decisions) != 5 {
		t.Errorf("page size = %d, want 5", len(resp.Decisions))
	}
	if resp.Meta.Total != 12 {
		t.Errorf("meta.total = %d, want 12 (pre-pagination)", resp.Meta.Total)
	}
	if resp.Meta.Limit != 5 || resp.Meta.Offset != 3 {
		t.Errorf("limit/offset echo wrong: %+v", resp.Meta)
	}
}

func TestCrowdSecDecisions_Pagination_OffsetBeyondEnd_ReturnsEmpty(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sampleLAPIDecisions))
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedCrowdSecConfig(t, h, lapi.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions?offset=999", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp lapiDecisionsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Decisions) != 0 {
		t.Errorf("expected empty page on out-of-range offset, got %d", len(resp.Decisions))
	}
	if resp.Meta.Total != 4 {
		t.Errorf("meta.total should still reflect filtered set, got %d", resp.Meta.Total)
	}
}

func TestCrowdSecDecisions_LAPI401_Returns502(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedCrowdSecConfig(t, h, lapi.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "authentication failed") {
		t.Errorf("body lacks auth-failed message: %s", rec.Body.String())
	}
}

func TestCrowdSecDecisions_LAPIRefused_Returns502(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	// LAPI never bound — connection refused.
	seedCrowdSecConfig(t, h, "http://127.0.0.1:1")
	// Also bring the timeout low so the test runs fast.
	cfg, _ := h.store.GetCrowdSecConfig(context.Background())
	cfg.TimeoutSeconds = 1
	_ = h.store.PutCrowdSecConfig(context.Background(), cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "refused") && !strings.Contains(body, "connection") {
		t.Errorf("body lacks refused/connection message: %s", body)
	}
}

func TestCrowdSecDecisions_LAPI204_ReturnsEmptyList(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedCrowdSecConfig(t, h, lapi.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp lapiDecisionsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Decisions) != 0 || resp.Meta.Total != 0 {
		t.Errorf("204 should yield empty: %+v", resp)
	}
}

func TestCrowdSecDecisions_LAPI200_NullBody_ReturnsEmptyList(t *testing.T) {
	// LAPI sometimes emits `null` instead of `[]` when no
	// decisions are active and the strict swagger contract
	// fires. The handler must accept this as empty, not 502.
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("null"))
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedCrowdSecConfig(t, h, lapi.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp lapiDecisionsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Decisions) != 0 {
		t.Errorf("expected empty list on null body, got %d", len(resp.Decisions))
	}
}

func TestCrowdSecDecisions_MalformedLAPIBody_Returns502(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[not json"))
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedCrowdSecConfig(t, h, lapi.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "malformed") {
		t.Errorf("body lacks malformed message: %s", rec.Body.String())
	}
}

func TestCrowdSecDecisions_BadLimit_Returns400(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedCrowdSecConfig(t, h, "http://127.0.0.1:8080")

	for _, tt := range []struct {
		name string
		qs   string
	}{
		{"non-numeric limit", "?limit=abc"},
		{"zero limit", "?limit=0"},
		{"over-cap limit", "?limit=101"},
		{"negative offset", "?offset=-1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions"+tt.qs, nil)
			rec := httptest.NewRecorder()
			h.listCrowdSecDecisions(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCrowdSecDecisions_ExpiresAtFromUntil_Canonicalised(t *testing.T) {
	body := `[{
        "id": 1,
        "duration": "1h",
        "origin": "CAPI",
        "scenario": "x",
        "scope": "ip",
        "type": "ban",
        "value": "1.1.1.1",
        "until": "2026-06-09T10:30:00.123Z"
    }]`
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer lapi.Close()

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedCrowdSecConfig(t, h, lapi.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/crowdsec/decisions", nil)
	rec := httptest.NewRecorder()
	h.listCrowdSecDecisions(rec, req)

	var resp lapiDecisionsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(resp.Decisions))
	}
	// Must be UTC-formatted via timestampFormat (RFC3339 with
	// millisecond precision, trailing zeros stripped).
	exp := resp.Decisions[0].ExpiresAt
	if !strings.HasSuffix(exp, "Z") {
		t.Errorf("ExpiresAt not normalised to UTC Z: %q", exp)
	}
	if !strings.Contains(exp, "2026-06-09T10:30:00.123") {
		t.Errorf("ExpiresAt lost precision: %q", exp)
	}
}

// --- helpers --------------------------------------------------

func buildBigDecisionList(n int) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, fmt.Sprintf(`{
            "id": %d,
            "duration": "1h",
            "origin": "CAPI",
            "scenario": "x",
            "scope": "ip",
            "type": "ban",
            "value": "10.0.%d.%d",
            "until": "2026-06-10T10:00:00Z"
        }`, i+1, i/256, i%256))
	}
	return "[" + strings.Join(parts, ",") + "]"
}
