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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/observability"
)

// AL.4.a — GET /api/v1/observability/alert-events handler
// pinning tests. Covers wire shape, filter parsing,
// pagination cursor pass-through, and the degraded-mode
// contract.

// fakeAlertEventReader is the AlertEventReader test
// double. Captures the filter the handler built so tests
// can assert query-string parsing without booting SQLite.
type fakeAlertEventReader struct {
	events     []observability.AlertEvent
	nextCursor string
	wantErr    error
	gotFilter  observability.AlertEventFilter
}

func (f *fakeAlertEventReader) QueryAlertEvents(_ context.Context, filter observability.AlertEventFilter) ([]observability.AlertEvent, string, error) {
	f.gotFilter = filter
	if f.wantErr != nil {
		return nil, "", f.wantErr
	}
	return f.events, f.nextCursor, nil
}

func TestAlertEvents_DegradedWhenReaderNil(t *testing.T) {
	env := newTestEnv(t, false)
	// Intentionally NOT calling SetAlertEventReader.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/alert-events", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d want 200 even when reader nil (degraded contract)", rec.Code)
	}
	var resp alertEventsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Degraded {
		t.Errorf("degraded=false; want true on nil reader")
	}
	if len(resp.Events) != 0 {
		t.Errorf("events non-empty on degraded path; want []")
	}
}

func TestAlertEvents_HappyPath_WireShape(t *testing.T) {
	env := newTestEnv(t, false)
	ts := time.Date(2026, 6, 16, 10, 30, 0, 0, time.UTC)
	reader := &fakeAlertEventReader{
		events: []observability.AlertEvent{{
			ID: 1, EventID: "evt-1", Ts: ts, RuleID: "rule-1", RuleName: "block-rate-high",
			Severity: 2, Category: "waf", Subject: "WAF block elevated",
			Body:              "5 blocks in 60s",
			LabelsJSON:        `{"route_id":"r1"}`,
			ChannelsFiredJSON: `["ch-1","ch-2"]`,
			ChannelsFailedJSON: `{"ch-3":"smtp timeout"}`,
		}},
		nextCursor: "next-cursor-xyz",
	}
	env.handler.SetAlertEventReader(reader)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/alert-events", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp alertEventsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("events len=%d want 1", len(resp.Events))
	}
	got := resp.Events[0]
	if got.EventID != "evt-1" {
		t.Errorf("EventID=%q", got.EventID)
	}
	if got.RuleName != "block-rate-high" {
		t.Errorf("RuleName=%q", got.RuleName)
	}
	if got.Severity != 2 {
		t.Errorf("Severity=%d", got.Severity)
	}
	if got.Labels["route_id"] != "r1" {
		t.Errorf("Labels.route_id=%q want r1", got.Labels["route_id"])
	}
	if len(got.ChannelsFired) != 2 || got.ChannelsFired[0] != "ch-1" {
		t.Errorf("ChannelsFired=%v", got.ChannelsFired)
	}
	if got.ChannelsFailed["ch-3"] != "smtp timeout" {
		t.Errorf("ChannelsFailed[ch-3]=%q", got.ChannelsFailed["ch-3"])
	}
	if resp.NextCursor != "next-cursor-xyz" {
		t.Errorf("NextCursor=%q want pass-through 'next-cursor-xyz'", resp.NextCursor)
	}
}

func TestAlertEvents_ParseSeverityFilter(t *testing.T) {
	env := newTestEnv(t, false)
	reader := &fakeAlertEventReader{}
	env.handler.SetAlertEventReader(reader)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/alert-events?severity=3", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if reader.gotFilter.Severity == nil || *reader.gotFilter.Severity != 3 {
		t.Errorf("Severity filter=%v; want pointer to 3", reader.gotFilter.Severity)
	}
}

func TestAlertEvents_RejectBadSeverity(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetAlertEventReader(&fakeAlertEventReader{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/alert-events?severity=99", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400 on severity=99", rec.Code)
	}
}

func TestAlertEvents_ParseRuleIDAndCategoryFilters(t *testing.T) {
	env := newTestEnv(t, false)
	reader := &fakeAlertEventReader{}
	env.handler.SetAlertEventReader(reader)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/alert-events?rule_id=rule-xyz&category=waf", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if reader.gotFilter.RuleID != "rule-xyz" {
		t.Errorf("RuleID=%q want rule-xyz", reader.gotFilter.RuleID)
	}
	if reader.gotFilter.Category != "waf" {
		t.Errorf("Category=%q want waf", reader.gotFilter.Category)
	}
}

func TestAlertEvents_DateRange_RejectsReversedBounds(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetAlertEventReader(&fakeAlertEventReader{})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/alert-events?since=2026-06-16T12:00:00Z&until=2026-06-16T10:00:00Z", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400 on reversed bounds", rec.Code)
	}
}

func TestAlertEvents_LimitClampedToCap(t *testing.T) {
	env := newTestEnv(t, false)
	reader := &fakeAlertEventReader{}
	env.handler.SetAlertEventReader(reader)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/alert-events?limit=5000", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if reader.gotFilter.Limit != alertEventsLimitCap {
		t.Errorf("Limit=%d want clamped to cap %d", reader.gotFilter.Limit, alertEventsLimitCap)
	}
}

func TestAlertEvents_InvalidCursor_400(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetAlertEventReader(&fakeAlertEventReader{
		wantErr: errors.New("observability: invalid cursor: base64 decode: illegal base64"),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/alert-events?cursor=garbage", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400 on invalid cursor surfaced from store", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid cursor") {
		t.Errorf("body=%s want 'invalid cursor'", rec.Body)
	}
}

func TestAlertEvents_StoreError_503(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetAlertEventReader(&fakeAlertEventReader{
		wantErr: errors.New("observability: query alert_event: database is locked"),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/alert-events", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d want 503 on store error", rec.Code)
	}
}
