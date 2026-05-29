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

package crowdsec

import (
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func strPtr(s string) *string { return &s }

func TestTranslateResponse_HappyPath(t *testing.T) {
	resp := &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{
				UUID:     "u-1",
				Scope:    strPtr("ip"),
				Value:    strPtr("1.2.3.4"),
				Type:     strPtr("ban"),
				Scenario: strPtr("crowdsecurity/http-probing"),
				Duration: strPtr("1h"),
				Until:    "2026-05-29T15:00:00Z",
			},
			{
				UUID:     "u-2",
				Scope:    strPtr("range"),
				Value:    strPtr("185.142.86.0/24"),
				Type:     strPtr("ban"),
				Scenario: strPtr("crowdsecurity/community-blocklist"),
				Duration: strPtr("24h"),
			},
		},
		Deleted: models.GetDecisionsResponse{
			{UUID: "u-old-1", Scope: strPtr("ip"), Value: strPtr("9.9.9.9"), Type: strPtr("ban")},
			{UUID: "u-old-2", Scope: strPtr("ip"), Value: strPtr("8.8.8.8"), Type: strPtr("ban")},
		},
	}
	delta := translateResponse(resp)
	if len(delta.New) != 2 {
		t.Fatalf("New len = %d, want 2", len(delta.New))
	}
	if delta.New[0].UUID != "u-1" || delta.New[0].Scope != "ip" || delta.New[0].Value != "1.2.3.4" {
		t.Errorf("New[0] mismatch: %+v", delta.New[0])
	}
	// Duration "1h" → 3600s.
	if delta.New[0].DurationSeconds != 3600 {
		t.Errorf("New[0].DurationSeconds = %d, want 3600", delta.New[0].DurationSeconds)
	}
	// Until takes precedence over Duration for ExpiresAt.
	want, _ := time.Parse(time.RFC3339, "2026-05-29T15:00:00Z")
	if !delta.New[0].ExpiresAt.Equal(want) {
		t.Errorf("New[0].ExpiresAt = %v, want %v (Until field overrides Duration)", delta.New[0].ExpiresAt, want)
	}
	if delta.New[1].Scope != "range" || delta.New[1].Value != "185.142.86.0/24" {
		t.Errorf("New[1] (range) mismatch: %+v", delta.New[1])
	}
	if len(delta.Deleted) != 2 {
		t.Errorf("Deleted len = %d, want 2", len(delta.Deleted))
	}
	if delta.Deleted[0] != "u-old-1" || delta.Deleted[1] != "u-old-2" {
		t.Errorf("Deleted = %v, want [u-old-1, u-old-2]", delta.Deleted)
	}
}

func TestTranslateResponse_NilResponse(t *testing.T) {
	delta := translateResponse(nil)
	if len(delta.New) != 0 || len(delta.Deleted) != 0 {
		t.Errorf("nil response should yield empty delta, got %+v", delta)
	}
}

func TestTranslateResponse_DropsMalformedDecisions(t *testing.T) {
	// Defensive translation: nil decisions in the slice, or
	// decisions with empty UUID / nil Scope / nil Value / nil
	// Type are silently dropped (LAPI would not normally emit
	// these, but the upstream model uses pointer fields with
	// omitempty so the path exists).
	resp := &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			nil,
			{UUID: "", Scope: strPtr("ip"), Value: strPtr("1.1.1.1"), Type: strPtr("ban")},       // empty UUID
			{UUID: "u-x", Scope: nil, Value: strPtr("1.1.1.1"), Type: strPtr("ban")},             // nil Scope
			{UUID: "u-y", Scope: strPtr("ip"), Value: nil, Type: strPtr("ban")},                  // nil Value
			{UUID: "u-z", Scope: strPtr("ip"), Value: strPtr("1.1.1.1"), Type: nil},              // nil Type
			{UUID: "u-good", Scope: strPtr("ip"), Value: strPtr("1.1.1.1"), Type: strPtr("ban")}, // good
		},
		Deleted: models.GetDecisionsResponse{
			nil,
			{UUID: ""},           // empty UUID
			{UUID: "u-old-good"}, // good
		},
	}
	delta := translateResponse(resp)
	if len(delta.New) != 1 || delta.New[0].UUID != "u-good" {
		t.Errorf("expected only 'u-good' in New, got %+v", delta.New)
	}
	if len(delta.Deleted) != 1 || delta.Deleted[0] != "u-old-good" {
		t.Errorf("expected only 'u-old-good' in Deleted, got %+v", delta.Deleted)
	}
}

func TestTranslateResponse_BadDurationStringFallsBackToZero(t *testing.T) {
	resp := &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{
				UUID:     "u-bad-dur",
				Scope:    strPtr("ip"),
				Value:    strPtr("1.1.1.1"),
				Type:     strPtr("ban"),
				Duration: strPtr("not-a-duration"),
			},
		},
	}
	delta := translateResponse(resp)
	if len(delta.New) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(delta.New))
	}
	if delta.New[0].DurationSeconds != 0 {
		t.Errorf("DurationSeconds = %d, want 0 (bad parse falls back)", delta.New[0].DurationSeconds)
	}
}

func TestNewLiveSource_RequiresAPIKey(t *testing.T) {
	_, err := NewLiveSource(LiveSourceConfig{APIURL: "http://127.0.0.1:8080/"}, silentLogger())
	if err == nil {
		t.Fatal("NewLiveSource with empty APIKey should error")
	}
}

func TestNewLiveSource_DefaultsURL(t *testing.T) {
	// Empty URL → bouncer's documented default. Not asserting
	// live LAPI behaviour, just that NewLiveSource returns
	// successfully with the canonical default.
	src, err := NewLiveSource(LiveSourceConfig{APIKey: "k", TickerInterval: time.Hour}, silentLogger())
	if err != nil {
		t.Fatalf("NewLiveSource: %v", err)
	}
	if src.bouncer.APIUrl != "http://127.0.0.1:8080/" {
		t.Errorf("default URL = %q, want http://127.0.0.1:8080/", src.bouncer.APIUrl)
	}
}
