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

package alerting

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Step AL.1.a foundation unit tests. Pin the Severity
// enum's int↔string round-trip and the AlertEvent JSON
// envelope so a future migration to a richer payload
// surface lands cleanly. No senders / no CRUD here —
// AL.1.b onward.

func TestSeverity_StringRoundTrip(t *testing.T) {
	cases := []struct {
		sev      Severity
		wantWire string
	}{
		{SeverityInfo, "info"},
		{SeverityWarning, "warning"},
		{SeverityCritical, "critical"},
		{SeverityEmergency, "emergency"},
	}
	for _, tc := range cases {
		t.Run(tc.wantWire, func(t *testing.T) {
			if got := tc.sev.String(); got != tc.wantWire {
				t.Errorf("String() = %q; want %q", got, tc.wantWire)
			}
			parsed, err := ParseSeverity(tc.wantWire)
			if err != nil {
				t.Fatalf("ParseSeverity(%q): %v", tc.wantWire, err)
			}
			if parsed != tc.sev {
				t.Errorf("ParseSeverity(%q) = %d; want %d", tc.wantWire, parsed, tc.sev)
			}
		})
	}
}

func TestParseSeverity_UnknownRejected(t *testing.T) {
	_, err := ParseSeverity("panic")
	if err == nil {
		t.Fatal("ParseSeverity(\"panic\") returned nil error; want unknown-severity rejection")
	}
	if !strings.Contains(err.Error(), "unknown severity") {
		t.Errorf("error %q should mention 'unknown severity'", err.Error())
	}
}

func TestSeverity_JSONRoundTrip(t *testing.T) {
	for _, sev := range []Severity{SeverityInfo, SeverityWarning, SeverityCritical, SeverityEmergency} {
		raw, err := json.Marshal(sev)
		if err != nil {
			t.Fatalf("Marshal(%d): %v", sev, err)
		}
		var got Severity
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("Unmarshal(%s): %v", raw, err)
		}
		if got != sev {
			t.Errorf("round-trip mismatch: in=%d, out=%d, raw=%s", sev, got, raw)
		}
	}
}

func TestSeverity_JSONUnmarshal_RejectsNonString(t *testing.T) {
	// Hand-edited webhook configs sometimes pass severity as
	// an int (mimicking the storage shape). The wire shape
	// is strict-string by design — a typo / mismatch
	// surfaces as a clean unmarshal error rather than a
	// silent miscategorisation.
	var s Severity
	err := json.Unmarshal([]byte(`2`), &s)
	if err == nil {
		t.Fatal("Unmarshal of bare int should fail; want strict-string rejection")
	}
}

func TestSeverity_JSONUnmarshal_RejectsUnknown(t *testing.T) {
	var s Severity
	err := json.Unmarshal([]byte(`"chaos"`), &s)
	if err == nil {
		t.Fatal("Unmarshal of unknown token should fail")
	}
}

func TestAlertEvent_JSONShape(t *testing.T) {
	// Pin the on-wire envelope shape against accidental
	// field renames — downstream consumers
	// (alertmanager-compatible processors, custom
	// webhook receivers) parse by snake_case key.
	evt := AlertEvent{
		ID:        "11111111-1111-1111-1111-111111111111",
		Timestamp: time.Date(2026, 6, 15, 14, 30, 0, 0, time.UTC),
		RuleID:    "rule-abc",
		RuleName:  "WAF spike",
		Severity:  SeverityCritical,
		Category:  "waf",
		Subject:   "WAF blocked 50 requests in 5min on registry.example.com",
		Body:      "Rule threshold crossed for the 3rd time today.",
		Context:   map[string]any{"route_id": "r-1", "count": 50},
		Labels:    map[string]string{"env": "prod"},
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(raw)
	for _, want := range []string{
		`"id":"11111111-1111-1111-1111-111111111111"`,
		`"timestamp":"2026-06-15T14:30:00Z"`,
		`"rule_id":"rule-abc"`,
		`"rule_name":"WAF spike"`,
		`"severity":"critical"`,
		`"category":"waf"`,
		`"subject":"WAF blocked`,
		`"body":"Rule threshold crossed`,
		`"context":`,
		`"labels":`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("wire shape missing %q\nfull: %s", want, s)
		}
	}
}

func TestAlertEvent_OmitemptyFieldsHidden(t *testing.T) {
	// A minimal event with only required fields populated
	// should not emit empty body/context/labels — the
	// frontend's activity-log renderer can safely skip
	// absent fields without nil checks.
	evt := AlertEvent{
		ID:        "x",
		Timestamp: time.Unix(0, 0).UTC(),
		RuleID:    "r",
		RuleName:  "n",
		Severity:  SeverityInfo,
		Category:  "system",
		Subject:   "boot ok",
	}
	raw, _ := json.Marshal(evt)
	for _, banned := range []string{`"body":`, `"context":`, `"labels":`} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("expected %q to be omitted on a minimal event; raw=%s",
				banned, raw)
		}
	}
}
