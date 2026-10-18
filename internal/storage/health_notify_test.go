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

package storage

import (
	"encoding/json"
	"strings"
	"testing"
)

func baseValidRoute() Route {
	return Route{
		ID:        "r1",
		Host:      "app.example.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
	}
}

func TestValidateHealthNotify(t *testing.T) {
	cases := []struct {
		name    string
		cfg     HealthNotifyConfig
		wantErr bool
	}{
		{"disabled is always valid", HealthNotifyConfig{Enabled: false}, false},
		{"disabled ignores a blank channel", HealthNotifyConfig{Enabled: false, ChannelID: ""}, false},
		{"enabled with channel + no reminder", HealthNotifyConfig{Enabled: true, ChannelID: "ch1"}, false},
		{"enabled with channel + reminder in range", HealthNotifyConfig{Enabled: true, ChannelID: "ch1", ReminderMinutes: 30}, false},
		{"enabled without a channel is rejected", HealthNotifyConfig{Enabled: true, ChannelID: "  "}, true},
		{"reminder below range", HealthNotifyConfig{Enabled: true, ChannelID: "ch1", ReminderMinutes: -1}, true},
		{"reminder above range", HealthNotifyConfig{Enabled: true, ChannelID: "ch1", ReminderMinutes: HealthNotifyReminderMax + 1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := baseValidRoute()
			r.HealthNotify = tc.cfg
			err := r.validate()
			if tc.wantErr && err == nil {
				t.Errorf("validate() = nil; want an error for %+v", tc.cfg)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validate() = %v; want nil for %+v", err, tc.cfg)
			}
		})
	}
}

// TestHealthNotify_CarriesNoSecret guards the spec's D2/D11 posture: the
// route's health-notify config references a channel by ID and must never
// carry a URL or any other secret. If someone later adds a URL field
// here, the route row would ship it in cleartext through the backup
// (which is NOT sealed for route fields) — this fails first and names
// that mistake.
func TestHealthNotify_CarriesNoSecret(t *testing.T) {
	r := baseValidRoute()
	r.HealthNotify = HealthNotifyConfig{Enabled: true, ChannelID: "ch-abc123", ReminderMinutes: 15}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, `"channel_id":"ch-abc123"`) {
		t.Errorf("health_notify did not round-trip the channel ID: %s", s)
	}
	// A channel ID is an opaque token, never a URL. Any scheme marker in
	// the health_notify block means a secret-bearing field crept in.
	var decoded map[string]json.RawMessage
	_ = json.Unmarshal(raw, &decoded)
	hn := string(decoded["health_notify"])
	for _, marker := range []string{"://", "http", "webhook", "token", "secret", "url"} {
		if strings.Contains(strings.ToLower(hn), marker) {
			t.Errorf("health_notify block contains %q — it must hold a channel ID only, no secret: %s", marker, hn)
		}
	}
}

// TestHealthNotify_AbsentFieldDecodesOff pins the "no migration" claim:
// a pre-v2.75 row (JSON without health_notify) decodes to the zero value,
// which is off.
func TestHealthNotify_AbsentFieldDecodesOff(t *testing.T) {
	const legacy = `{"id":"r1","host":"app.example.com","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}]}`
	var r Route
	if err := json.Unmarshal([]byte(legacy), &r); err != nil {
		t.Fatalf("unmarshal legacy row: %v", err)
	}
	if r.HealthNotify.Enabled {
		t.Error("a row without health_notify must decode to Enabled=false")
	}
}
