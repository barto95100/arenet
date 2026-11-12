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

package alerting

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.80.x — the waf_event_rate alert carries a breakdown so the mail can
// name the offenders, not only count them. These guard the wire the
// operator actually sees: the source populates SourceValue.Context with
// top IPs / rules / paths, and a body template can render them.

func wafRow(ip, rule, path string) observability.WafEvent {
	return observability.WafEvent{
		SrcIP:       ip,
		RuleID:      rule,
		RequestPath: path,
		Action:      observability.WafActionBlock,
	}
}

func TestWafEventRateSource_AttachesBreakdownContext(t *testing.T) {
	reader := &stubWafReader{events: []observability.WafEvent{
		wafRow("1.1.1.1", "942100", "/a"),
		wafRow("1.1.1.1", "942100", "/a"),
		wafRow("1.1.1.1", "930110", "/a"),
		wafRow("2.2.2.2", "942100", "/b"),
	}}
	src := NewWafEventRateSource(reader)

	v, err := src.Read(context.Background(), json.RawMessage(`{"windowSecs":300}`))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v.Float == nil || *v.Float != 4 {
		t.Fatalf("count = %v, want 4", v.Float)
	}
	if v.Context == nil {
		t.Fatal("Context is nil — the breakdown was not attached")
	}

	checkTop := func(key string, want []observability.WafEventGroup) {
		t.Helper()
		raw, ok := v.Context[key]
		if !ok {
			t.Fatalf("Context[%q] missing", key)
		}
		got, ok := raw.([]observability.WafEventGroup)
		if !ok {
			t.Fatalf("Context[%q] is %T, want []observability.WafEventGroup", key, raw)
		}
		if len(got) != len(want) {
			t.Fatalf("Context[%q] = %v, want %v", key, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("Context[%q][%d] = %v, want %v", key, i, got[i], want[i])
			}
		}
	}

	checkTop("topIPs", []observability.WafEventGroup{{Key: "1.1.1.1", Count: 3}, {Key: "2.2.2.2", Count: 1}})
	checkTop("topRules", []observability.WafEventGroup{{Key: "942100", Count: 3}, {Key: "930110", Count: 1}})
	checkTop("topPaths", []observability.WafEventGroup{{Key: "/a", Count: 3}, {Key: "/b", Count: 1}})
}

func TestWafEventRateSource_NoBreakdownWhenEmpty(t *testing.T) {
	src := NewWafEventRateSource(&stubWafReader{events: nil})
	v, err := src.Read(context.Background(), json.RawMessage(`{"windowSecs":300}`))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v.Float == nil || *v.Float != 0 {
		t.Fatalf("count = %v, want 0", v.Float)
	}
	if v.Context != nil {
		t.Fatalf("Context = %v, want nil on an empty window", v.Context)
	}
}

// The operator-facing promise end to end: a body template that ranges
// over the breakdown renders the offenders. This is the whole point of
// the feature — if newAlertEventTemplateContext ever stops forwarding
// SourceValue.Context, this is what breaks.
func TestBreakdownRendersInBodyTemplate(t *testing.T) {
	v := FloatValue(4)
	v.Context = map[string]any{
		"topIPs": []observability.WafEventGroup{{Key: "1.1.1.1", Count: 3}, {Key: "2.2.2.2", Count: 1}},
	}
	rule := storage.AlertRule{Name: "waf-spike", Source: "waf_event_rate"}

	tmplText := "Total {{.Value}}\n{{range .Context.topIPs}}{{.Key}} ({{.Count}}x)\n{{end}}"
	tmpl, err := compileBodyTemplate(tmplText)
	if err != nil {
		t.Fatalf("compileBodyTemplate: %v", err)
	}
	out, err := renderTemplate(tmpl, newAlertEventTemplateContext(rule, v, time.Now()))
	if err != nil {
		t.Fatalf("renderTemplate: %v", err)
	}
	want := "Total 4\n1.1.1.1 (3x)\n2.2.2.2 (1x)\n"
	if out != want {
		t.Fatalf("rendered body =\n%q\nwant\n%q", out, want)
	}
}
