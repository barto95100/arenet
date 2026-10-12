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
	"reflect"
	"strings"
	"testing"
)

// The inside of the blob.
//
// internal/storage/wire_coverage_test.go guards AlertRule's own fields
// and states its limit: source_params and eval_params are opaque JSON,
// replaced wholesale on every save, so field-name coverage there passes
// while the blob loses members.
//
// That is not hypothetical. WafEventRateParams carries four fields and
// the rule form builds three: `category` — the OWASP category filter —
// is neither read nor written by RuleModal.svelte, and the handler
// passes req.SourceParams through verbatim. So a rule built to alert on
// SQLi only, reopened and saved with nothing changed, comes back
// alerting on EVERY WAF category. It then fires on traffic it was
// written to ignore, which is worse than a lost field: the rule still
// exists and now means something else.
//
// `category` is live — it goes into the SQL filter in
// source_waf_event_rate.go and into the event labels — and it is a
// documented operator parameter in docs/wiki-seed/Alerting.md.
//
// The helper is duplicated from the storage file on purpose: a Go test
// helper cannot cross a package boundary without exporting it from
// non-test code, and exporting a test-only helper to avoid twenty
// duplicated lines is the worse trade.

const paramsUpdateHint = "\n\nA field was added to %s, which is a source_params shape — an opaque " +
	"blob that the rule handler replaces wholesale.\n" +
	"  1. web/frontend/src/routes/alerting/RuleModal.svelte must both READ it in the\n" +
	"     prefill effect and WRITE it in buildSourceParams, or every save of a rule\n" +
	"     using this source destroys it.\n" +
	"  2. web/frontend/src/lib/api/alerting.ts — the TypeScript shape.\n" +
	"  3. docs/wiki-seed/Alerting.md, if an operator is meant to set it.\n" +
	"Then add the tag below so this test passes again."

func paramsJSONTags(t *testing.T, v any) []string {
	t.Helper()
	rt := reflect.TypeOf(v)
	out := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		out = append(out, strings.Split(tag, ",")[0])
	}
	return out
}

func assertParamsFields(t *testing.T, label string, v any, want []string) {
	t.Helper()
	got := paramsJSONTags(t, v)
	wantSet := make(map[string]bool, len(want))
	for _, f := range want {
		wantSet[f] = true
	}
	for _, f := range got {
		if !wantSet[f] {
			t.Errorf("%s has an unexpected JSON field %q."+paramsUpdateHint, label, f, label)
		}
		delete(wantSet, f)
	}
	for f := range wantSet {
		t.Errorf("%s no longer carries the JSON field %q — if it was removed on purpose, "+
			"drop it from this list, from RuleModal.svelte and from the TypeScript shape.", label, f)
	}
}

func TestSourceParamsShapes_AreAllAccountedFor(t *testing.T) {
	// The one that was being destroyed. `category` is listed here as a
	// field the form MUST handle, not as one it may ignore.
	assertParamsFields(t, "WafEventRateParams", WafEventRateParams{}, []string{
		"routeId", "action", "windowSecs",
		"category",
	})

	assertParamsFields(t, "ThresholdParams", ThresholdParams{}, []string{"operator", "value"})
	assertParamsFields(t, "StateParams", StateParams{}, []string{"expected"})
	assertParamsFields(t, "CertExpiryParams", CertExpiryParams{}, []string{"host"})
	assertParamsFields(t, "CertRenewalFailedParams", CertRenewalFailedParams{}, []string{"domain", "windowSecs"})
	assertParamsFields(t, "CertManualExpiringParams", CertManualExpiringParams{}, []string{"thresholdDays"})
	assertParamsFields(t, "SystemHealthParams", SystemHealthParams{}, []string{"component"})
}
