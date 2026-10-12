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
	"reflect"
	"strings"
	"testing"
)

// Tripwires, not schema tests.
//
// An audit of the five operator forms on 2026-10-12 found the same
// defect in four of them: a form builds its write payload BY HAND, the
// handler replaces the whole record, and every field the form forgot is
// destroyed on save behind a success toast.
//
//	tcp-services  six fields, one of them inverting a deny IP filter
//	              into an allow list
//	routes        `disabled: false` shipped unconditionally, clearing a
//	              maintenance state the form had not set
//	alerting      sourceParams.category, which silently widens a WAF
//	              rule from one OWASP category to all of them
//	settings      UpdateCheckConfig.IntervalOverride, erased by a
//	              checkbox; MaxMindConfig.EditionID, erased by rotating
//	              the licence key, after which the updater downloads a
//	              different database
//
// Four occurrences is a pattern, not four bugs. Each one was fixed by
// making the payload carry what the form OWNS and leave the rest alone —
// but that only holds for the fields present today. A field added later
// reaches the TypeScript type or it does not, and if it does not, every
// save drops it in silence again. Nothing in the frontend can see that.
//
// This file is the half the frontend cannot check. A new field fails
// its struct's entry and the failure says where to go.
//
// LIMIT, stated because it matters: these assert field NAMES. A struct
// whose payload is a JSON blob — AlertRule.SourceParams — passes this
// check while losing everything inside the blob, which is exactly how
// `category` went missing. The blob's own shapes are covered by the
// sibling file internal/alerting/wire_coverage_test.go.

const wireUpdateHint = "\n\nA field was added to %s. Three things to check, in this order:\n" +
	"  1. the TypeScript interface for this type under web/frontend/src/lib/api/ —\n" +
	"     the form's payload carries what the JSON carries, so a field missing\n" +
	"     there is dropped on every save.\n" +
	"  2. the form that writes this record, only if the operator should be able to\n" +
	"     EDIT the field; an overlay preserves it either way.\n" +
	"  3. internal/storage/backup_apply.go — a new field must survive export/import.\n" +
	"Then add the tag below so this test passes again."

func jsonTagNames(t *testing.T, v any) []string {
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

func assertWireFields(t *testing.T, label string, v any, want []string) {
	t.Helper()
	got := jsonTagNames(t, v)
	wantSet := make(map[string]bool, len(want))
	for _, f := range want {
		wantSet[f] = true
	}
	for _, f := range got {
		if !wantSet[f] {
			t.Errorf("%s has an unexpected JSON field %q."+wireUpdateHint, label, f, label)
		}
		delete(wantSet, f)
	}
	for f := range wantSet {
		t.Errorf("%s no longer carries the JSON field %q — if it was removed on purpose, "+
			"drop it from this list and from the TypeScript interface.", label, f)
	}
}

func TestTCPServiceWireFields_AreAllAccountedFor(t *testing.T) {
	assertWireFields(t, "TCPService", TCPService{}, []string{
		// Server-managed: the request type omits these.
		"id", "createdAt", "updatedAt",
		// Owned by the edit form.
		"name", "listenAddr", "listenPort", "protocol", "acceptProtocol",
		"proxyProtocol", "crowdSecEnabled", "disabled",
		// Partly owned: the form edits upstreams[0].host/port,
		// healthCheck.enabled and the allow branch of ipFilter. The rest
		// of each survives only because the payload overlays the loaded
		// service.
		"upstreams", "healthCheck", "ipFilter",
		// Not owned by the form at all — preserved, never edited.
		"lbPolicy",
	})

	assertWireFields(t, "TCPUpstream", TCPUpstream{}, []string{
		"host", "port",
		// Not owned by the form.
		"maxConnections",
	})

	assertWireFields(t, "TCPHealthCheck", TCPHealthCheck{}, []string{
		// Owned by the checkbox.
		"enabled",
		// Not owned: preserved across a toggle so turning the check back
		// on does not silently reset the tuning.
		"interval", "timeout",
	})

	assertWireFields(t, "IPFilter", IPFilter{}, []string{
		// The form expresses only "allow these ranges" or "no filter".
		"mode", "cidrs",
		// Not owned: a custom reject status was being dropped on save.
		"statusCode",
	})
}

// UpdateCheckConfig is the sharpest case of the four. The settings
// section sends ONE of the two fields (UpdatesSection.svelte sends
// `{enabled}`), the handler builds a fresh struct with no read-first
// (internal/api/version.go), and there is no GET that reports the
// interval back — internal/api/openapi/backup-system.yaml says so
// outright. So the field cannot be shown, cannot be re-entered, and is
// erased by a checkbox. A new field here would land in exactly the same
// hole.
func TestUpdateCheckConfigWireFields_AreAllAccountedFor(t *testing.T) {
	assertWireFields(t, "UpdateCheckConfig", UpdateCheckConfig{}, []string{
		"enabled",
		// Not owned by any UI. Settable through the admin API and
		// restored from a backup.
		"intervalOverride",
	})
}

// MaxMindConfig: the GeoIP section sends accountId + licenseKey and the
// handler re-derives LicenseKey and CreatedAt from the previous record —
// but not EditionID, so rotating the licence key reverts the edition to
// GeoLite2-City and the updater then fetches a different database.
func TestMaxMindConfigWireFields_AreAllAccountedFor(t *testing.T) {
	assertWireFields(t, "MaxMindConfig", MaxMindConfig{}, []string{
		"account_id", "license_key",
		// Not owned by the form.
		"edition_id",
		// Server-managed.
		"created_at", "updated_at",
	})
}

// AlertRule's payload is mostly honest — the handler sets 13 fields and
// storage merges the 7 watcher/telemetry ones. The hazard is one field:
// source_params is an opaque blob, replaced wholesale, so this test
// passes while the blob loses members. See internal/alerting/
// wire_coverage_test.go for the shapes inside it.
func TestAlertRuleWireFields_AreAllAccountedFor(t *testing.T) {
	assertWireFields(t, "AlertRule", AlertRule{}, []string{
		"id", "created_at", "updated_at",
		"name", "enabled", "kind", "severity", "category", "source",
		"channels", "cooldown_secs", "subject_template", "body_template",
		// Opaque blobs. Field-name coverage cannot see inside them.
		"source_params", "eval_params",
		// Watcher telemetry, merged by UpdateAlertRule rather than sent.
		"last_fired_at", "last_eval_at", "last_error", "last_error_at",
		"last_matched",
	})
}
