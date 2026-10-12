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

// A tripwire, not a schema test.
//
// Editing a TCP service through the UI destroyed five stored fields on
// every save, for as long as the feature had existed: PUT /tcp-services
// is a full replace (api/tcpservices.go decodes into a fresh
// TCPService, UpdateTCPService carries over only CreatedAt), and the
// edit form built its payload by hand from the thirteen controls it
// has. Anything not listed was dropped, behind a success toast.
//
// v2.71 inverted that: the form now starts from the service it loaded
// and overrides only the fields it owns, so an unknown field
// round-trips. That fixes every field present today, and it keeps
// working for a field added later — PROVIDED the field also reaches the
// TypeScript type, since the overlay copies whatever the JSON carries.
//
// This test is the half the frontend cannot check. A new field here
// fails it, and the failure says what else to update. The frontend side
// is covered by "a save keeps what the form cannot show" in
// web/frontend/src/routes/tcp-services/page.test.ts.
//
// The file's own comment already warned about this class once — "that is
// how the v2.46 path redirect was lost". It then happened again. Hence a
// test rather than a comment.

const tcpWireUpdateHint = "\n\nA field was added to %s. Three things to check, in this order:\n" +
	"  1. web/frontend/src/lib/api/tcp-services.ts — add it to the interface, or the\n" +
	"     form's overlay cannot carry it and every save will drop it.\n" +
	"  2. web/frontend/src/routes/tcp-services/+page.svelte — only if the form should\n" +
	"     let the operator EDIT it; the overlay already preserves it either way.\n" +
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
			t.Errorf("%s has an unexpected JSON field %q."+tcpWireUpdateHint, label, f, label)
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
		// Partly owned: the form edits upstreams[0].host/port and
		// healthCheck.enabled and the allow branch of ipFilter. The rest
		// of each survives only because of the overlay.
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
