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

package waf

import (
	"runtime"
	"strings"
	"testing"
)

// A multi-megabyte matched value must never reach Redact at full length:
// Redact's four regex passes each allocate ~2x their input, so scrubbing
// a raw 5 MiB value before truncating allocated tens of MiB on the
// request goroutine (F5). RedactSnippet pre-truncates first, so the
// allocation stays bounded no matter how big the input is.
func TestRedactSnippet_BoundsAllocationOnHugeInput(t *testing.T) {
	big := strings.Repeat("A", 5<<20) // 5 MiB

	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)
	out := RedactSnippet(big, MaxPayloadSampleBytes)
	runtime.ReadMemStats(&m2)

	// Truncate adds a short marker past the cap, so allow a little slack;
	// the point is that 5 MiB collapsed to a bounded sample, not 5 MiB.
	if len(out) > 2*MaxPayloadSampleBytes {
		t.Fatalf("RedactSnippet returned %d bytes for a 5 MiB input, want bounded (<= %d)", len(out), 2*MaxPayloadSampleBytes)
	}
	// With the pre-truncate, Redact scans at most 2*cap bytes, so the
	// call allocates on the order of KiB. Without it, Redact copies the
	// whole 5 MiB several times (tens of MiB). 1 MiB cleanly separates.
	if alloc := m2.TotalAlloc - m1.TotalAlloc; alloc > 1<<20 {
		t.Errorf("RedactSnippet allocated %d bytes for a %d-byte input — Redact saw the full value (F5)", alloc, len(big))
	}
}

// A secret inside the window is still redacted; the final cap holds.
func TestRedactSnippet_RedactsWithinWindow(t *testing.T) {
	in := "Authorization: Bearer SECRET-TOKEN-VALUE and more"
	out := RedactSnippet(in, 256)
	if strings.Contains(out, "SECRET-TOKEN-VALUE") {
		t.Errorf("a bearer token within the window must be redacted: %q", out)
	}
}

// A matched value that IS a credential (a bare cookie, auth header or
// password arg, which Redact's prefix-anchored patterns miss) is masked
// wholesale, so the raw secret never lands in the viewer-readable event
// store (F5). A non-credential match is redacted normally.
func TestPayloadSampleFor_MasksCredentialVariables(t *testing.T) {
	creds := []struct{ matchedVar, value string }{
		{"REQUEST_COOKIES:session", "s%3Aabcdef.rawSessionCookieValue"},
		{"REQUEST_HEADERS:Authorization", "Bearer rawtokenvalue"},
		{"ARGS:password", "hunter2-in-the-clear"},
		{"ARGS_POST:api_key", "AKIA-secret-key"},
	}
	for _, c := range creds {
		got := payloadSampleFor(c.value, c.matchedVar, MaxPayloadSampleBytes)
		if got != credentialMask {
			t.Errorf("%s: sample = %q, want the credential mask (raw value would leak)", c.matchedVar, got)
		}
	}

	// A non-credential match (an SQLi probe in a search arg) is redacted,
	// not masked — the operator still sees what tripped the rule.
	got := payloadSampleFor("1' OR '1'='1", "ARGS:q", MaxPayloadSampleBytes)
	if got == credentialMask {
		t.Error("a non-credential match must keep its (redacted) sample, not be masked away")
	}
	if !strings.Contains(got, "OR") {
		t.Errorf("the non-credential sample should still show the probe: %q", got)
	}
}
