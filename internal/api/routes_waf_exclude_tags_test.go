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
	"reflect"
	"strings"
	"testing"
)

// Step X Option (e) — normalizeExcludeTags unit tests.
//
// Sibling of normalizeExcludeRules ; pins the canonicalisation
// + validation contract independently of the route handler
// integration paths.

func TestNormalizeExcludeTags_EmptyInputReturnsEmpty(t *testing.T) {
	got, err := normalizeExcludeTags(nil)
	if err != nil {
		t.Fatalf("nil input should not error ; got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("nil input → expected empty result ; got %v", got)
	}
	got, err = normalizeExcludeTags([]string{})
	if err != nil {
		t.Fatalf("empty slice should not error ; got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty slice → expected empty result ; got %v", got)
	}
}

func TestNormalizeExcludeTags_HappyPathLowercasesDedupesSortes(t *testing.T) {
	// Operator pastes a messy list ; the canonicalisation pipeline
	// returns the deterministic form that the emit + the audit
	// diff rely on.
	in := []string{
		"Attack-SQLI",      // mixed case
		"  attack-protocol  ", // surrounding whitespace
		"attack-sqli",      // duplicate (lowercased of #0)
		"paranoia-level/3",
	}
	got, err := normalizeExcludeTags(in)
	if err != nil {
		t.Fatalf("happy path errored: %v", err)
	}
	want := []string{"attack-protocol", "attack-sqli", "paranoia-level/3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("canonical form mismatch ; got=%v want=%v", got, want)
	}
}

func TestNormalizeExcludeTags_RejectsCommaAndWhitespace(t *testing.T) {
	// Comma + whitespace inside a single tag would smuggle
	// additional ctl: actions into the SecAction directive
	// line ; the canonicalisation rejects them upfront.
	cases := []struct {
		name string
		tag  string
	}{
		{"comma", "attack-sqli,attack-rce"},
		{"space", "attack sqli"},
		{"tab", "attack\tsqli"},
		{"newline", "attack-sqli\nattack-rce"},
		{"double-quote", "attack-sqli\""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := normalizeExcludeTags([]string{c.tag})
			if err == nil {
				t.Errorf("expected error for %q ; got nil", c.tag)
			}
			if !strings.Contains(err.Error(), "invalid for SecAction directive") {
				t.Errorf("expected SecAction directive error ; got %v", err)
			}
		})
	}
}

func TestNormalizeExcludeTags_RejectsEmptyAfterTrim(t *testing.T) {
	cases := []string{"", "   ", "\t\n"}
	for _, c := range cases {
		_, err := normalizeExcludeTags([]string{c})
		if err == nil {
			t.Errorf("expected error for empty-after-trim %q ; got nil", c)
		}
	}
}

func TestNormalizeExcludeTags_RejectsOversizedTag(t *testing.T) {
	// Past the 128-char cap.
	bigTag := strings.Repeat("a", wafExcludeTagMaxLen+1)
	_, err := normalizeExcludeTags([]string{bigTag})
	if err == nil {
		t.Errorf("expected error for tag over %d chars", wafExcludeTagMaxLen)
	}
}

func TestNormalizeExcludeTags_RejectsTooManyTags(t *testing.T) {
	// Past the 64-entry cap.
	tags := make([]string, wafExcludeTagsMaxCount+1)
	for i := range tags {
		tags[i] = "tag-" + strings.Repeat("a", i%5)
	}
	_, err := normalizeExcludeTags(tags)
	if err == nil {
		t.Errorf("expected error for >%d tags", wafExcludeTagsMaxCount)
	}
	if !strings.Contains(err.Error(), "too many tags") {
		t.Errorf("expected 'too many tags' error ; got %v", err)
	}
}

func TestNormalizeExcludeTags_SlashPathPreserved(t *testing.T) {
	// CRS uses slash-namespaced tags ("paranoia-level/3",
	// "OWASP_CRS/...") ; the slash MUST survive canonicalisation
	// (it's a literal byte to the Coraza matcher, no path
	// semantics — but we still preserve it because operator
	// expects to type it as-is).
	got, err := normalizeExcludeTags([]string{"paranoia-level/3"})
	if err != nil {
		t.Fatalf("slash tag errored: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"paranoia-level/3"}) {
		t.Errorf("slash tag mangled ; got=%v", got)
	}
}
