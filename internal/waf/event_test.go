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

package waf

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncate_BelowCap_Unchanged(t *testing.T) {
	in := "GET /api/v1/routes"
	if got := Truncate(in, 512); got != in {
		t.Fatalf("short input mutated: %q → %q", in, got)
	}
}

func TestTruncate_AtCap_Unchanged(t *testing.T) {
	in := strings.Repeat("a", 256)
	if got := Truncate(in, 256); got != in {
		t.Fatalf("input at exact cap mutated: len=%d → len=%d", len(in), len(got))
	}
}

func TestTruncate_OverCap_AppendsEllipsis(t *testing.T) {
	in := strings.Repeat("a", 300)
	got := Truncate(in, 256)
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("truncated output missing ellipsis: %q", got[len(got)-10:])
	}
	// Trimmed prefix should match input prefix.
	if got[:256] != in[:256] {
		t.Fatalf("truncated prefix diverges from input prefix")
	}
}

func TestTruncate_UTF8Safe_BacksUpToRuneBoundary(t *testing.T) {
	// "é" is 2 bytes (0xC3 0xA9). Place one at the cap so a
	// naive byte cut would split the rune; Truncate must
	// back up to the previous boundary.
	in := strings.Repeat("a", 255) + "é" + strings.Repeat("b", 50)
	// Total bytes: 255 + 2 + 50 = 307. Cap at 256 would land
	// mid-rune; Truncate must cut at byte 255 (before the é).
	got := Truncate(in, 256)
	body := strings.TrimSuffix(got, "…")
	if !utf8.ValidString(body) {
		t.Fatalf("truncated output is not valid UTF-8: %q", body)
	}
	if len(body) > 256 {
		t.Fatalf("truncated body exceeds cap: len=%d", len(body))
	}
}

func TestTruncate_ZeroOrNegativeCap_Passthrough(t *testing.T) {
	in := "anything"
	for _, cap := range []int{0, -1, -100} {
		if got := Truncate(in, cap); got != in {
			t.Fatalf("cap=%d should be a no-op; got %q", cap, got)
		}
	}
}

func TestAllCategories_NoDuplicates(t *testing.T) {
	seen := map[OwaspCategory]struct{}{}
	for _, c := range AllCategories {
		if _, dup := seen[c]; dup {
			t.Fatalf("duplicate category %q in AllCategories", c)
		}
		seen[c] = struct{}{}
	}
}

func TestAllCategories_DashboardDisplayOrder(t *testing.T) {
	// Anti-regression on the dashboard's expected order
	// (SQLi → XSS → RCE → LFI → PROTOCOL → OTHER). A
	// reorder would visually shuffle the distribution
	// strip; pin it.
	want := []OwaspCategory{
		CategorySQLi,
		CategoryXSS,
		CategoryRCE,
		CategoryLFI,
		CategoryProtocol,
		CategoryOther,
	}
	if len(AllCategories) != len(want) {
		t.Fatalf("len(AllCategories)=%d, want %d", len(AllCategories), len(want))
	}
	for i, c := range want {
		if AllCategories[i] != c {
			t.Fatalf("AllCategories[%d] = %q, want %q", i, AllCategories[i], c)
		}
	}
}
