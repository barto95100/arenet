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

import "testing"

// Phase Y (2026-06-18) — empirically-verified per-file CRS
// category mapping.
//
// Source of truth : the coraza-coreruleset embedded FS, file
// inventory captured by the Phase Y audit. Each REQUEST-NNN-
// NAME.conf / RESPONSE-NNN-NAME.conf file maps 1:1 to one
// Arenet OwaspCategory ; the test cases below pin a
// representative sample per file (first / mid / last id, with
// the first id taken from the empirical "first id observed"
// for that file).
//
// Adding a new range to category.go MUST add a row here AND
// confirm the upstream CRS conf file has shipped (otherwise
// the range is dead).

func TestCategoryForRule_PerCRSFile(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want OwaspCategory
	}{
		// --- Request attacks ---
		{"942 sqli first", "942011", CategorySQLi},
		{"942 sqli mid", "942300", CategorySQLi},
		{"942 sqli last", "942560", CategorySQLi},

		{"941 xss first", "941010", CategoryXSS},
		{"941 xss mid", "941200", CategoryXSS},
		{"941 xss last", "941400", CategoryXSS},

		{"932 rce shell", "932011", CategoryRCE},
		{"932 rce mid", "932200", CategoryRCE},

		{"933 php first", "933011", CategoryPHP},
		{"933 php mid", "933150", CategoryPHP},

		{"934 generic first", "934011", CategoryGeneric},
		{"934 generic mid", "934100", CategoryGeneric},

		{"930 lfi first", "930011", CategoryLFI},
		{"930 lfi mid", "930100", CategoryLFI},

		{"931 rfi first", "931011", CategoryRFI},
		{"931 rfi mid", "931100", CategoryRFI},

		{"944 java first", "944011", CategoryJava},
		{"944 java mid", "944150", CategoryJava},
		{"944 java log4shell range", "944210", CategoryJava},

		{"943 session first", "943011", CategorySession},
		{"943 session mid", "943100", CategorySession},

		// --- Protocol / behaviour ---
		{"911 method first", "911011", CategoryMethod},
		{"911 method last", "911100", CategoryMethod},

		{"920 protocol first", "920011", CategoryProtocol},
		{"920 protocol mid", "920300", CategoryProtocol},
		{"920 protocol last", "920620", CategoryProtocol},

		{"921 proto attack first", "921011", CategoryProtocolAttack},
		{"921 proto attack mid", "921200", CategoryProtocolAttack},

		{"922 multipart first", "922100", CategoryMultipart},
		{"922 multipart last", "922120", CategoryMultipart},

		{"913 scanner first", "913011", CategoryScanner},
		{"913 scanner mid", "913050", CategoryScanner},

		// --- Aggregators ---
		{"949 anomaly req first", "949011", CategoryAnomalyReq},
		{"949 anomaly req mid", "949100", CategoryAnomalyReq},

		{"959 anomaly resp first", "959011", CategoryAnomalyResp},
		{"959 anomaly resp mid", "959100", CategoryAnomalyResp},

		{"980 correlation first", "980011", CategoryCorrelation},
		{"980 correlation mid", "980100", CategoryCorrelation},

		// --- Response-side / data leak ---
		{"950 data leak first", "950011", CategoryDataLeak},
		{"950 data leak mid", "950100", CategoryDataLeak},

		{"951 data leak sql first", "951011", CategoryDataLeakSQL},
		{"951 data leak sql mid", "951100", CategoryDataLeakSQL},

		{"952 data leak java first", "952011", CategoryDataLeakJava},

		{"953 data leak php first", "953011", CategoryDataLeakPHP},

		{"954 data leak iis first", "954011", CategoryDataLeakIIS},

		{"955 webshell first", "955011", CategoryWebShell},
		{"955 webshell mid", "955200", CategoryWebShell},

		// --- Infrastructure ---
		{"901 init first", "901001", CategoryInit},
		{"901 init mid", "901250", CategoryInit},

		{"905 common except first", "905100", CategoryCommonExcept},
		{"905 common except last", "905110", CategoryCommonExcept},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CategoryForRule(tc.id); got != tc.want {
				t.Errorf("CategoryForRule(%q) = %q, want %q", tc.id, got, tc.want)
			}
		})
	}
}

// Phase Y boundary conditions — the upper / lower bounds of
// each [NN000, NN+1 000) range. Pre-Y a single off-by-one
// (e.g. 933000 → CategoryRCE) would have collapsed PHP back
// into RCE silently ; pinning the boundaries forces a
// deliberate decision on any future range change.
func TestCategoryForRule_BoundaryConditions(t *testing.T) {
	boundary := []struct {
		id   string
		want OwaspCategory
		note string
	}{
		// SQLi ↔ session-fixation boundary.
		{"942999", CategorySQLi, "upper of 942"},
		{"943000", CategorySession, "lower of 943 (not SQLi, not Other)"},
		// XSS ↔ SQLi.
		{"941999", CategoryXSS, "upper of 941"},
		{"942000", CategorySQLi, "lower of 942"},
		// RCE ↔ PHP ↔ Generic ↔ XSS gap.
		{"932999", CategoryRCE, "upper of 932"},
		{"933000", CategoryPHP, "lower of 933 (NOT RCE — Phase Y split)"},
		{"933999", CategoryPHP, "upper of 933"},
		{"934000", CategoryGeneric, "lower of 934 (NOT RCE — Phase Y split)"},
		{"934999", CategoryGeneric, "upper of 934"},
		// LFI ↔ RFI split (Phase Y).
		{"930999", CategoryLFI, "upper of 930"},
		{"931000", CategoryRFI, "lower of 931 (NOT LFI — Phase Y split)"},
		// 944 Java is its own bucket (Phase Y).
		{"944000", CategoryJava, "lower of 944 (NOT RCE)"},
		// Protocol family split.
		{"911999", CategoryMethod, "upper of 911"},
		{"912000", CategoryOther, "gap 912 — not classified"},
		{"920000", CategoryProtocol, "lower of 920"},
		{"920999", CategoryProtocol, "upper of 920"},
		{"921000", CategoryProtocolAttack, "lower of 921 (split from Protocol)"},
		{"922000", CategoryMultipart, "lower of 922 (split from Protocol)"},
		// Aggregators.
		{"949000", CategoryAnomalyReq, "lower of 949 (NOT Other)"},
		{"949999", CategoryAnomalyReq, "upper of 949"},
		// Data-leak family.
		{"950000", CategoryDataLeak, "lower of 950 (NOT Other — Phase Y)"},
		{"951000", CategoryDataLeakSQL, "lower of 951"},
		{"955000", CategoryWebShell, "lower of 955"},
		// Infrastructure.
		{"901000", CategoryInit, "lower of 901 (NOT Other — Phase Y)"},
		{"905000", CategoryCommonExcept, "lower of 905"},
	}
	for _, tc := range boundary {
		t.Run(tc.id, func(t *testing.T) {
			if got := CategoryForRule(tc.id); got != tc.want {
				t.Errorf("CategoryForRule(%q) = %q ; want %q (%s)",
					tc.id, got, tc.want, tc.note)
			}
		})
	}
}

func TestCategoryForRule_UnknownAndMalformed_FallBackToOther(t *testing.T) {
	cases := []string{
		"",            // empty
		"abc",         // non-numeric
		"-1",          // negative
		"99999999999", // huge, falls through ranges
		"500",         // too small for any range
		"800000",      // between known ranges
		"906000",      // gap between 905 (CommonExcept) and 911 (Method)
		"912000",      // gap between 911 and 913
		"914000",      // gap between 913 and 920
		"923000",      // gap between 922 and 930
		"935000",      // gap between 934 and 941
		"945000",      // gap between 944 and 949
		"956000",      // gap between 955 and 959
		"960000",      // gap between 959 and 980
		"990000",      // above 980, below 1M
	}
	for _, id := range cases {
		t.Run("input="+id, func(t *testing.T) {
			if got := CategoryForRule(id); got != CategoryOther {
				t.Errorf("CategoryForRule(%q) = %q, want OTHER (fallback)",
					id, got)
			}
		})
	}
}

// Phase Y — AllCategories sanity. The slice is the source of
// truth the frontend consumes via the type generator ; every
// category constant the SQLite layer may persist MUST appear
// in the slice so the frontend's switch / map covers it.
func TestAllCategories_ContainsEveryPhaseYCategory(t *testing.T) {
	want := []OwaspCategory{
		// Pre-Y (kept for storage compat).
		CategorySQLi, CategoryXSS, CategoryRCE, CategoryLFI, CategoryProtocol, CategoryOther,
		// Phase Y new.
		CategoryInit, CategoryCommonExcept, CategoryMethod, CategoryScanner,
		CategoryProtocolAttack, CategoryMultipart, CategoryRFI, CategoryPHP,
		CategoryGeneric, CategorySession, CategoryJava,
		CategoryAnomalyReq, CategoryAnomalyResp, CategoryCorrelation,
		CategoryDataLeak, CategoryDataLeakSQL, CategoryDataLeakJava,
		CategoryDataLeakPHP, CategoryDataLeakIIS, CategoryWebShell,
	}
	got := map[OwaspCategory]struct{}{}
	for _, c := range AllCategories {
		got[c] = struct{}{}
	}
	for _, c := range want {
		if _, ok := got[c]; !ok {
			t.Errorf("AllCategories missing %q (every storage-emittable category MUST appear)", c)
		}
	}
}
