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

import "strconv"

// CategoryForRule maps an OWASP CRS rule ID to an OwaspCategory
// for the dashboard's category distribution strip + the
// per-category counts on /api/v1/metrics/summary.
//
// Source of truth: the CRS rule files distributed by
// coraza-coreruleset/v4 v4.25.0 (filename pattern
// `REQUEST-<categoryRangePrefix>-<NAME>.conf`). The ID range
// allocation below is documented in the CRS rules-by-id
// convention; if a future CRS bump introduces a new range
// it should be added here AND a corresponding test case in
// category_test.go.
//
// Unknown / unparseable rule IDs fall back to CategoryOther
// so an unrecognised rule never crashes the dashboard or
// produces an empty category string in the SQLite row.
//
// Why integer-range bucketing instead of a per-rule map:
// the CRS ships ~250 active rules; a per-rule map would
// duplicate the range information that the CRS authors
// already encoded in the rule-ID prefix. The range-based
// classifier auto-classifies any future rule the operator
// adds without code changes (as long as the operator
// respects the CRS prefix convention).
func CategoryForRule(ruleID string) OwaspCategory {
	id, err := strconv.Atoi(ruleID)
	if err != nil || id < 0 {
		return CategoryOther
	}
	// Phase Y (2026-06-18) — 25-category mapping verified
	// empirically against coreruleset@v0.0.0-20240226 (CRS
	// 4.0.0-rc2). Each upstream conf file maps 1:1 to one
	// Arenet category :
	//   REQUEST-9NN-NAME.conf  → rules in [NN000, NN999]
	//   RESPONSE-9NN-NAME.conf → rules in [NN000, NN999]
	// The audit captured first/last id per file ; the
	// switch below uses [NN000, NN+1 000) half-open ranges
	// to be future-proof against new rules added inside
	// the same CRS file (the upstream convention reserves
	// the full prefix block for one file).
	switch {
	// --- Request attacks ---
	case id >= 942000 && id < 943000:
		return CategorySQLi // 942 SQL injection
	case id >= 941000 && id < 942000:
		return CategoryXSS // 941 XSS
	case id >= 932000 && id < 933000:
		return CategoryRCE // 932 shell-injection RCE
	case id >= 933000 && id < 934000:
		return CategoryPHP // 933 PHP-specific exec
	case id >= 934000 && id < 935000:
		return CategoryGeneric // 934 Node/SSRF/template
	case id >= 930000 && id < 931000:
		return CategoryLFI // 930 LFI (path traversal)
	case id >= 931000 && id < 932000:
		return CategoryRFI // 931 RFI (remote inclusion)
	case id >= 944000 && id < 945000:
		return CategoryJava // 944 Java deser/JNDI (Log4Shell)
	case id >= 943000 && id < 944000:
		return CategorySession // 943 session fixation

	// --- Protocol / behaviour ---
	case id >= 911000 && id < 912000:
		return CategoryMethod // 911 method enforcement
	case id >= 920000 && id < 921000:
		return CategoryProtocol // 920 protocol enforcement
	case id >= 921000 && id < 922000:
		return CategoryProtocolAttack // 921 smuggling/splitting
	case id >= 922000 && id < 923000:
		return CategoryMultipart // 922 multipart exploits
	case id >= 913000 && id < 914000:
		return CategoryScanner // 913 sqlmap/nikto UAs

	// --- Aggregators ---
	case id >= 949000 && id < 950000:
		return CategoryAnomalyReq // 949 inbound anomaly score
	case id >= 959000 && id < 960000:
		return CategoryAnomalyResp // 959 outbound anomaly score
	case id >= 980000 && id < 981000:
		return CategoryCorrelation // 980 in/out correlation

	// --- Response-side / data leak ---
	case id >= 950000 && id < 951000:
		return CategoryDataLeak // 950 generic info disclosure
	case id >= 951000 && id < 952000:
		return CategoryDataLeakSQL // 951 SQL error leak
	case id >= 952000 && id < 953000:
		return CategoryDataLeakJava // 952 Java stack leak
	case id >= 953000 && id < 954000:
		return CategoryDataLeakPHP // 953 PHP error leak
	case id >= 954000 && id < 955000:
		return CategoryDataLeakIIS // 954 IIS info leak
	case id >= 955000 && id < 956000:
		return CategoryWebShell // 955 webshell signatures

	// --- Infrastructure ---
	case id >= 901000 && id < 902000:
		return CategoryInit // 901 CRS tx.* setup
	case id >= 905000 && id < 906000:
		return CategoryCommonExcept // 905 false-positive bypasses
	}
	return CategoryOther
}
