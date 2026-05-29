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
	switch {
	case id >= 942000 && id < 943000:
		return CategorySQLi
	case id >= 941000 && id < 942000:
		return CategoryXSS
	case id >= 932000 && id < 933000,
		// PHP injection: 933xxx is technically a language-
		// specific RCE; PHP-code-injection lands here.
		id >= 933000 && id < 934000,
		// Generic application attacks: 934xxx (Node/SSRF/
		// template injection) lean RCE in effect.
		id >= 934000 && id < 935000,
		// Java-specific RCE (deserialisation, JNDI).
		id >= 944000 && id < 945000:
		return CategoryRCE
	case id >= 930000 && id < 932000:
		// 930xxx LFI + 931xxx RFI both expose the
		// filesystem; bucketed together as LFI.
		return CategoryLFI
	case id >= 920000 && id < 922000,
		// 920xxx protocol enforcement + 921xxx protocol
		// attacks + 922xxx multipart attacks.
		id >= 922000 && id < 923000,
		// 911xxx method enforcement.
		id >= 911000 && id < 912000:
		return CategoryProtocol
	}
	return CategoryOther
}
