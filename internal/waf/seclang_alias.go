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

import "github.com/barto95100/arenet/internal/seclang"

// The SecLang allowlist moved to internal/seclang (v2.73), and this
// file keeps the names its callers already use.
//
// Why it moved: the allowlist is the only thing standing between an
// operator-supplied directive string and the Coraza compiler, and it
// was reachable from exactly one caller — internal/api's
// normalizeSecLang. storage.Route.validate(), which EVERY write path
// goes through, could not call it, because internal/waf registers a
// Caddy module in its init() (module.go:65) and storage importing that
// would pull Caddy into every binary that touches the database,
// including the backup and healthcheck subcommands.
//
// So the check lived where one path could see it, the restore path
// could not, and a snapshot's waf_seclang reached coraza.NewWAF
// verbatim. internal/seclang has no Arenet dependencies and no module
// registration, so storage can call it.
//
// These aliases exist so internal/api and the tests keep compiling
// unchanged: a type alias is the same type, so a waf.SecLangError and
// a seclang.Error are interchangeable, including in a JSON payload.
type (
	// SecLangError is one problem found in a SecLang text.
	SecLangError = seclang.Error
	// SecLangRule is one accepted rule and its id.
	SecLangRule = seclang.Rule
)

// The ID range and size caps, re-exported unchanged.
const (
	SecLangMinID    = seclang.MinID
	SecLangMaxID    = seclang.MaxID
	SecLangMaxBytes = seclang.MaxBytes
	SecLangMaxRules = seclang.MaxRules
)

// CheckSecLang runs the allowlist over an operator-supplied SecLang
// text. Unchanged behaviour; see seclang.Check.
func CheckSecLang(text string) ([]SecLangRule, []SecLangError) {
	return seclang.Check(text)
}
