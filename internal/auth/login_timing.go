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

package auth

import "github.com/alexedwards/argon2id"

// dummyLoginHash is a fixed argon2id PHC string built once, at package
// load, with the SAME production parameters UserStore uses. It exists so
// the login handler can pay the identical key-derivation cost on the
// branches that have no real hash to check — an unknown username, or an
// account with no local password (OIDC / service) — instead of returning
// a 401 in microseconds while a real wrong-password check takes ~100 ms.
// That wall-clock gap is a username-enumeration oracle (F28/F47/F58); the
// identical 401 body is not enough on its own.
//
// The error is ignored deliberately: CreateHash fails only if the params
// themselves are invalid, which breaks every real hash too, so there is
// nothing left to equalise. EqualiseLoginTiming no-ops on the empty
// string in that case rather than panic at init.
var dummyLoginHash, _ = argon2id.CreateHash("arenet-login-timing-equaliser", argon2idParams)

// EqualiseLoginTiming runs a throwaway argon2id comparison against the
// fixed dummy hash and discards the result, so a login branch with no
// real hash to verify costs the same as one that does. Call it on every
// pre-verification failure branch of login before writing the 401.
func EqualiseLoginTiming(password string) {
	if dummyLoginHash == "" {
		return
	}
	_, _ = argon2id.ComparePasswordAndHash(password, dummyLoginHash)
}
