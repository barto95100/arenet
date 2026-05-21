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

package auth

import (
	"fmt"

	"github.com/alexedwards/argon2id"
)

// HashRoutePassword turns a plaintext password (typed by the admin
// when configuring per-route Basic Auth) into an argon2id PHC string.
//
// The output format `$argon2id$v=19$m=...,t=...,p=...$salt$key` is
// the standard PHC encoding, accepted as-is by Caddy v2.11.3's
// caddyhttp/caddyauth/argon2id.go: Caddy parses every parameter from
// the string at verify time, so the hash interoperates regardless of
// whose params produced it.
//
// Step I.5 reuses the Step D (admin login) argon2idParams — same
// memory/iterations/parallelism — for "vraie cohérence Step D"
// (Step I spec §5.5 misstated bcrypt; argon2id is the correct
// algorithm and Caddy supports it natively without an external
// module, so no new dependency is introduced).
//
// Returns the PHC string, or an error if the underlying argon2id
// library could not produce a hash (rare — mostly out-of-memory).
func HashRoutePassword(plaintext string) (string, error) {
	hash, err := argon2id.CreateHash(plaintext, argon2idParams)
	if err != nil {
		return "", fmt.Errorf("auth: hash route password: %w", err)
	}
	return hash, nil
}
