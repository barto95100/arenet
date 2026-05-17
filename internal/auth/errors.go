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

import "errors"

// User store sentinel errors. See spec §3.2.
var (
	// ErrUserNotFound is returned when GetByID or GetByUsername cannot
	// locate a matching user.
	ErrUserNotFound = errors.New("auth: user not found")

	// ErrUsernameTaken is returned when Create is called with a username
	// that already exists in the bucket.
	ErrUsernameTaken = errors.New("auth: username already taken")

	// ErrUsernameInvalid is returned when the supplied username does not
	// match the format defined by D5: regex ^[a-z0-9_-]+$, length 3..32.
	ErrUsernameInvalid = errors.New("auth: username does not match required format")

	// ErrDisplayNameTooLong is returned when DisplayName exceeds the
	// bound defined by D5 (64 characters).
	ErrDisplayNameTooLong = errors.New("auth: display name too long")

	// ErrPasswordTooShort is returned when a password is fewer than 15
	// characters (decision D6).
	ErrPasswordTooShort = errors.New("auth: password must be at least 15 characters")

	// ErrPasswordTooLong is returned when a password exceeds 128
	// characters (decision D6).
	ErrPasswordTooLong = errors.New("auth: password must be at most 128 characters")

	// ErrPasswordCommon is returned when the supplied password matches
	// an entry in the embedded top-10k common-passwords list, or when
	// a synchronous HIBP check (Chunk 2) confirms the password is
	// compromised. Same error for both sources so the user experience
	// is uniform.
	ErrPasswordCommon = errors.New("auth: password is in the list of common compromised passwords")
)

// Session store sentinel errors. See spec §3.3.
var (
	// ErrSessionNotFound is returned when Get cannot locate a session
	// by ID.
	ErrSessionNotFound = errors.New("auth: session not found")

	// ErrSessionExpired is returned when Get loads a session whose
	// ExpiresAt is in the past. The session is also lazy-purged from
	// the bucket on this code path.
	ErrSessionExpired = errors.New("auth: session expired")
)
