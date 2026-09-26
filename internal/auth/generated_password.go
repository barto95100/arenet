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
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// v2.48 — the first password of an admin-created account.
//
// Generated rather than invented, because an operator asked to think
// of a password for someone else reaches for something they will
// remember, and they do not need to remember this one: it is shown
// once, and the account has to change it at first login.

// generatedPasswordAlphabet excludes the characters that get misread
// or mistyped when a password is read off a screen and repeated to
// someone: 0/O, 1/l/I, and the symbols that vary by keyboard layout.
// This password crosses a human, sometimes out loud, so legibility is
// a property of the design and not a compromise on it.
const generatedPasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// generatedPasswordGroups / groupLen shape the output as
// "Xxxx-Xxxx-Xxxx-Xxxx-Xxxx": long enough to clear PasswordMinLen (15)
// with room to spare, and grouped because a 24-character run is
// transcribed wrongly far more often than five short ones.
const (
	generatedPasswordGroups = 5
	generatedPasswordGroup  = 4
)

// GeneratePassword returns a fresh password from crypto/rand.
//
// Entropy: 20 characters from a 56-symbol alphabet is about 116 bits,
// well past anything a password that lives for one login needs.
func GeneratePassword() (string, error) {
	max := big.NewInt(int64(len(generatedPasswordAlphabet)))
	groups := make([]string, 0, generatedPasswordGroups)
	for g := 0; g < generatedPasswordGroups; g++ {
		var sb strings.Builder
		for i := 0; i < generatedPasswordGroup; i++ {
			n, err := rand.Int(rand.Reader, max)
			if err != nil {
				// crypto/rand failing is not a condition to paper
				// over with a weaker source.
				return "", fmt.Errorf("auth: generate password: %w", err)
			}
			sb.WriteByte(generatedPasswordAlphabet[n.Int64()])
		}
		groups = append(groups, sb.String())
	}
	return strings.Join(groups, "-"), nil
}
