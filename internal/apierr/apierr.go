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

// Package apierr carries a stable code alongside a refusal, so the UI
// can say it in the operator's language.
//
// v2.46 — Arenet used to return refusals as English sentences and the
// frontend printed them verbatim, so an operator working in French met
// English at exactly the moments that matter: the loop guard, the
// uppercase path, the UDP probe. The project's own rule says UI
// strings go through i18n; these bypassed it.
//
// The mechanism is deliberately additive. An Error still carries its
// English sentence and still satisfies `error`, so every existing
// caller, log line and test keeps working unchanged. What it adds is a
// Code the frontend can look up and Params to substitute — and when
// the frontend does not know the code, it falls back to the sentence.
// That is what makes this translatable one message at a time instead
// of in one risky sweep.
package apierr

import (
	"errors"
	"fmt"
)

// Error is a refusal with a stable identity.
//
// Code is the lookup key, in snake_case, scoped by subject:
// "redirect_self_loop", "path_rule_uppercase". It is part of the API
// contract once shipped — the frontend keys its translations on it, so
// renaming one silently reverts that message to English.
type Error struct {
	Code   string
	Params map[string]string
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

// New builds a coded error. The message is formatted from args as
// usual; params carry the same values in structured form, because a
// translated sentence puts them in a different order — or drops them.
//
// Both are given explicitly rather than derived from each other: a
// French sentence may need a value the English one only implies, and
// guessing which is which from a format string is how this sort of
// helper becomes unpredictable.
func New(code string, params map[string]string, format string, args ...any) *Error {
	return &Error{Code: code, Params: params, Msg: fmt.Sprintf(format, args...)}
}

// Coded extracts the code and params of an error, following wrapping.
// Returns ok=false for a plain error, which the caller reports the way
// it always did.
func Coded(err error) (code string, params map[string]string, ok bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Code, e.Params, true
	}
	return "", nil, false
}
