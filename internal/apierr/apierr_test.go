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

package apierr

import (
	"errors"
	"fmt"
	"testing"
)

// v2.46 — what makes this safe to adopt gradually is that a coded
// error is still an ordinary error. Every existing caller, log line
// and test keeps working, and only the call sites that opt in gain a
// translated message.

func TestError_IsAnOrdinaryError(t *testing.T) {
	err := New("redirect_self_loop", map[string]string{"host": "a.example.com"},
		"redirect: the target points back at %s", "a.example.com")

	if err.Error() != "redirect: the target points back at a.example.com" {
		t.Fatalf("the English sentence must survive verbatim: %q", err.Error())
	}
}

func TestCoded_FollowsWrapping(t *testing.T) {
	inner := New("path_rule_uppercase", map[string]string{"path": "/Admin"}, "nope")
	wrapped := fmt.Errorf("saving the route: %w", inner)

	code, params, ok := Coded(wrapped)
	if !ok {
		t.Fatal("a wrapped coded error must still be recognised")
	}
	if code != "path_rule_uppercase" {
		t.Errorf("code: %q", code)
	}
	if params["path"] != "/Admin" {
		t.Errorf("params: %v", params)
	}
}

// A plain error carries no code, and the caller reports it the way it
// always did. This is the whole fallback story.
func TestCoded_PlainErrorHasNoCode(t *testing.T) {
	if _, _, ok := Coded(errors.New("something broke")); ok {
		t.Fatal("a plain error must not claim a code")
	}
	if _, _, ok := Coded(nil); ok {
		t.Fatal("nil must not claim a code")
	}
}
