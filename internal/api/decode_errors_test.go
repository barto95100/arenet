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

package api

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// #R-API-PUT-ROUTE-GENERIC-400 — unit tests for the
// translateDecodeError helper. Cover the four typed
// shapes (EOF, SyntaxError, UnmarshalTypeError, unknown
// field) plus the default raw fallback. Tests target the
// helper directly rather than going through a handler
// because every handler in the package routes its decode
// error through this single function — covering the
// helper covers all 22 call sites by transitivity.

func TestTranslateDecodeError_EOF(t *testing.T) {
	// Real-shape: an empty body sent through json.NewDecoder
	// returns io.EOF on the first Decode call. Confirm the
	// helper recognises io.EOF.
	got := translateDecodeError(io.EOF)
	if got != "JSON body is required" {
		t.Errorf("EOF translated to %q; want %q", got, "JSON body is required")
	}
	// Also: io.ErrUnexpectedEOF (premature truncation
	// mid-token) shares the same operator-facing meaning.
	gotUnexpected := translateDecodeError(io.ErrUnexpectedEOF)
	if gotUnexpected != "JSON body is required" {
		t.Errorf("ErrUnexpectedEOF translated to %q; want %q",
			gotUnexpected, "JSON body is required")
	}
}

func TestTranslateDecodeError_SyntaxError(t *testing.T) {
	// Drive a real json.SyntaxError by decoding a body
	// that's invalid JSON. "{not-json" trips the parser
	// at offset 1 or 2 depending on the Go version's
	// internal heuristic — assert structural (contains
	// "malformed JSON at offset") rather than the exact
	// offset to stay stable across Go versions.
	var v any
	err := json.NewDecoder(strings.NewReader("{not-json")).Decode(&v)
	if err == nil {
		t.Fatal("expected JSON parse error; got nil")
	}
	got := translateDecodeError(err)
	if !strings.HasPrefix(got, "malformed JSON at offset ") {
		t.Errorf("SyntaxError translated to %q; want prefix \"malformed JSON at offset \"", got)
	}
}

func TestTranslateDecodeError_UnmarshalTypeError(t *testing.T) {
	// Drive a real *json.UnmarshalTypeError: a wire
	// struct expects an int, the body sends a string.
	type wire struct {
		Weight int `json:"weight"`
	}
	var v wire
	err := json.NewDecoder(strings.NewReader(`{"weight":"not-a-number"}`)).Decode(&v)
	if err == nil {
		t.Fatal("expected type mismatch error; got nil")
	}
	got := translateDecodeError(err)
	// Pin three structural traits without locking the
	// exact full string (stdlib message format may evolve
	// across Go versions):
	//   - mentions the field name
	//   - mentions "expected"
	//   - mentions the expected Go type ("int")
	if !strings.Contains(got, "weight") {
		t.Errorf("translation %q missing field name 'weight'", got)
	}
	if !strings.Contains(got, "expected") {
		t.Errorf("translation %q missing word 'expected'", got)
	}
	if !strings.Contains(got, "int") {
		t.Errorf("translation %q missing expected type 'int'", got)
	}
}

func TestTranslateDecodeError_UnknownField(t *testing.T) {
	// Drive a real DisallowUnknownFields error: the wire
	// struct has no "bogusField" but the body provides
	// it. The stdlib emits json: unknown field "bogusField".
	type wire struct {
		Known string `json:"known"`
	}
	var v wire
	dec := json.NewDecoder(strings.NewReader(`{"bogusField":"value"}`))
	dec.DisallowUnknownFields()
	err := dec.Decode(&v)
	if err == nil {
		t.Fatal("expected unknown-field error; got nil")
	}
	got := translateDecodeError(err)
	// The helper should produce `unknown field "bogusField"`.
	// Pin both substrings.
	if !strings.Contains(got, "unknown field") {
		t.Errorf("translation %q missing 'unknown field' phrase", got)
	}
	if !strings.Contains(got, "bogusField") {
		t.Errorf("translation %q missing field name 'bogusField'", got)
	}
}

func TestTranslateDecodeError_DefaultFallback(t *testing.T) {
	// An arbitrary error that doesn't match any of the
	// typed cases. Confirm the helper passes it through
	// with the "invalid JSON body: " prefix so the
	// operator never sees a silent message loss.
	custom := errors.New("decoder ran out of toasters")
	got := translateDecodeError(custom)
	if got != "invalid JSON body: decoder ran out of toasters" {
		t.Errorf("default fallback = %q; want %q",
			got, "invalid JSON body: decoder ran out of toasters")
	}
}

func TestTranslateDecodeError_NilSafety(t *testing.T) {
	// Defensive: nil err shouldn't crash. Returns the
	// pre-fix generic phrase since the caller shouldn't
	// have reached this branch but a silent panic would
	// be worse than the legacy message.
	got := translateDecodeError(nil)
	if got != "invalid JSON body" {
		t.Errorf("nil err translated to %q; want %q", got, "invalid JSON body")
	}
}
