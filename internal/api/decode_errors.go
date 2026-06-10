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
	"fmt"
	"io"
	"strings"
)

// translateDecodeError converts a json.Decode error into an
// operator-readable 400 body. It distinguishes the four
// common shapes:
//
//   - io.EOF (empty body or premature truncation) →
//     "JSON body is required"
//   - *json.SyntaxError → "malformed JSON at offset N"
//   - *json.UnmarshalTypeError → "field X: expected T,
//     got U"
//   - strict-mode unknown field
//     (DisallowUnknownFields) → "unknown field 'X'"
//
// Anything else passes through with a generic "invalid
// JSON body: <raw>" prefix so the operator never sees a
// silent message loss.
//
// The unknown-field case has no typed error in the
// stdlib until proposal #41144 lands — until then,
// detection is a substring match on the canonical
// "json: unknown field "<name>"" form that encoding/json
// emits when DisallowUnknownFields is on. Brittle vs a
// typed errors.As(), but the format has been stable
// across every Go version that ships
// DisallowUnknownFields (1.10+) and any drift would be
// caught by the unit tests in routes_decode_errors_test.go.
//
// Step #R-API-PUT-ROUTE-GENERIC-400 — closes the
// observability gap that Day 8 smoke surfaced when
// commit 1 of #R-PROXMOX-HTTPS-LOOP shipped a wire-side
// gap: PUT /api/v1/routes/{id} returned a generic
// "invalid JSON body" that masked
// `json: unknown field "insecureSkipVerify"`, costing
// ~30min of diagnosis. With this helper, the same gap
// would have been a one-curl identification.
func translateDecodeError(err error) string {
	if err == nil {
		// Defensive: callers should not invoke on a nil
		// err, but returning "" here would produce a
		// blank 400 body that confuses operators worse
		// than the generic message.
		return "invalid JSON body"
	}

	// io.EOF: empty body, or a body that terminated
	// mid-token. Either way the decoder ran out of input
	// before reaching a top-level value.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "JSON body is required"
	}

	// *json.SyntaxError carries the byte offset where the
	// parse failed. Useful for hand-crafted curl payloads
	// (operator can `head -c <offset>` to see the prefix).
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return fmt.Sprintf("malformed JSON at offset %d", syntaxErr.Offset)
	}

	// *json.UnmarshalTypeError carries the field name +
	// the Go type the decoder expected. The wire-side
	// Value field is JSON-flavoured ("bool", "string",
	// "number"). Surface both so the operator can match
	// the input against the expected shape.
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		field := typeErr.Field
		if field == "" {
			// Top-level value-type mismatch (rare —
			// usually the caller sent an array where the
			// decoder expected an object). Fall back to
			// a generic phrasing.
			return fmt.Sprintf("expected JSON %s, got %s", typeErr.Type, typeErr.Value)
		}
		return fmt.Sprintf("field %q: expected %s, got %s", field, typeErr.Type, typeErr.Value)
	}

	// Strict-mode unknown field. Substring match on the
	// canonical stdlib format. The field name lives
	// between the first pair of double quotes in the
	// error string: `json: unknown field "foo"`.
	msg := err.Error()
	if strings.Contains(msg, "unknown field") {
		if start := strings.Index(msg, `"`); start != -1 {
			if end := strings.Index(msg[start+1:], `"`); end != -1 {
				return fmt.Sprintf("unknown field %q", msg[start+1:start+1+end])
			}
		}
		return "unknown field in JSON body"
	}

	// Anything else: preserve the raw error so the
	// operator gets full visibility. Future-proofs against
	// new stdlib error types we have not yet typed-cased.
	return "invalid JSON body: " + msg
}
