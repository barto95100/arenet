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

// Several validation-400 handlers answer with a machine code as the
// message, either bare ("cert_required", "invalid_country") or followed
// by an English technical detail ("key_does_not_match_cert: crypto/tls:
// private key does not match public key"). The UI is expected to show
// its own translated sentence for the codes it knows and the raw
// message for the ones it does not, so nothing is ever hidden.
//
// ExternalCertsPanel had that logic inline, which is why the re-import
// and the CSR forms in the same subsystem never got it and printed the
// raw code at the operator. One copy, imported by all three.

/** A code is a bare lower_snake token — never a human sentence. */
const CODE_RE = /^[a-z][a-z0-9_]*$/;

/**
 * Splits a backend error message into its leading machine code and the
 * rest. Returns a null code when the message does not start with one,
 * which is how a plain sentence (or a network failure string) survives
 * untouched.
 */
export function splitApiErrorCode(rawMessage: string): {
	code: string | null;
	detail: string;
} {
	const sep = rawMessage.indexOf(': ');
	const head = sep === -1 ? rawMessage : rawMessage.slice(0, sep);
	if (!CODE_RE.test(head)) {
		return { code: null, detail: rawMessage };
	}
	return { code: head, detail: sep === -1 ? '' : rawMessage.slice(sep + 2) };
}

/**
 * Resolves a backend error message against a code → i18n-key map.
 * `translate` is the caller's `t`, so this stays free of store imports
 * and testable on its own.
 *
 * Returns the translated sentence and the code when the code is known,
 * and the raw message with a null code otherwise — an unmapped error is
 * shown as it arrived rather than swallowed.
 */
export function resolveApiError(
	rawMessage: string,
	codeKeys: Record<string, string>,
	translate: (key: string) => string
): { message: string; code: string | null } {
	const { code } = splitApiErrorCode(rawMessage);
	if (code && codeKeys[code]) {
		return { message: translate(codeKeys[code]), code };
	}
	return { message: rawMessage, code: null };
}
