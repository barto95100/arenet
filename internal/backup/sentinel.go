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

package backup

import (
	"errors"
	"fmt"
)

// redactSnapshotInPlace overwrites every secret field listed in the
// spec §5.3 secret-scope table with SentinelLiteral. Called only when
// the export is the default (secrets excluded). The Snapshot passed
// in MUST be a fresh build off the live store — the receiver mutates
// it in place to keep the export pass single-pass + zero-allocation
// where Go allows.
//
// Field-by-field source of truth: spec §5.3 secret-scope table.
// Adding a new secret field elsewhere in the codebase REQUIRES
// adding a matching entry here, or the export silently leaks it.
// The companion test asserts the redaction is exhaustive against
// known field paths.
func redactSnapshotInPlace(s *Snapshot) {
	s.SecretsIncluded = false

	for i := range s.Routes {
		// routes[].basic_auth.password_hash
		if s.Routes[i].BasicAuth.PasswordHash != "" {
			s.Routes[i].BasicAuth.PasswordHash = SentinelLiteral
		}
	}
	for i := range s.Users {
		// users[].password_hash
		if s.Users[i].PasswordHash != "" {
			s.Users[i].PasswordHash = SentinelLiteral
		}
	}
	for i := range s.DNSProviders {
		// dns_providers[].application_key, application_secret, consumer_key
		if s.DNSProviders[i].ApplicationKey != "" {
			s.DNSProviders[i].ApplicationKey = SentinelLiteral
		}
		if s.DNSProviders[i].ApplicationSecret != "" {
			s.DNSProviders[i].ApplicationSecret = SentinelLiteral
		}
		if s.DNSProviders[i].ConsumerKey != "" {
			s.DNSProviders[i].ConsumerKey = SentinelLiteral
		}
	}
	for i := range s.ForwardAuthProviders {
		// forward_auth_providers[].client_secret
		if s.ForwardAuthProviders[i].ClientSecret != "" {
			s.ForwardAuthProviders[i].ClientSecret = SentinelLiteral
		}
	}
	// oidc_config.client_secret
	if s.OIDCConfig.ClientSecret != "" {
		s.OIDCConfig.ClientSecret = SentinelLiteral
	}
}

// unresolvedSentinel is the dedicated error returned by the
// resolution pass on a sentinel that finds no inheritable value
// AND the operator has not opted into AllowIncompleteRestore. The
// import surface unwraps this to produce the actionable
// reject-with-two-paths error message named in spec §5.3 rule 2.
type unresolvedSentinel struct {
	Entity   string
	Identity string // logical ID (route id, user id, "ovh", provider name, "default")
	Field    string // secret field name, e.g. "basic_auth.password_hash"
}

func (e *unresolvedSentinel) Error() string {
	// The wording mirrors spec §5.3 rule 2 verbatim. Pinning the
	// shape of this string is important: tests assert on it, and
	// the operator-facing CLI / UI surface it directly.
	return fmt.Sprintf(
		"restore: cannot import row %s (%s=%s): field %s is the redaction sentinel and no matching row exists in the target. The restored row would have no usable secret.\n\nTwo paths forward:\n (a) Re-export the source instance with --include-secrets\n     (mind the file-permission warning) and re-import.\n (b) Pass --allow-incomplete-restore to accept this row\n     knowingly. The affected secret field will be cleared;\n     the row's secret will need to be re-saved by hand before\n     the affected surface works again. The boot WARN at next\n     start lists every such row.",
		e.Entity,
		identityKey(e.Entity),
		e.Identity,
		e.Field,
	)
}

func identityKey(entity string) string {
	switch entity {
	case "routes", "users":
		return "id"
	case "dns_providers":
		return "key"
	case "forward_auth_providers":
		return "name"
	case "oidc_config":
		return "key"
	}
	return "id"
}

// isUnresolvedSentinel is a typed errors.As helper used by callers
// who want to surface the error message verbatim (the API handler,
// the CLI). Tests use this to assert the type without
// string-matching the body.
func isUnresolvedSentinel(err error) (*unresolvedSentinel, bool) {
	var us *unresolvedSentinel
	if errors.As(err, &us) {
		return us, true
	}
	return nil, false
}

// ErrPreflightDisasterRecovery is the dedicated error spec §5.3
// requires for the "no-secrets import onto a fresh target" path.
// The error has its own type so callers can show the dedicated
// pre-flight wording (which differs from the per-row sentinel
// rejection — the recovery wording is identical, but the lead
// names "no existing secrets to inherit" rather than a single
// row).
var ErrPreflightDisasterRecovery = errors.New(
	"restore: import file was exported WITHOUT --include-secrets " +
		"(secrets_included: false) AND the target instance has no " +
		"existing secrets to inherit. The restored configuration would " +
		"have no admin password, no OIDC client secret, no OVH DNS " +
		"credentials, no per-route Basic Auth passwords, and no " +
		"forward-auth client secrets — the resulting instance would be " +
		"inaccessible.\n\n" +
		"Two paths forward:\n" +
		" (a) Re-export the source instance with --include-secrets\n" +
		"     (mind the file-permission warning) and re-import.\n" +
		" (b) Pass --allow-incomplete-restore to accept this state\n" +
		"     knowingly. The restored instance will have a working\n" +
		"     admin user (via re-run of the boot-time setup token) but\n" +
		"     every per-route Basic Auth, OVH DNS, forward-auth, and\n" +
		"     OIDC field will need to be re-saved by hand before the\n" +
		"     corresponding routes work again.",
)

// ErrEmptyUsers is the dedicated error for AC #15: a restore whose
// Users slice is empty is rejected by default. The
// AllowEmptyUsers flag opts in.
var ErrEmptyUsers = errors.New(
	"restore: import file has zero users — restoring would leave the " +
		"instance without an admin account.\n\n" +
		"Two paths forward:\n" +
		" (a) Re-export the source instance with at least one user.\n" +
		" (b) Pass --allow-empty-users to accept this state knowingly;\n" +
		"     the next boot will re-trigger the setup-token flow so\n" +
		"     you can create a fresh admin account.",
)

// ErrSchemaMajorMismatch is returned when the import file's
// schema_version major component differs from SchemaMajor. The
// caller surfaces it with both versions visible.
type ErrSchemaMajorMismatch struct {
	FileVersion   string
	BinaryVersion string
}

func (e *ErrSchemaMajorMismatch) Error() string {
	return fmt.Sprintf(
		"restore: import file declares schema_version %q (major mismatch — this binary reads major %q only). The file was written by a binary on a different schema generation. Upgrade the binary, downgrade the file via a side migrate tool, or re-export from the source instance.",
		e.FileVersion,
		e.BinaryVersion,
	)
}
