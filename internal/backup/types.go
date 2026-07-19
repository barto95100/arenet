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

// Package backup implements the Step K.3 export / restore engine.
//
// Surface boundaries (intentional):
//
//   - export.go  → build a Snapshot from the live BoltDB; redact
//     secrets by default; emit a JSON file the operator can
//     archive. Idempotent, read-only.
//
//   - import.go  → take a Snapshot + Options, run the pre-flight
//     check, resolve sentinels by logical-identity match against
//     the live BoltDB, then commit the entire state in a single
//     bbolt transaction via storage.RestoreSnapshot. All-or-nothing.
//
//   - sentinel.go → the literal sentinel string, the redaction
//     pass, and the sentinel resolution pass (preserve-on-ID-match).
//
// The package never writes the sentinel literal into a target field
// (spec §5.3 rule 1, option (a) explicitly rejected as a silent
// footgun). Either we inherit a real value from the live store, or
// we reject the row (unless --allow-incomplete-restore explicitly
// opts in, in which case the field is cleared and the next boot
// emits a WARN).
package backup

import (
	"time"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// SentinelLiteral is the placeholder Arenet writes into every secret
// field when secrets are excluded from an export. The restore path
// looks for an exact equality match with this string; any other
// value (including empty string) is treated as the operator's intent
// to overwrite. The constant is exported so tests in other packages
// can pin the wire format.
const SentinelLiteral = "$$ARENET_REDACTED$$"

// SchemaVersion is the version string the running binary writes into
// every export AND the value its restore engine knows how to read.
// The restore enforces MAJOR-equal at import time per spec §5.3.
const SchemaVersion = "1.0.0"

// SchemaMajor is the MAJOR component of SchemaVersion. An import
// file whose MAJOR component differs is rejected with a clear error
// message naming both versions.
const SchemaMajor = "1"

// Snapshot is the full JSON shape of an exported Arenet
// configuration. The field order in the JSON output is deterministic
// (Go marshals struct fields in declaration order), so a clean
// round-trip produces byte-identical output modulo timestamps + IDs.
type Snapshot struct {
	SchemaVersion        string                        `json:"schema_version"`
	ExportedAt           time.Time                     `json:"exported_at"`
	SecretsIncluded      bool                          `json:"secrets_included"`
	ArenetVersion        string                        `json:"arenet_version"`
	Routes               []storage.Route               `json:"routes"`
	DNSProviders         []storage.DNSProviderConfig   `json:"dns_providers"`
	ForwardAuthProviders []storage.ForwardAuthProvider `json:"forward_auth_providers"`
	OIDCConfig           storage.OIDCConfig            `json:"oidc_config"`
	// MaxMindConfig is nil when the instance has never configured
	// MaxMind GeoIP credentials (mirrors the OIDC "never configured"
	// zero-value shape, but as a pointer since MaxMindConfig has no
	// natural "disabled" zero value the way OIDCConfig.Enabled
	// gives OIDC — a nil pointer is the unambiguous "row absent"
	// signal for the single-record store).
	MaxMindConfig *storage.MaxMindConfig `json:"maxmind_config,omitempty"`
	Users         []auth.User            `json:"users"`
	// ExternalCertificates carries operator-uploaded TLS certs
	// (v2.19.0). Each row's KeyPEM is a SECRET redacted by default
	// (sentinel) and preserved-on-ID-match at import, mirroring the
	// DNS-provider secret discipline. A pre-v2.19.0 snapshot has no
	// external_certificates key → this field decodes to nil, which
	// imports cleanly (backward-compat).
	ExternalCertificates []storage.ExternalCertificate `json:"external_certificates"`
}

// ImportOptions controls the two opt-in bypass flags. Both default
// to false ("loud-fail on every failure path" per spec §1.6 Δ5).
type ImportOptions struct {
	// AllowIncompleteRestore covers both unresolvable-sentinel
	// failure modes: the disaster-recovery pre-flight (fresh
	// target + no-secrets import) and the per-row sentinel
	// mismatch case (a sentinel whose logical identity doesn't
	// match any row in the live store). With the flag set, the
	// affected fields are cleared to empty string, the storage
	// validators are bypassed for those fields, and the next boot
	// prints a WARN listing every row that needs a re-saved
	// secret.
	AllowIncompleteRestore bool

	// AllowEmptyUsers permits an import whose Users slice is
	// empty. The default rejects empty-users imports (spec AC #15
	// + §1.6 Δ5): an operator restoring an empty-users export
	// onto an instance would lock themselves out. Opt-in
	// re-triggers the boot-time setup-token flow.
	AllowEmptyUsers bool
}

// ImportReport summarises the outcome of a successful import. The
// counts feed the config_restored audit event payload (spec §5.3 +
// AC #15bis). On a rejected restore the caller emits
// config_restored_rejected instead with the failure reason; this
// struct is only constructed on the happy path.
type ImportReport struct {
	SchemaVersion                string
	SecretsIncludedInSource      bool
	AllowIncompleteRestore       bool
	RoutesImported               int
	UsersImported                int
	DNSProvidersImported         int
	ForwardAuthProvidersImported int
	OIDCConfigImported           bool
	MaxMindConfigImported        bool
	ExternalCertificatesImported int
	// SentinelsInheritedTotal counts sentinel occurrences resolved
	// by ID match against the live store.
	SentinelsInheritedTotal int
	// SentinelsUnresolvedTotal counts sentinel occurrences that
	// found no inheritable value AND were cleared because
	// AllowIncompleteRestore was set. Always 0 on a default
	// (loud-fail) import; if the import made it to Report
	// construction with this >0, the operator opted in.
	SentinelsUnresolvedTotal int
	// IncompleteRows enumerates the (entity, identity, field)
	// tuples whose secret was cleared. The boot-time WARN in
	// cmd/arenet/main.go iterates this slice when present (spec
	// §1.6 J.4 boot WARN pattern).
	IncompleteRows []IncompleteRow
}

// IncompleteRow names a row whose secret was cleared under
// AllowIncompleteRestore. The caller persists the same names in
// the audit event so a post-mortem can list every affected surface.
type IncompleteRow struct {
	Entity   string // "routes", "users", "dns_providers", "forward_auth_providers", "oidc_config", "maxmind_config"
	Identity string // route id, user id, "ovh", provider name, or "default"
	Field    string // "basic_auth.password_hash", "password_hash", "application_key", etc.
}
