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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/google/uuid"
)

// ImportStorer is the storage subset Import consumes. The Import
// path reads the live state (to inherit sentinels by ID match), then
// calls RestoreSnapshot once at the end with the fully-resolved
// rows.
type ImportStorer interface {
	Storer
	RestoreSnapshot(ctx context.Context, in storage.RestoreSnapshotInput) error
}

// Import applies a Snapshot to the live store. The full pipeline,
// in order — any failure aborts BEFORE any write hits BoltDB:
//
//  1. Schema version check (MAJOR-equal rule).
//  2. AC #15 empty-users check (unless AllowEmptyUsers).
//  3. AC #14bis pre-flight: secrets_included=false + fresh target.
//  4. Sentinel resolution per row (rules 1-3 in spec §5.3).
//  5. Business-invariant re-check on the resolved snapshot. This
//     mirrors the domain validators CreateRoute / UpdateUser /
//     PutDNSProvider / PutOIDCConfig run on the live path —
//     storage.RestoreSnapshot bypasses them by construction (the
//     all-or-nothing transaction model needs unconditional writes
//     to be atomic), so we re-validate UPSTREAM. Narrow
//     dérogation for the specific (entity, identity, field)
//     tuples cleared under AllowIncompleteRestore. Cross-rules
//     (forward_auth provider exists, dns-01 requires DNS
//     provider, post-state has >= 1 local admin) are validated
//     against the snapshot's OWN set — the live state is about
//     to be replaced.
//  6. Atomic apply via storage.RestoreSnapshot.
//
// On any error in steps 1-5, the function returns BEFORE step 6.
// The BoltDB is left untouched. Step 6 itself runs under a single
// bbolt write transaction; a bbolt-level failure rolls the whole
// thing back. This is the "all-or-nothing" property pinned by spec
// §5.3.
func Import(ctx context.Context, store ImportStorer, users UserStorer, snap *Snapshot, opts ImportOptions) (*ImportReport, error) {
	if snap == nil {
		return nil, errors.New("import: nil snapshot")
	}
	if store == nil || users == nil {
		return nil, errors.New("import: nil store")
	}

	// 1. Schema major version check.
	if err := checkSchemaMajor(snap.SchemaVersion); err != nil {
		return nil, err
	}

	// 2. Empty-users guard (AC #15 + §1.6 Δ5).
	if len(snap.Users) == 0 && !opts.AllowEmptyUsers {
		return nil, ErrEmptyUsers
	}

	// 3. Pre-flight: AC #14bis. Reads the live store to decide
	// whether the target is "fresh".
	livePostFlight, err := readLive(ctx, store, users)
	if err != nil {
		return nil, fmt.Errorf("import: read live state: %w", err)
	}
	if !snap.SecretsIncluded && livePostFlight.isFresh() && !opts.AllowIncompleteRestore {
		return nil, ErrPreflightDisasterRecovery
	}

	// 4. Sentinel resolution. Each row in the snapshot whose
	// secret field carries SentinelLiteral inherits from the live
	// row of the same logical identity (rules 1-2 in spec §5.3).
	// Unresolved sentinels reject the whole import (rule 3) unless
	// AllowIncompleteRestore — in which case the field is cleared.
	report := &ImportReport{
		SchemaVersion:           snap.SchemaVersion,
		SecretsIncludedInSource: snap.SecretsIncluded,
		AllowIncompleteRestore:  opts.AllowIncompleteRestore,
	}
	resolved, err := resolveSentinels(snap, livePostFlight, opts, report)
	if err != nil {
		return nil, err
	}

	// 5. Business-invariant re-check on the resolved snapshot.
	// storage.RestoreSnapshot bypasses domain validators by
	// design (all-or-nothing transaction needs unconditional
	// writes), so we re-validate here. Narrow dérogation for the
	// fields the resolver legitimately cleared under
	// AllowIncompleteRestore — every other invariant unconditional.
	if err := validateResolvedSnapshot(resolved, report, opts); err != nil {
		return nil, err
	}

	// 6. Atomic apply.
	in, err := buildRestoreInput(resolved)
	if err != nil {
		return nil, fmt.Errorf("import: marshal: %w", err)
	}
	if err := store.RestoreSnapshot(ctx, in); err != nil {
		return nil, fmt.Errorf("import: apply: %w", err)
	}

	report.RoutesImported = len(resolved.Routes)
	report.UsersImported = len(resolved.Users)
	report.DNSProvidersImported = len(resolved.DNSProviders)
	report.ForwardAuthProvidersImported = len(resolved.ForwardAuthProviders)
	report.OIDCConfigImported = resolved.OIDCConfig.IssuerURL != "" || resolved.OIDCConfig.ClientID != ""
	return report, nil
}

// liveSnapshot captures the live store's current state, used by both
// the pre-flight check and the sentinel resolution pass.
type liveSnapshot struct {
	routesByID    map[string]storage.Route
	usersByID     map[string]auth.User
	dnsByKey      map[string]storage.DNSProviderConfig
	fwdAuthByName map[string]storage.ForwardAuthProvider
	oidc          storage.OIDCConfig
	oidcExists    bool
}

func (ls *liveSnapshot) isFresh() bool {
	// "Fresh" per spec §5.3 pre-flight: zero users, zero DNS
	// providers, zero forward-auth providers, no OIDC config.
	// The routes count is intentionally not part of the freshness
	// check (operator can restore routes onto an instance where
	// they pre-created the admin via setup-token; that's not the
	// disaster-recovery failure mode this pre-flight catches).
	return len(ls.usersByID) == 0 &&
		len(ls.dnsByKey) == 0 &&
		len(ls.fwdAuthByName) == 0 &&
		!ls.oidcExists
}

func readLive(ctx context.Context, store Storer, users UserStorer) (*liveSnapshot, error) {
	ls := &liveSnapshot{
		routesByID:    map[string]storage.Route{},
		usersByID:     map[string]auth.User{},
		dnsByKey:      map[string]storage.DNSProviderConfig{},
		fwdAuthByName: map[string]storage.ForwardAuthProvider{},
	}
	routes, err := store.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		ls.routesByID[r.ID] = r
	}
	uList, err := users.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, u := range uList {
		ls.usersByID[u.ID] = u
	}
	// Task 1a transitional: the DNS provider collection is now
	// UUID-keyed. Index the live rows by their ID so per-provider
	// secret-sentinel resolution (below) matches the snapshot row's
	// own ID. Task 1e revisits backup for the full collection.
	dnsList, err := store.ListDNSProviders(ctx)
	if err != nil {
		return nil, err
	}
	for _, dns := range dnsList {
		ls.dnsByKey[dns.ID] = dns
	}
	fwd, err := store.ListForwardAuthProviders(ctx)
	if err != nil {
		return nil, err
	}
	for _, fp := range fwd {
		ls.fwdAuthByName[fp.Name] = fp
	}
	oidc, err := store.GetOIDCConfig(ctx)
	if err == nil {
		ls.oidc = oidc
		// "Exists" iff at least one field is set — a fresh-row
		// zero-valued OIDCConfig should not count as configured.
		ls.oidcExists = oidc.IssuerURL != "" || oidc.ClientID != "" || oidc.ClientSecret != "" || len(oidc.AllowedIdentities) > 0
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	return ls, nil
}

// resolveSentinels mutates a copy of the snapshot, replacing every
// SentinelLiteral with either the inherited live value (steady
// state) or the empty string + record-incomplete (AllowIncomplete
// case). Returns the mutated snapshot on success, or an
// *unresolvedSentinel error on the first unresolved sentinel when
// the operator has NOT opted into AllowIncompleteRestore.
func resolveSentinels(snap *Snapshot, live *liveSnapshot, opts ImportOptions, report *ImportReport) (*Snapshot, error) {
	// Work on a deep copy so a rejection leaves the caller's
	// snapshot untouched (defensive — Import doesn't reuse it,
	// but the property is cheap to guarantee).
	out := *snap
	out.Routes = append([]storage.Route(nil), snap.Routes...)
	out.Users = append([]auth.User(nil), snap.Users...)
	out.DNSProviders = append([]storage.DNSProviderConfig(nil), snap.DNSProviders...)
	out.ForwardAuthProviders = append([]storage.ForwardAuthProvider(nil), snap.ForwardAuthProviders...)
	out.OIDCConfig = snap.OIDCConfig

	resolve := func(entity, identity, field, current string, lookup func() (string, bool)) (string, error) {
		if current != SentinelLiteral {
			return current, nil
		}
		if inherited, ok := lookup(); ok && inherited != "" {
			report.SentinelsInheritedTotal++
			return inherited, nil
		}
		if !opts.AllowIncompleteRestore {
			return "", &unresolvedSentinel{Entity: entity, Identity: identity, Field: field}
		}
		report.SentinelsUnresolvedTotal++
		report.IncompleteRows = append(report.IncompleteRows, IncompleteRow{
			Entity: entity, Identity: identity, Field: field,
		})
		return "", nil
	}

	// Routes — basic_auth.password_hash
	for i := range out.Routes {
		r := &out.Routes[i]
		v, err := resolve("routes", r.ID, "basic_auth.password_hash", r.BasicAuth.PasswordHash, func() (string, bool) {
			if live, ok := live.routesByID[r.ID]; ok {
				return live.BasicAuth.PasswordHash, true
			}
			return "", false
		})
		if err != nil {
			return nil, err
		}
		r.BasicAuth.PasswordHash = v
	}

	// Users — password_hash
	for i := range out.Users {
		u := &out.Users[i]
		v, err := resolve("users", u.ID, "password_hash", u.PasswordHash, func() (string, bool) {
			if live, ok := live.usersByID[u.ID]; ok {
				return live.PasswordHash, true
			}
			return "", false
		})
		if err != nil {
			return nil, err
		}
		u.PasswordHash = v
	}

	// DNS providers — keyed by provider ID (UUID collection, Task 1a).
	for i := range out.DNSProviders {
		d := &out.DNSProviders[i]
		// Backward-compat (pre-v2.11 / pre-Task-1a): a singleton backup
		// carries one provider row with an EMPTY ID (and no Label/Type —
		// they didn't exist in the old struct). Promote it to a valid
		// collection entry HERE, before secret resolution, validation
		// (validateResolvedSnapshot) and marshalling (buildRestoreInput)
		// so all three agree on the same UUID key. We assign a fresh
		// UUID and default Label/Type to "OVH (default)"/"ovh" — mirroring
		// the boot migration (MigrateLegacyDNSProvider) so the imported
		// row is immediately usable, with no reliance on a second
		// migration pass. Note the resolve() identity below then records
		// the real UUID (not the literal "ovh"), keeping IncompleteRows
		// consistent with the stored key.
		if d.ID == "" {
			d.ID = uuid.NewString()
			if d.Label == "" {
				d.Label = "OVH (default)"
			}
			if d.Type == "" {
				d.Type = storage.DNSProviderTypeOVH
			}
		}
		liveDNS, ok := live.dnsByKey[d.ID]
		liveExists := ok
		ak, err := resolve("dns_providers", d.ID, "application_key", d.ApplicationKey, func() (string, bool) {
			if liveExists {
				return liveDNS.ApplicationKey, true
			}
			return "", false
		})
		if err != nil {
			return nil, err
		}
		d.ApplicationKey = ak
		as, err := resolve("dns_providers", d.ID, "application_secret", d.ApplicationSecret, func() (string, bool) {
			if liveExists {
				return liveDNS.ApplicationSecret, true
			}
			return "", false
		})
		if err != nil {
			return nil, err
		}
		d.ApplicationSecret = as
		ck, err := resolve("dns_providers", d.ID, "consumer_key", d.ConsumerKey, func() (string, bool) {
			if liveExists {
				return liveDNS.ConsumerKey, true
			}
			return "", false
		})
		if err != nil {
			return nil, err
		}
		d.ConsumerKey = ck
	}

	// Forward-auth providers — keyed by name.
	for i := range out.ForwardAuthProviders {
		p := &out.ForwardAuthProviders[i]
		v, err := resolve("forward_auth_providers", p.Name, "client_secret", p.ClientSecret, func() (string, bool) {
			if live, ok := live.fwdAuthByName[p.Name]; ok {
				return live.ClientSecret, true
			}
			return "", false
		})
		if err != nil {
			return nil, err
		}
		p.ClientSecret = v
	}

	// OIDC config — keyed by "default".
	v, err := resolve("oidc_config", "default", "client_secret", out.OIDCConfig.ClientSecret, func() (string, bool) {
		if live.oidcExists {
			return live.oidc.ClientSecret, true
		}
		return "", false
	})
	if err != nil {
		return nil, err
	}
	out.OIDCConfig.ClientSecret = v

	return &out, nil
}

// BuildRestoreInputFromSnapshot marshals a Snapshot into the
// storage-layer wire shape. Exported so the API handler can build
// a pre-restore "rollback snapshot" of the LIVE store and keep it
// in memory for the duration of the Caddy reload — if the reload
// fails, the handler re-applies this input via
// storage.RestoreSnapshot to undo the restore (Step K.3 §5.3 Q4
// rollback). Internal callers stay on buildRestoreInput; this is
// the boundary symbol for cross-package rollback.
//
// Pre-condition: the snapshot must already be free of sentinel
// literals — i.e. it was either built via Export(includeSecrets=true)
// or fully resolved by resolveSentinels. The function does NOT
// validate; the caller owns that.
func BuildRestoreInputFromSnapshot(snap *Snapshot) (storage.RestoreSnapshotInput, error) {
	return buildRestoreInput(snap)
}

// buildRestoreInput marshals each row of the resolved snapshot to
// JSON and assembles the storage.RestoreSnapshotInput. Marshal
// failures here are programmer errors (every type round-trips
// json.Marshal cleanly by construction), but we still propagate them
// rather than panic.
func buildRestoreInput(snap *Snapshot) (storage.RestoreSnapshotInput, error) {
	out := storage.RestoreSnapshotInput{
		Routes:               map[string][]byte{},
		Users:                map[string][]byte{},
		DNSProviders:         map[string][]byte{},
		ForwardAuthProviders: map[string][]byte{},
	}
	for _, r := range snap.Routes {
		b, err := json.Marshal(r)
		if err != nil {
			return out, fmt.Errorf("marshal route %q: %w", r.ID, err)
		}
		out.Routes[r.ID] = b
	}
	for _, u := range snap.Users {
		b, err := json.Marshal(u)
		if err != nil {
			return out, fmt.Errorf("marshal user %q: %w", u.ID, err)
		}
		out.Users[u.ID] = b
	}
	for _, d := range snap.DNSProviders {
		b, err := json.Marshal(d)
		if err != nil {
			return out, fmt.Errorf("marshal dns provider %q: %w", d.ID, err)
		}
		// Key by the provider's own UUID (v2.11 multi-config collection).
		// Pre-v2.11 rows with an empty ID are promoted to a fresh UUID in
		// resolveSentinels BEFORE this point, so d.ID is always non-empty
		// here for a resolved snapshot. The prior code re-keyed every row
		// under the fixed literal "ovh", collapsing a multi-provider
		// backup down to a single stored entry (data loss on restore).
		out.DNSProviders[d.ID] = b
	}
	for _, p := range snap.ForwardAuthProviders {
		b, err := json.Marshal(p)
		if err != nil {
			return out, fmt.Errorf("marshal forward-auth provider %q: %w", p.Name, err)
		}
		out.ForwardAuthProviders[p.Name] = b
	}
	if snap.OIDCConfig.IssuerURL != "" || snap.OIDCConfig.ClientID != "" || len(snap.OIDCConfig.AllowedIdentities) > 0 {
		b, err := json.Marshal(snap.OIDCConfig)
		if err != nil {
			return out, fmt.Errorf("marshal oidc config: %w", err)
		}
		out.OIDCConfig = b
	}
	return out, nil
}

// checkSchemaMajor enforces the spec §5.3 MAJOR-equal rule. MINOR
// and PATCH mismatches are accepted (forward-compat / backward-
// compat tolerance). An empty schema_version field is rejected —
// the export always sets it, so absence indicates a malformed file.
func checkSchemaMajor(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return &ErrSchemaMajorMismatch{FileVersion: "<missing>", BinaryVersion: SchemaMajor}
	}
	major, _, _ := strings.Cut(v, ".")
	if major != SchemaMajor {
		return &ErrSchemaMajorMismatch{FileVersion: v, BinaryVersion: SchemaMajor}
	}
	return nil
}

// IsUnresolvedSentinelError is the typed test/caller helper. Lets
// API handlers + tests differentiate the "two paths forward" reject
// from generic errors without string-matching.
func IsUnresolvedSentinelError(err error) bool {
	_, ok := isUnresolvedSentinel(err)
	return ok
}
