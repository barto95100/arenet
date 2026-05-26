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

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// validateResolvedSnapshot runs the business-invariant re-check on
// a snapshot whose sentinels have already been resolved (or cleared
// under AllowIncompleteRestore). The check exists because
// storage.RestoreSnapshot bypasses the domain validators that
// CreateRoute / UpdateUser / PutDNSProvider / PutOIDCConfig run on
// the live path — a snapshot that smuggles a malformed Route, an
// out-of-enum role, a forward_auth route pointing to a non-existent
// provider, or zero local admins post-restore must NOT be allowed
// to land in BoltDB.
//
// Dérogation surface for AllowIncompleteRestore (narrow, by design):
//   - routes[].basic_auth.password_hash    (cleared by the restore)
//   - users[].password_hash                (cleared by the restore)
//   - dns_providers[].application_key /
//     application_secret / consumer_key   (cleared by the restore)
//   - oidc_config.client_secret            (cleared by the restore)
//
// Only the specific (entity, identity, field) tuples recorded in
// report.IncompleteRows are granted the dérogation. Every other
// invariant — host present, upstream non-empty, role enum, username
// regex, forward-auth provider existence, dns-01 → DNS provider
// existence, post-state has at least one local admin — is enforced
// unconditionally.
//
// Cross-rules (provider must exist, dns-01 requires DNS provider)
// run against the snapshot's OWN set, NOT the live store — the
// live state is about to be replaced.
func validateResolvedSnapshot(snap *Snapshot, report *ImportReport, opts ImportOptions) error {
	cleared := buildClearedSet(report)

	if err := validateUsers(snap.Users, cleared); err != nil {
		return err
	}
	// Local-admin presence guard. AllowEmptyUsers is the operator's
	// explicit opt-in for "restore with zero users; boot setup-
	// token will recreate one" — that's the ONE legitimate case
	// for zero local admins post-restore. Any other case (non-
	// empty users but none of them local+admin) is the lockout
	// the guard protects against.
	if !(opts.AllowEmptyUsers && len(snap.Users) == 0) {
		if err := validateLocalAdminCount(snap.Users); err != nil {
			return err
		}
	}

	// forward_auth_providers — validate each. Their secrets are
	// allowed empty by the validator already, so no dérogation
	// keyword needed.
	fwdNames := map[string]bool{}
	for _, p := range snap.ForwardAuthProviders {
		if err := storage.ValidateForwardAuthProvider(p); err != nil {
			return fmt.Errorf("restore: forward_auth_provider %q: %w", p.Name, err)
		}
		fwdNames[p.Name] = true
	}

	// dns_providers — validate each, with the dérogation for
	// cleared secret triplets.
	dnsExists := false
	for _, d := range snap.DNSProviders {
		if err := validateDNSProviderWithDerogation(d, cleared); err != nil {
			return err
		}
		dnsExists = true
	}

	// routes — local validate + cross-rules.
	for _, r := range snap.Routes {
		if err := validateRouteWithDerogation(r, cleared); err != nil {
			return err
		}
		// Cross-rule: forward_auth route must reference a provider
		// that EXISTS in the snapshot's own forward-auth set.
		if r.AuthMode == "forward_auth" {
			if !fwdNames[r.ForwardAuth.ProviderName] {
				return fmt.Errorf("restore: route %q (id=%s) references forward-auth provider %q which is not in the snapshot's forward_auth_providers; the restored config would point at a missing provider",
					r.Host, r.ID, r.ForwardAuth.ProviderName)
			}
		}
		// Cross-rule: dns-01 route requires a DNS provider in the
		// snapshot. (HTTP-01 is the default and never requires one.)
		if r.ACMEChallenge == "dns-01" && !dnsExists {
			return fmt.Errorf("restore: route %q (id=%s) is configured for dns-01 ACME but the snapshot carries no DNS provider; certificates for this route would fail to issue",
				r.Host, r.ID)
		}
	}

	// oidc_config — validate when Enabled, with the dérogation for
	// a cleared client_secret.
	if err := validateOIDCWithDerogation(snap.OIDCConfig, cleared); err != nil {
		return err
	}

	_ = opts // reserved for future invariants
	return nil
}

// clearedSet is the dérogation registry. Keys are
// "entity|identity|field" so a lookup is exact. Only fields the
// resolver actually cleared (i.e. listed in report.IncompleteRows)
// are exempt; every other empty value is rejected by the validator.
type clearedSet map[string]struct{}

func (cs clearedSet) has(entity, identity, field string) bool {
	_, ok := cs[entity+"|"+identity+"|"+field]
	return ok
}

func buildClearedSet(report *ImportReport) clearedSet {
	cs := clearedSet{}
	for _, row := range report.IncompleteRows {
		cs[row.Entity+"|"+row.Identity+"|"+row.Field] = struct{}{}
	}
	return cs
}

// validateRouteWithDerogation runs ValidateRoute. When the route's
// basic_auth.password_hash was legitimately cleared (entry in
// cleared set), the validator's "password_hash non-empty when
// auth_mode=basic" check is bypassed by substituting a placeholder
// only for the validation call — the actual storage write still
// carries an empty hash, which is the intended incomplete-restore
// state.
func validateRouteWithDerogation(r storage.Route, cleared clearedSet) error {
	if r.AuthMode == "basic" &&
		r.BasicAuth.PasswordHash == "" &&
		cleared.has("routes", r.ID, "basic_auth.password_hash") {
		// Temporary placeholder ONLY for the validate() call —
		// the in-memory Route copy stays cleared.
		probe := r
		probe.BasicAuth.PasswordHash = "incomplete-restore-placeholder"
		if err := storage.ValidateRoute(probe); err != nil {
			return fmt.Errorf("restore: route %q (id=%s): %w", r.Host, r.ID, err)
		}
		return nil
	}
	if err := storage.ValidateRoute(r); err != nil {
		return fmt.Errorf("restore: route %q (id=%s): %w", r.Host, r.ID, err)
	}
	return nil
}

func validateDNSProviderWithDerogation(d storage.DNSProviderConfig, cleared clearedSet) error {
	// Three secret fields; any of them may be in the cleared set.
	probe := d
	clearedAny := false
	if d.ApplicationKey == "" && cleared.has("dns_providers", "ovh", "application_key") {
		probe.ApplicationKey = "incomplete-restore-placeholder"
		clearedAny = true
	}
	if d.ApplicationSecret == "" && cleared.has("dns_providers", "ovh", "application_secret") {
		probe.ApplicationSecret = "incomplete-restore-placeholder"
		clearedAny = true
	}
	if d.ConsumerKey == "" && cleared.has("dns_providers", "ovh", "consumer_key") {
		probe.ConsumerKey = "incomplete-restore-placeholder"
		clearedAny = true
	}
	target := d
	if clearedAny {
		target = probe
	}
	if err := storage.ValidateDNSProvider(target); err != nil {
		return fmt.Errorf("restore: dns_provider (ovh): %w", err)
	}
	return nil
}

func validateOIDCWithDerogation(c storage.OIDCConfig, cleared clearedSet) error {
	if !c.Enabled {
		// Disabled config is exempt from non-empty checks per the
		// existing OIDCConfig.validate semantics.
		return storage.ValidateOIDCConfig(c)
	}
	probe := c
	if c.ClientSecret == "" && cleared.has("oidc_config", "default", "client_secret") {
		probe.ClientSecret = "incomplete-restore-placeholder"
		if err := storage.ValidateOIDCConfig(probe); err != nil {
			return fmt.Errorf("restore: oidc_config: %w", err)
		}
		return nil
	}
	if err := storage.ValidateOIDCConfig(c); err != nil {
		return fmt.Errorf("restore: oidc_config: %w", err)
	}
	return nil
}

func validateUsers(users []auth.User, cleared clearedSet) error {
	seenIDs := map[string]bool{}
	seenUsernames := map[string]bool{}
	for i, u := range users {
		if seenIDs[u.ID] {
			return fmt.Errorf("restore: users[%d]: duplicate id %q in snapshot", i, u.ID)
		}
		seenIDs[u.ID] = true
		if seenUsernames[u.Username] {
			return fmt.Errorf("restore: users[%d]: duplicate username %q in snapshot", i, u.Username)
		}
		seenUsernames[u.Username] = true
		allowEmpty := u.AuthSource == auth.UserAuthSourceLocal &&
			u.PasswordHash == "" &&
			cleared.has("users", u.ID, "password_hash")
		if err := auth.ValidateUserForRestore(u, allowEmpty); err != nil {
			return fmt.Errorf("restore: %w", err)
		}
	}
	return nil
}

// validateLocalAdminCount is the restore-time mirror of the K.2
// last-LOCAL-admin guard. A snapshot whose post-restore state has
// zero LOCAL admins would lock the operator out (an OIDC-only
// admin can't break in if the IdP is down — the break-glass
// invariant requires at least one local admin). Rejected
// unconditionally; the operator must edit the snapshot before
// restoring it.
func validateLocalAdminCount(users []auth.User) error {
	for _, u := range users {
		if u.AuthSource == auth.UserAuthSourceLocal && u.Role == auth.UserRoleAdmin {
			return nil
		}
	}
	return ErrNoLocalAdmin
}

// ErrNoLocalAdmin is the dedicated rejection for a restored state
// that would leave the instance with no LOCAL admin. The break-
// glass invariant (§1.3 #4-6) demands at least one.
var ErrNoLocalAdmin = errors.New(
	"restore: the snapshot's users list does not contain any local admin — restoring would lock the operator out of the break-glass channel.\n\n" +
		"Two paths forward:\n" +
		" (a) Edit the export file to ensure at least one user has\n" +
		"     auth_source=\"local\" AND role=\"admin\".\n" +
		" (b) If you intend a fresh setup, restore via the CLI with\n" +
		"     --allow-empty-users so the next boot re-triggers the\n" +
		"     setup-token flow.",
)
