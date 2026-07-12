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

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Step O.1 — managed-domain declaration for wildcard certificate
// management. One row per apex (e.g. "example.com"); multiple rows
// coexist per spec D6.A. Operator declares an apex → caddymgr emits
// ONE TLS policy for `*.<apex>` (and optionally the bare apex per
// IncludeApex / spec D2.C), covering every route whose host is
// `<single-label>.<apex>`.
//
// The ProviderID field references a DNSProviderConfig by its UUID
// (spec v2.11 multi-config). Empty means "no provider assigned"
// (the wildcard falls back to the internal CA); a non-empty value
// is validated for existence at the API layer, not in storage.
//
// SECRECY: this struct holds NO secrets. The DNS provider
// credentials it references live in DNSProviderConfig (keyed by
// its UUID) — fetched separately by caddymgr at config-build
// time. So the audit and API layers can echo ManagedDomain rows
// verbatim without redaction.
type ManagedDomain struct {
	// Apex is the registered base domain (e.g. "example.com"). NOT
	// the wildcard form (`*.example.com`) — the wildcard is implied
	// by the very concept of a managed domain. Validation rejects
	// leading "*." and forces lowercase + trailing-dot stripping
	// (DNS is case-insensitive, trailing-dot canonical form per
	// RFC 1035).
	Apex string `json:"apex"`
	// IncludeApex (spec D2.C) toggles whether the emitted cert
	// covers BOTH `*.<apex>` AND `<apex>` (true → multi-SAN cert,
	// 2 DNS-01 challenges during issuance) or just `*.<apex>`
	// (false → single-SAN cert, 1 challenge). Default true at the
	// API layer because most homelab operators have a landing
	// page on the apex.
	IncludeApex bool `json:"include_apex"`
	// ProviderID references the DNSProviderConfig.ID whose credentials
	// caddymgr uses for the DNS-01 challenge. Empty means "no provider
	// assigned" (wildcard falls back to the internal CA). Replaces the
	// pre-v2.11 `Provider` (a type string); the boot migration repoints
	// legacy "ovh" values to the migrated config's UUID. Existence of a
	// non-empty ProviderID is validated at the API layer against
	// GetDNSProvider — storage stays referential-integrity-free.
	ProviderID string `json:"provider_id"`
}

// managedDomainApexRE is a pragmatic RFC 1123 hostname check for
// the apex form: dot-separated labels, each 1-63 chars of alnum
// + dash, must start and end with alnum. Single-label TLDs (e.g.
// "lan", "test") are accepted because the homelab `.lan` / `.test`
// apex use-case is real and ACME with a real cert is impossible
// for those anyway — the cert flow will fall back to internal CA
// for non-public apex, but the managed-domain declaration is still
// useful for the inheritance + UI surface.
//
// Rejects leading "*." (the wildcard form is implied by the
// managed-domain concept; storing it would be redundant and would
// open a bug surface where the predicate strips it inconsistently).
var managedDomainApexRE = regexp.MustCompile(
	`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`,
)

// NormalizeApex canonicalises an apex for storage + lookup: strip
// the trailing dot (RFC 1035 canonical form), lowercase. Pure
// function. Used by the validator AND by the §3.2 coverage
// predicate so a route host like `App.Example.Com.` matches a
// stored apex `example.com`.
func NormalizeApex(apex string) string {
	return strings.ToLower(strings.TrimSuffix(apex, "."))
}

// ValidateManagedDomain is the exported shim — internal/backup
// re-validates a snapshot's managed domains before commit. Same
// pattern as ValidateDNSProvider.
func ValidateManagedDomain(md ManagedDomain) error {
	return md.validate()
}

func (md *ManagedDomain) validate() error {
	if md.Apex == "" {
		return errors.New("managed_domain: apex must not be empty")
	}
	// Reject the wildcard form — the wildcard is implied. An
	// operator who pastes `*.example.com` here would otherwise
	// silently get a managed domain for the literal `*.example.com`
	// apex, which is meaningless.
	if strings.HasPrefix(md.Apex, "*.") {
		return errors.New(`managed_domain: apex must be the bare domain (e.g. "example.com"), not the wildcard form ("*.example.com")`)
	}
	// The validator does NOT mutate the input; the API layer
	// is expected to call NormalizeApex BEFORE the storage write
	// so the canonical form is what lands on disk. Storage's
	// role is the last-line-of-defence shape check.
	if md.Apex != NormalizeApex(md.Apex) {
		return fmt.Errorf("managed_domain: apex %q is not in canonical form (lowercase, no trailing dot)", md.Apex)
	}
	if !managedDomainApexRE.MatchString(md.Apex) {
		return fmt.Errorf("managed_domain: apex %q is not a valid RFC 1123 hostname", md.Apex)
	}
	// ProviderID may be empty (unassigned → internal CA fallback) OR
	// any non-empty string. Existence against the DNSProviderConfig
	// collection is validated at the API layer (GetDNSProvider), not
	// here — storage stays referential-integrity-free like the rest
	// of the bucket layer.
	return nil
}

// GetManagedDomain returns the persisted managed-domain row for
// the given apex. Apex is normalised on the way in so callers
// don't need to pre-canonicalise. Returns ErrNotFound when no
// row exists — callers MUST distinguish that case from a real
// I/O error (same posture as GetDNSProvider).
func (s *Store) GetManagedDomain(ctx context.Context, apex string) (ManagedDomain, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	key := NormalizeApex(apex)
	var out ManagedDomain
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketManagedDomains))
		raw := b.Get([]byte(key))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return ManagedDomain{}, err
	}
	return out, nil
}

// ListManagedDomains returns all managed domains, lexicographically
// ordered by apex (BoltDB's natural key order). Empty list on a
// fresh install — never returns ErrNotFound (mirror of
// ListRoutes / ListForwardAuthProviders).
func (s *Store) ListManagedDomains(ctx context.Context) ([]ManagedDomain, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out []ManagedDomain
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketManagedDomains))
		return b.ForEach(func(_, raw []byte) error {
			var md ManagedDomain
			if err := json.Unmarshal(raw, &md); err != nil {
				return fmt.Errorf("unmarshal managed_domain: %w", err)
			}
			out = append(out, md)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PutManagedDomain persists a managed-domain row. Validates the
// input (last-line-of-defence shape check); the API layer is
// expected to have already normalised the apex (NormalizeApex)
// and resolved cross-rules (no overlap with an existing managed
// domain — spec D6 + §5 risks "multi-domain overlap" row) before
// reaching here. The route-side ACMEChallenge → "inherited"
// mutation that spec D8.A requires is the API layer's
// responsibility and runs in the SAME transaction as this Put
// (see PutManagedDomainWithRouteMigration below).
//
// Upsert semantics: an existing row for the same apex is
// overwritten. The route-side migration only runs at API-layer
// orchestration time, NOT inside this raw Put.
func (s *Store) PutManagedDomain(ctx context.Context, md ManagedDomain) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := md.validate(); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		buf, err := json.Marshal(md)
		if err != nil {
			return fmt.Errorf("marshal managed_domain: %w", err)
		}
		return tx.Bucket([]byte(bucketManagedDomains)).Put([]byte(md.Apex), buf)
	})
}

// DeleteManagedDomain removes the managed-domain row for the
// given apex. Idempotent — returns nil if the row is already
// absent (operator hitting the Delete button twice in quick
// succession should not see an error). The reverse route-side
// migration (ACMEChallenge "inherited" → "") is the API
// layer's responsibility, same transaction-discipline as the
// create path.
func (s *Store) DeleteManagedDomain(ctx context.Context, apex string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	key := NormalizeApex(apex)
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketManagedDomains))
		if b.Get([]byte(key)) == nil {
			return nil
		}
		return b.Delete([]byte(key))
	})
}

// --- Convention: ACMEChallenge="" semantics across managed-domain lifecycle ---
//
// The empty string in Route.ACMEChallenge is a J-era contract
// that this step PRESERVES: validate() accepts "" as input,
// and the API + Caddy-config generator both treat "" as
// equivalent to "http-01". A POST /routes with the field
// omitted is a valid route on the HTTP-01 path. That contract
// pre-dates Step O and must not change — flipping "" to
// "uninitialized requires operator action" would break every
// existing route fixture, every J-era backup snapshot, and
// the entire on-boarding path where a new operator creates a
// route without ever touching the ACME section.
//
// Therefore, in this package, "" ALWAYS means "use project
// default → HTTP-01". The validator never rejects it, the
// generator never errors on it, and the route is operable
// the moment it's persisted.
//
// Consequence for the managed-domain reverse path
// (DeleteManagedDomainWithRouteMigration below): a covered
// route whose ACMEChallenge was "inherited" reverts to "" on
// managed-domain delete. That's a CLEAN revert at the storage
// layer (the row is valid, the route is operable), but it
// does mean the next caddymgr reload triggers a fresh
// per-route HTTP-01 challenge for every revert-affected
// route — exactly the rate-limit footgun this step exists
// to prevent.
//
// The mitigation is at the O.3 API layer, NOT here: the
// DELETE /settings/managed-domains/{apex} endpoint will
// expose an explicit `revertTo` query parameter (one of
// "", "http-01", "dns-01") and the O.4 frontend will surface
// a confirm-dialog warning ("This will trigger N HTTP-01
// challenges. Continue?") before calling DELETE. The storage
// layer stays semantically simple; the operator decision is
// surfaced where it makes sense to surface it.
//
// If a future step changes the routes.go validator to
// distinguish "" (project default) from a new explicit
// "uninitialized" sentinel — for instance to force
// post-revert routes into a "needs attention" UI state
// instead of silently re-challenging — that's a J-contract
// migration, NOT an O-spec change. Acceptable; out of scope
// here.

// PutManagedDomainWithRouteMigration is the atomic API-layer
// helper that wraps the spec D8.A invariant: PUT a managed
// domain AND mutate every covered route's ACMEChallenge to
// "inherited" in ONE BoltDB transaction. A crash mid-tx
// rolls back cleanly (no partial state).
//
// The coverage predicate is injected as `isCovered` so this
// function stays storage-pure (no caddymgr import — that
// would invert the existing storage → caddymgr direction).
// Callers (api/managed_domain_handlers.go) pass
// caddymgr.IsHostCoveredByManagedDomain bound to the new md.
//
// Returns the number of routes mutated, for the audit event.
func (s *Store) PutManagedDomainWithRouteMigration(
	ctx context.Context,
	md ManagedDomain,
	isCovered func(host string) bool,
) (int, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := md.validate(); err != nil {
		return 0, err
	}
	var mutated int
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Write the managed-domain row first so a downstream
		// route migration that needs to read the new row from
		// disk would see it. (We pass isCovered as a closure
		// so this isn't strictly necessary, but it keeps the
		// tx order consistent with the operator mental model:
		// "the managed domain exists; the covered routes
		// inherit from it".)
		buf, err := json.Marshal(md)
		if err != nil {
			return fmt.Errorf("marshal managed_domain: %w", err)
		}
		if err := tx.Bucket([]byte(bucketManagedDomains)).Put([]byte(md.Apex), buf); err != nil {
			return err
		}
		// Iterate every route in the routes bucket; if its
		// primary host or any alias is covered AND the route
		// is NOT opting out via UseDedicatedCert, mutate
		// ACMEChallenge → "inherited" and persist.
		rb := tx.Bucket([]byte(bucketRoutes))
		return rb.ForEach(func(k, raw []byte) error {
			var r Route
			if err := json.Unmarshal(raw, &r); err != nil {
				return fmt.Errorf("unmarshal route %q: %w", string(k), err)
			}
			if r.UseDedicatedCert {
				return nil
			}
			hit := false
			for _, h := range r.AllHosts() {
				if isCovered(h) {
					hit = true
					break
				}
			}
			if !hit {
				return nil
			}
			if r.ACMEChallenge == ACMEChallengeInherited {
				// Already in the right state — idempotent
				// re-run (e.g. operator PUTs the same
				// managed domain twice) leaves the row
				// untouched, avoiding a write tx amplifier.
				return nil
			}
			r.ACMEChallenge = ACMEChallengeInherited
			r.UpdatedAt = time.Now().UTC()
			newRaw, err := json.Marshal(r)
			if err != nil {
				return fmt.Errorf("marshal route %q: %w", string(k), err)
			}
			if err := rb.Put(k, newRaw); err != nil {
				return err
			}
			mutated++
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	return mutated, nil
}

// DeleteManagedDomainWithRouteMigration is the atomic API-layer
// helper for the reverse path: DELETE a managed domain AND
// revert every covered route's ACMEChallenge from "inherited"
// back to "" (the J-era default → HTTP-01) in ONE transaction.
// Routes whose ACMEChallenge is not "inherited" are left
// untouched (operator may have manually overridden via the
// per-route opt-out at some earlier point).
//
// Thin wrapper around DeleteManagedDomainWithRouteMigrationRevertTo
// with revertTo="". Kept as a separate entry point so existing
// O.1 unit tests and any caller that wants the default revert
// behaviour stay terse.
func (s *Store) DeleteManagedDomainWithRouteMigration(
	ctx context.Context,
	apex string,
	isCovered func(host string) bool,
) (int, error) {
	return s.DeleteManagedDomainWithRouteMigrationRevertTo(ctx, apex, isCovered, "")
}

// DeleteManagedDomainWithRouteMigrationRevertTo is the
// parameterised version of the reverse migration. revertTo
// MUST be one of {"", "http-01", "dns-01"} — the caller (api
// layer) validates this BEFORE invocation. Storage defensively
// trusts the input enum here; an unknown value would land in
// the route's ACMEChallenge and the route validator would
// reject it on the next round-trip (defence-in-depth, not the
// front-line gate).
//
// The revertTo value is what the covered routes' ACMEChallenge
// is set to (instead of the default ""). Spec AC #21: the API
// layer exposes this on DELETE /settings/managed-domains/{apex}
// via a `?revertTo=` query parameter so the operator explicitly
// chooses the post-revert behaviour (avoids the silent
// HTTP-01-burst footgun called out in spec §3.8).
func (s *Store) DeleteManagedDomainWithRouteMigrationRevertTo(
	ctx context.Context,
	apex string,
	isCovered func(host string) bool,
	revertTo string,
) (int, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	key := NormalizeApex(apex)
	var mutated int
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketManagedDomains))
		if b.Get([]byte(key)) == nil {
			return ErrNotFound
		}
		if err := b.Delete([]byte(key)); err != nil {
			return err
		}
		rb := tx.Bucket([]byte(bucketRoutes))
		return rb.ForEach(func(k, raw []byte) error {
			var r Route
			if err := json.Unmarshal(raw, &r); err != nil {
				return fmt.Errorf("unmarshal route %q: %w", string(k), err)
			}
			if r.ACMEChallenge != ACMEChallengeInherited {
				return nil
			}
			hit := false
			for _, h := range r.AllHosts() {
				if isCovered(h) {
					hit = true
					break
				}
			}
			if !hit {
				return nil
			}
			r.ACMEChallenge = revertTo
			r.UpdatedAt = time.Now().UTC()
			newRaw, err := json.Marshal(r)
			if err != nil {
				return fmt.Errorf("marshal route %q: %w", string(k), err)
			}
			if err := rb.Put(k, newRaw); err != nil {
				return err
			}
			mutated++
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	return mutated, nil
}
