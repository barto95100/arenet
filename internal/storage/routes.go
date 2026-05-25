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
	"sort"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// Step J.1 load-balancing policies. Exposed as constants so the API
// validation layer and the Caddy generator share a single source of
// truth (no string typos drift). The order mirrors §1.3 decision 2.
const (
	LBPolicyRoundRobin         = "round_robin"
	LBPolicyWeightedRoundRobin = "weighted_round_robin"
	LBPolicyLeastConn          = "least_conn"
	LBPolicyIPHash             = "ip_hash"
	LBPolicyRandom             = "random"
	LBPolicyFirst              = "first"
)

// LBPolicies is the canonical ordered list of allowed LBPolicy values.
// Used by validate() and by the API enum check. Order matches the
// constants above and §1.3 decision 2.
var LBPolicies = []string{
	LBPolicyRoundRobin,
	LBPolicyWeightedRoundRobin,
	LBPolicyLeastConn,
	LBPolicyIPHash,
	LBPolicyRandom,
	LBPolicyFirst,
}

// Upstream is one backend in a Route's upstream pool (Step J.1).
//
// The pool replaces the pre-J.1 single Route.UpstreamURL string. Each
// Upstream carries the dial URL and a Weight; Weight defaults to 1 and
// is consulted only by the weighted_round_robin LB policy — other
// policies ignore it (§1.3 decision 1, §5.1).
type Upstream struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// Route is a proxied virtual host served by Arenet.
type Route struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	// Upstreams (Step J.1) is the pool of backends this route fans
	// traffic to. At least one element; created with one element by
	// the migrateUpstreamURLToPool boot migration for pre-J.1 rows.
	// The pre-J.1 UpstreamURL string field is gone — its value lives
	// at Upstreams[0].URL after migration. See spec §5.1, §6.1.
	Upstreams []Upstream `json:"upstreams"`
	// LBPolicy (Step J.1) is the load-balancing selection policy
	// Caddy applies across Upstreams. One of: round_robin (default),
	// weighted_round_robin, least_conn, ip_hash, random, first.
	// Materialised at create time and by the boot migration; never
	// empty post-J.1 (§5.1, §1.3 decision 2).
	LBPolicy   string `json:"lb_policy"`
	TLSEnabled bool   `json:"tls_enabled"`
	// RedirectToHTTPS (Step I.1, used by I.2) requests Caddy to
	// emit a 301 from http://<host>/* to https://<host>/* when the
	// matching route has TLSEnabled=true. Zero value is false: pre-
	// Step-I.1 routes silently keep the no-redirect behavior. The
	// wire JSON below this struct uses camelCase to match the API
	// shape; storage tags use snake_case for legacy reasons.
	RedirectToHTTPS bool `json:"redirect_to_https"`
	// Aliases (Step I.3) are additional hostnames served by the
	// SAME upstream. Caddy matches any of (Host ∪ Aliases) for this
	// route, and ACME issues a single multi-SAN cert covering them
	// all. Stored as a JSON array; pre-Step-I.3 routes decode with
	// a nil slice (zero value), which is treated identically to an
	// empty slice everywhere downstream.
	Aliases []string `json:"aliases"`
	// BasicAuthEnabled (Step I.5) gates HTTP Basic Auth on this
	// route. When true, BasicAuthUsername and BasicAuthPasswordHash
	// must be set; Caddy emits the `authentication` handler before
	// the proxy chain, returning 401 on missing / wrong credentials.
	BasicAuthEnabled  bool   `json:"basic_auth_enabled"`
	BasicAuthUsername string `json:"basic_auth_username"`
	// BasicAuthPasswordHash is an argon2id PHC string. NEVER exposed
	// over the API (the response surface uses a derived
	// BasicAuthPasswordSet bool instead) and NEVER embedded in
	// audit events (see routeForAudit in internal/api/routes.go).
	BasicAuthPasswordHash string `json:"basic_auth_password_hash"`
	// RequestHeaders (Step I.6) are key/value pairs set on the
	// proxied request before it reaches the upstream; ResponseHeaders
	// are set on the response before it reaches the client. Both
	// default nil; the API layer normalizes nil → {} on the wire so
	// frontend callers can iterate without a null check. Validation
	// (RFC 7230 token name, CR/LF-free value, hop-by-hop blacklist)
	// lives in internal/api/routes.go — storage trusts the API.
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	// WAFMode (Step I.4) replaces the pre-I.4 WAFEnabled bool with a
	// three-valued enum: "off" / "detect" / "block".
	//   - off    : no WAF inspection, no Caddy handler emitted.
	//   - detect : Coraza inspects, logs matches, lets traffic pass
	//              (SecRuleEngine DetectionOnly — FortiWeb-style
	//              safe shadow mode; recommended starting point).
	//   - block  : Coraza inspects and returns 403 on match
	//              (SecRuleEngine On).
	// Pre-I.4 routes with WAFEnabled=true are migrated to "block"
	// (semantic equivalent of "block on every detection"); WAFEnabled=
	// false routes are migrated to "off". See migrateWAFEnabledToWAFMode.
	WAFMode   string    `json:"waf_mode"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AllHosts returns the full ordered list of hostnames this route
// answers to: [Host, Aliases...]. The primary Host always comes
// first so callers that need a deterministic ordering (Caddy
// match.host, ACME subjects, audit log) get a stable shape.
func (r Route) AllHosts() []string {
	out := make([]string, 0, 1+len(r.Aliases))
	out = append(out, r.Host)
	out = append(out, r.Aliases...)
	return out
}

// validate checks the user-supplied fields of a Route.
func (r *Route) validate() error {
	if r.Host == "" {
		return errors.New("route: host must not be empty")
	}
	// Step J.1: upstream pool must contain at least one element, each
	// with a non-empty URL and a strictly positive weight. The API
	// layer validates the URL shape (http/https scheme, non-empty
	// host) earlier with friendlier messages; storage's job is to
	// reject obviously inconsistent rows that bypass the API.
	if len(r.Upstreams) == 0 {
		return errors.New("route: upstreams must contain at least one entry")
	}
	for i, u := range r.Upstreams {
		if u.URL == "" {
			return fmt.Errorf("route: upstreams[%d].url must not be empty", i)
		}
		if u.Weight < 1 {
			return fmt.Errorf("route: upstreams[%d].weight must be >= 1", i)
		}
	}
	// Step J.1: LBPolicy must be one of the six enum values. Empty is
	// rejected here because the API layer is responsible for
	// materialising the default (round_robin) before validation runs;
	// a row reaching storage with an empty LBPolicy is a programming
	// error, not a user-input case.
	{
		ok := false
		for _, p := range LBPolicies {
			if r.LBPolicy == p {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("route: lb_policy %q is not a valid policy", r.LBPolicy)
		}
	}
	// Step I.3: intra-route alias rules. Storage is the last line
	// of defense; the API layer also enforces these so the user
	// gets a 400 with a friendlier message. Keeping the check here
	// guarantees that any direct CreateRoute / UpdateRoute call
	// (tests, future internal callers) cannot smuggle a malformed
	// alias set into BoltDB.
	seen := make(map[string]struct{}, len(r.Aliases))
	for _, a := range r.Aliases {
		if a == "" {
			return errors.New("route: alias must not be empty")
		}
		if a == r.Host {
			return fmt.Errorf("route: alias %q duplicates the primary host", a)
		}
		if _, dup := seen[a]; dup {
			return fmt.Errorf("route: alias %q duplicates within the same route", a)
		}
		seen[a] = struct{}{}
	}
	// Step I.5: enabling Basic Auth requires both a non-empty
	// username and a hash. The API layer enforces these earlier
	// with friendlier messages (and triggers the hash computation);
	// storage's job is to reject obviously inconsistent rows that
	// bypass the API (tests, future internal callers).
	if r.BasicAuthEnabled {
		if r.BasicAuthUsername == "" {
			return errors.New("route: basic_auth_username must not be empty when basic auth is enabled")
		}
		if r.BasicAuthPasswordHash == "" {
			return errors.New("route: basic_auth_password_hash must not be empty when basic auth is enabled")
		}
	}
	return nil
}

// CreateRoute persists a new Route. The ID, CreatedAt and UpdatedAt fields
// are assigned by the store and the populated Route is returned.
func (s *Store) CreateRoute(ctx context.Context, r Route) (Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := r.validate(); err != nil {
		return Route{}, err
	}

	now := time.Now().UTC()
	r.ID = uuid.NewString()
	r.CreatedAt = now
	r.UpdatedAt = now

	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketRoutes))
		buf, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal route: %w", err)
		}
		return b.Put([]byte(r.ID), buf)
	}); err != nil {
		return Route{}, err
	}
	return r, nil
}

// GetRoute returns the Route identified by id, or ErrNotFound.
func (s *Store) GetRoute(ctx context.Context, id string) (Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return Route{}, errors.New("route: id must not be empty")
	}

	var out Route
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketRoutes)).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return Route{}, err
	}
	return out, nil
}

// ListRoutes returns all stored routes, sorted by CreatedAt ascending.
func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out []Route
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketRoutes)).ForEach(func(_, v []byte) error {
			var r Route
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("unmarshal route: %w", err)
			}
			out = append(out, r)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// UpdateRoute replaces an existing Route. The CreatedAt timestamp is preserved
// from the stored record and UpdatedAt is refreshed.
func (s *Store) UpdateRoute(ctx context.Context, r Route) (Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if r.ID == "" {
		return Route{}, errors.New("route: id must not be empty")
	}
	if err := r.validate(); err != nil {
		return Route{}, err
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketRoutes))
		raw := b.Get([]byte(r.ID))
		if raw == nil {
			return ErrNotFound
		}
		var existing Route
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("unmarshal existing route: %w", err)
		}
		r.CreatedAt = existing.CreatedAt
		r.UpdatedAt = time.Now().UTC()
		buf, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal route: %w", err)
		}
		return b.Put([]byte(r.ID), buf)
	})
	if err != nil {
		return Route{}, err
	}
	return r, nil
}

// DeleteRoute removes the Route identified by id. Returns ErrNotFound if it
// does not exist.
func (s *Store) DeleteRoute(ctx context.Context, id string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return errors.New("route: id must not be empty")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketRoutes))
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}

// RestoreRoute re-inserts an existing Route exactly as supplied, preserving
// the provided ID, CreatedAt and UpdatedAt timestamps.
//
// This method exists ONLY for the rollback path of internal/api when a Caddy
// reload fails after a DELETE. It bypasses the normal CreateRoute lifecycle
// (no UUID generation, no timestamp refresh) precisely to make rollback
// fidelity possible. Do NOT use it for business logic — use CreateRoute or
// UpdateRoute.
//
// RestoreRoute is an unconditional upsert: if the key already exists it is
// overwritten without error. By design, the rollback always wins the
// conflict — this is safe under the current single-writer flow (bbolt
// serialises writes and the HTTP handler processes mutations sequentially).
// Revisit if real concurrency on routes is introduced later.
func (s *Store) RestoreRoute(ctx context.Context, r Route) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if r.ID == "" {
		return errors.New("route: id must not be empty")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		buf, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal route: %w", err)
		}
		return tx.Bucket([]byte(bucketRoutes)).Put([]byte(r.ID), buf)
	})
}
