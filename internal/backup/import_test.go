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
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// Step K.3 backup/restore tests — the security-critical surfaces
// per spec §5.3:
//
//   * "Never silent" — every failure path has an actionable error
//     message; the engine never falls back to a silent partial
//     restore.
//   * Sentinel discipline — preserve-on-ID-match; unresolved
//     sentinels reject the whole import unless --allow-incomplete-
//     restore is set; the literal sentinel is NEVER written into a
//     target field.
//   * All-or-nothing — any single failure rolls the whole
//     transaction back; the BoltDB remains in the pre-restore state.
//   * Pre-flight — disaster-recovery scenario (fresh target +
//     no-secrets import) aborts BEFORE any write hits BoltDB.
//
// Each test that pins one of these invariants carries a named
// anti-regression assertion (NEVER SILENT, SENTINEL LEAK,
// ALL-OR-NOTHING REGRESSION, PRE-FLIGHT BYPASS REGRESSION) — these
// are NOT decorative. If one fires, an auth-bypass-class bug has
// shipped.

func newTestStoreWithUserStore(t *testing.T) (*storage.Store, *auth.UserStore) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, auth.NewUserStore(store.DB())
}

// seedLiveRoute creates a route with a Basic Auth password hash so
// the sentinel-inheritance tests have a target row to inherit from.
func seedLiveRoute(t *testing.T, store *storage.Store, host string) storage.Route {
	t.Helper()
	r, err := store.CreateRoute(context.Background(), storage.Route{
		Host: host,
		Upstreams: []storage.Upstream{
			{URL: "http://127.0.0.1:9000", Weight: 1},
		},
		LBPolicy:  storage.LBPolicyRoundRobin,
		AuthMode:  "basic",
		BasicAuth: storage.BasicAuthRouteConfig{Username: "admin", PasswordHash: "$argon2id$live-route-hash"},
		WAFMode:   "off",
	})
	if err != nil {
		t.Fatalf("seed route: %v", err)
	}
	return r
}

// seedLiveUser creates a user via the UserStore (which does its own
// argon2id hashing). Returns the persisted User.
func seedLiveUser(t *testing.T, us *auth.UserStore, username, password string) auth.User {
	t.Helper()
	u, err := us.Create(context.Background(), username, username, "", password)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

// ============================================================
// (1) Schema major version mismatch
// ============================================================

func TestImport_SchemaMajorMismatch_Rejected(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	snap := minimalSnapshot()
	snap.SchemaVersion = "2.0.0" // major != "1"

	_, err := Import(context.Background(), store, us, snap, ImportOptions{AllowEmptyUsers: true})
	if err == nil {
		t.Fatal("expected schema major mismatch rejection")
	}
	var se *ErrSchemaMajorMismatch
	if !errors.As(err, &se) {
		t.Fatalf("expected *ErrSchemaMajorMismatch, got %T: %v", err, err)
	}
	if se.FileVersion != "2.0.0" || se.BinaryVersion != "1" {
		t.Errorf("wrong versions in error: %v", se)
	}
}

func TestImport_SchemaMinorPatch_Accepted(t *testing.T) {
	// Minor / patch drift is accepted (forward-compat).
	store, us := newTestStoreWithUserStore(t)
	snap := minimalSnapshot()
	snap.SchemaVersion = "1.99.42"
	snap.Users = []auth.User{seedFakeUser("u-1", "$argon2id$..hash..")}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if err != nil {
		t.Fatalf("minor/patch drift should be accepted, got: %v", err)
	}
}

// ============================================================
// (2) Empty users guard — AC #15 / §1.6 Δ5
// ============================================================

func TestImport_EmptyUsers_Rejected(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	snap := minimalSnapshot()
	snap.Users = []auth.User{} // no users at all
	snap.SecretsIncluded = true

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if !errors.Is(err, ErrEmptyUsers) {
		t.Fatalf("LOCKOUT REGRESSION: expected ErrEmptyUsers, got %v", err)
	}
}

func TestImport_EmptyUsers_AllowEmptyUsersBypass(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	snap := minimalSnapshot()
	snap.Users = []auth.User{}
	snap.SecretsIncluded = true

	_, err := Import(context.Background(), store, us, snap, ImportOptions{AllowEmptyUsers: true})
	if err != nil {
		t.Fatalf("--allow-empty-users should bypass, got: %v", err)
	}
}

// ============================================================
// (3) Disaster-recovery pre-flight — AC #14bis
// ============================================================

// TestImport_PreflightDisasterRecovery_FreshTargetFailsLoud is the
// PRE-FLIGHT BYPASS REGRESSION pin: importing a no-secrets export
// onto a truly fresh target MUST abort with the dedicated pre-flight
// error BEFORE any write hits BoltDB. If this test ever passes
// silently, a fresh-target disaster restore would land in a state
// where the operator's secrets are gone and no warning was emitted.
func TestImport_PreflightDisasterRecovery_FreshTargetFailsLoud(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	snap := minimalSnapshot()
	snap.SecretsIncluded = false
	snap.Users = []auth.User{
		seedFakeUser("u-import-1", SentinelLiteral),
	}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if !errors.Is(err, ErrPreflightDisasterRecovery) {
		t.Fatalf("PRE-FLIGHT BYPASS REGRESSION: expected ErrPreflightDisasterRecovery, got %v", err)
	}
	if !strings.Contains(err.Error(), "Two paths forward") {
		t.Errorf("error wording missing 'Two paths forward' guidance: %s", err)
	}

	// Pinning the "no write hit BoltDB" promise: the target must
	// still be fresh.
	live, _ := readLive(context.Background(), store, us)
	if !live.isFresh() {
		t.Error("ALL-OR-NOTHING REGRESSION: pre-flight failure modified the live store")
	}
}

func TestImport_PreflightDisasterRecovery_AllowIncompleteBypass(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	snap := minimalSnapshot()
	snap.SecretsIncluded = false
	snap.Users = []auth.User{
		seedFakeUser("u-import-1", SentinelLiteral),
	}

	report, err := Import(context.Background(), store, us, snap, ImportOptions{
		AllowIncompleteRestore: true,
	})
	if err != nil {
		t.Fatalf("--allow-incomplete-restore should bypass pre-flight, got: %v", err)
	}
	// The user's password hash MUST be cleared (NOT the
	// sentinel literal). The boot-time setup token re-triggers
	// on next start.
	got, err := us.GetByID(context.Background(), "u-import-1")
	if err != nil {
		t.Fatalf("get restored user: %v", err)
	}
	if got.PasswordHash == SentinelLiteral {
		t.Fatalf("SENTINEL LEAK: imported user's PasswordHash was written as the literal sentinel %q — auth would silently break", SentinelLiteral)
	}
	if got.PasswordHash != "" {
		t.Errorf("PasswordHash should be cleared on incomplete restore, got %q", got.PasswordHash)
	}
	if report.SentinelsUnresolvedTotal == 0 {
		t.Error("report should record at least 1 unresolved sentinel")
	}
	if len(report.IncompleteRows) == 0 {
		t.Error("report.IncompleteRows must enumerate cleared rows")
	}
}

// ============================================================
// (4) Sentinel inheritance — happy path on a non-fresh target
// ============================================================

func TestImport_SentinelInheritance_RoutePasswordHashPreserved(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	// Seed live: route with a known hash + a user (so the target
	// isn't "fresh", pre-flight skips).
	live := seedLiveRoute(t, store, "alice.example.com")
	_ = seedLiveUser(t, us, "alice", "alice-password-15c-xx")

	// Import: SAME route id, sentinel in the password_hash. The
	// importer must inherit the live hash, not write the literal.
	snap := minimalSnapshot()
	snap.SecretsIncluded = false
	snap.Users = []auth.User{
		{ID: "u-imported", Username: "alice", DisplayName: "Alice",
			PasswordHash: SentinelLiteral, // also sentinel — must inherit
			AuthSource:   auth.UserAuthSourceLocal, Role: auth.UserRoleAdmin,
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
	}
	// Make the snapshot user inherit from the LIVE user by reusing the live ID.
	snap.Users[0].ID = live.ID // route ID is in `live`; we want the user ID
	// fix: reuse the actual seeded user via List
	seeded, _ := us.List(context.Background())
	snap.Users[0].ID = seeded[0].ID

	snap.Routes = []storage.Route{
		{
			ID:        live.ID,
			Host:      live.Host,
			Upstreams: live.Upstreams,
			LBPolicy:  live.LBPolicy,
			AuthMode:  "basic",
			BasicAuth: storage.BasicAuthRouteConfig{
				Username:     "admin",
				PasswordHash: SentinelLiteral, // ← inherit, don't write the literal
			},
			WAFMode:   live.WAFMode,
			CreatedAt: live.CreatedAt,
			UpdatedAt: live.UpdatedAt,
		},
	}

	report, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if err != nil {
		t.Fatalf("inheritance happy path failed: %v", err)
	}

	// Verify: live route's basic_auth.password_hash is INHERITED,
	// not the literal sentinel.
	routesAfter, _ := store.ListRoutes(context.Background())
	if len(routesAfter) != 1 {
		t.Fatalf("expected 1 route after restore, got %d", len(routesAfter))
	}
	r := routesAfter[0]
	if r.BasicAuth.PasswordHash == SentinelLiteral {
		t.Fatalf("SENTINEL LEAK: route password_hash written as the literal sentinel — auth broken")
	}
	if r.BasicAuth.PasswordHash != "$argon2id$live-route-hash" {
		t.Errorf("expected inherited live hash, got %q", r.BasicAuth.PasswordHash)
	}
	if report.SentinelsInheritedTotal == 0 {
		t.Error("report should record at least 1 inherited sentinel")
	}
}

// ============================================================
// (5) Sentinel rejection — partial mismatch (rule 2)
// ============================================================

// TestImport_SentinelMismatch_RejectsWithTwoPaths is the rule-2 pin.
// Live target has SOME data (so pre-flight skips), but the import's
// route has a different ID than any live route AND its
// password_hash is the sentinel. The whole import must reject.
func TestImport_SentinelMismatch_RejectsWithTwoPaths(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	_ = seedLiveRoute(t, store, "alice.example.com")
	_ = seedLiveUser(t, us, "alice", "alice-password-15c-xx")

	snap := minimalSnapshot()
	snap.SecretsIncluded = false
	seeded, _ := us.List(context.Background())
	snap.Users = []auth.User{seeded[0]}
	snap.Users[0].PasswordHash = SentinelLiteral
	// Route whose ID does NOT exist in live → sentinel cannot
	// inherit.
	snap.Routes = []storage.Route{
		{
			ID:        "id-not-in-live-store-aaaaaaaaaa",
			Host:      "stranger.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			AuthMode:  "basic",
			BasicAuth: storage.BasicAuthRouteConfig{
				Username:     "admin",
				PasswordHash: SentinelLiteral, // ← unresolvable
			},
			WAFMode: "off",
		},
	}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if err == nil {
		t.Fatal("NEVER SILENT REGRESSION: unresolvable sentinel passed without error")
	}
	if !IsUnresolvedSentinelError(err) {
		t.Errorf("expected unresolvedSentinel error, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "Two paths forward") {
		t.Errorf("error must contain 'Two paths forward' guidance: %s", err)
	}
	if !strings.Contains(err.Error(), "basic_auth.password_hash") {
		t.Errorf("error must name the affected field: %s", err)
	}

	// ALL-OR-NOTHING REGRESSION: live route must be untouched.
	routesAfter, _ := store.ListRoutes(context.Background())
	if len(routesAfter) != 1 || routesAfter[0].Host != "alice.example.com" {
		t.Fatalf("ALL-OR-NOTHING REGRESSION: live store was modified despite a rejected import: %+v", routesAfter)
	}
}

// ============================================================
// (6) Sentinel rejection then bypass — same shape with the flag
// ============================================================

func TestImport_SentinelMismatch_AllowIncompleteClearsField(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	_ = seedLiveRoute(t, store, "alice.example.com")
	_ = seedLiveUser(t, us, "alice", "alice-password-15c-xx")

	snap := minimalSnapshot()
	snap.SecretsIncluded = false
	seeded, _ := us.List(context.Background())
	snap.Users = []auth.User{seeded[0]}
	snap.Users[0].PasswordHash = SentinelLiteral

	snap.Routes = []storage.Route{
		{
			ID:        "id-not-in-live-store-bbbbbbbbbb",
			Host:      "stranger.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			AuthMode:  "basic",
			BasicAuth: storage.BasicAuthRouteConfig{
				Username:     "admin",
				PasswordHash: SentinelLiteral,
			},
			WAFMode: "off",
		},
	}

	report, err := Import(context.Background(), store, us, snap, ImportOptions{
		AllowIncompleteRestore: true,
	})
	if err != nil {
		t.Fatalf("bypass should proceed, got: %v", err)
	}

	// SENTINEL LEAK pin: cleared field must NOT be the literal.
	routesAfter, _ := store.ListRoutes(context.Background())
	for _, r := range routesAfter {
		if r.BasicAuth.PasswordHash == SentinelLiteral {
			t.Fatalf("SENTINEL LEAK: route %q got the literal sentinel as PasswordHash", r.ID)
		}
	}

	if report.SentinelsUnresolvedTotal < 1 {
		t.Errorf("report.SentinelsUnresolvedTotal = %d; expected >= 1", report.SentinelsUnresolvedTotal)
	}
	if len(report.IncompleteRows) < 1 {
		t.Errorf("report.IncompleteRows = %d; expected >= 1", len(report.IncompleteRows))
	}
}

// ============================================================
// (7) All-or-nothing rollback on storage failure
// ============================================================

// TestImport_AllOrNothing_NoPartialWriteOnRejection drives the
// rejection through a path BEFORE the RestoreSnapshot call and
// asserts the BoltDB is intact. Combined with (5)'s post-rejection
// check, this pins the "any failure leaves the BoltDB in the
// pre-restore state" property.
func TestImport_AllOrNothing_NoPartialWriteOnRejection(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	live := seedLiveRoute(t, store, "alice.example.com")
	_ = seedLiveUser(t, us, "alice", "alice-password-15c-xx")

	// Snapshot that fails the empty-users guard (no opt-in).
	snap := minimalSnapshot()
	snap.Users = nil

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if !errors.Is(err, ErrEmptyUsers) {
		t.Fatalf("expected empty-users rejection, got %v", err)
	}

	// Live store still has the original route — no partial write.
	routesAfter, _ := store.ListRoutes(context.Background())
	if len(routesAfter) != 1 || routesAfter[0].ID != live.ID {
		t.Fatalf("ALL-OR-NOTHING REGRESSION: live store mutated despite empty-users rejection: %+v", routesAfter)
	}
	usersAfter, _ := us.List(context.Background())
	if len(usersAfter) != 1 {
		t.Errorf("user count after rejection = %d; expected 1 (unmodified)", len(usersAfter))
	}
}

// ============================================================
// (8) Schema MAJOR mismatch — no write hits BoltDB
// ============================================================

func TestImport_SchemaMajorMismatch_NoWriteHitsBoltDB(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	live := seedLiveRoute(t, store, "alice.example.com")
	_ = seedLiveUser(t, us, "alice", "alice-password-15c-xx")

	snap := minimalSnapshot()
	snap.SchemaVersion = "2.0.0"
	snap.Users = []auth.User{seedFakeUser("u-1", "$argon2id$..hash..")}

	_, err := Import(context.Background(), store, us, snap, ImportOptions{})
	if err == nil {
		t.Fatal("expected schema rejection")
	}
	routesAfter, _ := store.ListRoutes(context.Background())
	if len(routesAfter) != 1 || routesAfter[0].ID != live.ID {
		t.Errorf("ALL-OR-NOTHING REGRESSION: schema-major rejection mutated live store: %+v", routesAfter)
	}
}

// ============================================================
// (9) Round-trip with --include-secrets
// ============================================================

func TestExportImport_RoundTrip_IncludeSecrets(t *testing.T) {
	sourceStore, sourceUS := newTestStoreWithUserStore(t)
	_ = seedLiveRoute(t, sourceStore, "round-trip.example.com")
	_ = seedLiveUser(t, sourceUS, "alice", "alice-password-15c-xx")

	// Export from source with --include-secrets.
	snap, err := Export(context.Background(), sourceStore, sourceUS, "test", true)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !snap.SecretsIncluded {
		t.Fatal("export should set SecretsIncluded=true")
	}
	// Sentinel literal must NOT appear in the cleartext export.
	for _, u := range snap.Users {
		if u.PasswordHash == SentinelLiteral {
			t.Errorf("sentinel literal leaked into cleartext export of user %q", u.Username)
		}
	}

	// Import into a FRESH target.
	destStore, destUS := newTestStoreWithUserStore(t)
	report, err := Import(context.Background(), destStore, destUS, snap, ImportOptions{})
	if err != nil {
		t.Fatalf("round-trip import: %v", err)
	}
	if report.RoutesImported != 1 || report.UsersImported != 1 {
		t.Errorf("expected 1 route + 1 user imported, got %+v", report)
	}

	// Verify the route + user landed with real (non-sentinel) values.
	routesAfter, _ := destStore.ListRoutes(context.Background())
	if len(routesAfter) != 1 {
		t.Fatalf("dest has %d routes; expected 1", len(routesAfter))
	}
	if routesAfter[0].BasicAuth.PasswordHash != "$argon2id$live-route-hash" {
		t.Errorf("password_hash didn't round-trip cleanly, got %q", routesAfter[0].BasicAuth.PasswordHash)
	}
	usersAfter, _ := destUS.List(context.Background())
	if len(usersAfter) != 1 {
		t.Fatalf("dest has %d users; expected 1", len(usersAfter))
	}
	if usersAfter[0].PasswordHash == "" {
		t.Error("user password_hash empty after include-secrets round-trip — secret lost")
	}
	if usersAfter[0].PasswordHash == SentinelLiteral {
		t.Errorf("SENTINEL LEAK: user password_hash equals sentinel after include-secrets round-trip")
	}
}

// ============================================================
// Helpers
// ============================================================

// minimalSnapshot is a valid Snapshot shell — SchemaVersion set, no
// data. Tests fill in the sections they need.
func minimalSnapshot() *Snapshot {
	return &Snapshot{
		SchemaVersion:        SchemaVersion,
		ExportedAt:           time.Now().UTC(),
		SecretsIncluded:      true,
		ArenetVersion:        "test",
		Routes:               []storage.Route{},
		DNSProviders:         []storage.DNSProviderConfig{},
		ForwardAuthProviders: []storage.ForwardAuthProvider{},
		Users:                []auth.User{},
	}
}

// seedFakeUser builds an auth.User directly (bypasses
// UserStore.Create's password hashing) for tests that need a known
// hash literal in the snapshot.
func seedFakeUser(id, hash string) auth.User {
	now := time.Now().UTC()
	return auth.User{
		ID:           id,
		Username:     "u_" + id,
		DisplayName:  id,
		PasswordHash: hash,
		AuthSource:   auth.UserAuthSourceLocal,
		Role:         auth.UserRoleAdmin,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}
