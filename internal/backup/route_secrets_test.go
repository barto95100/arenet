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
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.29 — path-rule basic-auth hashes and credential-bearing route
// headers are secrets in backups (were exported as-is).

func secretRoute() storage.Route {
	return storage.Route{
		ID:        "r1",
		Host:      "api.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		AuthMode:  "none",
		WAFMode:   "off",
		PathRules: []storage.PathRule{{
			PathPrefix: "/docs",
			BasicAuth:  &storage.BasicAuthRouteConfig{Username: "doc", PasswordHash: "$argon2id$path-hash"},
		}},
		RequestHeaders:  map[string]string{"Authorization": "Bearer UPSTREAM-TOKEN", "X-Env": "prod"},
		ResponseHeaders: map[string]string{"X-Service-Token": "RESP-SECRET"},
	}
}

func TestIsSensitiveHeader(t *testing.T) {
	for name, want := range map[string]bool{
		"Authorization": true, "proxy-authorization": true, "Cookie": true, "X-Api-Key": true,
		"X-Auth-Token": true, "X-Client-Secret": true, "X-Env": false, "Host": false, "X-Forwarded-For": false,
	} {
		if got := IsSensitiveHeader(name); got != want {
			t.Errorf("IsSensitiveHeader(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestRedact_PathRuleHashAndSensitiveHeaders(t *testing.T) {
	r := secretRoute()
	snap := minimalSnapshot()
	snap.Routes = []storage.Route{r}
	redactSnapshotInPlace(snap)

	raw, _ := json.Marshal(snap.Routes)
	for _, leaked := range []string{"path-hash", "UPSTREAM-TOKEN", "RESP-SECRET"} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("%q survived redaction: %s", leaked, raw)
		}
	}
	if snap.Routes[0].RequestHeaders["X-Env"] != "prod" {
		t.Error("non-sensitive header must be kept")
	}
	if r.PathRules[0].BasicAuth.PasswordHash != "$argon2id$path-hash" || r.RequestHeaders["Authorization"] != "Bearer UPSTREAM-TOKEN" {
		t.Error("redaction mutated the live route")
	}
}

func TestImport_PathRuleHashAndHeaders_InheritFromLiveRoute(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	ctx := context.Background()
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-x")
	live := secretRoute()
	live.ID = ""
	created, err := store.CreateRoute(ctx, live)
	if err != nil {
		t.Fatal(err)
	}

	snap := minimalSnapshot()
	snap.SecretsIncluded = false
	snap.Users = []auth.User{seedFakeUser("u-1", "$argon2id$hash")}
	exported := created
	snap.Routes = []storage.Route{exported}
	redactSnapshotInPlace(snap)
	snap.Users = []auth.User{seedFakeUser("u-1", "$argon2id$hash")}

	if _, err := Import(ctx, store, us, snap, ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, err := store.GetRoute(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PathRules[0].BasicAuth.PasswordHash != "$argon2id$path-hash" {
		t.Errorf("path-rule hash not inherited: %+v", got.PathRules[0].BasicAuth)
	}
	if got.RequestHeaders["Authorization"] != "Bearer UPSTREAM-TOKEN" || got.ResponseHeaders["X-Service-Token"] != "RESP-SECRET" {
		t.Errorf("headers not inherited: %v %v", got.RequestHeaders, got.ResponseHeaders)
	}
}

func TestImport_PathRuleHash_UnresolvedRejectsOrClears(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	ctx := context.Background()
	_ = seedLiveUser(t, us, "admin", "admin-password-15c-x")

	snap := minimalSnapshot()
	snap.SecretsIncluded = false
	snap.Users = []auth.User{seedFakeUser("u-1", "$argon2id$hash")}
	snap.Routes = []storage.Route{secretRoute()} // no live route with id r1
	redactSnapshotInPlace(snap)
	snap.Users = []auth.User{seedFakeUser("u-1", "$argon2id$hash")}

	if _, err := Import(ctx, store, us, snap, ImportOptions{}); err == nil || !IsUnresolvedSentinelError(err) {
		t.Fatalf("err = %v, want unresolved sentinel", err)
	}
	report, err := Import(ctx, store, us, snap, ImportOptions{AllowIncompleteRestore: true})
	if err != nil {
		t.Fatalf("incomplete restore must validate with cleared path-rule hash: %v", err)
	}
	fields := map[string]bool{}
	for _, row := range report.IncompleteRows {
		fields[row.Field] = true
	}
	for _, f := range []string{pathRuleHashField("/docs"), "request_headers[Authorization]", "response_headers[X-Service-Token]"} {
		if !fields[f] {
			t.Errorf("incomplete rows missing %q: %+v", f, report.IncompleteRows)
		}
	}
}
