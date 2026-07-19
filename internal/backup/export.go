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
	"fmt"
	"time"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// Storer is the storage subset Export consumes. Declared at the
// consumer side so tests can inject a fake without booting bbolt
// (decision D4, consistent with OIDCStore in internal/api).
type Storer interface {
	ListRoutes(ctx context.Context) ([]storage.Route, error)
	ListDNSProviders(ctx context.Context) ([]storage.DNSProviderConfig, error)
	ListForwardAuthProviders(ctx context.Context) ([]storage.ForwardAuthProvider, error)
	GetOIDCConfig(ctx context.Context) (storage.OIDCConfig, error)
	GetMaxMindConfig(ctx context.Context) (storage.MaxMindConfig, error)
	ListExternalCertificates(ctx context.Context) ([]storage.ExternalCertificate, error)
}

// UserStorer is the userstore subset Export consumes.
type UserStorer interface {
	List(ctx context.Context) ([]auth.User, error)
}

// Export builds a Snapshot from the live store. The redaction pass
// fires when includeSecrets is false (the default + 95% case); when
// includeSecrets is true the snapshot carries cleartext and the
// caller is responsible for surfacing the operator warnings (CLI
// stderr message, UI modal, etc.) BEFORE writing the file to disk.
//
// arenetVersion is the version string of the running binary,
// carried in the snapshot as operational metadata (post-mortem on
// "which version produced this file"). The caller passes it from
// cmd/arenet/main.go's version constant.
func Export(ctx context.Context, store Storer, users UserStorer, arenetVersion string, includeSecrets bool) (*Snapshot, error) {
	if store == nil || users == nil {
		return nil, errors.New("backup: nil store")
	}

	routes, err := store.ListRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: list routes: %w", err)
	}
	usersList, err := users.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: list users: %w", err)
	}

	// DNS providers: the v2.11 UUID-keyed collection (Task 1a). An
	// empty collection on a never-configured install exports as an
	// empty slice — normal, not a failure. Task 1e revisits backup
	// for the full collection semantics; this keeps export compiling
	// and correctly emits every provider.
	dnsList, err := store.ListDNSProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: list dns providers: %w", err)
	}

	fwdList, err := store.ListForwardAuthProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: list forward-auth providers: %w", err)
	}

	oidcCfg, err := store.GetOIDCConfig(ctx)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("export: get oidc config: %w", err)
	}
	// ErrNotFound → zero-valued OIDCConfig (Enabled false, all
	// fields empty); that's the correct exported shape for "never
	// configured".

	// MaxMind config (Brick 2 Task 4): a single-record store like
	// OIDC, but represented as a pointer in the snapshot — nil when
	// the instance has never configured it, populated otherwise.
	var maxMindCfg *storage.MaxMindConfig
	mm, err := store.GetMaxMindConfig(ctx)
	if err == nil {
		maxMindCfg = &mm
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("export: get maxmind config: %w", err)
	}

	// External certificates (v2.19.0 UUID-keyed collection): an empty
	// collection on a never-configured install exports as an empty
	// slice — normal, not a failure. The KeyPEM secret is redacted
	// below when includeSecrets is false.
	extList, err := store.ListExternalCertificates(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: list external certificates: %w", err)
	}

	snap := &Snapshot{
		SchemaVersion:        SchemaVersion,
		ExportedAt:           time.Now().UTC(),
		SecretsIncluded:      includeSecrets,
		ArenetVersion:        arenetVersion,
		Routes:               routes,
		DNSProviders:         dnsList,
		ForwardAuthProviders: fwdList,
		OIDCConfig:           oidcCfg,
		MaxMindConfig:        maxMindCfg,
		Users:                usersList,
		ExternalCertificates: extList,
	}
	if !includeSecrets {
		redactSnapshotInPlace(snap)
	}
	return snap, nil
}
