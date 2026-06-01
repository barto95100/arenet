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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/backup"
	appconfig "github.com/barto95100/arenet/internal/config"
	"github.com/barto95100/arenet/internal/storage"
)

// Step K.3 — CLI export / restore.
//
// Both are one-shot operations: when --export PATH or --restore
// PATH is set on the command line, the binary opens BoltDB, runs
// the corresponding action, prints a short summary, and exits.
// Caddy is NOT started; the metrics broadcaster is NOT started;
// the admin API is NOT served. This is the spec §5.3 "CLI restore
// runs at boot, before Caddy starts" — by short-circuiting BEFORE
// caddymgr.Start the binary never side-effects beyond BoltDB.

// runExportCLI implements --export PATH [--include-secrets].
//
// When --include-secrets is set, the file is written with mode
// 0o600 (owner-readable only) and a warning is printed to stderr
// BEFORE the file is written. The 0o600 protection is enforced by
// Arenet at write time — we don't rely on the operator.
func runExportCLI(ctx context.Context, logger *slog.Logger, cfg *appconfig.Config) error {
	dbPath := dbPathForCLI(cfg)
	store, err := storage.NewStore(dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = store.Close() }()
	users := auth.NewUserStore(store.DB())

	if cfg.IncludeSecrets {
		fmt.Fprintln(os.Stderr,
			"WARNING: --include-secrets requested. The exported file will\n"+
				"contain PLAINTEXT secrets (admin password hashes, OVH API\n"+
				"keys, OIDC client secret, forward-auth provider client\n"+
				"secrets, per-route Basic Auth hashes). Store the file with\n"+
				"restricted permissions (chmod 600) and consider encrypting\n"+
				"at rest (age / GPG / vault).")
	}

	snap, err := backup.Export(ctx, store, users, version, cfg.IncludeSecrets)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	mode := os.FileMode(0o644)
	if cfg.IncludeSecrets {
		// Spec §5.3 §B clarification: 0o600 on the write path
		// when secrets are in the file. Arenet enforces, not the
		// operator.
		mode = 0o600
	}
	if err := os.WriteFile(cfg.ExportPath, body, mode); err != nil {
		return fmt.Errorf("write %s: %w", cfg.ExportPath, err)
	}
	logger.Info("config exported",
		"path", cfg.ExportPath,
		"secrets_included", cfg.IncludeSecrets,
		"routes", len(snap.Routes),
		"users", len(snap.Users),
		"dns_providers", len(snap.DNSProviders),
		"forward_auth_providers", len(snap.ForwardAuthProviders),
	)
	return nil
}

// runRestoreCLI implements --restore PATH [--allow-incomplete-restore]
// [--allow-empty-users].
//
// The CLI restore runs BEFORE Caddy — no live ReloadFromStore call.
// The next normal boot (the one the operator runs after the CLI
// exits) builds Caddy fresh from the post-restore BoltDB. This is
// the spec §5.3 "Restore via CLI runs at boot, before Caddy starts"
// — semantically simpler than the API path (no hot-apply).
//
// The boot WARN about incomplete rows is also handled by the
// SUBSEQUENT normal boot, not this one — when the operator wires
// the IncompleteRows persistence in J.4's boot WARN pattern.
func runRestoreCLI(ctx context.Context, logger *slog.Logger, cfg *appconfig.Config) error {
	body, err := os.ReadFile(cfg.RestorePath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cfg.RestorePath, err)
	}
	var snap backup.Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return fmt.Errorf("parse %s: %w", cfg.RestorePath, err)
	}

	dbPath := dbPathForCLI(cfg)
	store, err := storage.NewStore(dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = store.Close() }()
	users := auth.NewUserStore(store.DB())

	report, err := backup.Import(ctx, store, users, &snap, backup.ImportOptions{
		AllowIncompleteRestore: cfg.AllowIncompleteRestore,
		AllowEmptyUsers:        cfg.AllowEmptyUsers,
	})
	if err != nil {
		// Print the full actionable message to stderr — the
		// operator needs the "two paths forward" wording verbatim.
		// Distinct from logger.Error which writes one-line
		// structured records.
		fmt.Fprintln(os.Stderr, err.Error())
		return fmt.Errorf("restore: %w", err)
	}

	logger.Info("config restored",
		"path", cfg.RestorePath,
		"schema_version", report.SchemaVersion,
		"secrets_included_in_source", report.SecretsIncludedInSource,
		"allow_incomplete_restore", report.AllowIncompleteRestore,
		"routes_imported", report.RoutesImported,
		"users_imported", report.UsersImported,
		"dns_providers_imported", report.DNSProvidersImported,
		"forward_auth_providers_imported", report.ForwardAuthProvidersImported,
		"oidc_config_imported", report.OIDCConfigImported,
		"sentinels_inherited_total", report.SentinelsInheritedTotal,
		"sentinels_unresolved_total", report.SentinelsUnresolvedTotal,
		"incomplete_rows", len(report.IncompleteRows),
	)

	if len(report.IncompleteRows) > 0 {
		// Loud, every-row WARN to stderr. Spec §5.3 "Never silent"
		// — the operator opted into the incomplete restore, but
		// they still need a list of every row that needs a
		// re-saved secret.
		fmt.Fprintln(os.Stderr, "\nIncomplete restore — the following secrets were cleared and need to be re-saved:")
		for _, row := range report.IncompleteRows {
			fmt.Fprintf(os.Stderr, "  - %s/%s: field %s\n", row.Entity, row.Identity, row.Field)
		}
	}
	return nil
}

func dbPathForCLI(cfg *appconfig.Config) string {
	return filepath.Join(cfg.DataDir, "arenet.db")
}
