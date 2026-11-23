// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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

// Package allowlist is the AreNET-native allowlist store (#364): trusted
// IPs/CIDRs exempt from AreNET Security Automation auto-bans, with a
// per-category scope (block / throttle / audit). It is deliberately
// independent of CrowdSec — the enforcement happens inside the AreNET
// trigger, not via any CrowdSec API (which has no released write path).
//
// The store persists to a dedicated SQLite file (security.db), separate
// from the retention-pruned metrics.db, so this operator config is never
// silently dropped (#364 spec D-STORE).
package allowlist

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Allowlist is one named allowlist with its scope flags.
type Allowlist struct {
	ID            int64     `json:"-"`
	Slug          string    `json:"slug"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Enabled       bool      `json:"enabled"`
	ScopeBlock    bool      `json:"scopeBlock"`
	ScopeThrottle bool      `json:"scopeThrottle"`
	ScopeAudit    bool      `json:"scopeAudit"`
	Entries       []Entry   `json:"entries"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// Entry is one IP/CIDR within an allowlist. CIDR is always stored in
// normalised prefix form (a bare IP becomes /32 or /128).
type Entry struct {
	CIDR string `json:"cidr"`
	Note string `json:"note"`
}

// Input is the create/update payload.
type Input struct {
	Name          string
	Description   string
	Enabled       bool
	ScopeBlock    bool
	ScopeThrottle bool
	ScopeAudit    bool
	Entries       []Entry
}

// ErrNotFound is returned when a slug does not resolve.
var ErrNotFound = errors.New("allowlist: not found")

const schemaSQL = `
CREATE TABLE IF NOT EXISTS allowlist (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  slug           TEXT    NOT NULL UNIQUE,
  name           TEXT    NOT NULL,
  description    TEXT    NOT NULL DEFAULT '',
  enabled        INTEGER NOT NULL DEFAULT 1,
  scope_block    INTEGER NOT NULL DEFAULT 1,
  scope_throttle INTEGER NOT NULL DEFAULT 1,
  scope_audit    INTEGER NOT NULL DEFAULT 1,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS allowlist_entry (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  allowlist_id INTEGER NOT NULL REFERENCES allowlist(id) ON DELETE CASCADE,
  cidr_or_ip   TEXT    NOT NULL,
  note         TEXT    NOT NULL DEFAULT '',
  created_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entry_allowlist ON allowlist_entry(allowlist_id);
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
`

// Store is the SQLite-backed allowlist store.
type Store struct {
	db *sql.DB
}

// Open initialises the allowlist DB at path and applies the schema.
// path may be ":memory:" for tests. Enforces foreign keys (for the
// entry cascade) and WAL, mirroring internal/observability.
func Open(ctx context.Context, path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("allowlist: sql.Open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("allowlist: ping: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("allowlist: schema init: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the DB handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// List returns every allowlist with its entries, ordered by name.
func (s *Store) List(ctx context.Context) ([]Allowlist, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, slug, name, description, enabled, scope_block, scope_throttle, scope_audit, created_at, updated_at
		FROM allowlist ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("allowlist: list: %w", err)
	}
	defer rows.Close()
	var out []Allowlist
	for rows.Next() {
		a, err := scanAllowlist(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		entries, err := s.entriesFor(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Entries = entries
	}
	return out, nil
}

// Get returns one allowlist by slug, with its entries.
func (s *Store) Get(ctx context.Context, slug string) (*Allowlist, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, slug, name, description, enabled, scope_block, scope_throttle, scope_audit, created_at, updated_at
		FROM allowlist WHERE slug = ?`, slug)
	a, err := scanAllowlist(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	entries, err := s.entriesFor(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	a.Entries = entries
	return &a, nil
}

// Create inserts a new allowlist and its (validated) entries. The slug is
// derived from name and made unique.
func (s *Store) Create(ctx context.Context, in Input) (*Allowlist, error) {
	norm, err := validateEntries(in.Entries)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, fmt.Errorf("allowlist: name required")
	}
	slug, err := s.uniqueSlug(ctx, slugify(name))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO allowlist (slug, name, description, enabled, scope_block, scope_throttle, scope_audit, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		slug, name, in.Description, b2i(in.Enabled), b2i(in.ScopeBlock), b2i(in.ScopeThrottle), b2i(in.ScopeAudit), now, now)
	if err != nil {
		return nil, fmt.Errorf("allowlist: insert: %w", err)
	}
	id, _ := res.LastInsertId()
	if err := insertEntries(ctx, tx, id, norm, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.Get(ctx, slug)
}

// Update replaces an allowlist's fields and entries wholesale.
func (s *Store) Update(ctx context.Context, slug string, in Input) (*Allowlist, error) {
	norm, err := validateEntries(in.Entries)
	if err != nil {
		return nil, err
	}
	existing, err := s.Get(ctx, slug)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, fmt.Errorf("allowlist: name required")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE allowlist SET name=?, description=?, enabled=?, scope_block=?, scope_throttle=?, scope_audit=?, updated_at=?
		WHERE id=?`,
		name, in.Description, b2i(in.Enabled), b2i(in.ScopeBlock), b2i(in.ScopeThrottle), b2i(in.ScopeAudit), now, existing.ID); err != nil {
		return nil, fmt.Errorf("allowlist: update: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM allowlist_entry WHERE allowlist_id=?`, existing.ID); err != nil {
		return nil, err
	}
	if err := insertEntries(ctx, tx, existing.ID, norm, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.Get(ctx, slug)
}

// Delete removes an allowlist and (via cascade) its entries.
func (s *Store) Delete(ctx context.Context, slug string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM allowlist WHERE slug=?`, slug)
	if err != nil {
		return fmt.Errorf("allowlist: delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- helpers -------------------------------------------------------------

type scanner interface {
	Scan(dest ...any) error
}

func scanAllowlist(sc scanner) (Allowlist, error) {
	var a Allowlist
	var enabled, sb, st, sa int
	var created, updated string
	if err := sc.Scan(&a.ID, &a.Slug, &a.Name, &a.Description, &enabled, &sb, &st, &sa, &created, &updated); err != nil {
		return Allowlist{}, err
	}
	a.Enabled = enabled != 0
	a.ScopeBlock = sb != 0
	a.ScopeThrottle = st != 0
	a.ScopeAudit = sa != 0
	a.CreatedAt, _ = time.Parse(time.RFC3339, created)
	a.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return a, nil
}

func (s *Store) entriesFor(ctx context.Context, id int64) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cidr_or_ip, note FROM allowlist_entry WHERE allowlist_id=? ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.CIDR, &e.Note); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func insertEntries(ctx context.Context, tx *sql.Tx, id int64, entries []Entry, now string) error {
	for _, e := range entries {
		if _, err := tx.ExecContext(ctx, `INSERT INTO allowlist_entry (allowlist_id, cidr_or_ip, note, created_at) VALUES (?,?,?,?)`,
			id, e.CIDR, e.Note, now); err != nil {
			return fmt.Errorf("allowlist: insert entry: %w", err)
		}
	}
	return nil
}

func (s *Store) uniqueSlug(ctx context.Context, base string) (string, error) {
	if base == "" {
		base = "allowlist"
	}
	slug := base
	for i := 2; ; i++ {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM allowlist WHERE slug=?`, slug).Scan(&n); err != nil {
			return "", err
		}
		if n == 0 {
			return slug, nil
		}
		slug = fmt.Sprintf("%s-%d", base, i)
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// validateEntries normalises and validates each entry's CIDR/IP.
//
// STUB (RED): currently accepts every entry verbatim, so the guard
// TestAllowlistCIDRValidation_G fails first. The real net/netip
// validation lands with the resolver implementation.
func validateEntries(in []Entry) ([]Entry, error) {
	return in, nil
}

// normalizeCIDR parses a bare IP or CIDR into canonical prefix form.
//
// STUB (RED): returns the input unchanged with no error.
func normalizeCIDR(s string) (string, error) {
	return s, nil
}

var _ = netip.Addr{} // keep net/netip imported for the real implementation
