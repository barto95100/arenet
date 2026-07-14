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

// Package geoipupdate downloads and installs GeoLite2/GeoIP2 MMDB
// database updates from MaxMind, using operator-supplied credentials
// (storage.MaxMindConfig). It computes the on-disk database's md5,
// asks the MaxMind API for a newer edition only if the digest
// changed, and installs the result atomically (temp file + rename)
// before reloading the shared *geo.Lookup so the running process
// picks up the new database without a restart.
//
// Task 1 implemented the core UpdateOnce download/install flow. Task
// 2 added the edition guard: after downloading, the temp file is
// opened and its Metadata().DatabaseType is checked to be a City
// edition (Arenet's reader.City() requires it — a Country/ASN DB
// would silently fail-open, disabling geoblock and blanking the world
// map) before it is renamed into place. The scheduler (periodic
// ticking) is a later task.
package geoipupdate

import (
	"context"
	"crypto/md5" //nolint:gosec // MaxMind's own change-detection digest, not a security boundary.
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/maxmind/geoipupdate/v8/client"
	"github.com/oschwald/geoip2-golang"

	"github.com/barto95100/arenet/internal/geo"
	"github.com/barto95100/arenet/internal/storage"
)

// Status constants for UpdateResult.Status.
const (
	// StatusUpdated means a new database was downloaded, installed,
	// and the shared *geo.Lookup was reloaded.
	StatusUpdated = "updated"
	// StatusUpToDate means the on-disk database's md5 already
	// matches what MaxMind currently serves; nothing was written.
	StatusUpToDate = "up_to_date"
	// StatusNoCreds means no MaxMind credentials are configured
	// (fresh install) or the stored credentials are incomplete.
	StatusNoCreds = "no_credentials"
	// StatusError means the download or install failed. The
	// existing on-disk database (if any) is left untouched.
	StatusError = "error"
)

// tmpSuffix is appended to Config.MMDBPath to form the temp file used
// for the atomic write-then-rename install.
const tmpSuffix = ".tmp"

// CredStore is the subset of storage.Store this package depends on.
// Satisfied by *storage.Store.
type CredStore interface {
	// GetMaxMindConfig returns the persisted MaxMind credentials, or
	// storage.ErrNotFound when none have been configured.
	GetMaxMindConfig(ctx context.Context) (storage.MaxMindConfig, error)
}

// DownloadFunc downloads the given edition if currentMD5 no longer
// matches what MaxMind currently serves. It is a seam over
// client.Client.Download so tests can substitute a fake without
// making real MaxMind API calls; the zero value of Config defaults
// this to the real client (see New).
type DownloadFunc func(ctx context.Context, accountID int, licenseKey, editionID, currentMD5 string) (client.DownloadResponse, error)

// Config holds the dependencies for an Updater. Store, Lookup, and
// MMDBPath are required; HTTPClient, Download, Warmup, and Logger
// default when left zero.
type Config struct {
	// Store supplies the MaxMind account credentials. Required.
	Store CredStore
	// Lookup is the shared GeoIP lookup reloaded after a successful
	// install. Required (may be a zero-value *geo.Lookup in tests —
	// Reload on it is a normal, non-nil call).
	Lookup *geo.Lookup
	// MMDBPath is the on-disk path of the managed database. Required.
	MMDBPath string
	// HTTPClient is used by the default DownloadFunc. Defaults to
	// http.DefaultClient when nil. Ignored if Download is set.
	HTTPClient *http.Client
	// Download is the download seam. Defaults to a real
	// geoipupdate/v8 client call when nil.
	Download DownloadFunc
	// Warmup is how long Run waits before its first UpdateOnce call,
	// mirroring the update-checker's 30s post-boot delay so a fresh
	// start doesn't fire an immediate outbound call. Defaults to 30s
	// when left zero (see New) — production wiring (cmd/arenet/main.go)
	// leaves this unset. Tests that want the loop to run without
	// waiting set NoWarmup (below), since the zero value of this
	// field is reserved for "use the 30s default."
	Warmup time.Duration
	// NoWarmup, when true, forces Run's warmup delay to exactly zero
	// instead of defaulting Warmup to 30s. Exists purely so tests can
	// request "tick immediately" without the zero value of Warmup
	// being ambiguous with "left unset."
	NoWarmup bool
	// Logger receives operational log lines. Defaults to
	// slog.Default() when nil. The LicenseKey is NEVER logged.
	Logger *slog.Logger
}

// defaultWarmup is Config.Warmup's zero-value default — the delay
// before Run's first UpdateOnce call.
const defaultWarmup = 30 * time.Second

// UpdateResult is the outcome of a single UpdateOnce call.
type UpdateResult struct {
	// Status is one of StatusUpdated, StatusUpToDate, StatusNoCreds,
	// StatusError.
	Status string
	// Error is a human-readable failure reason, set only when
	// Status == StatusError. Never contains the license key.
	Error string
	// LastModified is the database's modification date as reported
	// by MaxMind. Zero unless Status == StatusUpdated.
	LastModified time.Time
	// At is when this result was produced.
	At time.Time
}

// Updater downloads and installs GeoIP database updates. Safe for
// concurrent use; Status is a thread-safe snapshot, though UpdateOnce
// itself is expected to be driven by a single scheduler goroutine.
type Updater struct {
	store      CredStore
	lookup     *geo.Lookup
	mmdbPath   string
	httpClient *http.Client
	download   DownloadFunc
	warmup     time.Duration
	logger     *slog.Logger

	mu     sync.Mutex
	status UpdateResult
}

// New builds an Updater from cfg, validating required dependencies
// and defaulting HTTPClient, Download, and Logger when left zero.
func New(cfg Config) (*Updater, error) {
	if cfg.Store == nil {
		return nil, errors.New("geoipupdate: Store is required")
	}
	if cfg.Lookup == nil {
		return nil, errors.New("geoipupdate: Lookup is required")
	}
	if cfg.MMDBPath == "" {
		return nil, errors.New("geoipupdate: MMDBPath is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	warmup := cfg.Warmup
	if warmup == 0 && !cfg.NoWarmup {
		warmup = defaultWarmup
	}

	u := &Updater{
		store:      cfg.Store,
		lookup:     cfg.Lookup,
		mmdbPath:   cfg.MMDBPath,
		httpClient: httpClient,
		warmup:     warmup,
		logger:     logger,
	}

	download := cfg.Download
	if download == nil {
		download = u.defaultDownload
	}
	u.download = download

	return u, nil
}

// defaultDownload is the real MaxMind download path, used when
// Config.Download is left nil.
func (u *Updater) defaultDownload(
	ctx context.Context,
	accountID int,
	licenseKey, editionID, currentMD5 string,
) (client.DownloadResponse, error) {
	c, err := client.New(accountID, licenseKey, client.WithHTTPClient(u.httpClient))
	if err != nil {
		return client.DownloadResponse{}, fmt.Errorf("geoipupdate: build client: %w", err)
	}
	return c.Download(ctx, editionID, currentMD5)
}

// UpdateOnce performs a single check-and-update cycle:
//
//  1. Read MaxMind credentials from Store. Missing/incomplete creds
//     produce StatusNoCreds without attempting a download.
//  2. Compute the current on-disk database's md5 ("" if absent —
//     bootstrap case, matching client.Download's own convention for
//     "no database yet").
//  3. Call Download. A transport/API error produces StatusError,
//     leaving any existing database untouched.
//  4. If the server reports no update available, return
//     StatusUpToDate without writing anything.
//  5. Otherwise install atomically: stream the response into
//     "<path>.tmp", fsync, close, verify it is a City-type MMDB
//     (rejecting Country/ASN editions), rename over the final path,
//     then reload the shared *geo.Lookup.
//
// The result is recorded so Status() reflects it.
func (u *Updater) UpdateOnce(ctx context.Context) UpdateResult {
	result := u.updateOnce(ctx)

	u.mu.Lock()
	u.status = result
	u.mu.Unlock()

	return result
}

func (u *Updater) updateOnce(ctx context.Context) UpdateResult {
	now := time.Now().UTC()

	// Step 1: read credentials.
	cfg, err := u.store.GetMaxMindConfig(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			u.logger.InfoContext(ctx, "geoipupdate: no credentials configured, skipping")
			return UpdateResult{Status: StatusNoCreds, At: now}
		}
		u.logger.ErrorContext(ctx, "geoipupdate: read credentials failed", "error", err)
		return UpdateResult{Status: StatusError, Error: "read credentials failed", At: now}
	}
	if cfg.AccountID <= 0 || cfg.LicenseKey == "" {
		u.logger.InfoContext(ctx, "geoipupdate: credentials incomplete, skipping")
		return UpdateResult{Status: StatusNoCreds, At: now}
	}

	// Step 2: current on-disk md5 (bootstrap = "").
	currentMD5, err := md5OfFile(u.mmdbPath)
	if err != nil {
		u.logger.ErrorContext(ctx, "geoipupdate: hash existing database failed", "error", err)
		return UpdateResult{Status: StatusError, Error: "hash existing database failed", At: now}
	}

	// Step 3: download (only fetches the body if changed).
	resp, err := u.download(ctx, cfg.AccountID, cfg.LicenseKey, cfg.EditionID, currentMD5)
	if err != nil {
		reason := "download failed"
		var httpErr client.HTTPError
		if errors.As(err, &httpErr) {
			reason = "credentials rejected"
		}
		u.logger.ErrorContext(ctx, "geoipupdate: download failed", "reason", reason, "error", err)
		return UpdateResult{Status: StatusError, Error: reason, At: now}
	}

	// Step 4: nothing new.
	if !resp.UpdateAvailable {
		if resp.Reader != nil {
			_ = resp.Reader.Close()
		}
		u.logger.InfoContext(ctx, "geoipupdate: database already up to date")
		return UpdateResult{Status: StatusUpToDate, At: now}
	}
	defer func() {
		if resp.Reader != nil {
			_ = resp.Reader.Close()
		}
	}()

	// Step 5: atomic install (temp write + rename), then reload.
	if err := u.install(ctx, resp.Reader); err != nil {
		var editionErr *editionGuardError
		if errors.As(err, &editionErr) {
			msg := fmt.Sprintf("downloaded edition %q is not a City database: %v", cfg.EditionID, editionErr.Unwrap())
			u.logger.ErrorContext(ctx, "geoipupdate: edition guard rejected download", "edition_id", cfg.EditionID, "error", editionErr.Unwrap())
			return UpdateResult{Status: StatusError, Error: msg, At: now}
		}
		u.logger.ErrorContext(ctx, "geoipupdate: install failed", "error", err)
		return UpdateResult{Status: StatusError, Error: "install failed", At: now}
	}

	u.logger.InfoContext(ctx, "geoipupdate: database updated", "last_modified", resp.LastModified)
	return UpdateResult{Status: StatusUpdated, LastModified: resp.LastModified, At: now}
}

// install streams r into a temp file next to Config.MMDBPath, syncs
// and closes it, then renames it into place and reloads the shared
// *geo.Lookup. On any failure the temp file is removed and the
// existing database at MMDBPath is left untouched.
func (u *Updater) install(_ context.Context, r io.Reader) error {
	tmpPath := u.mmdbPath + tmpSuffix

	tmp, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("geoipupdate: create temp file: %w", err)
	}
	tmpStillPresent := true
	defer func() {
		if tmpStillPresent {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("geoipupdate: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("geoipupdate: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("geoipupdate: close temp file: %w", err)
	}

	// Edition guard: Arenet's reader calls reader.City(), which requires a
	// City-type MMDB. A Country/ASN DB would silently fail-open (every
	// LookupIP -> Found:false), disabling geoblock + blanking the world
	// map. Verify the freshly-downloaded file is a City database before
	// installing. On failure, the defer above removes tmpPath; we do NOT
	// rename or Reload, so the existing on-disk DB (if any) is untouched.
	if err := verifyCityMMDB(tmpPath); err != nil {
		return &editionGuardError{err: err}
	}

	if err := os.Rename(tmpPath, u.mmdbPath); err != nil {
		return fmt.Errorf("geoipupdate: rename temp file into place: %w", err)
	}
	tmpStillPresent = false

	// From this point the new file IS installed at u.mmdbPath. If Reload
	// fails below, the returned error still means "installed but reload
	// failed" — NOT "old DB still active" — callers must not mistake a
	// StatusError here for the pre-install state.
	if err := u.lookup.Reload(u.mmdbPath); err != nil {
		return fmt.Errorf("geoipupdate: reload lookup: %w", err)
	}

	return nil
}

// editionGuardError wraps a verifyCityMMDB failure so updateOnce can
// distinguish "downloaded edition is not a City database" from other
// install failures and produce the operator-facing message that names
// the configured edition ID.
type editionGuardError struct {
	err error
}

func (e *editionGuardError) Error() string {
	return fmt.Sprintf("geoipupdate: edition guard: %v", e.err)
}

func (e *editionGuardError) Unwrap() error {
	return e.err
}

// verifyCityMMDB opens the MMDB at path and confirms it is a City-type
// database (the type Arenet's reader.City() requires). Returns an
// error for Country/ASN/other editions, or if the file cannot be
// opened as a valid MMDB at all.
func verifyCityMMDB(path string) error {
	r, err := geoip2.Open(path)
	if err != nil {
		return fmt.Errorf("open downloaded mmdb: %w", err)
	}
	defer r.Close()

	dbType := r.Metadata().DatabaseType // e.g. "GeoLite2-City", "GeoLite2-Country"
	if !isCityType(dbType) {
		return fmt.Errorf("database type %q is not a City edition", dbType)
	}
	return nil
}

// isCityType reports whether dbType (a geoip2 Metadata().DatabaseType
// value) names a City-type edition. Matches "GeoLite2-City" and
// "GeoIP2-City"; rejects "GeoLite2-Country", "GeoLite2-ASN", and
// similar non-City editions. Factored out of verifyCityMMDB so the
// accept/reject decision has a pure-logic unit test independent of
// any MMDB fixture.
func isCityType(dbType string) bool {
	return strings.Contains(dbType, "City")
}

// Status returns a thread-safe snapshot of the most recent UpdateOnce
// result. The zero value (Status == "") is returned if UpdateOnce has
// never run.
func (u *Updater) Status() UpdateResult {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status
}

// Run starts the periodic scheduler loop: it waits Config.Warmup (30s
// default) — or returns early if ctx is cancelled first — then calls
// UpdateOnce once, then re-runs UpdateOnce every interval via a
// time.Ticker until ctx is cancelled. Mirrors the lifecycle shape of
// internal/alerting/watcher.go's Watcher.Run (warmup/immediate-first-
// tick/ticker/ctx-cancel) and cmd/arenet/main.go's startUpdateLoop
// goroutine.
//
// Run is resilient: a failed UpdateOnce (StatusError, already logged
// by UpdateOnce itself) never stops the loop — only an explicit ctx
// cancellation does. Blocks until ctx is done; call it in its own
// goroutine. The loop exits solely when ctx is cancelled — callers
// that need to restart the schedule (e.g. cmd/arenet's config PUT
// hook) may call Run again on the same Updater with a fresh ctx once
// the previous call has returned.
func (u *Updater) Run(ctx context.Context, interval time.Duration) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(u.warmup):
	}

	u.UpdateOnce(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.UpdateOnce(ctx)
		}
	}
}

// md5OfFile returns the hex-encoded md5 digest of the file at path,
// or "" (with a nil error) if the file does not exist — the
// bootstrap case where no database has been installed yet.
func md5OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("geoipupdate: open %q: %w", path, err)
	}
	defer f.Close()

	h := md5.New() //nolint:gosec // see import comment.
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("geoipupdate: hash %q: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
