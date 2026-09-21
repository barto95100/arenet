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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	"unicode/utf8"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/autobackup"
	"github.com/barto95100/arenet/internal/backup"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/go-chi/chi/v5"
)

// Scheduled backups (v2.33) — admin endpoints:
//   GET/PUT /settings/backup-schedule   config (passphrase write-only)
//   POST    /admin/backups/run          back up now
//   GET     /admin/backups              list the backup directory
//   GET     /admin/backups/{name}       download one backup
//   DELETE  /admin/backups/{name}       delete one backup
//   POST    /admin/backups/{name}/restore  restore it (stored passphrase)

const (
	codeBackupDirUnwritable = "backup_dir_unwritable"
	codeBackupFailed        = "backup_failed"
	codeBackupUnavailable   = "backup_schedule_unavailable"
	// maxBackupFileBytes bounds a backup read back from the directory
	// (same ceiling as POST /admin/restore).
	maxBackupFileBytes = 64 << 20
	// maxScheduleRequestBytes bounds the PUT body.
	maxScheduleRequestBytes = 16 << 10
)

// AutoBackupRunner is the autobackup.Service subset the API uses.
type AutoBackupRunner interface {
	Run(ctx context.Context, trigger string) (autobackup.Result, error)
	Dir(sched storage.BackupScheduleConfig) string
}

// SetAutoBackup wires scheduled backups: runner runs them, onChange
// (re)applies the schedule after a PUT or a restore.
func (h *Handler) SetAutoBackup(runner AutoBackupRunner, onChange func(storage.BackupScheduleConfig)) {
	h.autoBackup = runner
	h.onBackupScheduleChange = onChange
}

// backupScheduleResponse is the GET / PUT response.
type backupScheduleResponse struct {
	Enabled         bool                         `json:"enabled"`
	Frequency       string                       `json:"frequency"`
	Time            string                       `json:"time"`
	Weekday         int                          `json:"weekday"`
	Keep            int                          `json:"keep"`
	Dir             string                       `json:"dir"`
	EffectiveDir    string                       `json:"effectiveDir"`
	PassphraseSet   bool                         `json:"passphraseSet"`
	EmailMode       string                       `json:"emailMode"`
	EmailChannelID  string                       `json:"emailChannelId"`
	AlertChannelIDs []string                     `json:"alertChannelIds"`
	TimeZone        string                       `json:"timeZone"`
	NextRunAt       *time.Time                   `json:"nextRunAt,omitempty"`
	Status          storage.BackupScheduleStatus `json:"status"`
}

// backupScheduleRequest is the PUT body; an empty passphrase keeps
// the stored one.
type backupScheduleRequest struct {
	Enabled         bool     `json:"enabled"`
	Frequency       string   `json:"frequency"`
	Time            string   `json:"time"`
	Weekday         int      `json:"weekday"`
	Keep            int      `json:"keep"`
	Dir             string   `json:"dir"`
	Passphrase      string   `json:"passphrase"`
	EmailMode       string   `json:"emailMode"`
	EmailChannelID  string   `json:"emailChannelId"`
	AlertChannelIDs []string `json:"alertChannelIds"`
}

// serverTimeZone describes the zone schedules run in, e.g.
// "UTC+02:00 (CEST)" — in Docker it is UTC unless TZ is set.
func serverTimeZone(now time.Time) string {
	name, off := now.Zone()
	sign := "+"
	if off < 0 {
		sign, off = "-", -off
	}
	return fmt.Sprintf("UTC%s%02d:%02d (%s)", sign, off/3600, off%3600/60, name)
}

func (h *Handler) backupScheduleView(ctx context.Context, cfg storage.BackupScheduleConfig) (backupScheduleResponse, error) {
	st, err := h.store.GetBackupScheduleStatus(ctx)
	if err != nil {
		return backupScheduleResponse{}, err
	}
	now := time.Now()
	resp := backupScheduleResponse{
		Enabled: cfg.Enabled, Frequency: cfg.Frequency, Time: cfg.Time, Weekday: cfg.Weekday,
		Keep: cfg.Keep, Dir: cfg.Dir, EffectiveDir: h.autoBackup.Dir(cfg),
		PassphraseSet: cfg.Passphrase != "", EmailMode: cfg.EmailMode,
		EmailChannelID: cfg.EmailChannelID, AlertChannelIDs: cfg.AlertChannelIDs,
		TimeZone: serverTimeZone(now), Status: st,
	}
	if resp.AlertChannelIDs == nil {
		resp.AlertChannelIDs = []string{}
	}
	if cfg.Enabled {
		next := autobackup.NextSlot(cfg, now)
		resp.NextRunAt = &next
	}
	return resp, nil
}

func (h *Handler) requireAutoBackup(w http.ResponseWriter) bool {
	if h.autoBackup == nil {
		writeErrorCode(w, http.StatusConflict, codeBackupUnavailable, "scheduled backups are not available", nil)
		return false
	}
	return true
}

// getBackupSchedule handles GET /settings/backup-schedule.
func (h *Handler) getBackupSchedule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutoBackup(w) {
		return
	}
	cfg, err := h.store.GetBackupSchedule(r.Context())
	if err != nil {
		h.logger.Error("backup schedule: read", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to read the backup schedule")
		return
	}
	resp, err := h.backupScheduleView(r.Context(), cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the backup status")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// putBackupSchedule handles PUT /settings/backup-schedule.
func (h *Handler) putBackupSchedule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutoBackup(w) {
		return
	}
	var req backupScheduleRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxScheduleRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	ctx := r.Context()
	previous, err := h.store.GetBackupSchedule(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the backup schedule")
		return
	}
	cfg := storage.BackupScheduleConfig{
		Enabled: req.Enabled, Frequency: req.Frequency, Time: req.Time, Weekday: req.Weekday,
		Keep: req.Keep, Dir: req.Dir, Passphrase: previous.Passphrase,
		EmailMode: req.EmailMode, EmailChannelID: req.EmailChannelID, AlertChannelIDs: req.AlertChannelIDs,
	}
	if req.Passphrase != "" {
		if utf8.RuneCountInString(req.Passphrase) < backup.MinPassphraseLen {
			writeErrorCode(w, http.StatusBadRequest, codePassphraseTooShort, backup.ErrPassphraseTooShort.Error(),
				map[string]any{"min": backup.MinPassphraseLen})
			return
		}
		cfg.Passphrase = req.Passphrase
	}
	if err := storage.ValidateBackupSchedule(cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if cfg.Enabled && cfg.Passphrase == "" {
		writeErrorCode(w, http.StatusBadRequest, codePassphraseRequired, "scheduled backups need a passphrase", nil)
		return
	}
	if err := h.checkBackupChannels(ctx, cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dir := h.autoBackup.Dir(cfg)
	if err := autobackup.CheckDir(dir, cfg.Dir == ""); err != nil {
		writeErrorCode(w, http.StatusBadRequest, codeBackupDirUnwritable, err.Error(), map[string]any{"dir": dir})
		return
	}
	if err := h.store.PutBackupSchedule(ctx, cfg); err != nil {
		h.logger.Error("backup schedule: save", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to save the backup schedule")
		return
	}
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionBackupScheduleUpdated,
		TargetType: "backup_schedule",
		TargetID:   "config",
		BeforeJSON: mustMarshalForAudit(backupScheduleForAudit(previous)),
		AfterJSON:  mustMarshalForAudit(backupScheduleForAudit(cfg)),
	})
	if h.onBackupScheduleChange != nil {
		h.onBackupScheduleChange(cfg)
	}
	resp, err := h.backupScheduleView(ctx, cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the backup status")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// backupScheduleForAudit hides the passphrase (only whether one is set).
func backupScheduleForAudit(c storage.BackupScheduleConfig) storage.BackupScheduleConfig {
	if c.Passphrase != "" {
		c.Passphrase = auditRedacted
	}
	return c
}

// checkBackupChannels verifies the email channel (kind email) and the
// alert channels exist.
func (h *Handler) checkBackupChannels(ctx context.Context, cfg storage.BackupScheduleConfig) error {
	if cfg.EmailMode != storage.BackupEmailNever {
		ch, err := h.store.GetAlertChannel(ctx, cfg.EmailChannelID)
		if err != nil {
			return fmt.Errorf("email channel %q not found", cfg.EmailChannelID)
		}
		if ch.Kind != storage.ChannelKindEmail {
			return fmt.Errorf("channel %q is not an email channel", ch.Name)
		}
	}
	for _, id := range cfg.AlertChannelIDs {
		if _, err := h.store.GetAlertChannel(ctx, id); err != nil {
			return fmt.Errorf("alert channel %q not found", id)
		}
	}
	return nil
}

// runBackupNow handles POST /admin/backups/run.
func (h *Handler) runBackupNow(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutoBackup(w) {
		return
	}
	res, err := h.autoBackup.Run(r.Context(), autobackup.TriggerManual)
	if err != nil {
		writeErrorCode(w, http.StatusInternalServerError, codeBackupFailed, err.Error(),
			map[string]any{"file": res.File})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// backupDir resolves the directory of the stored schedule.
func (h *Handler) backupDir(ctx context.Context) (string, storage.BackupScheduleConfig, error) {
	cfg, err := h.store.GetBackupSchedule(ctx)
	if err != nil {
		return "", cfg, err
	}
	return h.autoBackup.Dir(cfg), cfg, nil
}

// listBackups handles GET /admin/backups.
func (h *Handler) listBackups(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutoBackup(w) {
		return
	}
	dir, _, err := h.backupDir(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the backup schedule")
		return
	}
	files, err := autobackup.List(dir)
	if err != nil {
		writeErrorCode(w, http.StatusInternalServerError, codeBackupDirUnwritable, err.Error(), map[string]any{"dir": dir})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dir": dir, "files": files})
}

// backupFilePath validates {name} and resolves it (404 on a bad name,
// so a traversal attempt learns nothing).
func (h *Handler) backupFilePath(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	name := chi.URLParam(r, "name")
	dir, _, err := h.backupDir(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the backup schedule")
		return "", "", false
	}
	p, err := autobackup.Path(dir, name)
	if err != nil {
		writeError(w, http.StatusNotFound, "backup not found")
		return "", "", false
	}
	return p, name, true
}

// downloadBackup handles GET /admin/backups/{name}.
func (h *Handler) downloadBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutoBackup(w) {
		return
	}
	p, name, ok := h.backupFilePath(w, r)
	if !ok {
		return
	}
	f, err := os.Open(p)
	if err != nil {
		writeError(w, http.StatusNotFound, "backup not found")
		return
	}
	defer func() { _ = f.Close() }()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// deleteBackup handles DELETE /admin/backups/{name}.
func (h *Handler) deleteBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutoBackup(w) {
		return
	}
	p, name, ok := h.backupFilePath(w, r)
	if !ok {
		return
	}
	if err := os.Remove(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "backup not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete the backup")
		return
	}
	h.appendAudit(r, audit.Event{Action: audit.ActionBackupDeleted, TargetType: "backup", TargetID: name})
	w.WriteHeader(http.StatusNoContent)
}

// restoreScheduledBackup handles POST /admin/backups/{name}/restore:
// the regular restore pipeline, decrypting with the stored passphrase
// unless the request carries X-Arenet-Backup-Passphrase (a file made
// before the passphrase was changed).
func (h *Handler) restoreScheduledBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutoBackup(w) {
		return
	}
	p, _, ok := h.backupFilePath(w, r)
	if !ok {
		return
	}
	f, err := os.Open(p)
	if err != nil {
		writeError(w, http.StatusNotFound, "backup not found")
		return
	}
	body, err := io.ReadAll(io.LimitReader(f, maxBackupFileBytes))
	_ = f.Close()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the backup")
		return
	}
	cfg, err := h.store.GetBackupSchedule(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the backup schedule")
		return
	}
	h.restoreBytes(w, r, body, cfg.Passphrase)
}
