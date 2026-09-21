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

package autobackup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/backup"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/google/uuid"
)

const (
	// tickInterval is how often the loop checks for a due slot.
	tickInterval = time.Minute
	// MaxEmailAttachmentBytes caps an emailed backup; most SMTP
	// servers refuse ~25 MB and base64 inflates by a third.
	MaxEmailAttachmentBytes = 10 << 20
	// weeklyEmailPeriod is the minimum spacing of weekly emails; one
	// hour of slack absorbs slot jitter and DST shifts.
	weeklyEmailPeriod = daysPerWeek*24*time.Hour - time.Hour
	// alertCategory tags failure alerts in the alert history.
	alertCategory = "backup"
)

// Triggers recorded in the audit log.
const (
	TriggerScheduled = "scheduled"
	TriggerManual    = "manual"
)

// Run status values.
const (
	statusOK    = "ok"
	statusError = "error"
)

// ErrNoPassphrase: backups cannot run without a passphrase.
var ErrNoPassphrase = errors.New("autobackup: no backup passphrase configured")

// Mailer sends one email with an attachment.
type Mailer interface {
	SendWithAttachment(ctx context.Context, subject, body string, att alerting.EmailAttachment) error
}

// MailerFactory builds the Mailer of an email alert channel.
type MailerFactory func(ch storage.Channel) (Mailer, error)

// Dispatcher is the alerting subset used to raise failure alerts.
type Dispatcher interface {
	Dispatch(ctx context.Context, evt alerting.AlertEvent, channelIDs []string) alerting.DispatchResult
}

// AuditAppender records one audit event.
type AuditAppender interface {
	Append(ctx context.Context, evt audit.Event) error
}

// Config wires a Service.
type Config struct {
	Store   *storage.Store
	Users   backup.UserStorer
	DataDir string
	Version string
	// Optional: failure alerts / audit trail / mailer / clock.
	Dispatcher Dispatcher
	Audit      AuditAppender
	NewMailer  MailerFactory
	Now        func() time.Time
	Logger     *slog.Logger
}

// Result describes one backup run.
type Result struct {
	File       string `json:"file,omitempty"`
	Size       int    `json:"size"`
	Pruned     int    `json:"pruned"`
	Emailed    bool   `json:"emailed"`
	EmailError string `json:"emailError,omitempty"`
}

// Service schedules and runs backups.
type Service struct {
	cfg    Config
	runMu  sync.Mutex // one backup at a time
	loopMu sync.Mutex
	cancel context.CancelFunc
}

// New returns a Service; call Apply to start the schedule.
func New(c Config) *Service {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.NewMailer == nil {
		c.NewMailer = emailChannelMailer
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return &Service{cfg: c}
}

// Dir returns the directory backups go to for sched.
func (s *Service) Dir(sched storage.BackupScheduleConfig) string {
	return ResolveDir(sched.Dir, s.cfg.DataDir)
}

// Apply (re)starts the schedule loop for sched under parent; a
// disabled schedule just stops it. Safe to call on every config change.
func (s *Service) Apply(parent context.Context, sched storage.BackupScheduleConfig) {
	s.loopMu.Lock()
	defer s.loopMu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	if !sched.Enabled {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	go s.loop(ctx, s.cfg.Now())
}

// Stop stops the schedule loop.
func (s *Service) Stop() {
	s.loopMu.Lock()
	defer s.loopMu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
}

func (s *Service) loop(ctx context.Context, activeSince time.Time) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick(ctx, activeSince)
		}
	}
}

func (s *Service) tick(ctx context.Context, activeSince time.Time) {
	sched, err := s.cfg.Store.GetBackupSchedule(ctx)
	if err != nil {
		s.cfg.Logger.Warn("autobackup: read schedule", "err", err)
		return
	}
	st, err := s.cfg.Store.GetBackupScheduleStatus(ctx)
	if err != nil {
		s.cfg.Logger.Warn("autobackup: read status", "err", err)
		return
	}
	if !Due(sched, st.LastRunAt, activeSince, s.cfg.Now()) {
		return
	}
	if _, err := s.Run(ctx, TriggerScheduled); err != nil {
		s.cfg.Logger.Error("autobackup: scheduled backup failed", "err", err)
	}
}

// Run performs one backup now with the stored config, whether or not
// the schedule is enabled. The returned error covers every step
// (email included); Result.File is set when the file was written.
func (s *Service) Run(ctx context.Context, trigger string) (Result, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	now := s.cfg.Now()
	var res Result

	sched, err := s.cfg.Store.GetBackupSchedule(ctx)
	if err != nil {
		return res, fmt.Errorf("autobackup: read schedule: %w", err)
	}
	st, err := s.cfg.Store.GetBackupScheduleStatus(ctx)
	if err != nil {
		return res, fmt.Errorf("autobackup: read status: %w", err)
	}
	dir := s.Dir(sched)

	body, runErr := s.writeBackup(ctx, sched, dir, now, &res)
	if runErr == nil && wantEmail(sched.EmailMode, st.LastEmailAt, now) {
		if err := s.email(ctx, sched, res.File, body, now); err != nil {
			res.EmailError = err.Error()
			st.LastEmailError = res.EmailError
			runErr = fmt.Errorf("backup %s saved, but the email failed: %w", res.File, err)
		} else {
			res.Emailed = true
			st.LastEmailAt = &now
			st.LastEmailError = ""
		}
	}

	st.LastRunAt = &now
	st.LastFile = res.File
	if runErr != nil {
		st.LastStatus, st.LastError = statusError, runErr.Error()
	} else {
		st.LastStatus, st.LastError = statusOK, ""
	}
	if err := s.cfg.Store.PutBackupScheduleStatus(ctx, st); err != nil {
		s.cfg.Logger.Warn("autobackup: save status", "err", err)
	}
	s.audit(ctx, trigger, dir, res, runErr)
	if runErr != nil {
		s.alert(ctx, sched, trigger, dir, runErr, now)
		return res, runErr
	}
	s.cfg.Logger.Info("autobackup: backup written", "trigger", trigger, "file", res.File,
		"dir", dir, "bytes", res.Size, "pruned", res.Pruned, "emailed", res.Emailed)
	return res, nil
}

// writeBackup exports, encrypts, writes and prunes; it returns the
// bytes written (the email sends exactly those).
func (s *Service) writeBackup(ctx context.Context, sched storage.BackupScheduleConfig, dir string, now time.Time, res *Result) ([]byte, error) {
	if sched.Passphrase == "" {
		return nil, ErrNoPassphrase
	}
	if err := CheckDir(dir, sched.Dir == ""); err != nil {
		return nil, err
	}
	snap, err := backup.Export(ctx, s.cfg.Store, s.cfg.Users, s.cfg.Version, true)
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	if err := backup.SealSnapshot(snap, sched.Passphrase); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	name, err := writeAtomic(dir, now, body)
	if err != nil {
		return nil, fmt.Errorf("write backup in %s: %w", dir, err)
	}
	res.File, res.Size = name, len(body)
	pruned, err := prune(dir, sched.Keep, name)
	res.Pruned = pruned
	if err != nil {
		return body, fmt.Errorf("backup %s saved, but pruning old backups failed: %w", name, err)
	}
	return body, nil
}

// wantEmail decides whether this run is emailed.
func wantEmail(mode string, lastEmail *time.Time, now time.Time) bool {
	switch mode {
	case storage.BackupEmailEach:
		return true
	case storage.BackupEmailWeekly:
		return lastEmail == nil || now.Sub(*lastEmail) >= weeklyEmailPeriod
	}
	return false
}

func (s *Service) email(ctx context.Context, sched storage.BackupScheduleConfig, name string, body []byte, now time.Time) error {
	ch, err := s.cfg.Store.GetAlertChannel(ctx, sched.EmailChannelID)
	if err != nil {
		return fmt.Errorf("email channel: %w", err)
	}
	mailer, err := s.cfg.NewMailer(ch)
	if err != nil {
		return err
	}
	subject := "[Arenet] Configuration backup " + now.Format("2006-01-02 15:04")
	text := "Attached: the Arenet configuration backup " + name + ".\n\n" +
		"Its secrets are encrypted with the backup passphrase set in Settings > Backup.\n" +
		"To restore it: Settings > Backup > Restore, then enter the passphrase.\n"
	if len(body) > MaxEmailAttachmentBytes {
		text = "The Arenet configuration backup " + name + " was saved but is too large to attach (" +
			fmt.Sprintf("%.1f MiB, limit %d MiB", float64(len(body))/(1<<20), MaxEmailAttachmentBytes>>20) +
			"). Download it from Settings > Backup.\n"
		if err := mailer.SendWithAttachment(ctx, subject, text, alerting.EmailAttachment{
			Filename: "README.txt", ContentType: "text/plain", Data: []byte(text),
		}); err != nil {
			return err
		}
		return fmt.Errorf("backup too large to email (%d bytes > %d)", len(body), MaxEmailAttachmentBytes)
	}
	return mailer.SendWithAttachment(ctx, subject, text, alerting.EmailAttachment{
		Filename: name, ContentType: "application/json", Data: body,
	})
}

// emailChannelMailer is the production MailerFactory.
func emailChannelMailer(ch storage.Channel) (Mailer, error) {
	if ch.Kind != storage.ChannelKindEmail {
		return nil, fmt.Errorf("channel %q is not an email channel", ch.Name)
	}
	if !ch.Enabled {
		return nil, fmt.Errorf("email channel %q is disabled", ch.Name)
	}
	cfg, err := alerting.ParseEmailConfig(ch.Config)
	if err != nil {
		return nil, err
	}
	return alerting.NewEmailSender(cfg, nil), nil
}

func (s *Service) audit(ctx context.Context, trigger, dir string, res Result, runErr error) {
	if s.cfg.Audit == nil {
		return
	}
	msg := fmt.Sprintf("trigger=%s encrypted=true dir=%s file=%s bytes=%d pruned=%d emailed=%t",
		trigger, dir, res.File, res.Size, res.Pruned, res.Emailed)
	if runErr != nil {
		msg += " error=" + runErr.Error()
	}
	if err := s.cfg.Audit.Append(ctx, audit.Event{Action: audit.ActionConfigExported, TargetType: "backup", TargetID: res.File, Message: msg}); err != nil {
		s.cfg.Logger.Warn("autobackup: audit", "err", err)
	}
}

// alert raises a failure event: always in the alert history (bell),
// and on the configured channels.
func (s *Service) alert(ctx context.Context, sched storage.BackupScheduleConfig, trigger, dir string, runErr error, now time.Time) {
	if s.cfg.Dispatcher == nil {
		return
	}
	evt := alerting.AlertEvent{
		ID:        uuid.NewString(),
		Timestamp: now,
		RuleName:  "Scheduled backup",
		Severity:  alerting.SeverityWarning,
		Category:  alertCategory,
		Subject:   "Arenet backup failed",
		Body:      runErr.Error(),
		Context:   map[string]any{"trigger": trigger, "dir": dir},
	}
	s.cfg.Dispatcher.Dispatch(ctx, evt, sched.AlertChannelIDs)
}
