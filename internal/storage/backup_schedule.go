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
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Scheduled backups (v2.33). The bucket holds two singleton rows: the
// operator's config (exported in backups) and the runtime status of
// the last runs (never exported), so saving one never clobbers the
// other.

const (
	bucketBackupSchedule    = "backup_schedule"
	backupScheduleKey       = "config"
	backupScheduleStatusKey = "status"
)

// Backup schedule enums and bounds.
const (
	BackupFrequencyDaily  = "daily"
	BackupFrequencyWeekly = "weekly"

	BackupEmailNever  = "never"
	BackupEmailEach   = "each"
	BackupEmailWeekly = "weekly"

	// BackupKeepDefault is the retention of a fresh config.
	BackupKeepDefault = 14
	// BackupKeepMax bounds the retention.
	BackupKeepMax = 365
	// BackupTimeDefault is the run time of a fresh config.
	BackupTimeDefault = "03:00"
)

// BackupScheduleConfig is the scheduled-backup configuration.
type BackupScheduleConfig struct {
	Enabled   bool   `json:"enabled"`
	Frequency string `json:"frequency"` // BackupFrequency*
	// Time is "HH:MM" in the server's time zone.
	Time    string `json:"time"`
	Weekday int    `json:"weekday"` // 0=Sunday..6, weekly only
	Keep    int    `json:"keep"`    // files kept in Dir
	// Dir is an absolute directory; "" means <data-dir>/backups.
	Dir string `json:"dir"`
	// Passphrase encrypts every backup (SECRET — sealed at rest).
	Passphrase      string   `json:"passphrase"`
	EmailMode       string   `json:"emailMode"` // BackupEmail*
	EmailChannelID  string   `json:"emailChannelId"`
	AlertChannelIDs []string `json:"alertChannelIds"`
}

// BackupScheduleDefaults returns the config of a fresh install
// (disabled).
func BackupScheduleDefaults() BackupScheduleConfig {
	return BackupScheduleConfig{
		Frequency: BackupFrequencyDaily,
		Time:      BackupTimeDefault,
		Keep:      BackupKeepDefault,
		EmailMode: BackupEmailNever,
	}
}

// BackupScheduleStatus is the runtime state of scheduled backups.
type BackupScheduleStatus struct {
	LastRunAt      *time.Time `json:"lastRunAt,omitempty"`
	LastStatus     string     `json:"lastStatus,omitempty"` // "ok" | "error"
	LastError      string     `json:"lastError,omitempty"`
	LastFile       string     `json:"lastFile,omitempty"`
	LastEmailAt    *time.Time `json:"lastEmailAt,omitempty"`
	LastEmailError string     `json:"lastEmailError,omitempty"`
}

// ValidateBackupSchedule checks the shape of a config. Cross-checks
// (channels exist, directory writable, passphrase length) belong to
// the callers that know them.
func ValidateBackupSchedule(c BackupScheduleConfig) error {
	switch c.Frequency {
	case BackupFrequencyDaily, BackupFrequencyWeekly:
	default:
		return fmt.Errorf("backup_schedule: frequency %q must be %q or %q", c.Frequency, BackupFrequencyDaily, BackupFrequencyWeekly)
	}
	if _, _, err := ParseBackupTime(c.Time); err != nil {
		return err
	}
	if c.Weekday < 0 || c.Weekday > 6 {
		return fmt.Errorf("backup_schedule: weekday %d must be in [0, 6]", c.Weekday)
	}
	if c.Keep < 1 || c.Keep > BackupKeepMax {
		return fmt.Errorf("backup_schedule: keep %d must be in [1, %d]", c.Keep, BackupKeepMax)
	}
	if c.Dir != "" && !filepath.IsAbs(c.Dir) {
		return fmt.Errorf("backup_schedule: dir %q must be an absolute path", c.Dir)
	}
	switch c.EmailMode {
	case BackupEmailNever, BackupEmailEach, BackupEmailWeekly:
	default:
		return fmt.Errorf("backup_schedule: emailMode %q must be never, each or weekly", c.EmailMode)
	}
	if c.EmailMode != BackupEmailNever && c.EmailChannelID == "" {
		return errors.New("backup_schedule: an email channel is required when email is enabled")
	}
	return nil
}

// ParseBackupTime parses "HH:MM".
func ParseBackupTime(s string) (hour, minute int, err error) {
	t, perr := time.Parse("15:04", s)
	if perr != nil {
		return 0, 0, fmt.Errorf("backup_schedule: time %q must be HH:MM", s)
	}
	return t.Hour(), t.Minute(), nil
}

// GetBackupSchedule returns the config, BackupScheduleDefaults() on a
// fresh install.
func (s *Store) GetBackupSchedule(ctx context.Context) (BackupScheduleConfig, error) {
	out := BackupScheduleDefaults()
	found, err := s.getBackupScheduleRow(ctx, backupScheduleKey, &out, true)
	if err != nil {
		return BackupScheduleConfig{}, err
	}
	if !found {
		return BackupScheduleDefaults(), nil
	}
	return out, nil
}

// PutBackupSchedule validates and stores the config (the passphrase
// is sealed at rest). The status row is untouched.
func (s *Store) PutBackupSchedule(ctx context.Context, c BackupScheduleConfig) error {
	if err := ValidateBackupSchedule(c); err != nil {
		return err
	}
	buf, err := s.encodeRow(bucketBackupSchedule, c)
	if err != nil {
		return fmt.Errorf("marshal backup schedule: %w", err)
	}
	return s.putBackupScheduleRow(ctx, backupScheduleKey, buf)
}

// GetBackupScheduleStatus returns the runtime status (zero value when
// no backup ran yet).
func (s *Store) GetBackupScheduleStatus(ctx context.Context) (BackupScheduleStatus, error) {
	var out BackupScheduleStatus
	if _, err := s.getBackupScheduleRow(ctx, backupScheduleStatusKey, &out, false); err != nil {
		return BackupScheduleStatus{}, err
	}
	return out, nil
}

// PutBackupScheduleStatus stores the runtime status.
func (s *Store) PutBackupScheduleStatus(ctx context.Context, st BackupScheduleStatus) error {
	buf, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("marshal backup schedule status: %w", err)
	}
	return s.putBackupScheduleRow(ctx, backupScheduleStatusKey, buf)
}

func (s *Store) getBackupScheduleRow(ctx context.Context, key string, out any, sealed bool) (bool, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketBackupSchedule)).Get([]byte(key))
		if raw == nil {
			return nil
		}
		found = true
		if sealed {
			return s.decodeRow(bucketBackupSchedule, raw, out)
		}
		return json.Unmarshal(raw, out)
	})
	return found, err
}

func (s *Store) putBackupScheduleRow(ctx context.Context, key string, buf []byte) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketBackupSchedule)).Put([]byte(key), buf)
	})
}
