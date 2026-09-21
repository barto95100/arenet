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

// Package autobackup runs Arenet's scheduled backups (v2.33): on a
// daily or weekly slot it exports the configuration with its secrets,
// encrypts it with the configured passphrase, writes it atomically to
// a directory (local disk or a mounted NAS share), prunes old files,
// optionally emails it through an email alert channel, and raises an
// alert when anything fails.
package autobackup

import (
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// daysPerWeek is the period of a weekly schedule.
const daysPerWeek = 7

// LastSlot returns the most recent scheduled time at or before now,
// in now's location. It returns the zero time for an invalid config.
func LastSlot(cfg storage.BackupScheduleConfig, now time.Time) time.Time {
	h, m, err := storage.ParseBackupTime(cfg.Time)
	if err != nil {
		return time.Time{}
	}
	slot := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if cfg.Frequency == storage.BackupFrequencyWeekly {
		back := (int(now.Weekday()) - cfg.Weekday + daysPerWeek) % daysPerWeek
		slot = slot.AddDate(0, 0, -back)
		if slot.After(now) {
			slot = slot.AddDate(0, 0, -daysPerWeek)
		}
		return slot
	}
	if slot.After(now) {
		slot = slot.AddDate(0, 0, -1)
	}
	return slot
}

// NextSlot returns the first scheduled time strictly after now.
func NextSlot(cfg storage.BackupScheduleConfig, now time.Time) time.Time {
	last := LastSlot(cfg, now)
	if last.IsZero() {
		return last
	}
	if cfg.Frequency == storage.BackupFrequencyWeekly {
		return last.AddDate(0, 0, daysPerWeek)
	}
	return last.AddDate(0, 0, 1)
}

// Due reports whether a scheduled backup must run now: the last slot
// has passed since the last run. Before the first run, only a slot
// reached after activeSince (when the schedule was switched on or
// Arenet started) counts — enabling at 14:00 a 03:00 schedule does not
// back up at once; the UI offers "back up now". After that, a slot
// missed while Arenet was stopped runs once at the next check.
func Due(cfg storage.BackupScheduleConfig, lastRun *time.Time, activeSince, now time.Time) bool {
	if !cfg.Enabled {
		return false
	}
	slot := LastSlot(cfg, now)
	if slot.IsZero() {
		return false
	}
	if lastRun == nil {
		return !slot.Before(activeSince)
	}
	return lastRun.Before(slot)
}
