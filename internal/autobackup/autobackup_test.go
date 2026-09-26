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

package autobackup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/backup"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/google/uuid"
)

var paris = func() *time.Location {
	l, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		panic(err)
	}
	return l
}()

func at(s string) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04", s, paris)
	if err != nil {
		panic(err)
	}
	return t
}

func daily(hhmm string) storage.BackupScheduleConfig {
	c := storage.BackupScheduleDefaults()
	c.Enabled, c.Time = true, hhmm
	return c
}

func TestLastAndNextSlot(t *testing.T) {
	d := daily("03:00")
	if got := LastSlot(d, at("2026-09-21 02:59")); !got.Equal(at("2026-09-20 03:00")) {
		t.Errorf("daily before slot: %v", got)
	}
	if got := LastSlot(d, at("2026-09-21 03:00")); !got.Equal(at("2026-09-21 03:00")) {
		t.Errorf("daily at slot: %v", got)
	}
	if got := NextSlot(d, at("2026-09-21 03:00")); !got.Equal(at("2026-09-22 03:00")) {
		t.Errorf("daily next: %v", got)
	}
	w := d
	w.Frequency, w.Weekday = storage.BackupFrequencyWeekly, int(time.Sunday)
	// 2026-09-21 is a Monday.
	if got := LastSlot(w, at("2026-09-21 12:00")); !got.Equal(at("2026-09-20 03:00")) {
		t.Errorf("weekly last: %v", got)
	}
	if got := NextSlot(w, at("2026-09-21 12:00")); !got.Equal(at("2026-09-27 03:00")) {
		t.Errorf("weekly next: %v", got)
	}
	if got := LastSlot(w, at("2026-09-20 02:00")); !got.Equal(at("2026-09-13 03:00")) {
		t.Errorf("weekly same day before time: %v", got)
	}
	// DST end in Paris: 2026-10-25 — the slot keeps its wall-clock time.
	if got := LastSlot(d, at("2026-10-25 12:00")); got.Hour() != 3 || got.Day() != 25 {
		t.Errorf("DST day slot: %v", got)
	}
}

func TestDue(t *testing.T) {
	d := daily("03:00")
	enabled := at("2026-09-21 14:00")
	if Due(d, nil, enabled, at("2026-09-21 14:01")) {
		t.Error("enabling after today's slot must not back up at once")
	}
	if !Due(d, nil, enabled, at("2026-09-22 03:00")) {
		t.Error("first slot after enabling must run")
	}
	last := at("2026-09-22 03:00")
	if Due(d, &last, enabled, at("2026-09-22 10:00")) {
		t.Error("already ran for this slot")
	}
	if !Due(d, &last, enabled, at("2026-09-24 09:00")) {
		t.Error("missed slot (Arenet stopped) must be caught up")
	}
	off := d
	off.Enabled = false
	if Due(off, nil, enabled, at("2026-09-22 03:00")) {
		t.Error("disabled schedule ran")
	}
}

func TestValidNameAndPath(t *testing.T) {
	for _, bad := range []string{"../arenet.db", "arenet.key", "arenet-backup-auto-20260921-030000.json/../x",
		"arenet-backup-auto-2026-09-21.json", "/etc/passwd", "arenet-backup-auto-20260921-030000.json.tmp"} {
		if ValidName(bad) {
			t.Errorf("accepted %q", bad)
		}
		if _, err := Path("/d", bad); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Path(%q) = %v", bad, err)
		}
	}
	for _, ok := range []string{"arenet-backup-auto-20260921-030000.json", "arenet-backup-auto-20260921-030000-2.json"} {
		if !ValidName(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
}

func TestWriteAtomicAndPrune(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "keep-me.json")
	_ = os.WriteFile(other, []byte("x"), 0o600)
	base := at("2026-09-01 03:00")
	for i := 0; i < 5; i++ {
		name, err := writeAtomic(dir, base.AddDate(0, 0, i), []byte("{}"))
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		info, _ := os.Stat(filepath.Join(dir, name))
		if info.Mode().Perm() != fileMode {
			t.Errorf("mode %o", info.Mode().Perm())
		}
		// Scrambled mtimes (NAS copy, clock skew) must not matter.
		ts := base.AddDate(0, 0, -i)
		_ = os.Chtimes(filepath.Join(dir, name), ts, ts)
	}
	// Same second twice → suffixed, never overwritten.
	if name, _ := writeAtomic(dir, base, []byte("{}")); !strings.HasSuffix(name, "-1.json") {
		t.Errorf("collision name %q", name)
	}
	n, err := prune(dir, 3, "arenet-backup-auto-20260901-030000.json")
	if err != nil || n != 2 {
		t.Fatalf("prune = %d, %v", n, err)
	}
	files, _ := List(dir)
	// Newest by name, whatever the mtimes; the just-written file (the
	// oldest name here) is never pruned.
	if len(files) != 4 || files[0].Name != "arenet-backup-auto-20260905-030000.json" || files[3].Name != "arenet-backup-auto-20260901-030000.json" {
		t.Errorf("kept %+v", files)
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("prune touched a file that is not a scheduled backup")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temporary file left: %s", e.Name())
		}
	}
}

func TestCheckDir(t *testing.T) {
	root := t.TempDir()
	if err := CheckDir(filepath.Join(root, "missing"), false); err == nil {
		t.Error("a missing custom dir (unmounted NAS) must be reported")
	}
	if err := CheckDir(filepath.Join(root, "default"), true); err != nil {
		t.Errorf("default dir not created: %v", err)
	}
	ro := filepath.Join(root, "ro")
	_ = os.Mkdir(ro, 0o500)
	if os.Geteuid() != 0 {
		if err := CheckDir(ro, false); err == nil || !strings.Contains(err.Error(), "cannot write") {
			t.Errorf("read-only dir: %v", err)
		}
	}
	file := filepath.Join(root, "f")
	_ = os.WriteFile(file, nil, 0o600)
	if err := CheckDir(file, false); err == nil {
		t.Error("a file is not a directory")
	}
}

// --- Service ---

type fakeMailer struct {
	mu     sync.Mutex
	sent   []alerting.EmailAttachment
	fail   error
	bodies []string
}

func (f *fakeMailer) SendWithAttachment(_ context.Context, _, body string, att alerting.EmailAttachment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.sent = append(f.sent, att)
	f.bodies = append(f.bodies, body)
	return nil
}

type fakeDispatcher struct {
	events   []alerting.AlertEvent
	channels [][]string
}

func (f *fakeDispatcher) Dispatch(_ context.Context, evt alerting.AlertEvent, ids []string) alerting.DispatchResult {
	f.events = append(f.events, evt)
	f.channels = append(f.channels, ids)
	return alerting.DispatchResult{}
}

type env struct {
	store  *storage.Store
	users  *auth.UserStore
	svc    *Service
	mail   *fakeMailer
	disp   *fakeDispatcher
	now    time.Time
	dir    string
	chanID string
}

const testPass = "a long backup passphrase"

func newEnv(t *testing.T) *env {
	t.Helper()
	data := t.TempDir()
	store, err := storage.NewStore(filepath.Join(data, "arenet.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	users := auth.NewUserStore(store.DB())
	if _, err := users.Create(context.Background(), "alice", "Alice", "", "alice-password-15c-xx"); err != nil {
		t.Fatalf("user: %v", err)
	}
	cfg, _ := json.Marshal(map[string]any{"smtpHost": "smtp.example.com", "smtpPort": 587, "from": "a@example.com", "to": []string{"b@example.com"}})
	ch, err := store.CreateAlertChannel(context.Background(), storage.Channel{ID: uuid.NewString(), Name: "mail", Kind: storage.ChannelKindEmail, Enabled: true, Config: cfg})
	if err != nil {
		t.Fatalf("channel: %v", err)
	}
	e := &env{store: store, users: users, mail: &fakeMailer{}, disp: &fakeDispatcher{}, now: at("2026-09-21 03:00"), chanID: ch.ID}
	e.svc = New(Config{
		Store: store, Users: users, DataDir: data, Version: "test",
		Dispatcher: e.disp,
		NewMailer:  func(storage.Channel) (Mailer, error) { return e.mail, nil },
		Now:        func() time.Time { return e.now },
	})
	e.dir = filepath.Join(data, DefaultDirName)
	return e
}

func (e *env) schedule(t *testing.T, mutate func(*storage.BackupScheduleConfig)) {
	t.Helper()
	c := daily("03:00")
	c.Passphrase = testPass
	c.Keep = 2
	mutate(&c)
	if err := e.store.PutBackupSchedule(context.Background(), c); err != nil {
		t.Fatalf("put schedule: %v", err)
	}
}

func TestRun_WritesRestorableEncryptedBackup(t *testing.T) {
	e := newEnv(t)
	e.schedule(t, func(c *storage.BackupScheduleConfig) {})
	res, err := e.svc.Run(context.Background(), TriggerManual)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(e.dir, res.File))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var snap backup.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil || !snap.IsEncrypted() {
		t.Fatalf("not an encrypted backup: %v", err)
	}
	if strings.Contains(string(raw), testPass) {
		t.Error("the passphrase leaked into the backup")
	}
	if err := backup.OpenSnapshot(&snap, testPass); err != nil {
		t.Fatalf("open: %v", err)
	}
	if snap.Extras == nil || snap.Extras.BackupSchedule == nil || snap.Extras.BackupSchedule.Passphrase != testPass {
		t.Error("the schedule (with its passphrase) should travel in the backup")
	}
	st, _ := e.store.GetBackupScheduleStatus(context.Background())
	if st.LastStatus != statusOK || st.LastFile != res.File || st.LastRunAt == nil {
		t.Errorf("status %+v", st)
	}
	if len(e.mail.sent) != 0 {
		t.Error("email mode never sent an email")
	}
}

func TestRun_RetentionAndEmailModes(t *testing.T) {
	e := newEnv(t)
	e.schedule(t, func(c *storage.BackupScheduleConfig) {
		c.EmailMode, c.EmailChannelID = storage.BackupEmailWeekly, e.chanID
	})
	for i := 0; i < 4; i++ {
		e.now = at("2026-09-21 03:00").AddDate(0, 0, i)
		if _, err := e.svc.Run(context.Background(), TriggerScheduled); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	files, _ := List(e.dir)
	if len(files) != 2 {
		t.Errorf("retention kept %d files, want 2", len(files))
	}
	if len(e.mail.sent) != 1 {
		t.Errorf("weekly mode sent %d emails over 4 days, want 1", len(e.mail.sent))
	}
	e.now = at("2026-09-28 03:00")
	if _, err := e.svc.Run(context.Background(), TriggerScheduled); err != nil {
		t.Fatalf("run a week later: %v", err)
	}
	if len(e.mail.sent) != 2 {
		t.Errorf("a week later: %d emails, want 2", len(e.mail.sent))
	}
	if att := e.mail.sent[1]; !ValidName(att.Filename) || att.ContentType != "application/json" {
		t.Errorf("attachment %s %s", att.Filename, att.ContentType)
	}
}

func TestRun_FailuresAlertAndRecord(t *testing.T) {
	e := newEnv(t)
	// No passphrase → nothing written, alert raised.
	e.schedule(t, func(c *storage.BackupScheduleConfig) {
		c.Enabled = false
		c.Passphrase = ""
		c.AlertChannelIDs = []string{e.chanID}
	})
	if _, err := e.svc.Run(context.Background(), TriggerManual); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("no passphrase: %v", err)
	}
	if len(e.disp.events) != 1 || e.disp.events[0].Category != alertCategory || e.disp.channels[0][0] != e.chanID {
		t.Errorf("alert %+v %v", e.disp.events, e.disp.channels)
	}
	st, _ := e.store.GetBackupScheduleStatus(context.Background())
	if st.LastStatus != statusError || !strings.Contains(st.LastError, "passphrase") {
		t.Errorf("status %+v", st)
	}

	// Email failure: the file is kept, the run reports the error.
	e.schedule(t, func(c *storage.BackupScheduleConfig) {
		c.EmailMode, c.EmailChannelID = storage.BackupEmailEach, e.chanID
	})
	e.mail.fail = errors.New("smtp down")
	res, err := e.svc.Run(context.Background(), TriggerManual)
	if err == nil || res.File == "" || !strings.Contains(err.Error(), "email failed") {
		t.Fatalf("email failure: res=%+v err=%v", res, err)
	}
	if _, statErr := os.Stat(filepath.Join(e.dir, res.File)); statErr != nil {
		t.Error("the backup file must be kept when only the email fails")
	}
	if len(e.disp.events) != 2 {
		t.Errorf("email failure not alerted: %d events", len(e.disp.events))
	}

	// Custom dir that does not exist (unmounted NAS): reported, no
	// fallback to the local disk.
	e.schedule(t, func(c *storage.BackupScheduleConfig) { c.Dir = filepath.Join(t.TempDir(), "nas-not-mounted") })
	if _, err := e.svc.Run(context.Background(), TriggerManual); err == nil || !strings.Contains(err.Error(), "cannot access") {
		t.Errorf("missing NAS dir: %v", err)
	}
}

func TestRun_TooLargeForEmail(t *testing.T) {
	e := newEnv(t)
	e.schedule(t, func(c *storage.BackupScheduleConfig) {
		c.EmailMode, c.EmailChannelID = storage.BackupEmailEach, e.chanID
	})
	big := strings.Repeat("x", MaxEmailAttachmentBytes)
	tmpl := storage.ErrorPageTemplate{ID: uuid.NewString(), Name: "big", Pages: map[int]string{404: big[:1<<20]}}
	for i := 0; i < 11; i++ {
		tmpl.ID, tmpl.Name = uuid.NewString(), "big"+strings.Repeat("x", i)
		if _, err := e.store.CreateErrorPageTemplate(context.Background(), tmpl); err != nil {
			t.Fatalf("template: %v", err)
		}
	}
	res, err := e.svc.Run(context.Background(), TriggerManual)
	if err == nil || !strings.Contains(err.Error(), "too large") || res.File == "" {
		t.Fatalf("too large: res=%+v err=%v", res, err)
	}
	if len(e.mail.sent) != 1 || e.mail.sent[0].ContentType != "text/plain" || !strings.Contains(e.mail.bodies[0], "too large") {
		t.Errorf("notice email: %+v", e.mail.sent)
	}
}
