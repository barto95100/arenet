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

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/automation"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/google/uuid"
)

// Secret values seeded by seedExtras; none may appear in a
// no-secrets export.
const (
	extSMTPPassword  = "smtp-secret-pw"
	extWebhookURL    = "https://discord.example/api/webhooks/123/very-secret"
	extWebhookHeader = "Bearer webhook-header-secret"
	extCrowdSecKey   = "crowdsec-bouncer-key-secret"
	extWatcherPass   = "watcher-password-secret"
	extSchedulePass  = "schedule-passphrase-secret"
)

type seededExtras struct {
	admin       auth.User
	service     auth.User
	tokenPlain  string
	token       auth.APIToken
	dnsID       string
	webhookID   string
	emailID     string
	ruleID      string
	templateID  string
	managedApex string
}

// seedExtras populates every extras area of the store.
func seedExtras(t *testing.T, store *storage.Store, us *auth.UserStore) seededExtras {
	t.Helper()
	ctx := context.Background()
	var s seededExtras
	s.admin = seedLiveUser(t, us, "alice", "alice-password-15c-xx")

	var err error
	if s.service, err = us.CreateServiceAccount(ctx, "n8n", auth.UserRoleViewer); err != nil {
		t.Fatalf("service account: %v", err)
	}
	ts := auth.NewAPITokenStore(store.DB())
	if s.tokenPlain, s.token, err = ts.CreateToken(ctx, s.service.ID, "n8n-prod", s.admin.ID, nil); err != nil {
		t.Fatalf("token: %v", err)
	}
	if err := ts.TouchLastUsed(ctx, s.token.ID); err != nil {
		t.Fatalf("touch token: %v", err)
	}

	dns, err := store.CreateDNSProvider(ctx, storage.DNSProviderConfig{
		ID: uuid.NewString(), Label: "cf", Type: "cloudflare",
		Credentials: map[string]string{"api_token": "cf-token"},
	})
	if err != nil {
		t.Fatalf("dns provider: %v", err)
	}
	s.dnsID = dns.ID
	s.managedApex = "example.com"
	if err := store.PutManagedDomain(ctx, storage.ManagedDomain{Apex: s.managedApex, IncludeApex: true, ProviderID: dns.ID}); err != nil {
		t.Fatalf("managed domain: %v", err)
	}

	tmpl, err := store.CreateErrorPageTemplate(ctx, storage.ErrorPageTemplate{
		ID: uuid.NewString(), Name: "brand", Pages: map[int]string{404: "<h1>nope</h1>"}, IsCatchallDefault: true,
	})
	if err != nil {
		t.Fatalf("error template: %v", err)
	}
	s.templateID = tmpl.ID
	if err := store.PutMaintenancePageConfig(ctx, storage.MaintenancePageConfig{Message: "back soon"}); err != nil {
		t.Fatalf("maintenance: %v", err)
	}

	webhookCfg, _ := json.Marshal(map[string]any{
		"url": extWebhookURL, "method": "POST", "timeoutSeconds": 10,
		"headers": map[string]string{"Authorization": extWebhookHeader},
	})
	wh, err := store.CreateAlertChannel(ctx, storage.Channel{
		ID: uuid.NewString(), Name: "discord", Kind: storage.ChannelKindWebhook, Enabled: true, Config: webhookCfg,
	})
	if err != nil {
		t.Fatalf("webhook channel: %v", err)
	}
	s.webhookID = wh.ID
	emailCfg, _ := json.Marshal(map[string]any{
		"smtpHost": "smtp.example.com", "smtpPort": 587, "smtpUsername": "ops",
		"smtpPassword": extSMTPPassword, "from": "arenet@example.com", "to": []string{"ops@example.com"},
		"useStartTLS": true,
	})
	em, err := store.CreateAlertChannel(ctx, storage.Channel{
		ID: uuid.NewString(), Name: "mail", Kind: storage.ChannelKindEmail, Enabled: true, Config: emailCfg,
	})
	if err != nil {
		t.Fatalf("email channel: %v", err)
	}
	s.emailID = em.ID
	rule, err := store.CreateAlertRule(ctx, storage.AlertRule{
		ID: uuid.NewString(), Name: "waf-spike", Enabled: true, Kind: "threshold", Source: "waf",
		Channels: []string{wh.ID, em.ID}, CooldownSecs: 300, LastError: "runtime noise",
	})
	if err != nil {
		t.Fatalf("alert rule: %v", err)
	}
	s.ruleID = rule.ID

	if err := store.PutCrowdSecConfig(ctx, storage.CrowdSecConfig{
		LAPIURL: "http://crowdsec:8080/", APIKey: extCrowdSecKey, BouncerName: "arenet",
	}); err != nil {
		t.Fatalf("crowdsec: %v", err)
	}
	if err := store.PutWatcherCredentials(ctx, storage.WatcherCredentials{
		LAPIURL: "http://crowdsec:8080/", MachineID: "arenet-watcher", Password: extWatcherPass,
	}); err != nil {
		t.Fatalf("watcher: %v", err)
	}
	rules, _ := json.Marshal(struct {
		Rules automation.RuleSet `json:"rules"`
	}{automation.DefaultRuleSet()})
	if err := store.PutAutomationRulesRaw(ctx, rules); err != nil {
		t.Fatalf("automation rules: %v", err)
	}
	if err := store.PutUpdateCheckConfig(ctx, storage.UpdateCheckConfig{Enabled: true, IntervalOverride: "12h0m0s"}); err != nil {
		t.Fatalf("update check: %v", err)
	}
	if err := store.PutGeoIPUpdateConfig(ctx, storage.GeoIPUpdateConfig{Enabled: true}); err != nil {
		t.Fatalf("geoip update: %v", err)
	}
	if err := store.PutBackupSchedule(ctx, storage.BackupScheduleConfig{
		Enabled: true, Frequency: storage.BackupFrequencyWeekly, Time: "02:30", Weekday: 1, Keep: 7,
		Dir: "/mnt/nas/arenet", Passphrase: extSchedulePass,
		EmailMode: storage.BackupEmailWeekly, EmailChannelID: em.ID, AlertChannelIDs: []string{wh.ID},
	}); err != nil {
		t.Fatalf("backup schedule: %v", err)
	}
	if err := store.PutServerPosition(ctx, storage.ServerPositionRecord{
		Lat: 48.85, Lon: 2.35, City: "Paris", Country: "FR", Mode: serverPositionManual, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("server position: %v", err)
	}
	return s
}

func TestExtras_RoundTrip_IncludeSecrets_FreshTarget(t *testing.T) {
	ctx := context.Background()
	src, srcUsers := newTestStoreWithUserStore(t)
	seeded := seedExtras(t, src, srcUsers)

	snap, err := Export(ctx, src, srcUsers, "test", true)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if snap.Extras == nil {
		t.Fatal("export carries no extras section")
	}
	if got := snap.Extras.APITokens[0].LastUsedAt; got != nil {
		t.Errorf("token last_used_at exported: %v", got)
	}
	if got := snap.Extras.AlertRules[0].LastError; got != "" {
		t.Errorf("rule runtime last_error exported: %q", got)
	}
	// Round-trip through JSON, as the file does.
	body, _ := json.Marshal(snap)
	var decoded Snapshot
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}

	dst, dstUsers := newTestStoreWithUserStore(t)
	report, err := Import(ctx, dst, dstUsers, &decoded, ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !report.ExtrasImported || report.APITokensImported != 1 || report.AlertChannelsImported != 2 ||
		report.AlertRulesImported != 1 || report.ManagedDomainsImported != 1 || report.ErrorTemplatesImported != 1 {
		t.Errorf("report counts: %+v", report)
	}

	// The service-account token authenticates on the target.
	got, err := auth.NewAPITokenStore(dst.DB()).LookupToken(ctx, seeded.tokenPlain)
	if err != nil || got.ID != seeded.token.ID {
		t.Fatalf("restored token lookup: %v (id %q)", err, got.ID)
	}
	if md, err := dst.GetManagedDomain(ctx, seeded.managedApex); err != nil || md.ProviderID != seeded.dnsID {
		t.Errorf("managed domain: %+v %v", md, err)
	}
	if tmpl, err := dst.GetErrorPageTemplate(ctx, seeded.templateID); err != nil || !tmpl.IsCatchallDefault {
		t.Errorf("error template: %+v %v", tmpl, err)
	}
	if mp, _ := dst.GetMaintenancePageConfig(ctx); mp.Message != "back soon" {
		t.Errorf("maintenance page: %+v", mp)
	}
	wh, err := dst.GetAlertChannel(ctx, seeded.webhookID)
	if err != nil || !strings.Contains(string(wh.Config), extWebhookURL) || !strings.Contains(string(wh.Config), extWebhookHeader) {
		t.Errorf("webhook channel: %s %v", wh.Config, err)
	}
	if rule, err := dst.GetAlertRule(ctx, seeded.ruleID); err != nil || len(rule.Channels) != 2 {
		t.Errorf("alert rule: %+v %v", rule, err)
	}
	if cs, _ := dst.GetCrowdSecConfig(ctx); cs.APIKey != extCrowdSecKey {
		t.Errorf("crowdsec key: %q", cs.APIKey)
	}
	if wc, _ := dst.GetWatcherCredentials(ctx); wc.Password != extWatcherPass {
		t.Errorf("watcher password: %q", wc.Password)
	}
	if _, err := dst.GetAutomationRulesRaw(ctx); err != nil {
		t.Errorf("automation rules: %v", err)
	}
	if uc, _ := dst.GetUpdateCheckConfig(ctx); !uc.Enabled || uc.IntervalOverride != "12h0m0s" {
		t.Errorf("update check: %+v", uc)
	}
	if gu, _ := dst.GetGeoIPUpdateConfig(ctx); !gu.Enabled {
		t.Errorf("geoip update: %+v", gu)
	}
	if sp, err := dst.GetServerPosition(ctx); err != nil || sp.City != "Paris" {
		t.Errorf("server position: %+v %v", sp, err)
	}
	if bs, _ := dst.GetBackupSchedule(ctx); !bs.Enabled || bs.Passphrase != extSchedulePass || bs.Dir != "/mnt/nas/arenet" {
		t.Errorf("backup schedule: %+v", bs)
	}
}

func TestExtras_DefaultExportRedactsEverySecret(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	seeded := seedExtras(t, store, us)

	snap, err := Export(context.Background(), store, us, "test", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	body, _ := json.Marshal(snap)
	for _, secret := range []string{extSMTPPassword, extWebhookURL, extWebhookHeader, extCrowdSecKey, extWatcherPass, extSchedulePass, seeded.token.TokenHash} {
		if strings.Contains(string(body), secret) {
			t.Errorf("REDACTION LEAK: %q in default export", secret)
		}
	}
	// Non-secret channel fields travel verbatim.
	if !strings.Contains(string(body), "smtp.example.com") {
		t.Error("email smtpHost should not be redacted")
	}
	// Redaction must not mutate the live store's rows.
	if cs, _ := store.GetCrowdSecConfig(context.Background()); cs.APIKey != extCrowdSecKey {
		t.Errorf("live crowdsec key mutated: %q", cs.APIKey)
	}
}

func TestExtras_SentinelsInheritOnSameInstance(t *testing.T) {
	ctx := context.Background()
	store, us := newTestStoreWithUserStore(t)
	seeded := seedExtras(t, store, us)

	snap, err := Export(ctx, store, us, "test", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	report, err := Import(ctx, store, us, snap, ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if report.SentinelsUnresolvedTotal != 0 {
		t.Errorf("unresolved sentinels: %+v", report.IncompleteRows)
	}
	if _, err := auth.NewAPITokenStore(store.DB()).LookupToken(ctx, seeded.tokenPlain); err != nil {
		t.Errorf("token lost after same-instance restore: %v", err)
	}
	wh, _ := store.GetAlertChannel(ctx, seeded.webhookID)
	if _, err := parseWebhook(wh.Config); err != nil || !strings.Contains(string(wh.Config), extWebhookURL) {
		t.Errorf("webhook config after inherit: %s (%v)", wh.Config, err)
	}
	em, _ := store.GetAlertChannel(ctx, seeded.emailID)
	if !strings.Contains(string(em.Config), extSMTPPassword) {
		t.Errorf("smtp password not inherited: %s", em.Config)
	}
	if wc, _ := store.GetWatcherCredentials(ctx); wc.Password != extWatcherPass {
		t.Errorf("watcher password not inherited: %q", wc.Password)
	}
	if cs, _ := store.GetCrowdSecConfig(ctx); cs.APIKey != extCrowdSecKey {
		t.Errorf("crowdsec key not inherited: %q", cs.APIKey)
	}
}

// TestExtras_UnresolvedSecrets_OtherInstance: a no-secrets backup
// restored on another (populated) instance rejects by default; with
// AllowIncompleteRestore the secrets are cleared and the token —
// unusable without its hash — is dropped.
func TestExtras_UnresolvedSecrets_OtherInstance(t *testing.T) {
	ctx := context.Background()
	src, srcUsers := newTestStoreWithUserStore(t)
	seedExtras(t, src, srcUsers)
	snap, err := Export(ctx, src, srcUsers, "test", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	dst, dstUsers := newTestStoreWithUserStore(t)
	_ = seedLiveUser(t, dstUsers, "bob", "bob-password-15c-xxx") // not fresh

	if _, err := Import(ctx, dst, dstUsers, snap, ImportOptions{}); !IsUnresolvedSentinelError(err) {
		t.Fatalf("want unresolved sentinel error, got %v", err)
	}

	report, err := Import(ctx, dst, dstUsers, snap, ImportOptions{AllowIncompleteRestore: true})
	if err != nil {
		t.Fatalf("incomplete import: %v", err)
	}
	if report.APITokensImported != 0 {
		t.Errorf("token without hash restored: %d", report.APITokensImported)
	}
	cleared := buildClearedSet(report)
	for _, want := range [][3]string{
		{entityAPITokens, snap.Extras.APITokens[0].ID, "token_hash"},
		{entityCrowdSec, singletonIdentity, "api_key"},
		{entityWatcher, singletonIdentity, "password"},
	} {
		if !cleared.has(want[0], want[1], want[2]) {
			t.Errorf("IncompleteRows missing %v: %+v", want, report.IncompleteRows)
		}
	}
	rows, _ := dst.ListAPITokenRows(ctx)
	if len(rows) != 0 {
		t.Errorf("api_tokens bucket: %d rows", len(rows))
	}
	channels, _ := dst.ListAlertChannels(ctx)
	if len(channels) != 2 {
		t.Fatalf("channels restored: %d", len(channels))
	}
	for _, c := range channels {
		if strings.Contains(string(c.Config), SentinelLiteral) {
			t.Errorf("sentinel written to storage: %s", c.Config)
		}
	}
}

// TestExtras_AbsentSection_LeavesAreasUntouched pins backward
// compatibility: a pre-v2.29 backup has no extras and must not wipe
// the areas it never carried.
func TestExtras_AbsentSection_LeavesAreasUntouched(t *testing.T) {
	ctx := context.Background()
	store, us := newTestStoreWithUserStore(t)
	seeded := seedExtras(t, store, us)

	snap, err := Export(ctx, store, us, "test", true)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	snap.Extras = nil
	if _, err := Import(ctx, store, us, snap, ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}
	if _, err := store.GetManagedDomain(ctx, seeded.managedApex); err != nil {
		t.Errorf("managed domain wiped: %v", err)
	}
	if _, err := auth.NewAPITokenStore(store.DB()).LookupToken(ctx, seeded.tokenPlain); err != nil {
		t.Errorf("token wiped: %v", err)
	}
	if cs, _ := store.GetCrowdSecConfig(ctx); cs.APIKey != extCrowdSecKey {
		t.Errorf("crowdsec wiped: %+v", cs)
	}
}

// TestExtras_PresentSection_ReplacesAreas: a section with emptied
// lists / nil singletons clears the corresponding rows.
func TestExtras_PresentSection_ReplacesAreas(t *testing.T) {
	ctx := context.Background()
	store, us := newTestStoreWithUserStore(t)
	seedExtras(t, store, us)

	snap, err := Export(ctx, store, us, "test", true)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	snap.Extras = &SnapshotExtras{}
	if _, err := Import(ctx, store, us, snap, ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}
	if mds, _ := store.ListManagedDomains(ctx); len(mds) != 0 {
		t.Errorf("managed domains kept: %d", len(mds))
	}
	if _, err := store.GetCrowdSecConfig(ctx); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("crowdsec row kept: %v", err)
	}
	if rows, _ := store.ListAPITokenRows(ctx); len(rows) != 0 {
		t.Errorf("tokens kept: %d", len(rows))
	}
	// A nil server position leaves the live row alone.
	if sp, err := store.GetServerPosition(ctx); err != nil || sp.City != "Paris" {
		t.Errorf("server position: %+v %v", sp, err)
	}
}

func TestExtras_AutoServerPositionNotExported(t *testing.T) {
	store, us := newTestStoreWithUserStore(t)
	_ = seedLiveUser(t, us, "alice", "alice-password-15c-xx")
	if err := store.PutServerPosition(context.Background(), storage.ServerPositionRecord{
		Lat: 1, Lon: 2, Mode: "auto", SourceIP: "203.0.113.9",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	snap, err := Export(context.Background(), store, us, "test", true)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if snap.Extras.ServerPosition != nil {
		t.Errorf("auto position exported: %+v", snap.Extras.ServerPosition)
	}
}

func TestExtras_ValidationRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(s *Snapshot)
		want   string
	}{
		{"rule references missing channel", func(s *Snapshot) {
			s.Extras.AlertRules[0].Channels = []string{"ghost"}
		}, "references channel"},
		{"two catch-all templates", func(s *Snapshot) {
			t2 := s.Extras.ErrorTemplates[0]
			t2.ID, t2.Name = uuid.NewString(), "other"
			s.Extras.ErrorTemplates = append(s.Extras.ErrorTemplates, t2)
		}, "catch-all"},
		{"managed domain with unknown provider", func(s *Snapshot) {
			s.Extras.ManagedDomains[0].ProviderID = "ghost"
		}, "DNS provider"},
		{"token of a non-service user", func(s *Snapshot) {
			s.Extras.APITokens[0].UserID = s.Users[0].ID
			for _, u := range s.Users {
				if u.AuthSource != auth.UserAuthSourceService {
					s.Extras.APITokens[0].UserID = u.ID
				}
			}
		}, "not a service account"},
		{"two active tokens for one account", func(s *Snapshot) {
			t2 := s.Extras.APITokens[0]
			t2.ID = uuid.NewString()
			s.Extras.APITokens = append(s.Extras.APITokens, t2)
		}, "two active tokens"},
		{"invalid webhook config", func(s *Snapshot) {
			for i := range s.Extras.AlertChannels {
				if s.Extras.AlertChannels[i].Kind == storage.ChannelKindWebhook {
					s.Extras.AlertChannels[i].Config = json.RawMessage(`{"url":"ftp://x"}`)
				}
			}
		}, "webhook"},
		{"invalid automation rules", func(s *Snapshot) {
			s.Extras.AutomationRules = json.RawMessage(`{"rules":{"rules":{"bogus":{}}}}`)
		}, "automation rules"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store, us := newTestStoreWithUserStore(t)
			seedExtras(t, store, us)
			snap, err := Export(ctx, store, us, "test", true)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			tc.mutate(snap)
			_, err = Import(ctx, store, us, snap, ImportOptions{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// parseWebhook validates a stored webhook config like the sender does.
func parseWebhook(raw json.RawMessage) (any, error) {
	var c struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(c.URL, "https://") {
		return nil, errors.New("webhook url not https")
	}
	return c, nil
}
