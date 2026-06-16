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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// AL.3b — AlertRule CRUD handler tests. Covers happy
// CRUD + validation rejects + /test endpoint outcomes.

// stubAlertingSource is a tiny Source impl that lets the
// test env wire a SourceLookup without booting the real
// observability / certinfo / systemhealth subsystems.
type stubAlertingSource struct {
	name string
}

func (s *stubAlertingSource) Name() string                              { return s.name }
func (s *stubAlertingSource) ValidateParams(_ json.RawMessage) error    { return nil }
func (s *stubAlertingSource) Read(_ context.Context, _ json.RawMessage) (alerting.SourceValue, error) {
	return alerting.FloatValue(0), nil
}

// wireRuleTestEnv prepares the env with a Source registry
// (waf_event_rate stub) so the validator's "source
// exists" check has something to match. Without this,
// every rule create would 400 with "source not
// registered" because the test handler doesn't get the
// production registry.
func wireRuleTestEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t, false)
	reg := alerting.NewSourceRegistry()
	_ = reg.Register(&stubAlertingSource{name: "waf_event_rate"})
	env.handler.SetAlertingSourceLookup(reg)
	return env
}

// seedChannelForRuleTests inserts a webhook channel and
// returns its ID. Rules need a real channel ID to pass
// the reference-integrity check.
func seedChannelForRuleTests(t *testing.T, env *testEnv, name string) string {
	t.Helper()
	cfg := alerting.WebhookConfig{
		URL:            "http://webhook.example.com",
		Method:         "POST",
		TimeoutSeconds: 5,
	}
	raw, _ := json.Marshal(cfg)
	created, err := env.store.CreateAlertChannel(context.Background(), storage.Channel{
		ID:          uuid.NewString(),
		Name:        name,
		Kind:        storage.ChannelKindWebhook,
		Enabled:     true,
		MinSeverity: 0,
		Config:      raw,
	})
	if err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	return created.ID
}

// validRulePostBody builds a minimal valid JSON POST body
// referencing the supplied channel ID. Tests mutate one
// field at a time to exercise per-invariant failures.
func validRulePostBody(name, channelID string) string {
	return `{
		"name":"` + name + `",
		"enabled":true,
		"kind":"threshold",
		"severity":1,
		"category":"waf",
		"source":"waf_event_rate",
		"sourceParams":{"windowSecs":300},
		"evalParams":{"operator":">","value":50},
		"channels":["` + channelID + `"],
		"cooldownSecs":300
	}`
}

func TestAlertRule_POST_HappyPathFiresAudit(t *testing.T) {
	env := wireRuleTestEnv(t)
	chID := seedChannelForRuleTests(t, env, "ops")

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules",
		strings.NewReader(validRulePostBody("block-rate-high", chID)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	var created alertRuleResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" {
		t.Errorf("response missing id")
	}
	if created.Source != "waf_event_rate" {
		t.Errorf("Source=%q want waf_event_rate", created.Source)
	}

	// Audit event emitted.
	var found bool
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionAlertRuleCreated {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("alert_rule_created audit event not emitted; events=%+v", env.audit.Events())
	}
}

func TestAlertRule_POST_UnknownSource_400(t *testing.T) {
	env := wireRuleTestEnv(t)
	chID := seedChannelForRuleTests(t, env, "ops")

	body := strings.Replace(validRulePostBody("bad-src", chID),
		`"source":"waf_event_rate"`,
		`"source":"ghost_source"`, 1)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400 (unknown source). body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "not registered") {
		t.Errorf("body=%s; want 'not registered' message", rec.Body)
	}
}

func TestAlertRule_POST_UnknownChannel_400(t *testing.T) {
	env := wireRuleTestEnv(t)
	// Reference a channel ID that doesn't exist in storage.
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules",
		strings.NewReader(validRulePostBody("orphan", "ghost-channel-id")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400 (unknown channel). body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "ghost-channel-id") {
		t.Errorf("body=%s; want offending channel id mentioned", rec.Body)
	}
}

func TestAlertRule_POST_InvalidKind_400(t *testing.T) {
	env := wireRuleTestEnv(t)
	chID := seedChannelForRuleTests(t, env, "ops")
	body := strings.Replace(validRulePostBody("bad-kind", chID),
		`"kind":"threshold"`, `"kind":"bogus"`, 1)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400. body=%s", rec.Code, rec.Body)
	}
}

func TestAlertRule_POST_BadTemplate_400(t *testing.T) {
	env := wireRuleTestEnv(t)
	chID := seedChannelForRuleTests(t, env, "ops")
	body := strings.Replace(validRulePostBody("bad-tmpl", chID),
		`"cooldownSecs":300`,
		`"cooldownSecs":300,"bodyTemplate":"{{.Unterminated"`, 1)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400 (bad template). body=%s", rec.Code, rec.Body)
	}
}

func TestAlertRule_POST_DuplicateName_409(t *testing.T) {
	env := wireRuleTestEnv(t)
	chID := seedChannelForRuleTests(t, env, "ops")

	body := validRulePostBody("shared-name", chID)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed POST status=%d body=%s", rec.Code, rec.Body)
	}
	// Second POST same name → 409.
	req = httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("status=%d want 409 on duplicate name. body=%s", rec.Code, rec.Body)
	}
}

func TestAlertRule_GET_List(t *testing.T) {
	env := wireRuleTestEnv(t)
	chID := seedChannelForRuleTests(t, env, "ops")

	// Seed two rules.
	for _, name := range []string{"rule-a", "rule-b"} {
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/settings/alerting/rules",
			strings.NewReader(validRulePostBody(name, chID)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("seed %q: status=%d", name, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/settings/alerting/rules", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("LIST status=%d body=%s", rec.Code, rec.Body)
	}
	var got []alertRuleResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got) != 2 {
		t.Errorf("len=%d want 2", len(got))
	}
}

func TestAlertRule_GET_NotFound_404(t *testing.T) {
	env := wireRuleTestEnv(t)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/settings/alerting/rules/ghost", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status=%d want 404", rec.Code)
	}
}

func TestAlertRule_PUT_FullReplace(t *testing.T) {
	env := wireRuleTestEnv(t)
	chID := seedChannelForRuleTests(t, env, "ops")

	// Create.
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules",
		strings.NewReader(validRulePostBody("rule-1", chID)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed: status=%d body=%s", rec.Code, rec.Body)
	}
	var created alertRuleResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// PUT — change cooldown + category.
	body := `{
		"name":"rule-1",
		"enabled":true,
		"kind":"threshold",
		"severity":2,
		"category":"system",
		"source":"waf_event_rate",
		"sourceParams":{"windowSecs":300},
		"evalParams":{"operator":">","value":100},
		"channels":["` + chID + `"],
		"cooldownSecs":600
	}`
	req = httptest.NewRequest(http.MethodPut,
		"/api/v1/settings/alerting/rules/"+created.ID,
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: status=%d body=%s", rec.Code, rec.Body)
	}
	var updated alertRuleResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.CooldownSecs != 600 {
		t.Errorf("CooldownSecs=%d want 600", updated.CooldownSecs)
	}
	if updated.Category != "system" {
		t.Errorf("Category=%q want system", updated.Category)
	}
	// Audit emitted with before+after.
	var found *audit.Event
	for i, e := range env.audit.Events() {
		if e.Action == audit.ActionAlertRuleUpdated {
			found = &env.audit.Events()[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("alert_rule_updated audit not emitted; events=%+v", env.audit.Events())
	}
	if len(found.BeforeJSON) == 0 || len(found.AfterJSON) == 0 {
		t.Errorf("audit missing before/after diff")
	}
}

func TestAlertRule_PUT_NotFound_404(t *testing.T) {
	env := wireRuleTestEnv(t)
	chID := seedChannelForRuleTests(t, env, "ops")
	body := validRulePostBody("ghost", chID)
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/settings/alerting/rules/ghost-id",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status=%d want 404", rec.Code)
	}
}

func TestAlertRule_DELETE_FiresAuditAndReturns204(t *testing.T) {
	env := wireRuleTestEnv(t)
	chID := seedChannelForRuleTests(t, env, "ops")
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules",
		strings.NewReader(validRulePostBody("doomed", chID)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed: status=%d", rec.Code)
	}
	var created alertRuleResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	req = httptest.NewRequest(http.MethodDelete,
		"/api/v1/settings/alerting/rules/"+created.ID, nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE: status=%d body=%s", rec.Code, rec.Body)
	}

	// Audit fired with BeforeJSON carrying the deleted rule.
	var found *audit.Event
	for i, e := range env.audit.Events() {
		if e.Action == audit.ActionAlertRuleDeleted {
			found = &env.audit.Events()[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("alert_rule_deleted audit not emitted")
	}
	if !strings.Contains(string(found.BeforeJSON), "doomed") {
		t.Errorf("BeforeJSON missing rule name; got %s", found.BeforeJSON)
	}

	// Subsequent GET = 404.
	req = httptest.NewRequest(http.MethodGet,
		"/api/v1/settings/alerting/rules/"+created.ID, nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("post-DELETE GET status=%d want 404", rec.Code)
	}
}

// --- /test endpoint ---------------------------------------

// stubRuleDispatcher records Dispatch calls and returns a
// scripted DispatchResult. Lets the /test handler tests
// exercise sent=true, partial failure, and skip paths
// without booting a real Dispatcher.
type stubRuleDispatcher struct {
	calls  []ruleDispatchCall
	result alerting.DispatchResult
}

type ruleDispatchCall struct {
	evt        alerting.AlertEvent
	channelIDs []string
}

func (s *stubRuleDispatcher) Dispatch(_ context.Context, evt alerting.AlertEvent, ids []string) alerting.DispatchResult {
	s.calls = append(s.calls, ruleDispatchCall{evt: evt, channelIDs: append([]string{}, ids...)})
	return s.result
}

func seedRule(t *testing.T, env *testEnv, name string, channelIDs []string) string {
	t.Helper()
	rule := storage.AlertRule{
		ID:           uuid.NewString(),
		Name:         name,
		Enabled:      true,
		Kind:         "threshold",
		Severity:     1,
		Category:     "waf",
		Source:       "waf_event_rate",
		SourceParams: json.RawMessage(`{"windowSecs":300}`),
		EvalParams:   json.RawMessage(`{"operator":">","value":50}`),
		Channels:     channelIDs,
		CooldownSecs: 300,
	}
	created, err := env.store.CreateAlertRule(context.Background(), rule)
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	return created.ID
}

func TestAlertRule_TEST_Happy_Returns200SentTrue(t *testing.T) {
	env := wireRuleTestEnv(t)
	ch1 := seedChannelForRuleTests(t, env, "ch-1")
	ch2 := seedChannelForRuleTests(t, env, "ch-2")
	ruleID := seedRule(t, env, "test-happy", []string{ch1, ch2})

	disp := &stubRuleDispatcher{result: alerting.DispatchResult{
		Fired:   []string{ch1, ch2},
		Failed:  map[string]string{},
		Skipped: map[string]string{},
	}}
	env.handler.SetAlertingDispatcher(disp)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules/"+ruleID+"/test", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", rec.Code, rec.Body)
	}
	var resp alertRuleTestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Sent {
		t.Errorf("Sent=false; want true")
	}
	if len(resp.ChannelsFired) != 2 {
		t.Errorf("ChannelsFired len=%d want 2", len(resp.ChannelsFired))
	}
	if len(disp.calls) != 1 {
		t.Fatalf("dispatcher calls=%d want 1", len(disp.calls))
	}
	// Synthetic event carries the rule's id + name.
	if disp.calls[0].evt.RuleID != ruleID {
		t.Errorf("evt.RuleID=%q want %q", disp.calls[0].evt.RuleID, ruleID)
	}
	if !strings.Contains(disp.calls[0].evt.Subject, "[TEST]") {
		t.Errorf("Subject missing [TEST] marker: %q", disp.calls[0].evt.Subject)
	}
}

func TestAlertRule_TEST_PartialFailure_Returns502(t *testing.T) {
	env := wireRuleTestEnv(t)
	ch1 := seedChannelForRuleTests(t, env, "ch-1")
	ch2 := seedChannelForRuleTests(t, env, "ch-2")
	ruleID := seedRule(t, env, "test-partial", []string{ch1, ch2})

	disp := &stubRuleDispatcher{result: alerting.DispatchResult{
		Fired:   []string{ch1},
		Failed:  map[string]string{ch2: "smtp connect refused"},
		Skipped: map[string]string{},
	}}
	env.handler.SetAlertingDispatcher(disp)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules/"+ruleID+"/test", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status=%d want 502 (partial failure)", rec.Code)
	}
	var resp alertRuleTestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Sent {
		t.Errorf("Sent=true on partial failure; want false")
	}
	if resp.Errors[ch2] != "smtp connect refused" {
		t.Errorf("Errors[%s]=%q want 'smtp connect refused'", ch2, resp.Errors[ch2])
	}
}

func TestAlertRule_TEST_AllSkipped_Returns502(t *testing.T) {
	env := wireRuleTestEnv(t)
	ch1 := seedChannelForRuleTests(t, env, "ch-1")
	ruleID := seedRule(t, env, "test-skip", []string{ch1})

	disp := &stubRuleDispatcher{result: alerting.DispatchResult{
		Fired:   []string{},
		Failed:  map[string]string{},
		Skipped: map[string]string{ch1: "channel disabled"},
	}}
	env.handler.SetAlertingDispatcher(disp)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules/"+ruleID+"/test", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status=%d want 502 (all skipped)", rec.Code)
	}
	var resp alertRuleTestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Sent {
		t.Errorf("Sent=true with all-skipped; want false")
	}
	if resp.Skipped[ch1] == "" {
		t.Errorf("Skipped[%s] empty; want reason surfaced", ch1)
	}
}

func TestAlertRule_TEST_RuleDisabled_StillFires(t *testing.T) {
	// Test endpoint ignores rule.Enabled — the operator
	// explicitly pressed Test, so even a soft-disabled
	// rule must dispatch. Per the brief: preference is
	// "ignore Enabled, test always dispatches".
	env := wireRuleTestEnv(t)
	ch1 := seedChannelForRuleTests(t, env, "ch-1")
	rule := storage.AlertRule{
		ID:           uuid.NewString(),
		Name:         "soft-paused",
		Enabled:      false, // soft-disabled
		Kind:         "threshold",
		Severity:     1,
		Category:     "waf",
		Source:       "waf_event_rate",
		SourceParams: json.RawMessage(`{"windowSecs":300}`),
		EvalParams:   json.RawMessage(`{"operator":">","value":50}`),
		Channels:     []string{ch1},
		CooldownSecs: 300,
	}
	created, err := env.store.CreateAlertRule(context.Background(), rule)
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	disp := &stubRuleDispatcher{result: alerting.DispatchResult{
		Fired:   []string{ch1},
		Failed:  map[string]string{},
		Skipped: map[string]string{},
	}}
	env.handler.SetAlertingDispatcher(disp)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules/"+created.ID+"/test", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d want 200 on disabled-rule test (test ignores Enabled)", rec.Code)
	}
	if len(disp.calls) != 1 {
		t.Errorf("dispatcher calls=%d want 1 (test must dispatch even when disabled)", len(disp.calls))
	}
}

func TestAlertRule_TEST_NotFound_404(t *testing.T) {
	env := wireRuleTestEnv(t)
	disp := &stubRuleDispatcher{}
	env.handler.SetAlertingDispatcher(disp)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules/ghost/test", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status=%d want 404", rec.Code)
	}
	if len(disp.calls) != 0 {
		t.Errorf("dispatcher called on missing rule; want 0 calls")
	}
}

func TestAlertRule_TEST_DispatcherUnwired_503(t *testing.T) {
	env := wireRuleTestEnv(t)
	ch1 := seedChannelForRuleTests(t, env, "ch-1")
	ruleID := seedRule(t, env, "no-disp", []string{ch1})
	// Intentionally NOT calling SetAlertingDispatcher.

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/settings/alerting/rules/"+ruleID+"/test", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d want 503 (dispatcher unwired)", rec.Code)
	}
}
