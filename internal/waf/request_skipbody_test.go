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

package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

// Phase 4.5 — processRequest skipBody tests.
//
// Approach: build a real (minimal) Coraza WAF with a single
// body-targeted rule that DENIES any request whose body
// contains the marker string "TRIGGER_BODY_RULE". Feed a
// request whose body contains the marker, then:
//   - With skipBody=false: Coraza inspects the body, the rule
//     matches, processRequest returns an interruption.
//   - With skipBody=true:  Coraza never reads the body, the
//     rule cannot match, processRequest returns nil. The body
//     bytes are still available for downstream reverse_proxy
//     consumption (we verify by reading req.Body afterwards).
//
// This is behavioural rather than introspective — we cannot
// observe Coraza's internal "did you call ReadRequestBodyFrom"
// without a mock of the full types.Transaction (~30 methods),
// but the visible effect (rule fires vs not, body left intact)
// is the actual contract Phase 4.5 protects.

const bodyRuleDirectives = `
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_BODY "@contains TRIGGER_BODY_RULE" \
    "id:90001,phase:2,deny,status:403,msg:'skipbody test rule'"
`

func newBodyRuleWAF(t *testing.T) coraza.WAF {
	t.Helper()
	cfg := coraza.NewWAFConfig().WithDirectives(bodyRuleDirectives)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("build test WAF: %v", err)
	}
	return waf
}

func TestProcessRequest_SkipBodyFalse_RuleFires(t *testing.T) {
	waf := newBodyRuleWAF(t)
	tx := waf.NewTransaction()
	defer tx.Close()

	body := strings.NewReader("payload=TRIGGER_BODY_RULE")
	req := httptest.NewRequest(http.MethodPost, "https://example.test/upload", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	it, err := processRequest(tx, req, false /* skipBody */)
	if err != nil {
		t.Fatalf("processRequest: %v", err)
	}
	if it == nil {
		t.Fatal("want interruption (body rule should fire when body is inspected); got nil")
	}
}

func TestProcessRequest_SkipBodyTrue_RuleDoesNotFire(t *testing.T) {
	waf := newBodyRuleWAF(t)
	tx := waf.NewTransaction()
	defer tx.Close()

	body := strings.NewReader("payload=TRIGGER_BODY_RULE")
	req := httptest.NewRequest(http.MethodPost, "https://example.test/upload", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	it, err := processRequest(tx, req, true /* skipBody */)
	if err != nil {
		t.Fatalf("processRequest: %v", err)
	}
	if it != nil {
		t.Fatalf("want no interruption (body must not be inspected); got %+v", it)
	}
}

func TestProcessRequest_SkipBodyTrue_BodyRemainsAvailableDownstream(t *testing.T) {
	// The reverse_proxy chained AFTER the WAF handler needs
	// to read the body. The skipBody path must leave req.Body
	// untouched so the proxy can stream the upload upstream.
	waf := newBodyRuleWAF(t)
	tx := waf.NewTransaction()
	defer tx.Close()

	const payload = "binary-bytes-12345-PRESERVED-67890"
	req := httptest.NewRequest(http.MethodPost, "https://example.test/upload",
		strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")

	if _, err := processRequest(tx, req, true); err != nil {
		t.Fatalf("processRequest: %v", err)
	}

	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read req.Body downstream: %v", err)
	}
	if string(got) != payload {
		t.Errorf("body altered by WAF skip path: got %q, want %q", string(got), payload)
	}
}

func TestProcessRequest_SkipBodyTrue_HeaderRuleStillFires(t *testing.T) {
	// Critical invariant: skipBody only affects the BODY phase.
	// A rule that matches on REQUEST_HEADERS must still fire
	// when skipBody=true — that's the whole point of the
	// per-route toggle (preserve header/URI inspection,
	// neutralise body buffering).
	const headerRule = `
SecRuleEngine On
SecRule REQUEST_HEADERS:X-Test-Trigger "@contains BAD_HEADER" \
    "id:90002,phase:1,deny,status:403,msg:'header rule'"
`
	cfg := coraza.NewWAFConfig().WithDirectives(headerRule)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("build test WAF: %v", err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()

	req := httptest.NewRequest(http.MethodPost, "https://example.test/upload",
		strings.NewReader("body-content"))
	req.Header.Set("X-Test-Trigger", "BAD_HEADER")

	it, err := processRequest(tx, req, true /* skipBody */)
	if err != nil {
		t.Fatalf("processRequest: %v", err)
	}
	if it == nil {
		t.Error("want interruption (header rule must still fire on skipBody=true); got nil")
	}
}
