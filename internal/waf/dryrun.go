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

package waf

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
)

// DryRunMaxBody caps the sample request body of a dry run.
const DryRunMaxBody = 64 * 1024

// DryRunRequest is a sample request for the WAF tester (v2.38).
type DryRunRequest struct {
	Method  string
	Path    string // path + optional query string
	Host    string
	Headers [][2]string
	Body    string
}

// DryRunMatch is one rule that matched the sample request.
type DryRunMatch struct {
	RuleID   int    `json:"id"`
	Message  string `json:"msg"`
	Severity string `json:"severity"`
	Data     string `json:"data,omitempty"`
}

// DryRunResult tells whether the sample would be blocked (engine On)
// and which rules matched.
type DryRunResult struct {
	Blocked   bool          `json:"blocked"`
	Status    int           `json:"status,omitempty"`
	BlockedBy int           `json:"blockedBy,omitempty"`
	Matches   []DryRunMatch `json:"matches"`
}

// DryRun evaluates req against a WAF built like the route's handler
// (the Arenet admin guard + directives + SecRuleEngine On), without
// traffic, event sink or Caddy. The engine is always On so the result
// says whether the request WOULD be blocked; the caller reports the
// route mode separately.
func DryRun(directives string, loadCRS bool, req DryRunRequest) (DryRunResult, error) {
	cfg := coraza.NewWAFConfig().
		WithDirectives(adminAPIExclusionDirective + directives + "\nSecRuleEngine On")
	if loadCRS {
		cfg = cfg.WithRootFS(mergefs.Merge(coreruleset.FS, mergefsio.OSFS))
	}
	w, err := coraza.NewWAF(cfg)
	if err != nil {
		return DryRunResult{}, fmt.Errorf("waf dry run: build: %w", err)
	}
	tx := w.NewTransaction()
	defer func() { _ = tx.Close() }()

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	path := req.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	tx.ProcessConnection("203.0.113.10", 40000, "127.0.0.1", 443)
	tx.ProcessURI(path, method, "HTTP/1.1")
	if req.Host != "" {
		tx.SetServerName(req.Host)
		tx.AddRequestHeader("Host", req.Host)
	}
	for _, h := range req.Headers {
		if strings.TrimSpace(h[0]) != "" {
			tx.AddRequestHeader(strings.TrimSpace(h[0]), h[1])
		}
	}
	it := tx.ProcessRequestHeaders()
	if it == nil && req.Body != "" {
		body := req.Body
		if len(body) > DryRunMaxBody {
			body = body[:DryRunMaxBody]
		}
		if it, _, err = tx.WriteRequestBody([]byte(body)); err == nil && it == nil {
			it, err = tx.ProcessRequestBody()
		}
		if err != nil {
			return DryRunResult{}, fmt.Errorf("waf dry run: body: %w", err)
		}
	} else if it == nil {
		it, _ = tx.ProcessRequestBody()
	}
	return dryRunResult(tx.MatchedRules(), it), nil
}

// dryRunResult keeps the rules an operator cares about: an ID, a
// message, and a severity, a custom-rule ID or the blocking rule (CRS
// bookkeeping rules such as 901340 have none of the last three;
// Coraza counts "pass" as disruptive, so that flag cannot be used).
func dryRunResult(matched []types.MatchedRule, it *types.Interruption) DryRunResult {
	res := DryRunResult{Matches: []DryRunMatch{}}
	for _, mr := range matched {
		r := mr.Rule()
		custom := r.ID() >= CustomRuleMinID && r.ID() <= SecLangMaxID
		// An unset severity is outside Emergency..Debug (String() = "unknown").
		knownSeverity := r.Severity() >= types.RuleSeverityEmergency && r.Severity() <= types.RuleSeverityDebug
		blocker := it != nil && it.RuleID == r.ID()
		if r.ID() == 0 || mr.Message() == "" || (!knownSeverity && !custom && !blocker) {
			continue
		}
		res.Matches = append(res.Matches, DryRunMatch{
			RuleID:   r.ID(),
			Message:  mr.Message(),
			Severity: r.Severity().String(),
			Data:     Truncate(Redact(mr.Data()), MaxPayloadSampleBytes),
		})
	}
	sort.SliceStable(res.Matches, func(i, j int) bool { return res.Matches[i].RuleID < res.Matches[j].RuleID })
	if it != nil {
		res.Blocked = true
		res.Status = it.Status
		if res.Status == 0 {
			res.Status = http.StatusForbidden
		}
		res.BlockedBy = it.RuleID
	}
	return res
}
