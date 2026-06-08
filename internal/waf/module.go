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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
)

// Caddy module identifiers. Mirrors the Step E
// metrics module's split between full dotted ID (Caddy
// internals) and the handler-name segment (JSON config).
const (
	ModuleID    = "http.handlers.arenet_waf"
	HandlerName = "arenet_waf"
)

// wafPool reuses coraza.WAF instances across Caddy reloads.
// Two routes with identical config + mode share one WAF
// (saves the ~50 ms CRS parse on every reload). Mirrors the
// coraza-caddy/v2 pattern.
var wafPool = caddy.NewUsagePool()

type pooledWAF struct {
	waf coraza.WAF
}

func (p *pooledWAF) Destruct() error {
	if c, ok := p.waf.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func init() {
	caddy.RegisterModule(ArenetWafHandler{})
}

// ArenetWafHandler is the Step M custom Caddy WAF module. It
// wraps coraza/v3 directly (rather than coraza-caddy/v2)
// so the per-rule match callback exposes per-block events
// that the dashboard requires (rule_id, OWASP category,
// severity, src_ip, payload sample). See spec
// docs/superpowers/specs/2026-05-28-step-m-security.md §3.2
// for the rationale and §1.3 D1 for the rejected alternative
// (status-code-derived).
//
// Configuration fields are populated by caddymgr's
// buildArenetWafHandler emit:
//   - RouteID: the storage route UUID this handler instance
//     guards. Carried into every emitted Event so the
//     dashboard can attribute blocks per-route.
//   - Mode: "block" or "detect". block returns the
//     interruption status (typically 403); detect emits the
//     event but lets the request continue. Distinct from
//     the Coraza-level SecRuleEngine directive — Mode is
//     OUR policy, baked into the appended directive at
//     Provision.
//   - Directives: the user's coraza directive string
//     (Include @coraza.conf-recommended, Include
//     @owasp_crs/*.conf, etc.). Step M caddymgr emit hardcodes
//     the recommended CRS setup, same as Step I.4.
//   - LoadOWASPCRS: when true, the CRS-embedded FS is mounted
//     so the @owasp_crs Include directives resolve.
type ArenetWafHandler struct {
	RouteID      string `json:"route_id,omitempty"`
	Mode         string `json:"mode,omitempty"`
	Directives   string `json:"directives,omitempty"`
	LoadOWASPCRS bool   `json:"load_owasp_crs,omitempty"`
	// Host is the primary hostname this handler guards. Used
	// only for the W.bugfix Fix #2 boot log line so operators
	// reading journalctl don't have to cross-reference
	// route_id back to a host. Optional on the wire — a
	// pre-Fix-#2 emit decodes with Host="" and the log line
	// just shows the route_id.
	Host string `json:"host,omitempty"`

	waf     coraza.WAF
	poolKey string
}

// CaddyModule satisfies caddy.Module.
func (ArenetWafHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ModuleID,
		New: func() caddy.Module { return new(ArenetWafHandler) },
	}
}

// Validate enforces the small set of fields the handler
// requires before Provision can build the WAF. RouteID and
// Mode are caddymgr-supplied; an empty RouteID would attribute
// every event to the "" route, which would silently corrupt
// the dashboard.
func (h *ArenetWafHandler) Validate() error {
	if h.RouteID == "" {
		return errors.New("arenet_waf: route_id is required")
	}
	switch h.Mode {
	case "block", "detect":
	case "":
		return errors.New("arenet_waf: mode is required (\"block\" or \"detect\")")
	default:
		return fmt.Errorf("arenet_waf: mode %q must be \"block\" or \"detect\"", h.Mode)
	}
	return nil
}

// Provision builds (or reuses from the pool) the coraza.WAF
// instance for this handler. The error callback registered
// here is the secret sauce of D1=B: Coraza calls it per
// matched rule, we translate each call into a sink.Emit.
func (h *ArenetWafHandler) Provision(_ caddy.Context) error {
	h.poolKey = h.computePoolKey()

	val, loaded, err := wafPool.LoadOrNew(h.poolKey, func() (caddy.Destructor, error) {
		waf, err := h.buildWAF()
		if err != nil {
			return nil, err
		}
		return &pooledWAF{waf: waf}, nil
	})
	if err != nil {
		return fmt.Errorf("arenet_waf: build waf: %w", err)
	}
	h.waf = val.(*pooledWAF).waf

	// W.bugfix Fix #2 — per-route boot signal. Emits one log
	// line every time Caddy instantiates a WAF handler (i.e.
	// once per route-with-WAF-on per reload). The `pooled`
	// field tells operators whether this provision reused an
	// existing Coraza WAF instance from wafPool (true == reused
	// — saves the ~50 ms CRS parse cost) or built a fresh one.
	// Two routes with identical (mode, directives, crs) share
	// a pool_key — that's intentional (computePoolKey design)
	// and visible in the log for verification.
	//
	// Pre-Fix-#2 boot logs showed only one sink-level
	// "waf event sink wired" line, leaving operators blind
	// to which routes actually had WAF on and at what mode.
	slog.Default().Info("waf handler provisioned",
		"route_id", h.RouteID,
		"host", h.Host,
		"mode", h.Mode,
		"pool_key", h.poolKey,
		"pooled", loaded,
		"load_owasp_crs", h.LoadOWASPCRS,
	)
	return nil
}

// buildWAF constructs the coraza.WAF, with the error callback
// hooking each rule match into the global EventSink. The
// callback closure captures h.RouteID + h.Mode so each event
// carries the right attribution.
func (h *ArenetWafHandler) buildWAF() (coraza.WAF, error) {
	// In block mode we need SecRuleEngine On; in detect mode
	// DetectionOnly. Append AFTER the user's directives so
	// our policy wins on conflict — the dashboard's notion
	// of "this route is in block mode" is the contract we
	// expose to the operator, and Coraza must agree.
	mode := "On"
	if h.Mode == "detect" {
		mode = "DetectionOnly"
	}
	directives := h.Directives + "\nSecRuleEngine " + mode

	cfg := coraza.NewWAFConfig().
		WithErrorCallback(h.onMatch).
		WithDirectives(directives)
	if h.LoadOWASPCRS {
		cfg = cfg.WithRootFS(mergefs.Merge(coreruleset.FS, mergefsio.OSFS))
	}
	return coraza.NewWAF(cfg)
}

// computePoolKey makes pool reuse hash-sensitive to the
// fields that influence WAF construction. Two handler
// instances with the same (mode, directives, load_owasp_crs)
// share a WAF; differing instances build their own.
func (h *ArenetWafHandler) computePoolKey() string {
	hash := sha256.New()
	hash.Write([]byte(h.Mode))
	hash.Write([]byte{0})
	hash.Write([]byte(h.Directives))
	hash.Write([]byte{0})
	if h.LoadOWASPCRS {
		hash.Write([]byte("crs"))
	}
	return fmt.Sprintf("arenet-waf-%x", hash.Sum(nil))
}

// Cleanup releases the pooled WAF reference. The pool's
// UsagePool destructs the underlying coraza.WAF when the last
// reference drops.
func (h *ArenetWafHandler) Cleanup() error {
	_, err := wafPool.Delete(h.poolKey)
	return err
}

// onMatch is Coraza's per-matched-rule callback. Fires once
// per rule the request tripped (a single bad request can
// trip several). Builds + emits an Event for the matches
// that should reach the operator; the sink's LRU rate-limit
// handles deduplication beyond that. The sink also bumps
// the per-minute block counter on every Emit (AC #3
// invariant), so the dashboard timeline reflects attack
// volume even when the LRU suppresses event-table rows.
//
// Filtering policy depends on the handler's mode:
//
//   - **block**: emit only Disruptive() matches. In
//     SecRuleEngine On, the disruptive match is the
//     determinative one (the rule that crossed the anomaly
//     threshold and got the request denied). Non-disruptive
//     warn-level CRS rules contribute to the score but are
//     noise on their own — emitting them would flood the
//     event log.
//
//   - **detect** (SecRuleEngine DetectionOnly): every match
//     is non-disruptive by Coraza's definition, so the
//     block-mode filter would emit nothing. Instead filter
//     by severity: Warning (4) or higher means a CRS rule
//     designed to indicate a real attack signature. Notice/
//     Info/Debug matches stay suppressed (CRS uses them for
//     scoring + tracing).
//
// Coraza severity scale is inverted: 0=Emergency, 1=Alert,
// 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug.
// Lower = more severe; we want sev ≤ 4 in detect mode.
const detectModeMaxSeverity = 4

func (h *ArenetWafHandler) onMatch(mr types.MatchedRule) {
	rule := mr.Rule()
	switch h.Mode {
	case "block":
		if !mr.Disruptive() {
			return
		}
	case "detect":
		if int(rule.Severity()) > detectModeMaxSeverity {
			return
		}
	default:
		// Validate caught this at Provision-time; defensive
		// belt-and-braces.
		return
	}
	sink := getGlobalSink()
	if sink == nil {
		return
	}
	ruleID := strconv.Itoa(rule.ID())
	method, path, payload := requestSnippetFromMatch(mr)

	// W.bugfix Fix #1 — mode-aware Action + StatusCode. Pre-
	// fix the sink emitted no Action and the frontend
	// hardcoded "BLOCK 403" labels regardless of mode,
	// producing the operator-facing false-positive perception
	// that detect mode blocks. Set the fields at emit time
	// from the handler's mode (known here; the post-block
	// response status is NOT known — Coraza's onMatch fires
	// during phase-1/2, before processResponse). StatusCode
	// for detect mode is 0 (sentinel for "request reached
	// upstream; actual status not captured at WAF layer");
	// the frontend renders "—" for that case.
	action := ActionDetect
	statusCode := 0
	if h.Mode == "block" {
		action = ActionBlock
		statusCode = http.StatusForbidden
	}

	sink.Emit(Event{
		Ts:            time.Now().UTC(),
		RouteID:       h.RouteID,
		RuleID:        ruleID,
		Category:      CategoryForRule(ruleID),
		Severity:      int(rule.Severity()),
		SrcIP:         mr.ClientIPAddress(),
		RequestMethod: method,
		RequestPath:   Truncate(Redact(path), MaxRequestPathBytes),
		PayloadSample: Truncate(Redact(payload), MaxPayloadSampleBytes),
		Action:        action,
		StatusCode:    statusCode,
	})
}

// requestSnippetFromMatch extracts the method, path, and a
// payload sample from a MatchedRule. The coraza/v3 types
// surface the URI on the rule (it's the full request URI
// unparsed). Method is not directly exposed on the rule, so
// we fall back to an empty string — the dashboard's recent-
// events widget shows "—" when method is unknown.
//
// Payload sample: built from the matched-variable Data() of
// the first MatchData (the variable that triggered the rule).
// CRS rules typically populate Data with the offending bytes;
// for non-CRS rules it may be empty.
func requestSnippetFromMatch(mr types.MatchedRule) (method, path, payload string) {
	path = mr.URI()
	// Method isn't on the rule; the request lives in the
	// transaction. Coraza doesn't expose it through the
	// MatchedRule interface, so we use the (empty) default.
	// caddymgr could pass it via a context-bound replacer
	// in a future refinement; for M.1 it's tolerable.
	method = ""
	for _, md := range mr.MatchedDatas() {
		if v := md.Value(); v != "" {
			payload = v
			break
		}
	}
	return
}

// ServeHTTP wraps the next handler with Coraza's request +
// response inspection. The shape mirrors coraza-caddy/v2's
// ServeHTTP exactly — the security path is too risky to
// reinvent. Differences from upstream:
//   - We use our package-local processRequest / wrap.
//   - Logging on interruption uses slog.Default rather than
//     a zap logger embedded in the handler (caddymgr emits
//     don't carry one).
//   - On interruption: in BLOCK mode we return HandlerError
//     so Caddy emits the configured status (typically 403);
//     in DETECT mode we let the request through (the
//     callback already emitted the event).
func (h *ArenetWafHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	tx := h.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	if tx.IsRuleEngineOff() {
		return next.ServeHTTP(w, r)
	}

	if it, err := processRequest(tx, r); err != nil {
		return caddyhttp.HandlerError{
			StatusCode: http.StatusInternalServerError,
			ID:         tx.ID(),
			Err:        err,
		}
	} else if it != nil {
		// In block mode the Coraza transaction is in
		// SecRuleEngine On so it returns a real interruption.
		// In detect mode it's DetectionOnly so we should NOT
		// see an interruption — but if the user's directives
		// include a disruptive rule that bypasses
		// DetectionOnly, fall through gracefully (don't
		// block the request, since the operator declared
		// detect intent on this route).
		if h.Mode == "block" {
			return caddyhttp.HandlerError{
				StatusCode: obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK),
				ID:         tx.ID(),
				Err:        errInterruptionTriggered,
			}
		}
		// detect mode + interruption: log and continue.
		return next.ServeHTTP(w, r)
	}

	ww, processResponse := wrap(w, r, tx)
	if err := next.ServeHTTP(ww, r); err != nil {
		return err
	}
	return processResponse(tx, r)
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*ArenetWafHandler)(nil)
	_ caddy.Validator             = (*ArenetWafHandler)(nil)
	_ caddy.CleanerUpper          = (*ArenetWafHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*ArenetWafHandler)(nil)
)
