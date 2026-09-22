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

// Package caddyimport reads a Caddyfile with Caddy's own parser and
// turns each site block into an Arenet route candidate, reporting what
// it could not translate (v2.40). It never writes anything: the API
// previews the result, then creates the routes the operator picked.
//
// See docs/superpowers/specs/2026-09-22-caddyfile-import-design.md.
package caddyimport

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	"github.com/barto95100/arenet/internal/storage"
)

// Limits of one import.
const (
	MaxBytes  = 64 * 1024
	MaxBlocks = 200
)

// Warning is something the import could not translate, with the
// Caddyfile line it comes from (0 for a whole-file remark).
type Warning struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

// Candidate is one site block turned into a route.
type Candidate struct {
	Host       string    `json:"host"`
	Aliases    []string  `json:"aliases"`
	Route      *Route    `json:"route,omitempty"`
	Importable bool      `json:"importable"`
	Reason     string    `json:"reason,omitempty"`
	Warnings   []Warning `json:"warnings"`
}

// Route is the subset of storage.Route the import fills in.
type Route struct {
	Host               string              `json:"host"`
	Aliases            []string            `json:"aliases"`
	Upstreams          []storage.Upstream  `json:"upstreams"`
	LBPolicy           string              `json:"lbPolicy"`
	TLSEnabled         bool                `json:"tlsEnabled"`
	ACMEChallenge      string              `json:"acmeChallenge"`
	InsecureSkipVerify bool                `json:"insecureSkipVerify"`
	RequestHeaders     map[string]string   `json:"requestHeaders,omitempty"`
	ResponseHeaders    map[string]string   `json:"responseHeaders,omitempty"`
	HealthCheck        storage.HealthCheck `json:"healthCheck"`
	PathRules          []storage.PathRule  `json:"pathRules,omitempty"`
}

// Result is what a Caddyfile yields.
type Result struct {
	GlobalWarnings []Warning   `json:"globalWarnings"`
	Candidates     []Candidate `json:"candidates"`
}

// lbPolicies maps Caddy's load-balancing policies to Arenet's; the
// others (ip_hash variants, cookie, uri_hash…) are reported.
var lbPolicies = map[string]string{
	"round_robin":          storage.LBPolicyRoundRobin,
	"weighted_round_robin": storage.LBPolicyWeightedRoundRobin,
	"least_conn":           storage.LBPolicyLeastConn,
	"ip_hash":              storage.LBPolicyIPHash,
	"random":               storage.LBPolicyRandom,
	"first":                storage.LBPolicyFirst,
}

// silentDirectives are handled globally by Arenet; ignoring them is
// not worth a warning.
var silentDirectives = map[string]bool{
	"encode": true, "log": true, "log_skip": true, "tracing": true,
}

// Parse reads the Caddyfile and returns one candidate per site block.
// A syntax error Caddy itself rejects is returned as an error.
func Parse(text string) (Result, error) {
	var res Result
	if len(text) > MaxBytes {
		return res, fmt.Errorf("the Caddyfile is larger than %d KiB", MaxBytes/1024)
	}
	blocks, err := caddyfile.Parse("Caddyfile", []byte(text))
	if err != nil {
		return res, fmt.Errorf("this is not a valid Caddyfile: %w", err)
	}
	if len(blocks) > MaxBlocks {
		return res, fmt.Errorf("too many site blocks (%d); max %d", len(blocks), MaxBlocks)
	}
	for _, block := range blocks {
		keys := block.GetKeysText()
		switch {
		case len(keys) == 0:
			res.GlobalWarnings = append(res.GlobalWarnings, Warning{blockLine(block),
				"global options block ignored: Arenet manages the listeners, ACME account and logs itself"})
			continue
		case block.IsNamedRoute:
			res.GlobalWarnings = append(res.GlobalWarnings, Warning{blockLine(block),
				fmt.Sprintf("named route %q ignored: Arenet has no equivalent", keys[0])})
			continue
		case strings.HasPrefix(keys[0], "("):
			res.GlobalWarnings = append(res.GlobalWarnings, Warning{blockLine(block),
				fmt.Sprintf("snippet %s ignored (only the site blocks are imported)", keys[0])})
			continue
		}
		res.Candidates = append(res.Candidates, parseBlock(block, keys))
	}
	return res, nil
}

// blockLine is the line the block starts on.
func blockLine(b caddyfile.ServerBlock) int {
	if len(b.Keys) > 0 {
		return b.Keys[0].Line
	}
	if len(b.Segments) > 0 && len(b.Segments[0]) > 0 {
		return b.Segments[0][0].Line
	}
	return 0
}

// parseBlock turns one site block into a candidate.
func parseBlock(block caddyfile.ServerBlock, keys []string) Candidate {
	c := Candidate{Warnings: []Warning{}, Aliases: []string{}}
	line := blockLine(block)

	// --- addresses ---
	tls := true
	for _, key := range keys {
		addr, err := httpcaddyfile.ParseAddress(key)
		if err != nil {
			c.Warnings = append(c.Warnings, Warning{line, fmt.Sprintf("address %q ignored: %v", key, err)})
			continue
		}
		if addr.Host == "" {
			c.Warnings = append(c.Warnings, Warning{line,
				fmt.Sprintf("address %q ignored: Arenet routes by host name, not by port alone", key)})
			continue
		}
		if addr.Path != "" {
			c.Warnings = append(c.Warnings, Warning{line,
				fmt.Sprintf("path %q of address %q dropped: a route matches a host, use a path rule", addr.Path, key)})
		}
		if addr.Scheme == "http" {
			tls = false
		}
		if addr.Port != "" && addr.Port != "80" && addr.Port != "443" {
			c.Warnings = append(c.Warnings, Warning{line,
				fmt.Sprintf("port %s of %q ignored: Arenet serves every route on its own HTTP/HTTPS ports", addr.Port, key)})
		}
		if c.Host == "" {
			c.Host = addr.Host
		} else if addr.Host != c.Host && !contains(c.Aliases, addr.Host) {
			c.Aliases = append(c.Aliases, addr.Host)
		}
	}
	if c.Host == "" {
		c.Reason = "no host name in this block"
		return c
	}

	route := &Route{
		Host: c.Host, Aliases: c.Aliases, TLSEnabled: tls,
		ACMEChallenge: storage.ACMEChallengeHTTP01, LBPolicy: storage.LBPolicyRoundRobin,
		RequestHeaders: map[string]string{}, ResponseHeaders: map[string]string{},
	}

	// --- directives ---
	for _, seg := range block.Segments {
		if len(seg) == 0 {
			continue
		}
		d := caddyfile.NewDispenser(seg)
		if !d.Next() {
			continue
		}
		name := d.Val()
		dLine := seg[0].Line
		switch {
		case silentDirectives[name]:
		case name == "reverse_proxy":
			parseReverseProxy(d, dLine, route, &c)
		case name == "handle_path" || name == "handle" || name == "route":
			parseHandle(d, dLine, name, route, &c)
		case name == "tls":
			parseTLS(d, dLine, route, &c)
		case name == "header":
			parseHeader(d, dLine, route, &c)
		case name == "basicauth" || name == "basic_auth":
			c.Warnings = append(c.Warnings, Warning{dLine,
				"basic auth not imported: Caddy stores a bcrypt hash, Arenet needs its own — set the password again on the route"})
		default:
			c.Warnings = append(c.Warnings, Warning{dLine,
				fmt.Sprintf("directive %q not imported (Arenet has no equivalent)", name)})
		}
	}

	if len(route.Upstreams) == 0 && len(route.PathRules) == 0 {
		c.Reason = "no reverse_proxy in this block: nothing to proxy"
		return c
	}
	if len(route.Upstreams) == 0 {
		// Path rules only: the route needs a pool, reuse the first one.
		route.Upstreams = route.PathRules[0].Upstreams
		c.Warnings = append(c.Warnings, Warning{line,
			fmt.Sprintf("no site-wide reverse_proxy: the pool of %q is used as the route's default", route.PathRules[0].PathPrefix)})
	}
	sort.Strings(route.Aliases)
	route.Aliases = route.Aliases[:len(route.Aliases):len(route.Aliases)]
	c.Route = route
	c.Importable = true
	return c
}

// parseReverseProxy fills the route's pool (or a path rule when the
// directive carries a path matcher).
func parseReverseProxy(d *caddyfile.Dispenser, line int, route *Route, c *Candidate) {
	args := d.RemainingArgs()
	var matcher string
	if len(args) > 0 && (strings.HasPrefix(args[0], "/") || strings.HasPrefix(args[0], "@") || args[0] == "*") {
		matcher = args[0]
		args = args[1:]
	}
	pool := upstreams(args, line, c)

	opts := proxyOptions{}
	parseProxyBlock(d, line, &opts, c)
	if len(opts.upstreams) > 0 {
		pool = append(pool, opts.upstreams...)
	}
	if len(pool) == 0 {
		c.Warnings = append(c.Warnings, Warning{line, "reverse_proxy without an upstream ignored"})
		return
	}

	switch {
	case matcher == "" || matcher == "*" || matcher == "/*":
		route.Upstreams = append(route.Upstreams, pool...)
		applyProxyOptions(opts, route, nil, line, c)
	case strings.HasPrefix(matcher, "@"):
		c.Warnings = append(c.Warnings, Warning{line,
			fmt.Sprintf("named matcher %s not imported: only path matchers become path rules", matcher)})
	default:
		rule := storage.PathRule{PathPrefix: cleanPrefix(matcher), Upstreams: pool, LBPolicy: storage.LBPolicyRoundRobin}
		applyProxyOptions(opts, route, &rule, line, c)
		route.PathRules = append(route.PathRules, rule)
	}
}

// proxyOptions holds what a reverse_proxy block carries.
type proxyOptions struct {
	upstreams    []storage.Upstream
	lbPolicy     string
	healthURI    string
	healthInt    string
	healthTO     string
	healthStatus int
	headerUp     map[string]string
	headerDown   map[string]string
	skipVerify   bool
}

// parseProxyBlock reads the block of a reverse_proxy directive.
func parseProxyBlock(d *caddyfile.Dispenser, line int, opts *proxyOptions, c *Candidate) {
	opts.headerUp = map[string]string{}
	opts.headerDown = map[string]string{}
	for d.NextBlock(0) {
		switch d.Val() {
		case "to":
			opts.upstreams = append(opts.upstreams, upstreams(d.RemainingArgs(), line, c)...)
		case "lb_policy":
			args := d.RemainingArgs()
			if len(args) == 0 {
				continue
			}
			if p, ok := lbPolicies[args[0]]; ok {
				opts.lbPolicy = p
			} else {
				c.Warnings = append(c.Warnings, Warning{d.Line(),
					fmt.Sprintf("lb_policy %q not supported: round robin used instead", args[0])})
			}
		case "health_uri":
			opts.healthURI = firstArg(d)
		case "health_interval":
			opts.healthInt = firstArg(d)
		case "health_timeout":
			opts.healthTO = firstArg(d)
		case "health_status":
			if n, err := strconv.Atoi(strings.TrimSuffix(firstArg(d), "xx")); err == nil {
				if n < 10 {
					n *= 100
				}
				opts.healthStatus = n
			}
		case "header_up", "header_down":
			which := d.Val()
			k, v, ok := headerArgs(d)
			switch {
			case !ok:
				// Removals (-Name) and additions (+Name) have no
				// equivalent: Arenet sets headers, it does not edit them.
				c.Warnings = append(c.Warnings, Warning{d.Line(),
					fmt.Sprintf("%s %s not imported (only `%s Name value` is)", which, k, which)})
			case which == "header_up":
				opts.headerUp[k] = v
			default:
				opts.headerDown[k] = v
			}
		case "transport":
			// Consume the transport name ("http") before its block,
			// otherwise NextBlock reads it as an option.
			d.RemainingArgs()
			for d.NextBlock(1) {
				if d.Val() == "tls_insecure_skip_verify" {
					opts.skipVerify = true
				}
			}
		default:
			c.Warnings = append(c.Warnings, Warning{line,
				fmt.Sprintf("reverse_proxy option %q not imported", d.Val())})
		}
	}
}

// applyProxyOptions copies the options onto the route, or onto rule
// when the proxy was behind a path matcher.
func applyProxyOptions(opts proxyOptions, route *Route, rule *storage.PathRule, line int, c *Candidate) {
	if rule != nil {
		if opts.lbPolicy != "" {
			rule.LBPolicy = opts.lbPolicy
		}
		rule.InsecureSkipVerify = opts.skipVerify
		if len(opts.headerUp)+len(opts.headerDown) > 0 {
			c.Warnings = append(c.Warnings, Warning{line,
				fmt.Sprintf("headers of the %q proxy not imported: Arenet sets headers per route, not per path", rule.PathPrefix)})
		}
		if opts.healthURI != "" {
			c.Warnings = append(c.Warnings, Warning{line,
				fmt.Sprintf("health check of the %q proxy not imported", rule.PathPrefix)})
		}
		return
	}
	if opts.lbPolicy != "" {
		route.LBPolicy = opts.lbPolicy
	}
	if opts.skipVerify {
		route.InsecureSkipVerify = true
	}
	for k, v := range opts.headerUp {
		route.RequestHeaders[k] = v
	}
	for k, v := range opts.headerDown {
		route.ResponseHeaders[k] = v
	}
	if opts.healthURI != "" {
		route.HealthCheck = storage.HealthCheck{
			Enabled: true, URI: opts.healthURI, Method: "GET",
			Interval: orDefault(opts.healthInt, "30s"), Timeout: orDefault(opts.healthTO, "5s"),
			ExpectStatus: orDefaultInt(opts.healthStatus, 200), Passes: 1, Fails: 1,
		}
	}
}

// parseHandle reads handle / handle_path / route blocks: only the
// reverse_proxy inside becomes a path rule.
func parseHandle(d *caddyfile.Dispenser, line int, name string, route *Route, c *Candidate) {
	args := d.RemainingArgs()
	matcher := ""
	if len(args) > 0 {
		matcher = args[0]
	}
	if strings.HasPrefix(matcher, "@") {
		c.Warnings = append(c.Warnings, Warning{line,
			fmt.Sprintf("%s %s not imported: only path matchers become path rules", name, matcher)})
		return
	}
	found := false
	for d.NextBlock(0) {
		if d.Val() != "reverse_proxy" {
			c.Warnings = append(c.Warnings, Warning{line,
				fmt.Sprintf("%q inside %s %s not imported", d.Val(), name, matcher)})
			continue
		}
		found = true
		inner := caddyfile.NewDispenser(d.NextSegment())
		if !inner.Next() {
			continue
		}
		pool := upstreams(inner.RemainingArgs(), line, c)
		opts := proxyOptions{}
		parseProxyBlock(inner, line, &opts, c)
		pool = append(pool, opts.upstreams...)
		if len(pool) == 0 {
			continue
		}
		if matcher == "" || matcher == "*" || matcher == "/*" {
			route.Upstreams = append(route.Upstreams, pool...)
			applyProxyOptions(opts, route, nil, line, c)
			continue
		}
		rule := storage.PathRule{PathPrefix: cleanPrefix(matcher), Upstreams: pool, LBPolicy: storage.LBPolicyRoundRobin}
		applyProxyOptions(opts, route, &rule, line, c)
		route.PathRules = append(route.PathRules, rule)
	}
	if !found && matcher != "" {
		c.Warnings = append(c.Warnings, Warning{line, fmt.Sprintf("%s %s has no reverse_proxy: nothing to import", name, matcher)})
	}
}

// parseTLS maps the tls directive; certificates and internal CAs are
// reported instead of guessed.
func parseTLS(d *caddyfile.Dispenser, line int, route *Route, c *Candidate) {
	args := d.RemainingArgs()
	switch {
	case len(args) == 0:
	case args[0] == "internal":
		c.Warnings = append(c.Warnings, Warning{line,
			"`tls internal` not imported: the route will use a public certificate (Let's Encrypt)"})
	case strings.Contains(args[0], "@"):
		// ACME e-mail: Arenet holds the account e-mail globally.
	case len(args) >= 2:
		c.Warnings = append(c.Warnings, Warning{line,
			fmt.Sprintf("certificate %q not imported: upload it in Certificates and set the route to a manual certificate", args[0])})
	}
	for d.NextBlock(0) {
		if d.Val() == "dns" {
			// Consume the provider and its arguments, otherwise they
			// are read as further tls options (smoke-caught).
			provider := ""
			if args := d.RemainingArgs(); len(args) > 0 {
				provider = args[0]
			}
			for d.NextBlock(1) {
				d.RemainingArgs()
			}
			route.ACMEChallenge = storage.ACMEChallengeDNS01
			c.Warnings = append(c.Warnings, Warning{line, fmt.Sprintf(
				"DNS-01 kept, but configure the %s provider in Arenet's settings (credentials are not imported)",
				orDefault(provider, "DNS"))})
			continue
		}
		// Name first, then consume its arguments so they are not read
		// as further options.
		option := d.Val()
		d.RemainingArgs()
		c.Warnings = append(c.Warnings, Warning{line, fmt.Sprintf("tls option %q not imported", option)})
	}
}

// parseHeader maps the response-header directive (`header Name value`);
// removals and matchers are reported.
func parseHeader(d *caddyfile.Dispenser, line int, route *Route, c *Candidate) {
	args := d.RemainingArgs()
	if len(args) >= 2 && !strings.HasPrefix(args[0], "@") && !strings.HasPrefix(args[0], "/") {
		if strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[0], "?") {
			c.Warnings = append(c.Warnings, Warning{line, fmt.Sprintf("header %s not imported (only `header Name value` is)", args[0])})
			return
		}
		route.ResponseHeaders[args[0]] = args[1]
		return
	}
	hadBlock := false
	for d.NextBlock(0) {
		hadBlock = true
		name := d.Val()
		vals := d.RemainingArgs()
		if strings.HasPrefix(name, "-") || strings.HasPrefix(name, "?") || len(vals) == 0 {
			c.Warnings = append(c.Warnings, Warning{line, fmt.Sprintf("header %s not imported (only `Name value` is)", name)})
			continue
		}
		route.ResponseHeaders[name] = vals[0]
	}
	if !hadBlock && len(args) < 2 {
		c.Warnings = append(c.Warnings, Warning{line, "header directive not imported"})
	}
}

// upstreams turns Caddy upstream tokens into Arenet upstreams.
func upstreams(args []string, line int, c *Candidate) []storage.Upstream {
	out := make([]storage.Upstream, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "unix/") || strings.HasPrefix(a, "unix+") {
			c.Warnings = append(c.Warnings, Warning{line, fmt.Sprintf("upstream %q not imported: Arenet proxies over HTTP(S) only", a)})
			continue
		}
		if strings.Contains(a, "{") {
			c.Warnings = append(c.Warnings, Warning{line, fmt.Sprintf("upstream %q not imported: placeholders are not supported", a)})
			continue
		}
		u := a
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			u = "http://" + u
		}
		out = append(out, storage.Upstream{URL: u, Weight: 1})
	}
	return out
}

// cleanPrefix turns a Caddy path matcher into a path-rule prefix.
func cleanPrefix(matcher string) string {
	p := strings.TrimSuffix(strings.TrimSuffix(matcher, "*"), "/")
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

// firstArg returns the directive's first argument, or "".
func firstArg(d *caddyfile.Dispenser) string {
	if args := d.RemainingArgs(); len(args) > 0 {
		return args[0]
	}
	return ""
}

// headerArgs reads a header_up / header_down line; ok is false for a
// removal / addition / matcher form, and the name is returned for the
// warning.
func headerArgs(d *caddyfile.Dispenser) (string, string, bool) {
	args := d.RemainingArgs()
	if len(args) == 0 {
		return "", "", false
	}
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[0], "+") {
		return args[0], "", false
	}
	return args[0], args[1], true
}

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDefaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
