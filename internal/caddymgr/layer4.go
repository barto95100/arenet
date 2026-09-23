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

package caddymgr

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.42 — emission of the Caddy `layer4` app for TCP services.
//
// Shape (verified against caddy-l4 v0.1.1, not assumed):
//
//	"layer4": {"servers": {"svc_<id>": {
//	    "listen": ["tcp/0.0.0.0:993"],
//	    "routes": [{"match": [...], "handle": [...]}]
//	}}}
//
// Module IDs used, all present in v0.1.1:
//   - layer4.matchers.remote_ip   (field "ranges", CIDR or bare IP)
//   - layer4.matchers.crowdsec    (from the bouncer we already embed)
//   - layer4.handlers.proxy       ("upstreams[].dial" is a LIST)
//   - layer4.handlers.close       (refuse without lingering)
//
// The 2023 snapshot that used to be pulled indirectly had neither
// `close` nor `not`, which is why the dependency is now pinned
// explicitly at v0.1.1 — and at v0.1.1 rather than v0.1.2, because
// v0.1.2 drags quic-go from 0.59.1 to 0.60.0 and we are not changing
// the HTTP/3 stack to add a TCP relay.
//
// Ordering matters and is deliberate: within a server the first route
// whose matchers accept the connection handles it, and a connection
// that matches nothing is dropped by caddy-l4's terminal nop handler.
// We never rely on that implicit drop for a refusal we decided — a
// refusal is an explicit `close` route, so the emitted config reads
// the way the operator's intent reads.

const (
	l4MatcherRemoteIP = "remote_ip"
	l4MatcherCrowdSec = "crowdsec"
	l4HandlerProxy    = "proxy"
	l4HandlerClose    = "close"
)

// buildLayer4App returns the `layer4` app block, or nil when there is
// nothing to serve. Returning nil is what keeps a config emitted by an
// installation without TCP services byte-identical to the pre-v2.42
// one: the caller only inserts the key when this is non-nil.
//
// crowdSecAvailable mirrors the HTTP side: the per-service CrowdSec
// flag is only honoured when the instance actually has a bouncer
// configured, otherwise the matcher would reference an app that is
// not in the config.
func buildLayer4App(services []storage.TCPService, crowdSecAvailable bool) map[string]any {
	servers := make(map[string]any)
	for _, svc := range services {
		if svc.Disabled {
			continue
		}
		servers[l4ServerName(svc)] = map[string]any{
			"listen": []string{"tcp/" + svc.ListenHostPort()},
			"routes": buildLayer4Routes(svc, crowdSecAvailable),
		}
	}
	if len(servers) == 0 {
		return nil
	}
	return map[string]any{"servers": servers}
}

// l4ServerName gives each service its own layer4 server (spec L10):
// one bad service fails to provision on its own instead of taking the
// whole app — and with it every other service — down.
func l4ServerName(svc storage.TCPService) string {
	return "svc_" + svc.ID
}

// buildLayer4Routes renders the gates then the relay, in the order the
// connection meets them.
func buildLayer4Routes(svc storage.TCPService, crowdSecAvailable bool) []map[string]any {
	routes := make([]map[string]any, 0, 3)

	// 1. A denied source is closed before anything else looks at it.
	if f := svc.IPFilter; f != nil && f.Mode == storage.IPFilterModeDeny && len(f.CIDRs) > 0 {
		routes = append(routes, map[string]any{
			"match":  []map[string]any{{l4MatcherRemoteIP: map[string]any{"ranges": f.CIDRs}}},
			"handle": []map[string]any{{"handler": l4HandlerClose}},
		})
	}

	// 2. The relay itself, gated by whatever must be true to reach it.
	match := map[string]any{}
	if crowdSecAvailable && svc.CrowdSecEnabled {
		// The matcher takes no options; an empty object is how a
		// Caddy matcher with no configuration is written.
		match[l4MatcherCrowdSec] = map[string]any{}
	}
	if f := svc.IPFilter; f != nil && f.Mode == storage.IPFilterModeAllow && len(f.CIDRs) > 0 {
		match[l4MatcherRemoteIP] = map[string]any{"ranges": f.CIDRs}
	}

	relay := map[string]any{"handle": []map[string]any{buildLayer4Proxy(svc)}}
	if len(match) > 0 {
		relay["match"] = []map[string]any{match}
	}
	routes = append(routes, relay)

	// 3. Anything that did not reach the relay is closed explicitly
	//    rather than left to the implicit drop — but only when a gate
	//    could actually reject: without one, this route is dead code.
	if len(match) > 0 {
		routes = append(routes, map[string]any{
			"handle": []map[string]any{{"handler": l4HandlerClose}},
		})
	}
	return routes
}

// buildLayer4Proxy renders the proxy handler. `dial` is a list in
// caddy-l4 (modules/l4proxy/upstream.go), not a string.
func buildLayer4Proxy(svc storage.TCPService) map[string]any {
	upstreams := make([]map[string]any, 0, len(svc.Upstreams))
	for _, u := range svc.Upstreams {
		up := map[string]any{"dial": []string{u.Dial()}}
		if u.MaxConnections > 0 {
			up["max_connections"] = u.MaxConnections
		}
		upstreams = append(upstreams, up)
	}

	proxy := map[string]any{
		"handler":   l4HandlerProxy,
		"upstreams": upstreams,
	}
	if svc.ProxyProtocol != storage.ProxyProtocolOff {
		proxy["proxy_protocol"] = svc.ProxyProtocol
	}
	if svc.LBPolicy != "" && svc.LBPolicy != storage.TCPLBRoundRobin {
		// round_robin is caddy-l4's default; omitting it keeps the
		// emitted config free of noise.
		// The field is "selection" with an inline "policy" key
		// (modules/l4proxy/loadbalancing.go:37) — not
		// "selection_policy", which caddy.Validate rejected outright
		// when this was written from memory.
		proxy["load_balancing"] = map[string]any{
			"selection": map[string]any{"policy": svc.LBPolicy},
		}
	}
	if hc := svc.HealthCheck; hc != nil && hc.Enabled {
		active := map[string]any{}
		if hc.Interval != "" {
			active["interval"] = hc.Interval
		}
		if hc.Timeout != "" {
			active["timeout"] = hc.Timeout
		}
		proxy["health_checks"] = map[string]any{"active": active}
	}
	return proxy
}

// ReservedTCPPorts returns the ports Arenet needs for itself, mapped
// to what uses them, so a refusal can name the culprit. Callers pass
// the admin port they were configured with.
//
// 2019 is Caddy's own admin endpoint: it is bound to 127.0.0.1 and
// disabled in our config, but a service listening there would be a
// foot-gun the day it is re-enabled.
func ReservedTCPPorts(httpPort, httpsPort, adminPort int) map[int]string {
	return map[int]string{
		httpPort:  "Arenet HTTP routes",
		httpsPort: "Arenet HTTPS routes",
		adminPort: "the Arenet admin interface",
		2019:      "Caddy's admin endpoint",
	}
}

// ValidateTCPListen refuses, BEFORE anything is stored or applied, a
// service that would fight over a socket: a port Arenet needs for
// itself, or one another service already listens on. Emission would
// otherwise fail at reload time, which leaves the operator with a
// config that did not apply and no clear reason why.
func ValidateTCPListen(services []storage.TCPService, reserved map[int]string) error {
	for _, svc := range services {
		if svc.Disabled {
			continue
		}
		if what, taken := reserved[svc.ListenPort]; taken {
			return fmt.Errorf("tcp service %q: port %d is used by %s", svc.Name, svc.ListenPort, what)
		}
	}
	return l4ListenConflicts(services)
}

// CanBindTCP reports whether this process can actually listen on addr,
// and turns the privileged-port refusal into the sentence the operator
// needs. Called at validation time: a port below 1024 that the process
// cannot bind must be refused while the operator is looking at the
// form, not discovered at the next reload.
func CanBindTCP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		_ = ln.Close()
		return nil
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return fmt.Errorf(
			"cannot listen on %s: ports below 1024 need the capability. "+
				"Add `AmbientCapabilities=CAP_NET_BIND_SERVICE` to the arenet systemd unit "+
				"(or publish the port in docker-compose.yml when running in a container), "+
				"then restart Arenet: %w", addr, err)
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf("cannot listen on %s: something else on this host already uses it: %w", addr, err)
	}
	return fmt.Errorf("cannot listen on %s: %w", addr, err)
}

// l4ListenConflicts reports services that would fight over the same
// listening socket. Returned as a plain error so both the API (before
// storing) and the manager (before emitting) can refuse with the same
// message.
func l4ListenConflicts(services []storage.TCPService) error {
	seen := make(map[string]string, len(services))
	for _, svc := range services {
		if svc.Disabled {
			continue
		}
		addr := svc.ListenHostPort()
		if other, dup := seen[addr]; dup {
			return fmt.Errorf("tcp services %q and %q both listen on %s", other, svc.Name, addr)
		}
		seen[addr] = svc.Name
	}
	return nil
}
