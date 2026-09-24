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
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/caddyserver/caddy/v2"

	// v2.42 — the layer-4 modules, blank-imported here for the same
	// reason as caddy-dns/ovh above: caddy.Validate provisions the
	// emitted JSON, so `layer4.handlers.proxy` and friends must be in
	// the test binary's module registry exactly as they are in the
	// production binary (cmd/arenet/main.go).
	_ "github.com/mholt/caddy-l4/modules/l4close"
	_ "github.com/mholt/caddy-l4/modules/l4proxy"
	_ "github.com/mholt/caddy-l4/modules/l4subroute"
	_ "github.com/mholt/caddy-l4/modules/l4tls"
)

// proxyOf returns the proxy handler of a route, skipping the metrics
// handler the emitter puts in front of it.
func proxyOf(t *testing.T, route map[string]any) map[string]any {
	t.Helper()
	handle, _ := route["handle"].([]map[string]any)
	for _, h := range handle {
		if h["handler"] == l4HandlerProxy {
			return h
		}
	}
	t.Fatalf("no proxy handler in %v", handle)
	return nil
}

func imapsService() storage.TCPService {
	return storage.TCPService{
		ID:         "svc1",
		Name:       "stalwart-imaps",
		ListenPort: 9993,
		Upstreams:  []storage.TCPUpstream{{Host: "10.20.0.5", Port: 993}},
	}
}

// layer4Of unmarshals the emitted config and returns the layer4 app,
// or nil when the key is absent.
func layer4Of(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps, _ := cfg["apps"].(map[string]any)
	if apps == nil {
		t.Fatal("no apps block")
	}
	l4, _ := apps["layer4"].(map[string]any)
	return l4
}

// The contract every existing installation depends on: no TCP
// service, no change whatsoever in the emitted config.
func TestBuildConfigJSON_NoTCPServices_ByteIdentical(t *testing.T) {
	routes := []storage.Route{{
		ID: "r1", Host: "app.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}

	before, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	// Same call, but going through the v2.42 field with nothing in it
	// and with a disabled service, which must not surface either.
	after, err := buildConfigJSON(routes, buildOpts{
		DevMode: true,
		TCPServices: []storage.TCPService{
			func() storage.TCPService { s := imapsService(); s.Disabled = true; return s }(),
		},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("emitted config changed with no active TCP service:\n--- before\n%s\n--- after\n%s", before, after)
	}
	if l4 := layer4Of(t, after); l4 != nil {
		t.Fatalf("layer4 app emitted with no active service: %v", l4)
	}
}

func TestBuildLayer4App_BareService(t *testing.T) {
	app := buildLayer4App([]storage.TCPService{imapsService()}, false)
	if app == nil {
		t.Fatal("buildLayer4App: want an app, got nil")
	}
	servers, _ := app["servers"].(map[string]any)
	srv, _ := servers["svc_svc1"].(map[string]any)
	if srv == nil {
		t.Fatalf("want one server per service, got %v", servers)
	}

	listen, _ := srv["listen"].([]string)
	if len(listen) != 1 || listen[0] != "tcp/0.0.0.0:9993" {
		t.Fatalf("listen: got %v", listen)
	}

	routes, _ := srv["routes"].([]map[string]any)
	if len(routes) != 1 {
		t.Fatalf("a service with no gate needs exactly one route, got %d: %v", len(routes), routes)
	}
	if _, hasMatch := routes[0]["match"]; hasMatch {
		t.Fatal("a service with no gate must not emit a matcher")
	}
	handle, _ := routes[0]["handle"].([]map[string]any)
	// v2.42 — metrics first, then the relay.
	if len(handle) != 2 || handle[0]["handler"] != "arenet_l4metrics" || handle[0]["service_id"] != "svc1" {
		t.Fatalf("handle: want the metrics handler then the proxy, got %v", handle)
	}
	proxy := proxyOf(t, routes[0])
	// dial is a LIST in caddy-l4, not a string.
	ups, _ := proxy["upstreams"].([]map[string]any)
	dial, _ := ups[0]["dial"].([]string)
	if len(dial) != 1 || dial[0] != "tcp/10.20.0.5:993" {
		t.Fatalf("dial: got %v", ups[0]["dial"])
	}
	if _, hasPP := proxy["proxy_protocol"]; hasPP {
		t.Fatal("proxy_protocol must be absent when the service does not send it")
	}
	if _, hasLB := proxy["load_balancing"]; hasLB {
		t.Fatal("round_robin is the default; it must not be emitted")
	}
}

func TestBuildLayer4App_ProxyProtocolAndHealthCheck(t *testing.T) {
	svc := imapsService()
	svc.ProxyProtocol = storage.ProxyProtocolV2
	svc.LBPolicy = storage.TCPLBLeastConn
	svc.HealthCheck = &storage.TCPHealthCheck{Enabled: true, Interval: "30s", Timeout: "5s"}
	svc.Upstreams[0].MaxConnections = 50

	app := buildLayer4App([]storage.TCPService{svc}, false)
	srv := app["servers"].(map[string]any)["svc_svc1"].(map[string]any)
	proxy := proxyOf(t, srv["routes"].([]map[string]any)[0])

	if proxy["proxy_protocol"] != storage.ProxyProtocolV2 {
		t.Fatalf("proxy_protocol: got %v", proxy["proxy_protocol"])
	}
	lb, _ := proxy["load_balancing"].(map[string]any)
	sel, _ := lb["selection"].(map[string]any)
	if sel["policy"] != storage.TCPLBLeastConn {
		t.Fatalf("selection policy: got %v", lb)
	}
	hc, _ := proxy["health_checks"].(map[string]any)
	active, _ := hc["active"].(map[string]any)
	if active["interval"] != "30s" || active["timeout"] != "5s" {
		t.Fatalf("health check: got %v", hc)
	}
	ups := proxy["upstreams"].([]map[string]any)
	if ups[0]["max_connections"] != 50 {
		t.Fatalf("max_connections: got %v", ups[0])
	}
}

// An allow filter gates the relay and everything else is closed
// explicitly — we never rely on caddy-l4's implicit drop for a
// refusal we decided.
func TestBuildLayer4App_IPFilterAllow(t *testing.T) {
	svc := imapsService()
	svc.IPFilter = &storage.IPFilter{Mode: storage.IPFilterModeAllow, CIDRs: []string{"192.168.1.0/24"}}

	app := buildLayer4App([]storage.TCPService{svc}, false)
	routes := app["servers"].(map[string]any)["svc_svc1"].(map[string]any)["routes"].([]map[string]any)
	if len(routes) != 2 {
		t.Fatalf("want relay + close, got %d routes: %v", len(routes), routes)
	}

	match := routes[0]["match"].([]map[string]any)[0]
	ip, _ := match[l4MatcherRemoteIP].(map[string]any)
	ranges, _ := ip["ranges"].([]string)
	if len(ranges) != 1 || ranges[0] != "192.168.1.0/24" {
		t.Fatalf("remote_ip ranges: got %v", match)
	}
	if proxyOf(t, routes[0])["handler"] != l4HandlerProxy {
		t.Fatal("the gated route must relay")
	}
	if routes[1]["handle"].([]map[string]any)[0]["handler"] != l4HandlerClose {
		t.Fatalf("the fallback must close, got %v", routes[1])
	}
	if _, hasMatch := routes[1]["match"]; hasMatch {
		t.Fatal("the fallback must match everything")
	}
}

// A deny filter closes the listed sources first, then relays the rest
// with no matcher at all.
func TestBuildLayer4App_IPFilterDeny(t *testing.T) {
	svc := imapsService()
	svc.IPFilter = &storage.IPFilter{Mode: storage.IPFilterModeDeny, CIDRs: []string{"203.0.113.0/24"}}

	app := buildLayer4App([]storage.TCPService{svc}, false)
	routes := app["servers"].(map[string]any)["svc_svc1"].(map[string]any)["routes"].([]map[string]any)
	if len(routes) != 2 {
		t.Fatalf("want close + relay, got %d routes: %v", len(routes), routes)
	}
	if routes[0]["handle"].([]map[string]any)[0]["handler"] != l4HandlerClose {
		t.Fatalf("denied sources must be closed first, got %v", routes[0])
	}
	if proxyOf(t, routes[1])["handler"] != l4HandlerProxy {
		t.Fatalf("the rest must relay, got %v", routes[1])
	}
	if _, hasMatch := routes[1]["match"]; hasMatch {
		t.Fatal("the relay must not be gated when the filter is a deny list")
	}
}

// The CrowdSec matcher is only wired when the bouncer app is in the
// same config — referencing an absent app fails provisioning.
func TestBuildLayer4App_CrowdSecOnlyWhenAvailable(t *testing.T) {
	svc := imapsService()
	svc.CrowdSecEnabled = true

	without := buildLayer4App([]storage.TCPService{svc}, false)
	routes := without["servers"].(map[string]any)["svc_svc1"].(map[string]any)["routes"].([]map[string]any)
	if _, hasMatch := routes[0]["match"]; hasMatch {
		t.Fatal("no bouncer configured: the crowdsec matcher must not be emitted")
	}

	with := buildLayer4App([]storage.TCPService{svc}, true)
	routes = with["servers"].(map[string]any)["svc_svc1"].(map[string]any)["routes"].([]map[string]any)
	match := routes[0]["match"].([]map[string]any)[0]
	if _, ok := match[l4MatcherCrowdSec]; !ok {
		t.Fatalf("crowdsec matcher missing: %v", match)
	}
}

func TestBuildLayer4App_OneServerPerService(t *testing.T) {
	a := imapsService()
	b := imapsService()
	b.ID, b.Name, b.ListenPort = "svc2", "stalwart-smtp", 9025

	app := buildLayer4App([]storage.TCPService{a, b}, false)
	servers := app["servers"].(map[string]any)
	if len(servers) != 2 {
		t.Fatalf("want one server per service, got %v", servers)
	}
	if _, ok := servers["svc_svc2"]; !ok {
		t.Fatalf("server svc_svc2 missing: %v", servers)
	}
}

func TestL4ListenConflicts(t *testing.T) {
	a := imapsService()
	b := imapsService()
	b.ID, b.Name = "svc2", "other"

	if err := l4ListenConflicts([]storage.TCPService{a, b}); err == nil {
		t.Fatal("two services on the same address must conflict")
	} else if !strings.Contains(err.Error(), "9993") {
		t.Fatalf("the error must name the address, got %v", err)
	}

	b.ListenPort = 9025
	if err := l4ListenConflicts([]storage.TCPService{a, b}); err != nil {
		t.Fatalf("distinct addresses must not conflict: %v", err)
	}

	// A disabled service listens on nothing.
	b.ListenPort = 9993
	b.Disabled = true
	if err := l4ListenConflicts([]storage.TCPService{a, b}); err != nil {
		t.Fatalf("a disabled service must not conflict: %v", err)
	}
}

// The Step I.7 lesson applied to layer 4: emitting JSON that looks
// right proves nothing until Caddy provisions it. Ports are high so
// the test needs no privilege.
func TestBuildConfigJSON_LoadsCleanly_WithTCPService(t *testing.T) {
	svc := imapsService()
	svc.ProxyProtocol = storage.ProxyProtocolV2
	svc.LBPolicy = storage.TCPLBLeastConn
	svc.HealthCheck = &storage.TCPHealthCheck{Enabled: true, Interval: "30s", Timeout: "5s"}
	svc.IPFilter = &storage.IPFilter{Mode: storage.IPFilterModeAllow, CIDRs: []string{"192.168.1.0/24"}}

	routes := []storage.Route{{
		ID: "r1", Host: "app.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}

	// The arenet_routemetrics module's Provision needs the registry
	// cmd/arenet installs at boot; without it Validate fails on the
	// HTTP app for a reason that has nothing to do with layer 4.
	//
	// The singleton is process-wide, so it is reset afterwards:
	// leaving it installed changed the outcome of
	// TestSyncRegistry_NotCalledOnReloadFailure, which turns out to
	// depend on the reload failing for lack of a registry.
	metrics.SetRegistry(metrics.NewRegistry())
	t.Cleanup(metrics.ResetForTest)

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true, TCPServices: []storage.TCPService{svc}})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if l4 := layer4Of(t, raw); l4 == nil {
		t.Fatal("layer4 app missing from the emitted config")
	}
	var cfg caddy.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("caddy.Validate on a config carrying a TCP service: %v\n%s", err, raw)
	}
}

func TestValidateTCPListen_ReservedPorts(t *testing.T) {
	reserved := ReservedTCPPorts(80, 443, 8001)

	for port, what := range map[int]string{80: "HTTP", 443: "HTTPS", 8001: "admin", 2019: "Caddy admin"} {
		svc := imapsService()
		svc.ListenPort = port
		err := ValidateTCPListen([]storage.TCPService{svc}, reserved)
		if err == nil {
			t.Fatalf("port %d (%s) must be refused", port, what)
		}
		if !strings.Contains(err.Error(), svc.Name) {
			t.Fatalf("the refusal must name the service, got %v", err)
		}
	}

	ok := imapsService()
	if err := ValidateTCPListen([]storage.TCPService{ok}, reserved); err != nil {
		t.Fatalf("a free port must be accepted: %v", err)
	}

	// A disabled service listens on nothing, so it cannot clash.
	clash := imapsService()
	clash.ListenPort = 443
	clash.Disabled = true
	if err := ValidateTCPListen([]storage.TCPService{clash}, reserved); err != nil {
		t.Fatalf("a disabled service must not be refused: %v", err)
	}
}

// The bind test is what turns "port 25 without the capability" into a
// sentence at validation time instead of a failed reload. Binding a
// high port must succeed on any host running the suite; the privileged
// branch is not exercised here because the test may well run as root.
func TestCanBindTCP(t *testing.T) {
	if err := CanBindTCP("127.0.0.1:0"); err != nil {
		t.Fatalf("binding an ephemeral port must work: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	err = CanBindTCP(ln.Addr().String())
	if err == nil {
		t.Fatal("an address already in use must be refused")
	}
	if !strings.Contains(err.Error(), "already uses it") {
		t.Fatalf("the refusal must say the address is taken, got %v", err)
	}
}

// v2.42 — UDP. A layer-4 relay that could not do UDP would be no use
// for WireGuard, DNS, syslog or a game server, which is most of what
// people put behind one.
func TestBuildLayer4App_UDPService(t *testing.T) {
	svc := imapsService()
	svc.Name, svc.ListenPort = "wireguard", 51820
	svc.Protocol = storage.TCPServiceProtocolUDP
	svc.Upstreams = []storage.TCPUpstream{{Host: "10.20.0.9", Port: 51820}}
	svc.ProxyProtocol = storage.ProxyProtocolV2

	app := buildLayer4App([]storage.TCPService{svc}, false)
	srv := app["servers"].(map[string]any)["svc_svc1"].(map[string]any)

	listen, _ := srv["listen"].([]string)
	if len(listen) != 1 || listen[0] != "udp/0.0.0.0:51820" {
		t.Fatalf("listen: got %v", listen)
	}
	proxy := proxyOf(t, srv["routes"].([]map[string]any)[0])
	dial, _ := proxy["upstreams"].([]map[string]any)[0]["dial"].([]string)
	if len(dial) != 1 || dial[0] != "udp/10.20.0.9:51820" {
		t.Fatalf("dial: got %v", dial)
	}
}

// Same port number on both networks is two sockets, not a conflict.
func TestL4ListenConflicts_TCPAndUDPCoexist(t *testing.T) {
	tcpSvc := imapsService()
	udpSvc := imapsService()
	udpSvc.ID, udpSvc.Name = "svc2", "same-port-udp"
	udpSvc.Protocol = storage.TCPServiceProtocolUDP

	if err := l4ListenConflicts([]storage.TCPService{tcpSvc, udpSvc}); err != nil {
		t.Fatalf("tcp and udp on the same port must coexist: %v", err)
	}
}
