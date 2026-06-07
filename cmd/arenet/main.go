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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	// Step I.4: register the Coraza WAF Caddy module via side-effect
	// import so its handler ID `coraza` is resolvable when
	// buildConfigJSON emits a `{"handler":"coraza", ...}` block. The
	// coraza-caddy v2 package's init() side-effects on caddy.RegisterModule
	// are what make this work; no symbol from coraza-caddy is referenced
	// directly anywhere in Arenet. OWASP CRS comes embedded via the
	// transitive coraza-coreruleset/v4 dep, so the binary is self-contained.
	_ "github.com/corazawaf/coraza-caddy/v2"

	// Step J.4: register the OVH DNS provider Caddy module via
	// side-effect import so its module ID `dns.providers.ovh` is
	// resolvable when buildTLSPolicies emits a DNS-01 ACME policy
	// with `challenges.dns.provider.name == "ovh"`. Same mechanism
	// as the coraza import above — init()-time caddy.RegisterModule
	// side-effect; no symbol from caddy-dns/ovh is referenced
	// directly. Removing this import would cause caddy.Validate /
	// caddy.Load to fail with `module not registered:
	// dns.providers.ovh` the first time a DNS-01 policy is emitted.
	// The anti-regression guard is TestBuildConfigJSON_LoadsCleanly,
	// which feeds a DNS-01 fixture through caddy.Validate (§5.4).
	_ "github.com/caddy-dns/ovh"

	"github.com/caddyserver/caddy/v2"

	"github.com/barto95100/arenet/internal/api"
	"github.com/barto95100/arenet/internal/api/topology"
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/automation"
	"github.com/barto95100/arenet/internal/caddyhc"
	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/certinfo"
	appconfig "github.com/barto95100/arenet/internal/config"
	"github.com/barto95100/arenet/internal/crowdsec"
	"github.com/barto95100/arenet/internal/geo"
	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/internal/throttle"
	"github.com/barto95100/arenet/internal/waf"
	"github.com/barto95100/arenet/web"
)

// version is overridable at link time via ldflags:
//
//	go build -ldflags="-X main.version=v1.0.1" ./cmd/arenet
//
// Step #S-13 fix: this MUST be a var, not a const. Go's -ldflags
// -X directive can only write to a package-level variable; a
// const target is silently ignored by the linker (no warning, no
// error), leaving the value at its declared default. The
// Dockerfile and release workflow both inject the real version
// this way at build time.
var version = "DEV"

// Step S.3 (2026-06-01): the local `type config struct` +
// parseFlags() were replaced by the centralised internal/config
// package. The new Load() function implements the spec D5
// precedence (flag > env > file > default) and is unit-tested
// independently. main() now calls appconfig.Load(os.Args[1:])
// and the resulting *appconfig.Config carries the same fields
// (now exported / PascalCase) consumed by run() below.

func newLogger(dev bool) *slog.Logger {
	level := slog.LevelInfo
	if dev {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(handler)
}

func ensureTestRoute(ctx context.Context, logger *slog.Logger, store *storage.Store) error {
	routes, err := store.ListRoutes(ctx)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Host == "test.local" {
			logger.Info("test route already present, skipping insert", "id", r.ID)
			return nil
		}
	}
	created, err := store.CreateRoute(ctx, storage.Route{
		Host:      "test.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9999", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	if err != nil {
		return err
	}
	logger.Info("inserted test route", "id", created.ID, "host", created.Host, "upstream", created.Upstreams[0].URL)
	return nil
}

func run(ctx context.Context, logger *slog.Logger, cfg *appconfig.Config) (retErr error) {
	logger.Info("Arenet starting",
		"version", version,
		"admin_port", cfg.AdminPort,
		"data_dir", cfg.DataDir,
		"dev", cfg.Dev,
	)

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	dbPath := filepath.Join(cfg.DataDir, "arenet.db")

	store, err := storage.NewStore(dbPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			logger.Error("store close error", "err", cerr)
			if retErr == nil {
				retErr = cerr
			}
		}
	}()
	logger.Info("storage opened", "path", dbPath)

	if cfg.InsertTestRoute {
		if err := ensureTestRoute(ctx, logger, store); err != nil {
			return err
		}
	}

	// Step E metrics pipeline — wired BEFORE caddymgr.Start because
	// the Caddy module's Provision (which runs during the first
	// applyLocked inside Start) reads metrics.GlobalRegistry(). The
	// order is:
	//   1. NewRegistry             — empty counter map
	//   2. SetRegistry(reg)        — installs the process-wide singleton
	//   3. caddymgr.New(..., reg)  — manager keeps the same pointer
	//   4. mgr.Start               — Provisions the module, applies config,
	//                                runs the first syncRegistry
	//   5. Broadcaster + Ticker    — start AFTER Start so the first tick
	//                                sees a populated registry (spec §4.3)
	metricsRegistry := metrics.NewRegistry()
	metrics.SetRegistry(metricsRegistry)
	metricsBroadcaster := metrics.NewBroadcaster(logger)

	// Step I.1: propagate dev mode + ACME contact email to the
	// Caddy manager so it can pick the right listen ports
	// (:8080/:8443 vs :80/:443) and the right ACME directory
	// (Let's Encrypt staging vs prod). Empty ARENET_ACME_EMAIL is
	// accepted by Let's Encrypt but we WARN below if any route
	// already opted into TLS — the operator likely wants expiry
	// notifications and a `caa` identity tied to a mailbox.
	acmeEmail := os.Getenv("ARENET_ACME_EMAIL")
	mgr, err := caddymgr.New(store, logger, metricsRegistry, cfg.Dev, acmeEmail)
	if err != nil {
		return err
	}
	if acmeEmail == "" {
		anyTLS, listErr := storeHasTLSRoute(ctx, store)
		switch {
		case listErr != nil:
			logger.Warn("could not check for TLS routes at boot (ARENET_ACME_EMAIL empty)", "err", listErr)
		case anyTLS:
			logger.Warn("at least one route has TLSEnabled=true but ARENET_ACME_EMAIL is empty — Let's Encrypt account will be email-free, no expiry reminders")
		}
	}

	// Step J.4: WARN at boot if any route is configured for DNS-01
	// ACME but the OVH DNS provider config is missing or
	// incomplete. The API rejects new DNS-01 routes that fail this
	// guard, but a provider deletion (or a never-completed PUT)
	// AFTER routes were saved can leave the system in this state —
	// boot WARN is the safety net the (β) decision requires
	// (validation edit-time + warnings, not xor).
	anyDNS01, providerOK, dnsCheckErr := storeDNS01Inconsistency(ctx, store)
	switch {
	case dnsCheckErr != nil:
		logger.Warn("could not check DNS-01 route / provider consistency at boot", "err", dnsCheckErr)
	case anyDNS01 && !providerOK:
		logger.Warn("at least one route has acmeChallenge=dns-01 but the OVH DNS provider is not fully configured — cert renewal will fail until you complete the provider config under Settings")
	}

	// Step N.1 — CrowdSec bouncer config. Read from env vars
	// (admin-Settings UI is a future revision; v1.0 is env-only).
	// MUST be set BEFORE mgr.Start so the initial Caddy config
	// includes apps.crowdsec from the first emitted JSON.
	//
	// AC #13 (fail-open at boot): empty API key → no apps.crowdsec
	// block, no per-route handler prepend, data plane runs without
	// IP-reputation gate. WAF + rate-limiter still active.
	csURL := os.Getenv("ARENET_CROWDSEC_API_URL")
	csKey := os.Getenv("ARENET_CROWDSEC_API_KEY")
	mgr.SetCrowdSecConfig(csURL, csKey)
	if csKey != "" {
		effURL := csURL
		if effURL == "" {
			effURL = "http://127.0.0.1:8080/"
		}
		logger.Info("crowdsec bouncer wired", "lapi_url", effURL)
	} else {
		logger.Info("crowdsec bouncer not configured (set ARENET_CROWDSEC_API_KEY to enable the IP-reputation gate)")
	}

	// #R-TOPO-real-health-probe (Stage B) — install the HC status
	// tracker BEFORE mgr.Start. Caddy's events App provisions the
	// arenet_topology_hc handler during caddy.Load (called from
	// inside mgr.Start); the handler's Provision then captures
	// the tracker via the package-level singleton. The Handle
	// path queries getTracker() per event, so a delayed install
	// would technically still work, but installing-then-starting
	// is the honest order: Caddy can fire its first event the
	// instant the active health-checker goroutine spawns, and we
	// want the tracker ready by then.
	hcTracker := caddyhc.NewTracker()
	caddyhc.SetTracker(hcTracker)

	// Bootstrap-prime the tracker so upstreams that boot healthy
	// and stay healthy aren't stuck at StatusUnknown for the
	// process's lifetime. Caddy's active health checker only
	// emits "healthy"/"unhealthy" events on STATE TRANSITIONS
	// (healthchecks.go:479/502: setHealthy returns true only when
	// the call actually flipped state). Upstreams start healthy
	// by default in Caddy; a route that boots healthy and stays
	// healthy never transitions, so Caddy never emits, and the
	// tracker would have no entry — the topology would render
	// gray-unknown forever on a route the operator can plainly
	// see is working.
	//
	// Priming-as-healthy mirrors Caddy's own optimistic default.
	// The first real event from Caddy (either healthy → unhealthy
	// on a failed probe, or the recovery transition back) will
	// overwrite the primed state immediately. The window where
	// the priming could be misleading: a downed upstream during
	// the first ~30-60s after boot, before Caddy's first probe
	// has time to fail. That's an acceptable trade-off — see
	// #R-TOPO-hc-bootstrap-down in the backlog.
	if routes, rerr := store.ListRoutes(ctx); rerr != nil {
		logger.Warn("topology HC bootstrap: failed to read routes; skipping prime",
			"err", rerr)
	} else {
		for _, r := range routes {
			if !r.HealthCheck.Enabled {
				continue
			}
			for _, u := range r.Upstreams {
				hcTracker.RecordHealthy(u.URL)
			}
		}
	}

	// Step T T.1 (2026-06-05) — install the cert-info tracker
	// BEFORE mgr.Start, same order as the hcTracker above and for
	// the same reason: the arenet_cert_info handler's Provision
	// pulls the singleton during caddy.Load (called from inside
	// mgr.Start), and the first cert event can fire the instant
	// certmagic's renewal loop spawns.
	//
	// Satisfies AC #1 cold-start bootstrap (Step T spec
	// v1.2.0-step-t-spec). Implemented by 1350777 (T.1);
	// wire-up safety belt by 30418ea (HF4).
	//
	// Reconcile-from-disk seeds the tracker with every cert
	// already on disk so the Certificates page shows correct
	// state immediately on boot — without it, freshly-restarted
	// AreNET would render an empty page until the next renewal /
	// new issuance fired an event. ReconcileFromDisk tolerates
	// a missing storage directory (fresh install) by returning
	// (0, nil); only catastrophic I/O failures bubble an error.
	certTracker := certinfo.NewTracker()
	certinfo.SetTracker(certTracker)
	certStorageDir := caddy.AppDataDir()
	if seeded, rerr := certinfo.ReconcileFromDisk(certTracker, certStorageDir); rerr != nil {
		logger.Warn("certinfo reconcile failed; tracker starts empty",
			"err", rerr, "storage", certStorageDir)
	} else {
		logger.Info("certinfo reconcile complete",
			"seeded", seeded, "storage", certStorageDir)
	}

	// Step V.1.3 — parse normal-traffic env vars + push the
	// operator's path-prefix exclusions into the manager
	// BEFORE Start so the first applyLocked emits them on
	// every route's metricsHandler config. Same invariant
	// as SetCrowdSecConfig above.
	//
	// All 3 env vars default to safe values:
	//   - SAMPLE_PCT default 0 → V.1 disabled (sink never
	//     installed at all). Boot signal still fires with
	//     present=false.
	//   - PER_IP_COOLDOWN default 30s (spec §D9).
	//   - EXCLUDE_PATHS default empty → only the hardcoded
	//     V.1.2 list applies (/healthz, /metrics,
	//     /api/v1/ws/topology, /api/v1/ws/geo-events).
	//
	// Validation: invalid SAMPLE_PCT / cooldown values are
	// FATAL at boot (returned as an error from run()) per
	// the spec §5 contract — silent fallback would mislead
	// the operator into thinking V.1 is configured when it
	// isn't. EXCLUDE_PATHS is a list parse: empty + extra
	// commas + whitespace are all forgiven.
	normalSamplePct, err := parseNormalTrafficSamplePct(os.Getenv("ARENET_NORMAL_TRAFFIC_SAMPLE_PCT"))
	if err != nil {
		return fmt.Errorf("invalid ARENET_NORMAL_TRAFFIC_SAMPLE_PCT: %w", err)
	}
	normalCooldown, err := parseNormalTrafficCooldown(os.Getenv("ARENET_NORMAL_TRAFFIC_PER_IP_COOLDOWN"))
	if err != nil {
		return fmt.Errorf("invalid ARENET_NORMAL_TRAFFIC_PER_IP_COOLDOWN: %w", err)
	}
	normalExcludePaths := parseNormalTrafficExcludePaths(os.Getenv("ARENET_NORMAL_TRAFFIC_EXCLUDE_PATHS"))
	mgr.SetNormalTrafficExcludePaths(normalExcludePaths)

	if err := mgr.Start(ctx); err != nil {
		return err
	}
	defer func() {
		if cerr := mgr.Stop(); cerr != nil {
			logger.Error("caddy stop error", "err", cerr)
			if retErr == nil {
				retErr = cerr
			}
		}
	}()

	// Build the metrics ticker FIRST so we can wire the
	// observability consumer (Step L L.7) on it BEFORE the tick
	// goroutine starts. The ticker reads .consumer without
	// synchronisation from its hot loop, so SetConsumer must
	// happen pre-Run.
	metricsTicker := metrics.NewTicker(metricsRegistry, metricsBroadcaster, &storeLister{store: store})

	// Step L L.1 — observability subsystem (per-route metrics
	// history on SQLite). AC #13 degraded-mode policy: if any
	// step here fails, log the error and continue WITHOUT the
	// metrics history. The Caddy data plane and the Step E live
	// pipeline must keep running.
	//
	// The aggregator and retention runner are started even when
	// the store is nil — they become silent no-ops (the
	// aggregator still drains its ingress channel so the
	// producer never blocks; the retention runner ticks but
	// finds nothing to do). This uniform shape keeps the wire-up
	// simple: the ticker always has a valid TickConsumer to feed.
	obsPath := filepath.Join(cfg.DataDir, "metrics.db")
	obsStore, obsErr := observability.Open(ctx, obsPath)
	if obsErr != nil {
		logger.Error("observability: metrics DB unavailable — continuing without metrics history (AC #13)",
			"path", obsPath, "err", obsErr,
		)
		obsStore = nil
	} else {
		logger.Info("observability storage opened", "path", obsPath)
	}

	// Step V.1 — GeoIP lookup + server position auto-detect.
	//
	// Both components are degraded-mode tolerant per spec §3.7:
	// missing MMDB or network failure yields nil/no-position, V.2
	// sinks read nil as "skip enrichment", V.4 will surface manual
	// override as the operator escape hatch. No fatal exit, no
	// panic — matches the AC #13 pattern from Step T.
	//
	// MMDB path resolution per spec §3.2: ARENET_GEOIP_MMDB env
	// override beats the canonical /var/lib/arenet path. Boot-log
	// signals follow the HF4 pattern (commit 30418ea) so future
	// wire-up regressions surface in journalctl, not silently.
	geoMMDBPath := os.Getenv("ARENET_GEOIP_MMDB")
	if geoMMDBPath == "" {
		geoMMDBPath = "/var/lib/arenet/GeoLite2-City.mmdb"
	}
	geoLookup, geoErr := geo.NewLookup(geoMMDBPath)
	if geoErr != nil {
		logger.Warn("geoip database not loaded — geo enrichment degraded",
			"path", geoMMDBPath, "present", false, "err", geoErr)
	} else {
		logger.Info("geoip database loaded",
			"path", geoMMDBPath, "present", true)
		defer func() {
			if cerr := geoLookup.Close(); cerr != nil {
				logger.Warn("geoip database close error", "err", cerr)
			}
		}()
	}

	// Step V.4 — server position resolution. Order of
	// precedence (spec §5.1):
	//
	//   1. Persisted manual override in arenet.db wins always
	//      — the operator's choice survives reboots without
	//      being clobbered by auto-detect.
	//   2. Persisted auto-detect row (from a previous boot)
	//      is used when the GeoIP DB is missing OR the ipify
	//      call is failing on THIS boot — the cached row is
	//      still a reasonable Mercator center.
	//   3. Live auto-detect via geo.DetectFromPublicIP when
	//      a MMDB is available — opportunistically persisted
	//      so the next boot can skip the ipify call.
	//   4. Degraded: nil bootPosition, GET endpoint returns
	//      {degraded:true}, frontend renders the banner.
	//
	// Modes:
	//   bootPositionMode = "manual" → operator-supplied (won path 1)
	//   bootPositionMode = "auto"   → fresh live detect (path 3)
	//                              OR persisted auto row (path 2)
	//   bootPositionMode = "none"   → degraded (path 4)
	var bootPosition *geo.ServerPosition
	bootPositionMode := "none"

	if persisted, perr := store.GetServerPosition(ctx); perr == nil {
		bootPosition = &geo.ServerPosition{
			Lat:        persisted.Lat,
			Lon:        persisted.Lon,
			City:       persisted.City,
			Country:    persisted.Country,
			Mode:       persisted.Mode,
			SourceIP:   persisted.SourceIP,
			DetectedAt: persisted.DetectedAt,
		}
		bootPositionMode = persisted.Mode
		logger.Info("server position loaded from store",
			"mode", persisted.Mode,
			"lat", persisted.Lat, "lon", persisted.Lon,
			"city", persisted.City, "country", persisted.Country)
	} else if !errors.Is(perr, storage.ErrNotFound) {
		logger.Warn("server position store read failed; falling back to auto-detect",
			"err", perr)
	}

	// Skip live auto-detect when the persisted row is a
	// manual override — the operator's choice wins. For an
	// auto row (or no row) we re-detect on every boot so the
	// position stays fresh when the public IP changes.
	if bootPositionMode != geo.ServerPositionModeManual {
		if geoLookup != nil {
			autoPos, autoErr := geo.DetectFromPublicIP(geoLookup)
			if autoErr != nil {
				logger.Warn("server position auto-detect failed; manual override required (V.4)",
					"err", autoErr)
			} else {
				bootPosition = autoPos
				bootPositionMode = autoPos.Mode
				logger.Info("server position auto-detected",
					"lat", autoPos.Lat, "lon", autoPos.Lon,
					"city", autoPos.City, "country", autoPos.Country,
					"mode", autoPos.Mode, "source_ip", autoPos.SourceIP)
				// Opportunistically persist so a next-boot
				// network hiccup doesn't degrade the map.
				if perr := store.PutServerPosition(ctx, storage.ServerPositionRecord{
					Lat:        autoPos.Lat,
					Lon:        autoPos.Lon,
					City:       autoPos.City,
					Country:    autoPos.Country,
					Mode:       autoPos.Mode,
					SourceIP:   autoPos.SourceIP,
					DetectedAt: autoPos.DetectedAt,
				}); perr != nil {
					logger.Warn("server position persist failed (non-fatal)",
						"err", perr)
				}
			}
		} else if bootPosition == nil {
			logger.Info("server position auto-detect skipped (geoip database absent)")
		}
	}
	logger.Info("boot server position resolved",
		"mode", bootPositionMode,
		"position_present", bootPosition != nil)

	// Step V.2 — Geo event enricher. Pure translation layer
	// from the per-source event types (waf/throttle/crowdsec/
	// auth) to the common GeoEvent shape spec §5.6 locks. The
	// V.3 forwarder sinks read this enricher to translate
	// per-source events into the wire shape the bus
	// broadcasts. Nil-tolerant per V.1 contract: a missing
	// MMDB leaves the Lookup as nil and the enricher returns
	// UNK-country events instead of panicking.
	//
	// MUST be created BEFORE the per-source sinks below so
	// the geo-forwarding wrappers can capture it at sink-
	// installation time.
	geoEnricher := geo.NewEnricher(geoLookup)
	logger.Info("geo event enricher wired",
		"lookup_present", geoEnricher.HasLookup(),
	)

	// Step V.3 — Geo event bus + ring buffer. Capacity locked
	// at spec §3.5 (N=500). The bus is the single fan-out
	// point: the four geo-forwarding sink wrappers below
	// publish into it; the WS handler subscribes for live
	// push; the GET /observability/geo-events handler reads
	// SnapshotLimited for the page-mount replay.
	//
	// nil-bus is the AC #13 degraded case: every consumer
	// honors it. The bus itself is allocated unconditionally
	// (cheap — just a 500-slot slice + a mutex) so the
	// observability subsystem only degrades when an outer
	// dependency (the GeoIP Lookup, in practice) is missing.
	//
	// MUST be created BEFORE the per-source sinks below so
	// the geo-forwarding wrappers can capture it at sink-
	// installation time.
	geoBus := geo.NewBus(geo.DefaultRingCapacity)
	logger.Info("geo event bus wired",
		"ring_capacity", geo.DefaultRingCapacity,
	)

	// Step V.1.3 — install the normal-traffic sink.
	//
	// Install-order: the geoBus + geoEnricher just got
	// constructed; mgr.Start ran earlier. The V.1.2
	// middleware reads metrics.GlobalNormalSubmitter()
	// LIVE on every eligible request via an atomic.Pointer
	// (see internal/metrics/global.go), so a late
	// installation is observed by all already-provisioned
	// RouteMetricsHandler instances on their next
	// request. No reload needed.
	//
	// When SAMPLE_PCT=0 (V.1 disabled — default), we still
	// emit the boot signal so the operator can grep
	// "normal traffic sink wired" in journalctl and
	// confirm V.1 is intentionally off, not silently
	// broken.
	//
	// Option D LAN counter deferment (per V.1.3 brief): we
	// pass NoopLANCounter for now. The real LAN pill
	// counter lives in the frontend (V.6 page-bus
	// subscriber); wiring it through a backend channel
	// would require a new HTTP endpoint or a WS frame
	// extension that doesn't fit V.1.3's scope. V.1.4
	// re-evaluates whether the LAN counter is even
	// meaningful for normal traffic (operator probably
	// cares less about LAN normal than LAN auth-failure).
	// Deviation from spec §3.5 D2 — flagged in the V.1.3
	// commit body; revisit at V.1.5 smoke.
	if normalSamplePct > 0 {
		normalSink := geo.NewDefaultNormalSink(geoBus, geoEnricher, geo.NoopLANCounter{}, geo.NormalSinkConfig{
			SamplePct: normalSamplePct,
			Cooldown:  normalCooldown,
		})
		metrics.SetNormalSubmitter(geoForwardingNormalSink{inner: normalSink})
		defer func() {
			if err := normalSink.Close(); err != nil {
				logger.Warn("normal traffic sink close error", "err", err)
			}
		}()
	}
	// The trusted-proxy-aware client-IP resolver is wired
	// later, AFTER auth.NewIPExtractor is constructed
	// (search for "Step V.1.3 — install trusted-proxy-aware
	// client-IP resolver" further down). atomic.Pointer
	// makes late installation visible to all already-
	// provisioned middleware handlers on their next
	// request.
	logger.Info("normal traffic sink wired",
		"present", normalSamplePct > 0,
		"sample_pct", normalSamplePct,
		"cooldown", normalCooldown.String(),
		"exclude_paths_count", len(normalExcludePaths),
		"hardcoded_exclude_paths_count", len(metrics.HardcodedExcludePaths()),
	)

	obsAggregator := observability.NewAggregator(obsStore, logger, 4096)
	obsRetention := observability.NewRetentionRunner(obsStore, logger)
	metricsTicker.SetConsumer(obsAggregator)
	obsCtx, obsCancel := context.WithCancel(ctx)
	var obsWG sync.WaitGroup
	obsWG.Add(2)
	go func() {
		defer obsWG.Done()
		obsAggregator.Run(obsCtx)
	}()
	go func() {
		defer obsWG.Done()
		obsRetention.Run(obsCtx)
	}()
	defer func() {
		obsCancel()
		obsWG.Wait()
		if obsStore != nil {
			if cerr := obsStore.Close(); cerr != nil {
				logger.Error("observability store close error", "err", cerr)
			}
		}
		logger.Info("observability subsystem stopped")
	}()

	// Step M.1 — WAF event sink. Wraps the observability
	// store's InsertWafEventBatch + the aggregator's
	// BumpWafBlocks via two tiny adapters (the waf package's
	// Inserter / BlockCounter interfaces). Both adapters
	// tolerate a nil store (AC #13 degraded-mode):
	//   - Inserter adapter holds the *observability.Store
	//     reference; when nil, the sink's flush path is a
	//     debug-logged no-op (events drop silently).
	//   - BlockCounter adapter is the aggregator directly —
	//     even in nil-store mode the aggregator drains its
	//     channel so the sink never backs up.
	//
	// WAF events from the custom arenet_waf Caddy module
	// reach this sink via the package-global SetGlobalSink
	// pointer (set just below). The pattern mirrors
	// metrics.SetRegistry — Caddy provisions modules from
	// JSON config and cannot inject Go pointers, so a
	// package-singleton is the only path.
	wafSink := waf.NewSink(wafInserterAdapter{obsStore}, obsAggregator, logger, waf.SinkConfig{})
	// Step V.3 — wrap the production sink with the
	// geo-forwarding adapter so every WAF block also lands on
	// the geo bus. The wrapper's Emit publishes the enriched
	// event to the bus, then delegates to the wrapped sink for
	// persistence + counter bump. Both inner sink and bus are
	// nil-safe at the wrapper; the data plane is unaffected.
	waf.SetGlobalSink(geoForwardingWafSink{bus: geoBus, enricher: geoEnricher, inner: wafSink})
	wafCtx, wafCancel := context.WithCancel(ctx)
	var wafWG sync.WaitGroup
	wafWG.Add(1)
	go func() {
		defer wafWG.Done()
		wafSink.Run(wafCtx)
	}()
	defer func() {
		wafCancel()
		wafWG.Wait()
		waf.SetGlobalSink(nil) // help GC + make test isolation cleaner
		logger.Info("waf sink stopped")
	}()
	if obsStore != nil {
		logger.Info("waf event sink wired", "store", obsPath)
	} else {
		logger.Info("waf event sink running in degraded mode (no persistence)")
	}

	// Step Q.1 — Throttle (rate-limit) event sink. Mirror of
	// the WAF wiring above. The auth handler's rate limiter
	// reaches this sink via the package-global SetGlobalSink
	// pointer; same rationale as waf.SetGlobalSink — internal
	// /auth lives in a different package and the rate limiter
	// predates the sink's lifecycle (it is constructed before
	// obsStore is opened, so constructor injection isn't
	// viable).
	//
	// AC #13 degraded-mode mirror: nil obsStore → adapter
	// returns nil from each flush (events drop silently rather
	// than inflating FlushErrBatches).
	throttleSink := throttle.NewSink(throttleInserterAdapter{obsStore}, obsAggregator, logger, throttle.SinkConfig{})
	// Step V.3 — geo-forwarding wrapper, mirror of the WAF
	// install above.
	throttle.SetGlobalSink(geoForwardingThrottleSink{bus: geoBus, enricher: geoEnricher, inner: throttleSink})
	throttleCtx, throttleCancel := context.WithCancel(ctx)
	var throttleWG sync.WaitGroup
	throttleWG.Add(1)
	go func() {
		defer throttleWG.Done()
		throttleSink.Run(throttleCtx)
	}()
	defer func() {
		throttleCancel()
		throttleWG.Wait()
		throttle.SetGlobalSink(nil)
		logger.Info("throttle sink stopped")
	}()
	if obsStore != nil {
		logger.Info("throttle event sink wired", "store", obsPath)
	} else {
		logger.Info("throttle event sink running in degraded mode (no persistence)")
	}

	// Step N.2 — CrowdSec decision event sink. Mirror of the
	// throttle wiring above, with TWO structural twists per N
	// spec:
	//   1. Dedupe BEFORE bump (D4.A): the LRU gates BOTH the
	//      event-table row AND the BlockCounter bump,
	//      preventing the bucket counter from inflating by
	//      (active_count × polls_per_minute) every minute.
	//   2. Parallel consumer architecture (D3.A): the
	//      caddy-crowdsec-bouncer (wired by N.1 in caddymgr)
	//      enforces decisions at the proxy edge; Arenet runs
	//      its OWN independent go-cs-bouncer.StreamBouncer
	//      consumer here to mirror decisions into the
	//      decision_event table for the dashboard. Both
	//      consumers poll LAPI at TickerInterval (60s per
	//      D7.A); bandwidth duplication is negligible
	//      against a homelab LAPI.
	//
	// AC #13 degraded-mode discipline mirrors M / Q:
	//   - nil obsStore (boot-failed observability) → adapter
	//     returns nil from each flush.
	//   - empty csKey (LAPI not configured at N.1 step) →
	//     the LiveSource is NOT built; the Consumer is NOT
	//     started; the Sink runs as a no-op drain that
	//     anything (e.g. a future test injection) can still
	//     emit into without crashing.
	crowdsecSink := crowdsec.NewSink(crowdsecInserterAdapter{obsStore}, obsAggregator, logger, crowdsec.SinkConfig{})
	// Step V.3 — geo-forwarding wrapper, mirror of the WAF /
	// throttle installs above.
	crowdsec.SetGlobalSink(geoForwardingCrowdsecSink{bus: geoBus, enricher: geoEnricher, inner: crowdsecSink})
	crowdsecCtx, crowdsecCancel := context.WithCancel(ctx)
	var crowdsecWG sync.WaitGroup
	crowdsecWG.Add(1)
	go func() {
		defer crowdsecWG.Done()
		crowdsecSink.Run(crowdsecCtx)
	}()

	// Spawn the parallel StreamBouncer consumer ONLY when the
	// LAPI key is configured. The caddy-crowdsec-bouncer side
	// is wired separately (N.1) and uses the same env vars;
	// when csKey is empty, BOTH consumers are absent and
	// /security/decisions returns disabled=true (AC #15).
	if csKey != "" {
		csEffURL := csURL
		if csEffURL == "" {
			csEffURL = "http://127.0.0.1:8080/"
		}
		liveSrc, srcErr := crowdsec.NewLiveSource(crowdsec.LiveSourceConfig{
			APIURL:         csEffURL,
			APIKey:         csKey,
			UserAgent:      "arenet/1.1 (mirror-consumer)",
			TickerInterval: crowdsec.SleepInterval,
		}, logger)
		if srcErr != nil {
			// Fail-open per AC #13: a LiveSource init failure
			// (bad URL shape, etc.) does NOT abort boot. The
			// bouncer-side enforcement may still come up
			// (different code path); only the mirror is
			// disabled. Operator sees the ERROR log line +
			// /security/decisions returns disabled=true.
			logger.Error("crowdsec mirror consumer: LiveSource init failed; mirror disabled (data plane unaffected — bouncer enforcement may still be active)",
				"err", srcErr)
		} else {
			crowdsecConsumer := crowdsec.NewConsumer(liveSrc, crowdsecSink, logger)
			crowdsecWG.Add(1)
			go func() {
				defer crowdsecWG.Done()
				crowdsecConsumer.Run(crowdsecCtx)
			}()
			logger.Info("crowdsec mirror consumer wired", "lapi_url", csEffURL, "ticker", crowdsec.SleepInterval)
		}
	} else {
		logger.Info("crowdsec mirror consumer not configured (set ARENET_CROWDSEC_API_KEY to enable the dashboard mirror)")
	}

	defer func() {
		crowdsecCancel()
		crowdsecWG.Wait()
		crowdsec.SetGlobalSink(nil)
		logger.Info("crowdsec sink stopped")
	}()

	if obsStore != nil {
		logger.Info("crowdsec event sink wired", "store", obsPath)
	} else {
		logger.Info("crowdsec event sink running in degraded mode (no persistence)")
	}

	// Step U.1 — Cert event sink. Subscribes (in U.2) to the
	// internal/certinfo.Tracker via the AC #18 Subscribe seam
	// from T.1 (commit 1350777) and persists lifecycle events
	// to the cert_event table (schema v5). U.1 ships the sink
	// + the boot-log signal; the actual Subscribe wire-up
	// arrives with U.2, so this sink starts here with zero
	// producers and remains idle until then. That's
	// intentional: U.1's role is to ship a working
	// infrastructure U.2 can plug into without a second main.go
	// edit.
	//
	// AC #13 degraded-mode mirror: nil obsStore (boot-failed
	// observability) → adapter returns nil from each flush
	// (events drop silently rather than inflating
	// FlushErrBatches). The sink runs as a no-op drain.
	//
	// Boot log generalizes the HF4 purger_present=true pattern
	// (commit 30418ea, backlog #R-API-boot-log-audit): future
	// wire-up regressions surface as present=false in
	// journalctl instead of silent degradation.
	certEventSink := observability.NewCertEventSink(certEventInserterAdapter{obsStore}, logger, observability.CertSinkConfig{})
	certEventCtx, certEventCancel := context.WithCancel(ctx)
	if err := certEventSink.Start(certEventCtx); err != nil {
		certEventCancel()
		return fmt.Errorf("start cert event sink: %w", err)
	}
	defer func() {
		certEventCancel()
		if stopErr := certEventSink.Stop(5 * time.Second); stopErr != nil {
			logger.Error("cert event sink stop timeout", slog.String("err", stopErr.Error()))
		}
		logger.Info("cert event sink stopped")
	}()
	logger.Info("cert event sink wired",
		"present", true,
		"store", obsPath,
		"degraded", obsStore == nil,
	)

	// Step U.2 — subscribe the cert event sink to the certinfo
	// Tracker's fan-out via the AC #18 Subscribe seam (T.1
	// commit 1350777). The adapter translates certinfo.Event →
	// observability.CertEvent and filters per spec §3.3
	// (Obtaining), §3.5 (cached_*), §3.8 (Removed). Subscription
	// must happen AFTER the sink is started (so the first event
	// the adapter forwards has a live channel to land in) AND
	// BEFORE caddy starts firing events. The unsubscribe defer
	// runs LIFO BEFORE the sink-stop defer above, so the tracker
	// stops sending into the channel before the sink drains.
	//
	// Boot log mirrors HF4's purger_present=true pattern (commit
	// 30418ea + backlog #R-API-boot-log-audit): any future
	// regression where the Subscribe call silently no-ops surfaces
	// as subscribed=false in journalctl instead of silent
	// degradation.
	certEventAdapter := observability.NewCertEventAdapter(certEventSink)
	unsubCertEventAdapter := certTracker.Subscribe(certEventAdapter)
	defer unsubCertEventAdapter()
	logger.Info("cert event sink subscribed to tracker",
		"subscribed", true,
	)

	// Step V.2 — Auth event sink. Mirror of the cert event
	// sink shape above (channel + batcher, AC #13 degraded mode
	// when obsStore is nil). The audit_helpers.appendAudit
	// fan-out in internal/api submits to this sink alongside
	// the existing audit-bucket Append per spec §3.6. The
	// audit log keeps the canonical record; this sink is the
	// real-time stream the V.3 geo bus consumes.
	//
	// Subscription wire (audit_helpers fan-out → sink) happens
	// when apiHandler.SetAuthEventSink fires below.
	authEventSink := observability.NewAuthEventSink(obsStore, logger, observability.AuthSinkConfig{})
	authEventCtx, authEventCancel := context.WithCancel(ctx)
	if err := authEventSink.Start(authEventCtx); err != nil {
		authEventCancel()
		return fmt.Errorf("start auth event sink: %w", err)
	}
	defer func() {
		authEventCancel()
		if stopErr := authEventSink.Stop(5 * time.Second); stopErr != nil {
			logger.Error("auth event sink stop timeout", slog.String("err", stopErr.Error()))
		}
		logger.Info("auth event sink stopped")
	}()
	logger.Info("auth event sink wired",
		"present", true,
		"store", obsPath,
		"degraded", obsStore == nil,
	)

	// (Step V.2 enricher + V.3 bus were moved upward to right
	// after geoLookup so the per-source sinks above can be
	// wrapped at construction time. See the §V.2/§V.3 wire-up
	// block above for the rationale.)

	// Start the metrics ticker AFTER caddymgr.Start so the first
	// tick sees the registry already populated by the post-Start
	// syncRegistry. Run on a child context so a Ctrl-C / shutdown
	// cancels Run promptly; we wait for the goroutine to exit
	// before returning from run(). The deferred tickerCancel
	// fires BEFORE the obsCancel above (LIFO defer order), so
	// the ticker stops sending to the aggregator before the
	// aggregator's Run goroutine exits — no panic-on-closed-chan
	// risk because the aggregator's in channel is buffered and
	// never closed; the producer just stops calling.
	tickerCtx, tickerCancel := context.WithCancel(ctx)
	var tickerWG sync.WaitGroup
	tickerWG.Add(1)
	go func() {
		defer tickerWG.Done()
		metricsTicker.Run(tickerCtx)
	}()
	defer func() {
		tickerCancel()
		tickerWG.Wait()
		logger.Info("metrics pipeline stopped")
	}()
	logger.Info("metrics pipeline started",
		"tick_interval", metrics.TickInterval,
		"ws_path", "/api/v1/ws/topology",
	)

	auditStore := audit.NewStore(store.DB())
	userStore := auth.NewUserStore(store.DB())
	sessionStore := auth.NewSessionStore(store.DB())
	hibpClient := auth.NewHIBPClient()
	rateLimiter := auth.NewRateLimiter(logger)
	rateLimiter.Start(ctx)
	setupTokenHolder := api.NewSetupTokenHolder()

	ipExtractor, err := auth.NewIPExtractor(os.Getenv("ARENET_TRUSTED_PROXIES"))
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if cidrs := ipExtractor.TrustedCIDRs(); len(cidrs) > 0 {
		logger.Info("auth: trusted proxies configured", "count", len(cidrs), "cidrs", cidrs)
	} else {
		logger.Info("auth: no trusted proxies configured (X-Forwarded-For will be ignored)")
	}

	// Step V.1.3 — install trusted-proxy-aware client-IP
	// resolver for the V.1 normal-traffic middleware.
	// Late install (post-ipExtractor construction) but
	// before any per-route traffic flows. atomic.Pointer
	// makes the swap visible to all already-provisioned
	// RouteMetricsHandler instances on their next
	// request.
	metrics.SetClientIPFn(ipExtractor.ClientIP)

	// Generate setup token if the users bucket is empty. The token
	// is logged at Info so the operator can paste it into /setup.
	userCount, err := userStore.Count(ctx)
	if err != nil {
		return fmt.Errorf("auth: count users: %w", err)
	}
	if userCount == 0 {
		tok := setupTokenHolder.Generate()
		logger.Info("Setup token: " + tok)
	}

	apiHandler := api.NewHandler(
		store, mgr, auditStore,
		userStore, sessionStore, hibpClient, rateLimiter, setupTokenHolder,
		cfg.Dev, logger,
	)
	if cfg.UIOrigin != "" {
		apiHandler.SetUIOrigin(cfg.UIOrigin)
		logger.Info("OIDC callback redirects will target SPA origin", "ui_origin", cfg.UIOrigin)
	}
	// Step L L.2 — attach the observability store to the API
	// handler so /api/v1/metrics/* can serve history.
	//
	// Pass the interface value explicitly nil when the store
	// failed to open (AC #13 degraded mode). Lifting a typed
	// (*observability.Store)(nil) into MetricsReader would
	// produce a non-nil interface wrapping a nil pointer — the
	// handler's `h.metrics == nil` check would miss it and the
	// next method call would NPE. The conditional assignment
	// keeps the interface comparison honest.
	if obsStore != nil {
		apiHandler.SetMetricsReader(obsStore)
		// Step M.2 — same nil-guard discipline for the WAF
		// event reader. Both the bucket metrics and the
		// per-event log live on *observability.Store; we
		// inject them independently so future test scaffolds
		// can mock one without the other.
		apiHandler.SetWafEventReader(obsStore)
		// Step Q.3 — throttle event reader. Backed by the
		// same *observability.Store (the throttle_event
		// table lives in metrics.db). Independent setter so
		// a future test can stub it without touching the
		// WAF reader. AC #14: nil obsStore → no setter call
		// → endpoints return disabled=true.
		apiHandler.SetThrottleEventReader(obsStore)
		// Step N.3 — CrowdSec decision reader. Backed by the
		// same *observability.Store (decision_event table from
		// N.2 storage). Same nil-obsStore degraded path as the
		// throttle reader above.
		apiHandler.SetDecisionReader(obsStore)
		// Step U.3 — cert event reader. Backed by the same
		// *observability.Store (cert_event table from U.1
		// storage; U.2's sink writes the rows this reader
		// serves). The endpoint at /observability/cert-events
		// powers the Activity log page's cert source.
		apiHandler.SetCertEventReader(obsStore)
	}
	// Step Q.2 — auth-failure reader. Backed by the audit
	// bucket (single source of truth, spec D2.B + D4.B), so
	// it is INDEPENDENT of obsStore: when the metrics DB is
	// sabotaged the auth-failures endpoint still works (the
	// audit bucket lives in the main BoltDB, not metrics.db).
	// The AC #14 degraded shape only fires if audit itself is
	// unreachable; in normal builds auditStore is always
	// non-nil since audit.NewStore panics on a nil DB
	// upstream and boot has already aborted in that case.
	apiHandler.SetAuthFailureReader(auditStore)

	// Critique 11 Pack A (2026-06-05) — share the Stage B HC
	// tracker with the Routes API so listRoutes / getRoute
	// attach the per-route aggregateStatus rollup. Tracker was
	// constructed + primed before mgr.Start, so it's already
	// receiving events by the time this setter fires.
	apiHandler.SetHCStatusReader(hcTracker)

	// Step T T.1 (2026-06-05) — share the cert-info tracker with
	// the API so GET /api/certificates serves real data. Tracker
	// was constructed + reconciled-from-disk + singleton-installed
	// before mgr.Start (above), so it is already populated with
	// every on-disk cert AND already receiving events from
	// certmagic via the arenet_cert_info handler module by the
	// time this setter fires.
	apiHandler.SetCertInfoReader(certTracker)
	// Post-T.5 hotfix (2026-06-05) — log the wire-up state so
	// any future regression (CertInfoReader interface narrowing,
	// missed setter call after a refactor, deploy of a stale
	// binary) is immediately visible in journalctl instead of
	// silently no-opping the DELETE managed-domain purge path.
	// The 17:54 smoke that revealed the gap had no boot-time
	// signal to look at; this line is the audit trail for the
	// next investigation.
	logger.Info("api handler wired with cert tracker",
		"purger_present", apiHandler.HasCertInfoPurger(),
	)
	// Step U.3 — log the cert-event reader wire-up state.
	// Mirrors the HF4 purger_present pattern (backlog
	// #R-API-boot-log-audit). A future regression where the
	// SetCertEventReader call goes missing surfaces here as
	// reader_present=false instead of silent /observability/
	// cert-events endpoint degradation.
	logger.Info("api handler wired with cert event reader",
		"reader_present", apiHandler.HasCertEventReader(),
	)
	// Step V.2 — wire the auth_event sink fan-out into the
	// appendAudit helper. Per spec §3.6 the audit log keeps
	// the canonical record; this Sink is the real-time stream
	// the V.3 geo bus reads. HF4 boot-log pattern (commit
	// 30418ea) — any future regression where SetAuthEventSink
	// goes missing surfaces here as sink_present=false instead
	// of silent geo-stream degradation.
	// Step V.3 — wrap the auth event sink with the geo-
	// forwarding adapter so every auth failure also lands on
	// the geo bus alongside the V.2 audit-helpers fan-out.
	// Same nil-safety guarantees as the WAF/throttle/crowdsec
	// wrappers above.
	apiHandler.SetAuthEventSink(geoForwardingAuthSink{bus: geoBus, enricher: geoEnricher, inner: authEventSink})
	logger.Info("api handler wired with auth event sink",
		"sink_present", apiHandler.HasAuthEventSink(),
	)
	// Step V.3 — wire the geo bus into the api handler so the
	// GET /observability/geo-events replay endpoint reads from
	// it. The WS handler builds on the same bus via the
	// NewWSGeoEventsHandler constructor below. HF4 boot-log
	// pattern (commit 30418ea) surfaces any future regression
	// as bus_present=false in journalctl.
	apiHandler.SetGeoBus(geoBus)
	apiHandler.SetGeoIPDegraded(!geoEnricher.HasLookup())
	logger.Info("api handler wired with geo bus",
		"bus_present", apiHandler.HasGeoBus(),
		"geoip_degraded", !geoEnricher.HasLookup(),
	)

	// Step V.4 — server position wire-up.
	//
	// Store: *storage.Store satisfies api.ServerPositionStore
	// via the V.4 GetServerPosition / PutServerPosition methods.
	// Boot-detected position: shipped from the V.4 boot
	// resolution block above (may be nil in degraded mode).
	// Redetector: a closure around geo.DetectFromPublicIP
	// capturing geoLookup at boot, so the POST :redetect
	// endpoint can re-run the V.1 path without taking a
	// hard dependency on internal/geo at the api package
	// boundary.
	apiHandler.SetServerPositionStore(store)
	apiHandler.SetBootDetectedPosition(bootPosition)
	apiHandler.SetServerPositionRedetector(serverPositionRedetector{lookup: geoLookup})
	logger.Info("api handler wired with server position store",
		"store_present", apiHandler.HasServerPositionStore(),
		"redetector_present", apiHandler.HasServerPositionRedetector(),
		"boot_position_mode", bootPositionMode,
	)

	// Step P.3 — auto-classify trigger engine wiring.
	// Read rules + credentials from BoltDB, build the
	// engine + manager, start the goroutines, register
	// the global Manager so the REST API handlers can
	// reconfigure at runtime. AC #15 degraded-mode: any
	// failure here logs WARN and disables the engine —
	// the data plane is unaffected.
	automationEngineCtx, automationEngineCancel := context.WithCancel(ctx)
	var automationWG sync.WaitGroup
	if err := wireAutomation(automationEngineCtx, &automationWG, store, obsStore, auditStore, crowdsecSink, logger); err != nil {
		logger.Warn("automation: trigger engine disabled", "err", err)
	}
	defer func() {
		automationEngineCancel()
		automationWG.Wait()
		automation.SetManager(nil)
		// Detach the tombstone listener so the
		// crowdsec.Sink doesn't fire into a stopped
		// engine on shutdown.
		if crowdsecSink != nil {
			crowdsecSink.SetTombstoneListener(nil)
		}
		logger.Info("automation engine stopped")
	}()

	wsTopologyHandler := api.NewWSTopologyHandler(metricsBroadcaster, cfg.Dev, logger)

	// Phase 2 #R-TOPO-v2 — topology endpoints with Stage B health
	// signal (post-#R-TOPO-real-health-probe, 2026-06-04).
	//
	// Sliding window + per-upstream health tracker are SHARED
	// between the snapshot endpoint and the stream endpoint. The
	// tracker (hcTracker) was constructed + installed + bootstrap-
	// primed earlier, before mgr.Start, so by the time we reach
	// here Caddy is already firing events into it and the bootstrap
	// prime has set the optimistic-healthy default for every
	// upstream of an HC-configured route. See the priming block
	// next to the mgr.Start call.
	//
	// The stream handler subscribes to the metrics broadcaster
	// each connection; the window is fed by per-subscriber pushes
	// (acknowledged Stage A wastefulness when multiple subscribers
	// exist, but cheap at homelab cardinality).
	topologyWindow := topology.NewSlidingWindow()
	topologySnapshotHandler := newTopologySnapshotHandler(
		store, topologyWindow, hcTracker, logger,
	)
	topologyStreamHandler := api.NewStreamHandler(
		metricsBroadcaster, store, topologyWindow, hcTracker,
		cfg.TopologyTickMs, cfg.Dev, logger,
	)

	// Step V.3 — geo events WebSocket handler. Mounted at
	// /api/v1/ws/geo-events by the router below. Hard-auth
	// middleware gates the upgrade per spec §5.5.
	wsGeoEventsHandler := api.NewWSGeoEventsHandler(geoBus, cfg.Dev, logger)

	router := api.NewRouter(
		apiHandler, cfg.Dev, ipExtractor,
		wsTopologyHandler, topologySnapshotHandler, topologyStreamHandler,
		wsGeoEventsHandler,
	)

	if cfg.Dev {
		router.Get("/", devLandingHandler(cfg.AdminPort))
	} else {
		staticFS, ferr := web.StaticFS()
		if ferr != nil {
			return fmt.Errorf("embed: %w", ferr)
		}
		router.Handle("/*", spaHandler(staticFS))
	}

	adminSrv := &http.Server{
		Addr:              cfg.AdminPort,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		// BaseContext propagates the process-level ctx (cancelled by
		// SIGINT / SIGTERM) into each request's context. Hijacked
		// connections — like the Step E WebSocket at
		// /api/v1/ws/topology — observe ctx.Done() and emit a clean
		// CloseGoingAway (code 1001) frame on shutdown. Without
		// BaseContext, http.Server.Shutdown does NOT cancel hijacked
		// requests, so the WS would only see an abrupt TCP close
		// (1006) at the grace deadline — violating spec §5.4.
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}
	serverErr := make(chan error, 1)
	go func() {
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	httpsActive, err := mgr.HasHTTPSServer(ctx)
	if err != nil {
		return err
	}
	// Pull the effective listen addresses from the manager so the
	// log line matches Caddy's actual bind even when the operator
	// overrides via ARENET_HTTP_PORT / ARENET_HTTPS_PORT (Step L
	// backlog #L.5-1). The existing "Caddy started" log line above
	// is sourced from the same accessor.
	listenAttrs := []any{"http", mgr.HTTPListen(), "admin_api", cfg.AdminPort}
	if httpsActive {
		listenAttrs = append(listenAttrs, "https", mgr.HTTPSListen())
	}
	logger.Info("Arenet listening", listenAttrs...)

	select {
	case <-ctx.Done():
	case err := <-serverErr:
		return fmt.Errorf("admin server: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := adminSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("admin server shutdown error", "err", err)
	}
	if err, ok := <-serverErr; ok && err != nil {
		logger.Error("admin server post-shutdown error", "err", err)
	}
	logger.Info("Arenet shutting down")
	return nil
}

// storeHasTLSRoute returns true if any persisted route has
// TLSEnabled=true. Used at boot (Step I.1) to decide whether to
// WARN about an empty ARENET_ACME_EMAIL.
func storeHasTLSRoute(ctx context.Context, store *storage.Store) (bool, error) {
	routes, err := store.ListRoutes(ctx)
	if err != nil {
		return false, err
	}
	for _, r := range routes {
		if r.TLSEnabled {
			return true, nil
		}
	}
	return false, nil
}

// storeDNS01Inconsistency reports whether the persisted state
// contains a route configured for DNS-01 ACME while the
// instance-level OVH DNS provider config is missing or
// incomplete. The triplet (anyDNS01, providerOK, err) is consumed
// by the boot WARN in run().
//
// Step J.4 §5.4 (β) decision: edit-time validation prevents new
// DNS-01 routes from being created without a configured provider,
// but it cannot prevent a provider that was deleted /
// half-configured AFTER routes were saved. The boot WARN is the
// safety net for that gap.
func storeDNS01Inconsistency(ctx context.Context, store *storage.Store) (bool, bool, error) {
	routes, err := store.ListRoutes(ctx)
	if err != nil {
		return false, false, err
	}
	anyDNS01 := false
	for _, r := range routes {
		if r.ACMEChallenge == storage.ACMEChallengeDNS01 {
			anyDNS01 = true
			break
		}
	}
	if !anyDNS01 {
		return false, true, nil
	}
	cfg, err := store.GetDNSProviderOVH(ctx)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return anyDNS01, false, err
	}
	providerOK := cfg.Endpoint != "" &&
		cfg.ApplicationKey != "" &&
		cfg.ApplicationSecret != "" &&
		cfg.ConsumerKey != ""
	return anyDNS01, providerOK, nil
}

// devLandingHandler returns a tiny HTML page guiding the developer to the
// Vite dev server. Only mounted at GET / when --dev is true.
func devLandingHandler(adminPort string) http.HandlerFunc {
	const tmpl = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>Arenet (dev)</title>
<style>body{font-family:system-ui;padding:2rem;max-width:40rem;margin:auto;background:#0a0e14;color:#e6edf3}
a{color:#00d9ff}code{background:#1a212b;padding:0.1rem 0.3rem;border-radius:0.2rem}</style>
</head><body>
<h1>Arenet — dev mode</h1>
<p>The admin API is running on <code>%s</code>.</p>
<p>The frontend is served separately by Vite. Open <a href="http://localhost:5173">http://localhost:5173</a>.</p>
</body></html>`
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, tmpl, adminPort)
	}
}

// spaHandler serves the embedded SvelteKit build. Requests for client-side
// routes (paths without a file extension) that don't resolve to a real file
// fall back to "200.html" — the SPA shell generated by adapter-static —
// so deep links and refreshes on routes like /routes or /topology work.
//
// Requests that look like assets (anything containing a "." in the last path
// segment, e.g. /_app/foo.js) bypass the fallback and produce an honest 404
// when missing, so build artifact problems surface instead of silently
// returning HTML.
func spaHandler(staticFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(staticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "200.html"
		}
		if _, err := fs.Stat(staticFS, path); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Path doesn't resolve to a file. If it looks like an asset (has an
		// extension in the last segment), let the FileServer return 404.
		last := path
		if i := strings.LastIndex(path, "/"); i >= 0 {
			last = path[i+1:]
		}
		if strings.Contains(last, ".") {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Otherwise treat it as a SPA route and serve the shell.
		shell, sErr := fs.ReadFile(staticFS, "200.html")
		if sErr != nil {
			http.Error(w, "SPA shell missing from embed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(shell)
	})
}

// storeLister adapts *storage.Store to the metrics.RouteLister
// interface. Defined inline rather than in internal/storage so the
// metrics package stays decoupled from the storage package — only
// main() wires the two together (spec §4.3).
type storeLister struct {
	store *storage.Store
}

// ListRoutesForMetrics returns the canonical route list (one entry
// per persisted route) in the order produced by storage.ListRoutes.
// The metrics ticker calls this once per tick to join counter deltas
// with route metadata for the wire-shape Snapshot.
func (l *storeLister) ListRoutesForMetrics(ctx context.Context) ([]metrics.RouteMetadata, error) {
	routes, err := l.store.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]metrics.RouteMetadata, len(routes))
	for i, r := range routes {
		// Step J.1: metrics.RouteMetadata still carries a single
		// Upstream string (Topology page is mono-upstream until J.6).
		// Expose Upstreams[0].URL — storage.validate() guarantees the
		// pool has at least one element. A multi-upstream route shows
		// only the first backend in the Topology graph until J.3 / J.6
		// rework the visualisation. Acceptable transitional behaviour
		// for J.1.
		var upstream string
		if len(r.Upstreams) > 0 {
			upstream = r.Upstreams[0].URL
		}
		out[i] = metrics.RouteMetadata{
			ID:       r.ID,
			Host:     r.Host,
			Upstream: upstream,
		}
	}
	return out, nil
}

// wafInserterAdapter satisfies waf.Inserter by translating
// waf.Event into observability.WafEvent and delegating to the
// store. Defined here (consumer side) so internal/waf and
// internal/observability stay decoupled — neither knows about
// the other's exact type, main.go bridges them. Tolerates a
// nil store: the sink's flush path then drops the batch
// silently in degraded mode (AC #13).
type wafInserterAdapter struct {
	store *observability.Store
}

// InsertWafEventBatch implements waf.Inserter.
func (a wafInserterAdapter) InsertWafEventBatch(ctx context.Context, events []waf.Event) error {
	if a.store == nil {
		// Degraded mode (boot-failed observability).
		// Returning nil rather than an error so the sink
		// records this as a successful flush (the events
		// are intentionally discarded); a real error would
		// inflate FlushErrBatches and confuse ops dashboards
		// in a way that mis-attributes the boot failure.
		return nil
	}
	rows := make([]observability.WafEvent, len(events))
	for i, e := range events {
		rows[i] = observability.WafEvent{
			Ts:            e.Ts,
			RouteID:       e.RouteID,
			RuleID:        e.RuleID,
			Category:      string(e.Category),
			Severity:      e.Severity,
			SrcIP:         e.SrcIP,
			RequestMethod: e.RequestMethod,
			RequestPath:   e.RequestPath,
			PayloadSample: e.PayloadSample,
		}
	}
	return a.store.InsertWafEventBatch(ctx, rows)
}

// throttleInserterAdapter satisfies throttle.Inserter by
// translating throttle.Event into observability.ThrottleEvent
// and delegating to the store. Same shape as
// wafInserterAdapter — keeps internal/throttle and
// internal/observability decoupled. Tolerates a nil store
// (AC #13 degraded mode) by returning nil so the sink does
// not record the boot failure as a runtime flush error.
type throttleInserterAdapter struct {
	store *observability.Store
}

// InsertThrottleEventBatch implements throttle.Inserter.
func (a throttleInserterAdapter) InsertThrottleEventBatch(ctx context.Context, events []throttle.Event) error {
	if a.store == nil {
		return nil
	}
	rows := make([]observability.ThrottleEvent, len(events))
	for i, e := range events {
		rows[i] = observability.ThrottleEvent{
			Ts:                   e.Ts,
			Tier:                 e.Tier,
			SrcIP:                e.SrcIP,
			AttemptedUsername:    e.AttemptedUsername,
			BlockedUntil:         e.BlockedUntil,
			BlockDurationSeconds: e.BlockDurationSeconds,
		}
	}
	return a.store.InsertThrottleEventBatch(ctx, rows)
}

// crowdsecInserterAdapter satisfies crowdsec.Inserter by
// translating crowdsec.Decision → observability.DecisionEvent
// and delegating to the store. Same shape as wafInserterAdapter
// and throttleInserterAdapter — keeps internal/crowdsec and
// internal/observability decoupled. Tolerates a nil store
// (AC #13 degraded mode).
type crowdsecInserterAdapter struct {
	store *observability.Store
}

// InsertDecisionEventBatch implements crowdsec.Inserter.
func (a crowdsecInserterAdapter) InsertDecisionEventBatch(ctx context.Context, events []crowdsec.Decision) error {
	if a.store == nil {
		return nil
	}
	rows := make([]observability.DecisionEvent, len(events))
	for i, e := range events {
		rows[i] = observability.DecisionEvent{
			UUID:            e.UUID,
			Ts:              e.Ts,
			Scope:           e.Scope,
			Value:           e.Value,
			Type:            e.Type,
			Scenario:        e.Scenario,
			ExpiresAt:       e.ExpiresAt,
			DurationSeconds: e.DurationSeconds,
		}
	}
	return a.store.InsertDecisionEventBatch(ctx, rows)
}

// MarkDecisionExpired implements crowdsec.Inserter for the
// tombstone path: LAPI signals revoke → soft-delete on the
// stored row (expires_at = now). nil-tolerant per AC #13.
func (a crowdsecInserterAdapter) MarkDecisionExpired(ctx context.Context, uuid string) error {
	if a.store == nil {
		return nil
	}
	return a.store.MarkDecisionExpired(ctx, uuid)
}

// certEventInserterAdapter satisfies observability.CertInserter
// by delegating to *observability.Store. Degenerate vs the
// WAF / throttle / crowdsec adapters because the cert sink
// already uses observability.CertEvent directly (the sink
// lives in the same package as the storage shape — no
// translation needed). The adapter exists only for the
// nil-store guard (AC #13 degraded mode: nil store → return
// nil rather than nil-pointer-panic).
type certEventInserterAdapter struct {
	store *observability.Store
}

// InsertCertEventBatch implements observability.CertInserter.
func (a certEventInserterAdapter) InsertCertEventBatch(ctx context.Context, events []observability.CertEvent) error {
	if a.store == nil {
		// Degraded mode (boot-failed observability). Returning
		// nil rather than an error so the sink records this as
		// a successful flush; a real error would inflate
		// FlushErrBatches and mis-attribute the boot failure.
		return nil
	}
	return a.store.InsertCertEventBatch(ctx, events)
}

func main() {
	cfg, err := appconfig.Load(os.Args[1:])
	if err != nil {
		// --help / -h prints the usage to stderr inside Load
		// and returns flag.ErrHelp; exit 0 in that case so the
		// shell doesn't treat a help request as failure.
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "arenet: config load failed:", err)
		os.Exit(2)
	}
	logger := newLogger(cfg.Dev)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Step S.1 — Docker healthcheck short-circuit. Runs BEFORE
	// the K.3 export/restore branches because it's the smallest
	// + most-frequent code path (every healthcheck.interval the
	// compose stack runs this) and has zero side-effects beyond
	// the outbound HTTP probe. Distroless containers use this
	// because they have no curl/wget.
	if cfg.HealthcheckURL != "" {
		if err := runHealthcheckCLI(ctx, cfg.HealthcheckURL); err != nil {
			// Stderr only; healthcheck output is captured by the
			// container runtime, not the user. Plain text, no JSON.
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		return
	}

	// Step K.3 — CLI export / restore short-circuits. The binary
	// becomes a one-shot tool: open BoltDB, do the operation,
	// exit. Caddy never starts; the admin API never listens.
	// Mutual exclusion: --export AND --restore together is a
	// usage error.
	if cfg.ExportPath != "" && cfg.RestorePath != "" {
		logger.Error("--export and --restore cannot be combined")
		os.Exit(2)
	}
	if cfg.ExportPath != "" {
		if err := runExportCLI(ctx, logger, cfg); err != nil {
			logger.Error("export failed", "err", err)
			os.Exit(1)
		}
		return
	}
	if cfg.RestorePath != "" {
		if err := runRestoreCLI(ctx, logger, cfg); err != nil {
			logger.Error("restore failed", "err", err)
			os.Exit(1)
		}
		return
	}

	logger.Info("Arenet v" + version + " starting...")

	if err := run(ctx, logger, cfg); err != nil {
		logger.Error("fatal error", "err", err)
		os.Exit(1)
	}
}
