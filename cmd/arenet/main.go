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

	"github.com/barto95100/arenet/internal/api"
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/web"
)

const version = "DEV"

type config struct {
	adminPort       string
	dataDir         string
	dev             bool
	insertTestRoute bool
	// Step K.3 — backup / restore flags. When exportPath OR
	// restorePath is set, run() short-circuits before Caddy
	// boots: the binary becomes a one-shot CLI tool.
	exportPath             string
	restorePath            string
	includeSecrets         bool
	allowIncompleteRestore bool
	allowEmptyUsers        bool
	// Step K.2 dev — when the SPA is served by a separate dev
	// server (Vite on :5173 typically) the OIDC callback's
	// in-handler 302 redirects (/routes on success,
	// /login?error=... on failure) cannot be relative — the
	// browser would land on :8001/routes which is API-only and
	// 404s. Setting --ui-origin=http://localhost:5173 makes the
	// callback emit absolute redirects to the frontend origin.
	// Empty (prod default) keeps the relative redirects, which
	// is correct when the static SPA is served by Arenet from
	// the same origin as the API.
	uiOrigin string
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.adminPort, "admin-port", ":8001", "address:port for the admin API (e.g. :8001)")
	flag.StringVar(&cfg.dataDir, "data-dir", "./data", "directory where Arenet stores its data")
	flag.BoolVar(&cfg.dev, "dev", false, "enable development mode (verbose logging, no TLS auto-issuance)")
	flag.BoolVar(&cfg.insertTestRoute, "insert-test-route", false,
		"insert a test route (test.local -> http://127.0.0.1:9999) before starting Caddy")
	flag.StringVar(&cfg.exportPath, "export", "",
		"Step K.3: export the configuration to PATH and exit (default redacts secrets)")
	flag.StringVar(&cfg.restorePath, "restore", "",
		"Step K.3: restore the configuration from PATH and exit (before Caddy starts)")
	flag.BoolVar(&cfg.includeSecrets, "include-secrets", false,
		"Step K.3: include plaintext secrets in --export output (warning printed to stderr)")
	flag.BoolVar(&cfg.allowIncompleteRestore, "allow-incomplete-restore", false,
		"Step K.3: accept --restore inputs whose sentinels cannot be inherited; affected secret fields are cleared")
	flag.BoolVar(&cfg.allowEmptyUsers, "allow-empty-users", false,
		"Step K.3: accept --restore inputs with zero users (next boot re-triggers the setup-token flow)")
	flag.StringVar(&cfg.uiOrigin, "ui-origin", "",
		"Step K.2 dev: absolute origin of the SPA dev server (e.g. http://localhost:5173); empty in prod (static SPA served by Arenet)")
	flag.Parse()
	return cfg
}

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

func run(ctx context.Context, logger *slog.Logger, cfg config) (retErr error) {
	logger.Info("Arenet starting",
		"version", version,
		"admin_port", cfg.adminPort,
		"data_dir", cfg.dataDir,
		"dev", cfg.dev,
	)

	if err := os.MkdirAll(cfg.dataDir, 0o755); err != nil {
		return err
	}
	dbPath := filepath.Join(cfg.dataDir, "arenet.db")

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

	if cfg.insertTestRoute {
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
	mgr, err := caddymgr.New(store, logger, metricsRegistry, cfg.dev, acmeEmail)
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
	obsPath := filepath.Join(cfg.dataDir, "metrics.db")
	obsStore, obsErr := observability.Open(ctx, obsPath)
	if obsErr != nil {
		logger.Error("observability: metrics DB unavailable — continuing without metrics history (AC #13)",
			"path", obsPath, "err", obsErr,
		)
		obsStore = nil
	} else {
		logger.Info("observability storage opened", "path", obsPath)
	}
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
		cfg.dev, logger,
	)
	if cfg.uiOrigin != "" {
		apiHandler.SetUIOrigin(cfg.uiOrigin)
		logger.Info("OIDC callback redirects will target SPA origin", "ui_origin", cfg.uiOrigin)
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
	}
	wsTopologyHandler := api.NewWSTopologyHandler(metricsBroadcaster, cfg.dev, logger)
	router := api.NewRouter(apiHandler, cfg.dev, ipExtractor, wsTopologyHandler)

	if cfg.dev {
		router.Get("/", devLandingHandler(cfg.adminPort))
	} else {
		staticFS, ferr := web.StaticFS()
		if ferr != nil {
			return fmt.Errorf("embed: %w", ferr)
		}
		router.Handle("/*", spaHandler(staticFS))
	}

	adminSrv := &http.Server{
		Addr:              cfg.adminPort,
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
	listenAttrs := []any{"http", ":8080", "admin_api", cfg.adminPort}
	if httpsActive {
		listenAttrs = append(listenAttrs, "https", ":8443")
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

func main() {
	cfg := parseFlags()
	logger := newLogger(cfg.dev)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Step K.3 — CLI export / restore short-circuits. The binary
	// becomes a one-shot tool: open BoltDB, do the operation,
	// exit. Caddy never starts; the admin API never listens.
	// Mutual exclusion: --export AND --restore together is a
	// usage error.
	if cfg.exportPath != "" && cfg.restorePath != "" {
		logger.Error("--export and --restore cannot be combined")
		os.Exit(2)
	}
	if cfg.exportPath != "" {
		if err := runExportCLI(ctx, logger, cfg); err != nil {
			logger.Error("export failed", "err", err)
			os.Exit(1)
		}
		return
	}
	if cfg.restorePath != "" {
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
