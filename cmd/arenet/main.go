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

	"github.com/barto95100/arenet/internal/api"
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/web"
)

const version = "DEV"

type config struct {
	adminPort       string
	dataDir         string
	dev             bool
	insertTestRoute bool
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.adminPort, "admin-port", ":8001", "address:port for the admin API (e.g. :8001)")
	flag.StringVar(&cfg.dataDir, "data-dir", "./data", "directory where Arenet stores its data")
	flag.BoolVar(&cfg.dev, "dev", false, "enable development mode (verbose logging, no TLS auto-issuance)")
	flag.BoolVar(&cfg.insertTestRoute, "insert-test-route", false,
		"insert a test route (test.local -> http://127.0.0.1:9999) before starting Caddy")
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

	// Start the metrics ticker AFTER caddymgr.Start so the first
	// tick sees the registry already populated by the post-Start
	// syncRegistry. Run on a child context so a Ctrl-C / shutdown
	// cancels Run promptly; we wait for the goroutine to exit
	// before returning from run().
	metricsTicker := metrics.NewTicker(metricsRegistry, metricsBroadcaster, &storeLister{store: store})
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

	logger.Info("Arenet v" + version + " starting...")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger, cfg); err != nil {
		logger.Error("fatal error", "err", err)
		os.Exit(1)
	}
}
