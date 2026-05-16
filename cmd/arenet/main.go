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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/barto95100/arenet/internal/api"
	"github.com/barto95100/arenet/internal/caddymgr"
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
		Host:        "test.local",
		UpstreamURL: "http://127.0.0.1:9999",
	})
	if err != nil {
		return err
	}
	logger.Info("inserted test route", "id", created.ID, "host", created.Host, "upstream", created.UpstreamURL)
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

	mgr, err := caddymgr.New(store, logger)
	if err != nil {
		return err
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

	apiHandler := api.NewHandler(store, mgr, logger)
	router := api.NewRouter(apiHandler, cfg.dev)

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
