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
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/storage"
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

	httpsActive, err := mgr.HasHTTPSServer(ctx)
	if err != nil {
		return err
	}
	listenAttrs := []any{"http", ":8080", "admin_api", cfg.adminPort}
	if httpsActive {
		listenAttrs = append(listenAttrs, "https", ":8443")
	}
	logger.Info("Arenet listening", listenAttrs...)

	<-ctx.Done()
	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		logger.Info("Arenet shutting down", "reason", err)
	} else {
		logger.Info("Arenet shutting down")
	}
	return nil
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
