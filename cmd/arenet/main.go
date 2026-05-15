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
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

const version = "DEV"

type config struct {
	adminPort string
	dataDir   string
	dev       bool
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.adminPort, "admin-port", ":8001", "address:port for the admin API (e.g. :8001)")
	flag.StringVar(&cfg.dataDir, "data-dir", "./data", "directory where Arenet stores its data")
	flag.BoolVar(&cfg.dev, "dev", false, "enable development mode (verbose logging, no TLS auto-issuance)")
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

func run(ctx context.Context, logger *slog.Logger, cfg config) error {
	logger.Info("Arenet starting",
		"version", version,
		"admin_port", cfg.adminPort,
		"data_dir", cfg.dataDir,
		"dev", cfg.dev,
	)

	<-ctx.Done()
	logger.Info("Arenet shutting down", "reason", ctx.Err())
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
