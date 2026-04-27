// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command moldd is the MoldChat relay server.
//
// The current build exposes a queue HTTP API. Storage backend is selected via
// the MOLDD_STORAGE environment variable: "memory" (the default, ephemeral)
// or "sqlite" (persistent, encrypted with SQLCipher and an HKDF-derived key
// per queue, requires MOLDD_MASTER_SEED and MOLDD_DATA_DIR).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	v1 "github.com/WissCore/moldchat/server/internal/api/v1"
	"github.com/WissCore/moldchat/server/internal/health"
	"github.com/WissCore/moldchat/server/internal/storage"
	"github.com/WissCore/moldchat/server/internal/storage/cleanup"
	"github.com/WissCore/moldchat/server/internal/storage/memory"
	"github.com/WissCore/moldchat/server/internal/storage/sqlite"
)

const (
	defaultAddr            = ":8080"
	readHeaderTimeout      = 10 * time.Second
	shutdownTimeout        = 5 * time.Second
	defaultCleanupInterval = 5 * time.Minute
)

func main() {
	os.Exit(run())
}

func run() int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	store, closeStore, runCleanup, err := initStorage(logger)
	if err != nil {
		logger.Error("init storage", "err", err.Error())
		return 1
	}
	defer func() { _ = closeStore() }()

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler())

	api := &v1.Server{Storage: store, Logger: logger}
	api.Mount(mux)

	srv := &http.Server{
		Addr:              addr(),
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()
	if runCleanup != nil {
		go runCleanup(rootCtx)
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("moldd starting", "addr", srv.Addr)
		if listenErr := srv.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			serverErr <- listenErr
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case listenErr := <-serverErr:
		logger.Error("server failed", "err", listenErr.Error())
		return 1
	case sig := <-stop:
		logger.Info("shutdown requested", "signal", sig.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if shutdownErr := srv.Shutdown(ctx); shutdownErr != nil {
		logger.Error("graceful shutdown failed", "err", shutdownErr.Error())
		return 1
	}
	logger.Info("moldd stopped")
	return 0
}

func addr() string {
	if v := os.Getenv("MOLDD_ADDR"); v != "" {
		return v
	}
	return defaultAddr
}

// initStorage constructs the configured storage backend and (when persistent)
// the cleanup-runner that evicts expired queues. The closeStore callback
// releases backend resources; runCleanup is nil for the in-memory backend.
func initStorage(logger *slog.Logger) (
	store storage.Storage,
	closeStore func() error,
	runCleanup func(context.Context),
	err error,
) {
	switch backend := os.Getenv("MOLDD_STORAGE"); backend {
	case "", "memory":
		mem := memory.New()
		return mem, func() error { return nil }, nil, nil

	case "sqlite":
		seed, seedErr := sqlite.LoadMasterSeed()
		if seedErr != nil {
			return nil, nil, nil, fmt.Errorf("sqlite backend: %w", seedErr)
		}
		dataDir := os.Getenv("MOLDD_DATA_DIR")
		if dataDir == "" {
			return nil, nil, nil, errors.New("sqlite backend: MOLDD_DATA_DIR is required")
		}
		st, openErr := sqlite.New(seed, dataDir)
		if openErr != nil {
			return nil, nil, nil, fmt.Errorf("sqlite backend: %w", openErr)
		}
		runner := &cleanup.Runner{
			Cleaner:  st,
			Interval: defaultCleanupInterval,
			Logger:   logger,
		}
		return st, st.Close, runner.Run, nil

	default:
		return nil, nil, nil, fmt.Errorf("unknown MOLDD_STORAGE backend: %q (valid: memory, sqlite)", backend)
	}
}
