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
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	v1 "github.com/WissCore/moldchat/server/internal/api/v1"
	"github.com/WissCore/moldchat/server/internal/auth"
	"github.com/WissCore/moldchat/server/internal/health"
	"github.com/WissCore/moldchat/server/internal/storage"
	"github.com/WissCore/moldchat/server/internal/storage/cleanup"
	"github.com/WissCore/moldchat/server/internal/storage/memory"
	"github.com/WissCore/moldchat/server/internal/storage/sqlite"
)

const (
	defaultAddr            = ":8080"
	readHeaderTimeout      = 10 * time.Second
	readTimeout            = 30 * time.Second
	writeTimeout           = 60 * time.Second
	idleTimeout            = 120 * time.Second
	maxHeaderBytes         = 16 * 1024
	shutdownTimeout        = 5 * time.Second
	cleanupShutdownTimeout = 10 * time.Second
	defaultCleanupInterval = 5 * time.Minute
)

func main() {
	os.Exit(run())
}

func run() int {
	// Tighten the file-creation mask so any database files SQLCipher
	// later opens land at 0600. The encrypted-at-rest property covers
	// content; this covers metadata access (ctime, mtime, size) plus the
	// raw ciphertext as a defence-in-depth measure against local readers.
	syscall.Umask(0o077)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevelFromEnv()}))
	slog.SetDefault(logger)

	// Register signal handlers FIRST so a TERM that arrives during the
	// brief startup window between "go func" and "signal.Notify" is not
	// dropped to the OS default handler (which would kill us without
	// graceful shutdown — visible during k8s scale-down storms).
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	store, closeStore, runCleanup, err := initStorage(logger)
	if err != nil {
		logger.Error("init storage", "err", err.Error())
		return 1
	}

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler())

	api := &v1.Server{Storage: store, Auth: auth.NewIssuer(), Logger: logger}
	api.Mount(mux)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	// Bind explicitly so the actual listening address (which may differ
	// from the configured one when MOLDD_ADDR=":0" is used in tests) is
	// available for the Debug log below.
	listener, err := net.Listen("tcp", addr())
	if err != nil {
		logger.Error("listen", "err", err.Error())
		return 1
	}

	rootCtx, rootCancel := context.WithCancel(context.Background())

	// Ordered shutdown: cancel cleanup ctx → wait for cleanup goroutine to
	// finish any in-flight Tick → only then close the store. Closing the
	// store while a Tick is mid-query produces undefined behaviour in the
	// SQL driver, so the WaitGroup gate is mandatory, not cosmetic. The
	// wait is itself bounded so a wedged SQL operation cannot hold the
	// process up forever; if the bound is exceeded we close the store
	// anyway and let the runtime tear the goroutine down.
	var cleanupWg sync.WaitGroup
	defer func() {
		shutdownCleanly(rootCancel, &cleanupWg, closeStore, cleanupShutdownTimeout, logger)
	}()

	if runCleanup != nil {
		cleanupWg.Add(1)
		go func() {
			defer cleanupWg.Done()
			runCleanup(rootCtx)
		}()
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("moldd starting")
		logger.Debug("http listener", "addr", listener.Addr().String())
		if serveErr := srv.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErr <- serveErr
		}
	}()

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

// shutdownCleanly cancels the cleanup-runner context, waits for it to
// drain (bounded by waitTimeout), and only then closes the store.
// Extracted into a function so the timeout path is unit-testable
// without spinning up the whole process. logger is optional for tests.
func shutdownCleanly(rootCancel context.CancelFunc, cleanupWg *sync.WaitGroup, closeStore func() error, waitTimeout time.Duration, logger *slog.Logger) {
	rootCancel()
	done := make(chan struct{})
	go func() {
		cleanupWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(waitTimeout):
		if logger != nil {
			logger.Warn("cleanup goroutine did not finish before timeout, forcing store close")
		}
	}
	if err := closeStore(); err != nil && logger != nil {
		logger.Warn("close store failed", "err", err.Error())
	}
}

// logLevelFromEnv reads MOLDD_LOG_LEVEL and returns the matching slog
// level. Unknown or unset values default to info. This is the only knob
// that exposes the listening address (Debug level), keeping operational
// topology out of production logs by default.
func logLevelFromEnv() slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("MOLDD_LOG_LEVEL"))) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
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
