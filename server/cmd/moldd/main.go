// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command moldd is the MoldChat relay server.
//
// The current build exposes a queue HTTP API backed by in-memory storage and
// authorises owners by constant-time comparison against the public key
// supplied at queue creation. Sealed-sender routing, persistence, anti-spam,
// and key transparency are not implemented yet.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	v1 "github.com/WissCore/moldchat/server/internal/api/v1"
	"github.com/WissCore/moldchat/server/internal/health"
	"github.com/WissCore/moldchat/server/internal/storage/memory"
)

const (
	defaultAddr       = ":8080"
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 5 * time.Second
)

func main() {
	os.Exit(run())
}

func run() int {
	addr := defaultAddr
	if v := os.Getenv("MOLDD_ADDR"); v != "" {
		addr = v
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler())

	api := &v1.Server{
		Storage: memory.New(),
		Logger:  logger,
	}
	api.Mount(mux)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("moldd starting", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		logger.Error("server failed", "err", err)
		return 1
	case sig := <-stop:
		logger.Info("shutdown requested", "signal", sig.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		return 1
	}
	logger.Info("moldd stopped")
	return 0
}
