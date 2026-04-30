// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command moldd is the MoldChat relay server.
//
// The current build exposes a queue HTTP API. Storage backend is selected via
// the MOLDD_STORAGE environment variable: "memory" (the default, ephemeral)
// or "sqlite" (persistent, encrypted with SQLCipher and an HKDF-derived key
// per queue, requires MOLDD_MASTER_SEED and MOLDD_DATA_DIR).
//
// Online backup is opt-in via MOLDD_SNAPSHOT_INTERVAL (a Go duration, e.g.
// "60s") and MOLDD_SNAPSHOT_DIR (an absolute path). Both must be set and the
// storage backend must be sqlite; an offline tool such as restic is expected
// to ship the resulting directory to remote storage.
//
// Anonymous-credential gating on PUT /v1/queues/{id}/messages is opt-in via
// MOLDD_ANONAUTH=enforce together with MOLDD_ANONAUTH_DATA_DIR. When enabled
// the issuer derives its POPRF key from MOLDD_MASTER_SEED and persists
// pseudonyms in an encrypted SQLite file under the data dir. Tunable knobs:
// MOLDD_ANONAUTH_EPOCH (Go duration, default 1h), MOLDD_ANONAUTH_PSEUDONYM_TTL
// (Go duration, default 720h), MOLDD_ANONAUTH_TOKENS_PER_EPOCH (uint32,
// default 100), MOLDD_ANONAUTH_POW_BITS (1..32, default 20).
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

	"github.com/WissCore/moldchat/server/internal/anonauth"
	"github.com/WissCore/moldchat/server/internal/anonauth/sqlitestore"
	v1 "github.com/WissCore/moldchat/server/internal/api/v1"
	"github.com/WissCore/moldchat/server/internal/auth"
	"github.com/WissCore/moldchat/server/internal/health"
	"github.com/WissCore/moldchat/server/internal/storage"
	"github.com/WissCore/moldchat/server/internal/storage/cleanup"
	"github.com/WissCore/moldchat/server/internal/storage/memory"
	"github.com/WissCore/moldchat/server/internal/storage/snapshot"
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
	runnersShutdownTimeout = 10 * time.Second
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

	runSnapshot, err := initSnapshot(store, logger)
	if err != nil {
		logger.Error("init snapshot", "err", err.Error())
		return 1
	}

	issuer, verifier, runAnonauthCleanup, closeAnonauth, err := initAnonauth(logger)
	if err != nil {
		logger.Error("init anonauth", "err", err.Error())
		return 1
	}

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler())

	api := &v1.Server{
		Storage:  store,
		Auth:     auth.NewIssuer(),
		Logger:   logger,
		Issuer:   issuer,
		Verifier: verifier,
	}
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

	// Ordered shutdown: cancel runners ctx → wait for every background
	// runner (cleanup, snapshot, ...) to finish any in-flight Tick → only
	// then close the store. Closing the store while a Tick is mid-query
	// produces undefined behaviour in the SQL driver, so the WaitGroup
	// gate is mandatory, not cosmetic. The wait is bounded so a wedged
	// SQL operation cannot hold the process up forever; if the bound is
	// exceeded we close the store anyway and let the runtime tear the
	// goroutines down. closeAnonauth runs after closeStore so the
	// pseudonym DB is shut down on the same code path.
	var runnersWg sync.WaitGroup
	defer func() {
		shutdownCleanly(rootCancel, &runnersWg, func() error {
			storeErr := closeStore()
			anonErr := closeAnonauth()
			if storeErr != nil {
				return storeErr
			}
			return anonErr
		}, runnersShutdownTimeout, logger)
	}()

	if runCleanup != nil {
		runnersWg.Add(1)
		go func() {
			defer runnersWg.Done()
			runCleanup(rootCtx)
		}()
	}
	if runSnapshot != nil {
		runnersWg.Add(1)
		go func() {
			defer runnersWg.Done()
			runSnapshot(rootCtx)
		}()
	}
	if runAnonauthCleanup != nil {
		runnersWg.Add(1)
		go func() {
			defer runnersWg.Done()
			runAnonauthCleanup(rootCtx)
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

// shutdownCleanly cancels the background-runner context, waits for the
// runners to drain (bounded by waitTimeout), and only then closes the
// store. Extracted into a function so the timeout path is unit-testable
// without spinning up the whole process. logger is optional for tests.
func shutdownCleanly(rootCancel context.CancelFunc, runnersWg *sync.WaitGroup, closeStore func() error, waitTimeout time.Duration, logger *slog.Logger) {
	rootCancel()
	done := make(chan struct{})
	go func() {
		runnersWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(waitTimeout):
		if logger != nil {
			logger.Warn("background runners did not finish before timeout, forcing store close")
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

// initAnonauth constructs the anonymous-credential issuer/verifier
// pair when MOLDD_ANONAUTH=enforce. The issuer key and pseudonym
// database are derived from the same MOLDD_MASTER_SEED already used
// by the SQLCipher backend, but via a dedicated HKDF info string so
// the two derivations cannot collide. Returns nil issuer + nil
// verifier when the feature is disabled (the default), in which case
// the API server treats the X-Anonauth-Token header as not required.
//
// runCleanup is the periodic pseudonym-expiry sweeper; nil when the
// feature is disabled. closeAnonauth releases the pseudonym backing
// store; it returns nil when the feature is disabled.
const defaultAnonauthCleanupInterval = 15 * time.Minute

func initAnonauth(logger *slog.Logger) (
	issuer *anonauth.Issuer,
	verifier *anonauth.Verifier,
	runCleanup func(context.Context),
	closeAnonauth func() error,
	err error,
) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("MOLDD_ANONAUTH")))
	switch mode {
	case "", "off", "disabled":
		return nil, nil, nil, func() error { return nil }, nil
	case "enforce":
	default:
		return nil, nil, nil, nil, fmt.Errorf("MOLDD_ANONAUTH: unknown value %q (valid: off, enforce)", mode)
	}

	seed, seedErr := sqlite.LoadMasterSeed()
	if seedErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("anonauth: %w", seedErr)
	}
	dataDir := strings.TrimSpace(os.Getenv("MOLDD_ANONAUTH_DATA_DIR"))
	if dataDir == "" {
		return nil, nil, nil, nil, errors.New("anonauth: MOLDD_ANONAUTH_DATA_DIR is required when MOLDD_ANONAUTH=enforce")
	}

	epochDur, epochErr := durationFromEnv("MOLDD_ANONAUTH_EPOCH", time.Hour)
	if epochErr != nil {
		return nil, nil, nil, nil, epochErr
	}
	ttlDur, ttlErr := durationFromEnv("MOLDD_ANONAUTH_PSEUDONYM_TTL", 30*24*time.Hour)
	if ttlErr != nil {
		return nil, nil, nil, nil, ttlErr
	}
	tokensPer, tokErr := uint32FromEnv("MOLDD_ANONAUTH_TOKENS_PER_EPOCH", 100)
	if tokErr != nil {
		return nil, nil, nil, nil, tokErr
	}
	powBits, powErr := uint8FromEnv("MOLDD_ANONAUTH_POW_BITS", anonauth.DefaultDifficultyBits)
	if powErr != nil {
		return nil, nil, nil, nil, powErr
	}
	cfg := anonauth.IssuerConfig{
		Epoch:             epochDur,
		PseudonymTTL:      ttlDur,
		TokensPerEpoch:    tokensPer,
		PoWDifficultyBits: powBits,
	}

	key, keyErr := anonauth.DeriveIssuerKey(seed[:])
	if keyErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("anonauth derive key: %w", keyErr)
	}
	store, storeErr := sqlitestore.New([32]byte(seed), dataDir)
	if storeErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("anonauth open store: %w", storeErr)
	}
	iss, issErr := anonauth.NewIssuer(cfg, key, store)
	if issErr != nil {
		_ = store.Close()
		return nil, nil, nil, nil, fmt.Errorf("anonauth issuer: %w", issErr)
	}
	ver, verErr := anonauth.NewVerifier(anonauth.VerifierConfig{Epoch: cfg.Epoch}, key)
	if verErr != nil {
		_ = store.Close()
		return nil, nil, nil, nil, fmt.Errorf("anonauth verifier: %w", verErr)
	}
	cleanup := &anonauth.CleanupRunner{
		Store:    store,
		Interval: defaultAnonauthCleanupInterval,
		Logger:   logger,
	}
	logger.Info("anonauth enforced",
		"epoch", cfg.Epoch.String(),
		"tokens_per_epoch", cfg.TokensPerEpoch,
		"pseudonym_ttl", cfg.PseudonymTTL.String(),
		"pow_bits", cfg.PoWDifficultyBits,
		"cleanup_interval", defaultAnonauthCleanupInterval.String(),
	)
	return iss, ver, cleanup.Run, store.Close, nil
}

// durationFromEnv reads a Go duration from the named env var. An
// empty value falls back to def; an unparsable value returns an
// error so the caller can fail startup with a normal exit code
// rather than panicking the process.
func durationFromEnv(name string, def time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("env %s: %w", name, err)
	}
	return d, nil
}

func uint32FromEnv(name string, def uint32) (uint32, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def, nil
	}
	var v uint64
	if _, err := fmt.Sscanf(raw, "%d", &v); err != nil || v == 0 || v > uint64(^uint32(0)) {
		return 0, fmt.Errorf("env %s: invalid uint32 %q", name, raw)
	}
	return uint32(v), nil
}

func uint8FromEnv(name string, def uint8) (uint8, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def, nil
	}
	var v uint64
	if _, err := fmt.Sscanf(raw, "%d", &v); err != nil || v == 0 || v > 255 {
		return 0, fmt.Errorf("env %s: invalid uint8 %q", name, raw)
	}
	return uint8(v), nil
}

// initSnapshot constructs the periodic snapshot runner when both
// MOLDD_SNAPSHOT_INTERVAL and MOLDD_SNAPSHOT_DIR are set and the storage
// backend implements snapshot.Snapshotter (currently *sqlite.Store).
// Returns nil when snapshotting is disabled by configuration.
func initSnapshot(store storage.Storage, logger *slog.Logger) (func(context.Context), error) {
	intervalStr := strings.TrimSpace(os.Getenv("MOLDD_SNAPSHOT_INTERVAL"))
	dst := strings.TrimSpace(os.Getenv("MOLDD_SNAPSHOT_DIR"))
	if intervalStr == "" && dst == "" {
		return nil, nil
	}
	if intervalStr == "" || dst == "" {
		return nil, errors.New("MOLDD_SNAPSHOT_INTERVAL and MOLDD_SNAPSHOT_DIR must both be set or both be unset")
	}
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		return nil, fmt.Errorf("MOLDD_SNAPSHOT_INTERVAL: %w", err)
	}
	if interval <= 0 {
		return nil, errors.New("MOLDD_SNAPSHOT_INTERVAL must be positive")
	}
	snapshotter, ok := store.(snapshot.Snapshotter)
	if !ok {
		return nil, errors.New("MOLDD_SNAPSHOT_DIR is set but the configured storage backend does not support snapshots")
	}
	runner := &snapshot.Runner{
		Snapshotter: snapshotter,
		Dst:         dst,
		Interval:    interval,
		Logger:      logger,
	}
	return runner.Run, nil
}
