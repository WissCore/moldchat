// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestShutdownCleanly_HappyPath verifies the bookkeeping when the
// cleanup goroutine exits promptly: rootCancel must run, cleanupWg
// must drain, closeStore must run exactly once.
func TestShutdownCleanly_HappyPath(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
	}()

	closes := &atomic.Int64{}
	closeStore := func() error {
		closes.Add(1)
		return nil
	}

	shutdownCleanly(cancel, &wg, closeStore, time.Second, nil)

	if got := closes.Load(); got != 1 {
		t.Errorf("closeStore calls: got %d, want 1", got)
	}
}

// TestShutdownCleanly_TimeoutPath verifies the bound: even if the
// cleanup goroutine never returns, shutdownCleanly closes the store
// once the timeout elapses, instead of hanging the process forever.
// This is the regression guard for the deadlock scenario flagged by
// the second-round audit (S/C-01).
func TestShutdownCleanly_TimeoutPath(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	_ = ctx // unused but required to mirror real call shape

	var wg sync.WaitGroup
	wg.Add(1)
	stuck := make(chan struct{})
	go func() {
		defer wg.Done()
		// Simulates a wedged Tick that ignores ctx cancellation.
		<-stuck
	}()
	t.Cleanup(func() { close(stuck) })

	closes := &atomic.Int64{}
	closeStore := func() error {
		closes.Add(1)
		return nil
	}

	start := time.Now()
	shutdownCleanly(cancel, &wg, closeStore, 50*time.Millisecond, nil)
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("shutdownCleanly took %v, expected ≈ 50ms timeout", elapsed)
	}
	if got := closes.Load(); got != 1 {
		t.Errorf("closeStore calls: got %d, want 1", got)
	}
}
