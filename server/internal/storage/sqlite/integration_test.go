// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package sqlite_test

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/queue"
	"github.com/WissCore/moldchat/server/internal/storage/cleanup"
	"github.com/WissCore/moldchat/server/internal/storage/sqlite"
)

// TestIntegration_FullLifecycle exercises the whole storage stack end
// to end: real SQLCipher store, real cleanup runner ticking in the
// background, real durability across a Close/Reopen cycle, real
// crypto-shred via TTL eviction. Build-tagged so the regular unit
// suite stays fast; run with `go test -tags integration ./...`.
func TestIntegration_FullLifecycle(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dir := t.TempDir()

	st, err := sqlite.New(seed, dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()

	// Phase 1: queue lifecycle.
	keys := queue.OwnerKeys{
		X25519Pub:  func() []byte { b := make([]byte, queue.X25519PubKeyBytes); b[0] = 1; return b }(),
		Ed25519Pub: make([]byte, queue.Ed25519PubKeyBytes),
	}
	q, err := st.CreateQueue(ctx, keys)
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	if _, perr := st.PutMessage(ctx, q.ID, []byte("hello")); perr != nil {
		t.Fatalf("PutMessage: %v", perr)
	}

	// Phase 2: durability across restart.
	if cerr := st.Close(); cerr != nil {
		t.Fatalf("first Close: %v", cerr)
	}
	st2, err := sqlite.New(seed, dir)
	if err != nil {
		t.Fatalf("re-New: %v", err)
	}
	msgs, _, err := st2.ListMessages(ctx, q.ID, 10)
	if err != nil {
		t.Fatalf("ListMessages after restart: %v", err)
	}
	if len(msgs) != 1 || string(msgs[0].Blob) != "hello" {
		t.Errorf("durability: got %+v", msgs)
	}

	// Phase 3: cleanup runner with a frozen far-future clock evicts
	// the queue, which triggers wal_checkpoint(FULL) and removes the
	// underlying file.
	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	r := &cleanup.Runner{
		Cleaner:  st2,
		Interval: 10 * time.Millisecond,
		Logger:   logger,
		Now:      func() time.Time { return time.Now().Add(48 * time.Hour) },
	}
	runCtx, runCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(runCtx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := st2.GetQueue(ctx, q.ID); errors.Is(err, queue.ErrQueueNotFound) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	runCancel()
	<-done

	if _, err := st2.GetQueue(ctx, q.ID); !errors.Is(err, queue.ErrQueueNotFound) {
		t.Errorf("queue not evicted by cleanup: %v", err)
	}

	if err := st2.Close(); err != nil {
		t.Errorf("final Close: %v", err)
	}
}

// testWriter adapts *testing.T to io.Writer so slog logs land in the
// test output stream when a phase fails.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(string(p))
	return len(p), nil
}
