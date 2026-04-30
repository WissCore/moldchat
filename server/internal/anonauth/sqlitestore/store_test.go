// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlitestore_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/anonauth"
	"github.com/WissCore/moldchat/server/internal/anonauth/sqlitestore"
)

func newStore(tb testing.TB) *sqlitestore.Store {
	tb.Helper()
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		tb.Fatalf("seed: %v", err)
	}
	store, err := sqlitestore.New(seed, tb.TempDir())
	if err != nil {
		tb.Fatalf("new: %v", err)
	}
	tb.Cleanup(func() { _ = store.Close() })
	return store
}

func freshKey(tb testing.TB) ed25519.PublicKey {
	tb.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("ed25519: %v", err)
	}
	return pub
}

func TestStore_DuplicateRegisterRejected(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	pub := freshKey(t)
	now := time.Now()
	if err := store.Register(context.Background(), pub, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("first: %v", err)
	}
	err := store.Register(context.Background(), pub, now, now.Add(time.Hour))
	if !errors.Is(err, anonauth.ErrPseudonymExists) {
		t.Fatalf("expected ErrPseudonymExists, got %v", err)
	}
}

func TestStore_CheckAndIncrement(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	pub := freshKey(t)
	now := time.Now()
	_ = store.Register(context.Background(), pub, now, now.Add(time.Hour))

	for i := uint32(0); i < 3; i++ {
		if err := store.CheckAndIncrement(context.Background(), pub, 99, 3, now); err != nil {
			t.Fatalf("inc %d: %v", i, err)
		}
	}
	if err := store.CheckAndIncrement(context.Background(), pub, 99, 3, now); !errors.Is(err, anonauth.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	if err := store.CheckAndIncrement(context.Background(), pub, 100, 3, now); err != nil {
		t.Fatalf("expected reset in next epoch, got %v", err)
	}
}

func TestStore_CheckAndIncrement_Expired(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	pub := freshKey(t)
	now := time.Now()
	_ = store.Register(context.Background(), pub, now.Add(-2*time.Hour), now.Add(-time.Hour))
	err := store.CheckAndIncrement(context.Background(), pub, 1, 5, now)
	if !errors.Is(err, anonauth.ErrPseudonymExpired) {
		t.Fatalf("expected ErrPseudonymExpired, got %v", err)
	}
}

func TestStore_CheckAndIncrement_NegativeEpochRejected(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	pub := freshKey(t)
	now := time.Now()
	_ = store.Register(context.Background(), pub, now, now.Add(time.Hour))
	err := store.CheckAndIncrement(context.Background(), pub, -1, 5, now)
	if err == nil {
		t.Fatalf("negative epoch must be rejected")
	}
}

func TestStore_DeleteExpired(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	now := time.Now()
	live := freshKey(t)
	dead := freshKey(t)
	_ = store.Register(context.Background(), live, now, now.Add(time.Hour))
	_ = store.Register(context.Background(), dead, now.Add(-2*time.Hour), now.Add(-time.Hour))
	deleted, err := store.DeleteExpired(context.Background(), now)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	// The live record must remain usable.
	if err := store.CheckAndIncrement(context.Background(), live, 0, 1, now); err != nil {
		t.Fatalf("live record gone after expired sweep: %v", err)
	}
}

func TestStore_CheckAndIncrement_Concurrent(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	pub := freshKey(t)
	now := time.Now()
	_ = store.Register(context.Background(), pub, now, now.Add(time.Hour))

	const limit = 50
	const goroutines = 16
	var ok atomic.Int64
	var rejected atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < limit; j++ {
				err := store.CheckAndIncrement(context.Background(), pub, 1, limit, now)
				switch {
				case err == nil:
					ok.Add(1)
				case errors.Is(err, anonauth.ErrRateLimited):
					rejected.Add(1)
				default:
					t.Errorf("unexpected: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if ok.Load() != int64(limit) {
		t.Fatalf("ok = %d, want exactly %d", ok.Load(), limit)
	}
	if rejected.Load() == 0 {
		t.Fatalf("expected rejections under contention")
	}
}

func TestStore_SurvivesRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var seed [32]byte
	_, _ = rand.Read(seed[:])

	first, err := sqlitestore.New(seed, dir)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	pub := freshKey(t)
	now := time.Now()
	_ = first.Register(context.Background(), pub, now, now.Add(time.Hour))
	_ = first.Close()

	second, err := sqlitestore.New(seed, dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = second.Close() }()
	// Issuance against the persisted pseudonym must work after restart.
	if err := second.CheckAndIncrement(context.Background(), pub, 0, 1, now); err != nil {
		t.Fatalf("expected persisted pseudonym to remain usable: %v", err)
	}
}
