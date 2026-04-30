// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth_test

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
)

func freshKey(tb testing.TB) ed25519.PublicKey {
	tb.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("ed25519: %v", err)
	}
	return pub
}

func TestMemoryStore_RegisterDuplicateRejected(t *testing.T) {
	t.Parallel()
	store := anonauth.NewMemoryPseudonymStore()
	pub := freshKey(t)
	now := time.Now()
	if err := store.Register(context.Background(), pub, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("first register: %v", err)
	}
	err := store.Register(context.Background(), pub, now, now.Add(time.Hour))
	if !errors.Is(err, anonauth.ErrPseudonymExists) {
		t.Fatalf("expected ErrPseudonymExists, got %v", err)
	}
}

func TestMemoryStore_CheckAndIncrement_Limit(t *testing.T) {
	t.Parallel()
	store := anonauth.NewMemoryPseudonymStore()
	pub := freshKey(t)
	now := time.Now()
	_ = store.Register(context.Background(), pub, now, now.Add(time.Hour))
	for i := uint32(0); i < 3; i++ {
		if err := store.CheckAndIncrement(context.Background(), pub, 42, 3, now); err != nil {
			t.Fatalf("increment %d: %v", i, err)
		}
	}
	if err := store.CheckAndIncrement(context.Background(), pub, 42, 3, now); !errors.Is(err, anonauth.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
}

func TestMemoryStore_CheckAndIncrement_EpochReset(t *testing.T) {
	t.Parallel()
	store := anonauth.NewMemoryPseudonymStore()
	pub := freshKey(t)
	now := time.Now()
	_ = store.Register(context.Background(), pub, now, now.Add(2*time.Hour))
	for i := 0; i < 5; i++ {
		_ = store.CheckAndIncrement(context.Background(), pub, 42, 5, now)
	}
	if err := store.CheckAndIncrement(context.Background(), pub, 43, 5, now); err != nil {
		t.Fatalf("expected fresh quota in new epoch, got %v", err)
	}
}

func TestMemoryStore_CheckAndIncrement_Expired(t *testing.T) {
	t.Parallel()
	store := anonauth.NewMemoryPseudonymStore()
	pub := freshKey(t)
	now := time.Now()
	_ = store.Register(context.Background(), pub, now.Add(-2*time.Hour), now.Add(-time.Hour))
	err := store.CheckAndIncrement(context.Background(), pub, 1, 5, now)
	if !errors.Is(err, anonauth.ErrPseudonymExpired) {
		t.Fatalf("expected ErrPseudonymExpired, got %v", err)
	}
}

func TestMemoryStore_DeleteExpired(t *testing.T) {
	t.Parallel()
	store := anonauth.NewMemoryPseudonymStore()
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
		t.Fatalf("expected 1 deletion, got %d", deleted)
	}
	// The live record must still authorise increments after the cleanup.
	if err := store.CheckAndIncrement(context.Background(), live, 0, 1, now); err != nil {
		t.Fatalf("live record should remain usable: %v", err)
	}
}

func TestMemoryStore_CheckAndIncrement_RaceBoundaryRespected(t *testing.T) {
	t.Parallel()
	store := anonauth.NewMemoryPseudonymStore()
	pub := freshKey(t)
	now := time.Now()
	_ = store.Register(context.Background(), pub, now, now.Add(time.Hour))

	const limit = 100
	const goroutines = 32
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
		t.Fatalf("expected exactly %d successful increments, got %d", limit, ok.Load())
	}
	if rejected.Load() == 0 {
		t.Fatalf("expected some rate-limit rejections under contention")
	}
}
