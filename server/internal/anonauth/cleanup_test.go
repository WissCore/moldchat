// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/anonauth"
)

// fakeStore is a PseudonymStore stub that records DeleteExpired calls
// and returns canned values. Used for unit-testing the cleanup
// runner in isolation from any backend.
type fakeStore struct {
	deleted int
	err     error
	calls   int
}

func (f *fakeStore) Register(_ context.Context, _ ed25519.PublicKey, _, _ time.Time) error {
	return nil
}

func (f *fakeStore) CheckAndIncrement(_ context.Context, _ ed25519.PublicKey, _ int64, _ uint32, _ time.Time) error {
	return nil
}

func (f *fakeStore) DeleteExpired(_ context.Context, _ time.Time) (int, error) {
	f.calls++
	return f.deleted, f.err
}

func (f *fakeStore) Close() error { return nil }

func TestCleanupRunner_TickReportsDeleted(t *testing.T) {
	t.Parallel()
	store := &fakeStore{deleted: 7}
	r := &anonauth.CleanupRunner{Store: store, Interval: time.Hour}
	got := r.Tick(context.Background())
	if got != 7 {
		t.Fatalf("Tick returned %d, want 7", got)
	}
	if store.calls != 1 {
		t.Fatalf("calls = %d, want 1", store.calls)
	}
}

func TestCleanupRunner_TickHandlesError(t *testing.T) {
	t.Parallel()
	store := &fakeStore{err: errors.New("boom")}
	r := &anonauth.CleanupRunner{Store: store, Interval: time.Hour}
	got := r.Tick(context.Background())
	if got != 0 {
		t.Fatalf("Tick on error returned %d, want 0", got)
	}
}

func TestCleanupRunner_RunNoopOnZeroInterval(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	r := &anonauth.CleanupRunner{Store: store, Interval: 0}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Run must return immediately on a non-positive interval
	r.Run(ctx)
	if store.calls != 0 {
		t.Fatalf("Run with zero interval should not call DeleteExpired")
	}
}

// freshKey here is package-local to avoid a cross-test dependency
// with the memory-store tests that also need one.
func freshKeyForCleanup(tb testing.TB) ed25519.PublicKey {
	tb.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("ed25519: %v", err)
	}
	return pub
}

func TestCleanupRunner_EndToEndAgainstMemoryStore(t *testing.T) {
	t.Parallel()
	store := anonauth.NewMemoryPseudonymStore()
	now := time.Now()
	live := freshKeyForCleanup(t)
	dead := freshKeyForCleanup(t)
	_ = store.Register(context.Background(), live, now, now.Add(time.Hour))
	_ = store.Register(context.Background(), dead, now.Add(-2*time.Hour), now.Add(-time.Minute))

	r := &anonauth.CleanupRunner{Store: store, Interval: time.Hour}
	if got := r.Tick(context.Background()); got != 1 {
		t.Fatalf("Tick deleted %d, want 1", got)
	}
	// The live pseudonym must still be usable after the sweep.
	if err := store.CheckAndIncrement(context.Background(), live, 0, 1, now); err != nil {
		t.Fatalf("live pseudonym usable: %v", err)
	}
}
