// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package cleanup_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/queue"
	"github.com/WissCore/moldchat/server/internal/storage/cleanup"
	"github.com/WissCore/moldchat/server/internal/storage/sqlite"
)

type fakeCleaner struct {
	expired    []string
	deleted    []string
	listErr    error
	deleteErrs map[string]error
	// listDelay simulates a slow Tick so tests can race a context
	// cancel against an in-flight ExpiredQueueIDs call.
	listDelay time.Duration
}

func (f *fakeCleaner) ExpiredQueueIDs(ctx context.Context, _ time.Time) ([]string, error) {
	if f.listDelay > 0 {
		select {
		case <-time.After(f.listDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.expired, nil
}

func (f *fakeCleaner) DeleteQueue(_ context.Context, id string) error {
	if err, ok := f.deleteErrs[id]; ok {
		return err
	}
	f.deleted = append(f.deleted, id)
	return nil
}

func TestTick_DeletesExpiredQueues(t *testing.T) {
	t.Parallel()

	c := &fakeCleaner{expired: []string{"q1", "q2", "q3"}}
	r := &cleanup.Runner{Cleaner: c}
	got := r.Tick(context.Background())

	if got != 3 {
		t.Errorf("deleted: got %d, want 3", got)
	}
	if len(c.deleted) != 3 {
		t.Errorf("delete calls: got %d, want 3", len(c.deleted))
	}
}

func TestTick_NothingToClean(t *testing.T) {
	t.Parallel()

	c := &fakeCleaner{expired: nil}
	r := &cleanup.Runner{Cleaner: c}
	if got := r.Tick(context.Background()); got != 0 {
		t.Errorf("deleted: got %d, want 0", got)
	}
}

func TestTick_SkipsRaceyAlreadyGone(t *testing.T) {
	t.Parallel()

	c := &fakeCleaner{
		expired: []string{"q1", "q2"},
		deleteErrs: map[string]error{
			"q1": queue.ErrQueueNotFound,
		},
	}
	r := &cleanup.Runner{Cleaner: c}
	got := r.Tick(context.Background())

	if got != 1 {
		t.Errorf("deleted: got %d, want 1 (q2; q1 was already gone)", got)
	}
}

func TestTick_ContinuesAfterDeleteError(t *testing.T) {
	t.Parallel()

	c := &fakeCleaner{
		expired: []string{"q1", "q2"},
		deleteErrs: map[string]error{
			"q1": errors.New("disk full"),
		},
	}
	r := &cleanup.Runner{Cleaner: c}
	if got := r.Tick(context.Background()); got != 1 {
		t.Errorf("deleted: got %d, want 1 (q2 succeeded; q1 errored)", got)
	}
}

func TestTick_ListErrorReturnsZero(t *testing.T) {
	t.Parallel()

	c := &fakeCleaner{listErr: errors.New("db locked")}
	r := &cleanup.Runner{Cleaner: c}
	if got := r.Tick(context.Background()); got != 0 {
		t.Errorf("deleted on list error: got %d, want 0", got)
	}
}

// TestRun_ExitsOnContextCancel is the regression guard for the shutdown
// race between cleanup goroutine and DB close: when its context is
// cancelled the Run loop must return promptly even if a Tick is
// in-flight, otherwise main()'s wait-then-close sequence would risk
// closing the store under an active query.
func TestRun_ExitsOnContextCancel(t *testing.T) {
	t.Parallel()

	c := &fakeCleaner{
		expired:   []string{"q1"},
		listDelay: 200 * time.Millisecond,
	}
	r := &cleanup.Runner{Cleaner: c, Interval: 10 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()

	// Give Run a tick to enter ExpiredQueueIDs.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of context cancel")
	}
}

// TestRun_ZeroInterval is a smoke test for the documented contract that
// Runner.Run with Interval <= 0 returns immediately rather than spinning.
func TestRun_ZeroInterval(t *testing.T) {
	t.Parallel()
	r := &cleanup.Runner{Cleaner: &fakeCleaner{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run with zero interval did not return")
	}
}

// Integration test: run against a real SQLCipher store with a frozen clock.
func TestTick_AgainstRealSQLiteStore(t *testing.T) {
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
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	x := make([]byte, queue.X25519PubKeyBytes)
	x[0] = 1
	keys := queue.OwnerKeys{
		X25519Pub:  x,
		Ed25519Pub: make([]byte, queue.Ed25519PubKeyBytes),
	}
	q, err := st.CreateQueue(ctx, keys)
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}

	// "Now" is 48h in the future, so the queue (TTL 24h) is expired.
	r := &cleanup.Runner{
		Cleaner: st,
		Now:     func() time.Time { return time.Now().Add(48 * time.Hour) },
	}
	if got := r.Tick(ctx); got != 1 {
		t.Errorf("deleted: got %d, want 1", got)
	}
	if _, err := st.GetQueue(ctx, q.ID); !errors.Is(err, queue.ErrQueueNotFound) {
		t.Errorf("queue still present after cleanup: %v", err)
	}
	// File on disk should be gone. Filenames are HMAC(seed, queueID),
	// not the raw queue id.
	path := filepath.Join(dir, seed.QueueFilename(q.ID)+".db")
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("queue db file still exists after cleanup: %v", statErr)
	}
}
