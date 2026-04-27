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
}

func (f *fakeCleaner) ExpiredQueueIDs(_ context.Context, _ time.Time) ([]string, error) {
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
	// File on disk should be gone.
	path := filepath.Join(dir, q.ID+".db")
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("queue db file still exists after cleanup: %v", statErr)
	}
}
