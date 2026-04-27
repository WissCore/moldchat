// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/queue"
	"github.com/WissCore/moldchat/server/internal/storage/sqlite"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

func newTestStore(t *testing.T) (*sqlite.Store, string) {
	t.Helper()

	var seed sqlite.MasterSeed
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dir := t.TempDir()
	st, err := sqlite.New(seed, dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, dir
}

func ownerKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, queue.OwnerKeyBytes)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestNew_CreatesDataDir(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	st, err := sqlite.New(seed, dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = st.Close() }()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("dir permissions should be 0700, got %o", info.Mode().Perm())
	}
}

func TestCreateAndPutAndList_RoundTrip(t *testing.T) {
	t.Parallel()
	st, _ := newTestStore(t)
	ctx := context.Background()

	q, err := st.CreateQueue(ctx, ownerKey(t))
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	want := []byte("opaque-blob")
	if _, putErr := st.PutMessage(ctx, q.ID, want); putErr != nil {
		t.Fatalf("PutMessage: %v", putErr)
	}
	msgs, hasMore, err := st.ListMessages(ctx, q.ID, 10)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if hasMore {
		t.Errorf("hasMore: got true, want false")
	}
	if len(msgs) != 1 {
		t.Fatalf("len(msgs): got %d, want 1", len(msgs))
	}
	if !bytes.Equal(msgs[0].Blob, want) {
		t.Errorf("blob round-trip: got %q, want %q", msgs[0].Blob, want)
	}
}

func TestDurability_AcrossRestart(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dir := t.TempDir()

	first, err := sqlite.New(seed, dir)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	ctx := context.Background()
	q, err := first.CreateQueue(ctx, ownerKey(t))
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	want := []byte("persisted")
	if _, putErr := first.PutMessage(ctx, q.ID, want); putErr != nil {
		t.Fatalf("PutMessage: %v", putErr)
	}
	if closeErr := first.Close(); closeErr != nil {
		t.Fatalf("close first: %v", closeErr)
	}

	second, err := sqlite.New(seed, dir)
	if err != nil {
		t.Fatalf("second New: %v", err)
	}
	defer func() { _ = second.Close() }()

	msgs, _, err := second.ListMessages(ctx, q.ID, 10)
	if err != nil {
		t.Fatalf("ListMessages after restart: %v", err)
	}
	if len(msgs) != 1 || !bytes.Equal(msgs[0].Blob, want) {
		t.Errorf("messages did not survive restart: %+v", msgs)
	}
}

func TestEncryptionAtRest_DBFileIsOpaque(t *testing.T) {
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
	if _, createErr := st.CreateQueue(context.Background(), ownerKey(t)); createErr != nil {
		t.Fatalf("CreateQueue: %v", createErr)
	}
	if closeErr := st.Close(); closeErr != nil {
		t.Fatalf("close: %v", closeErr)
	}

	// The SQLite driver must refuse to open the file without the cipher key.
	// This is the operational guarantee we care about: even with disk access,
	// no process can read the database without MOLDD_MASTER_SEED.
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(dir, "master.db"))
	if err != nil {
		t.Fatalf("open without key: %v", err)
	}
	defer func() { _ = db.Close() }()
	if pingErr := db.Ping(); pingErr == nil {
		t.Errorf("ping without key succeeded; the file is not encrypted")
	}
}

func TestPutMessage_QueueNotFound(t *testing.T) {
	t.Parallel()
	st, _ := newTestStore(t)

	if _, err := st.PutMessage(context.Background(), "missing-queue-id", []byte("x")); !errors.Is(err, queue.ErrQueueNotFound) {
		t.Errorf("got %v, want ErrQueueNotFound", err)
	}
}

func TestPutMessage_RejectsTooLargeAndEmpty(t *testing.T) {
	t.Parallel()
	st, _ := newTestStore(t)
	ctx := context.Background()
	q, err := st.CreateQueue(ctx, ownerKey(t))
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	if _, err := st.PutMessage(ctx, q.ID, nil); !errors.Is(err, queue.ErrEmptyBlob) {
		t.Errorf("empty: got %v, want ErrEmptyBlob", err)
	}
	if _, err := st.PutMessage(ctx, q.ID, make([]byte, queue.MaxBlobSize+1)); !errors.Is(err, queue.ErrBlobTooLarge) {
		t.Errorf("oversize: got %v, want ErrBlobTooLarge", err)
	}
}

func TestDeleteMessage_RoundTrip(t *testing.T) {
	t.Parallel()
	st, _ := newTestStore(t)
	ctx := context.Background()

	q, err := st.CreateQueue(ctx, ownerKey(t))
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	m, err := st.PutMessage(ctx, q.ID, []byte("payload"))
	if err != nil {
		t.Fatalf("PutMessage: %v", err)
	}
	if delErr := st.DeleteMessage(ctx, q.ID, m.ID); delErr != nil {
		t.Fatalf("DeleteMessage: %v", delErr)
	}
	msgs, _, err := st.ListMessages(ctx, q.ID, 10)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("after delete: got %d msgs, want 0", len(msgs))
	}
	if err := st.DeleteMessage(ctx, q.ID, m.ID); !errors.Is(err, queue.ErrMessageNotFound) {
		t.Errorf("second delete: got %v, want ErrMessageNotFound", err)
	}
}

func TestExpiredAndDeleteQueue(t *testing.T) {
	t.Parallel()
	st, dir := newTestStore(t)
	ctx := context.Background()

	q, err := st.CreateQueue(ctx, ownerKey(t))
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	// Far future cutoff: the queue is treated as expired.
	ids, err := st.ExpiredQueueIDs(ctx, time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatalf("ExpiredQueueIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != q.ID {
		t.Fatalf("expected one expired id, got %v", ids)
	}
	if err := st.DeleteQueue(ctx, q.ID); err != nil {
		t.Fatalf("DeleteQueue: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, q.ID+".db")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("queue file still exists: %v", err)
	}
	if _, err := st.GetQueue(ctx, q.ID); !errors.Is(err, queue.ErrQueueNotFound) {
		t.Errorf("queue still in master: %v", err)
	}
}
