// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/WissCore/moldchat/server/internal/queue"

	// Registers the "sqlite3" driver with SQLCipher 4.x support.
	_ "github.com/mutecomm/go-sqlcipher/v4"
)

const (
	driverName          = "sqlite3"
	masterFilename      = "master.db"
	queueFilenameSuffix = ".db"
	cipherPageSize      = 4096
	dataDirPerm         = 0o700
)

// Store is a SQLCipher-backed implementation of storage.Storage.
//
// One master database holds queue metadata; each queue's messages live in
// their own encrypted file. Database keys are derived from a single master
// seed via HKDF, so seizing the storage directory without the seed yields
// only opaque ciphertext.
type Store struct {
	seed     MasterSeed
	dataDir  string
	masterDB *sql.DB

	mu sync.Mutex
}

// New opens (or creates) the master database and initialises its schema.
// dataDir is created with 0700 permissions if it does not exist.
func New(seed MasterSeed, dataDir string) (*Store, error) {
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve dataDir: %w", err)
	}
	if mkdirErr := os.MkdirAll(abs, dataDirPerm); mkdirErr != nil {
		return nil, fmt.Errorf("create dataDir: %w", mkdirErr)
	}
	masterDB, err := openEncryptedDB(filepath.Join(abs, masterFilename), seed.MasterKey())
	if err != nil {
		return nil, fmt.Errorf("open master.db: %w", err)
	}
	if _, schemaErr := masterDB.Exec(masterSchema); schemaErr != nil {
		_ = masterDB.Close()
		return nil, fmt.Errorf("init master schema: %w", schemaErr)
	}
	return &Store{seed: seed, dataDir: abs, masterDB: masterDB}, nil
}

// Close releases resources held by the store.
func (s *Store) Close() error { return s.masterDB.Close() }

const masterSchema = `
CREATE TABLE IF NOT EXISTS queues (
	id           TEXT    PRIMARY KEY,
	owner_key    BLOB    NOT NULL,
	created_at   INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	last_access  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queues_expires_at ON queues(expires_at);
`

const queueSchema = `
CREATE TABLE IF NOT EXISTS messages (
	id           TEXT    PRIMARY KEY,
	blob         BLOB    NOT NULL,
	received_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at);
`

// openEncryptedDB opens a SQLCipher database at path with the given hex key.
// The connection pool is capped at 1 to match SQLite's single-writer model.
func openEncryptedDB(path, hexKey string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma_key=x'%s'&_pragma_cipher_page_size=%d",
		path, hexKey, cipherPageSize)
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if pingErr := db.Ping(); pingErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", pingErr)
	}
	return db, nil
}

func (s *Store) queuePath(queueID string) string {
	return filepath.Join(s.dataDir, queueID+queueFilenameSuffix)
}

// openQueue opens (and initialises if needed) the per-queue database.
// The returned handle must be closed by the caller.
func (s *Store) openQueue(queueID string) (*sql.DB, error) {
	db, err := openEncryptedDB(s.queuePath(queueID), s.seed.DeriveQueueKey(queueID))
	if err != nil {
		return nil, err
	}
	if _, schemaErr := db.Exec(queueSchema); schemaErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init queue schema: %w", schemaErr)
	}
	return db, nil
}

// CreateQueue inserts a new queue row and creates its per-queue database file.
func (s *Store) CreateQueue(ctx context.Context, ownerKey []byte) (*queue.Queue, error) {
	if err := queue.ValidateOwnerKey(ownerKey); err != nil {
		return nil, err
	}
	id, err := queue.NewID()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expires := now.Add(queue.DefaultTTL)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, execErr := s.masterDB.ExecContext(ctx,
		`INSERT INTO queues(id, owner_key, created_at, expires_at, last_access) VALUES (?, ?, ?, ?, ?)`,
		id, ownerKey, now.UnixNano(), expires.UnixNano(), now.UnixNano(),
	); execErr != nil {
		return nil, fmt.Errorf("insert queue: %w", execErr)
	}

	qdb, err := s.openQueue(id)
	if err != nil {
		// Roll back the master row so we do not leak a metadata entry without a file.
		_, _ = s.masterDB.ExecContext(ctx, `DELETE FROM queues WHERE id = ?`, id)
		return nil, fmt.Errorf("init queue db: %w", err)
	}
	_ = qdb.Close()

	return &queue.Queue{
		ID:         id,
		OwnerKey:   append([]byte(nil), ownerKey...),
		CreatedAt:  now,
		ExpiresAt:  expires,
		LastAccess: now,
	}, nil
}

// GetQueue returns queue metadata or queue.ErrQueueNotFound.
func (s *Store) GetQueue(ctx context.Context, id string) (*queue.Queue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getQueueLocked(ctx, id)
}

func (s *Store) getQueueLocked(ctx context.Context, id string) (*queue.Queue, error) {
	var (
		q                                queue.Queue
		createdNs, expiresNs, lastAccess int64
	)
	row := s.masterDB.QueryRowContext(ctx,
		`SELECT id, owner_key, created_at, expires_at, last_access FROM queues WHERE id = ?`, id,
	)
	if err := row.Scan(&q.ID, &q.OwnerKey, &createdNs, &expiresNs, &lastAccess); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, queue.ErrQueueNotFound
		}
		return nil, err
	}
	q.CreatedAt = time.Unix(0, createdNs).UTC()
	q.ExpiresAt = time.Unix(0, expiresNs).UTC()
	q.LastAccess = time.Unix(0, lastAccess).UTC()
	return &q, nil
}

// PutMessage appends an opaque blob to the queue.
func (s *Store) PutMessage(ctx context.Context, queueID string, blob []byte) (*queue.Message, error) {
	switch {
	case len(blob) == 0:
		return nil, queue.ErrEmptyBlob
	case len(blob) > queue.MaxBlobSize:
		return nil, queue.ErrBlobTooLarge
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.getQueueLocked(ctx, queueID); err != nil {
		return nil, err
	}

	qdb, err := s.openQueue(queueID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = qdb.Close() }()

	msgID, err := queue.NewMessageID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()

	if _, execErr := qdb.ExecContext(ctx,
		`INSERT INTO messages(id, blob, received_at) VALUES (?, ?, ?)`,
		msgID, blob, now.UnixNano(),
	); execErr != nil {
		return nil, fmt.Errorf("insert message: %w", execErr)
	}

	if err := s.touchQueue(ctx, queueID, now); err != nil {
		return nil, err
	}

	return &queue.Message{
		ID:         msgID,
		QueueID:    queueID,
		Blob:       append([]byte(nil), blob...),
		ReceivedAt: now,
	}, nil
}

// ListMessages returns up to limit messages in arrival order plus a hasMore flag.
func (s *Store) ListMessages(ctx context.Context, queueID string, limit int) ([]*queue.Message, bool, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.getQueueLocked(ctx, queueID); err != nil {
		return nil, false, err
	}

	qdb, err := s.openQueue(queueID)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = qdb.Close() }()

	rows, err := qdb.QueryContext(ctx,
		`SELECT id, blob, received_at FROM messages ORDER BY received_at ASC LIMIT ?`, limit+1,
	)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()

	var msgs []*queue.Message
	for rows.Next() {
		var (
			m          queue.Message
			receivedNs int64
		)
		if scanErr := rows.Scan(&m.ID, &m.Blob, &receivedNs); scanErr != nil {
			return nil, false, scanErr
		}
		m.QueueID = queueID
		m.ReceivedAt = time.Unix(0, receivedNs).UTC()
		msgs = append(msgs, &m)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	hasMore := len(msgs) > limit
	if hasMore {
		msgs = msgs[:limit]
	}
	if err := s.touchQueue(ctx, queueID, time.Now().UTC()); err != nil {
		return nil, false, err
	}
	return msgs, hasMore, nil
}

// DeleteMessage removes a single message from the queue.
func (s *Store) DeleteMessage(ctx context.Context, queueID, messageID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.getQueueLocked(ctx, queueID); err != nil {
		return err
	}

	qdb, err := s.openQueue(queueID)
	if err != nil {
		return err
	}
	defer func() { _ = qdb.Close() }()

	res, err := qdb.ExecContext(ctx, `DELETE FROM messages WHERE id = ?`, messageID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return queue.ErrMessageNotFound
	}
	return s.touchQueue(ctx, queueID, time.Now().UTC())
}

func (s *Store) touchQueue(ctx context.Context, queueID string, t time.Time) error {
	_, err := s.masterDB.ExecContext(ctx,
		`UPDATE queues SET last_access = ? WHERE id = ?`, t.UnixNano(), queueID)
	return err
}

// ExpiredQueueIDs returns queue identifiers whose expires_at is before t.
func (s *Store) ExpiredQueueIDs(ctx context.Context, t time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.masterDB.QueryContext(ctx,
		`SELECT id FROM queues WHERE expires_at < ?`, t.UnixNano())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			return nil, scanErr
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// DeleteQueue removes a queue's metadata row and its database file.
// Used by the TTL cleanup goroutine.
func (s *Store) DeleteQueue(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.masterDB.ExecContext(ctx, `DELETE FROM queues WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return queue.ErrQueueNotFound
	}
	if removeErr := os.Remove(s.queuePath(id)); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return fmt.Errorf("remove queue db file: %w", removeErr)
	}
	return nil
}
