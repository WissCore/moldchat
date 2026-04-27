// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/WissCore/moldchat/server/internal/queue"

	sqlcipher "github.com/mutecomm/go-sqlcipher/v4"
)

const (
	masterFilename      = "master.db"
	queueFilenameSuffix = ".db"
	dataDirPerm         = 0o700

	// masterWriterMaxOpenConns is intentionally 1: SQLite serialises
	// writers anyway, and a single connection eliminates the chance
	// of SQLITE_BUSY between concurrent INSERT / UPDATE / DELETE
	// statements going through the writer pool.
	masterWriterMaxOpenConns = 1

	// masterReaderMaxOpenConns gives reader queries (GetQueue,
	// ExpiredQueueIDs, getQueueWithSalt) a parallel pool sized for
	// typical small-server CPU counts. WAL mode lets these readers
	// proceed against the last committed snapshot without blocking
	// the writer or each other.
	masterReaderMaxOpenConns = 4

	// queueMaxOpenConns stays at 1 because per-queue files are
	// write-mostly and not WAL — there is no concurrent-read benefit
	// to spare connections, and one connection keeps SQLite's writer
	// serialization free of SQLITE_BUSY.
	queueMaxOpenConns = 1
)

// cipherDriver is the SQLCipher driver instance used by the cipherConnector.
// It is package-level rather than re-allocated per connection so the
// driver's internal initialisation (loadable extensions, etc.) runs once.
var cipherDriver = &sqlcipher.SQLiteDriver{}

// cipherConnector is a database/sql Connector that opens a SQLCipher
// connection, applies the cipher key, and configures privacy-relevant
// PRAGMAs before returning the connection to the pool.
//
// The hex key is produced by deriveKey on every Connect call rather
// than stored on the struct: this minimises the lifetime of the
// derived 32-byte secret as a Go string. The seed material itself
// lives one level up as a [32]byte that callers can later wipe, even
// though the underlying driver still copies the resulting DSN into
// its own per-connection state — fully eliminating that copy would
// require a driver-side change.
//
// PRAGMA syntax pitfall: SQLCipher accepts `PRAGMA key = x'<hex>'` as
// a raw key (blob literal) and `PRAGMA key = "x'<hex>'"` as a
// passphrase that goes through PBKDF2 — the second form silently
// produces a different key and surfaces as "file is not a database"
// on subsequent opens. The _pragma_key URL parameter route used here
// passes the raw blob literal directly via the driver's open hook; do
// not switch to a string-quoted PRAGMA form without matching the
// derivation on the other side.
type cipherConnector struct {
	dsn       string
	deriveKey func() (string, error)
	enableWAL bool
}

func (c *cipherConnector) Connect(ctx context.Context) (driver.Conn, error) {
	hexKey, err := c.deriveKey()
	if err != nil {
		return nil, err
	}
	conn, err := cipherDriver.Open(c.dsn + "?_pragma_key=x'" + hexKey + "'")
	if err != nil {
		return nil, err
	}
	execer, ok := conn.(driver.ExecerContext)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("sqlite driver does not implement ExecerContext")
	}
	// Force the temp store to memory: by default SQLite may spill
	// query intermediates (sorts, joins, large GROUP BY) to plaintext
	// temp files in /tmp, defeating the encryption-at-rest guarantee.
	// PRAGMA temp_store = MEMORY (=2) overrides the build-time default
	// at runtime. This is best-effort — if the driver was compiled with
	// SQLITE_TEMP_STORE=0 (always file, runtime override forbidden) the
	// PRAGMA returns success and the value is silently ignored. The
	// upstream go-sqlcipher build does not enforce that mode, so the
	// runtime override holds for our deployment, but operators
	// rebuilding with custom flags should re-verify.
	if _, execErr := execer.ExecContext(ctx, "PRAGMA temp_store = MEMORY", nil); execErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set pragma temp_store: %w", execErr)
	}
	if c.enableWAL {
		if _, execErr := execer.ExecContext(ctx, "PRAGMA journal_mode = WAL", nil); execErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("set pragma journal_mode: %w", execErr)
		}
	}
	return conn, nil
}

func (c *cipherConnector) Driver() driver.Driver { return cipherDriver }

// Store is a SQLCipher-backed implementation of storage.Storage.
//
// One master database holds queue metadata (including the per-queue
// salt); each queue's messages live in their own encrypted file whose
// key is derived from the master seed, the queue id, and that salt.
// Deleting a queue's master row therefore crypto-shreds the queue: the
// file may persist on disk or in a backup, but without the salt the
// HKDF derivation cannot be reproduced.
//
// Threat model the crypto-shred property covers:
//
//   - File-only attacker (backup leak, filesystem snapshot, forensic
//     image): cannot recover deleted queues because the salt is gone
//     from the master row, and we PRAGMA wal_checkpoint(FULL) after
//     every DeleteQueue so nothing meaningful sits in master.db-wal.
//   - Cold seed leak: leaking only the master seed without any of the
//     storage files yields no plaintext.
//
// Threat model it does NOT cover:
//
//   - Live memory dump: master seed and active per-queue salts both
//     live in the process heap as Go values; an attacker with
//     /proc/<pid> access on a live process can still recover them.
//   - Operational metadata: directory shard count, file mtime/size,
//     and master.db-wal size leak coarse activity signals to anyone
//     with filesystem read access. Mitigate via encrypted block
//     storage and `mount -o noatime`; tracked operationally.
//   - WAL bytes between commit and checkpoint on per-queue files
//     (per-queue WAL is currently disabled, so this is a no-op today,
//     but flip the bit and the same caveat applies).
type Store struct {
	seed         MasterSeed
	dataDir      string
	masterDB     *sql.DB // writer pool, MaxOpenConns=1
	masterReadDB *sql.DB // reader pool, MaxOpenConns=N (WAL snapshot reads)
	pool         *queueDBPool
	// queueLocks serialises operations targeting the same queue.
	// DeleteQueue takes the write side (exclusive); concurrent
	// PutMessage / ListMessages / DeleteMessage on the same id share
	// the read side, so they can proceed in parallel without
	// contending on each other while still being mutually exclusive
	// with the destructor.
	queueLocks sync.Map // map[string]*sync.RWMutex
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
	masterPath := filepath.Join(abs, masterFilename)
	masterDB, err := openEncryptedDB(
		masterPath,
		seed.MasterKey,
		true,
		masterWriterMaxOpenConns,
	)
	if err != nil {
		return nil, fmt.Errorf("open master.db (writer): %w", err)
	}
	if _, schemaErr := masterDB.Exec(masterSchema); schemaErr != nil {
		_ = masterDB.Close()
		return nil, fmt.Errorf("init master schema: %w", schemaErr)
	}
	// Reader pool shares the file via WAL: the writer commits create
	// fresh snapshots; readers can run concurrently without blocking
	// each other or the writer.
	masterReadDB, err := openEncryptedDB(
		masterPath,
		seed.MasterKey,
		false, // WAL is already enabled by the writer; the file metadata persists
		masterReaderMaxOpenConns,
	)
	if err != nil {
		_ = masterDB.Close()
		return nil, fmt.Errorf("open master.db (reader): %w", err)
	}
	return &Store{
		seed:         seed,
		dataDir:      abs,
		masterDB:     masterDB,
		masterReadDB: masterReadDB,
		pool:         newQueueDBPool(queueDBCapacity),
	}, nil
}

// Close releases resources held by the store: it drains the per-queue
// pool first, then closes both master DB handles (reader and writer).
// The first close error is reported; subsequent ones are best-effort.
func (s *Store) Close() error {
	s.pool.Close()
	readErr := s.masterReadDB.Close()
	writeErr := s.masterDB.Close()
	if writeErr != nil {
		return writeErr
	}
	return readErr
}

const masterSchema = `
CREATE TABLE IF NOT EXISTS queues (
	id                 TEXT    NOT NULL,
	owner_x25519_pub   BLOB    NOT NULL,
	owner_ed25519_pub  BLOB    NOT NULL,
	key_salt           BLOB    NOT NULL,
	created_at         INTEGER NOT NULL,
	expires_at         INTEGER NOT NULL,
	last_access        INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS idx_queues_expires_at ON queues(expires_at);
`

const queueSchema = `
CREATE TABLE IF NOT EXISTS messages (
	id           TEXT    NOT NULL,
	blob         BLOB    NOT NULL,
	received_at  INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at);
`

// openEncryptedDB opens a SQLCipher database at path. The encryption
// key is produced lazily by deriveKey on every freshly opened pooled
// connection, so the derived hex bytes never live on a long-lived
// struct field. enableWAL is opt-in because per-queue files benefit
// less from WAL than the hot-path master DB does. maxOpenConns caps
// the underlying database/sql pool: master uses several to let WAL
// readers run concurrently; per-queue files stay at 1 because they
// are write-mostly.
//
// Backup note: with WAL enabled, a snapshot tool that copies only the
// main DB file without the matching -wal/-shm files will see a
// pre-checkpoint state. Crypto-shred via salt deletion still holds
// for any data that was committed at snapshot time, but uncommitted
// pages live in the -wal until checkpointed; backup pipelines must
// either include all three files or trigger PRAGMA wal_checkpoint
// before snapshotting.
func openEncryptedDB(path string, deriveKey func() (string, error), enableWAL bool, maxOpenConns int) (*sql.DB, error) {
	conn := &cipherConnector{
		dsn:       "file:" + path,
		deriveKey: deriveKey,
		enableWAL: enableWAL,
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(maxOpenConns)
	if pingErr := db.Ping(); pingErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", pingErr)
	}
	return db, nil
}

// queuePath returns the absolute filesystem path for the queue's
// encrypted database. The basename is HMAC(seed, queueID) so a
// directory listing does not enumerate live queue identifiers, and
// the file is placed in a two-hex-char shard (up to 256 sub-dirs)
// so a single readdir at the top level reveals only how many shards
// exist, not the queue count.
func (s *Store) queuePath(queueID string) string {
	name := s.seed.QueueFilename(queueID)
	return filepath.Join(s.dataDir, name[:2], name[2:]+queueFilenameSuffix)
}

// ensureQueueShard creates the per-queue shard sub-directory with the
// same 0700 permissions as the data dir.
func (s *Store) ensureQueueShard(queueID string) error {
	name := s.seed.QueueFilename(queueID)
	return os.MkdirAll(filepath.Join(s.dataDir, name[:2]), dataDirPerm)
}

// useQueueDB acquires the cached *sql.DB for queueID (opening it the
// first time) and runs fn against it. The acquired handle is released
// regardless of fn's outcome.
//
// The salt is copied into a fresh slice owned by this call's closures
// — the deriveKey closure re-uses it on every Connect (the SQL pool
// may open new connections after idle drops), and the onClose hook
// zeroes it once the entry is evicted from the cache. This caps the
// in-heap lifetime of the per-queue salt at "while the queue's DB is
// in cache" rather than "until process death", which materially
// shortens the window a memory-dump attacker has to recover it.
func (s *Store) useQueueDB(queueID string, salt []byte, fn func(*sql.DB) error) error {
	saltCopy := append([]byte(nil), salt...)
	db, release, err := s.pool.acquire(
		queueID,
		func() (*sql.DB, error) {
			qdb, err := openEncryptedDB(
				s.queuePath(queueID),
				func() (string, error) { return s.seed.DeriveQueueKey(queueID, saltCopy) },
				false,
				queueMaxOpenConns,
			)
			if err != nil {
				return nil, err
			}
			if _, schemaErr := qdb.Exec(queueSchema); schemaErr != nil {
				_ = qdb.Close()
				return nil, fmt.Errorf("init queue schema: %w", schemaErr)
			}
			return qdb, nil
		},
		func() {
			for i := range saltCopy {
				saltCopy[i] = 0
			}
		},
	)
	if err != nil {
		return err
	}
	defer release()
	return fn(db)
}

// CreateQueue inserts a new queue row and creates its per-queue database
// file. A fresh per-queue salt is generated and persisted alongside the
// metadata; the salt is the load-bearing secret for the crypto-shred
// property when the queue is later deleted.
func (s *Store) CreateQueue(ctx context.Context, keys queue.OwnerKeys) (*queue.Queue, error) {
	if err := queue.ValidateOwnerKeys(keys); err != nil {
		return nil, err
	}
	id, err := queue.NewID()
	if err != nil {
		return nil, err
	}
	salt := make([]byte, QueueKeySaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate queue salt: %w", err)
	}

	// Defence in depth against the (cryptographically infeasible) event
	// of an HMAC-derived filename colliding with an existing file: if
	// the path already exists, refuse rather than silently overwrite a
	// foreign queue's data.
	if err := s.ensureQueueShard(id); err != nil {
		return nil, fmt.Errorf("create queue shard: %w", err)
	}
	if _, statErr := os.Stat(s.queuePath(id)); statErr == nil {
		return nil, fmt.Errorf("queue file already exists at derived path: %w", os.ErrExist)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("stat queue path: %w", statErr)
	}

	now := time.Now().UTC()
	expires := now.Add(queue.DefaultTTL)

	if _, execErr := s.masterDB.ExecContext(ctx,
		`INSERT INTO queues(id, owner_x25519_pub, owner_ed25519_pub, key_salt, created_at, expires_at, last_access) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, keys.X25519Pub, keys.Ed25519Pub, salt, now.UnixNano(), expires.UnixNano(), now.UnixNano(),
	); execErr != nil {
		return nil, fmt.Errorf("insert queue: %w", execErr)
	}

	if err := s.useQueueDB(id, salt, func(_ *sql.DB) error { return nil }); err != nil {
		s.rollbackCreate(ctx, id)
		return nil, fmt.Errorf("init queue db: %w", err)
	}

	return &queue.Queue{
		ID:              id,
		OwnerX25519Pub:  append([]byte(nil), keys.X25519Pub...),
		OwnerEd25519Pub: append([]byte(nil), keys.Ed25519Pub...),
		CreatedAt:       now,
		ExpiresAt:       expires,
		LastAccess:      now,
	}, nil
}

// queueLock returns the per-queue RWMutex, creating it on first
// access. PutMessage / ListMessages / DeleteMessage take RLock so
// they can run concurrently against the same queue (SQLite's own
// single-connection writer is the actual serialiser at the SQL
// layer); DeleteQueue takes the write Lock so it can never
// interleave with an in-flight per-queue operation.
func (s *Store) queueLock(queueID string) *sync.RWMutex {
	if existing, ok := s.queueLocks.Load(queueID); ok {
		return existing.(*sync.RWMutex)
	}
	created := &sync.RWMutex{}
	actual, _ := s.queueLocks.LoadOrStore(queueID, created)
	return actual.(*sync.RWMutex)
}

// rollbackCreate cleans up after a CreateQueue failure that left the
// master row in place: it deletes the row, removes the (possibly
// partially-initialised) queue file, and forces a WAL checkpoint so
// the salt does not survive in master.db-wal. Failures here are
// logged at slog.Default() level — they leave operator-visible
// orphan state but cannot abort the original error path.
func (s *Store) rollbackCreate(ctx context.Context, id string) {
	if _, delErr := s.masterDB.ExecContext(ctx, `DELETE FROM queues WHERE id = ?`, id); delErr != nil {
		slog.Default().Warn("CreateQueue rollback delete failed", "err", delErr.Error())
	}
	if remErr := os.Remove(s.queuePath(id)); remErr != nil && !errors.Is(remErr, os.ErrNotExist) {
		slog.Default().Warn("CreateQueue rollback remove failed", "err", remErr.Error())
	}
	if _, checkErr := s.masterDB.ExecContext(ctx, "PRAGMA wal_checkpoint(FULL)"); checkErr != nil {
		slog.Default().Warn("CreateQueue rollback wal_checkpoint failed", "err", checkErr.Error())
	}
}

// GetQueue returns queue metadata or queue.ErrQueueNotFound.
func (s *Store) GetQueue(ctx context.Context, id string) (*queue.Queue, error) {
	q, _, err := s.getQueueWithSalt(ctx, id)
	return q, err
}

// getQueueWithSalt returns the queue metadata together with the per-queue
// salt the caller needs to open the encrypted file. Reads go through the
// reader pool so concurrent GetQueue calls don't serialise on the writer.
func (s *Store) getQueueWithSalt(ctx context.Context, id string) (*queue.Queue, []byte, error) {
	var (
		q                                queue.Queue
		salt                             []byte
		createdNs, expiresNs, lastAccess int64
	)
	row := s.masterReadDB.QueryRowContext(ctx,
		`SELECT id, owner_x25519_pub, owner_ed25519_pub, key_salt, created_at, expires_at, last_access FROM queues WHERE id = ?`, id,
	)
	if err := row.Scan(&q.ID, &q.OwnerX25519Pub, &q.OwnerEd25519Pub, &salt, &createdNs, &expiresNs, &lastAccess); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, queue.ErrQueueNotFound
		}
		return nil, nil, err
	}
	q.CreatedAt = time.Unix(0, createdNs).UTC()
	q.ExpiresAt = time.Unix(0, expiresNs).UTC()
	q.LastAccess = time.Unix(0, lastAccess).UTC()
	return &q, salt, nil
}

// PutMessage appends an opaque blob to the queue.
func (s *Store) PutMessage(ctx context.Context, queueID string, blob []byte) (*queue.Message, error) {
	switch {
	case len(blob) == 0:
		return nil, queue.ErrEmptyBlob
	case len(blob) > queue.MaxBlobSize:
		return nil, queue.ErrBlobTooLarge
	}

	lk := s.queueLock(queueID)
	lk.RLock()
	defer lk.RUnlock()

	_, salt, err := s.getQueueWithSalt(ctx, queueID)
	if err != nil {
		return nil, err
	}

	msgID, err := queue.NewMessageID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()

	useErr := s.useQueueDB(queueID, salt, func(qdb *sql.DB) error {
		_, execErr := qdb.ExecContext(ctx,
			`INSERT INTO messages(id, blob, received_at) VALUES (?, ?, ?)`,
			msgID, blob, now.UnixNano(),
		)
		if execErr != nil {
			return fmt.Errorf("insert message: %w", execErr)
		}
		return nil
	})
	if useErr != nil {
		return nil, useErr
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

	lk := s.queueLock(queueID)
	lk.RLock()
	defer lk.RUnlock()

	_, salt, err := s.getQueueWithSalt(ctx, queueID)
	if err != nil {
		return nil, false, err
	}

	var (
		msgs    []*queue.Message
		hasMore bool
	)
	useErr := s.useQueueDB(queueID, salt, func(qdb *sql.DB) error {
		rows, queryErr := qdb.QueryContext(ctx,
			`SELECT id, blob, received_at FROM messages ORDER BY received_at ASC LIMIT ?`, limit+1,
		)
		if queryErr != nil {
			return queryErr
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var (
				m          queue.Message
				receivedNs int64
			)
			if scanErr := rows.Scan(&m.ID, &m.Blob, &receivedNs); scanErr != nil {
				return scanErr
			}
			m.QueueID = queueID
			m.ReceivedAt = time.Unix(0, receivedNs).UTC()
			msgs = append(msgs, &m)
		}
		return rows.Err()
	})
	if useErr != nil {
		return nil, false, useErr
	}
	if len(msgs) > limit {
		msgs = msgs[:limit]
		hasMore = true
	}
	if err := s.touchQueue(ctx, queueID, time.Now().UTC()); err != nil {
		return nil, false, err
	}
	return msgs, hasMore, nil
}

// DeleteMessage removes a single message from the queue.
func (s *Store) DeleteMessage(ctx context.Context, queueID, messageID string) error {
	lk := s.queueLock(queueID)
	lk.RLock()
	defer lk.RUnlock()

	_, salt, err := s.getQueueWithSalt(ctx, queueID)
	if err != nil {
		return err
	}

	var affected int64
	useErr := s.useQueueDB(queueID, salt, func(qdb *sql.DB) error {
		res, execErr := qdb.ExecContext(ctx, `DELETE FROM messages WHERE id = ?`, messageID)
		if execErr != nil {
			return execErr
		}
		var rowsErr error
		affected, rowsErr = res.RowsAffected()
		return rowsErr
	})
	if useErr != nil {
		return useErr
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
// Read-only — uses the reader pool so the periodic cleanup tick does not
// contend with in-flight writes on the master DB.
func (s *Store) ExpiredQueueIDs(ctx context.Context, t time.Time) ([]string, error) {
	rows, err := s.masterReadDB.QueryContext(ctx,
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

// DeleteQueue removes a queue's database file first, then the metadata
// row, then forces a WAL checkpoint so the row's salt cannot survive
// in master.db-wal beyond the call.
//
// Removing the file before the row means a partial failure leaves the
// master row pointing at a missing file — subsequent operations surface
// that as ErrQueueNotFound, which is the appropriate semantic (the
// queue has effectively been destroyed). Deleting the row first would
// risk leaving an orphan file with recoverable content; with
// crypto-shred the salt also vanishes when the row goes, but the file
// itself should not survive a successful delete.
//
// The wal_checkpoint(FULL) call is the load-bearing piece for the
// crypto-shred guarantee against backup-style adversaries. Without it,
// a snapshot taken between DELETE and the next autocheckpoint (default
// 1000 pages, which a small master.db rarely hits) would still see the
// salt in the WAL and could decrypt the file.
func (s *Store) DeleteQueue(ctx context.Context, id string) error {
	lk := s.queueLock(id)
	lk.Lock()
	defer lk.Unlock()

	// Drop any cached handle so the OS can actually unlink the file.
	s.pool.drop(id)

	if removeErr := os.Remove(s.queuePath(id)); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return fmt.Errorf("remove queue db file: %w", removeErr)
	}

	res, err := s.masterDB.ExecContext(ctx, `DELETE FROM queues WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return queue.ErrQueueNotFound
	}

	// Crypto-shred completion: force the salt out of the WAL.
	if _, checkErr := s.masterDB.ExecContext(ctx, "PRAGMA wal_checkpoint(FULL)"); checkErr != nil {
		slog.Default().Warn("DeleteQueue wal_checkpoint failed", "err", checkErr.Error())
	}

	// Drop the per-queue mutex from the map so a long-running server
	// does not accumulate one entry per ever-deleted queue. A goroutine
	// still holding a pointer to the now-orphan mutex finishes safely;
	// any future call for the same id allocates a fresh one.
	s.queueLocks.Delete(id)
	return nil
}
