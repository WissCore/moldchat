// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sqlitestore is the SQLCipher-backed implementation of
// anonauth.PseudonymStore. The pseudonym database lives in its own
// encrypted file with a key derived from the deployment's master seed
// via a dedicated HKDF info string, so the queue-storage seed and
// this file's seed never share derivation paths even when they share
// the same underlying secret.
package sqlitestore

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/WissCore/moldchat/server/internal/anonauth"
	sqlcipher "github.com/mutecomm/go-sqlcipher/v4"
	"golang.org/x/crypto/hkdf"
)

const (
	dbFilename       = "pseudonyms.db"
	dataDirPerm      = 0o700
	maxOpenConns     = 1 // SQLite serialises writers; one conn avoids SQLITE_BUSY
	pseudonymKeyInfo = "moldd-anonauth-pseudonym-db-key-v1"
	masterSeedBytes  = 32
)

// cipherDriver is the package-shared SQLCipher driver instance, kept
// at package scope so its one-time initialisation (loadable
// extensions, etc.) does not run per Connect.
var cipherDriver = &sqlcipher.SQLiteDriver{}

// cipherConnector mirrors the queue-store cipherConnector pattern
// closely on purpose: same key derivation discipline (compute the
// hex key inside Connect, never store it on the struct), same
// PRAGMA temp_store hardening, same WAL toggle.
type cipherConnector struct {
	dsn       string
	deriveKey func() (string, error)
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
	if _, execErr := execer.ExecContext(ctx, "PRAGMA temp_store = MEMORY", nil); execErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set pragma temp_store: %w", execErr)
	}
	if _, execErr := execer.ExecContext(ctx, "PRAGMA journal_mode = WAL", nil); execErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set pragma journal_mode: %w", execErr)
	}
	return conn, nil
}

func (c *cipherConnector) Driver() driver.Driver { return cipherDriver }

// Store is the SQLCipher-backed pseudonym store.
type Store struct {
	db   *sql.DB
	mu   sync.Mutex // serialises CheckAndIncrement updates against the same row
	seed [masterSeedBytes]byte
}

// New opens (or creates) the pseudonym database under dataDir. dataDir
// is created with 0700 permissions if it does not exist; the database
// file is encrypted with a key derived from seed via the package's
// dedicated HKDF info string.
func New(seed [masterSeedBytes]byte, dataDir string) (*Store, error) {
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve dataDir: %w", err)
	}
	if mkdirErr := os.MkdirAll(abs, dataDirPerm); mkdirErr != nil {
		return nil, fmt.Errorf("create dataDir: %w", mkdirErr)
	}
	dbPath := filepath.Join(abs, dbFilename)
	conn := &cipherConnector{
		dsn: "file:" + dbPath,
		deriveKey: func() (string, error) {
			return deriveHexKey(seed[:])
		},
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(maxOpenConns)
	if pingErr := db.Ping(); pingErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", pingErr)
	}
	if _, schemaErr := db.Exec(schema); schemaErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", schemaErr)
	}
	return &Store{db: db, seed: seed}, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

const schema = `
CREATE TABLE IF NOT EXISTS pseudonyms (
	pubkey            BLOB    NOT NULL,
	created_at        INTEGER NOT NULL,
	expires_at        INTEGER NOT NULL,
	last_epoch        INTEGER NOT NULL DEFAULT 0,
	tokens_in_epoch   INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (pubkey)
);
CREATE INDEX IF NOT EXISTS idx_pseudonyms_expires_at ON pseudonyms(expires_at);
`

// Register persists a pseudonym record. Returns
// anonauth.ErrPseudonymExists if the pubkey is already registered.
func (s *Store) Register(ctx context.Context, pub ed25519.PublicKey, created, expires time.Time) error {
	if len(pub) != ed25519.PublicKeySize {
		return anonauth.ErrPseudonymInvalid
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO pseudonyms(pubkey, created_at, expires_at, last_epoch, tokens_in_epoch) VALUES (?, ?, ?, 0, 0)`,
		[]byte(pub), created.UnixNano(), expires.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("insert pseudonym: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return anonauth.ErrPseudonymExists
	}
	return nil
}

// CheckAndIncrement runs the per-epoch counter logic atomically. The
// SELECT-then-UPDATE happens inside a transaction; the package mutex
// guards against the SQLITE_BUSY-free race between two writers
// reaching the same row at the same instant.
//
// The sequence:
//
//  1. SELECT the current row inside a transaction.
//  2. If expires_at <= now, abort with ErrPseudonymExpired.
//  3. If last_epoch != epoch, the row's counter is stale and we
//     treat the current value as 0. Otherwise we use it as is.
//  4. If the (possibly reset) counter is already at the limit, abort
//     with ErrRateLimited.
//  5. UPDATE the row to the new (epoch, counter+1) and commit.
func (s *Store) CheckAndIncrement(ctx context.Context, pub ed25519.PublicKey, epoch int64, limit uint32, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize {
		return anonauth.ErrPseudonymInvalid
	}
	if epoch < 0 {
		return fmt.Errorf("anonauth/sqlitestore: negative epoch %d", epoch)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		expiresNs int64
		lastEpoch int64
		tokensCur int64
	)
	row := tx.QueryRowContext(ctx,
		`SELECT expires_at, last_epoch, tokens_in_epoch FROM pseudonyms WHERE pubkey = ?`,
		[]byte(pub),
	)
	if scanErr := row.Scan(&expiresNs, &lastEpoch, &tokensCur); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return anonauth.ErrPseudonymInvalid
		}
		return fmt.Errorf("select pseudonym: %w", scanErr)
	}
	if expiresNs <= now.UnixNano() {
		return anonauth.ErrPseudonymExpired
	}
	if lastEpoch < 0 || tokensCur < 0 {
		return fmt.Errorf("pseudonym counter out of range: epoch=%d tokens=%d", lastEpoch, tokensCur)
	}

	current := tokensCur
	if lastEpoch != epoch {
		current = 0
	}
	if current >= int64(limit) {
		return anonauth.ErrRateLimited
	}
	if _, execErr := tx.ExecContext(ctx,
		`UPDATE pseudonyms SET last_epoch = ?, tokens_in_epoch = ? WHERE pubkey = ?`,
		epoch, current+1, []byte(pub),
	); execErr != nil {
		return fmt.Errorf("update counter: %w", execErr)
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return fmt.Errorf("commit: %w", commitErr)
	}
	return nil
}

// DeleteExpired removes records whose expiry is at or before before.
func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM pseudonyms WHERE expires_at <= ?`, before.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("delete expired: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(affected), nil
}

// deriveHexKey runs HKDF-SHA-256 over the seed and the package's
// dedicated info string and returns the resulting 32 bytes hex-
// encoded, ready to drop into the SQLCipher PRAGMA key.
func deriveHexKey(seed []byte) (string, error) {
	r := hkdf.New(sha256.New, seed, nil, []byte(pseudonymKeyInfo))
	out := make([]byte, masterSeedBytes)
	if _, err := io.ReadFull(r, out); err != nil {
		return "", fmt.Errorf("hkdf read: %w", err)
	}
	return hex.EncodeToString(out), nil
}

var _ anonauth.PseudonymStore = (*Store)(nil)
