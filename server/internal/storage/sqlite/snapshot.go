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
)

// Snapshot writes a self-consistent backup of all encrypted databases
// to dst. The destination directory is created with the same 0700
// permissions as the live data directory. Existing snapshot files at
// the target paths are overwritten.
//
// Layout mirrors the live data directory: <dst>/master.db plus
// <dst>/<shard>/<hash>.db for each queue. The snapshot files retain
// the original SQLCipher encryption — opening them requires the same
// master seed and per-queue salts as the source.
//
// The snapshot is taken online: writers continue to make progress
// against the source. Each queue file is captured under the read side
// of the per-queue lock, which is concurrent with PutMessage,
// ListMessages and DeleteMessage and only blocks DeleteQueue. Master
// is captured first; the queue set is then enumerated from live
// master and each shard captured one at a time. A queue created
// between master capture and enumeration is included; a queue created
// after enumeration is omitted from this snapshot — both cases are
// safe under the disaster-recovery use case.
func (s *Store) Snapshot(ctx context.Context, dst string) error {
	if err := os.MkdirAll(dst, dataDirPerm); err != nil {
		return fmt.Errorf("create snapshot dir: %w", err)
	}

	if err := s.snapshotMaster(ctx, dst); err != nil {
		return err
	}

	queues, err := s.listQueueRefs(ctx)
	if err != nil {
		return err
	}

	for _, q := range queues {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err := s.snapshotQueue(ctx, q.id, q.salt, dst); err != nil {
			return fmt.Errorf("snapshot queue %s: %w", q.id, err)
		}
	}
	return nil
}

func (s *Store) snapshotMaster(ctx context.Context, dst string) error {
	dstPath := filepath.Join(dst, masterFilename)
	if err := os.Remove(dstPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear stale master snapshot: %w", err)
	}
	if _, err := s.masterDB.ExecContext(ctx, `VACUUM INTO ?`, dstPath); err != nil {
		return fmt.Errorf("vacuum master: %w", err)
	}
	return nil
}

type queueRef struct {
	id   string
	salt []byte
}

func (s *Store) listQueueRefs(ctx context.Context) ([]queueRef, error) {
	rows, err := s.masterReadDB.QueryContext(ctx, `SELECT id, key_salt FROM queues`)
	if err != nil {
		return nil, fmt.Errorf("list queues: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var queues []queueRef
	for rows.Next() {
		var q queueRef
		if scanErr := rows.Scan(&q.id, &q.salt); scanErr != nil {
			return nil, fmt.Errorf("scan queue row: %w", scanErr)
		}
		queues = append(queues, q)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, rowsErr
	}
	return queues, nil
}

func (s *Store) snapshotQueue(ctx context.Context, id string, salt []byte, dst string) error {
	lk := s.queueLock(id)
	lk.RLock()
	defer lk.RUnlock()

	name := s.seed.QueueFilename(id)
	shardDir := filepath.Join(dst, name[:2])
	if err := os.MkdirAll(shardDir, dataDirPerm); err != nil {
		return fmt.Errorf("create snapshot shard: %w", err)
	}
	snapPath := filepath.Join(shardDir, name[2:]+queueFilenameSuffix)
	if err := os.Remove(snapPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear stale queue snapshot: %w", err)
	}
	return s.useQueueDB(id, salt, func(db *sql.DB) error {
		_, execErr := db.ExecContext(ctx, `VACUUM INTO ?`, snapPath)
		return execErr
	})
}
