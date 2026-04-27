// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cleanup runs periodic deletion of expired queues from a Cleaner.
package cleanup

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/WissCore/moldchat/server/internal/queue"
)

// Cleaner is the subset of the storage interface required for TTL cleanup.
// A storage backend that supports TTL-based eviction implements this interface.
type Cleaner interface {
	ExpiredQueueIDs(ctx context.Context, before time.Time) ([]string, error)
	DeleteQueue(ctx context.Context, id string) error
}

// Runner periodically asks a Cleaner to drop expired queues.
type Runner struct {
	Cleaner  Cleaner
	Interval time.Duration
	Logger   *slog.Logger
	// Now returns the current time; tests inject a fake clock.
	Now func() time.Time
}

// Run blocks until ctx is cancelled, calling Tick at every Interval.
func (r *Runner) Run(ctx context.Context) {
	if r.Interval <= 0 {
		return
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Tick(ctx)
		}
	}
}

// Tick performs one cleanup pass and returns the number of queues deleted.
//
// Errors from the Cleaner are logged but do not stop the runner; transient
// failures (locked database, disk full) should resolve on the next tick.
func (r *Runner) Tick(ctx context.Context) int {
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now()
	}
	ids, err := r.Cleaner.ExpiredQueueIDs(ctx, now)
	if err != nil {
		r.log(ctx, slog.LevelError, "list expired queues", "err", err.Error())
		return 0
	}
	deleted := 0
	for _, id := range ids {
		if err := r.Cleaner.DeleteQueue(ctx, id); err != nil {
			if errors.Is(err, queue.ErrQueueNotFound) {
				continue
			}
			r.log(ctx, slog.LevelError, "delete expired queue", "err", err.Error())
			continue
		}
		deleted++
	}
	if deleted > 0 {
		r.log(ctx, slog.LevelInfo, "cleanup tick complete", "deleted", deleted)
	}
	return deleted
}

func (r *Runner) log(ctx context.Context, level slog.Level, msg string, attrs ...any) {
	if r.Logger == nil {
		return
	}
	r.Logger.LogAttrs(ctx, level, msg, sliceToAttrs(attrs)...)
}

// sliceToAttrs adapts a flat key-value slice to []slog.Attr for LogAttrs.
func sliceToAttrs(kv []any) []slog.Attr {
	if len(kv)%2 != 0 {
		return nil
	}
	out := make([]slog.Attr, 0, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			continue
		}
		out = append(out, slog.Any(key, kv[i+1]))
	}
	return out
}
