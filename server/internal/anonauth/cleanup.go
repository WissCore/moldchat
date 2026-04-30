// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// CleanupRunner periodically asks a PseudonymStore to drop expired
// pseudonyms. It mirrors the storage-layer cleanup runner pattern so
// operator-facing behaviour (interval, error handling, log shape) is
// uniform across the binary.
type CleanupRunner struct {
	Store    PseudonymStore
	Interval time.Duration
	Logger   *slog.Logger
}

// Run blocks until ctx is cancelled, calling Tick on every Interval.
// A non-positive Interval makes Run a no-op so callers can wire the
// runner in unconditionally and gate it via configuration.
func (r *CleanupRunner) Run(ctx context.Context) {
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

// Tick performs one cleanup pass and returns the number of records
// deleted. Errors are logged but do not stop the runner; transient
// failures (locked database, disk full) should resolve on the next
// tick.
func (r *CleanupRunner) Tick(ctx context.Context) int {
	deleted, err := r.Store.DeleteExpired(ctx, time.Now().UTC())
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return 0
		}
		if r.Logger != nil {
			r.Logger.LogAttrs(ctx, slog.LevelError, "anonauth cleanup tick failed",
				slog.String("err", err.Error()),
			)
		}
		return 0
	}
	if deleted > 0 && r.Logger != nil {
		r.Logger.LogAttrs(ctx, slog.LevelInfo, "anonauth cleanup tick complete",
			slog.Int("deleted", deleted),
		)
	}
	return deleted
}
