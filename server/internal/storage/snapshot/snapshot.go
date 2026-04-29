// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package snapshot runs periodic online backups of a Snapshotter to a
// destination directory. The snapshot files are intended to be picked up
// out-of-band by an offline backup tool (e.g. restic) and shipped to
// remote storage; this package does not talk to S3 itself.
package snapshot

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Snapshotter is the subset of the storage interface required for online
// backup. A storage backend that supports point-in-time consistent
// snapshots implements this interface.
type Snapshotter interface {
	Snapshot(ctx context.Context, dst string) error
}

// Runner periodically asks a Snapshotter to write a snapshot to Dst.
type Runner struct {
	Snapshotter Snapshotter
	Dst         string
	Interval    time.Duration
	Logger      *slog.Logger
}

// Run blocks until ctx is cancelled, calling Tick on every Interval. A
// non-positive Interval makes Run a no-op so callers can wire the runner
// in unconditionally and gate it via configuration.
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
			// Tick logs its own errors; the run loop continues on
			// every outcome so a transient failure does not stop
			// future ticks.
			_ = r.Tick(ctx)
		}
	}
}

// Tick performs one snapshot pass. Errors from the Snapshotter are logged
// but do not stop the runner; transient failures (locked database, disk
// full) should resolve on the next tick. Context cancellation is
// propagated without an error log because it is the expected shutdown
// signal.
func (r *Runner) Tick(ctx context.Context) error {
	err := r.Snapshotter.Snapshot(ctx, r.Dst)
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if r.Logger != nil {
		r.Logger.LogAttrs(ctx, slog.LevelError, "snapshot tick failed",
			slog.String("err", err.Error()),
			slog.String("dst", r.Dst),
		)
	}
	return err
}
