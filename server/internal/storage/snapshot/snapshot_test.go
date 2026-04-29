// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package snapshot_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/storage/snapshot"
)

type fakeSnapshotter struct {
	calls atomic.Int64
	err   error
	delay time.Duration
}

func (f *fakeSnapshotter) Snapshot(ctx context.Context, _ string) error {
	f.calls.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return f.err
}

func TestTick_SuccessReturnsNil(t *testing.T) {
	t.Parallel()
	s := &fakeSnapshotter{}
	r := &snapshot.Runner{Snapshotter: s, Dst: "/tmp/x"}
	if err := r.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got := s.calls.Load(); got != 1 {
		t.Errorf("calls = %d, want 1", got)
	}
}

func TestTick_PropagatesError(t *testing.T) {
	t.Parallel()
	want := errors.New("disk full")
	s := &fakeSnapshotter{err: want}
	r := &snapshot.Runner{Snapshotter: s, Dst: "/tmp/x"}
	if err := r.Tick(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Tick = %v, want %v", err, want)
	}
}

func TestTick_DoesNotLogContextCancel(t *testing.T) {
	t.Parallel()
	s := &fakeSnapshotter{err: context.Canceled}
	r := &snapshot.Runner{Snapshotter: s, Dst: "/tmp/x"}
	if err := r.Tick(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Tick = %v, want context.Canceled", err)
	}
}

func TestRun_NoIntervalIsNoop(t *testing.T) {
	t.Parallel()
	s := &fakeSnapshotter{}
	r := &snapshot.Runner{Snapshotter: s, Dst: "/tmp/x", Interval: 0}
	r.Run(context.Background())
	if got := s.calls.Load(); got != 0 {
		t.Errorf("calls = %d, want 0", got)
	}
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	t.Parallel()
	s := &fakeSnapshotter{}
	r := &snapshot.Runner{Snapshotter: s, Dst: "/tmp/x", Interval: 5 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not exit within 1s of cancel")
	}
	if got := s.calls.Load(); got == 0 {
		t.Errorf("calls = 0, expected at least one tick before cancel")
	}
}
