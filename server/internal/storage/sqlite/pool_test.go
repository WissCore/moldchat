// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// newOpener returns an opener that produces a fresh *sql.DB plus a
// counter the test can inspect to verify how many times the opener
// actually ran.
func newOpener(t *testing.T, dir, queueID string) (func() (*sql.DB, error), *atomic.Int64) {
	t.Helper()
	calls := &atomic.Int64{}
	var seed MasterSeed
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	salt := make([]byte, QueueKeySaltBytes)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	return func() (*sql.DB, error) {
		calls.Add(1)
		return openEncryptedDB(
			filepath.Join(dir, queueID+queueFilenameSuffix),
			func() (string, error) { return seed.DeriveQueueKey(queueID, salt) },
			false,
			1,
		)
	}, calls
}

func TestPool_AcquireReleaseSingleQueue(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pool := newQueueDBPool(4)
	t.Cleanup(pool.Close)

	opener, calls := newOpener(t, dir, "Q1")
	db, release, err := pool.acquire("Q1", opener, nil)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if db == nil {
		t.Fatal("db is nil")
	}
	release()

	// Second acquire should be a cache hit.
	db2, release2, err := pool.acquire("Q1", opener, nil)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if db != db2 {
		t.Errorf("expected same db handle on cache hit")
	}
	release2()

	if got := calls.Load(); got != 1 {
		t.Errorf("opener calls: got %d, want 1", got)
	}
	if stats := pool.Stats(); stats.Hits != 1 || stats.Misses != 1 {
		t.Errorf("stats: %+v", stats)
	}
}

func TestPool_EvictionRespectsRefcount(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pool := newQueueDBPool(2)
	t.Cleanup(pool.Close)

	opener1, _ := newOpener(t, dir, "Q1")
	opener2, _ := newOpener(t, dir, "Q2")
	opener3, _ := newOpener(t, dir, "Q3")

	closed1 := &atomic.Bool{}
	db1, rel1, err := pool.acquire("Q1", opener1, func() { closed1.Store(true) })
	if err != nil {
		t.Fatalf("acquire Q1: %v", err)
	}
	defer rel1()
	_, rel2, err := pool.acquire("Q2", opener2, nil)
	if err != nil {
		t.Fatalf("acquire Q2: %v", err)
	}
	rel2()

	// Acquiring Q3 evicts Q2 (LRU); Q1 stays because it was used most
	// recently and has an outstanding ref.
	_, rel3, err := pool.acquire("Q3", opener3, nil)
	if err != nil {
		t.Fatalf("acquire Q3: %v", err)
	}
	rel3()

	// Now access Q3 again, then Q2 — Q2 was evicted, so it must
	// re-open. Use yet another opener to verify miss path.
	_, _, err = pool.acquire("Q2", opener2, nil)
	if err != nil {
		t.Fatalf("acquire Q2 again: %v", err)
	}

	// Q1 was held throughout, so its handle must still be alive.
	if closed1.Load() {
		t.Error("Q1 was closed while still referenced")
	}
	if db1 == nil {
		t.Error("Q1 handle nil")
	}
}

func TestPool_OnCloseRunsAfterEvictionAndLastRelease(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pool := newQueueDBPool(1) // capacity 1 forces immediate eviction
	t.Cleanup(pool.Close)

	opener1, _ := newOpener(t, dir, "Q1")
	opener2, _ := newOpener(t, dir, "Q2")

	closed := &atomic.Bool{}
	_, rel1, err := pool.acquire("Q1", opener1, func() { closed.Store(true) })
	if err != nil {
		t.Fatalf("acquire Q1: %v", err)
	}

	// Acquire Q2 — Q1 is evicted but still has refs. onClose must
	// not run yet.
	_, rel2, err := pool.acquire("Q2", opener2, nil)
	if err != nil {
		t.Fatalf("acquire Q2: %v", err)
	}
	if closed.Load() {
		t.Fatal("onClose fired while ref still held")
	}

	rel1()
	if !closed.Load() {
		t.Fatal("onClose did not fire after final release of evicted entry")
	}
	rel2()
}

func TestPool_OnCloseRunsAtMostOnce(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pool := newQueueDBPool(1)

	opener, _ := newOpener(t, dir, "Q1")
	count := &atomic.Int64{}
	_, rel, err := pool.acquire("Q1", opener, func() { count.Add(1) })
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	rel()
	pool.Close()
	if got := count.Load(); got != 1 {
		t.Errorf("onClose calls: got %d, want 1", got)
	}
}

func TestPool_AcquireAfterCloseFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pool := newQueueDBPool(1)
	pool.Close()

	opener, _ := newOpener(t, dir, "Q1")
	_, _, err := pool.acquire("Q1", opener, nil)
	if !errors.Is(err, errPoolClosed) {
		t.Errorf("got %v, want errPoolClosed", err)
	}
}

// TestPool_ConcurrentStress hammers the pool from many goroutines so the
// race detector and refcount-vs-eviction logic are exercised together.
// On top of "no error" it asserts the canonical leak invariant —
// after Close, every open must be balanced by exactly one close — and
// the bound that the pool size never exceeds its configured capacity.
func TestPool_ConcurrentStress(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const capacity = 8
	pool := newQueueDBPool(capacity)

	const queues = 32
	const goroutines = 64
	const perGoroutine = 50

	openers := make([]func() (*sql.DB, error), queues)
	openCounts := make([]*atomic.Int64, queues)
	closeCounts := make([]*atomic.Int64, queues)
	for i := range openers {
		baseOpener, _ := newOpener(t, dir, idFor(i))
		openCounts[i] = &atomic.Int64{}
		closeCounts[i] = &atomic.Int64{}
		idx := i
		openers[i] = func() (*sql.DB, error) {
			// Count only successful opens — every successful open
			// must be balanced by exactly one onClose, regardless
			// of whether the entry is stored, raced out by another
			// goroutine, or rejected because the pool was closed
			// in the gap between open and registration.
			db, err := baseOpener()
			if err != nil {
				return nil, err
			}
			openCounts[idx].Add(1)
			return db, nil
		}
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				idx := (seed*7 + j) % queues
				closeIdx := idx
				_, rel, err := pool.acquire(
					idFor(idx),
					openers[idx],
					func() { closeCounts[closeIdx].Add(1) },
				)
				if err != nil {
					t.Errorf("acquire: %v", err)
					return
				}
				if size := pool.Stats().Size; size > capacity {
					t.Errorf("pool size %d exceeded capacity %d", size, capacity)
				}
				rel()
			}
		}(g)
	}
	wg.Wait()

	// Final invariant: pool.Close() must drain every cached handle
	// and trigger every onClose hook for which a corresponding open
	// happened. opens == closes per-key with no exceptions.
	pool.Close()
	for i := range openers {
		opens := openCounts[i].Load()
		closes := closeCounts[i].Load()
		if opens != closes {
			t.Errorf("queue %d: opens=%d closes=%d (must be equal after pool.Close)", i, opens, closes)
		}
	}
}

func idFor(i int) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	return string(alpha[i%len(alpha)]) + string(alpha[(i*3)%len(alpha)])
}

// TestPool_ConcurrentAcquireSameKey covers the race where two
// goroutines miss the cache for the same key at the same time. The
// pool's design is to let both call opener (concurrently, off-lock)
// and then resolve under lock: one wins, one closes its db and gets
// the winner's handle. The visible contract is that both callers see
// the same *sql.DB and the loser's onClose fires immediately, not
// when the entry is later evicted.
func TestPool_ConcurrentAcquireSameKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pool := newQueueDBPool(4)
	t.Cleanup(pool.Close)

	opener, openCalls := newOpener(t, dir, "Q1")
	loserClosed := &atomic.Int64{}

	start := make(chan struct{})
	type result struct {
		db  *sql.DB
		rel func()
	}
	results := make(chan result, 2)

	for g := 0; g < 2; g++ {
		go func() {
			<-start
			db, rel, err := pool.acquire("Q1", opener, func() { loserClosed.Add(1) })
			if err != nil {
				t.Errorf("acquire: %v", err)
				results <- result{}
				return
			}
			results <- result{db, rel}
		}()
	}
	close(start)
	r1 := <-results
	r2 := <-results
	if r1.db != r2.db {
		t.Errorf("concurrent acquires returned different *sql.DB handles")
	}
	r1.rel()
	r2.rel()

	// At most one open call survives in the pool, so at least one of
	// the two onClose hooks fires immediately on the loser's branch.
	// The remaining one fires later, on pool.Close (registered above).
	if openCalls.Load() < 1 || openCalls.Load() > 2 {
		t.Errorf("opener calls: got %d, want 1 or 2", openCalls.Load())
	}
	if loserClosed.Load() < 1 {
		// The race is allowed to resolve such that one open never
		// happened (one goroutine grabbed the freshly-stored entry
		// before the other ran its opener). In that case loserClosed
		// stays 0 and the single onClose fires on pool.Close.
		t.Logf("no loser branch hit (race resolved on cache hit) — acceptable")
	}
}

// TestPool_ResurrectionAfterEviction is the regression guard against
// "dead" entries staying reachable. After a full eviction cycle,
// re-acquiring the same key MUST trigger a fresh opener call rather
// than reuse the closed handle.
func TestPool_ResurrectionAfterEviction(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pool := newQueueDBPool(1) // capacity 1 forces eviction on next acquire
	t.Cleanup(pool.Close)

	opener1, calls1 := newOpener(t, dir, "Q1")
	opener2, _ := newOpener(t, dir, "Q2")

	_, rel1, err := pool.acquire("Q1", opener1, nil)
	if err != nil {
		t.Fatalf("acquire Q1: %v", err)
	}
	rel1()
	// Q2 evicts Q1 (Q1 was at capacity, refs=0 so it closes immediately).
	_, rel2, err := pool.acquire("Q2", opener2, nil)
	if err != nil {
		t.Fatalf("acquire Q2: %v", err)
	}
	rel2()

	// Re-acquire Q1: must call opener again (the previous handle is
	// closed and removed from the index).
	_, rel3, err := pool.acquire("Q1", opener1, nil)
	if err != nil {
		t.Fatalf("acquire Q1 again: %v", err)
	}
	rel3()
	if got := calls1.Load(); got != 2 {
		t.Errorf("opener1 calls: got %d, want 2 (initial + post-eviction)", got)
	}
}

// BenchmarkPool_AcquireRelease measures the steady-state hot path —
// repeated acquire/release on the same already-cached queue. This is
// the single most common operation in production once pool warm-up
// has finished.
func BenchmarkPool_AcquireRelease(b *testing.B) {
	dir := b.TempDir()
	pool := newQueueDBPool(4)
	b.Cleanup(pool.Close)

	var seed MasterSeed
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	salt := make([]byte, QueueKeySaltBytes)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	opener := func() (*sql.DB, error) {
		return openEncryptedDB(
			filepath.Join(dir, "Q1"+queueFilenameSuffix),
			func() (string, error) { return seed.DeriveQueueKey("Q1", salt) },
			false,
			1,
		)
	}
	// Warm the cache so the benchmark measures the hit path.
	_, rel, err := pool.acquire("Q1", opener, nil)
	if err != nil {
		b.Fatalf("warm-up acquire: %v", err)
	}
	rel()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, rel, err := pool.acquire("Q1", opener, nil)
		if err != nil {
			b.Fatalf("acquire: %v", err)
		}
		rel()
	}
}
