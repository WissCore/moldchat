// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"container/list"
	"database/sql"
	"errors"
	"sync"
)

// queueDBCapacity bounds the number of per-queue *sql.DB handles the
// pool keeps open at once. Per-queue files are not WAL so they use one
// FD each; the master DB plus its WAL/-shm consume three more, and
// http listeners, stdio, and runtime housekeeping take roughly fifty.
// At cap=256 the worst case fits well inside the typical container
// ulimit of 1024, leaving headroom for sudden bursts of FD-hungry
// operations (TLS handshakes via the Xray frontend, log rotation).
// Operators running with a higher ulimit can tune via build-time
// override if needed.
const queueDBCapacity = 256

// errPoolClosed is returned from acquire after Close has been called.
var errPoolClosed = errors.New("queue db pool closed")

// queueDBPool is an LRU cache of opened per-queue databases.
//
// The pool exists to amortise the cost of opening (and re-running schema
// init on) each per-queue file across the many requests that target the
// same queue. acquire returns the cached handle plus a release function;
// callers must call release exactly once when they are done with the
// handle. Eviction defers the actual db.Close until the last in-flight
// caller has released its reference, so a hot eviction never closes a
// connection out from under an active query.
type queueDBPool struct {
	mu        sync.Mutex
	capacity  int
	order     *list.List // front = MRU, back = LRU
	index     map[string]*list.Element
	closed    bool
	hits      uint64
	misses    uint64
	evictions uint64
}

// PoolStats is a point-in-time snapshot of the pool's counters,
// suitable for exporting to the L8 aggregate-counter pipeline.
type PoolStats struct {
	Size      int
	Hits      uint64
	Misses    uint64
	Evictions uint64
}

// Stats returns a copy of the current pool counters.
func (p *queueDBPool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PoolStats{
		Size:      len(p.index),
		Hits:      p.hits,
		Misses:    p.misses,
		Evictions: p.evictions,
	}
}

type queueDBEntry struct {
	queueID string
	db      *sql.DB
	refs    int
	evicted bool
	// onClose runs after the entry's *sql.DB has been closed and is
	// the hook callers use to wipe per-entry secrets (e.g., the
	// per-queue salt buffer captured by the deriveKey closure).
	// Invoked at most once.
	onClose func()
}

func newQueueDBPool(capacity int) *queueDBPool {
	return &queueDBPool{
		capacity: capacity,
		order:    list.New(),
		index:    make(map[string]*list.Element),
	}
}

// acquire returns the cached *sql.DB for queueID, opening a fresh one
// via opener if the queue is not yet cached. The returned release
// callback decrements the refcount; closing the pool, evicting under
// pressure, or both will defer the underlying Close until refs == 0.
// onClose is invoked once after the underlying *sql.DB is closed and
// is intended for wiping per-entry secrets such as the per-queue salt.
func (p *queueDBPool) acquire(queueID string, opener func() (*sql.DB, error), onClose func()) (*sql.DB, func(), error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, nil, errPoolClosed
	}
	if elem, ok := p.index[queueID]; ok {
		entry := elem.Value.(*queueDBEntry)
		entry.refs++
		p.order.MoveToFront(elem)
		p.hits++
		p.mu.Unlock()
		return entry.db, p.releaseFunc(entry), nil
	}
	p.misses++
	p.mu.Unlock()

	// Open outside the lock — opening a SQLCipher DB takes milliseconds
	// and we do not want to serialise concurrent first-touches.
	db, err := opener()
	if err != nil {
		return nil, nil, err
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = db.Close()
		if onClose != nil {
			onClose()
		}
		return nil, nil, errPoolClosed
	}
	// Another caller may have populated the entry while we were opening.
	if elem, ok := p.index[queueID]; ok {
		_ = db.Close()
		if onClose != nil {
			onClose()
		}
		entry := elem.Value.(*queueDBEntry)
		entry.refs++
		p.order.MoveToFront(elem)
		p.hits++
		p.mu.Unlock()
		return entry.db, p.releaseFunc(entry), nil
	}
	if len(p.index) >= p.capacity {
		p.evictOldestLocked()
	}
	entry := &queueDBEntry{queueID: queueID, db: db, refs: 1, onClose: onClose}
	elem := p.order.PushFront(entry)
	p.index[queueID] = elem
	p.mu.Unlock()
	return db, p.releaseFunc(entry), nil
}

// drop removes a specific queue's cached entry. Used by DeleteQueue so
// the file can be unlinked without leaving a pinned handle behind.
func (p *queueDBPool) drop(queueID string) {
	p.mu.Lock()
	elem, ok := p.index[queueID]
	if !ok {
		p.mu.Unlock()
		return
	}
	entry := elem.Value.(*queueDBEntry)
	delete(p.index, queueID)
	p.order.Remove(elem)
	entry.evicted = true
	p.maybeCloseLocked(entry)
	p.mu.Unlock()
}

// Close evicts every cached db and closes its handle once the last
// in-flight caller has released. Subsequent acquire calls return
// errPoolClosed.
func (p *queueDBPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for elem := p.order.Front(); elem != nil; elem = elem.Next() {
		entry := elem.Value.(*queueDBEntry)
		entry.evicted = true
		p.maybeCloseLocked(entry)
	}
	p.order.Init()
	p.index = make(map[string]*list.Element)
}

func (p *queueDBPool) releaseFunc(entry *queueDBEntry) func() {
	return func() {
		p.mu.Lock()
		entry.refs--
		p.maybeCloseLocked(entry)
		p.mu.Unlock()
	}
}

func (p *queueDBPool) evictOldestLocked() {
	elem := p.order.Back()
	if elem == nil {
		return
	}
	entry := elem.Value.(*queueDBEntry)
	delete(p.index, entry.queueID)
	p.order.Remove(elem)
	entry.evicted = true
	p.evictions++
	p.maybeCloseLocked(entry)
}

func (p *queueDBPool) maybeCloseLocked(entry *queueDBEntry) {
	if entry.evicted && entry.refs == 0 {
		_ = entry.db.Close()
		if entry.onClose != nil {
			entry.onClose()
			entry.onClose = nil
		}
	}
}
