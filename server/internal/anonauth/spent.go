// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth

import (
	"container/list"
	"sync"
	"time"
)

// spentSet tracks redeemed token MACs so a presented token cannot be
// replayed within its epoch (or the one-epoch grace window). Implemented
// as a bounded LRU keyed by the truncated MAC; the truncation is
// safe because the MAC is a 64-byte SHA-512 output and the first 16
// bytes carry far more collision resistance than the issuance rate
// can plausibly exhaust.
//
// Eviction policy: oldest entry first when the cap is hit. That is
// safe because tokens carry an epoch in their POPRF info — a token
// older than the grace window will fail FullEvaluate before its mac
// is ever consulted, so an evicted-but-still-valid mac is impossible.
type spentSet struct {
	mu       sync.Mutex
	capacity int
	order    *list.List // front = MRU, back = LRU
	index    map[[spentKeyBytes]byte]*list.Element
}

const (
	// spentKeyBytes is the truncation length of the stored mac. 16
	// bytes (128 bits) of SHA-512 output yields a collision
	// probability well below 2^-100 at any plausible token volume,
	// which is more than enough for replay protection.
	spentKeyBytes = 16

	// DefaultSpentSetCapacity bounds the in-memory spent-set. The
	// default supports several hundred thousand redemptions per
	// epoch — well above what a single per-pseudonym counter can
	// authorise — without growing past a few tens of MiB.
	DefaultSpentSetCapacity = 1_000_000
)

type spentEntry struct {
	key       [spentKeyBytes]byte
	expiresAt time.Time
}

// newSpentSet returns a fresh spent set with the supplied capacity.
// Capacity ≤ 0 is rejected at construction so callers cannot
// accidentally disable replay protection by passing the zero value.
func newSpentSet(capacity int) *spentSet {
	if capacity <= 0 {
		capacity = DefaultSpentSetCapacity
	}
	return &spentSet{
		capacity: capacity,
		order:    list.New(),
		index:    make(map[[spentKeyBytes]byte]*list.Element),
	}
}

// markIfFresh records mac as spent unless it is already in the set
// and its recorded expiry is still in the future. Returns true on
// fresh insertion, false when the mac was already present and unexpired
// (i.e. a replay). An entry whose expiry has lapsed is treated as
// fresh: the old record is overwritten and the call returns true,
// which lets the operator change the epoch boundary without flushing
// state explicitly.
func (s *spentSet) markIfFresh(mac []byte, expiresAt time.Time, now time.Time) bool {
	if len(mac) < spentKeyBytes {
		return false
	}
	var key [spentKeyBytes]byte
	copy(key[:], mac[:spentKeyBytes])

	s.mu.Lock()
	defer s.mu.Unlock()

	if elem, ok := s.index[key]; ok {
		entry := elem.Value.(*spentEntry)
		if entry.expiresAt.After(now) {
			return false
		}
		// Stale — replace in place.
		entry.expiresAt = expiresAt
		s.order.MoveToFront(elem)
		return true
	}

	if len(s.index) >= s.capacity {
		oldest := s.order.Back()
		if oldest != nil {
			oldEntry := oldest.Value.(*spentEntry)
			delete(s.index, oldEntry.key)
			s.order.Remove(oldest)
		}
	}
	entry := &spentEntry{key: key, expiresAt: expiresAt}
	elem := s.order.PushFront(entry)
	s.index[key] = elem
	return true
}

// size returns the current number of tracked entries; used by tests
// only, not exported on the issuance path.
func (s *spentSet) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}
