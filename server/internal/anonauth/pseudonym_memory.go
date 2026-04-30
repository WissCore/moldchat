// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth

import (
	"context"
	"crypto/ed25519"
	"sync"
	"time"
)

// MemoryPseudonymStoreCapacity bounds the in-memory pseudonym map so
// a misconfigured deployment cannot grow without bound. Once reached,
// Register returns ErrPseudonymCapacity and the HTTP layer surfaces a
// 503 Service Unavailable.
const MemoryPseudonymStoreCapacity = 100_000

// pseudonymRecord is the in-memory representation of a registered
// pseudonym; package-private because no caller outside the store
// needs to see the per-epoch counter directly.
type pseudonymRecord struct {
	expires         time.Time
	lastEpoch       int64
	tokensThisEpoch uint32
}

// memoryPseudonymStore is the in-memory PseudonymStore. Suitable for
// tests and short-lived development instances; production deployments
// should run the SQLCipher-backed store from the sqlitestore
// subpackage.
type memoryPseudonymStore struct {
	mu       sync.Mutex
	capacity int
	records  map[string]*pseudonymRecord
}

// NewMemoryPseudonymStore returns an empty in-memory store.
func NewMemoryPseudonymStore() PseudonymStore {
	return &memoryPseudonymStore{
		capacity: MemoryPseudonymStoreCapacity,
		records:  make(map[string]*pseudonymRecord),
	}
}

func (s *memoryPseudonymStore) Register(_ context.Context, pub ed25519.PublicKey, _ time.Time, expires time.Time) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrPseudonymInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := string(pub)
	if _, exists := s.records[key]; exists {
		return ErrPseudonymExists
	}
	if len(s.records) >= s.capacity {
		return ErrPseudonymCapacity
	}
	s.records[key] = &pseudonymRecord{expires: expires}
	return nil
}

func (s *memoryPseudonymStore) CheckAndIncrement(_ context.Context, pub ed25519.PublicKey, epoch int64, limit uint32, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrPseudonymInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[string(pub)]
	if !ok {
		return ErrPseudonymInvalid
	}
	if !rec.expires.After(now) {
		return ErrPseudonymExpired
	}
	if rec.lastEpoch != epoch {
		rec.lastEpoch = epoch
		rec.tokensThisEpoch = 0
	}
	if rec.tokensThisEpoch >= limit {
		return ErrRateLimited
	}
	rec.tokensThisEpoch++
	return nil
}

func (s *memoryPseudonymStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	deleted := 0
	for key, rec := range s.records {
		if !rec.expires.After(before) {
			delete(s.records, key)
			deleted++
		}
	}
	return deleted, nil
}

func (s *memoryPseudonymStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = nil
	return nil
}
