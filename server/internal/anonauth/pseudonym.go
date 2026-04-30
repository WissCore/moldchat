// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"
)

// PseudonymStore is the persistence interface the issuer uses to
// register pseudonyms and bookkeep per-epoch counters.
//
// Concurrency: implementations MUST serialise CheckAndIncrement so
// that two parallel token requests under the same pseudonym in the
// same epoch never both succeed past the configured limit.
type PseudonymStore interface {
	// Register persists a fresh pseudonym. Returns ErrPseudonymExists
	// if the public key is already registered.
	Register(ctx context.Context, pub ed25519.PublicKey, created, expires time.Time) error

	// CheckAndIncrement atomically rolls the per-epoch counter
	// forward to the supplied epoch (resetting it when the epoch
	// differs from the row's stored last_epoch) and increments by
	// one. Returns ErrRateLimited when the post-increment value
	// would exceed limit, ErrPseudonymExpired when now is past the
	// pseudonym's expiry, and ErrPseudonymInvalid when the pseudonym
	// is unknown.
	CheckAndIncrement(ctx context.Context, pub ed25519.PublicKey, epoch int64, limit uint32, now time.Time) error

	// DeleteExpired removes pseudonym records whose expiry is at or
	// before the supplied cutoff. The periodic cleanup runner calls
	// this; implementations may treat it as best-effort.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)

	// Close releases any backend resources. Calling Close on a store
	// that is already closed is a no-op.
	Close() error
}

// Sentinel errors specific to the pseudonym store. The HTTP layer
// collapses them into a single client response per the package-level
// note in anonauth.go, but the distinct values are useful for tests
// and storage backends.
var (
	ErrPseudonymExists   = errors.New("pseudonym already registered")
	ErrPseudonymExpired  = errors.New("pseudonym expired")
	ErrPseudonymCapacity = errors.New("pseudonym store at capacity")
)
