// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth

import (
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"
)

// Hashcash parameters. The challenge is a fresh 32-byte random value;
// the client searches for an 8-byte nonce such that the SHA-256 hash
// of the concatenation has at least DifficultyBits leading zero bits.
// Difficulty is set at construction; changing it requires a restart,
// which is acceptable because difficulty changes are rare and a
// rolling restart is the standard response to a sustained flood.
const (
	// challengeBytes is the size of the random challenge handed out by
	// the issuer. 32 bytes is overkill for collision resistance at any
	// reasonable issuance rate; the size matches a SHA-256 block so a
	// challenge plus an 8-byte nonce hashes in a single compression.
	challengeBytes = 32

	// nonceBytes is the size of the client-supplied nonce. 8 bytes
	// gives 2^64 search space, far above any difficulty an operator
	// would set, so the nonce field itself is never the bottleneck.
	nonceBytes = 8

	// challengeTTL bounds how long an issued challenge remains
	// redeemable. A short TTL caps the in-memory map and stops a
	// client from pre-computing a large stockpile of nonces against
	// future challenges.
	challengeTTL = 2 * time.Minute

	// MaxOutstandingChallenges caps the in-memory challenge map. The
	// cap is generous enough for normal client behaviour and small
	// enough to bound memory under flooding; once reached, Issue
	// returns ErrIssuerSaturated and the HTTP layer surfaces a 503.
	MaxOutstandingChallenges = 10_000

	// DefaultDifficultyBits is the default leading-zero-bits target.
	// On a modern CPU a SHA-256 grind hits 2^20 in roughly one second,
	// which is a manageable one-time cost per pseudonym.
	DefaultDifficultyBits = 20

	// MaxDifficultyBits caps how high operators can crank the knob.
	// 32 bits ≈ 4 billion attempts which already takes minutes on a
	// CPU; anything above that crosses into UX-hostile territory and
	// is rejected at config-load time rather than allowed to brick
	// pseudonym registration.
	MaxDifficultyBits = 32
)

// PoWChallenge is what the issuer hands the client. Bytes is the
// random nonce; DifficultyBits is the leading-zero-bits target the
// client must hit; ExpiresAt is the wall-clock deadline after which
// the verifier rejects the submission.
type PoWChallenge struct {
	Bytes          []byte
	DifficultyBits uint8
	ExpiresAt      time.Time
}

// PoWStore tracks outstanding challenges. The store is in-memory,
// bounded, and self-pruning: each successful Issue lazily evicts
// expired entries, and the Verify call atomically removes the entry
// it consumes so the same challenge cannot be redeemed twice. The
// store is not durable across restarts — challenges become invalid on
// process restart, which is the intended semantics (no challenge
// outlives the process that issued it).
type PoWStore struct {
	mu             sync.Mutex
	difficultyBits uint8
	outstanding    map[string]time.Time
	now            func() time.Time
}

// NewPoWStore returns a fresh PoWStore configured at the supplied
// leading-zero-bits target. A zero or out-of-range difficulty is a
// configuration error and is rejected here rather than at every
// Issue call so misconfiguration surfaces at startup.
func NewPoWStore(difficultyBits uint8) (*PoWStore, error) {
	if difficultyBits == 0 || difficultyBits > MaxDifficultyBits {
		return nil, ErrPoWInvalid
	}
	return &PoWStore{
		difficultyBits: difficultyBits,
		outstanding:    make(map[string]time.Time),
		now:            time.Now,
	}, nil
}

// Issue returns a fresh challenge and remembers it until Verify
// consumes it or it expires. The store is pruned of expired entries
// only when the cap is reached so the fast path stays O(1).
func (s *PoWStore) Issue() (PoWChallenge, error) {
	bytes := make([]byte, challengeBytes)
	if _, err := rand.Read(bytes); err != nil {
		return PoWChallenge{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if len(s.outstanding) >= MaxOutstandingChallenges {
		for k, exp := range s.outstanding {
			if !exp.After(now) {
				delete(s.outstanding, k)
			}
		}
		if len(s.outstanding) >= MaxOutstandingChallenges {
			return PoWChallenge{}, ErrIssuerSaturated
		}
	}

	expiresAt := now.Add(challengeTTL)
	s.outstanding[string(bytes)] = expiresAt
	return PoWChallenge{
		Bytes:          bytes,
		DifficultyBits: s.difficultyBits,
		ExpiresAt:      expiresAt,
	}, nil
}

// Verify checks that the supplied nonce satisfies the difficulty
// against the stored challenge and consumes the challenge. The
// challenge is removed regardless of outcome: a single challenge must
// authorise at most one verification attempt so a client cannot grind
// alternative nonces after a near-miss.
func (s *PoWStore) Verify(challenge, nonce []byte) error {
	if len(challenge) != challengeBytes || len(nonce) != nonceBytes {
		return ErrPoWInvalid
	}

	s.mu.Lock()
	expiresAt, ok := s.outstanding[string(challenge)]
	if !ok {
		s.mu.Unlock()
		return ErrPoWChallengeUnknown
	}
	delete(s.outstanding, string(challenge))
	difficulty := s.difficultyBits
	now := s.now()
	s.mu.Unlock()

	if !expiresAt.After(now) {
		return ErrPoWChallengeUnknown
	}
	if !satisfiesDifficulty(challenge, nonce, difficulty) {
		return ErrPoWInvalid
	}
	return nil
}

// satisfiesDifficulty reports whether SHA-256(challenge || nonce) has
// at least bits leading zero bits. Implemented byte-then-bit so the
// loop short-circuits on the first non-zero bit and runs in constant
// time relative to bits — there is nothing secret to leak through
// timing here, but uniform structure keeps the function
// straightforward to audit.
func satisfiesDifficulty(challenge, nonce []byte, bits uint8) bool {
	h := sha256.New()
	_, _ = h.Write(challenge)
	_, _ = h.Write(nonce)
	digest := h.Sum(nil)

	full := int(bits / 8)
	for i := 0; i < full; i++ {
		if digest[i] != 0 {
			return false
		}
	}
	rem := bits % 8
	if rem == 0 {
		return true
	}
	mask := byte(0xFF) << (8 - rem)
	return digest[full]&mask == 0
}
