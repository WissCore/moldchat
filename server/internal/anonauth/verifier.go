// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth

import (
	"crypto/subtle"
	"fmt"
	"math"
	"time"

	"github.com/cloudflare/circl/oprf"
)

// VerifierConfig captures the verifier-side knobs. Epoch must match
// the issuer; SpentSetCapacity bounds the in-memory replay map and
// can be left zero to take the default.
type VerifierConfig struct {
	Epoch            time.Duration
	SpentSetCapacity int
}

// Verifier consumes presented tokens. It is safe for concurrent use.
//
// The verifier accepts tokens for the current epoch and the
// immediately preceding epoch; that one-epoch grace covers the case
// where a client finalised a token a few seconds before the boundary
// and presents it just after. Tokens older than that are rejected
// because their POPRF FullEvaluate produces a different MAC, so the
// constant-time compare fails.
type Verifier struct {
	cfg    VerifierConfig
	server oprf.PartialObliviousServer
	spent  *spentSet
	now    func() time.Time
}

// NewVerifier constructs a verifier from the issuer's key. The
// issuer and verifier share the same key material because POPRF
// FullEvaluate requires the private scalar; this is identical to the
// issuer-side oprf.PartialObliviousServer constructor and is fine to
// instantiate twice.
func NewVerifier(cfg VerifierConfig, key *IssuerKey) (*Verifier, error) {
	if cfg.Epoch <= 0 {
		return nil, fmt.Errorf("anonauth: VerifierConfig.Epoch must be > 0")
	}
	if key == nil {
		return nil, fmt.Errorf("anonauth: IssuerKey is required")
	}
	return &Verifier{
		cfg:    cfg,
		server: oprf.NewPartialObliviousServer(key.Suite(), key.privateKey()),
		spent:  newSpentSet(cfg.SpentSetCapacity),
		now:    time.Now,
	}, nil
}

// CurrentEpoch returns the epoch index for the supplied time using
// the verifier's epoch duration. Times before the Unix epoch
// collapse to 0; see computeEpoch for the shared logic.
func (v *Verifier) CurrentEpoch(now time.Time) int64 {
	return computeEpoch(now, v.cfg.Epoch)
}

// Verify checks that the supplied (input, mac) pair is a valid POPRF
// finalised output for the current epoch or the immediately
// preceding epoch, and records the mac in the spent set. Returns
// ErrTokenInvalid for any cryptographic mismatch and
// ErrTokenReplayed when the mac is already present and unexpired.
//
// MAC matching strategy: try the current epoch first, then the
// previous epoch. Both calls go through subtle.ConstantTimeCompare so
// the matched-epoch decision does not branch on a non-constant-time
// path; the early-exit on the current epoch is intentional to bound
// the worst-case CPU cost to two FullEvaluate calls plus two
// constant-time compares.
func (v *Verifier) Verify(input, mac []byte) error {
	if len(input) == 0 || len(mac) == 0 {
		return ErrTokenInvalid
	}
	now := v.now()
	current := v.CurrentEpoch(now)

	matchedEpoch, ok := v.matchEpoch(input, mac, current)
	if !ok && current > 0 {
		matchedEpoch, ok = v.matchEpoch(input, mac, current-1)
	}
	if !ok {
		return ErrTokenInvalid
	}

	// Spent-set TTL: keep the entry until the matched epoch is no
	// longer redeemable, i.e. one full epoch past matchedEpoch's
	// boundary. After that the constant-time compare against either
	// the current or previous epoch will already reject the token,
	// so the entry can safely be evicted. The arithmetic is bound-
	// checked because nothing else upstream prevents an absurdly
	// large matchedEpoch from overflowing int64 once it is multiplied
	// by an epoch in nanoseconds.
	expiresAt := spentEntryExpiry(matchedEpoch, v.cfg.Epoch)
	if !v.spent.markIfFresh(mac, expiresAt, now) {
		return ErrTokenReplayed
	}
	return nil
}

func spentEntryExpiry(matchedEpoch int64, epoch time.Duration) time.Time {
	epochNs := int64(epoch)
	if epochNs <= 0 || matchedEpoch < 0 {
		// Verifier construction guards epoch > 0 and matchedEpoch
		// is computed by computeEpoch which returns 0 for negative
		// times; reaching either branch means a misuse from a
		// future caller.
		return time.Unix(0, math.MaxInt64)
	}
	// Bound the product (matchedEpoch+2) * epochNs so it fits in
	// int64; clamp to far-future on overflow rather than wrapping.
	const grace = 2
	if matchedEpoch > math.MaxInt64/epochNs-grace {
		return time.Unix(0, math.MaxInt64)
	}
	return time.Unix(0, (matchedEpoch+grace)*epochNs)
}

// matchEpoch returns the epoch and true if FullEvaluate(input, epoch)
// produces a byte-identical mac. The compare is constant-time.
func (v *Verifier) matchEpoch(input, mac []byte, epoch int64) (int64, bool) {
	expected, err := v.server.FullEvaluate(input, EpochInfo(epoch))
	if err != nil {
		return 0, false
	}
	if subtle.ConstantTimeCompare(expected, mac) != 1 {
		return 0, false
	}
	return epoch, true
}
