// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth

import (
	"time"

	"github.com/cloudflare/circl/oprf"
)

func newPartialObliviousServerForTest(key *IssuerKey) oprf.PartialObliviousServer {
	return oprf.NewPartialObliviousServer(key.Suite(), key.privateKey())
}

// The helpers in this file are exported for the benefit of test
// packages outside this one (notably internal/api/v1 integration
// tests). They are NOT part of the production API: each name carries
// a "ForTest" suffix so a slip into production code is loud at the
// call site, and the godoc deliberately discourages non-test use.
//
// They live in a regular source file rather than `*_test.go` because
// Go's external test packages cannot import test-only symbols from
// another package; this is the standard workaround.

// SetClockForTest replaces the issuer's clock with a deterministic
// function. For tests only.
func (i *Issuer) SetClockForTest(now func() time.Time) { i.now = now }

// SetClockForTest replaces the verifier's clock with a deterministic
// function. For tests only.
func (v *Verifier) SetClockForTest(now func() time.Time) { v.now = now }

// SetClockForTest replaces the PoW store clock. For tests only.
func (s *PoWStore) SetClockForTest(now func() time.Time) { s.now = now }

// SpentSetSizeForTest exposes the spent-set occupancy. For tests only.
func (v *Verifier) SpentSetSizeForTest() int { return v.spent.size() }

// CanonicalIssuancePayloadForTest exposes the canonical signing
// payload so a test client can sign without duplicating the layout.
// For tests only.
func CanonicalIssuancePayloadForTest(epoch int64, blinded []byte) []byte {
	return canonicalIssuancePayload(epoch, blinded)
}

// FullEvaluateForTest runs POPRF.FullEvaluate against the issuer key
// for the supplied epoch info. Lets spent-set tests build verifier-
// acceptable tokens without going through the blinded protocol.
// For tests only.
func FullEvaluateForTest(key *IssuerKey, input []byte, epoch int64) ([]byte, error) {
	srv := newPartialObliviousServerForTest(key)
	return srv.FullEvaluate(input, EpochInfo(epoch))
}
