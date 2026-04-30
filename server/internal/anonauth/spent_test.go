// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/anonauth"
)

// The spent-set is package-private. The tests here exercise it
// through the only public consumer (Verifier.Verify) which gives the
// same coverage without reaching into unexported state. Each test
// sets up a verifier with a tiny SpentSetCapacity to make eviction
// observable in a few requests.

// newVerifier mirrors the helper in roundtrip_test.go but inlines
// the seed/key boilerplate so this file is self-contained.
func newVerifierWithCapacity(tb testing.TB, capacity int, now time.Time) (*anonauth.Verifier, *anonauth.IssuerKey) {
	tb.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		tb.Fatalf("seed: %v", err)
	}
	key, err := anonauth.DeriveIssuerKey(seed)
	if err != nil {
		tb.Fatalf("derive: %v", err)
	}
	ver, err := anonauth.NewVerifier(anonauth.VerifierConfig{
		Epoch:            time.Hour,
		SpentSetCapacity: capacity,
	}, key)
	if err != nil {
		tb.Fatalf("verifier: %v", err)
	}
	ver.SetClockForTest(func() time.Time { return now })
	return ver, key
}

// finalizeOne constructs a (input, mac) pair for the supplied epoch
// by running FullEvaluate on a fresh random input. This bypasses the
// blinded-protocol path used in roundtrip_test.go because the
// spent-set tests do not need blinded inputs — they only need
// distinct, verifier-acceptable tokens.
func finalizeOne(tb testing.TB, key *anonauth.IssuerKey, epoch int64) (input, mac []byte) {
	tb.Helper()
	input = make([]byte, 16)
	if _, err := rand.Read(input); err != nil {
		tb.Fatalf("input: %v", err)
	}
	out, err := anonauth.FullEvaluateForTest(key, input, epoch)
	if err != nil {
		tb.Fatalf("full evaluate: %v", err)
	}
	return input, out
}

func TestSpentSet_FreshThenReplay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ver, key := newVerifierWithCapacity(t, 16, now)
	input, mac := finalizeOne(t, key, ver.CurrentEpoch(now))

	if err := ver.Verify(input, mac); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := ver.Verify(input, mac); !errors.Is(err, anonauth.ErrTokenReplayed) {
		t.Fatalf("expected ErrTokenReplayed on replay, got %v", err)
	}
}

func TestSpentSet_LRUEvictionAllowsReuseAfterEviction(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	const capacity = 2
	ver, key := newVerifierWithCapacity(t, capacity, now)

	tokens := make([][2][]byte, 3)
	for i := range tokens {
		input, mac := finalizeOne(t, key, ver.CurrentEpoch(now))
		tokens[i] = [2][]byte{input, mac}
		if err := ver.Verify(input, mac); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if got := ver.SpentSetSizeForTest(); got != capacity {
		t.Fatalf("size after eviction = %d, want %d", got, capacity)
	}
	// The first token was the LRU and must have been evicted, so a
	// replay attempt is no longer detected. This is intentional:
	// once a token is evicted from the spent-set the operator
	// accepts that the per-pseudonym counter (issuance side) is the
	// only remaining defence. Document the behaviour by asserting
	// the evicted token re-verifies cleanly.
	if err := ver.Verify(tokens[0][0], tokens[0][1]); err != nil {
		t.Fatalf("evicted token should re-verify cleanly, got %v", err)
	}
}

func TestSpentSet_RejectsTamperedTokenWithoutConsumingSlot(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ver, key := newVerifierWithCapacity(t, 16, now)
	input, mac := finalizeOne(t, key, ver.CurrentEpoch(now))

	tampered := append([]byte{}, mac...)
	tampered[0] ^= 0x01
	if err := ver.Verify(input, tampered); !errors.Is(err, anonauth.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid on tampered mac, got %v", err)
	}
	// The original mac must still verify because the failed attempt
	// never reached the spent-set markIfFresh path.
	if err := ver.Verify(input, mac); err != nil {
		t.Fatalf("original mac after tamper: %v", err)
	}
}

func TestSpentSet_ZeroLengthMacRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ver, _ := newVerifierWithCapacity(t, 16, now)
	if err := ver.Verify(bytes.Repeat([]byte{0x01}, 16), nil); !errors.Is(err, anonauth.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for empty mac, got %v", err)
	}
}
