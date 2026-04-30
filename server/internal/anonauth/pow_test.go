// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/WissCore/moldchat/server/internal/anonauth"
)

// solvePoW grinds nonces sequentially until SHA-256(challenge||nonce)
// has at least bits leading zero bits. Test-only helper; production
// clients run the same loop in their own code.
func solvePoW(tb testing.TB, challenge []byte, bits uint8) []byte {
	tb.Helper()
	nonce := make([]byte, 8)
	for i := uint64(0); ; i++ {
		binary.BigEndian.PutUint64(nonce, i)
		h := sha256.Sum256(append(append([]byte{}, challenge...), nonce...))
		if leadingZeroBits(h[:]) >= int(bits) {
			return append([]byte{}, nonce...)
		}
		if i > 1<<28 {
			tb.Fatalf("pow grinding exceeded budget at bits=%d", bits)
		}
	}
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if x&mask == 0 {
				n++
			} else {
				return n
			}
		}
		return n
	}
	return n
}

func TestPoW_HappyPath(t *testing.T) {
	t.Parallel()
	store, err := anonauth.NewPoWStore(8)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ch, err := store.Issue()
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(ch.Bytes) == 0 {
		t.Fatalf("empty challenge")
	}
	nonce := solvePoW(t, ch.Bytes, ch.DifficultyBits)
	if err := store.Verify(ch.Bytes, nonce); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestPoW_InvalidNonce(t *testing.T) {
	t.Parallel()
	store, err := anonauth.NewPoWStore(8)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ch, _ := store.Issue()
	bad := bytes.Repeat([]byte{0xFF}, 8)
	if err := store.Verify(ch.Bytes, bad); !errors.Is(err, anonauth.ErrPoWInvalid) {
		t.Fatalf("expected ErrPoWInvalid, got %v", err)
	}
}

func TestPoW_ChallengeConsumed(t *testing.T) {
	t.Parallel()
	store, err := anonauth.NewPoWStore(4)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ch, _ := store.Issue()
	nonce := solvePoW(t, ch.Bytes, ch.DifficultyBits)
	if err := store.Verify(ch.Bytes, nonce); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// Second attempt with same challenge must be rejected as
	// unknown — the entry was consumed atomically.
	if err := store.Verify(ch.Bytes, nonce); !errors.Is(err, anonauth.ErrPoWChallengeUnknown) {
		t.Fatalf("expected ErrPoWChallengeUnknown on replay, got %v", err)
	}
}

func TestPoW_NearMissBurnsChallenge(t *testing.T) {
	t.Parallel()
	store, err := anonauth.NewPoWStore(8)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ch, _ := store.Issue()
	bad := make([]byte, 8) // almost certainly does not satisfy 8 bits
	if err := store.Verify(ch.Bytes, bad); !errors.Is(err, anonauth.ErrPoWInvalid) {
		t.Fatalf("expected ErrPoWInvalid, got %v", err)
	}
	// The challenge must be burned so a second attempt with a
	// freshly ground correct nonce cannot succeed.
	good := solvePoW(t, ch.Bytes, ch.DifficultyBits)
	if err := store.Verify(ch.Bytes, good); !errors.Is(err, anonauth.ErrPoWChallengeUnknown) {
		t.Fatalf("expected ErrPoWChallengeUnknown after near-miss burn, got %v", err)
	}
}

func TestPoW_RejectsZeroDifficulty(t *testing.T) {
	t.Parallel()
	if _, err := anonauth.NewPoWStore(0); err == nil {
		t.Fatal("expected error for difficulty 0")
	}
	if _, err := anonauth.NewPoWStore(255); err == nil {
		t.Fatal("expected error for difficulty above max")
	}
}

func TestPoW_RejectsBadSizes(t *testing.T) {
	t.Parallel()
	store, _ := anonauth.NewPoWStore(4)
	if err := store.Verify(make([]byte, 31), make([]byte, 8)); err == nil {
		t.Fatal("expected error for short challenge")
	}
	if err := store.Verify(make([]byte, 32), make([]byte, 7)); err == nil {
		t.Fatal("expected error for short nonce")
	}
}
