// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth_test

import (
	"bytes"
	"testing"

	"github.com/WissCore/moldchat/server/internal/anonauth"
)

func TestDeriveIssuerKey_Deterministic(t *testing.T) {
	t.Parallel()
	seed := bytes.Repeat([]byte{0xAB}, 32)
	a, err := anonauth.DeriveIssuerKey(seed)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	b, err := anonauth.DeriveIssuerKey(seed)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	pubA, err := a.PublicKey()
	if err != nil {
		t.Fatalf("pub a: %v", err)
	}
	pubB, err := b.PublicKey()
	if err != nil {
		t.Fatalf("pub b: %v", err)
	}
	if !bytes.Equal(pubA, pubB) {
		t.Fatalf("derivation non-deterministic: %x vs %x", pubA, pubB)
	}
}

func TestDeriveIssuerKey_DifferentSeedsDifferentKeys(t *testing.T) {
	t.Parallel()
	a, err := anonauth.DeriveIssuerKey(bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := anonauth.DeriveIssuerKey(bytes.Repeat([]byte{0x02}, 32))
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	pubA, _ := a.PublicKey()
	pubB, _ := b.PublicKey()
	if bytes.Equal(pubA, pubB) {
		t.Fatalf("two seeds produced same public key, derivation is not injective")
	}
}

func TestDeriveIssuerKey_RejectsBadSeedLength(t *testing.T) {
	t.Parallel()
	cases := [][]byte{
		nil,
		make([]byte, 0),
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 64),
	}
	for _, seed := range cases {
		if _, err := anonauth.DeriveIssuerKey(seed); err == nil {
			t.Errorf("expected error for seed length %d, got nil", len(seed))
		}
	}
}
