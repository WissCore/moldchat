// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/WissCore/moldchat/server/internal/auth"
)

// FuzzParseAuthorization feeds arbitrary header strings into the
// Authorization parser. Beyond "no panic", the parser must return
// only the documented sentinel errors so a future refactor cannot
// accidentally leak a different error type to the API layer (where
// it would surface as 500 instead of 401).
func FuzzParseAuthorization(f *testing.F) {
	seeds := []string{
		"",
		"ED25519-Sig YWFh,YmJi,Y2Nj",
		"ed25519-sig\tYWFh,YmJi,Y2Nj",
		"Bearer abc",
		"ED25519-Sig only",
		"ED25519-Sig a,b,c,d,e",
		"ED25519-Sig !!!,!!!,!!!",
		"ED25519-Sig\nbroken",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		_, _, _, err := auth.ParseAuthorization(header)
		if err == nil {
			return
		}
		if !errors.Is(err, auth.ErrAuthorizationMissing) &&
			!errors.Is(err, auth.ErrAuthorizationMalformed) {
			t.Errorf("unexpected error type for header %q: %T %v", header, err, err)
		}
	})
}

// FuzzCanonicalPayload verifies the two invariants Ed25519.Verify
// relies on for the auth contract: (1) length lower bound — the
// returned slice is at least as long as the concatenation of inputs,
// (2) determinism — the same inputs produce the same bytes. The
// exact format is internal, but a non-deterministic canonical payload
// would silently break every signed request after a refactor.
//
// Note on separator framing: the implementation uses 0x00 as a field
// delimiter without length prefixes. Our wire-level inputs (queue id,
// message id, method) cannot contain 0x00 because they are validated
// against base32 / HTTP-token alphabets at the API boundary, so the
// framing is unambiguous in practice. This test would still pass on
// inputs with embedded 0x00; if a future field could carry arbitrary
// bytes, the framing must move to length-prefixed form.
func FuzzCanonicalPayload(f *testing.F) {
	f.Add(make([]byte, auth.NonceBytes), "Q", "GET", "")
	f.Add(make([]byte, auth.NonceBytes), "Q1", "DELETE", "MSG1")
	f.Fuzz(func(t *testing.T, nonce []byte, queueID, method, resourceID string) {
		got := auth.CanonicalPayload(nonce, queueID, method, resourceID)
		if len(got) < len(nonce)+len(queueID)+len(method)+len(resourceID) {
			t.Errorf("payload shorter than concatenation of inputs")
		}
		again := auth.CanonicalPayload(nonce, queueID, method, resourceID)
		if !bytes.Equal(got, again) {
			t.Errorf("canonical payload not deterministic")
		}
	})
}

// FuzzVerify feeds random pubkeys, nonces, and signatures at Verify
// to confirm it never panics on malformed inputs and consistently
// rejects garbage with one of the documented sentinel errors. A
// successful verification on a fresh issuer (no nonce ever issued)
// would also be a contract violation: the only possible non-error
// path requires Issue() to have run first.
func FuzzVerify(f *testing.F) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("ed25519 keygen: %v", err)
	}
	f.Add([]byte(pub), make([]byte, auth.NonceBytes), make([]byte, ed25519.SignatureSize), "Q", "GET", "")
	f.Add([]byte("short-pubkey"), []byte("short-nonce"), []byte("short-sig"), "", "", "")
	f.Fuzz(func(t *testing.T, pubkey, nonce, sig []byte, queueID, method, resourceID string) {
		iss := auth.NewIssuer()
		err := iss.Verify(ed25519.PublicKey(pubkey), nonce, sig, queueID, method, resourceID)
		if err == nil {
			t.Errorf("Verify on fresh issuer must fail (no nonce ever issued)")
			return
		}
		if !errors.Is(err, auth.ErrSignatureInvalid) &&
			!errors.Is(err, auth.ErrAuthorizationMalformed) &&
			!errors.Is(err, auth.ErrReplay) {
			t.Errorf("unexpected error type: %T %v", err, err)
		}
	})
}
