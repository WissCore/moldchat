// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/WissCore/moldchat/server/internal/auth"
)

// BenchmarkVerify measures the cost of a successful challenge-response
// verification including nonce lookup, Ed25519 verify, and replay
// burning. This is the single hottest auth path on the server and
// regressions here directly cap owner-only request throughput.
func BenchmarkVerify(b *testing.B) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("ed25519 keygen: %v", err)
	}
	iss := auth.NewIssuer()
	queueID, method, resourceID := "Q1", "GET", ""

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nonce, _, err := iss.Issue()
		if err != nil {
			b.Fatalf("Issue: %v", err)
		}
		sig := ed25519.Sign(priv, auth.CanonicalPayload(nonce, queueID, method, resourceID))
		if err := iss.Verify(pub, nonce, sig, queueID, method, resourceID); err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}

// BenchmarkParseAuthorization measures the cost of header parsing on
// the request hot path. Every owner-only request runs this once; a
// regression here applies a tax to every authenticated call.
func BenchmarkParseAuthorization(b *testing.B) {
	sig := make([]byte, ed25519.SignatureSize)
	pubkey := make([]byte, ed25519.PublicKeySize)
	nonce := make([]byte, auth.NonceBytes)
	header := auth.FormatAuthorization(sig, pubkey, nonce)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = auth.ParseAuthorization(header)
	}
}
