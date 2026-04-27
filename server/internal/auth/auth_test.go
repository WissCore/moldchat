// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/auth"
)

func newKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 GenerateKey: %v", err)
	}
	return pub, priv
}

func TestIssue_LengthAndUniqueness(t *testing.T) {
	t.Parallel()
	iss := auth.NewIssuer()

	a, _, err := iss.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	b, _, err := iss.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(a) != auth.NonceBytes || len(b) != auth.NonceBytes {
		t.Errorf("nonce length: got %d/%d, want %d", len(a), len(b), auth.NonceBytes)
	}
	if string(a) == string(b) {
		t.Error("two consecutive Issue() calls returned the same nonce")
	}
}

func TestIssue_RejectsAtSaturation(t *testing.T) {
	t.Parallel()
	iss := auth.NewIssuer()

	// Fill the store up to the cap. Each issued nonce sits in memory for
	// NonceTTL; since this test runs in well under a second, none expire.
	for i := 0; i < auth.MaxOutstandingNonces; i++ {
		if _, _, err := iss.Issue(); err != nil {
			t.Fatalf("Issue[%d]: %v", i, err)
		}
	}
	_, _, err := iss.Issue()
	if !errors.Is(err, auth.ErrIssuerSaturated) {
		t.Errorf("at saturation: got %v, want ErrIssuerSaturated", err)
	}
}

func TestVerify_HappyPath(t *testing.T) {
	t.Parallel()
	iss := auth.NewIssuer()
	pub, priv := newKeypair(t)

	nonce, _, err := iss.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	queueID, method, path := "Q1", "GET", "/v1/queues/Q1/messages"
	sig := ed25519.Sign(priv, auth.CanonicalPayload(nonce, queueID, method, path))

	if err := iss.Verify(pub, nonce, sig, queueID, method, path); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerify_RejectsReplay(t *testing.T) {
	t.Parallel()
	iss := auth.NewIssuer()
	pub, priv := newKeypair(t)

	nonce, _, err := iss.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	queueID, method, path := "Q1", "GET", "/v1/queues/Q1/messages"
	sig := ed25519.Sign(priv, auth.CanonicalPayload(nonce, queueID, method, path))

	if err := iss.Verify(pub, nonce, sig, queueID, method, path); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if err := iss.Verify(pub, nonce, sig, queueID, method, path); !errors.Is(err, auth.ErrReplay) {
		t.Errorf("second Verify: got %v, want ErrReplay", err)
	}
}

func TestVerify_RejectsExpiredNonce(t *testing.T) {
	t.Parallel()
	iss := auth.NewIssuer()
	pub, priv := newKeypair(t)

	nonce, _, err := iss.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	auth.SetClockForTest(iss, func() time.Time { return time.Now().Add(2 * auth.NonceTTL) })

	queueID, method, path := "Q1", "GET", "/v1/queues/Q1/messages"
	sig := ed25519.Sign(priv, auth.CanonicalPayload(nonce, queueID, method, path))

	if err := iss.Verify(pub, nonce, sig, queueID, method, path); !errors.Is(err, auth.ErrReplay) {
		t.Errorf("expired nonce: got %v, want ErrReplay", err)
	}
}

func TestVerify_RejectsForgedSignature(t *testing.T) {
	t.Parallel()
	iss := auth.NewIssuer()
	pub, _ := newKeypair(t)
	_, otherPriv := newKeypair(t)

	nonce, _, err := iss.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	queueID, method, path := "Q1", "GET", "/v1/queues/Q1/messages"
	sig := ed25519.Sign(otherPriv, auth.CanonicalPayload(nonce, queueID, method, path))

	if err := iss.Verify(pub, nonce, sig, queueID, method, path); !errors.Is(err, auth.ErrSignatureInvalid) {
		t.Errorf("forged sig: got %v, want ErrSignatureInvalid", err)
	}
	// Even on signature failure the nonce is burned so it cannot be reused.
	if err := iss.Verify(pub, nonce, sig, queueID, method, path); !errors.Is(err, auth.ErrReplay) {
		t.Errorf("burned nonce should report replay: got %v", err)
	}
}

func TestVerify_RejectsTamperedPayload(t *testing.T) {
	t.Parallel()
	iss := auth.NewIssuer()
	pub, priv := newKeypair(t)

	nonce, _, err := iss.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	sig := ed25519.Sign(priv, auth.CanonicalPayload(nonce, "Q1", "GET", "/v1/queues/Q1/messages"))

	if err := iss.Verify(pub, nonce, sig, "Q2", "GET", "/v1/queues/Q1/messages"); !errors.Is(err, auth.ErrSignatureInvalid) {
		t.Errorf("tampered queue_id: got %v, want ErrSignatureInvalid", err)
	}
}

func TestVerify_RejectsTamperedMethod(t *testing.T) {
	t.Parallel()
	iss := auth.NewIssuer()
	pub, priv := newKeypair(t)

	nonce, _, err := iss.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	sig := ed25519.Sign(priv, auth.CanonicalPayload(nonce, "Q1", "GET", "/v1/queues/Q1/messages"))

	if err := iss.Verify(pub, nonce, sig, "Q1", "DELETE", "/v1/queues/Q1/messages"); !errors.Is(err, auth.ErrSignatureInvalid) {
		t.Errorf("tampered method: got %v, want ErrSignatureInvalid", err)
	}
}

func TestVerify_RejectsBadLengths(t *testing.T) {
	t.Parallel()
	iss := auth.NewIssuer()
	pub, _ := newKeypair(t)

	if err := iss.Verify(pub, []byte("short-nonce"), make([]byte, ed25519.SignatureSize), "Q", "GET", "/x"); !errors.Is(err, auth.ErrAuthorizationMalformed) {
		t.Errorf("short nonce: got %v, want ErrAuthorizationMalformed", err)
	}
	if err := iss.Verify(pub, make([]byte, auth.NonceBytes), []byte("short-sig"), "Q", "GET", "/x"); !errors.Is(err, auth.ErrAuthorizationMalformed) {
		t.Errorf("short sig: got %v, want ErrAuthorizationMalformed", err)
	}
}

func TestParseAuthorization_RoundTrip(t *testing.T) {
	t.Parallel()
	sig := make([]byte, ed25519.SignatureSize)
	pubkey := make([]byte, ed25519.PublicKeySize)
	nonce := make([]byte, auth.NonceBytes)
	for i := range sig {
		sig[i] = byte(i)
	}
	for i := range pubkey {
		pubkey[i] = byte(i + 50)
	}
	for i := range nonce {
		nonce[i] = byte(i + 100)
	}
	header := auth.FormatAuthorization(sig, pubkey, nonce)
	gotSig, gotPub, gotNonce, err := auth.ParseAuthorization(header)
	if err != nil {
		t.Fatalf("ParseAuthorization: %v", err)
	}
	if string(gotSig) != string(sig) || string(gotPub) != string(pubkey) || string(gotNonce) != string(nonce) {
		t.Errorf("round-trip mismatch")
	}
}

func TestParseAuthorization_RejectsMalformed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		header string
		want   error
	}{
		{"empty", "", auth.ErrAuthorizationMissing},
		{"wrong-scheme", "Bearer abc", auth.ErrAuthorizationMalformed},
		{"missing-comma", "ED25519-Sig abcdef", auth.ErrAuthorizationMalformed},
		{"two-parts-only", "ED25519-Sig YWFh,YmJi", auth.ErrAuthorizationMalformed},
		{"too-many-parts", "ED25519-Sig a,b,c,d", auth.ErrAuthorizationMalformed},
		{"bad-base64-sig", "ED25519-Sig !!!,YWFh,YmJi", auth.ErrAuthorizationMalformed},
		{"bad-base64-pub", "ED25519-Sig YWFh,!!!,YmJi", auth.ErrAuthorizationMalformed},
		{"bad-base64-nonce", "ED25519-Sig YWFh,YmJi,!!!", auth.ErrAuthorizationMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, err := auth.ParseAuthorization(tc.header)
			if !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestIssuer_ConcurrentIssueAndVerify exercises the issuer under heavy
// parallel use and lets the race detector verify there are no data races.
func TestIssuer_ConcurrentIssueAndVerify(t *testing.T) {
	t.Parallel()
	iss := auth.NewIssuer()
	pub, priv := newKeypair(t)

	const goroutines = 64
	const perGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				nonce, _, err := iss.Issue()
				if err != nil {
					t.Errorf("Issue: %v", err)
					return
				}
				payload := auth.CanonicalPayload(nonce, "Q", "GET", "/x")
				sig := ed25519.Sign(priv, payload)
				if err := iss.Verify(pub, nonce, sig, "Q", "GET", "/x"); err != nil {
					t.Errorf("Verify: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
