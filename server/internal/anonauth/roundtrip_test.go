// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/anonauth"
	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	dleqpkg "github.com/cloudflare/circl/zk/dleq"
)

// fixedClock returns a closure that always reports t. Tests advance
// the clock by replacing the closure rather than mutating shared
// state, which keeps each step explicit.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// newTestStack constructs an issuer + verifier pair sharing a fresh
// in-memory pseudonym store and a deterministic clock. The returned
// IssuerKey lets tests build the matching POPRF client.
func newTestStack(tb testing.TB, now time.Time, cfg anonauth.IssuerConfig) (*anonauth.Issuer, *anonauth.Verifier, *anonauth.IssuerKey) {
	tb.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		tb.Fatalf("seed: %v", err)
	}
	key, err := anonauth.DeriveIssuerKey(seed)
	if err != nil {
		tb.Fatalf("derive: %v", err)
	}
	iss, err := anonauth.NewIssuer(cfg, key, anonauth.NewMemoryPseudonymStore())
	if err != nil {
		tb.Fatalf("issuer: %v", err)
	}
	ver, err := anonauth.NewVerifier(anonauth.VerifierConfig{Epoch: cfg.Epoch}, key)
	if err != nil {
		tb.Fatalf("verifier: %v", err)
	}
	iss.SetClockForTest(fixedClock(now))
	ver.SetClockForTest(fixedClock(now))
	return iss, ver, key
}

// registerPseudonym solves a hashcash and registers a fresh
// pseudonym. Returns the pseudonym key pair.
func registerPseudonym(tb testing.TB, iss *anonauth.Issuer) (ed25519.PublicKey, ed25519.PrivateKey) {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("ed25519: %v", err)
	}
	ch, err := iss.PoWChallenge()
	if err != nil {
		tb.Fatalf("challenge: %v", err)
	}
	nonce := solvePoW(tb, ch.Bytes, ch.DifficultyBits)
	if err := iss.RegisterPseudonym(context.Background(), pub, ch.Bytes, nonce); err != nil {
		tb.Fatalf("register: %v", err)
	}
	return pub, priv
}

// issueAndFinalize runs the full client flow: blind one input, send
// to issuer, finalize the response into the canonical (input, mac).
// The DLEQ proof is verified inside Finalize so a bug in proof
// generation would surface here, not silently downstream.
func issueAndFinalize(tb testing.TB, iss *anonauth.Issuer, key *anonauth.IssuerKey, pub ed25519.PublicKey, priv ed25519.PrivateKey, epoch int64) (input, mac []byte) {
	tb.Helper()
	suite := key.Suite()
	pubKey, err := key.PublicKey()
	if err != nil {
		tb.Fatalf("issuer pub: %v", err)
	}
	parsedPub := new(oprf.PublicKey)
	if parseErr := parsedPub.UnmarshalBinary(suite, pubKey); parseErr != nil {
		tb.Fatalf("parse pub: %v", parseErr)
	}
	client := oprf.NewPartialObliviousClient(suite, parsedPub)

	input = make([]byte, 16)
	if _, randErr := rand.Read(input); randErr != nil {
		tb.Fatalf("input: %v", randErr)
	}
	finData, evalReq, err := client.Blind([][]byte{input})
	if err != nil {
		tb.Fatalf("blind: %v", err)
	}
	blindedBytes, err := evalReq.Elements[0].MarshalBinaryCompress()
	if err != nil {
		tb.Fatalf("marshal blinded: %v", err)
	}

	signed := anonauth.CanonicalIssuancePayloadForTest(epoch, blindedBytes)
	sig := ed25519.Sign(priv, signed)
	resp, err := iss.IssueToken(context.Background(), anonauth.IssuanceRequest{
		Blinded:      blindedBytes,
		PseudonymPub: pub,
		Signature:    sig,
		Epoch:        epoch,
	})
	if err != nil {
		tb.Fatalf("issue: %v", err)
	}

	evalElement := suite.Group().NewElement()
	if elemErr := evalElement.UnmarshalBinary(resp.Evaluation); elemErr != nil {
		tb.Fatalf("unmarshal evaluation: %v", elemErr)
	}
	proof := &dleqpkg.Proof{}
	full := append(append([]byte{}, resp.ProofC...), resp.ProofS...)
	if proofErr := proof.UnmarshalBinary(suite.Group(), full); proofErr != nil {
		tb.Fatalf("unmarshal proof: %v", proofErr)
	}
	evaluation := &oprf.Evaluation{
		Elements: []group.Element{evalElement},
		Proof:    proof,
	}

	outputs, err := client.Finalize(finData, evaluation, anonauth.EpochInfo(epoch))
	if err != nil {
		tb.Fatalf("finalize: %v", err)
	}
	if len(outputs) != 1 {
		tb.Fatalf("unexpected output arity %d", len(outputs))
	}
	return input, outputs[0]
}

func TestRoundtrip_HappyPath(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	iss, ver, key := newTestStack(t, now, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    3,
		PoWDifficultyBits: 4,
	})
	pub, priv := registerPseudonym(t, iss)
	input, mac := issueAndFinalize(t, iss, key, pub, priv, iss.CurrentEpoch(now))
	if err := ver.Verify(input, mac); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestRoundtrip_ReplayRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	iss, ver, key := newTestStack(t, now, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    5,
		PoWDifficultyBits: 4,
	})
	pub, priv := registerPseudonym(t, iss)
	input, mac := issueAndFinalize(t, iss, key, pub, priv, iss.CurrentEpoch(now))
	if err := ver.Verify(input, mac); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := ver.Verify(input, mac); !errors.Is(err, anonauth.ErrTokenReplayed) {
		t.Fatalf("expected ErrTokenReplayed on replay, got %v", err)
	}
}

func TestRoundtrip_TamperedMACRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	iss, ver, key := newTestStack(t, now, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    5,
		PoWDifficultyBits: 4,
	})
	pub, priv := registerPseudonym(t, iss)
	input, mac := issueAndFinalize(t, iss, key, pub, priv, iss.CurrentEpoch(now))
	tampered := append([]byte{}, mac...)
	tampered[0] ^= 0x01
	if err := ver.Verify(input, tampered); !errors.Is(err, anonauth.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid on tamper, got %v", err)
	}
	// The original mac must still verify cleanly: tamper attempts
	// must not consume the spent-set slot.
	if err := ver.Verify(input, mac); err != nil {
		t.Fatalf("original verify after tamper: %v", err)
	}
}

func TestRoundtrip_CrossEpochRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	iss, ver, key := newTestStack(t, now, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    5,
		PoWDifficultyBits: 4,
	})
	pub, priv := registerPseudonym(t, iss)
	input, mac := issueAndFinalize(t, iss, key, pub, priv, iss.CurrentEpoch(now))

	// Advance both clocks past the grace window (two full epochs).
	future := now.Add(3 * time.Hour)
	iss.SetClockForTest(fixedClock(future))
	ver.SetClockForTest(fixedClock(future))

	if err := ver.Verify(input, mac); !errors.Is(err, anonauth.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid past grace, got %v", err)
	}
}

func TestRoundtrip_GraceEpochAccepted(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	iss, ver, key := newTestStack(t, now, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    5,
		PoWDifficultyBits: 4,
	})
	pub, priv := registerPseudonym(t, iss)
	input, mac := issueAndFinalize(t, iss, key, pub, priv, iss.CurrentEpoch(now))

	// Advance verifier clock by one epoch so the token's epoch is
	// now the immediately preceding one. The grace window must
	// still accept it.
	graced := now.Add(time.Hour + time.Minute)
	ver.SetClockForTest(fixedClock(graced))
	if err := ver.Verify(input, mac); err != nil {
		t.Fatalf("expected acceptance in grace epoch, got %v", err)
	}
}

func TestRoundtrip_RateLimit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	iss, _, key := newTestStack(t, now, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    2,
		PoWDifficultyBits: 4,
	})
	pub, priv := registerPseudonym(t, iss)
	for i := 0; i < 2; i++ {
		issueAndFinalize(t, iss, key, pub, priv, iss.CurrentEpoch(now))
	}

	suite := key.Suite()
	pubKey, _ := key.PublicKey()
	parsedPub := new(oprf.PublicKey)
	_ = parsedPub.UnmarshalBinary(suite, pubKey)
	client := oprf.NewPartialObliviousClient(suite, parsedPub)
	_, evalReq, _ := client.Blind([][]byte{[]byte("third")})
	blinded, _ := evalReq.Elements[0].MarshalBinaryCompress()
	signed := anonauth.CanonicalIssuancePayloadForTest(iss.CurrentEpoch(now), blinded)
	sig := ed25519.Sign(priv, signed)
	_, err := iss.IssueToken(context.Background(), anonauth.IssuanceRequest{
		Blinded:      blinded,
		PseudonymPub: pub,
		Signature:    sig,
		Epoch:        iss.CurrentEpoch(now),
	})
	if !errors.Is(err, anonauth.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}

	// Advancing one epoch resets the counter.
	next := now.Add(time.Hour)
	iss.SetClockForTest(fixedClock(next))
	signed2 := anonauth.CanonicalIssuancePayloadForTest(iss.CurrentEpoch(next), blinded)
	sig2 := ed25519.Sign(priv, signed2)
	if _, err := iss.IssueToken(context.Background(), anonauth.IssuanceRequest{
		Blinded:      blinded,
		PseudonymPub: pub,
		Signature:    sig2,
		Epoch:        iss.CurrentEpoch(next),
	}); err != nil {
		t.Fatalf("expected fresh quota in next epoch, got %v", err)
	}
}

func TestRoundtrip_ConcurrentIssueAndVerify(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	iss, ver, key := newTestStack(t, now, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    1000,
		PoWDifficultyBits: 4,
	})
	pub, priv := registerPseudonym(t, iss)

	const workers = 8
	const perWorker = 25
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				input, mac := issueAndFinalize(t, iss, key, pub, priv, iss.CurrentEpoch(now))
				if err := ver.Verify(input, mac); err != nil {
					t.Errorf("verify in worker: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	got := ver.SpentSetSizeForTest()
	if got != workers*perWorker {
		t.Fatalf("spent set size = %d, want %d", got, workers*perWorker)
	}
}

func TestRoundtrip_ForgedSignatureRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	iss, _, key := newTestStack(t, now, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    5,
		PoWDifficultyBits: 4,
	})
	pub, _ := registerPseudonym(t, iss)
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)

	suite := key.Suite()
	pubKey, _ := key.PublicKey()
	parsedPub := new(oprf.PublicKey)
	_ = parsedPub.UnmarshalBinary(suite, pubKey)
	client := oprf.NewPartialObliviousClient(suite, parsedPub)
	_, evalReq, _ := client.Blind([][]byte{[]byte("forged")})
	blinded, _ := evalReq.Elements[0].MarshalBinaryCompress()
	signed := anonauth.CanonicalIssuancePayloadForTest(iss.CurrentEpoch(now), blinded)
	sig := ed25519.Sign(attacker, signed)
	_, err := iss.IssueToken(context.Background(), anonauth.IssuanceRequest{
		Blinded:      blinded,
		PseudonymPub: pub,
		Signature:    sig,
		Epoch:        iss.CurrentEpoch(now),
	})
	if !errors.Is(err, anonauth.ErrPseudonymInvalid) {
		t.Fatalf("expected ErrPseudonymInvalid for forged signature, got %v", err)
	}
}

func TestCanonicalPayload_LayoutStable(t *testing.T) {
	t.Parallel()
	const tag = "moldd-anonauth-issue-v1"
	const epoch int64 = 0x1EADBEEF12345678
	blinded := []byte{0x01, 0x02, 0x03}
	want := append(append(append(append(append([]byte{}, tag...), 0), anonauth.EpochInfo(epoch)...), 0), blinded...)
	got := anonauth.CanonicalIssuancePayloadForTest(epoch, blinded)
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical payload changed: got %x want %x", got, want)
	}
}
