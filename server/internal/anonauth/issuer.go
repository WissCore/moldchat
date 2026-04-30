// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
)

// IssuerConfig captures the operator-controlled knobs of the issuer.
// Zero values are not acceptable for any field; NewIssuer rejects an
// invalid config at construction so the failure surfaces at startup
// rather than under load.
type IssuerConfig struct {
	// Epoch is the wall-clock duration of one rate-limit window.
	// Tokens are bound to the epoch index in their POPRF info, so a
	// token issued at epoch N produces a different MAC under epoch
	// N+1 and cannot be replayed across epochs.
	Epoch time.Duration

	// PseudonymTTL is how long a freshly registered pseudonym remains
	// valid for token issuance. Beyond this point CheckAndIncrement
	// rejects with ErrPseudonymExpired and the client must re-register
	// (and re-solve a hashcash challenge).
	PseudonymTTL time.Duration

	// TokensPerEpoch is the per-pseudonym ceiling for one epoch.
	// Once the counter hits this value the issuer returns
	// ErrRateLimited until the epoch boundary advances.
	TokensPerEpoch uint32

	// PoWDifficultyBits is the leading-zero-bits target for the
	// hashcash challenge a client must solve before registering a
	// pseudonym. Bounded by [1, MaxDifficultyBits].
	PoWDifficultyBits uint8
}

// validate returns a descriptive error for the first invalid field.
// Errors here are meant for the operator, not for clients, so they
// carry the field name verbatim.
func (c IssuerConfig) validate() error {
	switch {
	case c.Epoch <= 0:
		return fmt.Errorf("anonauth: IssuerConfig.Epoch must be > 0")
	case c.PseudonymTTL <= 0:
		return fmt.Errorf("anonauth: IssuerConfig.PseudonymTTL must be > 0")
	case c.TokensPerEpoch == 0:
		return fmt.Errorf("anonauth: IssuerConfig.TokensPerEpoch must be > 0")
	case c.PoWDifficultyBits == 0 || c.PoWDifficultyBits > MaxDifficultyBits:
		return fmt.Errorf("anonauth: IssuerConfig.PoWDifficultyBits must be in [1, %d]", MaxDifficultyBits)
	}
	return nil
}

// Issuer is the server side of pseudonym registration and token
// issuance. It is safe for concurrent use; serialisation of the
// per-pseudonym counter happens inside the PseudonymStore.
type Issuer struct {
	cfg    IssuerConfig
	key    *IssuerKey
	pow    *PoWStore
	store  PseudonymStore
	server oprf.PartialObliviousServer
	now    func() time.Time
}

// NewIssuer constructs an issuer with the supplied configuration,
// derived key, and pseudonym backing store. The hashcash store is
// created internally; the caller does not own it.
func NewIssuer(cfg IssuerConfig, key *IssuerKey, store PseudonymStore) (*Issuer, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("anonauth: IssuerKey is required")
	}
	if store == nil {
		return nil, fmt.Errorf("anonauth: PseudonymStore is required")
	}
	pow, err := NewPoWStore(cfg.PoWDifficultyBits)
	if err != nil {
		return nil, err
	}
	return &Issuer{
		cfg:    cfg,
		key:    key,
		pow:    pow,
		store:  store,
		server: oprf.NewPartialObliviousServer(key.Suite(), key.privateKey()),
		now:    time.Now,
	}, nil
}

// Config returns the active configuration for the HTTP layer to
// surface in challenge responses.
func (i *Issuer) Config() IssuerConfig { return i.cfg }

// PoWChallenge returns a fresh hashcash challenge.
func (i *Issuer) PoWChallenge() (PoWChallenge, error) { return i.pow.Issue() }

// IssuerPublicKey returns the marshalled POPRF public key so clients
// can verify DLEQ proofs returned with each evaluation.
func (i *Issuer) IssuerPublicKey() ([]byte, error) { return i.key.PublicKey() }

// CurrentEpoch returns the epoch index for the supplied wall-clock
// time. Exposed so tests can inject a fixed clock; production callers
// should use the issuer's own clock under the hood. Times before the
// Unix epoch collapse to epoch 0.
func (i *Issuer) CurrentEpoch(now time.Time) int64 {
	return computeEpoch(now, i.cfg.Epoch)
}

// computeEpoch is the shared epoch-index calculator used by both the
// issuer and the verifier so the two cannot drift out of sync.
// Returns 0 for any time at or before the Unix epoch and for any
// non-positive epoch duration; both inputs are validated upstream
// (issuer/verifier construction reject epoch <= 0) so reaching the
// guards here means a misuse from a future caller.
func computeEpoch(now time.Time, epoch time.Duration) int64 {
	ns := now.UnixNano()
	epochNs := int64(epoch)
	if ns < 0 || epochNs <= 0 {
		return 0
	}
	return ns / epochNs
}

// EpochInfo encodes the supplied epoch index as the public info
// parameter that goes into the POPRF Evaluate call. Big-endian
// fixed-width keeps the encoding canonical and platform-independent.
// Negative epochs are a programming error: every in-package source of
// epoch values (computeEpoch, the JSON-decoded IssuanceRequest.Epoch
// after its issuer-side range check) is non-negative by construction.
// We panic rather than silently produce a high-bit-set encoding so
// the bug surfaces at the call site instead of as a mysterious
// FullEvaluate mismatch on the verification side.
func EpochInfo(epoch int64) []byte {
	if epoch < 0 {
		panic("anonauth: EpochInfo called with negative epoch")
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, uint64(epoch))
	return out
}

// RegisterPseudonym verifies a hashcash submission and persists a
// fresh pseudonym keyed by the supplied Ed25519 public key. The PoW
// challenge is consumed atomically — a successful registration
// removes the challenge so it cannot be reused for a second
// pseudonym. The supplied public key MUST be 32 bytes; any deviation
// is rejected as ErrPseudonymInvalid.
func (i *Issuer) RegisterPseudonym(ctx context.Context, pub ed25519.PublicKey, challenge, nonce []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrPseudonymInvalid
	}
	if err := i.pow.Verify(challenge, nonce); err != nil {
		return err
	}
	now := i.now()
	return i.store.Register(ctx, pub, now, now.Add(i.cfg.PseudonymTTL))
}

// IssuanceRequest bundles everything the client sends with a token
// issuance request. Blinded is the marshalled compressed-point form
// of the POPRF blinded element; PseudonymPub is the registered
// Ed25519 public key; Signature is the Ed25519 signature over the
// canonical issuance payload (see canonicalIssuancePayload).
type IssuanceRequest struct {
	Blinded      []byte
	PseudonymPub ed25519.PublicKey
	Signature    []byte
	Epoch        int64
}

// IssuanceResponse is the server's reply. Evaluation is the
// marshalled compressed-point form of the POPRF evaluation; ProofC
// and ProofS are the DLEQ proof scalars the client needs for
// Finalize.
type IssuanceResponse struct {
	Evaluation []byte
	ProofC     []byte
	ProofS     []byte
	Epoch      int64
	IssuedAt   time.Time
}

// canonicalIssuancePayload is the byte string the client signs and
// the server verifies. Format:
//
//	"moldd-anonauth-issue-v1" || 0x00 || epoch_be_uint64 || 0x00 || blinded
//
// Length-prefixing is unnecessary because epoch is fixed-width and
// blinded comes last; the leading domain tag prevents cross-protocol
// signature reuse against any other Ed25519 signing context the
// client might have.
func canonicalIssuancePayload(epoch int64, blinded []byte) []byte {
	const tag = "moldd-anonauth-issue-v1"
	out := make([]byte, 0, len(tag)+1+8+1+len(blinded))
	out = append(out, tag...)
	out = append(out, 0)
	out = append(out, EpochInfo(epoch)...)
	out = append(out, 0)
	out = append(out, blinded...)
	return out
}

// IssueToken runs the full issuance flow for one request.
//
//  1. Verify the supplied epoch matches the server's current epoch
//     (a one-epoch tolerance window is intentionally NOT applied
//     here — issuance is bound to the present, not the recent past,
//     so a client whose clock is skewed re-fetches a challenge).
//  2. Verify the Ed25519 signature against the canonical payload.
//  3. Atomically check-and-increment the per-pseudonym counter.
//  4. Run POPRF.Evaluate with the epoch as info.
//  5. Marshal the evaluation element and the DLEQ proof scalars.
func (i *Issuer) IssueToken(ctx context.Context, req IssuanceRequest) (*IssuanceResponse, error) {
	now := i.now()
	currentEpoch := i.CurrentEpoch(now)
	if req.Epoch != currentEpoch {
		return nil, ErrPseudonymInvalid
	}
	if len(req.PseudonymPub) != ed25519.PublicKeySize {
		return nil, ErrPseudonymInvalid
	}
	payload := canonicalIssuancePayload(req.Epoch, req.Blinded)
	if !ed25519.Verify(req.PseudonymPub, payload, req.Signature) {
		return nil, ErrPseudonymInvalid
	}
	// Validate the blinded element BEFORE consuming the per-epoch
	// counter slot. A malformed element from a registered client must
	// not cost the client a token of their quota; the signature has
	// already proved the request is theirs, so the failure mode is
	// "bad client encoding" rather than a flooding attempt and the
	// fair response is to reject without charging.
	suite := i.key.Suite()
	blinded := suite.Group().NewElement()
	if err := blinded.UnmarshalBinary(req.Blinded); err != nil {
		return nil, fmt.Errorf("anonauth: unmarshal blinded element: %w", err)
	}
	if err := i.store.CheckAndIncrement(ctx, req.PseudonymPub, currentEpoch, i.cfg.TokensPerEpoch, now); err != nil {
		return nil, err
	}

	evalReq := &oprf.EvaluationRequest{Elements: []group.Element{blinded}}
	evaluation, err := i.server.Evaluate(evalReq, EpochInfo(currentEpoch))
	if err != nil {
		return nil, fmt.Errorf("anonauth: poprf evaluate: %w", err)
	}
	if len(evaluation.Elements) != 1 {
		return nil, fmt.Errorf("anonauth: unexpected evaluation arity %d", len(evaluation.Elements))
	}
	evalBytes, err := evaluation.Elements[0].MarshalBinaryCompress()
	if err != nil {
		return nil, fmt.Errorf("anonauth: marshal evaluation: %w", err)
	}
	proofBytes, err := evaluation.Proof.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("anonauth: marshal proof: %w", err)
	}
	c, s, err := splitDLEQProof(proofBytes, suite)
	if err != nil {
		return nil, err
	}
	return &IssuanceResponse{
		Evaluation: evalBytes,
		ProofC:     c,
		ProofS:     s,
		Epoch:      currentEpoch,
		IssuedAt:   now,
	}, nil
}

// splitDLEQProof breaks the DLEQ proof's MarshalBinary output into
// its (c, s) scalar halves. circl writes both scalars concatenated
// in their fixed-width compressed form; the suite's group dictates
// the scalar byte length so the split point is deterministic.
func splitDLEQProof(raw []byte, suite oprf.Suite) (c, s []byte, err error) {
	scalarLenU := suite.Group().Params().ScalarLength
	// ScalarLength is the byte width of a group scalar, bounded by
	// the curve definition (≤ 64 bytes for any of the supported
	// suites). The explicit cap turns a future suite with an absurd
	// scalar size into an error rather than a silent panic.
	if scalarLenU > 1024 {
		return nil, nil, fmt.Errorf("anonauth: implausible scalar length %d", scalarLenU)
	}
	scalarLen := int(scalarLenU)
	if len(raw) != 2*scalarLen {
		return nil, nil, fmt.Errorf("anonauth: dleq proof length %d not 2*scalar (%d)", len(raw), scalarLen)
	}
	return raw[:scalarLen], raw[scalarLen:], nil
}
