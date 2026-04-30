// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package anonauth implements anonymous, rate-limited credentials for
// gating message-send operations.
//
// The construction has three pieces:
//
//   - Pseudonym registration. A client generates a fresh Ed25519 key pair,
//     solves a hashcash proof of work over a server-supplied challenge, and
//     submits the public key. The server stores the public key together
//     with creation time and a per-epoch token counter. The pseudonym is
//     long-lived (default 30 days) and acts as the rate-limit handle —
//     no IP, no fingerprint, no user-supplied identifier is ever recorded.
//
//   - Token issuance. The pseudonym signs a fresh blinded element with its
//     Ed25519 private key. The server verifies the signature, atomically
//     increments the per-pseudonym counter against the configured per-epoch
//     limit, and runs a Partial Oblivious PRF (RFC 9497, POPRF mode) over
//     the blinded element with the current epoch as the public info. The
//     evaluation plus a DLEQ proof are returned to the client, which
//     unblinds and finalises the token.
//
//     The POPRF info parameter cryptographically binds the token to its
//     epoch: a token finalised at epoch N produces a different MAC under
//     epoch N+1, so cross-epoch reuse is detected on verify rather than
//     by tracking expiry timestamps.
//
//   - Token verification. The client presents (input, mac) on a
//     gated request. The server runs the POPRF FullEvaluate over the
//     input with the current epoch info, constant-time-compares against
//     the supplied mac, and consults a bounded spent-set keyed by mac to
//     prevent single-token replay within the epoch. A one-epoch grace
//     window allows a token finalised seconds before an epoch boundary to
//     remain redeemable.
//
// The construction provides anonymity for the redemption step (the server
// learns nothing about which pseudonym redeemed a given token) and a
// rate limit at issuance (the per-pseudonym counter is the only authority
// on how many tokens an actor may obtain per epoch). Sybil resistance is
// best-effort and rests on the cost of solving the hashcash challenge per
// pseudonym; difficulty is operator-tunable so it can be cranked under
// active flooding without re-issuing client software.
//
// What this package does NOT provide:
//
//   - Strong anti-Sybil. Hashcash with SHA-256 grinding is asymmetric (the
//     server verifies in one hash) but a GPU/ASIC adversary can grind
//     pseudonyms cheaper than a CPU client. Operators must rely on
//     external signals (network-level rate caps, abuse heuristics) for
//     sustained flood resistance; this package supplies the per-pseudonym
//     ceiling and replay protection only.
//   - Verifiable per-presentation unlinkability across multiple servers.
//     A single issuer key is used for all clients in a deployment, which
//     gives unlinkability among clients sharing that issuer; multi-issuer
//     federation is out of scope here.
package anonauth

import "errors"

// Sentinel errors surfaced by the issuer and verifier. Callers MUST NOT
// distinguish between them in client-visible responses; doing so would
// turn the API into a side channel that reveals which check rejected a
// given request. The HTTP layer collapses all of them to a single 401 or
// 429 with no diagnostic hint in the body.
var (
	// ErrPoWInvalid is returned when the supplied hashcash nonce does
	// not satisfy the configured difficulty against the issued
	// challenge. Distinguishable in tests, opaque on the wire.
	ErrPoWInvalid = errors.New("hashcash proof of work invalid")

	// ErrPoWChallengeUnknown is returned when the supplied challenge
	// id is not in the outstanding-challenge map (expired, never
	// issued, or already consumed).
	ErrPoWChallengeUnknown = errors.New("hashcash challenge unknown or expired")

	// ErrPseudonymInvalid is returned for any failure to bind a
	// request to a registered pseudonym: missing record, malformed
	// public key, signature mismatch, or expired pseudonym.
	ErrPseudonymInvalid = errors.New("pseudonym binding invalid")

	// ErrRateLimited is returned when the per-pseudonym per-epoch
	// counter has already reached the configured ceiling. The HTTP
	// layer maps this to 429 Too Many Requests.
	ErrRateLimited = errors.New("pseudonym rate limit reached for current epoch")

	// ErrTokenInvalid is returned when a presented token fails POPRF
	// FullEvaluate against the current or grace epoch. Wraps both
	// "wrong mac" and "wrong input length"; clients see one 401.
	ErrTokenInvalid = errors.New("anonymous token invalid")

	// ErrTokenReplayed is returned when a presented token's mac is
	// already present in the spent-set for its matching epoch.
	ErrTokenReplayed = errors.New("anonymous token already spent")

	// ErrIssuerSaturated is returned when the in-memory outstanding
	// challenge map is full. The HTTP layer maps this to 503 so a
	// flood spike does not cascade into OOM.
	ErrIssuerSaturated = errors.New("issuer outstanding challenge cap reached")
)
