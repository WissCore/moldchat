// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auth implements challenge-response authentication for queue
// owner-only operations.
//
// Flow:
//
//  1. Client requests GET /v1/queues/{id}/auth-challenge.
//     Server returns a fresh 32-byte nonce with a 30-second TTL.
//  2. Client signs the canonical payload
//     "moldd-v1-auth" || 0x00 || nonce || 0x00 || queue_id || 0x00 ||
//     method || 0x00 || path
//     using the Ed25519 private key whose public half was registered when
//     the queue was created.
//  3. Client sends the request with header
//     Authorization: ED25519-Sig <signature_b64>,<pubkey_b64>,<nonce_b64>
//     The header format is comma-separated bare base64 fields rather than
//     the auth-params syntax of RFC 7235; we deliberately keep it compact
//     because every byte of an authenticated request matters and the scheme
//     is private to MoldChat clients.
//  4. Server re-derives the canonical payload, checks the supplied pubkey
//     matches the one registered with the queue (constant-time), verifies
//     the signature, and burns the nonce so it cannot be replayed.
//
// The nonce store is in-memory, has a hard cap on outstanding entries,
// and is GCed lazily on each Issue call.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"
)

// Sizing and TTLs for challenge nonces.
const (
	NonceBytes = 32
	NonceTTL   = 30 * time.Second
	AuthScheme = "ED25519-Sig"

	// MaxOutstandingNonces caps the in-memory map of issued-but-not-yet-used
	// nonces. Once reached, Issue returns ErrIssuerSaturated and the caller
	// is expected to surface a 503 to the client. The cap protects the
	// process against memory exhaustion when /auth-challenge is hit at a
	// rate higher than legitimate clients require; finer-grained per-client
	// rate limiting belongs in the L4 anti-spam layer.
	MaxOutstandingNonces = 10_000

	domainTag = "moldd-v1-auth"
	separator = 0x00
)

// Sentinel errors returned by the auth layer.
var (
	ErrAuthorizationMissing   = errors.New("authorization header missing")
	ErrAuthorizationMalformed = errors.New("authorization header malformed")
	ErrSignatureInvalid       = errors.New("signature invalid")
	ErrReplay                 = errors.New("nonce already used or expired")
	ErrIssuerSaturated        = errors.New("issuer at capacity")
)

// Issuer issues nonces and verifies challenge-response signatures.
//
// All methods are safe for concurrent use. Memory usage is bounded by
// MaxOutstandingNonces; expired entries are reaped lazily on each call
// to Issue.
type Issuer struct {
	mu     sync.Mutex
	issued map[string]time.Time // nonce → expires_at
	now    func() time.Time
}

// NewIssuer returns a fresh Issuer using time.Now as its clock.
func NewIssuer() *Issuer {
	return &Issuer{
		issued: make(map[string]time.Time),
		now:    time.Now,
	}
}

// Issue returns a fresh nonce together with its expiry timestamp.
// The nonce is single-use and remembered until Verify consumes it or it
// expires. Sweeping of expired entries is amortised: it runs only when
// the live set has hit the MaxOutstandingNonces cap, which keeps the
// fast path O(1) under normal load. After sweeping, if the cap is still
// reached, ErrIssuerSaturated is returned.
func (i *Issuer) Issue() (nonce []byte, expiresAt time.Time, err error) {
	nonce = make([]byte, NonceBytes)
	if _, err = rand.Read(nonce); err != nil {
		return nil, time.Time{}, err
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	now := i.now()
	if len(i.issued) >= MaxOutstandingNonces {
		for k, exp := range i.issued {
			if !exp.After(now) {
				delete(i.issued, k)
			}
		}
		if len(i.issued) >= MaxOutstandingNonces {
			return nil, time.Time{}, ErrIssuerSaturated
		}
	}

	expiresAt = now.Add(NonceTTL)
	i.issued[string(nonce)] = expiresAt
	return nonce, expiresAt, nil
}

// Verify checks the signature against pubkey for the canonical payload
// derived from (nonce, queueID, method, path). On success the nonce is
// burned so subsequent calls return ErrReplay. The nonce is also burned
// on signature failure: a single nonce must never authorise more than
// one verification attempt, regardless of outcome.
func (i *Issuer) Verify(pubkey ed25519.PublicKey, nonce, sig []byte, queueID, method, path string) error {
	if len(pubkey) != ed25519.PublicKeySize {
		return ErrSignatureInvalid
	}
	if len(nonce) != NonceBytes {
		return ErrAuthorizationMalformed
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrAuthorizationMalformed
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	expiresAt, ok := i.issued[string(nonce)]
	if !ok {
		return ErrReplay
	}
	if !expiresAt.After(i.now()) {
		delete(i.issued, string(nonce))
		return ErrReplay
	}

	payload := canonicalPayload(nonce, queueID, method, path)
	if !ed25519.Verify(pubkey, payload, sig) {
		delete(i.issued, string(nonce))
		return ErrSignatureInvalid
	}
	delete(i.issued, string(nonce))
	return nil
}

// canonicalPayload returns the bytes that must be signed by the client.
// The format is documented at the top of this package.
func canonicalPayload(nonce []byte, queueID, method, path string) []byte {
	out := make([]byte, 0, len(domainTag)+1+len(nonce)+1+len(queueID)+1+len(method)+1+len(path))
	out = append(out, domainTag...)
	out = append(out, separator)
	out = append(out, nonce...)
	out = append(out, separator)
	out = append(out, queueID...)
	out = append(out, separator)
	out = append(out, method...)
	out = append(out, separator)
	out = append(out, path...)
	return out
}

// CanonicalPayload exposes the canonical signing payload for clients and
// integration tests. Callers should not mutate the returned slice.
func CanonicalPayload(nonce []byte, queueID, method, path string) []byte {
	return canonicalPayload(nonce, queueID, method, path)
}

// ParseAuthorization parses an "ED25519-Sig <sig_b64>,<pubkey_b64>,<nonce_b64>"
// header into raw signature, public-key, and nonce bytes. The auth-scheme
// token is matched case-insensitively per RFC 7235 §2.1, and the
// separator between the scheme and the credentials may be any run of
// SP/HTAB characters as the same RFC permits.
func ParseAuthorization(header string) (sig, pubkey, nonce []byte, err error) {
	if header == "" {
		return nil, nil, nil, ErrAuthorizationMissing
	}
	sep := strings.IndexAny(header, " \t")
	if sep < 0 {
		return nil, nil, nil, ErrAuthorizationMalformed
	}
	if !strings.EqualFold(header[:sep], AuthScheme) {
		return nil, nil, nil, ErrAuthorizationMalformed
	}
	rest := strings.TrimLeft(header[sep+1:], " \t")
	parts := strings.Split(rest, ",")
	if len(parts) != 3 {
		return nil, nil, nil, ErrAuthorizationMalformed
	}
	sig, err = base64.StdEncoding.DecodeString(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, nil, nil, ErrAuthorizationMalformed
	}
	pubkey, err = base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, nil, nil, ErrAuthorizationMalformed
	}
	nonce, err = base64.StdEncoding.DecodeString(strings.TrimSpace(parts[2]))
	if err != nil {
		return nil, nil, nil, ErrAuthorizationMalformed
	}
	return sig, pubkey, nonce, nil
}

// FormatAuthorization is the inverse of ParseAuthorization, primarily for
// client and test use.
func FormatAuthorization(sig, pubkey, nonce []byte) string {
	return AuthScheme + " " +
		base64.StdEncoding.EncodeToString(sig) + "," +
		base64.StdEncoding.EncodeToString(pubkey) + "," +
		base64.StdEncoding.EncodeToString(nonce)
}
