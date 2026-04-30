// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package anonauth

import (
	"fmt"

	"github.com/cloudflare/circl/oprf"
)

// MasterSeedBytes is the length of the seed material consumed by
// DeriveIssuerKey. It is intentionally identical to the storage layer
// seed length so callers can reuse the same secret without truncating
// or padding.
const MasterSeedBytes = 32

// issuerKeyInfo is the HKDF info string used to derive the POPRF
// issuer private key. The "v1" suffix is a key-versioning hook: any
// future change to the derivation path (suite, mode, or info layout)
// MUST bump the version so a key rotated under the new scheme cannot
// collide with one derived under the old scheme.
const issuerKeyInfo = "moldd-anonauth-issuer-key-v1"

// IssuerKey wraps the POPRF private key together with its public
// counterpart. The private key never leaves the process and is wiped
// on Close; the public key is exposed via PublicKey for clients to use
// during Finalize verification.
type IssuerKey struct {
	private *oprf.PrivateKey
	public  *oprf.PublicKey
	suite   oprf.Suite
}

// Suite is the POPRF suite chosen for the deployment. Ristretto255
// with SHA-512 produces 32-byte group elements and 64-byte finalised
// outputs; the smaller group elements keep the issued evaluation
// payload compact, and Ristretto255 has no cofactor concerns that the
// server has to mitigate.
func Suite() oprf.Suite { return oprf.SuiteRistretto255 }

// DeriveIssuerKey produces the deterministic POPRF private key used
// by the issuer. The derivation goes through circl's DeriveKey,
// which already runs HashToScalar with a domain-separated DST tag
// over the seed and info string; layering an additional HKDF on top
// would not strengthen anything but would be one more place a future
// reviewer must understand. The version-tagged info string namespaces
// this key from any other future use of the same seed.
func DeriveIssuerKey(seed []byte) (*IssuerKey, error) {
	if len(seed) != MasterSeedBytes {
		return nil, fmt.Errorf("anonauth: seed must be %d bytes", MasterSeedBytes)
	}
	suite := Suite()
	priv, err := oprf.DeriveKey(suite, oprf.PartialObliviousMode, seed, []byte(issuerKeyInfo))
	if err != nil {
		return nil, fmt.Errorf("anonauth: derive issuer key: %w", err)
	}
	return &IssuerKey{private: priv, public: priv.Public(), suite: suite}, nil
}

// PublicKey returns the marshalled compressed-point form of the
// issuer's public key. Clients embed this in their POPRF.Finalize
// step to verify the DLEQ proof returned with each evaluation, which
// is what guarantees that all clients see the same key (and therefore
// cannot be partitioned by per-client key choice).
func (k *IssuerKey) PublicKey() ([]byte, error) {
	return k.public.MarshalBinary()
}

// Suite returns the POPRF suite this key was derived for.
func (k *IssuerKey) Suite() oprf.Suite { return k.suite }

// privateKey is package-internal so the issuance handler can pass it
// to the POPRF server without exporting the raw key material.
func (k *IssuerKey) privateKey() *oprf.PrivateKey { return k.private }
