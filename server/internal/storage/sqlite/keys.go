// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sqlite implements storage.Storage on top of a SQLCipher-encrypted
// SQLite database. Per-queue databases live in their own files; their
// encryption keys are derived from a single master seed plus a per-queue
// random salt via HKDF, so deleting the master row crypto-shreds the
// queue even if the file is later recovered from a backup or snapshot.
package sqlite

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

// MasterSeedBytes is the length of the master seed in bytes.
const MasterSeedBytes = 32

// MasterSeed is a high-entropy 32-byte secret used to derive per-database
// SQLCipher keys. It is loaded once at startup; production deployments should
// fetch it from an HSM or KMS rather than from an environment variable.
type MasterSeed [MasterSeedBytes]byte

// QueueKeySaltBytes is the length of the per-queue salt stored in the
// master database alongside each queue row.
const QueueKeySaltBytes = 32

// envVarMasterSeed is the environment variable that supplies the seed.
const envVarMasterSeed = "MOLDD_MASTER_SEED"

// Sentinel errors related to seed loading.
var (
	ErrMasterSeedMissing = errors.New("master seed missing: set " + envVarMasterSeed)
	ErrMasterSeedInvalid = fmt.Errorf("master seed must be base64-encoded %d bytes", MasterSeedBytes)
	ErrInvalidQueueSalt  = fmt.Errorf("queue salt must be %d bytes", QueueKeySaltBytes)
)

// LoadMasterSeed reads the seed from the environment variable.
//
// The value must be a base64 encoding (standard, with or without padding) of
// exactly MasterSeedBytes bytes.
func LoadMasterSeed() (MasterSeed, error) {
	raw := os.Getenv(envVarMasterSeed)
	if raw == "" {
		return MasterSeed{}, ErrMasterSeedMissing
	}
	return parseSeed(raw)
}

func parseSeed(raw string) (MasterSeed, error) {
	for _, dec := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		buf, err := dec.DecodeString(raw)
		if err == nil && len(buf) == MasterSeedBytes {
			var seed MasterSeed
			copy(seed[:], buf)
			return seed, nil
		}
	}
	return MasterSeed{}, ErrMasterSeedInvalid
}

// HKDF info strings. Versioning the namespace allows a future migration to
// rotate keys without losing access to data encrypted under the old scheme.
const (
	infoMasterDB = "moldd-master-key-v1"
	infoQueueDB  = "moldd-queue-key-v1|"
	infoFilename = "moldd-queue-filename-v1"
)

// MasterKey returns the SQLCipher hex key (without the 'x' wrapper) for
// the master metadata database. The error is reserved for any future
// HKDF-side failure; SHA-256 single-block expansion never fails today.
func (m MasterSeed) MasterKey() (string, error) {
	return deriveKey(m[:], nil, []byte(infoMasterDB))
}

// DeriveQueueKey returns the SQLCipher hex key (without the 'x' wrapper)
// for the per-queue database identified by queueID and bound to the
// supplied per-queue salt. Once the salt is overwritten or deleted, the
// queue's database file becomes unrecoverable even when the master seed
// is intact — this is the crypto-shred property.
func (m MasterSeed) DeriveQueueKey(queueID string, salt []byte) (string, error) {
	if len(salt) != QueueKeySaltBytes {
		return "", ErrInvalidQueueSalt
	}
	info := append([]byte(infoQueueDB), []byte(queueID)...)
	return deriveKey(m[:], salt, info)
}

// QueueFilename returns the on-disk basename for the queue's database
// file. The basename is HMAC(seed, queueID) so a directory listing of the
// data dir does not reveal which queue identifiers exist; mapping a
// queueID to its file requires the master seed.
func (m MasterSeed) QueueFilename(queueID string) string {
	mac := hmac.New(sha256.New, m[:])
	_, _ = mac.Write([]byte(infoFilename))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(queueID))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// deriveKey runs HKDF-Extract+Expand with SHA-256 over the IKM and salt
// and returns 32 bytes hex-encoded, ready to be embedded in a SQLCipher
// PRAGMA key.
func deriveKey(ikm, salt, info []byte) (string, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, MasterSeedBytes)
	if _, err := io.ReadFull(r, out); err != nil {
		return "", fmt.Errorf("hkdf read: %w", err)
	}
	return hex.EncodeToString(out), nil
}
