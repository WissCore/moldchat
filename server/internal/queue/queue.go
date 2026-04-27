// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package queue defines the domain types for opaque message queues.
//
// A queue is an append-only mailbox addressed by an opaque identifier. The
// server treats every blob as opaque bytes; encryption and routing semantics
// are the responsibility of clients.
package queue

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Sizing and limits for queues and messages.
const (
	queueIDBytes   = 20
	messageIDBytes = 16

	X25519PubKeyBytes  = curve25519.PointSize
	Ed25519PubKeyBytes = ed25519.PublicKeySize
	DefaultTTL         = 24 * time.Hour
	MaxBlobSize        = 64 * 1024
)

// Sentinel errors returned by the storage and API layers.
var (
	ErrQueueNotFound     = errors.New("queue not found")
	ErrMessageNotFound   = errors.New("message not found")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrBlobTooLarge      = errors.New("blob exceeds maximum size")
	ErrEmptyBlob         = errors.New("blob is empty")
	ErrInvalidX25519Key  = errors.New("x25519 public key must be 32 bytes")
	ErrInvalidEd25519Key = errors.New("ed25519 public key must be 32 bytes")
	ErrServiceCapacity   = errors.New("service at capacity")
)

// OwnerKeys is the pair of public keys registered with a queue at creation
// time. X25519Pub is reserved for future Diffie-Hellman use (sealed-sender,
// per-queue ECDH); Ed25519Pub authenticates owner-only operations through a
// challenge-response signature.
type OwnerKeys struct {
	X25519Pub  []byte
	Ed25519Pub []byte
}

// Queue is the metadata for an opaque message mailbox.
type Queue struct {
	ID              string
	OwnerX25519Pub  []byte
	OwnerEd25519Pub []byte
	CreatedAt       time.Time
	ExpiresAt       time.Time
	LastAccess      time.Time
}

// Message is a single blob stored in a queue.
type Message struct {
	ID         string
	QueueID    string
	Blob       []byte
	ReceivedAt time.Time
}

// idEncoding is unpadded uppercase base32 (RFC 4648 §6).
var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewID returns a fresh queue identifier (32 base32 chars from 20 random bytes).
func NewID() (string, error) { return generateID(queueIDBytes) }

// NewMessageID returns a fresh message identifier (26 base32 chars from 16 random bytes).
func NewMessageID() (string, error) { return generateID(messageIDBytes) }

func generateID(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return idEncoding.EncodeToString(buf), nil
}

// ValidateOwnerKeys rejects key pairs whose lengths do not match the
// expected sizes for X25519 and Ed25519 public keys, and rejects the
// trivially-bad all-zero X25519 point. Full low-order point screening
// will land alongside the first DH consumer so it is exercised on the
// same code path that uses the key.
func ValidateOwnerKeys(k OwnerKeys) error {
	if len(k.X25519Pub) != X25519PubKeyBytes {
		return ErrInvalidX25519Key
	}
	if isAllZero(k.X25519Pub) {
		return ErrInvalidX25519Key
	}
	if len(k.Ed25519Pub) != Ed25519PubKeyBytes {
		return ErrInvalidEd25519Key
	}
	return nil
}

// isAllZero returns true iff every byte of b is zero.
func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
