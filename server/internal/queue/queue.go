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
	"crypto/rand"
	"encoding/base32"
	"errors"
	"time"
)

// Sizing and limits for queues and messages.
const (
	queueIDBytes   = 20
	messageIDBytes = 16

	OwnerKeyBytes = 32
	DefaultTTL    = 24 * time.Hour
	MaxBlobSize   = 64 * 1024
)

// Sentinel errors returned by the storage and API layers.
var (
	ErrQueueNotFound   = errors.New("queue not found")
	ErrMessageNotFound = errors.New("message not found")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrBlobTooLarge    = errors.New("blob exceeds maximum size")
	ErrEmptyBlob       = errors.New("blob is empty")
	ErrInvalidOwnerKey = errors.New("owner key must be 32 bytes")
)

// Queue is the metadata for an opaque message mailbox.
type Queue struct {
	ID         string
	OwnerKey   []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastAccess time.Time
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

// ValidateOwnerKey rejects keys whose length differs from OwnerKeyBytes.
func ValidateOwnerKey(key []byte) error {
	if len(key) != OwnerKeyBytes {
		return ErrInvalidOwnerKey
	}
	return nil
}
