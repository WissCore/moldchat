// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package queue_test

import (
	"errors"
	"testing"

	"github.com/WissCore/moldchat/server/internal/queue"
)

func TestNewID_Unique(t *testing.T) {
	t.Parallel()

	a, err := queue.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	b, err := queue.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if a == b {
		t.Errorf("two NewID calls returned the same id: %s", a)
	}
	if got := len(a); got != 32 {
		t.Errorf("queue id length: got %d, want 32", got)
	}
}

func TestNewMessageID_Length(t *testing.T) {
	t.Parallel()

	id, err := queue.NewMessageID()
	if err != nil {
		t.Fatalf("NewMessageID: %v", err)
	}
	if got := len(id); got != 26 {
		t.Errorf("message id length: got %d, want 26", got)
	}
}

func TestValidateOwnerKeys(t *testing.T) {
	t.Parallel()

	good := queue.OwnerKeys{
		X25519Pub:  make([]byte, queue.X25519PubKeyBytes),
		Ed25519Pub: make([]byte, queue.Ed25519PubKeyBytes),
	}
	if err := queue.ValidateOwnerKeys(good); err != nil {
		t.Errorf("valid pair rejected: %v", err)
	}

	shortX := good
	shortX.X25519Pub = make([]byte, 31)
	if err := queue.ValidateOwnerKeys(shortX); !errors.Is(err, queue.ErrInvalidX25519Key) {
		t.Errorf("short X25519: got %v, want ErrInvalidX25519Key", err)
	}

	shortEd := good
	shortEd.Ed25519Pub = make([]byte, 31)
	if err := queue.ValidateOwnerKeys(shortEd); !errors.Is(err, queue.ErrInvalidEd25519Key) {
		t.Errorf("short Ed25519: got %v, want ErrInvalidEd25519Key", err)
	}

	if err := queue.ValidateOwnerKeys(queue.OwnerKeys{}); !errors.Is(err, queue.ErrInvalidX25519Key) {
		t.Errorf("empty pair: got %v, want ErrInvalidX25519Key", err)
	}
}
