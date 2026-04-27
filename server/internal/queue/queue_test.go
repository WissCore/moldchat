// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package queue_test

import (
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

func TestValidateOwnerKey(t *testing.T) {
	t.Parallel()

	if err := queue.ValidateOwnerKey(make([]byte, 32)); err != nil {
		t.Errorf("32-byte key rejected: %v", err)
	}
	if err := queue.ValidateOwnerKey(make([]byte, 31)); err == nil {
		t.Error("31-byte key was not rejected")
	}
	if err := queue.ValidateOwnerKey(nil); err == nil {
		t.Error("nil key was not rejected")
	}
}
