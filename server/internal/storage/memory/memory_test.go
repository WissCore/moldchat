// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package memory_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/WissCore/moldchat/server/internal/queue"
	"github.com/WissCore/moldchat/server/internal/storage/memory"
)

func validKeys() queue.OwnerKeys {
	x := make([]byte, queue.X25519PubKeyBytes)
	x[0] = 1
	return queue.OwnerKeys{
		X25519Pub:  x,
		Ed25519Pub: make([]byte, queue.Ed25519PubKeyBytes),
	}
}

func TestCreateQueue_RejectsInvalidKeys(t *testing.T) {
	t.Parallel()

	s := memory.New()

	nonZeroX := make([]byte, queue.X25519PubKeyBytes)
	nonZeroX[0] = 1

	bad := queue.OwnerKeys{X25519Pub: make([]byte, 31), Ed25519Pub: make([]byte, 32)}
	if _, err := s.CreateQueue(context.Background(), bad); !errors.Is(err, queue.ErrInvalidX25519Key) {
		t.Errorf("31-byte X25519: got %v, want ErrInvalidX25519Key", err)
	}

	bad = queue.OwnerKeys{X25519Pub: nonZeroX, Ed25519Pub: make([]byte, 31)}
	if _, err := s.CreateQueue(context.Background(), bad); !errors.Is(err, queue.ErrInvalidEd25519Key) {
		t.Errorf("31-byte Ed25519: got %v, want ErrInvalidEd25519Key", err)
	}
}

func TestPutAndListMessages_RoundTrip(t *testing.T) {
	t.Parallel()

	s := memory.New()
	ctx := context.Background()
	q, err := s.CreateQueue(ctx, validKeys())
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	want := []byte("opaque-blob-1")
	if _, putErr := s.PutMessage(ctx, q.ID, want); putErr != nil {
		t.Fatalf("PutMessage: %v", putErr)
	}
	msgs, hasMore, err := s.ListMessages(ctx, q.ID, 10)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if hasMore {
		t.Errorf("hasMore: got true, want false")
	}
	if len(msgs) != 1 {
		t.Fatalf("len(msgs): got %d, want 1", len(msgs))
	}
	if !bytes.Equal(msgs[0].Blob, want) {
		t.Errorf("blob round-trip: got %q, want %q", msgs[0].Blob, want)
	}
}

func TestPutMessage_RejectsEmpty(t *testing.T) {
	t.Parallel()

	s := memory.New()
	ctx := context.Background()
	q, err := s.CreateQueue(ctx, validKeys())
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	if _, err := s.PutMessage(ctx, q.ID, nil); !errors.Is(err, queue.ErrEmptyBlob) {
		t.Errorf("PutMessage(nil): got %v, want ErrEmptyBlob", err)
	}
}

func TestPutMessage_RejectsTooLarge(t *testing.T) {
	t.Parallel()

	s := memory.New()
	ctx := context.Background()
	q, err := s.CreateQueue(ctx, validKeys())
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	if _, err := s.PutMessage(ctx, q.ID, make([]byte, queue.MaxBlobSize+1)); !errors.Is(err, queue.ErrBlobTooLarge) {
		t.Errorf("PutMessage oversized: got %v, want ErrBlobTooLarge", err)
	}
}

func TestPutMessage_QueueNotFound(t *testing.T) {
	t.Parallel()

	s := memory.New()
	if _, err := s.PutMessage(context.Background(), "missing", []byte("x")); !errors.Is(err, queue.ErrQueueNotFound) {
		t.Errorf("PutMessage on missing queue: got %v, want ErrQueueNotFound", err)
	}
}

func TestListMessages_HasMore(t *testing.T) {
	t.Parallel()

	s := memory.New()
	ctx := context.Background()
	q, err := s.CreateQueue(ctx, validKeys())
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, putErr := s.PutMessage(ctx, q.ID, []byte{byte(i)}); putErr != nil {
			t.Fatalf("PutMessage[%d]: %v", i, putErr)
		}
	}
	msgs, hasMore, err := s.ListMessages(ctx, q.ID, 3)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if !hasMore {
		t.Errorf("hasMore: got false, want true")
	}
	if len(msgs) != 3 {
		t.Errorf("len(msgs): got %d, want 3", len(msgs))
	}
}

func TestDeleteMessage_RoundTrip(t *testing.T) {
	t.Parallel()

	s := memory.New()
	ctx := context.Background()
	q, err := s.CreateQueue(ctx, validKeys())
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	m, err := s.PutMessage(ctx, q.ID, []byte("payload"))
	if err != nil {
		t.Fatalf("PutMessage: %v", err)
	}
	if delErr := s.DeleteMessage(ctx, q.ID, m.ID); delErr != nil {
		t.Fatalf("DeleteMessage: %v", delErr)
	}
	msgs, _, err := s.ListMessages(ctx, q.ID, 10)
	if err != nil {
		t.Fatalf("ListMessages after delete: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("after delete: got %d msgs, want 0", len(msgs))
	}
	if err := s.DeleteMessage(ctx, q.ID, m.ID); !errors.Is(err, queue.ErrMessageNotFound) {
		t.Errorf("second DeleteMessage: got %v, want ErrMessageNotFound", err)
	}
}
