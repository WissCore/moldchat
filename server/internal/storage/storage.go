// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package storage defines the persistence interface used by the API layer.
//
// The interface decouples API handlers from the backing store; an in-memory
// implementation lives under storage/memory. Persistent encrypted backends
// can be added behind the same interface without touching handler code.
package storage

import (
	"context"

	"github.com/WissCore/moldchat/server/internal/queue"
)

// Storage is implemented by any backing store for queues and messages.
//
// All methods are expected to be safe for concurrent use.
type Storage interface {
	CreateQueue(ctx context.Context, keys queue.OwnerKeys) (*queue.Queue, error)
	GetQueue(ctx context.Context, id string) (*queue.Queue, error)
	PutMessage(ctx context.Context, queueID string, blob []byte) (*queue.Message, error)
	ListMessages(ctx context.Context, queueID string, limit int) (msgs []*queue.Message, hasMore bool, err error)
	DeleteMessage(ctx context.Context, queueID, messageID string) error
}
