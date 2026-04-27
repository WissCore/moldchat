// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package memory is an in-memory implementation of storage.Storage.
//
// State is lost when the process restarts; intended for tests and short-lived
// development instances. A persistent encrypted backend can be added behind
// the same interface without touching API code.
package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/WissCore/moldchat/server/internal/queue"
)

// Storage holds all queues and messages in process memory.
type Storage struct {
	mu       sync.RWMutex
	queues   map[string]*queue.Queue
	messages map[string][]*queue.Message
}

// New returns an empty in-memory store.
func New() *Storage {
	return &Storage{
		queues:   make(map[string]*queue.Queue),
		messages: make(map[string][]*queue.Message),
	}
}

// CreateQueue registers a new queue owned by the given key.
func (s *Storage) CreateQueue(_ context.Context, ownerKey []byte) (*queue.Queue, error) {
	if err := queue.ValidateOwnerKey(ownerKey); err != nil {
		return nil, err
	}
	id, err := queue.NewID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	q := &queue.Queue{
		ID:         id,
		OwnerKey:   append([]byte(nil), ownerKey...),
		CreatedAt:  now,
		ExpiresAt:  now.Add(queue.DefaultTTL),
		LastAccess: now,
	}
	s.mu.Lock()
	s.queues[id] = q
	s.mu.Unlock()
	return cloneQueue(q), nil
}

// GetQueue returns a copy of the queue metadata or queue.ErrQueueNotFound.
func (s *Storage) GetQueue(_ context.Context, id string) (*queue.Queue, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q, ok := s.queues[id]
	if !ok {
		return nil, queue.ErrQueueNotFound
	}
	return cloneQueue(q), nil
}

// PutMessage appends an opaque blob to the queue and bumps last-access.
func (s *Storage) PutMessage(_ context.Context, queueID string, blob []byte) (*queue.Message, error) {
	switch {
	case len(blob) == 0:
		return nil, queue.ErrEmptyBlob
	case len(blob) > queue.MaxBlobSize:
		return nil, queue.ErrBlobTooLarge
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	q, ok := s.queues[queueID]
	if !ok {
		return nil, queue.ErrQueueNotFound
	}
	id, err := queue.NewMessageID()
	if err != nil {
		return nil, err
	}
	m := &queue.Message{
		ID:         id,
		QueueID:    queueID,
		Blob:       append([]byte(nil), blob...),
		ReceivedAt: time.Now().UTC(),
	}
	s.messages[queueID] = append(s.messages[queueID], m)
	q.LastAccess = m.ReceivedAt
	return cloneMessage(m), nil
}

// ListMessages returns up to limit messages in arrival order plus a hasMore flag.
func (s *Storage) ListMessages(_ context.Context, queueID string, limit int) ([]*queue.Message, bool, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	q, ok := s.queues[queueID]
	if !ok {
		return nil, false, queue.ErrQueueNotFound
	}
	src := s.messages[queueID]
	sort.SliceStable(src, func(i, j int) bool { return src[i].ReceivedAt.Before(src[j].ReceivedAt) })

	hasMore := false
	if len(src) > limit {
		src = src[:limit]
		hasMore = true
	}
	out := make([]*queue.Message, len(src))
	for i, m := range src {
		out[i] = cloneMessage(m)
	}
	q.LastAccess = time.Now().UTC()
	return out, hasMore, nil
}

// DeleteMessage removes a single message from the queue.
func (s *Storage) DeleteMessage(_ context.Context, queueID, messageID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	q, ok := s.queues[queueID]
	if !ok {
		return queue.ErrQueueNotFound
	}
	msgs := s.messages[queueID]
	for i, m := range msgs {
		if m.ID == messageID {
			s.messages[queueID] = append(msgs[:i], msgs[i+1:]...)
			q.LastAccess = time.Now().UTC()
			return nil
		}
	}
	return queue.ErrMessageNotFound
}

func cloneQueue(q *queue.Queue) *queue.Queue {
	cp := *q
	cp.OwnerKey = append([]byte(nil), q.OwnerKey...)
	return &cp
}

func cloneMessage(m *queue.Message) *queue.Message {
	cp := *m
	cp.Blob = append([]byte(nil), m.Blob...)
	return &cp
}
