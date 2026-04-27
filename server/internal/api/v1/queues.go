// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/WissCore/moldchat/server/internal/queue"
)

// maxCreateBody bounds the JSON body for queue-creation requests.
const maxCreateBody = 4 * 1024

func (s *Server) handleCreateQueue() http.Handler {
	type request struct {
		OwnerPubkey string `json:"owner_pubkey"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxCreateBody)

		var req request
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		key, err := base64.StdEncoding.DecodeString(req.OwnerPubkey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "owner_pubkey must be base64-encoded")
			return
		}
		q, err := s.Storage.CreateQueue(r.Context(), key)
		switch {
		case errors.Is(err, queue.ErrInvalidOwnerKey):
			writeError(w, http.StatusBadRequest, err.Error())
			return
		case err != nil:
			s.logServerError("create queue", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"queue_id":   q.ID,
			"expires_at": q.ExpiresAt.Format(time.RFC3339),
		})
	})
}

func (s *Server) handlePutMessage() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, queue.MaxBlobSize+1)
		blob, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "blob exceeds maximum size")
			return
		}
		if len(blob) > queue.MaxBlobSize {
			writeError(w, http.StatusRequestEntityTooLarge, "blob exceeds maximum size")
			return
		}
		queueID := r.PathValue("id")
		m, err := s.Storage.PutMessage(r.Context(), queueID, blob)
		switch {
		case errors.Is(err, queue.ErrQueueNotFound):
			writeError(w, http.StatusNotFound, "queue not found")
			return
		case errors.Is(err, queue.ErrEmptyBlob):
			writeError(w, http.StatusBadRequest, "empty body")
			return
		case errors.Is(err, queue.ErrBlobTooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, "blob exceeds maximum size")
			return
		case err != nil:
			s.logServerError("put message", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"message_id":  m.ID,
			"accepted_at": m.ReceivedAt.Format(time.RFC3339),
		})
	})
}

func (s *Server) handleListMessages() http.Handler {
	type messagePayload struct {
		ID   string `json:"id"`
		Blob string `json:"blob"`
		TS   string `json:"ts"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queueID := r.PathValue("id")
		q, err := s.Storage.GetQueue(r.Context(), queueID)
		if errors.Is(err, queue.ErrQueueNotFound) {
			writeError(w, http.StatusNotFound, "queue not found")
			return
		}
		if err != nil {
			s.logServerError("get queue", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !s.authorizeOwner(r, q) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		msgs, hasMore, err := s.Storage.ListMessages(r.Context(), queueID, 100)
		if err != nil {
			s.logServerError("list messages", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		out := make([]messagePayload, len(msgs))
		for i, m := range msgs {
			out[i] = messagePayload{
				ID:   m.ID,
				Blob: base64.StdEncoding.EncodeToString(m.Blob),
				TS:   m.ReceivedAt.Format(time.RFC3339),
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"messages": out,
			"has_more": hasMore,
		})
	})
}

func (s *Server) handleDeleteMessage() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queueID := r.PathValue("id")
		messageID := r.PathValue("mid")

		q, err := s.Storage.GetQueue(r.Context(), queueID)
		if errors.Is(err, queue.ErrQueueNotFound) {
			writeError(w, http.StatusNotFound, "queue not found")
			return
		}
		if err != nil {
			s.logServerError("get queue", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !s.authorizeOwner(r, q) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		err = s.Storage.DeleteMessage(r.Context(), queueID, messageID)
		switch {
		case errors.Is(err, queue.ErrMessageNotFound):
			writeError(w, http.StatusNotFound, "message not found")
			return
		case err != nil:
			s.logServerError("delete message", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// authorizeOwner compares the X-Owner-Pubkey header (base64-encoded 32 bytes)
// against the key supplied at queue creation, in constant time. This is a
// placeholder for a proper Ed25519 challenge-response signature.
func (s *Server) authorizeOwner(r *http.Request, q *queue.Queue) bool {
	header := r.Header.Get("X-Owner-Pubkey")
	if header == "" {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(key, q.OwnerKey) == 1
}

func (s *Server) logServerError(op string, err error) {
	if s.Logger == nil {
		return
	}
	s.Logger.Error("server error", "op", op, "err", err.Error())
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// Response already partially written; nothing actionable for the client.
		return
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
