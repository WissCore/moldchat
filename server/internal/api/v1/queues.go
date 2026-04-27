// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/WissCore/moldchat/server/internal/auth"
	"github.com/WissCore/moldchat/server/internal/queue"
)

// errAuthDenied is returned by authorizeOwner for any reason an owner-only
// request is rejected. The cause is intentionally not surfaced to the
// client, but it bumps the AuthFailureCount counter on Server.
var errAuthDenied = errors.New("authorization denied")

// queueIDRegex validates the format of queue identifiers received from
// clients. New IDs are 32 unpadded base32 characters (RFC 4648 §6).
// Rejecting malformed IDs early keeps storage lookups predictable and
// closes off any path-traversal vector through the URL.
var queueIDRegex = regexp.MustCompile(`^[A-Z2-7]{32}$`)

// maxCreateBody bounds the JSON body for queue-creation requests.
const maxCreateBody = 4 * 1024

func (s *Server) handleCreateQueue() http.Handler {
	type request struct {
		OwnerX25519Pubkey  string `json:"owner_x25519_pubkey"`
		OwnerEd25519Pubkey string `json:"owner_ed25519_pubkey"`
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
		x25519Key, err := base64.StdEncoding.DecodeString(req.OwnerX25519Pubkey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "owner_x25519_pubkey must be base64-encoded")
			return
		}
		ed25519Key, err := base64.StdEncoding.DecodeString(req.OwnerEd25519Pubkey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "owner_ed25519_pubkey must be base64-encoded")
			return
		}
		keys := queue.OwnerKeys{X25519Pub: x25519Key, Ed25519Pub: ed25519Key}
		q, err := s.Storage.CreateQueue(r.Context(), keys)
		switch {
		case errors.Is(err, queue.ErrInvalidX25519Key), errors.Is(err, queue.ErrInvalidEd25519Key):
			writeError(w, http.StatusBadRequest, err.Error())
			return
		case errors.Is(err, queue.ErrServiceCapacity):
			writeError(w, http.StatusServiceUnavailable, "service at capacity")
			return
		case err != nil:
			s.logServerError("create queue", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, map[string]any{
			"queue_id":   q.ID,
			"expires_at": q.ExpiresAt.Format(time.RFC3339),
		})
	})
}

func (s *Server) handleAuthChallenge() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queueID := r.PathValue("id")
		if !queueIDRegex.MatchString(queueID) {
			writeError(w, http.StatusNotFound, "queue not found")
			return
		}
		if _, err := s.Storage.GetQueue(r.Context(), queueID); err != nil {
			if errors.Is(err, queue.ErrQueueNotFound) {
				writeError(w, http.StatusNotFound, "queue not found")
				return
			}
			s.logServerError("get queue", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		nonce, expiresAt, err := s.Auth.Issue()
		switch {
		case errors.Is(err, auth.ErrIssuerSaturated):
			writeError(w, http.StatusServiceUnavailable, "too many outstanding challenges")
			return
		case err != nil:
			s.logServerError("issue nonce", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{
			"nonce":      base64.StdEncoding.EncodeToString(nonce),
			"expires_at": expiresAt.Format(time.RFC3339),
		})
	})
}

func (s *Server) handlePutMessage() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate the queue_id BEFORE reading the body. This stops the
		// trivial DoS where an attacker sends MaxBlobSize bodies to
		// guaranteed-malformed IDs: we'd otherwise consume bandwidth, RAM,
		// and CPU for nothing. Cheap path-only check first, expensive body
		// read only if the URL is well-formed.
		queueID := r.PathValue("id")
		if !queueIDRegex.MatchString(queueID) {
			writeError(w, http.StatusNotFound, "queue not found")
			return
		}
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
		case errors.Is(err, queue.ErrServiceCapacity):
			writeError(w, http.StatusServiceUnavailable, "service at capacity")
			return
		case err != nil:
			s.logServerError("put message", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
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
		if !queueIDRegex.MatchString(queueID) {
			writeError(w, http.StatusNotFound, "queue not found")
			return
		}
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
		if authErr := s.authorizeOwner(r, q, ""); authErr != nil {
			s.AuthFailureCount.Add(1)
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
		w.Header().Set("Cache-Control", "no-store")
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

		if !queueIDRegex.MatchString(queueID) {
			writeError(w, http.StatusNotFound, "queue not found")
			return
		}
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
		if authErr := s.authorizeOwner(r, q, messageID); authErr != nil {
			s.AuthFailureCount.Add(1)
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
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})
}

// authorizeOwner verifies the Ed25519-Sig challenge-response in the
// Authorization header against the queue's registered owner public key.
// resourceID is the message identifier when present in the URL (DELETE)
// and the empty string otherwise; it binds the signature to the
// targeted resource without depending on the literal request path.
// Returns nil on success and errAuthDenied for every failure mode; the
// cause is intentionally collapsed so the response does not reveal
// which check failed.
func (s *Server) authorizeOwner(r *http.Request, q *queue.Queue, resourceID string) error {
	sig, pubkey, nonce, err := auth.ParseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		return errAuthDenied
	}
	// Explicit length guard: subtle.ConstantTimeCompare returns 1 when both
	// inputs are empty, which would be a "match" if either side were ever
	// nil. Verify catches that downstream, but failing here keeps the check
	// single-step.
	if len(pubkey) != ed25519.PublicKeySize || len(q.OwnerEd25519Pub) != ed25519.PublicKeySize {
		return errAuthDenied
	}
	if subtle.ConstantTimeCompare(pubkey, q.OwnerEd25519Pub) != 1 {
		return errAuthDenied
	}
	if verifyErr := s.Auth.Verify(
		ed25519.PublicKey(pubkey),
		nonce, sig,
		q.ID, r.Method, resourceID,
	); verifyErr != nil {
		return errAuthDenied
	}
	return nil
}

func (s *Server) logServerError(op string, err error) {
	if s.Logger == nil {
		return
	}
	s.Logger.Error("server error", "op", op, "err", err.Error())
}

// writeJSON commits the headers and best-effort encodes body as JSON.
// Encode failures here mean the connection broke after the status line
// was already sent; we cannot recover, but we do want a breadcrumb. The
// debug call routes through slog.Default(), which the binary's main()
// is responsible for setting via slog.SetDefault — without that wiring
// the message goes to the stdlib default handler at info level and is
// silently dropped.
//
// Headers set:
//   - Content-Type: application/json
//   - X-Content-Type-Options: nosniff to forbid MIME sniffing on any
//     response a user agent might decide to render. We never serve
//     HTML from this endpoint, but the header is the standard OWASP
//     defence and costs nothing.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Default().Debug("response encode failed", "err", err.Error())
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
