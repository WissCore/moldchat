// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package v1 implements the HTTP API for opaque message queues.
//
// Endpoints:
//
//	POST   /v1/queues                          - create a queue
//	GET    /v1/queues/{id}/auth-challenge       - request a fresh nonce
//	PUT    /v1/queues/{id}/messages             - append a blob (unauth)
//	GET    /v1/queues/{id}/messages             - list pending messages (owner-only)
//	DELETE /v1/queues/{id}/messages/{mid}       - delete a message (owner-only)
//
// Owner-only operations are authorised by an Ed25519 challenge-response
// signature: the client requests a nonce, signs (nonce, queue_id, method,
// path) with the private key whose public half was registered at queue
// creation, and presents the signature in an Authorization header. See
// the auth package for the canonical payload format and replay protection.
package v1

import (
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/WissCore/moldchat/server/internal/auth"
	"github.com/WissCore/moldchat/server/internal/storage"
)

// Server holds dependencies shared by handlers. Storage and Auth must be
// initialised before Mount is called; Logger is optional.
//
// AuthFailureCount is incremented for every owner-only request that fails
// authorisation, regardless of cause (missing header, malformed payload,
// unknown queue, wrong key, expired or replayed nonce, bad signature).
// Returning a single boolean to clients while keeping a server-side
// aggregate avoids leaking which check failed and supports later
// integration with the L8 forward-secure counter pipeline.
type Server struct {
	Storage          storage.Storage
	Auth             *auth.Issuer
	Logger           *slog.Logger
	AuthFailureCount atomic.Uint64
}

// Mount registers the v1 routes on the supplied mux. Storage and Auth
// must already be set; Mount panics otherwise to fail loudly at startup.
func (s *Server) Mount(mux *http.ServeMux) {
	if s.Storage == nil {
		panic("v1.Server.Storage must be set before Mount")
	}
	if s.Auth == nil {
		panic("v1.Server.Auth must be set before Mount")
	}
	mux.Handle("POST /v1/queues", s.handleCreateQueue())
	mux.Handle("GET /v1/queues/{id}/auth-challenge", s.handleAuthChallenge())
	mux.Handle("PUT /v1/queues/{id}/messages", s.handlePutMessage())
	mux.Handle("GET /v1/queues/{id}/messages", s.handleListMessages())
	mux.Handle("DELETE /v1/queues/{id}/messages/{mid}", s.handleDeleteMessage())
}
