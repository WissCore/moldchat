// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package v1 implements the HTTP API for opaque message queues.
//
// Endpoints:
//
//	POST   /v1/queues                       - create a queue
//	PUT    /v1/queues/{id}/messages          - append a blob
//	GET    /v1/queues/{id}/messages          - list pending messages (owner-only)
//	DELETE /v1/queues/{id}/messages/{mid}    - delete a message (owner-only)
//
// Owner-only operations are authorised by a constant-time comparison against
// the public key supplied at queue creation. This is a placeholder; a proper
// Ed25519 challenge-response signature will replace it.
package v1

import (
	"log/slog"
	"net/http"

	"github.com/WissCore/moldchat/server/internal/storage"
)

// Server holds dependencies shared by handlers.
type Server struct {
	Storage storage.Storage
	Logger  *slog.Logger
}

// Mount registers the v1 routes on the supplied mux.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.Handle("POST /v1/queues", s.handleCreateQueue())
	mux.Handle("PUT /v1/queues/{id}/messages", s.handlePutMessage())
	mux.Handle("GET /v1/queues/{id}/messages", s.handleListMessages())
	mux.Handle("DELETE /v1/queues/{id}/messages/{mid}", s.handleDeleteMessage())
}
