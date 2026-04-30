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

	"github.com/WissCore/moldchat/server/internal/anonauth"
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

	// Issuer and Verifier are the anonymous-credential server
	// pieces. When both are non-nil the API enforces the
	// X-Anonauth-Token header on PUT /v1/queues/{id}/messages and
	// the issuance endpoints from MountAnonauth become live. Leaving
	// either nil disables the feature entirely; the existing send
	// path then accepts unauthenticated PUTs as before.
	Issuer   *anonauth.Issuer
	Verifier *anonauth.Verifier
}

// Mount registers the v1 routes on the supplied mux. Storage and Auth
// must already be set; Mount panics otherwise to fail loudly at startup.
//
// Anonauth wiring is all-or-nothing: setting one of Issuer or
// Verifier without the other is a misconfiguration that would mount
// the issuance endpoints without the matching enforcement on PUT
// (or vice versa), so Mount panics in that case to surface the bug
// at startup rather than at request time.
func (s *Server) Mount(mux *http.ServeMux) {
	if s.Storage == nil {
		panic("v1.Server.Storage must be set before Mount")
	}
	if s.Auth == nil {
		panic("v1.Server.Auth must be set before Mount")
	}
	if (s.Issuer == nil) != (s.Verifier == nil) {
		panic("v1.Server.Issuer and v1.Server.Verifier must be set together or both left nil")
	}
	mux.Handle("POST /v1/queues", s.handleCreateQueue())
	mux.Handle("GET /v1/queues/{id}/auth-challenge", s.handleAuthChallenge())
	mux.Handle("PUT /v1/queues/{id}/messages", s.handlePutMessage())
	mux.Handle("GET /v1/queues/{id}/messages", s.handleListMessages())
	mux.Handle("DELETE /v1/queues/{id}/messages/{mid}", s.handleDeleteMessage())
	s.mountAnonauth(mux)
}
