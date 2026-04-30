// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/WissCore/moldchat/server/internal/anonauth"
)

// Body-size caps for the anonauth endpoints. The numbers are tight on
// purpose: every field is a fixed-length byte string in base64, so a
// generous cap would only buy a malformed-body reader extra work.
const (
	maxAnonauthRegisterBody = 4 * 1024
	maxAnonauthIssueBody    = 4 * 1024
)

// mountAnonauth registers the anonymous-credential endpoints on mux.
// The function is a no-op when neither s.Issuer nor s.Verifier is
// set; the asymmetric-config check lives in Mount itself so a misuse
// is rejected before any handler is registered.
func (s *Server) mountAnonauth(mux *http.ServeMux) {
	if s.Issuer == nil {
		return
	}
	mux.Handle("GET /v1/pseudonyms/challenge", s.handlePseudonymChallenge())
	mux.Handle("POST /v1/pseudonyms", s.handleRegisterPseudonym())
	mux.Handle("POST /v1/tokens/issue", s.handleIssueToken())
}

// AnonauthEnabled reports whether the API server is configured to
// enforce anonymous-credential gating on send operations. The send
// handler consults this to decide whether to require the
// X-Anonauth-Token header.
func (s *Server) AnonauthEnabled() bool {
	return s.Issuer != nil && s.Verifier != nil
}

func (s *Server) handlePseudonymChallenge() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		challenge, err := s.Issuer.PoWChallenge()
		if errors.Is(err, anonauth.ErrIssuerSaturated) {
			writeError(w, http.StatusServiceUnavailable, "issuer at capacity")
			return
		}
		if err != nil {
			s.logServerError("pow challenge", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		issuerPub, err := s.Issuer.IssuerPublicKey()
		if err != nil {
			s.logServerError("issuer public key", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		cfg := s.Issuer.Config()
		writeJSON(w, http.StatusOK, map[string]any{
			"challenge":             base64.StdEncoding.EncodeToString(challenge.Bytes),
			"difficulty_bits":       challenge.DifficultyBits,
			"expires_at":            challenge.ExpiresAt.Format(time.RFC3339),
			"issuer_public_key":     base64.StdEncoding.EncodeToString(issuerPub),
			"epoch_seconds":         int64(cfg.Epoch.Seconds()),
			"tokens_per_epoch":      cfg.TokensPerEpoch,
			"pseudonym_ttl_seconds": int64(cfg.PseudonymTTL.Seconds()),
		})
	})
}

func (s *Server) handleRegisterPseudonym() http.Handler {
	type request struct {
		PseudonymPub string `json:"pseudonym_public_key"`
		Challenge    string `json:"challenge"`
		Nonce        string `json:"nonce"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxAnonauthRegisterBody)
		var req request
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		pub, err := base64.StdEncoding.DecodeString(req.PseudonymPub)
		if err != nil {
			writeError(w, http.StatusBadRequest, "pseudonym_public_key must be base64")
			return
		}
		challenge, err := base64.StdEncoding.DecodeString(req.Challenge)
		if err != nil {
			writeError(w, http.StatusBadRequest, "challenge must be base64")
			return
		}
		nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			writeError(w, http.StatusBadRequest, "nonce must be base64")
			return
		}
		err = s.Issuer.RegisterPseudonym(r.Context(), ed25519.PublicKey(pub), challenge, nonce)
		switch {
		case errors.Is(err, anonauth.ErrPoWInvalid),
			errors.Is(err, anonauth.ErrPoWChallengeUnknown),
			errors.Is(err, anonauth.ErrPseudonymInvalid):
			// All three collapse to the same wire response so the
			// client cannot distinguish "wrong nonce" from "wrong
			// challenge" from "wrong pubkey length".
			writeError(w, http.StatusUnauthorized, "registration rejected")
			return
		case errors.Is(err, anonauth.ErrPseudonymExists):
			writeError(w, http.StatusConflict, "pseudonym already registered")
			return
		case errors.Is(err, anonauth.ErrPseudonymCapacity):
			writeError(w, http.StatusServiceUnavailable, "pseudonym store at capacity")
			return
		case err != nil:
			s.logServerError("register pseudonym", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"registered_at": time.Now().UTC().Format(time.RFC3339),
		})
	})
}

func (s *Server) handleIssueToken() http.Handler {
	type request struct {
		PseudonymPub string `json:"pseudonym_public_key"`
		Signature    string `json:"signature"`
		Blinded      string `json:"blinded"`
		Epoch        int64  `json:"epoch"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxAnonauthIssueBody)
		var req request
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		pub, err := base64.StdEncoding.DecodeString(req.PseudonymPub)
		if err != nil {
			writeError(w, http.StatusBadRequest, "pseudonym_public_key must be base64")
			return
		}
		sig, err := base64.StdEncoding.DecodeString(req.Signature)
		if err != nil {
			writeError(w, http.StatusBadRequest, "signature must be base64")
			return
		}
		blinded, err := base64.StdEncoding.DecodeString(req.Blinded)
		if err != nil {
			writeError(w, http.StatusBadRequest, "blinded must be base64")
			return
		}
		resp, err := s.Issuer.IssueToken(r.Context(), anonauth.IssuanceRequest{
			Blinded:      blinded,
			PseudonymPub: ed25519.PublicKey(pub),
			Signature:    sig,
			Epoch:        req.Epoch,
		})
		switch {
		case errors.Is(err, anonauth.ErrPseudonymInvalid):
			writeError(w, http.StatusUnauthorized, "issuance rejected")
			return
		case errors.Is(err, anonauth.ErrPseudonymExpired):
			writeError(w, http.StatusUnauthorized, "pseudonym expired")
			return
		case errors.Is(err, anonauth.ErrRateLimited):
			writeError(w, http.StatusTooManyRequests, "rate limit reached")
			return
		case err != nil:
			s.logServerError("issue token", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"evaluation": base64.StdEncoding.EncodeToString(resp.Evaluation),
			"proof_c":    base64.StdEncoding.EncodeToString(resp.ProofC),
			"proof_s":    base64.StdEncoding.EncodeToString(resp.ProofS),
			"epoch":      resp.Epoch,
			"issued_at":  resp.IssuedAt.UTC().Format(time.RFC3339),
		})
	})
}

// AnonauthHeader is the request header that carries a presented
// token on PUT /v1/queues/{id}/messages when anonauth is enforced.
// Format: base64(input || mac), where input is the same byte string
// the client supplied to POPRF.Blind and mac is the finalised output.
const AnonauthHeader = "X-Anonauth-Token"

// parseAnonauthToken decodes the token header into its (input, mac)
// components. The mac length is fixed by the suite (SHA-512 → 64
// bytes); anything shorter is an immediate reject. There is no upper
// bound on input length here — input is whatever the client chose
// at Blind time — but the wider HTTP layer caps the header size, so
// the practical maximum is bounded already.
func parseAnonauthToken(header string) (input, mac []byte, err error) {
	if header == "" {
		return nil, nil, anonauth.ErrTokenInvalid
	}
	raw, decErr := base64.StdEncoding.DecodeString(header)
	if decErr != nil {
		return nil, nil, anonauth.ErrTokenInvalid
	}
	const macLen = 64
	if len(raw) <= macLen {
		return nil, nil, anonauth.ErrTokenInvalid
	}
	return raw[:len(raw)-macLen], raw[len(raw)-macLen:], nil
}
