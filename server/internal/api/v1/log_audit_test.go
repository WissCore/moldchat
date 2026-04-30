// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/anonauth"
	v1 "github.com/WissCore/moldchat/server/internal/api/v1"
	"github.com/WissCore/moldchat/server/internal/auth"
	"github.com/WissCore/moldchat/server/internal/storage/memory"
)

// TestLogAudit_AnonauthFlowDoesNotLeakSecrets runs the full anonauth
// happy-path against an httptest server whose logger writes to an
// in-memory buffer. After the flow completes, the buffer is scanned
// for substrings that would indicate a leak: per-request blinded
// elements, finalised MACs, pseudonym pubkeys, queue identifiers.
//
// This is the only test that asserts the package-level claim that
// "no per-request crypto material reaches the logs"; if a future
// edit ever adds slog calls that include those fields, this test
// fails immediately.
func TestLogAudit_AnonauthFlowDoesNotLeakSecrets(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	// slog.JSONHandler serialises writes to its underlying io.Writer
	// with an internal mutex (documented in slog.NewJSONHandler), so
	// a plain bytes.Buffer is safe to share across the handler's
	// concurrent callers.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	key, err := anonauth.DeriveIssuerKey(seed)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	issuer, err := anonauth.NewIssuer(anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    5,
		PoWDifficultyBits: 4,
	}, key, anonauth.NewMemoryPseudonymStore())
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	verifier, err := anonauth.NewVerifier(anonauth.VerifierConfig{Epoch: time.Hour}, key)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	issuer.SetClockForTest(func() time.Time { return now })
	verifier.SetClockForTest(func() time.Time { return now })

	mux := http.NewServeMux()
	api := &v1.Server{
		Storage:  memory.New(),
		Auth:     auth.NewIssuer(),
		Logger:   logger,
		Issuer:   issuer,
		Verifier: verifier,
	}
	api.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)
	pub, priv := registerPseudonymHTTP(t, srv.URL)
	stack := &anonauthTestServer{Server: srv, api: api, issuer: issuer, verifier: verifier, key: key}
	input, mac := issueTokenHTTP(t, srv.URL, stack, pub, priv, now)

	resp := putWithToken(t, srv.URL, queueID, []byte("payload"), encodeToken(input, mac))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("PUT status %d", resp.StatusCode)
	}

	logged := logBuf.String()

	// Forbidden substrings: anything that would let an attacker who
	// reads the logs link a presented token to its issuance, or
	// discover which queues exist. Per-substring assertions, so a
	// regression points at the offending field.
	forbidden := map[string]string{
		"queue id in logs":         queueID,
		"pseudonym pubkey in logs": base64.StdEncoding.EncodeToString(pub),
		"token mac in logs":        base64.StdEncoding.EncodeToString(mac),
		"token input in logs":      base64.StdEncoding.EncodeToString(input),
		"raw header field in logs": v1.AnonauthHeader,
	}
	for label, needle := range forbidden {
		if needle == "" {
			continue
		}
		if strings.Contains(logged, needle) {
			t.Errorf("%s: substring %q found in log output", label, needle)
		}
	}
}
