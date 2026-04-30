// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build smoke

package smoke

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/WissCore/moldchat/server/internal/auth"
	"github.com/WissCore/moldchat/server/internal/queue"
)

func init() {
	RegisterCase(Case{
		Name: "QueueLifecycleHappyPath",
		Run:  queueLifecycleCase,
	})
}

// queueLifecycleCase walks a queue end to end on a real moldd
// process: create → put a blob → owner-authenticated list → owner-
// authenticated delete. Mirrors the in-process httptest e2e but goes
// through a real socket against the actually-built binary.
func queueLifecycleCase(t *testing.T, fix *Fixtures) {
	srv := fix.StartServer(t, ServerOptions{})

	owner := mintOwner(t)
	queueID := smokeCreateQueue(t, srv.BaseURL, owner)

	const blob = "hello-from-smoke"
	mid := smokePutMessage(t, srv.BaseURL, queueID, []byte(blob), "")
	if mid == "" {
		t.Fatal("put returned empty message_id")
	}

	got := smokeListSingleMessage(t, srv.BaseURL, queueID, owner)
	if got != blob {
		t.Fatalf("listed blob = %q, want %q", got, blob)
	}

	smokeDeleteMessage(t, srv.BaseURL, queueID, mid, owner)

	// Listing after delete must yield zero messages.
	if remaining := smokeListSingleMessage(t, srv.BaseURL, queueID, owner); remaining != "" {
		t.Fatalf("queue still holds blob after delete: %q", remaining)
	}
}

// smokeOwner is the credential pair used by the owner-authenticated
// smoke flows. Only Ed25519 is exercised in the signing path; X25519
// is registered alongside per the API contract but unused on the
// wire today.
type smokeOwner struct {
	x25519Pub  []byte
	ed25519Pub ed25519.PublicKey
	ed25519Pri ed25519.PrivateKey
}

func mintOwner(t *testing.T) smokeOwner {
	t.Helper()
	x := make([]byte, queue.X25519PubKeyBytes)
	if _, err := rand.Read(x); err != nil {
		t.Fatalf("rand x25519: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	return smokeOwner{x25519Pub: x, ed25519Pub: pub, ed25519Pri: priv}
}

func smokeCreateQueue(t *testing.T, baseURL string, owner smokeOwner) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"owner_x25519_pubkey":  base64.StdEncoding.EncodeToString(owner.x25519Pub),
		"owner_ed25519_pubkey": base64.StdEncoding.EncodeToString(owner.ed25519Pub),
	})
	resp, err := http.Post(baseURL+"/v1/queues", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("create queue status %d: %s", resp.StatusCode, buf)
	}
	var got struct {
		QueueID string `json:"queue_id"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&got); decErr != nil {
		t.Fatalf("decode queue: %v", decErr)
	}
	if got.QueueID == "" {
		t.Fatalf("create queue returned empty id")
	}
	return got.QueueID
}

func smokePutMessage(t *testing.T, baseURL, queueID string, blob []byte, anonToken string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, baseURL+"/v1/queues/"+queueID+"/messages", bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("build put: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if anonToken != "" {
		req.Header.Set("X-Anonauth-Token", anonToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("put status %d: %s", resp.StatusCode, buf)
	}
	var got struct {
		MessageID string `json:"message_id"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&got); decErr != nil {
		t.Fatalf("decode put: %v", decErr)
	}
	return got.MessageID
}

func smokeListSingleMessage(t *testing.T, baseURL, queueID string, owner smokeOwner) string {
	t.Helper()
	req := smokeOwnerRequest(t, baseURL, queueID, http.MethodGet, "/v1/queues/"+queueID+"/messages", "", owner)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("list status %d: %s", resp.StatusCode, buf)
	}
	var got struct {
		Messages []struct {
			Blob string `json:"blob"`
		} `json:"messages"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&got); decErr != nil {
		t.Fatalf("decode list: %v", decErr)
	}
	if len(got.Messages) == 0 {
		return ""
	}
	if len(got.Messages) > 1 {
		t.Fatalf("list returned %d messages, smoke expects exactly one", len(got.Messages))
	}
	raw, err := base64.StdEncoding.DecodeString(got.Messages[0].Blob)
	if err != nil {
		t.Fatalf("decode blob: %v", err)
	}
	return string(raw)
}

func smokeDeleteMessage(t *testing.T, baseURL, queueID, mid string, owner smokeOwner) {
	t.Helper()
	req := smokeOwnerRequest(t, baseURL, queueID, http.MethodDelete, "/v1/queues/"+queueID+"/messages/"+mid, mid, owner)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete status %d: %s", resp.StatusCode, buf)
	}
}

// smokeOwnerRequest builds a request with a fresh challenge nonce
// signed by owner. resourceID binds the signature to the targeted
// message id for DELETE; pass empty string for list/auth-challenge.
func smokeOwnerRequest(t *testing.T, baseURL, queueID, method, target, resourceID string, owner smokeOwner) *http.Request {
	t.Helper()
	nonce := smokeFetchNonce(t, baseURL, queueID)
	payload := auth.CanonicalPayload(nonce, queueID, method, resourceID)
	sig := ed25519.Sign(owner.ed25519Pri, payload)
	req, err := http.NewRequest(method, baseURL+target, nil)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, target, err)
	}
	req.Header.Set("Authorization", auth.FormatAuthorization(sig, owner.ed25519Pub, nonce))
	return req
}

func smokeFetchNonce(t *testing.T, baseURL, queueID string) []byte {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("%s/v1/queues/%s/auth-challenge", baseURL, queueID))
	if err != nil {
		t.Fatalf("auth-challenge: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("auth-challenge status %d", resp.StatusCode)
	}
	var got struct {
		Nonce string `json:"nonce"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&got); decErr != nil {
		t.Fatalf("decode nonce: %v", decErr)
	}
	nonce, err := base64.StdEncoding.DecodeString(got.Nonce)
	if err != nil {
		t.Fatalf("decode nonce bytes: %v", err)
	}
	return nonce
}
