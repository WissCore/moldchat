// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	v1 "github.com/WissCore/moldchat/server/internal/api/v1"
	"github.com/WissCore/moldchat/server/internal/queue"
	"github.com/WissCore/moldchat/server/internal/storage/memory"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	(&v1.Server{Storage: memory.New()}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func randomOwnerKey(t *testing.T) (raw []byte, b64 string) {
	t.Helper()
	raw = make([]byte, queue.OwnerKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return raw, base64.StdEncoding.EncodeToString(raw)
}

func decodeJSON(t *testing.T, body io.Reader, dst any) {
	t.Helper()
	if err := json.NewDecoder(body).Decode(dst); err != nil {
		t.Fatalf("decode json: %v", err)
	}
}

// putBlob sends a PUT request with an octet-stream body.
func putBlob(t *testing.T, url string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, body)
	if err != nil {
		t.Fatalf("new put request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	return resp
}

func createQueue(t *testing.T, baseURL, ownerB64 string) string {
	t.Helper()
	resp, err := http.Post(baseURL+"/v1/queues", "application/json",
		strings.NewReader(`{"owner_pubkey":"`+ownerB64+`"}`))
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create queue status: %d", resp.StatusCode)
	}
	var got struct {
		QueueID string `json:"queue_id"`
	}
	decodeJSON(t, resp.Body, &got)
	return got.QueueID
}

func TestCreateQueue_Happy(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	_, b64 := randomOwnerKey(t)

	resp, err := http.Post(srv.URL+"/v1/queues", "application/json",
		strings.NewReader(`{"owner_pubkey":"`+b64+`"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want 201", resp.StatusCode)
	}
	var got struct {
		QueueID   string `json:"queue_id"`
		ExpiresAt string `json:"expires_at"`
	}
	decodeJSON(t, resp.Body, &got)
	if got.QueueID == "" || got.ExpiresAt == "" {
		t.Errorf("missing fields in response: %+v", got)
	}
}

func TestCreateQueue_InvalidKeyLength(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	body := strings.NewReader(`{"owner_pubkey":"` + base64.StdEncoding.EncodeToString([]byte("short")) + `"}`)
	resp, err := http.Post(srv.URL+"/v1/queues", "application/json", body)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestPutMessage_RoundTrip(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	rawKey, b64 := randomOwnerKey(t)
	queueID := createQueue(t, srv.URL, b64)

	blob := []byte("opaque-blob-content")
	putResp := putBlob(t, srv.URL+"/v1/queues/"+queueID+"/messages", bytes.NewReader(blob))
	defer func() { _ = putResp.Body.Close() }()
	if putResp.StatusCode != http.StatusAccepted {
		t.Fatalf("PUT status: got %d, want 202", putResp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/queues/"+queueID+"/messages", nil)
	if err != nil {
		t.Fatalf("new get: %v", err)
	}
	req.Header.Set("X-Owner-Pubkey", base64.StdEncoding.EncodeToString(rawKey))
	getResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = getResp.Body.Close() }()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status: got %d, want 200", getResp.StatusCode)
	}
	var listed struct {
		Messages []struct {
			ID   string `json:"id"`
			Blob string `json:"blob"`
		} `json:"messages"`
		HasMore bool `json:"has_more"`
	}
	decodeJSON(t, getResp.Body, &listed)
	if len(listed.Messages) != 1 {
		t.Fatalf("messages: got %d, want 1", len(listed.Messages))
	}
	got, err := base64.StdEncoding.DecodeString(listed.Messages[0].Blob)
	if err != nil {
		t.Fatalf("decode blob: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("blob round-trip: got %q, want %q", got, blob)
	}
}

func TestPutMessage_QueueNotFound(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	resp := putBlob(t, srv.URL+"/v1/queues/MISSING/messages", strings.NewReader("x"))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", resp.StatusCode)
	}
}

func TestPutMessage_TooLarge(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	_, b64 := randomOwnerKey(t)
	queueID := createQueue(t, srv.URL, b64)

	resp := putBlob(t, srv.URL+"/v1/queues/"+queueID+"/messages",
		bytes.NewReader(make([]byte, queue.MaxBlobSize+1)))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status: got %d, want 413", resp.StatusCode)
	}
}

func TestListMessages_Unauthorized(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	_, b64 := randomOwnerKey(t)
	queueID := createQueue(t, srv.URL, b64)

	noKeyResp, err := http.Get(srv.URL + "/v1/queues/" + queueID + "/messages")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = noKeyResp.Body.Close() }()
	if noKeyResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no auth: got %d, want 401", noKeyResp.StatusCode)
	}

	wrongKey, _ := randomOwnerKey(t)
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/queues/"+queueID+"/messages", nil)
	if err != nil {
		t.Fatalf("new get: %v", err)
	}
	req.Header.Set("X-Owner-Pubkey", base64.StdEncoding.EncodeToString(wrongKey))
	wrongKeyResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = wrongKeyResp.Body.Close() }()
	if wrongKeyResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong key: got %d, want 401", wrongKeyResp.StatusCode)
	}
}

func TestDeleteMessage_RoundTrip(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	rawKey, b64 := randomOwnerKey(t)
	queueID := createQueue(t, srv.URL, b64)

	putResp := putBlob(t, srv.URL+"/v1/queues/"+queueID+"/messages", strings.NewReader("payload"))
	var puts struct {
		MessageID string `json:"message_id"`
	}
	decodeJSON(t, putResp.Body, &puts)
	_ = putResp.Body.Close()

	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/v1/queues/"+queueID+"/messages/"+puts.MessageID, nil)
	if err != nil {
		t.Fatalf("new delete: %v", err)
	}
	req.Header.Set("X-Owner-Pubkey", base64.StdEncoding.EncodeToString(rawKey))
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = delResp.Body.Close() }()
	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE status: got %d, want 204", delResp.StatusCode)
	}
}
