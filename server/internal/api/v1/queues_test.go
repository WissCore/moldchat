// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	v1 "github.com/WissCore/moldchat/server/internal/api/v1"
	"github.com/WissCore/moldchat/server/internal/auth"
	"github.com/WissCore/moldchat/server/internal/queue"
	"github.com/WissCore/moldchat/server/internal/storage/memory"
)

type ownerCreds struct {
	x25519Pub  []byte
	ed25519Pub ed25519.PublicKey
	ed25519Pri ed25519.PrivateKey
}

// testServer pairs the underlying *v1.Server with its httptest fixture so
// tests can both hit the API and observe internal counters.
type testServer struct {
	*httptest.Server
	api *v1.Server
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	mux := http.NewServeMux()
	api := &v1.Server{Storage: memory.New(), Auth: auth.NewIssuer()}
	api.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &testServer{Server: srv, api: api}
}

func newOwner(t *testing.T) ownerCreds {
	t.Helper()
	x := make([]byte, queue.X25519PubKeyBytes)
	if _, err := rand.Read(x); err != nil {
		t.Fatalf("rand x25519: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	return ownerCreds{x25519Pub: x, ed25519Pub: pub, ed25519Pri: priv}
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

func createQueue(t *testing.T, baseURL string, owner ownerCreds) string {
	t.Helper()
	body := map[string]string{
		"owner_x25519_pubkey":  base64.StdEncoding.EncodeToString(owner.x25519Pub),
		"owner_ed25519_pubkey": base64.StdEncoding.EncodeToString(owner.ed25519Pub),
	}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(baseURL+"/v1/queues", "application/json", bytes.NewReader(raw))
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

// fetchNonce calls GET /auth-challenge and returns the raw nonce bytes.
func fetchNonce(t *testing.T, baseURL, queueID string) []byte {
	t.Helper()
	resp, err := http.Get(baseURL + "/v1/queues/" + queueID + "/auth-challenge")
	if err != nil {
		t.Fatalf("auth-challenge: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("auth-challenge status: %d", resp.StatusCode)
	}
	var got struct {
		Nonce string `json:"nonce"`
	}
	decodeJSON(t, resp.Body, &got)
	nonce, err := base64.StdEncoding.DecodeString(got.Nonce)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	return nonce
}

// signedRequest builds a request authenticated with a fresh challenge.
// resourceID binds the signature to the targeted message id for DELETE
// requests; pass empty string for list/auth-challenge.
func signedRequest(t *testing.T, baseURL, queueID, method, target, resourceID string, owner ownerCreds) *http.Request {
	t.Helper()
	nonce := fetchNonce(t, baseURL, queueID)
	payload := auth.CanonicalPayload(nonce, queueID, method, resourceID)
	sig := ed25519.Sign(owner.ed25519Pri, payload)

	req, err := http.NewRequest(method, baseURL+target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", auth.FormatAuthorization(sig, owner.ed25519Pub, nonce))
	return req
}

func TestCreateQueue_Happy(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	owner := newOwner(t)

	body := map[string]string{
		"owner_x25519_pubkey":  base64.StdEncoding.EncodeToString(owner.x25519Pub),
		"owner_ed25519_pubkey": base64.StdEncoding.EncodeToString(owner.ed25519Pub),
	}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/v1/queues", "application/json", bytes.NewReader(raw))
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

	body := map[string]string{
		"owner_x25519_pubkey":  base64.StdEncoding.EncodeToString([]byte("short")),
		"owner_ed25519_pubkey": base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/v1/queues", "application/json", bytes.NewReader(raw))
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
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

	blob := []byte("opaque-blob-content")
	putResp := putBlob(t, srv.URL+"/v1/queues/"+queueID+"/messages", bytes.NewReader(blob))
	defer func() { _ = putResp.Body.Close() }()
	if putResp.StatusCode != http.StatusAccepted {
		t.Fatalf("PUT status: got %d, want 202", putResp.StatusCode)
	}

	req := signedRequest(t, srv.URL, queueID, http.MethodGet,
		"/v1/queues/"+queueID+"/messages", "", owner)
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
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

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
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

	noAuthResp, err := http.Get(srv.URL + "/v1/queues/" + queueID + "/messages")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = noAuthResp.Body.Close() }()
	if noAuthResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no auth: got %d, want 401", noAuthResp.StatusCode)
	}

	intruder := newOwner(t)
	req := signedRequest(t, srv.URL, queueID, http.MethodGet,
		"/v1/queues/"+queueID+"/messages", "", intruder)
	wrongResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = wrongResp.Body.Close() }()
	if wrongResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong key: got %d, want 401", wrongResp.StatusCode)
	}
}

func TestListMessages_RejectsReplay(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

	req := signedRequest(t, srv.URL, queueID, http.MethodGet,
		"/v1/queues/"+queueID+"/messages", "", owner)
	first, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("first do: %v", err)
	}
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status: %d", first.StatusCode)
	}

	// Same Authorization header, second time should be rejected.
	replay, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/queues/"+queueID+"/messages", nil)
	if err != nil {
		t.Fatalf("new replay: %v", err)
	}
	replay.Header.Set("Authorization", req.Header.Get("Authorization"))
	replayResp, err := http.DefaultClient.Do(replay)
	if err != nil {
		t.Fatalf("replay do: %v", err)
	}
	defer func() { _ = replayResp.Body.Close() }()
	if replayResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("replay status: got %d, want 401", replayResp.StatusCode)
	}
}

func TestAuthChallenge_QueueNotFound(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/v1/queues/MISSING/auth-challenge")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", resp.StatusCode)
	}
}

func TestDeleteMessage_RoundTrip(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

	putResp := putBlob(t, srv.URL+"/v1/queues/"+queueID+"/messages", strings.NewReader("payload"))
	var puts struct {
		MessageID string `json:"message_id"`
	}
	decodeJSON(t, putResp.Body, &puts)
	_ = putResp.Body.Close()

	req := signedRequest(t, srv.URL, queueID, http.MethodDelete,
		"/v1/queues/"+queueID+"/messages/"+puts.MessageID, puts.MessageID, owner)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = delResp.Body.Close() }()
	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE status: got %d, want 204", delResp.StatusCode)
	}
}

// TestListMessages_RejectsTamperedMethod proves that a signature produced
// for one HTTP method cannot authorise another. The client signs payload
// with method GET, then submits the signed Authorization header on a
// DELETE request; the server must reject it.
func TestListMessages_RejectsTamperedMethod(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

	putResp := putBlob(t, srv.URL+"/v1/queues/"+queueID+"/messages", strings.NewReader("payload"))
	var puts struct {
		MessageID string `json:"message_id"`
	}
	decodeJSON(t, putResp.Body, &puts)
	_ = putResp.Body.Close()

	// Sign for GET, submit as DELETE.
	req := signedRequest(t, srv.URL, queueID, http.MethodGet,
		"/v1/queues/"+queueID+"/messages/"+puts.MessageID, puts.MessageID, owner)
	req.Method = http.MethodDelete
	req.URL.Path = "/v1/queues/" + queueID + "/messages/" + puts.MessageID

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", resp.StatusCode)
	}
}

// TestListMessages_MalformedAuthorizationHeader covers the API-level
// surface for headers that don't even parse: garbage, wrong scheme,
// invalid base64. All must collapse to 401 (not 400) so we don't leak
// which validation step rejected the request.
func TestListMessages_MalformedAuthorizationHeader(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

	cases := []string{
		"garbage",
		"Bearer abc",
		"ED25519-Sig only-one-part",
		"ED25519-Sig !!!,!!!,!!!",
	}
	for _, header := range cases {
		t.Run(header, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/queues/"+queueID+"/messages", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Authorization", header)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("got %d, want 401", resp.StatusCode)
			}
		})
	}
}

// TestMessages_RejectMalformedQueueID covers the API-level reaction to
// queue identifiers that don't match the on-the-wire format. Anything
// that is not 32 base32 characters must collapse to 404 so we don't
// leak validation-vs-lookup distinctions.
func TestMessages_RejectMalformedQueueID(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	cases := []string{
		"too-short",
		"contains-lowercase-not-base32",
		strings.Repeat("A", 33),
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1", // '1' is outside base32 RFC4648 §6
	}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			type probe struct {
				method, target string
			}
			probes := []probe{
				{http.MethodGet, "/v1/queues/" + id + "/messages"},
				{http.MethodGet, "/v1/queues/" + id + "/auth-challenge"},
				{http.MethodDelete, "/v1/queues/" + id + "/messages/SOMEMSG"},
			}
			for _, p := range probes {
				req, err := http.NewRequest(p.method, srv.URL+p.target, nil)
				if err != nil {
					t.Fatalf("new request %s %s: %v", p.method, p.target, err)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("%s %s: %v", p.method, p.target, err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusNotFound {
					t.Errorf("%s %s: got %d, want 404", p.method, p.target, resp.StatusCode)
				}
			}
		})
	}
}

// TestCreateQueue_ServiceCapacity verifies that filling the in-memory
// backend to MaxQueues makes the next POST return 503 Service
// Unavailable rather than leaking a 500 internal error. Heavy: skipped
// in -short. Reuses a single owner across iterations so the cap path
// (not crypto keygen) is what's exercised.
func TestCreateQueue_ServiceCapacity(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping capacity test in -short mode")
	}
	srv := newTestServer(t)
	owner := newOwner(t)
	body := map[string]string{
		"owner_x25519_pubkey":  base64.StdEncoding.EncodeToString(owner.x25519Pub),
		"owner_ed25519_pubkey": base64.StdEncoding.EncodeToString(owner.ed25519Pub),
	}
	raw, _ := json.Marshal(body)

	for i := 0; i < memory.MaxQueues; i++ {
		resp, err := http.Post(srv.URL+"/v1/queues", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("seed %d: got %d, want 201", i, resp.StatusCode)
		}
	}

	resp, err := http.Post(srv.URL+"/v1/queues", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("over-cap post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("over-cap status: got %d, want 503", resp.StatusCode)
	}
}

// TestAuthFailureCount_BumpsOnDenial verifies the server-side aggregate
// counter is incremented on auth failure.
func TestAuthFailureCount_BumpsOnDenial(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

	before := srv.api.AuthFailureCount.Load()
	resp, err := http.Get(srv.URL + "/v1/queues/" + queueID + "/messages")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()

	if got := srv.api.AuthFailureCount.Load(); got != before+1 {
		t.Errorf("counter: got %d, want %d", got, before+1)
	}
}
