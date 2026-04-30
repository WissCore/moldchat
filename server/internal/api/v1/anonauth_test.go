// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/anonauth"
	v1 "github.com/WissCore/moldchat/server/internal/api/v1"
	"github.com/WissCore/moldchat/server/internal/auth"
	"github.com/WissCore/moldchat/server/internal/storage/memory"
	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	dleqpkg "github.com/cloudflare/circl/zk/dleq"
)

// anonauthTestServer wires the API with anonauth enforcement enabled
// and exposes the issuer/verifier so tests can drive their clocks.
type anonauthTestServer struct {
	*httptest.Server
	api      *v1.Server
	issuer   *anonauth.Issuer
	verifier *anonauth.Verifier
	key      *anonauth.IssuerKey
}

func newAnonauthServer(t *testing.T, cfg anonauth.IssuerConfig, now time.Time) *anonauthTestServer {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	key, err := anonauth.DeriveIssuerKey(seed)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	issuer, err := anonauth.NewIssuer(cfg, key, anonauth.NewMemoryPseudonymStore())
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	verifier, err := anonauth.NewVerifier(anonauth.VerifierConfig{Epoch: cfg.Epoch}, key)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	issuer.SetClockForTest(func() time.Time { return now })
	verifier.SetClockForTest(func() time.Time { return now })

	mux := http.NewServeMux()
	api := &v1.Server{
		Storage:  memory.New(),
		Auth:     auth.NewIssuer(),
		Issuer:   issuer,
		Verifier: verifier,
	}
	api.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &anonauthTestServer{Server: srv, api: api, issuer: issuer, verifier: verifier, key: key}
}

// solvePoWHTTP grinds nonces locally — same algorithm as in the
// package-internal pow tests, kept here to avoid a cross-test
// dependency on internal helpers.
func solvePoWHTTP(tb testing.TB, challenge []byte, bits uint8) []byte {
	tb.Helper()
	nonce := make([]byte, 8)
	for i := uint64(0); ; i++ {
		binary.BigEndian.PutUint64(nonce, i)
		h := sha256.Sum256(append(append([]byte{}, challenge...), nonce...))
		if leadingZeros(h[:]) >= int(bits) {
			out := append([]byte{}, nonce...)
			return out
		}
		if i > 1<<28 {
			tb.Fatalf("pow grinding budget exceeded")
		}
	}
}

func leadingZeros(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if x&mask == 0 {
				n++
			} else {
				return n
			}
		}
		return n
	}
	return n
}

// fetchPseudonymChallenge calls GET /v1/pseudonyms/challenge and
// decodes the response.
func fetchPseudonymChallenge(t *testing.T, baseURL string) (challenge []byte, bits uint8, issuerPub []byte) {
	t.Helper()
	resp, err := http.Get(baseURL + "/v1/pseudonyms/challenge")
	if err != nil {
		t.Fatalf("get challenge: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge status: %d", resp.StatusCode)
	}
	var got struct {
		Challenge       string `json:"challenge"`
		DifficultyBits  uint8  `json:"difficulty_bits"`
		IssuerPublicKey string `json:"issuer_public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cb, _ := base64.StdEncoding.DecodeString(got.Challenge)
	pk, _ := base64.StdEncoding.DecodeString(got.IssuerPublicKey)
	return cb, got.DifficultyBits, pk
}

// registerPseudonymHTTP runs the full registration flow against the
// HTTP API and returns the freshly minted Ed25519 key pair.
func registerPseudonymHTTP(t *testing.T, baseURL string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	challenge, bits, _ := fetchPseudonymChallenge(t, baseURL)
	nonce := solvePoWHTTP(t, challenge, bits)
	body, _ := json.Marshal(map[string]string{
		"pseudonym_public_key": base64.StdEncoding.EncodeToString(pub),
		"challenge":            base64.StdEncoding.EncodeToString(challenge),
		"nonce":                base64.StdEncoding.EncodeToString(nonce),
	})
	resp, err := http.Post(baseURL+"/v1/pseudonyms", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post pseudonym: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("register status: %d body: %s", resp.StatusCode, buf)
	}
	return pub, priv
}

// issueTokenHTTP does the full token issuance against the HTTP API
// and returns the (input, mac) the client would present.
func issueTokenHTTP(t *testing.T, baseURL string, srv *anonauthTestServer, pub ed25519.PublicKey, priv ed25519.PrivateKey, now time.Time) (input, mac []byte) {
	t.Helper()
	suite := srv.key.Suite()
	pubKey, _ := srv.key.PublicKey()
	parsedPub := new(oprf.PublicKey)
	if err := parsedPub.UnmarshalBinary(suite, pubKey); err != nil {
		t.Fatalf("parse issuer pub: %v", err)
	}
	client := oprf.NewPartialObliviousClient(suite, parsedPub)
	input = make([]byte, 16)
	if _, err := rand.Read(input); err != nil {
		t.Fatalf("input: %v", err)
	}
	finData, evalReq, err := client.Blind([][]byte{input})
	if err != nil {
		t.Fatalf("blind: %v", err)
	}
	blinded, _ := evalReq.Elements[0].MarshalBinaryCompress()

	epoch := srv.issuer.CurrentEpoch(now)
	signed := anonauth.CanonicalIssuancePayloadForTest(epoch, blinded)
	sig := ed25519.Sign(priv, signed)
	body, _ := json.Marshal(map[string]any{
		"pseudonym_public_key": base64.StdEncoding.EncodeToString(pub),
		"signature":            base64.StdEncoding.EncodeToString(sig),
		"blinded":              base64.StdEncoding.EncodeToString(blinded),
		"epoch":                epoch,
	})
	resp, err := http.Post(baseURL+"/v1/tokens/issue", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("issue status: %d body: %s", resp.StatusCode, buf)
	}
	var got struct {
		Evaluation string `json:"evaluation"`
		ProofC     string `json:"proof_c"`
		ProofS     string `json:"proof_s"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&got); decErr != nil {
		t.Fatalf("decode: %v", decErr)
	}
	evalBytes, _ := base64.StdEncoding.DecodeString(got.Evaluation)
	cBytes, _ := base64.StdEncoding.DecodeString(got.ProofC)
	sBytes, _ := base64.StdEncoding.DecodeString(got.ProofS)
	evalElement := suite.Group().NewElement()
	if elemErr := evalElement.UnmarshalBinary(evalBytes); elemErr != nil {
		t.Fatalf("unmarshal eval: %v", elemErr)
	}
	proof := &dleqpkg.Proof{}
	if proofErr := proof.UnmarshalBinary(suite.Group(), append(cBytes, sBytes...)); proofErr != nil {
		t.Fatalf("unmarshal proof: %v", proofErr)
	}
	evaluation := &oprf.Evaluation{Elements: []group.Element{evalElement}, Proof: proof}
	outputs, err := client.Finalize(finData, evaluation, anonauth.EpochInfo(epoch))
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	return input, outputs[0]
}

// putWithToken posts a body to PUT /messages with the supplied
// token in the X-Anonauth-Token header.
func putWithToken(t *testing.T, baseURL, queueID string, body []byte, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, baseURL+"/v1/queues/"+queueID+"/messages", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new put: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if token != "" {
		req.Header.Set(v1.AnonauthHeader, token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	return resp
}

func encodeToken(input, mac []byte) string {
	return base64.StdEncoding.EncodeToString(append(append([]byte{}, input...), mac...))
}

func TestAnonauth_EndToEnd(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	srv := newAnonauthServer(t, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    2,
		PoWDifficultyBits: 4,
	}, now)

	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

	pub, priv := registerPseudonymHTTP(t, srv.URL)

	// Spend the per-epoch quota.
	for i := 0; i < 2; i++ {
		input, mac := issueTokenHTTP(t, srv.URL, srv, pub, priv, now)
		resp := putWithToken(t, srv.URL, queueID, []byte("hello"), encodeToken(input, mac))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("PUT %d: status %d, want 202", i, resp.StatusCode)
		}
	}

	// Third issuance must hit the rate limit.
	{
		challenge, _ := bytes.NewReader(nil), 0
		_ = challenge
		// Construct manually because issueTokenHTTP would Fatalf
		// on the expected 429.
		suite := srv.key.Suite()
		pubKey, _ := srv.key.PublicKey()
		parsedPub := new(oprf.PublicKey)
		_ = parsedPub.UnmarshalBinary(suite, pubKey)
		client := oprf.NewPartialObliviousClient(suite, parsedPub)
		_, evalReq, _ := client.Blind([][]byte{[]byte("third")})
		blinded, _ := evalReq.Elements[0].MarshalBinaryCompress()
		epoch := srv.issuer.CurrentEpoch(now)
		signed := anonauth.CanonicalIssuancePayloadForTest(epoch, blinded)
		sig := ed25519.Sign(priv, signed)
		body, _ := json.Marshal(map[string]any{
			"pseudonym_public_key": base64.StdEncoding.EncodeToString(pub),
			"signature":            base64.StdEncoding.EncodeToString(sig),
			"blinded":              base64.StdEncoding.EncodeToString(blinded),
			"epoch":                epoch,
		})
		resp, err := http.Post(srv.URL+"/v1/tokens/issue", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d", resp.StatusCode)
		}
	}
}

func TestAnonauth_PutWithoutTokenRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	srv := newAnonauthServer(t, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    5,
		PoWDifficultyBits: 4,
	}, now)
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

	resp := putWithToken(t, srv.URL, queueID, []byte("hello"), "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}
}

func TestAnonauth_PutWithReplayedTokenRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	srv := newAnonauthServer(t, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    5,
		PoWDifficultyBits: 4,
	}, now)
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

	pub, priv := registerPseudonymHTTP(t, srv.URL)
	input, mac := issueTokenHTTP(t, srv.URL, srv, pub, priv, now)
	token := encodeToken(input, mac)

	first := putWithToken(t, srv.URL, queueID, []byte("hello"), token)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusAccepted {
		t.Fatalf("first PUT: %d", first.StatusCode)
	}
	second := putWithToken(t, srv.URL, queueID, []byte("hello"), token)
	_ = second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on replay, got %d", second.StatusCode)
	}
}

func TestAnonauth_PutWithGarbledTokenRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	srv := newAnonauthServer(t, anonauth.IssuerConfig{
		Epoch:             time.Hour,
		PseudonymTTL:      24 * time.Hour,
		TokensPerEpoch:    5,
		PoWDifficultyBits: 4,
	}, now)
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)

	cases := []string{
		"!!!not-base64!!!",
		base64.StdEncoding.EncodeToString(make([]byte, 10)), // too short for input+mac
	}
	for _, c := range cases {
		resp := putWithToken(t, srv.URL, queueID, []byte("x"), c)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q: status %d, want 401", c, resp.StatusCode)
		}
	}
}

func TestAnonauth_BackwardCompatWhenDisabled(t *testing.T) {
	t.Parallel()
	// Construct a server WITHOUT Issuer/Verifier — anonauth disabled.
	mux := http.NewServeMux()
	api := &v1.Server{Storage: memory.New(), Auth: auth.NewIssuer()}
	api.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	owner := newOwner(t)
	queueID := createQueue(t, srv.URL, owner)
	resp := putWithToken(t, srv.URL, queueID, []byte("hi"), "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("backward-compat PUT without token: status %d, want 202", resp.StatusCode)
	}
}

func TestAnonauth_HalfConfiguredMountPanics(t *testing.T) {
	t.Parallel()
	// Issuer set, Verifier nil — must panic at Mount time so the
	// half-configured state cannot reach a request handler.
	now := time.Now()
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
		PseudonymTTL:      time.Hour,
		TokensPerEpoch:    1,
		PoWDifficultyBits: 4,
	}, key, anonauth.NewMemoryPseudonymStore())
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	issuer.SetClockForTest(func() time.Time { return now })

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for half-configured anonauth wiring")
		}
	}()
	api := &v1.Server{Storage: memory.New(), Auth: auth.NewIssuer(), Issuer: issuer}
	api.Mount(http.NewServeMux())
}
