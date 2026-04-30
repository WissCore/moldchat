// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build smoke

package smoke

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
	"testing"
	"time"

	"github.com/WissCore/moldchat/server/internal/anonauth"
	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	dleqpkg "github.com/cloudflare/circl/zk/dleq"
)

func init() {
	RegisterCase(Case{
		Name: "AnonauthEndToEndSendsMessage",
		Run:  anonauthEndToEndCase,
	})
	RegisterCase(Case{
		Name: "AnonauthRejectsSendWithoutToken",
		Run:  anonauthRejectsWithoutTokenCase,
	})
}

func anonauthEndToEndCase(t *testing.T, fix *Fixtures) {
	srv := fix.StartServer(t, ServerOptions{EnableAnonauth: true})
	owner := mintOwner(t)
	queueID := smokeCreateQueue(t, srv.BaseURL, owner)

	reg := registerPseudonymAndFetchIssuerPub(t, srv.BaseURL)
	input, mac := issueAndFinalizeToken(t, srv.BaseURL, reg)

	token := base64.StdEncoding.EncodeToString(append(append([]byte{}, input...), mac...))
	mid := smokePutMessage(t, srv.BaseURL, queueID, []byte("with-anon-token"), token)
	if mid == "" {
		t.Fatal("anonauth-gated put returned empty message_id")
	}
}

func anonauthRejectsWithoutTokenCase(t *testing.T, fix *Fixtures) {
	srv := fix.StartServer(t, ServerOptions{EnableAnonauth: true})
	owner := mintOwner(t)
	queueID := smokeCreateQueue(t, srv.BaseURL, owner)

	req, err := http.NewRequest(http.MethodPut, srv.BaseURL+"/v1/queues/"+queueID+"/messages", bytes.NewReader([]byte("naked")))
	if err != nil {
		t.Fatalf("build put: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("naked put status %d, want 401: %s", resp.StatusCode, buf)
	}
}

// pseudonymRegistration bundles everything a follow-up
// issueAndFinalizeToken call needs: the pseudonym key pair, the
// POPRF suite + issuer public key parsed from the same challenge
// response, and the server's epoch_seconds so the client can compute
// the current epoch index without a second challenge round trip.
type pseudonymRegistration struct {
	pub          ed25519.PublicKey
	priv         ed25519.PrivateKey
	suite        oprf.Suite
	issuerPub    *oprf.PublicKey
	epochSeconds int64
}

// registerPseudonymAndFetchIssuerPub does the GET /pseudonyms/challenge
// → solve PoW → POST /pseudonyms exchange and returns the freshly
// minted Ed25519 keypair plus everything the issuance step needs
// later. Reading epoch_seconds out of the same challenge response we
// already parse avoids a second /pseudonyms/challenge round trip
// (and the wasted outstanding-challenge slot it would consume).
func registerPseudonymAndFetchIssuerPub(t *testing.T, baseURL string) pseudonymRegistration {
	t.Helper()
	resp, err := http.Get(baseURL + "/v1/pseudonyms/challenge")
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	var ch struct {
		Challenge       string `json:"challenge"`
		DifficultyBits  uint8  `json:"difficulty_bits"`
		IssuerPublicKey string `json:"issuer_public_key"`
		EpochSeconds    int64  `json:"epoch_seconds"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&ch); decErr != nil {
		_ = resp.Body.Close()
		t.Fatalf("decode challenge: %v", decErr)
	}
	_ = resp.Body.Close()
	if ch.EpochSeconds <= 0 {
		t.Fatalf("challenge epoch_seconds = %d, want > 0", ch.EpochSeconds)
	}
	challenge, _ := base64.StdEncoding.DecodeString(ch.Challenge)
	issuerPubBytes, _ := base64.StdEncoding.DecodeString(ch.IssuerPublicKey)

	nonce := solveSmokePoW(t, challenge, ch.DifficultyBits)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"pseudonym_public_key": base64.StdEncoding.EncodeToString(pub),
		"challenge":            base64.StdEncoding.EncodeToString(challenge),
		"nonce":                base64.StdEncoding.EncodeToString(nonce),
	})
	resp, err = http.Post(baseURL+"/v1/pseudonyms", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("register status %d: %s", resp.StatusCode, buf)
	}

	suite := anonauth.Suite()
	issuerPub := new(oprf.PublicKey)
	if pkErr := issuerPub.UnmarshalBinary(suite, issuerPubBytes); pkErr != nil {
		t.Fatalf("unmarshal issuer pub: %v", pkErr)
	}
	return pseudonymRegistration{
		pub:          pub,
		priv:         priv,
		suite:        suite,
		issuerPub:    issuerPub,
		epochSeconds: ch.EpochSeconds,
	}
}

// issueAndFinalizeToken runs Blind → POST /tokens/issue → Finalize and
// returns a token (input, mac) ready to present in X-Anonauth-Token.
func issueAndFinalizeToken(t *testing.T, baseURL string, reg pseudonymRegistration) ([]byte, []byte) {
	t.Helper()
	client := oprf.NewPartialObliviousClient(reg.suite, reg.issuerPub)
	input := make([]byte, 16)
	if _, err := rand.Read(input); err != nil {
		t.Fatalf("rand input: %v", err)
	}
	finData, evalReq, err := client.Blind([][]byte{input})
	if err != nil {
		t.Fatalf("blind: %v", err)
	}
	blinded, _ := evalReq.Elements[0].MarshalBinaryCompress()

	// Compute the current epoch from the server-supplied
	// epoch_seconds and the local clock. Smoke runs against a
	// process on the same host so clock skew is not a concern.
	epoch := time.Now().Unix() / reg.epochSeconds
	signed := anonauth.CanonicalIssuancePayloadForTest(epoch, blinded)
	sig := ed25519.Sign(reg.priv, signed)

	body, _ := json.Marshal(map[string]any{
		"pseudonym_public_key": base64.StdEncoding.EncodeToString(reg.pub),
		"signature":            base64.StdEncoding.EncodeToString(sig),
		"blinded":              base64.StdEncoding.EncodeToString(blinded),
		"epoch":                epoch,
	})
	resp, err := http.Post(baseURL+"/v1/tokens/issue", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("issue status %d: %s", resp.StatusCode, buf)
	}
	var got struct {
		Evaluation string `json:"evaluation"`
		ProofC     string `json:"proof_c"`
		ProofS     string `json:"proof_s"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&got); decErr != nil {
		t.Fatalf("decode issue: %v", decErr)
	}
	evalBytes, _ := base64.StdEncoding.DecodeString(got.Evaluation)
	cBytes, _ := base64.StdEncoding.DecodeString(got.ProofC)
	sBytes, _ := base64.StdEncoding.DecodeString(got.ProofS)
	evalElement := reg.suite.Group().NewElement()
	if elemErr := evalElement.UnmarshalBinary(evalBytes); elemErr != nil {
		t.Fatalf("unmarshal eval: %v", elemErr)
	}
	proof := &dleqpkg.Proof{}
	if proofErr := proof.UnmarshalBinary(reg.suite.Group(), append(cBytes, sBytes...)); proofErr != nil {
		t.Fatalf("unmarshal proof: %v", proofErr)
	}
	evaluation := &oprf.Evaluation{Elements: []group.Element{evalElement}, Proof: proof}
	outputs, err := client.Finalize(finData, evaluation, anonauth.EpochInfo(epoch))
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	return input, outputs[0]
}

// solveSmokePoW grinds an 8-byte nonce until SHA-256 of (challenge ||
// nonce) has at least bits leading zero bits. Mirrors the helper in
// the anonauth tests; duplicated here to keep the smoke package
// self-contained.
func solveSmokePoW(t *testing.T, challenge []byte, bits uint8) []byte {
	t.Helper()
	nonce := make([]byte, 8)
	for i := uint64(0); ; i++ {
		binary.BigEndian.PutUint64(nonce, i)
		h := sha256.Sum256(append(append([]byte{}, challenge...), nonce...))
		if leadingZeroBits(h[:]) >= int(bits) {
			out := append([]byte{}, nonce...)
			return out
		}
		if i > 1<<28 {
			t.Fatalf("smoke pow grinding budget exceeded")
		}
	}
}

func leadingZeroBits(b []byte) int {
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
