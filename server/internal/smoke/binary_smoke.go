// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build smoke

package smoke

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

// newCmdContext builds an *exec.Cmd for the moldd binary with the
// supplied env and a context-bound lifetime, intended for cases that
// intentionally exercise the failure path (where the binary is
// expected to exit non-zero before /healthz would respond, so
// StartServer's healthz-wait would hang). The ctx makes it
// observable when the binary refuses to exit at all — without it,
// the test would silently consume the outer go-test timeout.
// Stdout and stderr are discarded; tests that need them can override.
func newCmdContext(ctx context.Context, t *testing.T, fix *Fixtures, env []string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, fix.BinaryPath)
	cmd.Env = env
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd
}

func init() {
	RegisterCase(Case{
		Name: "BinaryStartsServesHealthzAndStopsCleanly",
		Run:  binaryHealthzCase,
	})
	RegisterCase(Case{
		Name: "BinaryRejectsUnknownAnonauthMode",
		Run:  binaryRejectsBadAnonauthCase,
	})
}

func binaryHealthzCase(t *testing.T, fix *Fixtures) {
	srv := fix.StartServer(t, ServerOptions{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.BaseURL+"/healthz", nil)
	if err != nil {
		t.Fatalf("build healthz: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status %d, want 200", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("healthz body: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("healthz body[status] = %q, want ok", body["status"])
	}

	srv.Stop() // drives graceful shutdown and asserts exit 0
}

// binaryRejectsBadAnonauthCase confirms main.go validates env values
// and exits non-zero on a bogus MOLDD_ANONAUTH setting. We exercise
// the failure path by spawning the binary directly (not via
// StartServer, which would wait for /healthz that never arrives) and
// checking the exit code under a bounded context. The bound matters
// because a regression that makes the binary hang on bad config
// would otherwise burn the whole `-timeout` window of `go test`
// before reporting failure.
func binaryRejectsBadAnonauthCase(t *testing.T, fix *Fixtures) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := newCmdContext(ctx, t, fix, []string{
		"MOLDD_STORAGE=memory",
		"MOLDD_ANONAUTH=invalid-mode",
	})
	err := cmd.Run()
	switch {
	case err == nil:
		t.Fatalf("expected moldd to exit non-zero on bogus MOLDD_ANONAUTH, got nil")
	case ctx.Err() != nil:
		t.Fatalf("moldd did not exit within %s on bogus MOLDD_ANONAUTH (likely hung)", "5s")
	}
}
