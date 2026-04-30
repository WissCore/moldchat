// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package smoke

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"
)

// healthzWaitTimeout bounds how long StartServer waits for the
// freshly spawned binary to start answering /healthz. The default is
// generous enough to absorb cold-start I/O on slow CI runners and
// short enough that a wedged process surfaces quickly during local
// runs.
const healthzWaitTimeout = 10 * time.Second

// shutdownWaitTimeout bounds how long Server.Stop waits for the
// process to exit after SIGTERM before escalating to SIGKILL and
// failing the test. Matches the binary's own shutdownTimeout +
// runnersShutdownTimeout sum plus a safety margin.
const shutdownWaitTimeout = 20 * time.Second

// ServerOptions is the configuration knob set passed to
// Fixtures.StartServer. Each field is intentionally explicit rather
// than env-string-based so a typo in a smoke case is a compile error.
type ServerOptions struct {
	// DataDir is where the binary writes its SQLCipher files. If
	// empty, StartServer uses t.TempDir() so the data is wiped on
	// test completion.
	DataDir string

	// MasterSeedBase64 is the value of MOLDD_MASTER_SEED. If empty,
	// StartServer generates a fresh 32-byte random seed.
	MasterSeedBase64 string

	// EnableAnonauth toggles MOLDD_ANONAUTH=enforce vs disabled.
	EnableAnonauth bool

	// AnonauthDataDir overrides MOLDD_ANONAUTH_DATA_DIR. Ignored
	// when EnableAnonauth is false. Defaults to a sub-directory of
	// DataDir so anonauth and queue storage stay isolated.
	AnonauthDataDir string

	// ExtraEnv is appended verbatim to the child process's environ.
	// Use it to set knobs (e.g. MOLDD_ANONAUTH_POW_BITS) that don't
	// have first-class fields here.
	ExtraEnv []string
}

// Server is a handle to a running moldd process. Tests use BaseURL to
// build HTTP requests and Stop to drive a graceful shutdown. Kill is
// the SIGKILL escape hatch for tests that intentionally simulate a
// crash.
//
// Stop and Kill are safe to call from any goroutine and any number
// of times: stopOnce serialises the first invocation, all subsequent
// calls are no-ops.
type Server struct {
	BaseURL  string
	DataDir  string
	cmd      *exec.Cmd
	stderr   *os.File
	t        *testing.T
	stopOnce sync.Once
}

// StartServer launches a moldd subprocess with the supplied options,
// waits for /healthz to respond 200, and registers a t.Cleanup that
// stops the process. Multiple cases may call StartServer; each gets
// an isolated process on its own port and data directory.
func (f *Fixtures) StartServer(t *testing.T, opts ServerOptions) *Server {
	t.Helper()

	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = t.TempDir()
	}
	seed := opts.MasterSeedBase64
	if seed == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatalf("smoke: rand seed: %v", err)
		}
		seed = base64.StdEncoding.EncodeToString(raw)
	}
	addr, err := reservePort()
	if err != nil {
		t.Fatalf("smoke: reserve port: %v", err)
	}
	stderr, err := os.CreateTemp("", "moldd-smoke-*.stderr.log")
	if err != nil {
		t.Fatalf("smoke: stderr tempfile: %v", err)
	}
	t.Cleanup(func() {
		_ = stderr.Close()
		_ = os.Remove(stderr.Name())
	})

	env := []string{
		"MOLDD_ADDR=" + addr,
		"MOLDD_STORAGE=sqlite",
		"MOLDD_MASTER_SEED=" + seed,
		"MOLDD_DATA_DIR=" + dataDir,
		"MOLDD_LOG_LEVEL=warn",
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	if opts.EnableAnonauth {
		anonDir := opts.AnonauthDataDir
		if anonDir == "" {
			anonDir = dataDir + "/anonauth"
		}
		// Use the production defaults for every anonauth knob so
		// smoke validates the actual deployed configuration. The
		// default difficulty (20 bits) is cheap in absolute terms
		// — SHA-256 grinding hits ~10 ms on a modern CPU — so
		// running with it adds negligible suite time while making
		// sure a future regression in the default cannot land
		// without breaking the smoke job.
		env = append(env,
			"MOLDD_ANONAUTH=enforce",
			"MOLDD_ANONAUTH_DATA_DIR="+anonDir,
		)
	}
	env = append(env, opts.ExtraEnv...)

	cmd := exec.Command(f.BinaryPath)
	cmd.Env = env
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	// Stop targets the child by PID via cmd.Process.Signal, so
	// process-group manipulation buys nothing; leaving the child in
	// the test runner's group means a Ctrl-C against `go test`
	// propagates to moldd children naturally instead of leaving
	// them as zombies.

	if startErr := cmd.Start(); startErr != nil {
		t.Fatalf("smoke: start moldd: %v", startErr)
	}

	srv := &Server{
		BaseURL: "http://" + addr,
		DataDir: dataDir,
		cmd:     cmd,
		stderr:  stderr,
		t:       t,
	}
	t.Cleanup(srv.Stop)

	if err := waitForHealthz(srv.BaseURL, healthzWaitTimeout); err != nil {
		dumpStderr(t, stderr)
		t.Fatalf("smoke: %v", err)
	}
	return srv
}

// Stop sends SIGTERM and waits for graceful exit, failing the test if
// the process does not exit within shutdownWaitTimeout. Safe to call
// any number of times from any goroutine: the work runs at most once
// thanks to stopOnce.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		if s.cmd.Process == nil {
			return
		}
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case waitErr := <-waitForExit(s.cmd):
			if waitErr != nil {
				// Non-zero exit on graceful shutdown is a real
				// failure — surface it and dump stderr so the
				// cause lands in the test log.
				dumpStderr(s.t, s.stderr)
				s.t.Fatalf("smoke: moldd exited with error after SIGTERM: %v", waitErr)
			}
		case <-time.After(shutdownWaitTimeout):
			_ = s.cmd.Process.Kill()
			<-waitForExit(s.cmd)
			dumpStderr(s.t, s.stderr)
			s.t.Fatalf("smoke: moldd did not exit within %s of SIGTERM", shutdownWaitTimeout)
		}
	})
}

// Kill sends SIGKILL and waits for the process to be reaped. Used by
// restart-style cases that need to simulate a crash. Safe to call
// any number of times from any goroutine.
func (s *Server) Kill() {
	s.stopOnce.Do(func() {
		if s.cmd.Process == nil {
			return
		}
		_ = s.cmd.Process.Kill()
		<-waitForExit(s.cmd)
	})
}

// waitForExit fires off cmd.Wait in a goroutine and returns a
// channel that delivers the wait error (or nil) exactly once. Used
// by both Stop and Kill so the wait-then-select pattern is
// expressed identically in both code paths.
func waitForExit(cmd *exec.Cmd) <-chan error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return done
}

// reservePort grabs a free TCP port from the kernel and immediately
// closes the listener. The window between close and the moldd child
// re-binding is small enough that races are rare in practice; the
// alternative (passing an inherited file descriptor) requires
// per-platform plumbing that isn't worth the complexity for a smoke
// suite.
func reservePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := l.Addr().String()
	if closeErr := l.Close(); closeErr != nil {
		return "", closeErr
	}
	return addr, nil
}

// waitForHealthz polls /healthz with exponential-ish backoff until
// it returns 200 or the timeout elapses. The HTTP client is reused
// across iterations so its connection pool can warm up — important
// when /healthz races a slow startup and we hit it many times.
func waitForHealthz(baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	delay := 50 * time.Millisecond
	client := &http.Client{Timeout: 1 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/healthz", nil)
		if err != nil {
			cancel()
			return fmt.Errorf("build healthz request: %w", err)
		}
		resp, err := client.Do(req)
		cancel()
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("healthz returned %d", resp.StatusCode)
		} else if !errors.Is(err, context.DeadlineExceeded) {
			lastErr = err
		}
		time.Sleep(delay)
		if delay < 500*time.Millisecond {
			delay *= 2
		}
	}
	if lastErr != nil {
		return fmt.Errorf("healthz did not become ready within %s: %w", timeout, lastErr)
	}
	return fmt.Errorf("healthz did not become ready within %s", timeout)
}

// dumpStderr copies the captured stderr file to the test log so
// failures include the binary's own complaint rather than a bare
// "exit 1".
func dumpStderr(t *testing.T, f *os.File) {
	t.Helper()
	if _, err := f.Seek(0, 0); err != nil {
		t.Logf("smoke: stderr seek: %v", err)
		return
	}
	data, err := io.ReadAll(f)
	if err != nil {
		t.Logf("smoke: stderr read: %v", err)
		return
	}
	if len(data) == 0 {
		return
	}
	t.Logf("smoke: moldd stderr:\n%s", data)
}
