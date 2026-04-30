// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build smoke

package smoke_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/WissCore/moldchat/server/internal/smoke"
)

// suiteFixtures is the shared Fixtures handed to every Case. Built
// once per `go test` invocation by TestMain so the moldd binary is
// compiled exactly once regardless of how many cases are registered.
var suiteFixtures *smoke.Fixtures

// TestMain builds the moldd binary into a tempdir, points the
// Fixtures at it, runs the suite, and cleans up. A non-zero exit
// from the build aborts the suite immediately with the build's
// stderr in the test log so a CGo / SQLCipher regression surfaces
// without first running every case.
func TestMain(m *testing.M) {
	os.Exit(runSuite(m))
}

// runSuite is split out of TestMain so the cleanup defer runs even
// when m.Run reports a non-zero exit code; calling os.Exit inside
// TestMain bypasses any defers there but not here.
func runSuite(m *testing.M) int {
	tmpDir, err := os.MkdirTemp("", "moldd-smoke-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: tempdir: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	binPath := filepath.Join(tmpDir, "moldd")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/moldd")
	// The smoke package lives at server/internal/smoke; the module
	// root is two levels up. Set Dir explicitly so `go build` finds
	// the right go.mod regardless of where `go test` was invoked.
	build.Dir = filepath.Join("..", "..")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if buildErr := build.Run(); buildErr != nil {
		fmt.Fprintf(os.Stderr, "smoke: go build moldd: %v\n", buildErr)
		return 1
	}

	suiteFixtures = &smoke.Fixtures{BinaryPath: binPath}
	return m.Run()
}

// TestSuite is the single entry point that drives every registered
// Case as a subtest. Cases run in parallel because each spawns its
// own moldd process on its own port and data directory; the
// per-case fixtures are isolated.
func TestSuite(t *testing.T) {
	t.Parallel()
	cases := smoke.Registered()
	if len(cases) == 0 {
		t.Fatal("smoke: no cases registered — has any *_smoke.go file dropped its build tag?")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			c.Run(t, suiteFixtures)
		})
	}
}
