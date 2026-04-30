// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package smoke holds the binary-level smoke test suite.
//
// A smoke test exercises the actually-built moldd binary against
// realistic configuration: it spawns the process, waits for /healthz,
// drives the public HTTP API the way an external client would, and
// checks the process exits cleanly on SIGTERM. Smoke tests catch the
// class of regressions that slip past unit and integration tests:
// env-variable wiring in main.go, signal handling, runner
// orchestration, build-time dependencies (CGo, SQLCipher), and the
// happy-path wire format on a real socket.
//
// # Registration model
//
// Each smoke scenario is a Case registered at package init time:
//
//	package smoke
//
//	func init() {
//	    RegisterCase(Case{
//	        Name: "QueueLifecycle",
//	        Run:  func(t *testing.T, fix *Fixtures) { ... },
//	    })
//	}
//
// The runner in suite_test.go reads the global registry and invokes
// each case as a subtest. Adding a new smoke scenario is a one-file
// change with no edits to lefthook, mise, or the CI workflow — the
// registry is the single source of truth.
//
// # How to run
//
// Direct:
//
//	cd server && go test -tags smoke -count=1 -timeout=2m ./internal/smoke/
//
// Via mise (mirrors what CI runs):
//
//	mise run smoke
package smoke

import "testing"

// Fixtures bundles the shared setup that every Case needs: the path
// to a freshly built moldd binary, plus helpers for starting and
// stopping isolated server instances. The runner constructs one
// Fixtures per suite invocation so the binary is built only once.
type Fixtures struct {
	// BinaryPath is the absolute filesystem path to the built moldd
	// binary the suite will exec.
	BinaryPath string
}

// Case is one smoke scenario. The Run function receives a *testing.T
// scoped to a subtest plus the shared Fixtures. Each Case is
// responsible for any servers it starts; using fix.StartServer
// registers the right cleanup automatically.
type Case struct {
	Name string
	Run  func(t *testing.T, fix *Fixtures)
}

// registry is the package-global slice of registered cases. Cases
// self-register via init(); the runner reads Registered() to iterate.
var registry []Case

// RegisterCase appends a Case to the registry. Intended to be called
// from package-init in a per-scenario file. Names must be unique
// across the suite — RegisterCase panics on collision so a copy-paste
// bug surfaces at build time rather than as a silent shadow.
func RegisterCase(c Case) {
	if c.Name == "" {
		panic("smoke: RegisterCase requires a non-empty Name")
	}
	if c.Run == nil {
		panic("smoke: RegisterCase requires a non-nil Run")
	}
	for _, existing := range registry {
		if existing.Name == c.Name {
			panic("smoke: duplicate Case name " + c.Name)
		}
	}
	registry = append(registry, c)
}

// Registered returns a defensive copy of the current registry. The
// runner walks this slice in registration order so failures are
// reported under stable subtest names regardless of map iteration.
func Registered() []Case {
	out := make([]Case, len(registry))
	copy(out, registry)
	return out
}
