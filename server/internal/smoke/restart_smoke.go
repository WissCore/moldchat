// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build smoke

package smoke

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func init() {
	RegisterCase(Case{
		Name: "DataSurvivesProcessRestart",
		Run:  restartDurabilityCase,
	})
}

// restartDurabilityCase confirms a queue and its messages survive a
// SIGKILL'd process when the same data dir and master seed are reused
// on the next start. This is the smoke-level cousin of the
// SQLCipher integration test; it adds value by going through the
// real binary, the real OS-level file write path, and a real crash
// rather than a Close()-then-New() round trip in the same process.
func restartDurabilityCase(t *testing.T, fix *Fixtures) {
	dataDir := t.TempDir()
	seed := freshSeed(t)

	first := fix.StartServer(t, ServerOptions{DataDir: dataDir, MasterSeedBase64: seed})
	owner := mintOwner(t)
	queueID := smokeCreateQueue(t, first.BaseURL, owner)
	const blob = "survives-the-crash"
	if mid := smokePutMessage(t, first.BaseURL, queueID, []byte(blob), ""); mid == "" {
		t.Fatal("first put returned empty id")
	}
	first.Kill() // simulate a hard crash, no graceful shutdown

	second := fix.StartServer(t, ServerOptions{DataDir: dataDir, MasterSeedBase64: seed})
	if got := smokeListSingleMessage(t, second.BaseURL, queueID, owner); got != blob {
		t.Fatalf("after restart: blob = %q, want %q", got, blob)
	}
}

func freshSeed(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand seed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
