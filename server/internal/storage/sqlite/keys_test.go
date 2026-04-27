// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/WissCore/moldchat/server/internal/storage/sqlite"
)

func TestDeriveQueueKey_Deterministic(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	for i := range seed {
		seed[i] = byte(i)
	}
	a := seed.DeriveQueueKey("queue-1")
	b := seed.DeriveQueueKey("queue-1")
	if a != b {
		t.Errorf("derive is not deterministic: %s != %s", a, b)
	}
}

func TestDeriveQueueKey_DistinctPerQueue(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	for i := range seed {
		seed[i] = byte(i)
	}
	a := seed.DeriveQueueKey("queue-1")
	b := seed.DeriveQueueKey("queue-2")
	if a == b {
		t.Errorf("two queues produced the same key: %s", a)
	}
}

func TestDeriveQueueKey_IsolatedFromMaster(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	master := seed.MasterKey()
	queue := seed.DeriveQueueKey("any-id")
	if master == queue {
		t.Errorf("master key collides with queue key: %s", master)
	}
}

func TestDeriveKey_Length(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	got := seed.DeriveQueueKey("anything")
	if len(got) != 64 {
		t.Errorf("hex key length: got %d, want 64", len(got))
	}
}

func TestLoadMasterSeed_MissingEnv(t *testing.T) {
	t.Setenv("MOLDD_MASTER_SEED", "")

	_, err := sqlite.LoadMasterSeed()
	if !errors.Is(err, sqlite.ErrMasterSeedMissing) {
		t.Errorf("got %v, want ErrMasterSeedMissing", err)
	}
}

func TestLoadMasterSeed_InvalidLength(t *testing.T) {
	t.Setenv("MOLDD_MASTER_SEED", base64.StdEncoding.EncodeToString([]byte("too-short")))

	_, err := sqlite.LoadMasterSeed()
	if err == nil {
		t.Fatalf("expected error for short seed, got nil")
	}
	if errors.Is(err, sqlite.ErrMasterSeedMissing) {
		t.Errorf("classified as Missing instead of Invalid")
	}
}

func TestLoadMasterSeed_Valid(t *testing.T) {
	raw := make([]byte, sqlite.MasterSeedBytes)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	t.Setenv("MOLDD_MASTER_SEED", base64.StdEncoding.EncodeToString(raw))

	seed, err := sqlite.LoadMasterSeed()
	if err != nil {
		t.Fatalf("LoadMasterSeed: %v", err)
	}
	if seed[0] != 1 || seed[31] != 32 {
		t.Errorf("seed mismatch: first=%d last=%d", seed[0], seed[31])
	}
}
