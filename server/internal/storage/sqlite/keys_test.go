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

func nonZeroSalt() []byte {
	salt := make([]byte, sqlite.QueueKeySaltBytes)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	return salt
}

func TestDeriveQueueKey_Deterministic(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	for i := range seed {
		seed[i] = byte(i)
	}
	salt := nonZeroSalt()
	a, err := seed.DeriveQueueKey("queue-1", salt)
	if err != nil {
		t.Fatalf("DeriveQueueKey: %v", err)
	}
	b, err := seed.DeriveQueueKey("queue-1", salt)
	if err != nil {
		t.Fatalf("DeriveQueueKey: %v", err)
	}
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
	salt := nonZeroSalt()
	a, err := seed.DeriveQueueKey("queue-1", salt)
	if err != nil {
		t.Fatalf("DeriveQueueKey: %v", err)
	}
	b, err := seed.DeriveQueueKey("queue-2", salt)
	if err != nil {
		t.Fatalf("DeriveQueueKey: %v", err)
	}
	if a == b {
		t.Errorf("two queues produced the same key: %s", a)
	}
}

func TestDeriveQueueKey_DistinctPerSalt(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	for i := range seed {
		seed[i] = byte(i)
	}
	saltA := make([]byte, sqlite.QueueKeySaltBytes)
	saltB := make([]byte, sqlite.QueueKeySaltBytes)
	saltA[0] = 1
	saltB[0] = 2
	a, err := seed.DeriveQueueKey("queue-1", saltA)
	if err != nil {
		t.Fatalf("DeriveQueueKey: %v", err)
	}
	b, err := seed.DeriveQueueKey("queue-1", saltB)
	if err != nil {
		t.Fatalf("DeriveQueueKey: %v", err)
	}
	if a == b {
		t.Errorf("salt change did not change derived key — crypto-shred is broken: %s", a)
	}
}

func TestDeriveQueueKey_RejectsInvalidSalt(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	if _, err := seed.DeriveQueueKey("q", make([]byte, sqlite.QueueKeySaltBytes-1)); !errors.Is(err, sqlite.ErrInvalidQueueSalt) {
		t.Errorf("short salt: got %v, want ErrInvalidQueueSalt", err)
	}
	if _, err := seed.DeriveQueueKey("q", nil); !errors.Is(err, sqlite.ErrInvalidQueueSalt) {
		t.Errorf("nil salt: got %v, want ErrInvalidQueueSalt", err)
	}
}

func TestDeriveQueueKey_IsolatedFromMaster(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	master, err := seed.MasterKey()
	if err != nil {
		t.Fatalf("MasterKey: %v", err)
	}
	queueKey, err := seed.DeriveQueueKey("any-id", nonZeroSalt())
	if err != nil {
		t.Fatalf("DeriveQueueKey: %v", err)
	}
	if master == queueKey {
		t.Errorf("master key collides with queue key: %s", master)
	}
}

func TestDeriveKey_Length(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	got, err := seed.DeriveQueueKey("anything", nonZeroSalt())
	if err != nil {
		t.Fatalf("DeriveQueueKey: %v", err)
	}
	if len(got) != 64 {
		t.Errorf("hex key length: got %d, want 64", len(got))
	}
}

func TestQueueFilename_HidesQueueID(t *testing.T) {
	t.Parallel()

	var seed sqlite.MasterSeed
	for i := range seed {
		seed[i] = byte(i)
	}
	queueID := "VERYLONGUNIQUEQUEUEIDENTIFIERXYZ"
	filename := seed.QueueFilename(queueID)
	if filename == queueID {
		t.Errorf("filename equals queue id: %q", filename)
	}
	if len(filename) != 32 {
		t.Errorf("filename length: got %d, want 32 hex chars", len(filename))
	}
	// Determinism: same input → same output, otherwise lookups fail.
	if filename != seed.QueueFilename(queueID) {
		t.Error("filename derivation not deterministic")
	}
	// Different seeds produce different filenames so an attacker who
	// learns the seed of one deployment cannot enumerate another.
	var other sqlite.MasterSeed
	other[0] = 1
	if other.QueueFilename(queueID) == filename {
		t.Error("filename does not depend on seed")
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
