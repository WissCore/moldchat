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

// FuzzParseSeed exercises the seed parser against arbitrary
// base64-shaped inputs. The function must not panic and any error
// it returns must be one of the documented sentinels — anything
// else (a wrapped fmt.Errorf, an os.PathError, etc.) would surface
// to operators as "internal error" instead of the precise
// "missing/invalid seed" diagnostic main() relies on.
func FuzzParseSeed(f *testing.F) {
	seeds := []string{
		"",
		"too-short",
		base64.StdEncoding.EncodeToString(make([]byte, sqlite.MasterSeedBytes)),
		base64.RawStdEncoding.EncodeToString(make([]byte, sqlite.MasterSeedBytes)),
		"!!!not-base64!!!",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, err := sqlite.ParseSeedForTest(raw)
		if err == nil {
			return
		}
		if !errors.Is(err, sqlite.ErrMasterSeedMissing) &&
			!errors.Is(err, sqlite.ErrMasterSeedInvalid) {
			t.Errorf("unexpected error type: %T %v", err, err)
		}
	})
}

// FuzzDeriveQueueKey hammers the per-queue HKDF derivation with
// arbitrary queue identifiers and salt buffers. The function must:
// (a) never panic, (b) reject malformed salt (length != 32) only with
// ErrInvalidQueueSalt, (c) be deterministic — same inputs must yield
// the same key, otherwise the encrypted DB becomes unrecoverable on
// the next pool open.
func FuzzDeriveQueueKey(f *testing.F) {
	f.Add("queue-1", make([]byte, sqlite.QueueKeySaltBytes))
	f.Add("", []byte(nil))
	f.Add("very-long-queue-id-with-unicode-Ω-and-bytes\x00", []byte("short"))
	f.Fuzz(func(t *testing.T, queueID string, salt []byte) {
		var seed sqlite.MasterSeed
		got, err := seed.DeriveQueueKey(queueID, salt)
		if err != nil && !errors.Is(err, sqlite.ErrInvalidQueueSalt) {
			t.Errorf("unexpected error: %T %v", err, err)
			return
		}
		if err != nil {
			return
		}
		again, err2 := seed.DeriveQueueKey(queueID, salt)
		if err2 != nil {
			t.Errorf("re-derivation failed: %v", err2)
			return
		}
		if got != again {
			t.Errorf("queue-key derivation not deterministic")
		}
	})
}

// FuzzQueueFilename verifies that arbitrary queue identifiers always
// yield a deterministic 32-hex-char filename and that the function
// never panics — it is on the hot path for every storage operation.
func FuzzQueueFilename(f *testing.F) {
	f.Add("queue-1")
	f.Add("")
	f.Add("\x00\x01\x02")
	f.Fuzz(func(t *testing.T, queueID string) {
		var seed sqlite.MasterSeed
		got := seed.QueueFilename(queueID)
		if len(got) != 32 {
			t.Errorf("filename length: got %d, want 32", len(got))
		}
		if got != seed.QueueFilename(queueID) {
			t.Error("filename derivation not deterministic")
		}
	})
}
