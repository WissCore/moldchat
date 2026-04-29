// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/WissCore/moldchat/server/internal/storage/sqlite"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

func TestSnapshot_RoundTrip(t *testing.T) {
	t.Parallel()
	st, seed, _ := newTestStore(t)
	ctx := context.Background()

	q1, err := st.CreateQueue(ctx, ownerKeys(t))
	if err != nil {
		t.Fatalf("create q1: %v", err)
	}
	q2, err := st.CreateQueue(ctx, ownerKeys(t))
	if err != nil {
		t.Fatalf("create q2: %v", err)
	}
	if _, perr := st.PutMessage(ctx, q1.ID, []byte("hello-1")); perr != nil {
		t.Fatalf("put q1: %v", perr)
	}
	if _, perr := st.PutMessage(ctx, q2.ID, []byte("hello-2")); perr != nil {
		t.Fatalf("put q2: %v", perr)
	}

	snapDir := t.TempDir()
	if serr := st.Snapshot(ctx, snapDir); serr != nil {
		t.Fatalf("Snapshot: %v", serr)
	}

	st2, err := sqlite.New(seed, snapDir)
	if err != nil {
		t.Fatalf("New(snap): %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })

	msgs1, _, err := st2.ListMessages(ctx, q1.ID, 100)
	if err != nil {
		t.Fatalf("List q1: %v", err)
	}
	if len(msgs1) != 1 || !bytes.Equal(msgs1[0].Blob, []byte("hello-1")) {
		t.Errorf("q1 messages mismatch: %+v", msgs1)
	}
	msgs2, _, err := st2.ListMessages(ctx, q2.ID, 100)
	if err != nil {
		t.Fatalf("List q2: %v", err)
	}
	if len(msgs2) != 1 || !bytes.Equal(msgs2[0].Blob, []byte("hello-2")) {
		t.Errorf("q2 messages mismatch: %+v", msgs2)
	}
}

func TestSnapshot_WrongSeedCannotRead(t *testing.T) {
	t.Parallel()
	st, _, _ := newTestStore(t)
	ctx := context.Background()

	q, err := st.CreateQueue(ctx, ownerKeys(t))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, perr := st.PutMessage(ctx, q.ID, []byte("secret")); perr != nil {
		t.Fatalf("put: %v", perr)
	}

	snapDir := t.TempDir()
	if serr := st.Snapshot(ctx, snapDir); serr != nil {
		t.Fatalf("Snapshot: %v", serr)
	}

	var wrongSeed sqlite.MasterSeed
	if _, rerr := rand.Read(wrongSeed[:]); rerr != nil {
		t.Fatalf("rand: %v", rerr)
	}
	st2, err := sqlite.New(wrongSeed, snapDir)
	if err != nil {
		// New rejecting the snapshot at open time is the strongest
		// possible signal that the wrong seed cannot read the data.
		return
	}
	t.Cleanup(func() { _ = st2.Close() })
	if _, gerr := st2.GetQueue(ctx, q.ID); gerr == nil {
		t.Errorf("GetQueue with wrong seed should fail")
	}
}

func TestSnapshot_EmptyStoreProducesUsableMaster(t *testing.T) {
	t.Parallel()
	st, seed, _ := newTestStore(t)
	ctx := context.Background()

	snapDir := t.TempDir()
	if err := st.Snapshot(ctx, snapDir); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snapDir, "master.db")); err != nil {
		t.Fatalf("master.db should exist after empty snapshot: %v", err)
	}

	st2, err := sqlite.New(seed, snapDir)
	if err != nil {
		t.Fatalf("New(snap): %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })

	q, err := st2.CreateQueue(ctx, ownerKeys(t))
	if err != nil {
		t.Fatalf("CreateQueue on restored empty store: %v", err)
	}
	if q.ID == "" {
		t.Errorf("restored store returned empty queue id")
	}
}

func TestSnapshot_OverwritesStaleSnapshotFiles(t *testing.T) {
	t.Parallel()
	st, seed, _ := newTestStore(t)
	ctx := context.Background()

	q, err := st.CreateQueue(ctx, ownerKeys(t))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, perr := st.PutMessage(ctx, q.ID, []byte("v1")); perr != nil {
		t.Fatalf("put v1: %v", perr)
	}

	snapDir := t.TempDir()
	if serr := st.Snapshot(ctx, snapDir); serr != nil {
		t.Fatalf("first Snapshot: %v", serr)
	}

	if _, perr := st.PutMessage(ctx, q.ID, []byte("v2")); perr != nil {
		t.Fatalf("put v2: %v", perr)
	}
	if serr := st.Snapshot(ctx, snapDir); serr != nil {
		t.Fatalf("second Snapshot: %v", serr)
	}

	st2, err := sqlite.New(seed, snapDir)
	if err != nil {
		t.Fatalf("New(snap): %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	msgs, _, err := st2.ListMessages(ctx, q.ID, 100)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages after second snapshot, got %d", len(msgs))
	}
	bodies := []string{string(msgs[0].Blob), string(msgs[1].Blob)}
	hasV1, hasV2 := false, false
	for _, b := range bodies {
		switch b {
		case "v1":
			hasV1 = true
		case "v2":
			hasV2 = true
		}
	}
	if !hasV1 || !hasV2 {
		t.Errorf("missing message bodies: %v", bodies)
	}
}
