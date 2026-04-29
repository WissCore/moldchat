# Restic restore runbook

Recovery procedure for the SQLCipher snapshot pipeline (see
`deploy/compose.yaml` and `deploy/restic/run-cycle.sh`). Use this when
the live `MOLDD_DATA_DIR` is lost or corrupted and you need to bring
a fresh moldd instance up against the latest snapshot from one of the
configured jurisdictions.

## Scope

This procedure restores:

- the `master.db` index of all queues that existed at snapshot time
- every per-queue SQLCipher database that was open at snapshot time

It does **not** recover:

- messages produced after the most recent snapshot (RPO is the snapshot
  cadence — 60 s by default)
- queues created and deleted entirely between snapshots

## Prerequisites

You will need, in this order:

1. The original `MOLDD_MASTER_SEED`. Without it the restored `.db`
   files are opaque ciphertext. The seed is the root of trust; treat
   recovery without it as data loss.
2. `restic` v0.18.x or newer on the recovery host.
3. Read access to **one** of the configured jurisdictional buckets.
   A single healthy region is sufficient; the others are redundancy.
   Locate the matching `RESTIC_REPOSITORY_*`, `RESTIC_PASSWORD_*`,
   `AWS_ACCESS_KEY_ID_*`, `AWS_SECRET_ACCESS_KEY_*` from the operator
   secret store.
4. A clean target directory on the recovery host with at least the
   snapshot's footprint of free space. A tmpfs-backed staging path is
   acceptable and preferable for state-actor threat models.

## Procedure

### 1. Stop the failed instance

Hard-stop any moldd process still attached to the old `MOLDD_DATA_DIR`
before touching the data tree. A live writer would race the restore and
either corrupt the restored files or be silently overwritten:

```sh
docker compose stop moldd
```

### 2. Point the restic environment at one repository

Pick the jurisdiction with the freshest known-good snapshot (start with
the primary; fall back to the next region if it is unreachable). Export
the matching credentials:

```sh
export RESTIC_REPOSITORY=s3:https://s3.eu-central-003.backblazeb2.com/moldd-backup-eu
export RESTIC_PASSWORD=<primary-passphrase>
export AWS_ACCESS_KEY_ID=<primary-key-id>
export AWS_SECRET_ACCESS_KEY=<primary-application-key>
```

### 3. List snapshots and pick one

```sh
restic snapshots
```

Each row is one backup cycle. The newest is usually correct; if the
disaster started at a known time, prefer the last snapshot taken
before that timestamp.

### 4. Verify repository integrity before restoring

A restore from a corrupted repository silently produces corrupted
output. Always check first:

```sh
restic check                       # structural integrity, fast
restic check --read-data           # full crypto verification, slow
```

For multi-gigabyte repositories, a sampled check is acceptable on the
critical path:

```sh
restic check --read-data-subset=10%
```

### 5. Dry-run the restore

```sh
restic restore latest --target /tmp/restore --dry-run --verbose=2
```

Confirm the file count and total size against the snapshot listing
from step 3. A wildly different count means you have the wrong
snapshot or are pointing at the wrong path inside it.

### 6. Restore

```sh
restic restore latest --target /tmp/restore
```

The restored tree appears under
`/tmp/restore/<absolute-path-of-snap-dir-at-backup-time>` because
restic preserves the original absolute path. Locate it:

```sh
find /tmp/restore -name master.db
```

### 7. Install into a fresh data directory

The restored snapshot directory has the same shard layout as a live
`MOLDD_DATA_DIR`: `master.db` at the root and `<shard>/<hash>.db` per
queue. Move it (or symlink it) into place:

```sh
mv /tmp/restore/<original-snap-path> /var/lib/moldd-recovered
```

### 8. Boot a new instance against the restored data

```sh
MOLDD_DATA_DIR=/var/lib/moldd-recovered \
MOLDD_MASTER_SEED=<original-seed> \
docker compose up -d moldd
```

If the seed is correct, moldd starts cleanly. If the seed is wrong,
the first SQLCipher operation fails with `file is not a database` —
this is a key mismatch, not corruption.

## Post-restore validation

After moldd is up, confirm each guarantee independently:

- `GET /healthz` returns 200.
- `gh api ...` (or the equivalent admin tool, when one exists) lists
  the queues you expected to recover.
- A test client creates a queue, puts and lists a message — proves the
  master DB and per-queue write path are functional end to end.
- Container logs show no `decrypt` or `cipher` errors during the first
  five minutes of traffic.

## Failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| `restic check` reports inconsistencies | Repository corruption at the provider | Switch to a different jurisdiction's repository (steps 2–6) |
| `file is not a database` on first read | Wrong `MOLDD_MASTER_SEED` | Verify seed against operator records; the file is intact, the key is wrong |
| `master.db` missing from restore tree | Selected an old or partial snapshot | Re-run step 3 picking a different snapshot ID |
| Restore extracts but moldd refuses to start with `permission denied` | Restored files owned by root, moldd runs as nonroot | `chown -R 65532:65532 /var/lib/moldd-recovered` |
| All three jurisdictions unreachable | Network partition or coordinated outage | Recovery is paused until at least one bucket is reachable; there is no offline fallback in this design |
