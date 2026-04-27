# Storage operations runbook

Operational guidance for deployments using the SQLCipher storage backend
(`MOLDD_STORAGE=sqlite`). The code itself implements every guarantee
that can be enforced from inside the process; the items below are
host-level controls that the operator must apply to preserve those
guarantees end to end.

## Filesystem mount options

Mount the directory pointed to by `MOLDD_DATA_DIR` with `noatime` (and,
where supported, `nodiratime`):

```fstab
/dev/mapper/moldd-data  /var/lib/moldd  ext4  defaults,noatime,nodiratime  0 2
```

Without `noatime` the kernel updates an access timestamp every time the
server reads a queue file. Anyone with read-only filesystem access (a
backup tool, a forensic image, an unprivileged sidecar) can correlate
those timestamps with traffic patterns — defeating the metadata-privacy
half of the encryption-at-rest design.

## Backup pipelines

Both the master database (`master.db`) and its WAL files
(`master.db-wal`, `master.db-shm`) must be captured atomically. The
server periodically calls `PRAGMA wal_checkpoint(FULL)` after queue
deletions so that crypto-shredded salts do not survive in the WAL, but
between checkpoints the WAL holds recently-committed pages.

Acceptable strategies:

- File-system snapshot (LVM, ZFS, btrfs): captures all three files at
  the same instant. Preferred.
- `sqlite3 .backup` against a live `master.db`: SQLite handles the
  consistency for you.
- `cp master.db master.db-wal master.db-shm` while the server is
  running: only safe if the filesystem provides ordered writes and the
  caller copies all three files; otherwise the snapshot may be
  inconsistent.

Do **not** copy only `master.db`. A point-in-time `master.db` without
its matching WAL is a stale snapshot whose semantics depend on whether
the most recent checkpoint had run.

Per-queue files (`<shard>/<hex>.db`) currently run without WAL, so they
are atomically captured by a single file copy.

## Block-level encryption

The SQLCipher layer encrypts page contents but cannot hide:

- Filesystem metadata: directory entries, file sizes, mtime/ctime.
- WAL file size growth, which broadly correlates with write activity.
- The fact that `MOLDD_DATA_DIR` exists at all.

For deployments where these signals matter (state-actor adversary,
seizure-resistance), wrap the data directory in full-disk encryption
(LUKS) keyed independently from `MOLDD_MASTER_SEED`. Mount the LUKS
volume only after operator attestation at boot.

## Process-level limits

The per-queue `*sql.DB` cache is capped at 256 entries and each entry
consumes one file descriptor in the steady state. The master DB plus
its WAL/-shm consume three more. Listeners, log files, and runtime
housekeeping take roughly fifty. The default container `nofile` limit
of 1024 leaves comfortable headroom; explicitly raise it if you tune
the cache cap upward.

```yaml
# kubernetes example
securityContext:
  fsGroup: 65532
resources:
  limits:
    ...
# pod-level
spec:
  containers:
  - name: moldd
    securityContext:
      capabilities:
        drop: [ALL]
    resources: ...
    # nofile via kernel ulimit or sysctl
```

## Master seed handling

`MOLDD_MASTER_SEED` is the root of trust for both the master database
and every queue's derived key. Treat it like any other private signing
key:

- Never commit the value to source control.
- Provision via the platform's secret manager (Kubernetes Secrets +
  encryption-at-rest, Vault, AWS Secrets Manager, etc.). Mount it as an
  environment variable for the process and not as a file the server
  reads.
- Rotate by spinning up a fresh deployment with a new seed, replicating
  active queues out of the old store, and decommissioning the old node.
  In-place rekey is not currently supported — the salt scheme expects
  the seed to be stable for the lifetime of a queue.
- Never log the seed or anything derived from it. The slog handlers
  used by this server filter PII by convention; the seed itself never
  reaches any log call site, but any tool added to the operational
  pipeline must hold the same line.
