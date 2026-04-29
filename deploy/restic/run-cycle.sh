#!/bin/sh
# Periodic backup loop for the restic sidecar.
#
# For each configured region (primary, secondary, tertiary), swap the
# active credentials into the standard restic environment variables, run
# `restic init || true` (idempotent) and then `restic backup /data`.
# Regions whose RESTIC_REPOSITORY_* slot is empty are skipped, so the
# same script handles one-region, two-region, and three-region setups.

set -eu

backup_region() {
  suffix="$1"
  repo_var="RESTIC_REPOSITORY_${suffix}"
  pass_var="RESTIC_PASSWORD_${suffix}"
  key_var="AWS_ACCESS_KEY_ID_${suffix}"
  sec_var="AWS_SECRET_ACCESS_KEY_${suffix}"

  eval "repo=\${${repo_var}:-}"
  if [ -z "${repo}" ]; then
    return 0
  fi

  eval "RESTIC_REPOSITORY=\${${repo_var}}"
  eval "RESTIC_PASSWORD=\${${pass_var}}"
  eval "AWS_ACCESS_KEY_ID=\${${key_var}}"
  eval "AWS_SECRET_ACCESS_KEY=\${${sec_var}}"
  export RESTIC_REPOSITORY RESTIC_PASSWORD AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

  if ! restic snapshots --no-lock --quiet >/dev/null 2>&1; then
    restic init
  fi
  # Back up only the consistent snapshot directory written by moldd via
  # VACUUM INTO, never the live SQLCipher files alongside it. Backing up
  # the live files would risk torn-page reads against an in-flight
  # SQLite writer.
  restic backup --quiet /data/snap
}

interval="${BACKUP_INTERVAL_SECONDS:-60}"

while true; do
  backup_region PRIMARY || echo "primary backup failed; will retry next cycle" >&2
  backup_region SECONDARY || echo "secondary backup failed; will retry next cycle" >&2
  backup_region TERTIARY || echo "tertiary backup failed; will retry next cycle" >&2
  sleep "${interval}"
done
