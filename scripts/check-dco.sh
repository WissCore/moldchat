#!/usr/bin/env bash
# Verify the commit message contains a valid Developer Certificate of Origin sign-off.
# See https://developercertificate.org/ for the DCO text.
set -euo pipefail

msg_file="${1:?usage: check-dco.sh <commit-msg-file>}"

if grep -qE '^Signed-off-by: .+ <.+@.+>$' "$msg_file"; then
  exit 0
fi

cat >&2 <<'EOF'
Error: missing Developer Certificate of Origin sign-off.

Every commit must end with a line like:
    Signed-off-by: Your Name <you@example.com>

Use 'git commit -s' to add it automatically, or amend with:
    git commit --amend -s --no-edit
EOF
exit 1
