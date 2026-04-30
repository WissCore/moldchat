# Branch protection: required status checks

The `main` branch is gated by a single required status check named
**`ci / ci-success`**. That check is emitted by the `ci-success` job in
`.github/workflows/ci.yml`, which depends on every other CI job and
fails if any of them does not succeed (or is unexpectedly skipped).
This runbook is the operator-facing reference for keeping branch
protection in sync with the CI orchestrator.

## Required check

Set on **Settings → Branches → Branch protection rules → main**:

```text
Require status checks to pass before merging:  enabled
  ci / ci-success                              required
```

Nothing else from the `ci` workflow should be listed. Listing
sub-jobs by name (for example `ci / build-test`) is brittle — those
names are an implementation detail of the orchestrator's DAG and
will change as new tiers are added.

The `ci-success` job is the only stable contract: it succeeds when
the entire CI graph succeeds, and fails otherwise.

## Migrating from per-workflow checks

If the protection rule still lists per-workflow checks from the
pre-orchestrator era, replace the entire set with the single
`ci / ci-success` entry. Old check names that should be removed:

- `ci / server (Go)`
- `gitleaks / gitleaks`
- `zizmor / zizmor`
- `codeql / analyze (go)`
- `osv-scanner / scan`
- `dco / dco`
- `smoke / server smoke`
- `backup-roundtrip / snapshot -> restic -> restore`

Once `ci / ci-success` is required and these are removed, every PR
shows exactly one mandatory check; drilling into the run reveals the
full DAG.

## Independent workflows that stay required as themselves

A handful of workflows are not part of the orchestrator and remain
listed as separate required checks where the rule applied before:

- `dependency-review / dep-review` — runs only on `pull_request`
  events and uses the GitHub-internal diff API; cannot be invoked
  via `workflow_call`.
- `semantic-pr / validate` — validates the PR title against
  Conventional Commits 1.0; runs on `pull_request` title-edit
  events independent of the CI pipeline.

These should remain individually required if they were before.

## Adding a new check to the orchestrator

When a new validation joins the CI graph, add it to two places in
`.github/workflows/ci.yml`:

1. A new top-level job that `uses:` the reusable workflow.
2. The `needs:` list of the `ci-success` summary job.

If the new job is conditionally skipped (paths filter, event-type
gate, etc.), also add its name to the `allowed_skip` set in the
python check inside `ci-success`. Forgetting either step makes the
new check silently non-blocking — branch protection still passes
even when the new job fails.
