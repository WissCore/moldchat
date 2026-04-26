# Governance

MoldChat is a small, mission-driven open-source project. This document describes how decisions are made.

## Decision model

The current model is **lead maintainer with community input**.

- Day-to-day decisions are made by the lead maintainer (see [MAINTAINERS.md](MAINTAINERS.md)) and any active maintainers, in the open, on GitHub.
- Routine technical decisions follow [Architecture Decision Records](docs/adr/) (MADR format).
- Cross-cutting changes — protocol modifications, threat model changes, new external dependencies in security-sensitive paths — follow the [RFC process](docs/rfcs/).
- The community may propose changes via Issues, Discussions, or Pull Requests.

The model is intentionally lightweight while the project is small. It will evolve as the contributor base grows.

## Mission

The project mission is fixed and not subject to vote:

> Build a messenger whose network traffic and on-device footprint cannot be readily identified, classified, or attributed to a specific user by network observers, including well-resourced ones.

Any decision that reduces this property is rejected, regardless of other benefits.

## Conflicts

If a disagreement among maintainers cannot be resolved through normal review, the lead maintainer makes the final call and documents the rationale in an ADR.

## Code of Conduct

All interactions in project spaces are governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Enforcement is the responsibility of the maintainers.

## Funding and finances

MoldChat is currently funded by the lead maintainer and voluntary contributions. Income, when material, will be reported in a public transparency document.

## Relicensing

The project is licensed under AGPL-3.0. Relicensing would require:

- Consensus of all active maintainers.
- Permission from every contributor whose code is still in the tree, or removal of their contributions.
- A 60-day public comment period.

The project does not use a CLA, so there is no maintainer authority to relicense unilaterally. This is intentional.

## Trademarks

"MoldChat" and the Mold logo are unregistered marks used by the project. Use in association with derivative works that could mislead users about the origin or trustworthiness of the software is not permitted.
