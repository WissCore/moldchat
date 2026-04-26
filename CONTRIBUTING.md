# Contributing to MoldChat

Thank you for considering a contribution. MoldChat is a privacy-focused messenger with strict threat-model commitments; the bar for changes is high, and we expect every contributor to read this document before opening a PR.

## What we accept

- **Bug fixes** with a clear reproduction.
- **Documentation improvements** that make the project easier to audit, build, or use.
- **Test coverage** for existing functionality.
- **Security hardening** that does not change observable behaviour.
- **Refactors** that reduce surface area, complexity, or dependencies.

## What needs prior discussion

Open an issue or discussion **before** starting work on:

- Cryptographic protocol changes.
- Network transport changes (anything that affects traffic-shape properties, fingerprinting resistance, or REALITY config).
- New external dependencies, especially crypto libraries.
- New features, especially user-visible ones.
- Anything that changes the threat model.

For substantial changes, open an [RFC](docs/rfcs/) PR before implementation.

## Developer Certificate of Origin (DCO)

Every commit **must** carry a `Signed-off-by:` trailer that certifies the [Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s -m "feat(server): add session resumption"
```

This appends:

```text
Signed-off-by: Your Name <your.email@example.com>
```

PRs without DCO sign-off on every commit will be blocked by CI.

We do **not** require a CLA.

## Signed commits

All commits must be cryptographically signed with GPG. PRs with unsigned commits will be blocked by branch protection. Set up signing once:

```sh
# 1. Generate a GPG key (Ed25519)
gpg --full-generate-key
# choose: (9) ECC and ECC, (1) Curve 25519, expire 2y
# Real name: Your Name
# Email: your.email@example.com
# Passphrase: strong, store in a password manager

# 2. Find your KEY_ID
gpg --list-secret-keys --keyid-format=long
# in "sec ed25519/<KEY_ID>", copy the part after the slash

# 3. Configure git
KEY_ID=YOUR_KEY_ID_HERE
git config --global user.signingkey $KEY_ID
git config --global commit.gpgsign true
git config --global tag.gpgsign true
echo 'export GPG_TTY=$(tty)' >> ~/.bashrc && source ~/.bashrc

# 4. Export the public key for GitHub
gpg --armor --export $KEY_ID
```

Copy the output of the last command (from `-----BEGIN` to `-----END`) and add it to your GitHub account under Settings → SSH and GPG keys → **New GPG key**.

**Back up the private key** (losing it means your commits can no longer be signed with this identity):

```sh
gpg --export-secret-keys --armor $KEY_ID > my-gpg-private.asc
# store in a password manager or an encrypted USB; never in git, never in unencrypted cloud
```

## Workflow

1. Fork the repository.
2. Create a topic branch from `main`: `feat/short-kebab`, `fix/issue-123`, `docs/...`, `chore/...`.
3. Make focused commits using [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `build:`, `ci:`, `chore:`, `revert:`, optional scope `feat(server): ...`, breaking with `feat!:` or footer).
4. Push and open a pull request.
5. CI must pass: build, tests, secret scan, dependency review, code scanning, DCO check.
6. Resolve review comments. We squash-merge by default.

## Code style

Tooling is pinned via [mise](https://mise.jdx.dev) — run `mise install` once. Pre-commit hooks are managed by [lefthook](https://github.com/evilmartians/lefthook) — run `lefthook install` once.

| Language | Formatter        | Linter                    |
|----------|------------------|---------------------------|
| Go       | `gofumpt`        | `golangci-lint`, `gosec`, `govulncheck` |
| Kotlin   | `ktfmt`          | `detekt` (with ktlint rules) |
| Swift    | `swift-format`   | `swiftlint --strict`      |
| Markdown | (none)           | `markdownlint`            |
| Shell    | `shfmt -i 2`     | `shellcheck`              |

## Tests

- Server (Go): `go test ./...` from `server/`.
- Android: `./gradlew test` from `apps/android/`.
- iOS: `xcodebuild test ...` from `apps/ios/`.

Crypto-touching changes must include unit tests against known-answer vectors where applicable.

## Reporting security issues

**Do not** open a public issue or PR for security problems. Follow [SECURITY.md](SECURITY.md).

## Code of conduct

By participating, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

By contributing, you agree that your contributions are licensed under the GNU Affero General Public License v3.0 (AGPL-3.0), the same licence as the project.
