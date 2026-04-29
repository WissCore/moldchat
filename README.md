# MoldChat

> Speak freely. Secure messaging app, by design.

<p align="center">
  <img src="https://moldchat.com/wp-content/themes/mold/apple-touch-icon.png" alt="MoldChat" width="160">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="License"></a>
  <a href="https://github.com/WissCore/moldchat/releases"><img src="https://img.shields.io/github/v/release/WissCore/moldchat?include_prereleases" alt="Release"></a>
  <a href="https://github.com/WissCore/moldchat/actions"><img src="https://img.shields.io/github/actions/workflow/status/WissCore/moldchat/ci.yml?branch=main" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/WissCore/moldchat"><img src="https://api.scorecard.dev/projects/github.com/WissCore/moldchat/badge" alt="OpenSSF Scorecard"></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-orange" alt="Security policy"></a>
</p>

---

## Status

**Pre-alpha.** Design is being formalised. No production users. No protocol audit yet. Do not rely on MoldChat for life-and-limb threat models until at least one independent cryptographic audit is published.

## What this is

MoldChat is an end-to-end encrypted messenger built around one rule: **the traffic should look like ordinary HTTPS browsing on the wire**. Everything else — protocol choice, server architecture, distribution model — is derived from that rule.

MoldChat is built for people living under censorship and repression — journalists, human-rights defenders, and ordinary people whose safety depends on anonymity. Authoritarian governments do not stop at physical coercion of their citizens: they take control of civilian communications, block resources, throttle access, and outlaw the services the rest of the world uses. MoldChat is a messenger that stays invisible to those systems.

## Threat model in one paragraph

A passive network observer should not be able to identify a MoldChat user from traffic patterns alone. An active probe against a MoldChat server should not yield a positive identification. A compromised server should not reveal useful metadata about communication patterns. A compromised device should not reveal plaintext message history. Compromise of one endpoint should not retroactively decrypt prior sessions, nor indefinitely decrypt future ones.

A complete and current threat model lives in [docs/specs/](docs/specs/).

## Architecture in one diagram

```text
Android (Kotlin)               Server (Go)               iOS (Swift)
    |                              |                         |
    | libsignal-android            |                         | LibSignalClient
    | (E2E crypto, on device)      |                         | (E2E crypto, on device)
    |                              |                         |
    | sealed envelope ----->  per-contact queues  <----- sealed envelope
    |                         (opaque blobs only)            |
    |                              |                         |
    | SQLCipher + Keystore         | SQLite + Litestream     | SQLCipher + Keychain
    |                              | + Xray (REALITY)        |
```

The server holds opaque ciphertext blobs addressed by queue ID. It does not see senders, recipients, contents, social graphs, or message timing semantics beyond what is required for delivery. Crypto runs only on clients.

## Repository layout

```text
apps/android/         Android client (Kotlin + Jetpack Compose)
apps/ios/             iOS client (Swift + SwiftUI)
server/               Go server (single Go module)
docs/                 Architecture decisions, RFCs, protocol specs
deploy/               Docker, systemd units, deployment manifests
scripts/              Build, release, maintenance scripts
tools/                Code generation, dev utilities
.github/              CI workflows, issue templates, CODEOWNERS
.well-known/          security.txt and similar
```

## Build from source

Toolchain is pinned via [mise](https://mise.jdx.dev). After cloning:

```sh
mise install
```

Then per platform:

| Component       | Command                   | Output                          |
|-----------------|---------------------------|---------------------------------|
| Server          | `cd server && go build ./cmd/moldd` | `server/moldd`           |
| Android         | `cd apps/android && ./gradlew assembleRelease` | `apps/android/.../moldchat.apk` |
| iOS             | `cd apps/ios && xcodebuild ...` | `apps/ios/build/MoldChat.ipa` |

Detailed build instructions, including reproducible-build flags, are in [docs/build.md](docs/build.md) (TBD).

## Documentation

- [docs/specs/](docs/specs/) — protocol specifications
- [docs/adr/](docs/adr/) — architecture decision records (MADR)
- [docs/rfcs/](docs/rfcs/) — RFCs for cross-cutting changes
- Public site: [moldchat.com](https://moldchat.com)

## Security

If you believe you have found a security issue, **do not open a public issue**. Use [GitHub Private Vulnerability Reporting](https://github.com/WissCore/moldchat/security/advisories/new) or write to `alan@wisscore.com`. Full policy: [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first. All commits must carry a [DCO](https://developercertificate.org/) sign-off (`git commit -s`).

## Community

- Twitter / X: [@MoldChatHQ](https://x.com/MoldChatHQ)
- Telegram channel: [t.me/moldapp](https://t.me/moldapp)
- Questions and ideas: [GitHub Discussions](https://github.com/WissCore/moldchat/discussions)

## Support the project

MoldChat is free and will remain free. If you want to help us cover infrastructure and development:

- One-time card payment: see donation tiers at [moldchat.com/about#support](https://moldchat.com/about#support)
- GitHub Sponsors: TBD
- Cryptocurrency: TBD

## License

Copyright © 2026 Alan Wiss and MoldChat contributors.

Released under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE).

## Acknowledgements

MoldChat stands on top of work by people who built and audited the cryptographic primitives we rely on:

- [libsignal](https://github.com/signalapp/libsignal) — Signal Foundation
- [Xray-core / REALITY](https://github.com/XTLS/Xray-core) — XTLS team
- [openmls](https://github.com/openmls/openmls) — Phoenix R&D, Cryspen
- [Sigstore](https://github.com/sigstore) — OpenSSF
- [SQLCipher](https://github.com/sqlcipher/sqlcipher) — Zetetic

We do not invent cryptography. We integrate vetted libraries and we tell you which ones.
