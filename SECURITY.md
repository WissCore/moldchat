# Security policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in MoldChat, **please do not open a public GitHub issue or discuss it on social media**. We treat security reports as confidential until a fix is published.

**Preferred channel:** [GitHub Private Vulnerability Reporting](https://github.com/WissCore/moldchat/security/advisories/new).

**Backup channel:** email `alan@wisscore.com` — a plain email is fine, describe the issue as-is.

We commit to:

- **Acknowledge** your report within 72 hours.
- **Initial triage** within 7 days (severity, reproduction confirmation).
- **Coordinated disclosure** in agreement with you. Default embargo is 90 days from initial report, extendable by mutual agreement when a fix is non-trivial.
- **Credit you** in the advisory (your handle, your real name, or anonymous — your choice), unless you prefer otherwise.

## Scope

In scope:

- Cryptographic protocol flaws (handshake, ratcheting, key derivation, sealed sender, key transparency).
- Network transport flaws that enable identification, blocking, or active probing of MoldChat traffic.
- Client-side issues that leak plaintext, keys, or metadata (memory, storage, IPC, push notification payloads).
- Server-side issues that expose metadata beyond what the protocol requires (sender↔recipient mapping, contact lists, IPs).
- Build, release, and supply-chain integrity (signed releases, reproducibility).
- Authentication, authorisation, and anti-abuse mechanisms.

Out of scope:

- Reports requiring physical access without realistic threat models (e.g. cold-boot attacks against unencrypted RAM with no relation to the threat model).
- Self-XSS, missing best-practice headers without an exploitable consequence.
- Issues in third-party services (Cloudflare, Apple, Google) that we depend on and cannot fix.
- Social engineering of maintainers.

## Supported versions

| Version | Status      | Security fixes |
|---------|-------------|----------------|
| 0.x     | Pre-release | All affected releases |

We are pre-1.0. Until 1.0, security fixes are issued only on the latest minor release.

## Safe harbour

We will not pursue legal action against researchers who:

- Make a good-faith effort to comply with this policy.
- Avoid privacy violations, destruction of data, and disruption to users.
- Provide a reasonable time for us to fix issues before public disclosure.
- Do not exploit the issue beyond what is necessary to demonstrate it.

## CVE assignment

We file CVEs for vulnerabilities that affect user security via [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories).

## Acknowledgements

We maintain a list of researchers who have helped us at [moldchat.com/security](https://moldchat.com/security) (TBD).
