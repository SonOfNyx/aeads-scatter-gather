# Security Policy

> **⚠️ Fork Information & Security Disclaimer**
> This repository is a modified fork of the upstream RustCrypto AEAD crates, adapted to support scatter-gather/streaming APIs.
> **Please note that these modifications have not undergone a formal security audit. Use at your own risk.**

## Supported Versions

Security updates are applied only to the most recent release.

## Reporting a Vulnerability

If you have discovered a security vulnerability in this project, please report
it privately. **Do not disclose it as a public issue.** This gives us time to
work with you to fix the issue before public exposure, reducing the chance that
the exploit will be used before a patch is released.

Since this project is a fork, please route your report based on where the vulnerability lies:

1. **Upstream Vulnerabilities (Core Algorithms):**
   If the issue affects the original RustCrypto implementation, please report it directly to the upstream maintainers via their [security advisory](https://github.com/RustCrypto/AEADs/security/advisories/new).

2. **Fork-Specific Vulnerabilities (Scatter-Gather API):**
   If the issue is specific to the modifications made in this fork (e.g., the scatter-gather additions), please disclose it to the developers of this fork by sending an email to: [ni_sc@uni-bremen.de](mailto:ni_sc@uni-bremen.de).

This project is maintained by a team of volunteers on a reasonable-effort basis.
As such, please give us at least 90 days to work on a fix before public exposure.
