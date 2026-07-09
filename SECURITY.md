# Security Policy

Scrye is a self-hosted security scanner, so we take the security of Scrye itself
seriously. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a security
vulnerability.** Public disclosure before a fix is available puts every deployer
at risk.

Instead, report it privately through GitHub's **[private vulnerability
reporting](https://github.com/tyler-rich/Scrye/security/advisories/new)** (the
"Report a vulnerability" button on the repository's **Security** tab). If that is
unavailable to you, contact the maintainer directly rather than filing anything
public.

Please include, where you can:

- a description of the issue and its impact;
- the affected version, image tag, or commit;
- steps to reproduce (a proof of concept is ideal);
- any suggested remediation.

You will get an acknowledgement as soon as the report is triaged. We will work on
a fix, keep you updated, and credit you in the release notes unless you prefer to
remain anonymous. Please give us a reasonable window to prepare and ship a fix
before any public disclosure.

## Supported versions

Scrye is pre-1.0 and ships as a rolling set of image tags rather than long-lived
maintenance branches:

| Tag | Source | Security fixes |
| --- | ------ | -------------- |
| `ghcr.io/tyler-rich/scrye:latest` and `:<version>` | Tagged releases from `main` | Yes — always run the latest release. |
| `ghcr.io/tyler-rich/scrye:dev` | Nightly build of `dev` | Best-effort (moving tag; not for production). |

Fixes are made on `dev` and shipped in the next tagged release. There is no
back-porting to older `:<version>` tags — upgrade to the latest release to pick
up a security fix.

## Scope

In scope: the Scrye application (backend, frontend), its container image and
hardened Compose posture, its handling of stored secrets and credentials, and its
authentication/authorization.

Out of scope: vulnerabilities in the bundled upstream scanner binaries
(`trivy`/`grype`/`syft`) or their embedded modules — report those to Aqua
Security and Anchore respectively. Scrye tracks their fixes by keeping the pinned
scanner versions current (see the README "Building the image" note).
