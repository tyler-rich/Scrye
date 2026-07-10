# Changelog

All notable changes to Scrye are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-09

First release. A self-hosted, browser-based web UI that unifies the
[Trivy](https://github.com/aquasecurity/trivy) and
[Grype](https://github.com/anchore/grype) scanners (with
[Syft](https://github.com/anchore/syft) for SBOMs) behind one normalized findings
model, in a single hardened container.

### Added

- **Trivy scanning** — container image and git repository (public/private)
  targets; selectable vulnerability, misconfiguration/IaC, secret, and license
  scanners; per-scan severity filter, `--ignore-unfixed`, and branch/commit/tag;
  optional Syft SBOM generation alongside an image scan; global VEX and
  `.trivyignore` policy.
- **Grype scanning** — container image, filesystem/directory (admin allowlist,
  off by default), and uploaded SBOM (CycloneDX / SPDX / Syft JSON) targets;
  global Grype ignore config.
- **Syft** — on-request SBOM generation, stored as a downloadable artifact and
  reusable as a Grype target.
- **Private registries** — field-encrypted credentials materialized into a
  transient in-memory Docker `config.json` at scan time; static credentials
  built in, ECR/GCR/ACR helper config generated (helper binaries not bundled).
- **Docker environments** — image enumeration via a read-only
  `docker-socket-proxy` sidecar; the app never mounts the Docker socket.
- **Normalized findings** — raw scanner JSON persisted verbatim as the source of
  truth, normalized into a shared 6-level severity model.
- **Exports** — CSV, Markdown, and JSON, per scan or across a filtered history
  set (with CSV formula-injection guards).
- **Scan history** — filterable, sortable, paginated, with saved filter presets
  and per-scan tags.
- **Scan diff** — new vs. fixed findings and per-severity deltas between two
  scans of the same target.
- **Dashboard** — total scans, 30-day trend, top vulnerable targets, open
  critical/high, scanner-DB freshness, recent scans, and failed-scan alerts.
- **Scheduled scans** — recurring scans on a 5-field cron cadence from saved
  templates, with a run-now action.
- **Notifications** — event-driven dispatch (scan completed / scan failed /
  critical-or-high findings) to webhook, Discord, SMTP, and Matrix channels, each
  with a test-send.
- **Result retention** — optional pruning of old raw artifacts while keeping scan
  rows and normalized findings.
- **Monitoring** — an authenticated Prometheus `/metrics` endpoint.
- **Authentication & RBAC** — local accounts (argon2id) with revocable
  server-side sessions, optional TOTP MFA with an enforceable policy, personal
  API tokens, and generic OIDC (Authlib, PKCE + nonce, ID-token validation)
  alongside local auth; viewer / operator / admin roles.
- **Secrets at rest** — AES-256-GCM field encryption with the master key from a
  Docker secret file; write-only secret API fields; log redaction; decryption
  only in memory at scan time into tmpfs.
- **Backup & restore** — portable, passphrase-protected bundles that re-wrap
  secrets on backup and re-encrypt them under the new host's master key on
  restore; optional scheduled backups with retention.
- **Distribution** — multi-arch (linux/amd64 + linux/arm64) image published to
  GHCR as `ghcr.io/tyler-rich/scrye:0.1.0` and `:latest` from a semver tag on
  `main`; bundled Trivy 0.72.0, Grype 0.115.0, and Syft 1.46.0 (Apache-2.0,
  license/notice files carried in the image).
- **Hardening** — CIS-aligned container posture (digest-pinned base images,
  non-root user, `cap_drop: ALL`, `no-new-privileges`, read-only root filesystem
  + tmpfs, resource limits, healthcheck, loopback-only port binding); CSRF
  protection, rate-limited auth, and an audit log.

[Unreleased]: https://github.com/tyler-rich/Scrye/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tyler-rich/Scrye/releases/tag/v0.1.0
