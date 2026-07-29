# Changelog

All notable changes to Scrye are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The master key is generated automatically on first launch, so a new
  deployment starts with no pre-seeded secret.** Previously the container would
  not start until you had run `openssl rand -base64 48` into
  `secrets/app_secret_key` — and because Compose requires a `secrets:` file to
  exist before it will even read the stack, that was a hard first-run blocker
  rather than a startup error you could read. With no key supplied, Scrye now
  mints one from the OS CSPRNG (48 random bytes base64-encoded — the exact
  `openssl rand -base64 48` equivalent, clearing the existing entropy floor),
  writes it to `/data/app_secret_key` with mode `0600`, verifies those
  permissions off disk, and logs one INFO line saying where it went and that it
  **must be backed up**. Concurrent starts cannot both generate: the file is
  created with `O_CREAT|O_EXCL` and the loser reads the winner's key.

  **Precedence is unchanged where it already existed.** A Docker secret at
  `SCRYE_APP_SECRET_KEY_FILE` still wins over everything; generation is the last
  resort, and only when no key file exists. Two new settings control it:
  `SCRYE_APP_SECRET_KEY_AUTOGENERATE` (default `true`) and
  `SCRYE_APP_SECRET_KEY_AUTOGEN_FILE` (default `/data/app_secret_key`).

  **An existing key file is never replaced.** A key file that exists but cannot be
  loaded — unreadable, empty, not base64, too short, malformed — now fails startup
  instead of ever being regenerated, because a second key would leave every stored
  secret undecryptable while the app looked healthy. For the same reason: a *set*
  `SCRYE_APP_SECRET_KEY_FILE` pointing at a missing file is a startup error, not a
  cue to generate one; and a supplied secret alongside a previously auto-generated
  key that it does not cover stops startup until the two are reconciled.

  **Existing deployments are unaffected** — their key file is found exactly as
  before, and no stored ciphertext changed (no KDF or token-format change). **New
  deployments must back up `/data/app_secret_key`**: lose it and every stored
  secret is unrecoverable. See [The master key](README.md#the-master-key), which
  now documents the precedence order, the loss consequences, and the trade-off of
  the generated key living on the same volume as the database it protects.

  `docker/docker-compose.yml` and the README paste-in stack no longer require the
  secret; the Docker-secret blocks are kept, commented out, for deployments that
  want the key and the data on separate mounts.

### Changed

- **The Compose stack no longer uses `deploy:` keys, so it deploys on NAS
  container platforms.** Synology Container Manager and QNAP Container Station
  reject or mishandle the Swarm-oriented `deploy:` block, which
  `docker/docker-compose.yml` used to carry on all three services — the stack
  simply would not deploy there, even though Compose v2 honours `deploy:`
  standalone.

  **Memory limits are unchanged in effect and still on by default**, now written
  with the portable `mem_limit` / `mem_reservation` keys: `scrye` 2g (256m
  reserved), `trivy-server` 1g, `docker-socket-proxy` 64m. Compose treats these
  and `deploy.resources.limits.memory` as the same field.

  **CPU limits moved to a new opt-in overlay,
  `docker/docker-compose.cpu-limits.yml`**, rather than being deleted — the caps
  (`scrye` 2.0, `trivy-server` 1.0, `docker-socket-proxy` 0.5) are a hardening
  measure and the 0.5 cap on the socket proxy in particular is deliberate. Apply
  it with a second `-f`:

  ```bash
  docker compose -f docker/docker-compose.yml \
                 -f docker/docker-compose.cpu-limits.yml up -d
  ```

  **Action required only if you want CPU caps back:** add that second `-f` (on
  every command for the stack, not just `up`), or set `COMPOSE_FILE` once. A
  plain `docker compose up` now starts without CPU limits; memory limits apply
  either way. If you deploy with your own Compose file, the paste-in stack in the
  README changed the same way. See
  [Resource limits](README.md#resource-limits-and-nas-platforms).

- **The backend runtime moved from Python 3.13 to Python 3.14.** The image is
  built on `python:3.14-slim-bookworm`, digest-pinned to **3.14.6**. The floor is
  3.14.6 and not lower: 3.14.0–3.14.4 shipped an incremental garbage collector
  that let resident memory grow several-fold in long-running servers, reverted in
  3.14.5. Native (non-container) development now needs Python 3.14.

  **No interpreter CVE is cleared by this move.** It was scoped on the premise
  that 3.14.6 carried the **CVE-2025-15366** / **CVE-2025-15367** (imaplib/poplib
  command injection) fixes. It does not: released 3.14.6 has neither guard, so the
  upgrade cleared nothing at the version the image pins. **CVE-2026-15308** and
  **CVE-2026-12003** were already known to be unaffected by the move. All four stay
  waived in the dogfood scan.

  What *has* changed is the outlook, and only for one of them. Three of the four —
  CVE-2026-15308, CVE-2026-12003 and **CVE-2025-15366** — now have their fixes
  merged on the CPython `3.14` maintenance branch and unreleased, so they close on
  the next point release, **3.14.7**; they are tracked in **issue #98** with a
  2026-10-25 review. Only **CVE-2025-15367** (poplib) is genuinely unfixable below
  3.15 — its fix exists on `main` alone with no backport to any maintenance branch —
  and it is a standing accepted risk with an annual re-confirmation, tracked in
  **issue #52**. An earlier version of this entry said all four were unfixable until
  3.15 and pointed at #52 for all of them; both statements were wrong, and the
  imaplib backport had in fact merged before this entry was first written.

  Dependencies bumped for 3.14: `pydantic` 2.10.4 → 2.13.4, `uvicorn[standard]`
  0.34.0 → 0.51.0, `sqlalchemy` 2.0.36 → 2.0.51, and a new explicit
  `greenlet` 3.5.4 pin for SQLAlchemy's async support. The pydantic bump is
  behaviour-neutral for API consumers: the only OpenAPI-schema change is that
  fields typed as a bare object now state `"additionalProperties": true`
  explicitly, which was already implied.

  **No action required for deployments** — pull the new image. Only contributors
  running the backend natively need to recreate their virtualenv on 3.14.

- **List endpoints returning persisted resources now use the shared
  `{total, items}` envelope.** Thirteen endpoints that previously returned a
  bare JSON array now return `{"total": <int>, "items": [...]}`, matching the
  shape `/api/scans/history`, `/api/scans/{id}/findings`, and `/api/audit`
  already used:

  `GET /api/registries` · `GET /api/git-credentials` · `GET /api/users` ·
  `GET /api/notifications` · `GET /api/scan-schedules` · `GET /api/api-tokens` ·
  `GET /api/backups` · `GET /api/filter-presets` ·
  `GET /api/docker-environments` · `GET /api/trivy/vex-documents` ·
  `GET /api/trivy/ignore-rules` · `GET /api/auth/sessions` ·
  `GET /api/scans/{id}/artifacts`

  These endpoints remain unpaginated, so `total` always equals `items.length`
  today. Enveloping them now means pagination can be added later as a purely
  additive `limit`/`offset` parameter rather than as a second breaking change.

  The convention that decides a new endpoint's shape: **persisted resource
  collections** get the envelope; **fixed enumerations and live, non-persisted
  data** stay bare arrays. Four endpoints are therefore deliberately unchanged —
  `GET /api/registries/options`, `GET /api/git-credentials/options`,
  `GET /api/notifications/events`, and
  `GET /api/docker-environments/{id}/images`. See `CONTRIBUTING.md`
  § API conventions.

  **Action required for API-token consumers only.** Scripts calling any of the
  thirteen endpoints above must read the rows from `.items`
  (`resp.json()["items"]` instead of `resp.json()`). The Scrye web UI is
  unaffected — it unwraps the envelope in its API client, and no page behavior
  changed. (L13 / APIR-8 — see [`docs/ARCHIVE.md` §15](docs/ARCHIVE.md#15-finding-id-index-decoder-for-14s-citations))

- **`GET /api/scans` is deprecated** in favour of `GET /api/scans/history`. It
  returns a bare array with no total, so a client paging through it cannot tell
  when the results are exhausted. Its response shape is a frozen contract and is
  **unchanged**; only the OpenAPI `deprecated` marker and a description naming
  the replacement were added. `/api/scans/history` supersedes it with the full
  filter set and the standard `{total, items}` envelope.

- **Docker socket proxy migrated to `wollomatic/socket-proxy`.** The optional
  `docker-env` sidecar — the only container in the stack that mounts
  `/var/run/docker.sock` — now runs `wollomatic/socket-proxy` (a from-scratch Go
  binary running as uid 65534, digest-pinned) instead of
  `tecnativa/docker-socket-proxy` (HAProxy on Alpine, running as root). Its
  request allowlist is pinned to the **single** endpoint Scrye calls,
  `GET /images/json`; every other path is refused with 403 and every other method
  with 405 before reaching the socket, and only the `scrye` container may connect.
  The previous configuration allowed the whole `/images` and `/containers` GET
  surface — including `/containers/{id}/json` (container environment variables),
  `/containers/{id}/archive`, and `/containers/{id}/export` — to any client on the
  Compose network. The sidecar also no longer needs a writable `/run` tmpfs.
  ([#63](https://github.com/tyler-rich/Scrye/issues/63))

  **Action required if you use the `docker-env` profile:** the proxy now runs
  unprivileged and must be given the host's docker group id to read the socket —
  set `DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"` before
  `docker compose --profile docker-env up`. Derive it rather than trusting the
  Compose fallback of `999` — that is a convention, not a guarantee, and the
  Debian host this was verified on used `989`. A wrong value crash-loops the
  sidecar (STATUS `Restarting`) and leaves image enumeration returning 502; it
  does not affect the rest of Scrye. No Scrye configuration changes;
  `SCRYE_DOCKER_PROXY_URL` and port 2375 are unchanged.

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
