# Scrye

> A unified, self-hosted web UI for the **Trivy** and **Grype** scanners.
> _("Scry": to perceive hidden things — fused with "scan.")_

Scrye puts a clean, modern browser UI in front of two best-in-class open-source
security scanners — [Trivy](https://github.com/aquasecurity/trivy) (Aqua
Security) and [Grype](https://github.com/anchore/grype) (Anchore) — so you can
run, review, export, and track vulnerability and configuration scans from one
place, on your own infrastructure.

[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](./LICENSE)
![Build](https://img.shields.io/badge/build-local-informational)

> **Project status — early, actively building.** Scrye is being built in phases
> (see the [Roadmap](#roadmap)). Shipped so far: the application skeleton
> (FastAPI + React/Mantine SPA, SQLite/Alembic, hardened CIS-aligned image) and
> the **auth & secrets foundation** — local accounts (argon2id) with revocable
> server-side sessions, first-run admin bootstrap, RBAC (viewer/operator/admin),
> CSRF protection, auth rate limiting, an audit log, and the AES-256-GCM
> field-encryption module for stored secrets. Scanning, history, and the rest of
> the features below are delivered in later phases and are documented here as
> the intended end state.

---

## Screenshots

_Placeholders — add real captures as the UI lands._

| Dashboard | New scan | Results | History |
| --------- | -------- | ------- | ------- |
| _TODO_    | _TODO_   | _TODO_  | _TODO_  |

---

## Features

Trivy and Grype each bring a different scope; Scrye unifies them behind one UI
and one normalized findings model.

- **Trivy scanning**
  - Targets: a **single container image** (registry ref or uploaded tar),
    **images running in a Docker environment** (enumerated via a read-only
    socket proxy), and **git repositories** (public or private).
  - Scanners (all selectable, default all): **vulnerabilities/CVEs**, **SBOM**
    (OS packages + dependencies), **IaC misconfiguration**, **secrets**, and
    **licenses**.
  - Per-scan options: scanner selection, severity filter, `--ignore-unfixed`,
    VEX policy, `.trivyignore` rules, repo branch/ref, SBOM format.
- **Grype scanning** (vulnerabilities — Grype's scope)
  - Targets: **container image**, **filesystem/directory**, and an existing
    **SBOM** (fed the Syft-generated SBOM directly).
  - **Private registries** via a transient, in-memory Docker config
    materialized at scan time (static creds and ECR/GCR/ACR credential helpers).
- **Syft** generates one SBOM per artifact, handed to Grype and stored as a
  downloadable artifact.
- **Normalized findings** — raw scanner JSON is persisted as the source of
  truth, then normalized so Trivy and Grype render in one table.
- **Exports** — **CSV**, **Markdown**, and **JSON**, per scan or for a filtered
  history set.
- **Scan history** — filterable, sortable, paginated table with saved presets;
  **scan diff** to compare two scans of the same target (new vs. fixed).
- **Dashboard** — aggregate widgets (totals, trend, top vulnerable targets, open
  critical/high, scanner-DB freshness, recent and failed scans).
- **Authentication** — local accounts (argon2id) with sessions and optional TOTP
  MFA, plus generic **OIDC** (Pocket ID / RS256). **RBAC**: viewer / operator /
  admin.
- **Secrets handling** — stored credentials are field-encrypted with
  **AES-256-GCM**; the master key comes from a Docker secret file; secret API
  fields are write-only. (See [Security model](#security-model).)
- **Backup & restore** — portable, passphrase-protected bundles that re-key
  secrets on restore; optional scheduled backups.
- **Notifications, scheduled scans, and API tokens** — for automation and alerts.

## Integrations

- **Trivy**, **Grype**, **Syft** — official binaries, orchestrated and parsed
  from their JSON output (Scrye never reimplements scanner logic).
- **OIDC** — generic, validated against Pocket ID.
- **Docker** — image enumeration via a **read-only** `docker-socket-proxy`
  sidecar (the app never mounts the Docker socket itself).
- **Private registries** — static credentials and ECR/GCR/ACR helpers.
- **Notification channels** — webhook / Discord / SMTP / Matrix (planned).

---

## Architecture

```
                         ┌───────────────────────────────────────────────┐
   Browser ── HTTPS ──▶  │  Caddy (reverse proxy + TLS)                   │
                         └───────────────────────────────────────────────┘
                                            │ HTTP (loopback / internal net)
                                            ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │  Scrye container (single image)                                    │
        │  ┌────────────────────┐   ┌──────────────────────────────────┐    │
        │  │ FastAPI API + SPA  │   │ In-process async scan worker     │    │
        │  │ - REST endpoints   │◀─▶│ - polls `scans` table            │    │
        │  │ - serves React SPA │   │ - runs trivy/grype subprocesses  │    │
        │  │ - auth / sessions  │   │ - parses JSON → findings         │    │
        │  └────────┬───────────┘   └───────────────┬──────────────────┘    │
        │           ▼                                ▼                       │
        │   ┌───────────────┐              ┌──────────────────┐             │
        │   │ SQLite (/data)│              │ trivy/grype/syft │             │
        │   │ field-encrypted│             │ binaries + DBs   │             │
        │   │   secrets      │             │ (/cache)         │             │
        │   └───────────────┘              └──────────────────┘             │
        └──────────────────────────────────────────────────────────────────┘
              │ optional sidecars (compose profiles):
              ├── trivy-server        (shared vuln-DB cache)
              └── docker-socket-proxy (read-only) ── "scan running images"
```

- **FastAPI app** serves the REST API and the built React SPA, and handles auth.
- **In-process async worker** runs scans (DB-backed `scans` table + a
  concurrency semaphore) — no Redis/arq in v1, but behind a thin interface so it
  could be swapped later.
- **SQLite** holds all state; stored secrets are field-encrypted at the app
  layer.
- **Scanner binaries** (`trivy`/`grype`/`syft`) are bundled and run as
  subprocesses.

---

## Requirements

- **Docker** 24+ and the **Compose v2** plugin.
- ~2 GB RAM available to the container for typical scans (configurable limits in
  Compose); disk for the scanner vulnerability databases (under `/cache`).
- Optional sidecars: a **Trivy server** (shared vuln-DB cache) and a read-only
  **docker-socket-proxy** (to scan running images).
- For native (non-container) development: **Python 3.12**, **Node 20+**, and the
  `trivy`/`grype`/`syft` binaries on `PATH`. See
  [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## Quick start

Scrye's image is **built locally** (there is no published registry image yet).

```bash
# 1. Clone
git clone https://github.com/iamgroot60/scrye.git
cd scrye

# 2. Create the application master key as a Docker secret file (never committed)
mkdir -p docker/secrets
openssl rand -base64 48 > docker/secrets/app_secret_key

# 3. Build the image and bring up the stack
docker compose -f docker/docker-compose.yml up --build -d

# 4. Verify health
curl -fsS http://127.0.0.1:8089/healthz
# {"status":"healthy","version":"0.1.0","database":"ok"}
```

Open <http://127.0.0.1:8089/> in your browser. The app binds to **loopback**
only; put it behind your own reverse proxy (e.g. Caddy) for TLS and external
access.

Persistent data lives in the `scrye_data` volume (SQLite database) and the
`scrye_cache` volume (scanner databases).

**First run:** open the app in your browser — while no accounts exist, Scrye
shows a one-time setup screen that creates the first account as **admin** and
signs it in (the setup endpoint permanently disables itself once any account
exists). Additional users are created by an admin, with roles: **viewer**
(read/export), **operator** (viewer + launch scans + own API tokens), or
**admin** (everything, incl. settings/users/credentials).

### Optional sidecars

```bash
# Shared Trivy vulnerability-DB cache
docker compose -f docker/docker-compose.yml --profile trivy-server up -d

# Read-only Docker socket proxy ("scan running images") — see Security model
docker compose -f docker/docker-compose.yml --profile docker-env up -d
```

---

## Configuration

Configuration is driven by environment variables (prefix `SCRYE_`). The
[`.env.example`](./.env.example) file is **generated from the backend
`Settings` model** — copy it to `.env` for local development. Only
**non-sensitive** variables belong there.

| Variable                    | Default                      | Description                                                       |
| --------------------------- | ---------------------------- | ----------------------------------------------------------------- |
| `SCRYE_APP_NAME`            | `Scrye`                      | Application name shown in the UI and logs.                        |
| `SCRYE_ENVIRONMENT`         | `production`                 | `development` or `production`.                                    |
| `SCRYE_LOG_LEVEL`           | `INFO`                       | Root log level.                                                   |
| `SCRYE_HOST`                | `0.0.0.0`                    | Bind address inside the container (published to loopback).        |
| `SCRYE_PORT`                | `8089`                       | API/SPA port inside the container.                                |
| `SCRYE_CORS_ORIGINS`        | _(empty)_                    | Comma-separated dev CORS origins (e.g. `http://localhost:5173`).  |
| `SCRYE_DATABASE_PATH`       | `/data/scrye.db`             | SQLite database file path.                                        |
| `SCRYE_APP_SECRET_KEY_FILE` | `/run/secrets/app_secret_key`| Path to the Docker secret file holding the **master key**.        |
| `SCRYE_SESSION_LIFETIME_HOURS` | `168`                     | Login session lifetime (hours).                                   |
| `SCRYE_SESSION_COOKIE_SECURE` | `true`                     | `Secure` flag on session cookies (disable only for plain-HTTP dev). |
| `SCRYE_AUTH_RATE_LIMIT_ATTEMPTS` | `5`                     | Max auth attempts per client IP per window.                       |
| `SCRYE_AUTH_RATE_LIMIT_WINDOW_SECONDS` | `60`              | Auth rate-limit window length (seconds).                          |
| `SCRYE_TRIVY_SERVER_URL`    | _(unset)_                    | Optional Trivy server URL (shared vuln-DB cache).                 |
| `SCRYE_DOCKER_PROXY_URL`    | _(unset)_                    | Optional read-only docker-socket-proxy URL.                       |
| `SCRYE_TRIVY_BINARY`        | `trivy`                      | Trivy binary path/name (resolved on `PATH` if a bare name).       |
| `SCRYE_GRYPE_BINARY`        | `grype`                      | Grype binary path/name (resolved on `PATH` if a bare name).       |
| `SCRYE_SYFT_BINARY`         | `syft`                       | Syft binary path/name (resolved on `PATH` if a bare name).        |
| `SCRYE_MAX_CONCURRENT_SCANS`| `2`                          | Max scans the in-process worker runs at once.                     |
| `SCRYE_SCAN_TIMEOUT_SECONDS`| `1800`                       | Per-scan wall-clock timeout (seconds).                            |
| `SCRYE_ARTIFACTS_DIR`       | `/data/artifacts`            | Directory holding raw scanner artifacts (JSON output, SBOMs).     |
| `SCRYE_FRONTEND_DIST_DIR`   | `/app/frontend/dist`         | Directory of the built SPA served by FastAPI.                     |

### The master key

The application **master key** is **never** an environment variable or baked
into an image layer. It is read at runtime from the Docker secret file pointed
to by `SCRYE_APP_SECRET_KEY_FILE` (default `/run/secrets/app_secret_key`).
Generate it once with `openssl rand -base64 48` and provide it as a Docker
secret. Stored credentials are encrypted with a key derived from it. In
production the app **refuses to start** without a valid key file.

**Key rotation:** the key file may hold multiple versions, one per line, as
`v<N>:<base64>` entries (a plain single-line key is version 1). New secrets are
encrypted under the highest version; older versions remain readable so existing
secrets can be re-encrypted, after which the old line can be removed.

---

## Usage

**Available now (Phase 2 — image scanning):**

- **Run an image scan** — from **New scan**, choose **Trivy** or **Grype** and
  enter a container image reference (e.g. `alpine:3.19` or
  `ghcr.io/org/app:tag`). For Trivy, pick which scanners run
  (vulnerabilities / misconfigurations / secrets / licenses), an optional
  severity filter, and whether to ignore unfixed vulnerabilities. Grype scans
  for vulnerabilities only. The in-process async worker runs the official binary
  under a concurrency limit and parses its JSON output.
- **Read results** — the **scan detail** page shows live status while the scan
  runs, then a severity summary and a normalized findings table (both scanners
  render in one shape). Filter findings by severity or class.
- **Raw artifacts** — every completed scan stores the scanner's original JSON
  verbatim as the source of truth; download it from the scan detail page.

**Coming in later phases:** git-repository / filesystem / SBOM targets and
private-registry credentials (Phase 3); history, scan diff, and CSV/Markdown/JSON
exports (Phase 4); OIDC, backup/restore, and settings (Phase 5).

Scanner options that stay write-only and secret (registry / git / OIDC
credentials, API tokens) are entered once and never returned in plaintext — the
API returns a mask and a "last updated" timestamp, and plaintext is only ever
decrypted in memory at scan time.

---

## Security model

- **Field-level encryption.** Stored secrets (registry creds, git tokens, OIDC
  client secret, API tokens) are encrypted with **AES-256-GCM** (random
  per-secret nonce, HKDF-derived key, key-version tagged). The database never
  holds plaintext secrets.
- **Master key via secret file.** The key comes from a Docker secret file
  (`SCRYE_APP_SECRET_KEY_FILE`) — never an env var or image layer.
- **Write-only secret API.** Secret fields accept values on write and return a
  mask (`••••`) plus a timestamp on read. A logging filter redacts secret
  fields.
- **Scan-time only.** Secrets are decrypted in memory into transient credential
  files on **tmpfs**, used for the scanner subprocess, then shredded.
- **CIS-aligned container posture.** Base images are pinned by digest;
  `trivy`/`grype`/`syft` are installed from the publishers' release archives and
  verified against their signed checksum files (never `curl | bash`); the image
  runs as a **non-root** user with `cap_drop: ALL`, `no-new-privileges`, a
  **read-only** root filesystem + tmpfs, resource limits, a healthcheck, and
  loopback-only port binding.
- **Docker socket residual risk.** "Scan running images" uses a **read-only**
  `docker-socket-proxy` restricted to read endpoints (`POST=0`). The Scrye app
  **never** mounts `/var/run/docker.sock`. The proxy is the only place the
  socket is mounted (read-only); anyone who can reach it can _enumerate_ images
  and containers, so enable that profile deliberately and keep it on the
  internal network.

---

## Backup & restore

Backups are **portable, passphrase-protected bundles** (SQLite dump + schema
version + manifest with checksums, optionally stored artifacts). Because secrets
are encrypted under the host master key (which does not travel), on backup each
secret is **re-wrapped** under a user-supplied passphrase; on restore you supply
the passphrase and Scrye **re-encrypts** the secrets under the new host's master
key. A restore therefore works on a fresh host with only the passphrase — no
master-key transplant. Scheduled backups to a mounted path with retention are
supported. _(Delivered in Phase 5.)_

---

## Roadmap

Build order (see [`docs/PLAN.md`](./docs/PLAN.md) §12):

- **Phase 0 — Scaffold** ✅ — repo structure, FastAPI + SPA skeleton,
  SQLite/SQLAlchemy/Alembic baseline, `/healthz`, teal theme + light/dark
  toggle, hardened Dockerfile, base docs.
- **Phase 1 — Auth & secrets foundation** ✅ _(this release)_ — local auth
  (argon2id) + revocable sessions + RBAC + first-admin bootstrap; AES-256-GCM
  envelope encryption with master-key rotation; write-only secret pattern + log
  redaction; CSRF + auth rate limiting; audit log.
- **Phase 2** — core scanning (Trivy image + Grype image), async worker,
  normalized findings, scan detail + raw artifacts.
- **Phase 3** — Trivy repo + git creds; Grype filesystem/SBOM; Syft SBOM;
  registry credentials; Docker-environment enumeration.
- **Phase 4** — history, filters, scan diff/trend, exports.
- **Phase 5** — full settings, OIDC + MFA, backup/restore, scheduled backups.
- **Phase 6** — dashboard, notifications, scheduled scans, API tokens,
  `/metrics`, retention, multi-arch build, self-scanning CI.

**Deferred (not in v1):** arq/Redis scale-out, SQLCipher full-DB encryption,
container-registry publishing.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for local development setup, project
layout, coding standards, testing, the PR process, and how to report security
issues privately.

## License

[MIT](./LICENSE).
