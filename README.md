# Scrye

> A unified, self-hosted web UI for the **Trivy** and **Grype** scanners.
> _("Scry": to perceive hidden things — fused with "scan.")_

Scrye puts a clean, modern browser UI in front of two best-in-class open-source
security scanners — [Trivy](https://github.com/aquasecurity/trivy) (Aqua
Security) and [Grype](https://github.com/anchore/grype) (Anchore) — so you can
run, review, export, and track vulnerability and configuration scans from one
place, on your own infrastructure. It orchestrates the official scanner binaries,
persists their raw JSON as the source of truth, and normalizes the results into a
single findings model so Trivy and Grype render in one table.

[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](./LICENSE)
![Build](https://img.shields.io/badge/build-multi--arch-informational)

- **What it is:** one container that serves a React SPA and a FastAPI backend,
  runs `trivy`/`grype`/`syft` as subprocesses, and stores everything in SQLite.
- **Who it's for:** teams that want a self-hosted, hardened scan console with
  history, exports, scheduling, notifications, RBAC, and OIDC — without wiring a
  pipeline together by hand.
- **Distribution:** stable releases on Docker Hub (`securedbytyler/scrye`), the
  moving dev build on GHCR (`ghcr.io/iamgroot60/scrye:dev`), or build locally
  from this repo.

---

## Contents

- [Screenshots](#screenshots)
- [Features](#features)
- [Integrations](#integrations)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Deploying with Docker](#deploying-with-docker)
  - [1. Prerequisites](#1-prerequisites)
  - [2. Choose an image](#2-choose-an-image-build-docker-hub-or-ghcr)
  - [3. Generate the application master key](#3-generate-the-application-master-key)
  - [4. Bring up the stack](#4-bring-up-the-stack)
  - [5. First-run setup (admin bootstrap)](#5-first-run-setup-admin-bootstrap)
  - [6. Where persistent data lives](#6-where-persistent-data-lives)
  - [7. Optional sidecars](#7-optional-sidecars)
  - [8. Put it behind a reverse proxy](#8-put-it-behind-a-reverse-proxy)
  - [Troubleshooting first-run issues](#troubleshooting-first-run-issues)
- [Configuration](#configuration)
- [Configuring OIDC](#configuring-oidc)
- [Usage](#usage)
- [Security model](#security-model)
- [Backup & restore](#backup--restore)
- [Monitoring](#monitoring)
- [Building the image yourself](#building-the-image-yourself)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Screenshots

_Placeholders — real captures are tracked on the [roadmap](./docs/ROADMAP.md)._

| Dashboard | New scan | Results | History |
| --------- | -------- | ------- | ------- |
| _TODO_    | _TODO_   | _TODO_  | _TODO_  |

---

## Features

Trivy and Grype each bring a different scope; Scrye unifies them behind one UI
and one normalized findings model.

- **Trivy scanning**
  - Targets: a **single container image** (registry reference) and a **git
    repository** (public or private, by HTTPS clone URL with optional
    branch/commit/tag).
  - Scanners (selectable per scan, default all): **vulnerabilities/CVEs**
    (`vuln`), **misconfiguration/IaC** (`misconfig`), **secrets** (`secret`),
    and **licenses** (`license`). An optional Syft **SBOM** can be generated
    alongside an image scan.
  - Per-scan options: scanner selection, severity filter
    (`UNKNOWN`…`CRITICAL`), `--ignore-unfixed`, repo branch/commit/tag, and SBOM
    format. **VEX policy** and **`.trivyignore`** rules are managed **globally**
    (Settings → Trivy policy) and applied to every Trivy scan, not entered
    per-scan.
- **Grype scanning** (vulnerabilities — Grype's scope)
  - Targets: **container image**, **filesystem/directory** (a mounted path
    under an admin-configured allowlist — disabled by default), and an existing
    **SBOM** (uploaded CycloneDX / SPDX / Syft JSON). A global Grype ignore
    config (Settings → Scanners) is applied to every Grype scan.
- **Syft** generates one SBOM per artifact on request, stored as a downloadable
  artifact and usable as a Grype SBOM target.
- **Private registries** — a transient, in-memory Docker `config.json` is
  materialized in tmpfs at scan time from a stored, field-encrypted credential.
  Static username/password and token credentials work out of the box; ECR/GCR/ACR
  credential-helper config is generated, but the **helper binaries are not
  bundled** — those registry types work only where the helper is present in the
  runtime environment.
- **Normalized findings** — raw scanner JSON is persisted verbatim as the source
  of truth, then normalized into a shared model with a 6-level severity scale so
  Trivy and Grype findings render in one table.
- **Exports** — **CSV**, **Markdown**, and **JSON**, per scan or across a
  filtered history set (with CSV formula-injection guards).
- **Scan history** — a filterable, sortable, paginated table (by scanner, target
  type, target text search, status, date range, initiator, highest severity,
  severity threshold, and tags), with **saved presets** and per-scan **tags**.
- **Scan diff** — compare two scans of the same target/scanner/type to see **new
  vs. fixed** findings and the per-severity delta over time.
- **Dashboard** — aggregate posture: total scans, a 30-day trend, top vulnerable
  targets, open critical/high (from the latest scan per target), scanner-DB
  freshness, recent scans, and failed-scan alerts.
- **Scheduled scans** — recurring scans on a standard 5-field **cron** cadence,
  from a saved scan template, with a "run now" action.
- **Notifications** — event-driven dispatch on **scan completed / scan failed /
  critical-or-high findings** to **webhook / Discord / SMTP / Matrix** channels,
  each subscribing to the events it cares about, each with a "send test" action.
- **Result retention** — optionally prune the raw scanner artifacts of old scans
  to bound disk usage while keeping the scan rows and normalized findings.
- **Metrics** — an authenticated Prometheus **`/metrics`** endpoint.
- **Authentication** — local accounts (**argon2id**) with revocable server-side
  sessions, optional **TOTP MFA** (with an enforceable policy), personal **API
  tokens**, and generic **OIDC** alongside local auth. **RBAC**: viewer /
  operator / admin.
- **Secrets handling** — stored credentials are field-encrypted with
  **AES-256-GCM**; the master key comes from a Docker secret file; secret API
  fields are write-only. (See [Security model](#security-model).)
- **Backup & restore** — portable, passphrase-protected bundles that re-key
  secrets on restore; optional scheduled backups with retention.

## Integrations

- **Trivy**, **Grype**, **Syft** — official binaries (currently Trivy `0.72.0`,
  Grype `0.115.0`, Syft `1.46.0`), orchestrated and parsed from their JSON output
  (Scrye never reimplements scanner logic). All three are Apache-2.0; their
  `LICENSE`/`NOTICE` files are bundled unmodified in the image at
  `/THIRD_PARTY_LICENSES` (see
  [`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/README.md)).
- **OIDC** — generic OpenID Connect (Authlib, authorization-code + PKCE, RS256),
  validated against Pocket ID. Configured entirely in the UI.
- **Docker** — image enumeration via a **read-only** `docker-socket-proxy`
  sidecar; the app never mounts the Docker socket itself.
- **Private registries** — static credentials (built in); ECR/GCR/ACR credential
  helpers where the deployment provides the helper binary.
- **Notification channels** — webhook / Discord / SMTP / Matrix, dispatched on
  scan events.
- **Prometheus** — an authenticated `/metrics` endpoint for scraping.

---

## Architecture

```
                         ┌───────────────────────────────────────────────┐
   Browser ── HTTPS ──▶  │  Reverse proxy + TLS (e.g. Caddy / nginx)      │
                         └───────────────────────────────────────────────┘
                                            │ HTTP (loopback / internal net)
                                            ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │  Scrye container (single image)                                    │
        │  ┌────────────────────┐   ┌──────────────────────────────────┐    │
        │  │ FastAPI API + SPA  │   │ In-process async scan worker     │    │
        │  │ - REST endpoints   │◀─▶│ - claims queued `scans` rows     │    │
        │  │ - serves React SPA │   │ - runs trivy/grype/syft subproc  │    │
        │  │ - auth / sessions  │   │ - parses JSON → findings         │    │
        │  └────────┬───────────┘   └───────────────┬──────────────────┘    │
        │           ▼                                ▼                       │
        │   ┌────────────────┐             ┌──────────────────┐             │
        │   │ SQLite (/data) │             │ trivy/grype/syft │             │
        │   │ field-encrypted│             │ binaries + DBs   │             │
        │   │   secrets      │             │ (/cache)         │             │
        │   └────────────────┘             └──────────────────┘             │
        └──────────────────────────────────────────────────────────────────┘
              │ optional sidecars (compose profiles):
              ├── trivy-server        (shared vuln-DB cache)
              └── docker-socket-proxy (read-only) ── "scan running images"
```

- **FastAPI app** serves the REST API and the built React SPA, and handles auth,
  running database migrations (`alembic upgrade head`) on startup.
- **In-process async worker** runs scans (DB-backed `scans` table + a
  concurrency semaphore) behind a thin `ScanWorker` interface — no Redis/arq in
  v1, but swappable later. On startup it recovers interrupted scans.
- **SQLite** holds all state; stored secrets are field-encrypted at the app
  layer. Raw scanner JSON and generated SBOMs live on disk under `/data`.
- **Scanner binaries** (`trivy`/`grype`/`syft`) are bundled and run as
  subprocesses, with their databases and scratch space on the `/cache` volume.

---

## Requirements

- **Docker** 24+ and the **Compose v2** plugin (Buildx for a multi-arch build).
- **~2 GB RAM** available to the container for typical scans (the shipped Compose
  limit). Sufficient for images around 1 GB unpacked, including SBOM generation;
  raise the limit for substantially larger images.
- **Disk for the `/cache` volume — plan for ≥ 10 GB.** Everything the scanners
  read and write at scan time lives on this named volume (`scrye_cache`):
  - **Trivy vulnerability DB:** ~1.2 GB (downloads once, persists across
    restarts, refreshed incrementally).
  - **Trivy Java index DB:** up to ~1 GB more, downloaded on demand the first
    time a Java artifact is scanned.
  - **Grype vulnerability DB:** ~1.5–2 GB (downloads once, then incremental
    updates).
  - **Transient image staging:** while an image scan runs, layers are unpacked
    under `/cache/tmp` — budget roughly the **uncompressed size of the largest
    image you scan** (e.g. a ~330 MB-compressed image stages ~1.1 GB, cleaned up
    when the scan finishes).
- **The `/tmp` tmpfs stays small (200 MB) on purpose.** tmpfs is **RAM-backed** —
  every byte written there is charged against the container's memory limit.
  `/tmp` holds only transient credential files (a few KB); all large scanner
  writes go to the disk-backed `/cache` volume instead. Do **not** enlarge the
  tmpfs to "fix" a disk-space error — a multi-GB tmpfs would let image staging
  consume RAM and OOM the container. (See
  [Troubleshooting](#troubleshooting-first-run-issues).)
- Optional sidecars: a **Trivy server** (shared vuln-DB cache) and a read-only
  **docker-socket-proxy** (to scan running images).
- For native (non-container) development: **Python 3.13**, **Node 20+**, and the
  `trivy`/`grype`/`syft` binaries on `PATH`. See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## Deploying with Docker

This is the supported way to run Scrye. The steps below use the hardened
`docker/docker-compose.yml` from this repo, which builds the image locally by
default; [step 2](#2-choose-an-image-build-docker-hub-or-ghcr) covers pulling a
published image instead.

### 1. Prerequisites

- Docker 24+ with Compose v2 (`docker compose version`).
- `openssl` (to generate the master key) — present on essentially every Linux/macOS host.
- A clone of this repository (for the Compose file and the Dockerfile):

  ```bash
  git clone https://github.com/iamgroot60/scrye.git
  cd scrye
  ```

### 2. Choose an image: build, Docker Hub, or GHCR

Scrye is published to two registries with two distinct roles:

| Source | Reference | Use it for |
| ------ | --------- | ---------- |
| **Docker Hub** | `securedbytyler/scrye:latest` or `securedbytyler/scrye:<version>` | **Stable releases.** Built and pushed only from tagged `v*.*.*` releases on `main`. |
| **GHCR** | `ghcr.io/iamgroot60/scrye:dev` | **Testing the current dev state.** A single moving tag rebuilt nightly from `dev`; not a release, not production. |
| **Local build** | `scrye:0.1.0` (built by Compose) | Building from source / development. |

The shipped `docker/docker-compose.yml` **builds locally** (`build:` context with
`image: scrye:0.1.0`). To run a **published** image instead, edit the `scrye`
service — remove/comment the `build:` block and set `image:` to the tag you want:

```yaml
services:
  scrye:
    # build:                      # ← remove or comment out to skip the local build
    #   context: ..
    #   dockerfile: docker/Dockerfile
    image: securedbytyler/scrye:latest      # stable release
    # image: ghcr.io/iamgroot60/scrye:dev   # or the moving dev build
```

Then pull it:

```bash
docker pull securedbytyler/scrye:latest       # stable
# docker pull ghcr.io/iamgroot60/scrye:dev    # dev (GHCR package inherits repo visibility)
```

Everything else in the Compose file (hardening, volumes, secret, healthcheck) is
image-agnostic and applies unchanged.

### 3. Generate the application master key

The **master key** encrypts all stored secrets. It is provided as a **Docker
secret file**, never an environment variable or image layer. Generate it once and
keep it out of version control:

```bash
mkdir -p docker/secrets
openssl rand -base64 48 > docker/secrets/app_secret_key
chmod 600 docker/secrets/app_secret_key
```

The Compose file mounts this file as the `app_secret_key` secret at
`/run/secrets/app_secret_key` (the path in `SCRYE_APP_SECRET_KEY_FILE`). In
production Scrye **refuses to start** without a valid key file. **Back this file
up** — losing it makes every stored secret unrecoverable. (Key rotation is
supported; see [The master key](#the-master-key).)

### 4. Bring up the stack

```bash
# Builds the SPA + backend into one image (skip --build if you set a published image)
docker compose -f docker/docker-compose.yml up --build -d

# Verify health
curl -fsS http://127.0.0.1:8089/healthz
# {"status":"healthy","version":"0.1.0","database":"ok"}
```

On startup the container applies database migrations (`alembic upgrade head`)
and then serves the API and SPA. The port is published to **loopback only**
(`127.0.0.1:8089`) — put it behind your own reverse proxy for TLS and external
access ([step 8](#8-put-it-behind-a-reverse-proxy)).

### 5. First-run setup (admin bootstrap)

Open <http://127.0.0.1:8089/> in a browser. While **no accounts exist**, Scrye
shows a one-time **setup screen** that creates the first account as **admin** and
signs it in. The underlying endpoint (`POST /api/auth/setup`) works exactly once
— as soon as any account exists it permanently returns 409 and the screen is
gone. You can also bootstrap via the API:

```bash
curl -X POST http://127.0.0.1:8089/api/auth/setup \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "<a strong passphrase, 12+ chars>"}'
```

Additional users are created by an admin (Settings → Users & roles, or
`POST /api/users`) with one of three roles:

- **viewer** — read and export.
- **operator** — viewer + launch scans, manage own scan tags, own API tokens,
  and scheduled scans.
- **admin** — everything, including settings, users, credentials, and
  backup/restore.

### 6. Where persistent data lives

Two named Docker volumes:

- **`scrye_data`** → `/data` — the SQLite database (`/data/scrye.db`), raw
  scanner artifacts (`/data/artifacts`), and backup bundles (`/data/backups`).
  **This is the volume to back up.**
- **`scrye_cache`** → `/cache` — scanner vulnerability databases and scan-time
  scratch space. Large but reconstructible; it re-downloads if lost.

Inspect their host paths with `docker volume inspect scrye_scrye_data`. For a
fixed on-disk location, replace the named volumes with bind mounts to a directory
you control (e.g. `/mnt/appdata/scrye/data:/data`).

### 7. Optional sidecars

Both are gated behind Compose **profiles**, so a plain `up` starts only the app.

```bash
# Shared Trivy vulnerability-DB cache (a trivy-server the app queries)
docker compose -f docker/docker-compose.yml --profile trivy-server up -d

# Read-only Docker socket proxy ("scan running images") — see Security model
docker compose -f docker/docker-compose.yml --profile docker-env up -d
```

When you enable a sidecar, point the app at it by uncommenting the matching env
var in the `scrye` service:

- `SCRYE_TRIVY_SERVER_URL=http://trivy-server:4954`
- `SCRYE_DOCKER_PROXY_URL=http://docker-socket-proxy:2375`

The `docker-socket-proxy` is the **only** place a Docker socket is mounted (read-
only), and it is restricted to read endpoints (`POST=0`). See the
[Security model](#security-model) for the residual-risk note.

### 8. Put it behind a reverse proxy

Scrye serves plain HTTP internally and binds to loopback. Front it with a
TLS-terminating reverse proxy (Caddy, nginx, Traefik, …) that forwards to
`127.0.0.1:8089`. **One deployment-specific setting is required:** set
`SCRYE_FORWARDED_ALLOW_IPS` to the IP/CIDR your proxy actually connects **from**,
so Scrye trusts `X-Forwarded-For` from it and the auth rate limiter and audit log
see the real client IP. See
[Trusted reverse-proxy hops](#security-model) for the details and per-topology
examples — the default (`172.16.0.0/12`) assumes Caddy as a Docker container on
the default bridge.

### Troubleshooting first-run issues

- **`{"status":"degraded",...,"database":"error"}` from `/healthz`.** The process
  is up but can't reach SQLite. Check that `/data` is writable by uid 1000 (the
  container runs non-root) and that the `scrye_data` volume mounted.
- **Container exits at start with `refusing to start: master key file …`.** The
  `app_secret_key` secret file is missing or empty. Re-run
  [step 3](#3-generate-the-application-master-key) and confirm
  `docker/secrets/app_secret_key` exists and is non-empty.
- **`exec /app/entrypoint.sh: no such file or directory`.** The entrypoint was
  checked out with CRLF line endings (a Windows checkout). The repo pins shell
  scripts to LF via `.gitattributes` and the image strips stray CRs, so a normal
  clone is fine; if you hit this, run `git add --renormalize .` and rebuild.
- **Scanner fails with `mkdir /app/.cache: read-only file system` or
  `no space left on device`.** This is the classic hardened-runtime cache-path
  issue. Scrye runs non-root on a **read-only root filesystem**, so a scanner's
  default cache (`$HOME/.cache`) is unwritable and the small `/tmp` tmpfs can't
  hold a multi-GB vulnerability DB or image staging. The shipped image already
  routes all scanner cache and temp writes to the disk-backed `/cache` volume
  (`TRIVY_CACHE_DIR`, `GRYPE_DB_CACHE_DIR`, `XDG_CACHE_HOME`/`HOME`, `TMPDIR`) and
  mounts `/tmp` owned by uid 1000. If you see this, you're almost certainly
  running a **stale image** built before that fix — **rebuild from the current
  source** (`docker compose … up --build`) or pull a current published tag. Do
  **not** try to fix it by enlarging the `/tmp` tmpfs; that trades a disk error
  for an OOM (tmpfs is RAM-backed). Ensure `/cache` has ≥ 10 GB free.
- **Filesystem scans are rejected.** Filesystem (Grype `dir:`) scanning is
  **disabled by default**. An admin must set `SCRYE_FILESYSTEM_SCAN_ROOTS` to one
  or more absolute paths and mount them into the container; targets outside those
  roots are refused.

---

## Configuration

Configuration is driven by environment variables (prefix `SCRYE_`). The
[`.env.example`](./.env.example) file is **generated from the backend `Settings`
model** (`backend/app/core/config.py`) — copy it to `.env` for local development.
Only **non-sensitive** variables belong there; the master key is always the
Docker secret file. Runtime-editable, non-secret options (instance name, auth
policy, scanner defaults, retention) are **not** env vars — they live in the app's
Settings UI and database.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SCRYE_APP_NAME` | `Scrye` | Application name shown in the UI and logs. |
| `SCRYE_ENVIRONMENT` | `production` | `development` or `production`. |
| `SCRYE_LOG_LEVEL` | `INFO` | Root log level. |
| `SCRYE_HOST` | `0.0.0.0` | Bind address inside the container (published to loopback). |
| `SCRYE_PORT` | `8089` | API/SPA port inside the container. |
| `SCRYE_FORWARDED_ALLOW_IPS` | `172.16.0.0/12` | **Required per deployment.** IP/CIDR the reverse proxy connects from; the trust boundary for `X-Forwarded-For`. Never `*`. See [Security model](#security-model). |
| `SCRYE_CORS_ORIGINS` | _(empty)_ | Comma-separated dev CORS origins (e.g. `http://localhost:5173`); empty in production (same-origin SPA). |
| `SCRYE_DATABASE_PATH` | `/data/scrye.db` | SQLite database file path. |
| `SCRYE_APP_SECRET_KEY_FILE` | `/run/secrets/app_secret_key` | Path to the Docker secret file holding the **master key**. |
| `SCRYE_SESSION_LIFETIME_HOURS` | `168` | Login session lifetime (hours; 168 = 7 days). |
| `SCRYE_SESSION_COOKIE_SECURE` | `true` | `Secure` flag on session cookies (disable only for plain-HTTP dev). |
| `SCRYE_AUTH_RATE_LIMIT_ATTEMPTS` | `5` | Max auth attempts per client IP per window. |
| `SCRYE_AUTH_RATE_LIMIT_WINDOW_SECONDS` | `60` | Auth rate-limit window length (seconds). |
| `SCRYE_TRIVY_SERVER_URL` | _(unset)_ | Optional Trivy server URL (shared vuln-DB cache sidecar). |
| `SCRYE_DOCKER_PROXY_URL` | _(unset)_ | Optional read-only docker-socket-proxy URL. |
| `SCRYE_TRIVY_BINARY` | `trivy` | Trivy binary path/name (resolved on `PATH` if a bare name). |
| `SCRYE_GRYPE_BINARY` | `grype` | Grype binary path/name. |
| `SCRYE_SYFT_BINARY` | `syft` | Syft binary path/name. |
| `SCRYE_MAX_CONCURRENT_SCANS` | `2` | Max scans the in-process worker runs at once. |
| `SCRYE_SCAN_TIMEOUT_SECONDS` | `1800` | Per-scan wall-clock timeout (seconds). |
| `SCRYE_SCANNER_MAX_OUTPUT_BYTES` | `536870912` | Max stdout (512 MiB) captured from a scanner subprocess; output past this kills and fails the scan. |
| `SCRYE_SCANNER_CACHE_DIR` | `/cache` | Writable volume for scanner vuln DBs and scratch (see [Requirements](#requirements)). |
| `SCRYE_ARTIFACTS_DIR` | `/data/artifacts` | Directory holding raw scanner artifacts (JSON output, SBOMs). |
| `SCRYE_BACKUPS_DIR` | `/data/backups` | Directory holding backup bundles (manual and scheduled). |
| `SCRYE_FILESYSTEM_SCAN_ROOTS` | _(empty)_ | Comma-separated absolute paths under which filesystem (`dir:`) scans are allowed. Empty disables filesystem scanning. |
| `SCRYE_FRONTEND_DIST_DIR` | `/app/frontend/dist` | Directory of the built SPA served by FastAPI. |

### The master key

The application **master key** is **never** an environment variable or baked into
an image layer. It is read at runtime from the Docker secret file pointed to by
`SCRYE_APP_SECRET_KEY_FILE` (default `/run/secrets/app_secret_key`). Generate it
once with `openssl rand -base64 48` and provide it as a Docker secret. Stored
credentials are encrypted with a key derived from it (HKDF-SHA256 → AES-256-GCM).
In production the app **refuses to start** without a valid key file.

**Key rotation.** The key file may hold multiple versions, one per line, as
`v<N>:<base64>` entries (a plain single-line key is version 1). New secrets are
encrypted under the highest version and older versions remain readable, so you can
add a new version and restart safely. Note that v1 does **not** yet ship an
admin-facing bulk re-encryption action, so existing rows stay wrapped under the
version they were written with until each is next updated; keep the older key line
in place until that tool lands (tracked on the [roadmap](./docs/ROADMAP.md)).

---

## Configuring OIDC

OIDC is configured **in the UI**, not via environment variables — go to
**Settings → Authentication** (admin) and fill in:

- **Issuer** — the provider's base URL (Scrye discovers
  `<issuer>/.well-known/openid-configuration`).
- **Client ID** / **Client secret** — from a confidential client registered with
  your provider. The secret is stored field-encrypted and write-only; omit it to
  use public PKCE only. Register Scrye's **redirect URI** —
  `https://<your-scrye-host>/api/auth/oidc/callback` — with the provider.
- **Scopes** (default `openid profile email`), **username claim**, optional
  **groups claim** and **admin group** (users in the admin group are provisioned
  as admin), **auto-provision** toggle, and the **default role** for new OIDC
  users.
- **Enable** the provider — a "Sign in with …" button then appears on the login
  screen alongside local login.

Notes:

- Scrye uses generic OIDC (authorization-code + PKCE, RS256), validated against
  Pocket ID. ID-token signature and `iss`/`aud`/`exp`/`nonce`/`sub` claims are
  verified, and each login is bound to the initiating browser (defeating
  login-CSRF/session fixation).
- You can require OIDC-only by disabling local login (Settings → Authentication),
  but only once OIDC is enabled.
- **MFA and OIDC:** the mandatory-MFA policy is enforced on **local** login only;
  OIDC delegates the second factor to the identity provider. If you require MFA
  for OIDC users, enforce it at the IdP. (See [Security model](#security-model).)

---

## Usage

**Running scans** — from **New scan**, pick a target type; the scanner choices
adjust to match:

- **Image (Trivy or Grype)** — enter a reference (e.g. `alpine:3.19` or
  `ghcr.io/org/app:tag`). For a private registry, select a **registry credential**
  (Settings → Registries). For Trivy, choose which scanners run and an optional
  severity filter; optionally toggle **Generate SBOM** to also produce a Syft SBOM.
- **Repository (Trivy)** — enter an HTTPS clone URL and optionally a
  branch/commit/tag. For a private repo, select a **git credential** (Settings →
  Git providers): GitHub/GitLab use Trivy's token env vars; a generic host is
  cloned with the system `git` binary via a transient `GIT_ASKPASS` helper, so the
  credential never touches the process argument list, is never stored, and is
  never logged.
- **Filesystem (Grype)** — enter an absolute path. Disabled by default; an admin
  must allow paths via `SCRYE_FILESYSTEM_SCAN_ROOTS`, and targets outside those
  roots are rejected.
- **SBOM (Grype)** — upload a CycloneDX / SPDX / Syft JSON file; Scrye stores it
  as the scan input and runs `grype sbom:…`.
- **Scan running images** — Settings → Docker environments: register a read-only
  `docker-socket-proxy` URL, acknowledge the residual risk, **enumerate** images,
  then scan any listed reference as an image target.

**Reading results** — the **scan detail** page shows live status, a severity
summary, and the normalized findings table; every completed scan stores the
scanner's original JSON (and any generated SBOM) verbatim, downloadable from that
page.

**History, diff & export** — the **Scan history** page filters, sorts, and
paginates scans, with saveable filter **presets** and per-scan **tags**. Select
two scans of the same target to **diff** them (new vs. fixed). Export a single
scan's findings, or a whole filtered history set, as **CSV**, **Markdown**, or
**JSON**.

**Settings (admin)** cover general options, authentication policy, users & roles,
scanner defaults & ignore rules, Trivy VEX/ignore policy, registries, git
providers, Docker environments, notification channels, retention, and
backup/restore, plus an about/health tab. **Scheduled scans** and **API tokens**
are available to operators. Every user has an **Account** page for password, MFA,
and session management.

Secret fields (registry / git / OIDC credentials, notification secrets, TOTP
secrets, API tokens) are **write-only** — entered once, never returned in
plaintext (the API returns a mask and a "last updated" timestamp), and decrypted
only in memory at scan time.

---

## Security model

- **Field-level encryption.** Stored secrets (registry creds, git tokens, OIDC
  client secret, notification secrets/URLs, TOTP MFA secrets, scheduled-backup
  passphrase) are encrypted with **AES-256-GCM** (random per-secret nonce,
  HKDF-derived key, key-version tagged, column-bound AAD). The database never
  holds plaintext secrets.
- **Master key via secret file.** The key comes from a Docker secret file
  (`SCRYE_APP_SECRET_KEY_FILE`) — never an env var or image layer.
- **Authentication.** Local accounts use **argon2id** with revocable server-side
  sessions (opaque token, only its SHA-256 stored); generic **OIDC** (Authlib,
  PKCE + nonce, ID-token signature/claim validation, browser-bound login) runs
  alongside local auth; optional **TOTP MFA** with an enforceable policy adds a
  second factor. **API tokens** are bearer credentials stored only as a SHA-256
  hash, scoped to a role no higher than their owner's. Cookie sessions require a
  CSRF token (`X-CSRF-Token`) on every state-changing request; bearer tokens are
  CSRF-exempt (not sent cross-site). Auth endpoints are rate-limited per client IP.
- **Write-only secret API + log redaction.** Secret fields accept values on write
  and return a mask + timestamp on read. A logging filter redacts secret fields,
  bearer/basic tokens, and URL userinfo across messages and tracebacks (and is
  attached to uvicorn's loggers). Scanner subprocesses don't inherit Scrye's
  `SCRYE_*` config.
- **Scan-time only.** Secrets are decrypted in memory into transient credential
  files on **tmpfs** (Docker `config.json`, `GIT_ASKPASS` helper), used for the
  scanner subprocess, then shredded.
- **CIS-aligned container posture.** Base images are pinned by digest;
  `trivy`/`grype`/`syft` are installed from the publishers' release archives and
  verified against their signed checksum files before extraction (never
  `curl | bash`); the image runs as a **non-root** user with `cap_drop: ALL`,
  `no-new-privileges`, a **read-only** root filesystem + tmpfs, resource limits, a
  healthcheck, and loopback-only port binding.
- **Writable scratch under a read-only root.** The only writable paths are the
  `/data` and `/cache` volumes and a small `/tmp` tmpfs (mounted owned by uid
  1000, holding only in-memory credential files). Every scanner invocation —
  scans **and** the About-tab version/DB-status probes — is pointed at the
  persistent `/cache` volume via `TRIVY_CACHE_DIR`, `GRYPE_DB_CACHE_DIR`,
  `XDG_CACHE_HOME`/`HOME`, and `TMPDIR`, so nothing falls back to the read-only
  `$HOME/.cache` or overflows the tmpfs, and the vuln DBs persist across restarts.
- **Docker socket residual risk.** "Scan running images" uses a **read-only**
  `docker-socket-proxy` restricted to read endpoints (`POST=0`). The Scrye app
  **never** mounts `/var/run/docker.sock`; the proxy is the only place the socket
  is mounted (read-only). Anyone who can reach the proxy can _enumerate_ images
  and containers, so enable that profile deliberately and keep it on the internal
  network.
- **Trusted reverse-proxy hops (`SCRYE_FORWARDED_ALLOW_IPS` — required per
  deployment).** Scrye honors `X-Forwarded-For` (uvicorn `--proxy-headers`) so the
  auth rate limiter and audit log see the **real** client IP. The logic is
  **proxy-agnostic** — it works behind any proxy that sets `X-Forwarded-For`
  (Caddy, nginx, Traefik, HAProxy, …). uvicorn trusts the header only when the
  connecting peer is in `SCRYE_FORWARDED_ALLOW_IPS`, then takes the first address
  that is **not** in that set, discarding any spoofed leftmost entry.

  Set it to the IP/CIDR your proxy actually connects from. The default
  (`172.16.0.0/12`) assumes Caddy as a Docker container on the default bridge.
  **Fail-safe on mismatch:** if the configured value doesn't include the real
  connecting peer, `X-Forwarded-For` is ignored and the raw proxy IP is used — no
  spoofing possible, but per-client rate-limit buckets and accurate audit IPs
  don't take effect until you set it correctly. **Never set it to `*`** and never
  include the client LAN range — that trusts every hop and re-opens the spoofing
  hole. Examples:
  - Caddy as a Docker container (default): `SCRYE_FORWARDED_ALLOW_IPS=172.16.0.0/12`.
  - Host-networked nginx (proxying to `127.0.0.1:8089`): `SCRYE_FORWARDED_ALLOW_IPS=127.0.0.1`.
  - Traefik in its own Docker network (e.g. `10.89.0.0/24`): `SCRYE_FORWARDED_ALLOW_IPS=10.89.0.0/24`.
- **MFA scope for OIDC (accepted limitation).** The mandatory-MFA policy
  (`required_all` / `required_admin`) is enforced on **local** password login.
  OIDC logins delegate the second factor to the identity provider — Scrye has no
  local TOTP challenge in the OIDC handshake, and provisioned OIDC accounts carry
  no usable local password. If you require MFA for OIDC users, enforce it at the
  IdP. When group→role mapping is configured it re-applies on each login, but an
  **absent** groups claim preserves the user's current role rather than demoting
  them, and an OIDC sync can never remove the last admin.

---

## Backup & restore

Backups are **portable, passphrase-protected bundles** — a logical, per-row dump
of the database plus a manifest with the app/schema version. Because secrets are
encrypted under the host master key (which does not travel), on backup each secret
is **re-wrapped** under a user-supplied passphrase (a scrypt-derived AES-256-GCM
key), and the whole inner dump is encrypted under that passphrase too; on restore
you supply the passphrase and Scrye **re-encrypts** the secrets under the new
host's master key. A restore therefore works on a fresh host with only the
passphrase — no master-key transplant.

Manage backups under **Settings → Backup & restore** (admin): create a bundle,
download or delete stored bundles, restore from an uploaded bundle (a
**destructive** action that replaces all data and signs you out), and configure
**scheduled backups** — an interval, a retention count, and an encrypted
passphrase the in-process scheduler uses to produce bundles unattended. Restore
requires the bundle's schema version to match the running installation, and is
**refused while a scan is queued or running** (finish or cancel it first).

**What a bundle contains.** A logical dump of the database — scan history,
normalized findings, users, settings, and (re-wrapped) secrets. It does **not**
carry the **raw scanner-output artifact files** (raw Trivy/Grype JSON and
generated SBOMs), which live on disk under `SCRYE_ARTIFACTS_DIR` and are
re-created by re-running a scan; their bookkeeping rows are omitted from the
bundle and cleared on restore, so a restored database never points at missing
files. Copy `SCRYE_ARTIFACTS_DIR` separately if you need the raw outputs preserved
across a move.

**Size note.** A bundle is assembled and encrypted in memory in a single pass, so
backing up or restoring an instance with a very large findings table (roughly
hundreds of thousands of rows and up) needs container memory headroom proportional
to the dump; a warning is logged past that threshold. (A framed streaming format
is on the [roadmap](./docs/ROADMAP.md).)

---

## Monitoring

Scrye exposes Prometheus metrics at **`/metrics`** in the text exposition format —
`scrye_scans_total{status=…}`, `scrye_open_findings{severity=critical|high}`,
`scrye_scan_schedules{state=…}`, `scrye_build_info`, and account/token/channel
counts. Because these reveal scan volume and vulnerability posture, the endpoint
is **authenticated** (viewer role): scrape it with a personal **API token** as a
bearer credential rather than exposing it publicly.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: scrye
    metrics_path: /metrics
    authorization: { credentials: '<a Scrye API token>' }
    static_configs: [{ targets: ['scrye.internal:8089'] }]
```

---

## Building the image yourself

Published release images are on Docker Hub as **`securedbytyler/scrye`** (`:latest`
and `:<version>` from tagged releases); the current `dev` branch is on GHCR as
**`ghcr.io/iamgroot60/scrye:dev`** (nightly). To build locally instead — single-
arch for the host you're on:

```bash
docker build -f docker/Dockerfile -t scrye:0.1.0 .
```

For a **multi-arch** image (`linux/amd64` + `linux/arm64`), use Buildx; the
Dockerfile is arch-aware and pulls the correct `trivy`/`grype`/`syft` binaries per
target platform:

```bash
docker buildx create --use --name scrye-builder   # once
docker buildx build -f docker/Dockerfile \
  --platform linux/amd64,linux/arm64 \
  -t scrye:0.1.0 .
```

CI builds both architectures and **dogfoods** the result: it scans Scrye's own
image with Trivy and Grype and fails on any **fixable HIGH/CRITICAL** finding in
Scrye's own attack surface — its base-image OS packages (including the `git`
runtime dependency), Python and JS dependencies, and application code (the whole
image filesystem is scanned). The **bundled `trivy`/`grype`/`syft` binaries** are
the one thing excluded from the gate (they still appear in the informational scan
report): they're unmodified upstream Go binaries Scrye can't rebuild, so CVEs in
their embedded Go modules track upstream's release cadence — keeping the pinned
scanner versions current is how those are addressed. CI never publishes; Docker
Hub and GHCR publishing live in separate workflows.

---

## Roadmap

Scrye is feature-complete for its core mission. Forward-looking work — open
features, known limitations, and candidate improvements — is tracked in
**[`docs/ROADMAP.md`](./docs/ROADMAP.md)**.

The full history of how Scrye was built (the phase-by-phase build order, locked
decisions, and the dated deviations log) is preserved in
**[`docs/ARCHIVE.md`](./docs/ARCHIVE.md)**.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for local development setup, project
layout, coding standards, testing, the branching model and PR process, the release
procedure, and how to report security issues privately.

## License

[MIT](./LICENSE). Bundled Trivy, Grype, and Syft are Apache-2.0 — see
[`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/README.md).
