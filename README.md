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

[![CI](https://github.com/tyler-rich/Scrye/actions/workflows/ci.yml/badge.svg)](https://github.com/tyler-rich/Scrye/actions/workflows/ci.yml)
[![Container: GHCR](https://img.shields.io/badge/ghcr.io-tyler--rich%2Fscrye-2496ED?logo=github&logoColor=white)](https://github.com/tyler-rich/scrye/pkgs/container/scrye)
![Arch: amd64 · arm64](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-informational)
[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](./LICENSE)

- **What it is:** one container that serves a React SPA and a FastAPI backend,
  runs `trivy`/`grype`/`syft` as subprocesses, and stores everything in SQLite.
- **Who it's for:** teams and homelabbers who want a self-hosted, hardened scan
  console with history, exports, scheduling, notifications, RBAC, and OIDC —
  without wiring a pipeline together by hand.
- **Distribution:** published to the GitHub Container Registry (GHCR):
  `ghcr.io/tyler-rich/scrye:latest` and `:<version>` for stable releases, and the
  moving `:dev` tag from the nightly `dev` build. You can also build the image
  locally from this repo. (No Docker Hub.)

---

## Contents

- [Screenshots](#screenshots)
- [Features](#features)
- [Integrations](#integrations)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Deploying with Docker](#deploying-with-docker)
  - [1. Prerequisites](#1-prerequisites)
  - [2. The application master key (nothing to do)](#2-the-application-master-key-nothing-to-do)
  - [3. Create `docker-compose.yml`](#3-create-docker-composeyml)
  - [4. Start it](#4-start-it)
  - [5. First-run setup (admin bootstrap)](#5-first-run-setup-admin-bootstrap)
  - [6. Where persistent data lives](#6-where-persistent-data-lives)
  - [Resource limits (and NAS platforms)](#resource-limits-and-nas-platforms)
  - [Which image tag?](#which-image-tag)
  - [Build from source instead](#build-from-source-instead)
  - [Troubleshooting first-run issues](#troubleshooting-first-run-issues)
- [Configuration](#configuration)
- [Reverse proxy (TLS)](#reverse-proxy-tls)
  - [If you're not using HTTPS](#if-youre-not-using-https)
- [Optional sidecars](#optional-sidecars)
- [Configuring OIDC](#configuring-oidc)
- [Usage](#usage)
- [Security model](#security-model)
- [Backup & restore](#backup--restore)
- [Monitoring](#monitoring)
- [Building the image yourself](#building-the-image-yourself)
- [Supply chain](#supply-chain)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Screenshots

| Dashboard | New scan | Results | History |
| --------- | -------- | ------- | ------- |
| <img src="./docs/screenshots/dashboard.png" width="260" alt="Dashboard"> | <img src="./docs/screenshots/new-scan.png" width="260" alt="New scan"> | <img src="./docs/screenshots/results.png" width="260" alt="Results"> | <img src="./docs/screenshots/history.png" width="260" alt="History"> |

---

## Features

Trivy and Grype each bring a different scope; Scrye unifies them behind one UI
and one normalized findings model.

- **Trivy scanning**
  - Targets: a **single container image** (registry reference) and a **git
    repository** (public or private, by **remote clone URL** — `http`, `https`,
    `ssh`, or `git` — with optional branch/commit/tag). A local filesystem path
    is **rejected** as a repository target; see
    [Security model](#security-model).
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
- **OIDC** — generic OpenID Connect (Authlib, authorization-code + PKCE, RS256).
  Configured entirely in the UI; works with any compliant provider (developed
  against Pocket ID).
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
   Browser ── HTTPS ──▶  │  Reverse proxy + TLS (Caddy / nginx / Traefik) │
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
  **docker-socket-proxy** (to scan running images). Both off by default — see
  [Optional sidecars](#optional-sidecars).
- For native (non-container) development: **Python 3.14**, **Node 20+**, and the
  `trivy`/`grype`/`syft` binaries on `PATH`. See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## Deploying with Docker

The fastest path is to **pull the published image from GHCR** — you do **not**
need to clone this repository. Create a directory, drop in the master-key secret
and a `docker-compose.yml`, and bring it up. (Prefer to build from source? See
[Build from source instead](#build-from-source-instead).)

### 1. Prerequisites

- Docker 24+ with Compose v2 (`docker compose version`).
- A working directory for the deployment:

  ```bash
  mkdir scrye && cd scrye
  ```

### 2. The application master key (nothing to do)

The **master key** encrypts all stored secrets. **You do not have to create it.**
On first launch, if no key is supplied, Scrye generates one with a CSPRNG (the
equivalent of `openssl rand -base64 48`) and persists it at
**`/data/app_secret_key`** — mode `0600`, owned by the container's uid, on the
`scrye_data` volume. It is generated exactly once: every later start reuses that
file, and an existing key file is **never** overwritten.

> **⚠️ Back that file up, separately from the container.** Every stored secret —
> registry credentials, git tokens, the OIDC client secret, MFA seeds, scheduled
> backup passphrases — is encrypted with a key derived from it. **If you lose it,
> those secrets are unrecoverable**: there is no reset, no recovery path, no
> backdoor. Scrye still starts and everything else (scan history, findings, users,
> settings) is intact, but each stored secret has to be re-entered. See
> [Backup & restore](#backup--restore) for how the master key relates to backup
> bundles, and [The master key](#the-master-key) for the full details.

**For production, prefer supplying it yourself as a Docker secret** so the key
does not sit on the same volume as the database it protects:

```bash
mkdir -p secrets
openssl rand -base64 48 > secrets/app_secret_key
chmod 600 secrets/app_secret_key
```

then uncomment the `app_secret_key` blocks in the compose file below. A supplied
secret always takes precedence and nothing is generated. Note that once
`SCRYE_APP_SECRET_KEY_FILE` is set, the file **must** exist there — Scrye refuses
to start rather than silently substitute a different key. (Key rotation is
supported; see [The master key](#the-master-key).)

### 3. Create `docker-compose.yml`

Save this in the working directory. It runs the **published GHCR image** with the
same hardened, CIS-aligned posture the project ships (non-root, read-only root
FS, dropped capabilities, resource limits, loopback-only port, healthcheck):

```yaml
services:
  scrye:
    image: ghcr.io/tyler-rich/scrye:latest # or :<version> to pin a release
    user: "1000:1000"
    read_only: true
    security_opt:
      - "no-new-privileges:true"
    cap_drop:
      - "ALL"
    ports:
      # Loopback only — put a reverse proxy in front for TLS/external access.
      # For a quick local trial without a proxy, change to "8089:8089".
      - "127.0.0.1:8089:8089"
    environment:
      - SCRYE_DATABASE_PATH=/data/scrye.db
      # Master key: left unset, Scrye generates one at /data/app_secret_key on
      # first launch (mode 0600) and reuses it forever after. To supply it as a
      # Docker secret instead, uncomment this line and both secrets: blocks.
      # - SCRYE_APP_SECRET_KEY_FILE=/run/secrets/app_secret_key
      # REQUIRED behind a reverse proxy: the IP/CIDR your proxy connects FROM.
      # The default below fits a proxy container on the default Docker bridge;
      # set it to match your topology (see "Reverse proxy" below). Never "*".
      - SCRYE_FORWARDED_ALLOW_IPS=172.16.0.0/12
    # secrets:
    #   - app_secret_key
    volumes:
      # Holds the SQLite DB, raw artifacts, backups — and, unless you supply a
      # Docker secret, the generated master key at /data/app_secret_key.
      - scrye_data:/data # BACK THIS UP
      - scrye_cache:/cache # scanner vuln DBs + scratch (≥10 GB; reconstructible)
    tmpfs:
      # RAM-backed, owned by uid 1000, holds only transient credential files.
      # Do NOT enlarge to "fix" a scanner disk error — see "Requirements".
      - /tmp:size=200m,mode=1700,uid=1000,gid=1000
    # Memory containment. `mem_limit`/`mem_reservation` rather than a `deploy:`
    # block — see "Resource limits" below, including how to add a CPU cap.
    mem_limit: 2g
    mem_reservation: 256m
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:8089/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  scrye_data:
  scrye_cache:
# Uncomment (with the two lines above) only if you supply the master key
# yourself. Compose requires the file to exist when it reads this stack, so an
# absent `secrets/app_secret_key` fails `docker compose up` before the container
# starts — which is why it is commented out by default.
# secrets:
#   app_secret_key:
#     file: ./secrets/app_secret_key # created in step 2; never commit it
```

### 4. Start it

```bash
docker compose up -d

# Verify health
curl -fsS http://127.0.0.1:8089/healthz
# {"status":"healthy","version":"0.2.0","database":"ok"}
```

On startup the container applies database migrations (`alembic upgrade head`) and
then serves the API and SPA. Because the port is published to **loopback only**,
put it behind a [reverse proxy](#reverse-proxy-tls) for TLS and external access
(or change the port mapping to `8089:8089` for a quick local trial over plain
HTTP).

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
- **operator** — viewer + launch scans, delete completed scans, manage own scan
  tags, own API tokens, and scheduled scans.
- **admin** — everything, including settings, users, credentials, and
  backup/restore.

### 6. Where persistent data lives

Two named Docker volumes:

- **`scrye_data`** → `/data` — the SQLite database (`/data/scrye.db`), raw
  scanner artifacts (`/data/artifacts`), backup bundles (`/data/backups`), and —
  unless you supplied a Docker secret — the auto-generated **master key**
  (`/data/app_secret_key`, mode `0600`). **This is the volume to back up**, and
  the master key is the one file in it you cannot regenerate.
- **`scrye_cache`** → `/cache` — scanner vulnerability databases and scan-time
  scratch space. Large but reconstructible; it re-downloads if lost.

Inspect their host paths with `docker volume inspect scrye_scrye_data`. For a
fixed on-disk location, replace the named volumes with bind mounts to a directory
you control (e.g. `/mnt/appdata/scrye/data:/data`).

### Resource limits (and NAS platforms)

Capping container resources is part of the hardened baseline Scrye ships — an
unbounded scan should degrade, not take the host down with it. How those caps are
spelled changed, because the Compose-native spelling isn't portable.

**Memory limits are on by default and need nothing from you.** Every service in
[`docker/docker-compose.yml`](docker/docker-compose.yml), and the paste-in stack
[above](#3-create-docker-composeyml), sets `mem_limit` (and `mem_reservation` on
the app), which every Compose implementation accepts:

| Service | `mem_limit` | `mem_reservation` |
| ------- | ----------- | ----------------- |
| `scrye` | `2g` | `256m` |
| `trivy-server` (optional) | `1g` | — |
| `docker-socket-proxy` (optional) | `64m` | — |

Memory is the cap that matters most: it bounds the OOM blast radius, and the
RAM-backed `/tmp` tmpfs counts against it. Don't remove these.

**CPU limits are opt-in, in a separate overlay file.** Compose expresses them
through the Swarm-oriented `deploy.resources` block. Compose v2 honours `deploy:`
for a plain `docker compose up`, but several NAS container platforms — **Synology
Container Manager** and **QNAP Container Station** among them — reject or
mishandle `deploy:` keys, so a base file carrying them won't deploy there at all.
Rather than drop the caps, they moved to
[`docker/docker-compose.cpu-limits.yml`](docker/docker-compose.cpu-limits.yml),
which you add with a second `-f`:

```bash
docker compose -f docker/docker-compose.yml \
               -f docker/docker-compose.cpu-limits.yml up -d
```

That applies `cpus: 2.0` to `scrye`, `1.0` to `trivy-server`, and `0.5` to
`docker-socket-proxy` (the tightest cap, since it's the only container that
mounts the Docker socket). The overlay uses the portable `cpus:` key rather than
`deploy:`, so it works on anything that understands it — including NAS platforms
that accept `cpus` but not `deploy`. Compose treats `cpus` and
`deploy.resources.limits.cpus` as the same field, so this is the same limit, not
a weaker one.

**Name both files on every command for that stack** (`ps`, `logs`, `down`, not
just `up`) — otherwise Compose recomputes the project without the overlay and
recreates the containers uncapped. Set it once instead if you prefer:

```bash
export COMPOSE_FILE=docker/docker-compose.yml:docker/docker-compose.cpu-limits.yml
```

If you're on a NAS, skip the overlay and set CPU limits in your platform's own
container UI, which writes them straight to the Docker API. If you deploy from
the published image with your own Compose file, add `cpus:` to your service
directly — there's no need for a second file.

### Which image tag?

Everything publishes to GHCR (`ghcr.io/tyler-rich/scrye`):

| Tag | What it is | Use it for |
| --- | ---------- | ---------- |
| `:latest` | The most recent tagged release (built from `main`). | **Production.** Tracks the newest release. |
| `:<version>` (e.g. `:0.2.0`) | A specific tagged release. | **Production, pinned** — reproducible, no surprise upgrades. |
| `:dev` | A **moving** tag rebuilt nightly from the `dev` branch. | **Testing HEAD-of-dev only.** Not a release; may be unstable. Do not run in production. |

Pin `:<version>` for anything you care about; use `:latest` if you want to track
releases and re-`pull` on your own cadence. All tags are multi-arch
(`linux/amd64` + `linux/arm64`).

```bash
docker pull ghcr.io/tyler-rich/scrye:latest
# docker pull ghcr.io/tyler-rich/scrye:0.2.0   # pin a release
# docker pull ghcr.io/tyler-rich/scrye:dev     # test the dev branch
```

### Build from source instead

If you'd rather build the image yourself (to modify Scrye, or to avoid pulling a
prebuilt image), clone the repo and use the bundled Compose file, which **builds
locally** instead of pulling:

```bash
git clone https://github.com/tyler-rich/scrye.git
cd scrye
docker compose -f docker/docker-compose.yml up --build -d
```

As above, the master key is generated on first launch — see
[step 2](#2-the-application-master-key-nothing-to-do) if you'd rather supply it
as a Docker secret (the compose file has the blocks ready to uncomment).

See [Building the image yourself](#building-the-image-yourself) for multi-arch
builds and the dogfooding self-scan, and
[Resource limits](#resource-limits-and-nas-platforms) for the optional CPU-cap
overlay.

### Troubleshooting first-run issues

- **Container exits immediately with `Scrye: FATAL - the data directory /data is
  not writable by uid 1000:1000`.** This is the **bind-mount ownership** case, and
  it is the most common first-run failure on NAS platforms (Synology, QNAP): a
  **bind mount keeps the host directory's ownership**, whereas a **named volume
  inherits the correct ownership from the image**. Scrye runs as uid 1000 on a
  read-only root filesystem, so it cannot create `/data/scrye.db` — nor the
  generated master key — in a directory it may not write. The message names the
  path and the uid; fix it on the host with any one of:
  - `sudo chown -R 1000:1000 /path/on/host` (the directory you bind-mounted), or
  - set the container's `user:` to the directory's existing owner
    (`stat -c '%u:%g' /path/on/host`), or
  - drop the bind mount and use a named volume (as the compose above does).

  The check runs **before** migrations deliberately: previously the only symptom
  was `sqlite3.OperationalError: unable to open database file`, which named
  neither the path nor the fix.
- **Container exits with `Generated master key … is owned by uid N, not the
  container uid 1000`.** The filesystem under `/data` is **synthesizing**
  ownership — a CIFS/SMB mount with `uid=`, or an NFS export that squashes it — so
  the key's `0600` would not actually protect it. `chown` cannot help here. Either
  put `/data` on a filesystem that preserves POSIX ownership (strongly preferred —
  SQLite is unreliable over CIFS/SMB regardless), run the container as the uid the
  filesystem reports, or supply the master key as a Docker secret, which needs no
  writable volume at all. No key file is left behind when this refusal fires.
- **`{"status":"degraded",...,"database":"error"}` from `/healthz`.** The process
  is up but can't reach SQLite. Check that `/data` is writable by uid 1000 (the
  container runs non-root) and that the `scrye_data` volume mounted. On a fresh
  start the entrypoint preflight above catches this first; this state usually means
  the volume went away or changed ownership *after* a successful start.
- **Container exits at start with `Refusing to start without a valid master
  key`.** Read the rest of the line; each case is a deliberate refusal, and none
  of them is fixed by deleting a key file that has real data behind it:
  - **`SCRYE_APP_SECRET_KEY_FILE is set to … but no file exists there`** — the
    Docker secret is not mounted (a missing `secrets:` block, a wrong path, a
    typo'd filename). Mount it, or unset the variable to let Scrye manage the key
    itself. Scrye will not substitute a generated key here, because a key that
    *should* be present usually means secrets were already encrypted under it.
  - **`is empty` / `is not valid base64` / `too short` / `malformed`** — a key
    file exists but does not load. Restore the real key content; regenerating
    would orphan every stored secret. The one safe exception is a **zero-byte**
    file left by a first start that was interrupted mid-generation, with nothing
    stored yet — deleting that is fine.
  - **`Two different master keys are present`** — a Docker secret was added to a
    deployment that had already generated its own key at `/data/app_secret_key`.
    Carry the generated key forward as a version in the secret file (see
    [Key rotation](#the-master-key)), or delete it if nothing was stored under it.
  - **`Cannot create the master key file …`** — the key's directory is missing or
    not writable by uid 1000. The message names the directory, the container
    uid:gid, and the `chown` to run; see the bind-mount bullet at the top of this
    section. (If the key lives on the same volume as the database, the entrypoint
    preflight normally reports this first.)
- **`exec /app/entrypoint.sh: no such file or directory`** (only when building
  from source). The entrypoint was checked out with CRLF line endings (a Windows
  checkout). The repo pins shell scripts to LF via `.gitattributes` and the image
  strips stray CRs, so a normal clone is fine; if you hit this, run
  `git add --renormalize .` and rebuild.
- **Scanner fails with `mkdir /app/.cache: read-only file system` or
  `no space left on device`.** This is the classic hardened-runtime cache-path
  issue. Scrye runs non-root on a **read-only root filesystem**, so a scanner's
  default cache (`$HOME/.cache`) is unwritable and the small `/tmp` tmpfs can't
  hold a multi-GB vulnerability DB or image staging. The shipped image already
  routes all scanner cache and temp writes to the disk-backed `/cache` volume
  (`TRIVY_CACHE_DIR`, `GRYPE_DB_CACHE_DIR`, `XDG_CACHE_HOME`/`HOME`, `TMPDIR`) and
  mounts `/tmp` owned by uid 1000 — provided you keep the `scrye_cache` volume and
  the `/tmp` tmpfs from the compose above. If you see this, confirm those mounts
  are present and that `/cache` has ≥ 10 GB free, and that you're on a **current
  image** (`docker pull …:latest`). Do **not** try to fix it by enlarging the
  `/tmp` tmpfs; that trades a disk error for an OOM (tmpfs is RAM-backed).
- **Sign-in is refused with "Sign-in is unavailable over plain HTTP", or you get
  401s with credentials you know are correct.** Scrye's session cookie is marked
  `Secure` by default, and browsers refuse to store a `Secure` cookie on an
  `http://` page — so the login can't stick. This is a transport problem, not a
  password problem, and the login screen, the startup log, and an
  `auth.login_blocked_insecure_transport` audit entry all say so. Either reach
  Scrye over HTTPS, or make your TLS-terminating proxy send `X-Forwarded-Proto:
  https` with `SCRYE_FORWARDED_ALLOW_IPS` pointed at it, or — for a deliberate
  plain-HTTP deployment — set `SCRYE_SESSION_COOKIE_SECURE=false`. Read
  [If you're not using HTTPS](#if-youre-not-using-https) first: the opt-out puts
  the session cookie on the wire in cleartext.
- **Filesystem scans are rejected.** Filesystem (Grype `dir:`) scanning is
  **disabled by default**. An admin must set `SCRYE_FILESYSTEM_SCAN_ROOTS` to one
  or more absolute paths and mount them into the container; targets outside those
  roots are refused.

---

## Configuration

Configuration is driven by environment variables (prefix `SCRYE_`). The
[`.env.example`](./.env.example) file is **generated from the backend `Settings`
model** (`backend/app/core/config.py`). Only **non-sensitive** variables belong
in the environment; the master key is always the Docker secret file.
Runtime-editable, non-secret options (instance name, auth policy, scanner
defaults, retention) are **not** env vars — they live in the app's Settings UI
and database.

Every variable has a working default; the **Need** column says when you actually
have to touch it:

- **Required** — must be present/correct for a normal deployment.
- **Conditional** — only matters under the named circumstance; ignore otherwise.
- **Optional** — a tuning knob; the default is fine for most deployments.

| Variable | Default | Need | Description |
| -------- | ------- | ---- | ----------- |
| `SCRYE_APP_SECRET_KEY_FILE` | `/run/secrets/app_secret_key` | Optional | Path to the Docker secret file holding the **master key**, and the highest-precedence key source. **If you set this, the file must exist there** — Scrye refuses to start rather than generate a different key. Leave it unset to use the auto-generated key below. |
| `SCRYE_APP_SECRET_KEY_AUTOGENERATE` | `true` | Optional | Generate a master key on first launch when no key file exists at either path. An existing key file is always reused, never overwritten. Set `false` to require an operator-supplied key. |
| `SCRYE_APP_SECRET_KEY_AUTOGEN_FILE` | `/data/app_secret_key` | Optional | Where the auto-generated key is written (mode `0600`) and read back from. Must be on a **persistent** volume. |
| `SCRYE_FORWARDED_ALLOW_IPS` | `172.16.0.0/12` | **Required** *(behind a proxy)* | IP/CIDR your reverse proxy connects **from** — the trust boundary for `X-Forwarded-For` **and `X-Forwarded-Proto`** (the latter is what tells Scrye a TLS-terminating proxy's client is on HTTPS). Set it to match your topology (see [Reverse proxy](#reverse-proxy-tls)). Never `*`. Irrelevant only if nothing fronts Scrye. |
| `SCRYE_SESSION_COOKIE_SECURE` | `true` | **Conditional** | **HTTPS enforcement for sign-in.** Marks the session/CSRF cookies `Secure`, which browsers store only on `https://` pages — so with this `true`, **login over plain HTTP cannot work** and Scrye refuses it explicitly. Keep `true` in production, including behind a TLS-terminating proxy. Set `false` **only** to opt out deliberately on a plain-HTTP LAN/evaluation deployment. See [If you're not using HTTPS](#if-youre-not-using-https). |
| `SCRYE_CORS_ORIGINS` | _(empty)_ | **Conditional** | Comma-separated origins for a **split dev frontend** (e.g. `http://localhost:5173`). Empty for the normal same-origin SPA. |
| `SCRYE_TRIVY_SERVER_URL` | _(unset)_ | **Conditional** | Only when the [`trivy-server` sidecar](#optional-sidecars) is enabled (e.g. `http://trivy-server:4954`). |
| `SCRYE_DOCKER_PROXY_URL` | _(unset)_ | **Conditional** | Only for ["scan running images"](#optional-sidecars) via the read-only docker-socket-proxy (e.g. `http://docker-socket-proxy:2375`). |
| `SCRYE_FILESYSTEM_SCAN_ROOTS` | _(empty)_ | **Conditional** | Comma-separated absolute paths under which Grype `dir:` scans are allowed. Empty **disables** filesystem scanning; set it (and mount the paths) to enable. |
| `SCRYE_ALLOW_INTERNAL_EGRESS` | `false` | Optional | Allow server-side fetchers (notification webhook/SMTP/Matrix, the registry probe) to reach **private/internal** addresses. Off by default to block SSRF; enable only if you use an internal SMTP relay or private registry. Loopback and cloud-metadata addresses are **always** refused. |
| `SCRYE_APP_NAME` | `Scrye` | Optional | Application name shown in the UI and logs. |
| `SCRYE_ENVIRONMENT` | `production` | Optional | `development` or `production`. |
| `SCRYE_LOG_LEVEL` | `INFO` | Optional | Root log level. |
| `SCRYE_HOST` | `0.0.0.0` | Optional | Bind address inside the container (published to loopback by the port mapping). |
| `SCRYE_PORT` | `8089` | Optional | API/SPA port inside the container. |
| `SCRYE_DATABASE_PATH` | `/data/scrye.db` | Optional | SQLite database file path. |
| `SCRYE_SESSION_LIFETIME_HOURS` | `168` | Optional | Login session lifetime (hours; 168 = 7 days). |
| `SCRYE_AUTH_RATE_LIMIT_ATTEMPTS` | `5` | Optional | Max auth attempts per client IP per window. |
| `SCRYE_AUTH_RATE_LIMIT_WINDOW_SECONDS` | `60` | Optional | Auth rate-limit window length (seconds). |
| `SCRYE_MAX_CONCURRENT_SCANS` | `2` | Optional | Max scans the in-process worker runs at once. |
| `SCRYE_SCAN_TIMEOUT_SECONDS` | `1800` | Optional | Per-scan wall-clock timeout (seconds). |
| `SCRYE_SCANNER_MAX_OUTPUT_BYTES` | `536870912` | Optional | Max stdout (512 MiB) captured from a scanner subprocess; output past this kills and fails the scan. |
| `SCRYE_SCANNER_CACHE_DIR` | `/cache` | Optional | Writable volume for scanner vuln DBs and scratch (see [Requirements](#requirements)). |
| `SCRYE_ARTIFACTS_DIR` | `/data/artifacts` | Optional | Directory holding raw scanner artifacts (JSON output, SBOMs). |
| `SCRYE_BACKUPS_DIR` | `/data/backups` | Optional | Directory holding backup bundles (manual and scheduled). |
| `SCRYE_TRIVY_BINARY` | `trivy` | Optional | Trivy binary path/name (resolved on `PATH` if a bare name). |
| `SCRYE_GRYPE_BINARY` | `grype` | Optional | Grype binary path/name. |
| `SCRYE_SYFT_BINARY` | `syft` | Optional | Syft binary path/name. |
| `SCRYE_FRONTEND_DIST_DIR` | `/app/frontend/dist` | Optional | Directory of the built SPA served by FastAPI. |

Two environment variables are **not** Scrye `Settings` fields, so they appear
neither in the table above nor in `.env.example`:

- **`DOCKER_GID`** — a Compose-level variable read only by
  `docker/docker-compose.yml`, only when the
  [`docker-env` profile](#docker-socket-proxy--scan-running-images) is enabled.
  It must be the **host's** docker group id
  (`stat -c '%g' /var/run/docker.sock`) — the socket proxy runs unprivileged and
  needs that group to read the socket. The Compose file falls back to `999` if
  you leave it unset, but treat that as a **placeholder, not a safe default**:
  `999` is a packaging convention, not a guarantee, and it is often wrong. On
  the Debian host this sidecar was last exercised on, the docker group was
  **`989`** — the fallback would have failed there. Always derive the value with
  `stat`; never assume it.
- **`SCRYE_ALLOW_WEAK_MASTER_KEY`** — a temporary migration escape hatch read
  directly by the crypto module, not by the config loader. See
  [The master key](#the-master-key); it is not meant to be left enabled.

**A wrong `DOCKER_GID` crash-loops the sidecar — and only the sidecar.** The
proxy cannot open `/var/run/docker.sock` (`root:docker`, mode 0660) without the
right group, so it logs

```text
dial unix /var/run/docker.sock: connect: permission denied
```

and exits. It does not then sit there stopped: `restart: unless-stopped` starts
it again, it fails identically, and Docker keeps retrying it under its restart
backoff. In `docker compose ps` / `docker ps -a` the container shows STATUS
**`Restarting`** (cycling, occasionally caught mid-attempt) — **not** `Exited`,
so don't go looking for a stopped container.

**Scrye itself starts and stays up throughout.** That is structural, not luck:
no service in `docker/docker-compose.yml` declares `depends_on` at all, in any
profile. The `scrye` container therefore never waits on the proxy at startup and
is never torn down when it fails; there is no `condition: service_healthy` gate
to block on, and the proxy's healthcheck is consumed by nothing but itself.

The one visible symptom inside the app is that enumerating images for that
Docker environment returns **502 Bad Gateway**. Read the detail text — it tells
you which of the two failures you have:

- **A connection error** (`Could not reach the Docker proxy at …`) — nothing is
  listening, i.e. the sidecar is crash-looping. Probing by hand shows the same
  thing: `curl` reports status **`000`**, not an HTTP status, because the TCP
  connection itself never completes. This is the `DOCKER_GID` case.
- **`returned HTTP 403`** — the proxy is up and answering, and the request was
  refused by its allowlist (a non-allowlisted path, or a source that isn't the
  `scrye` container). `DOCKER_GID` is fine.

That distinction — connection failure vs. an HTTP status — is the signal that
separates a broken sidecar from a working-but-restrictive allowlist. Either way,
scans, history, schedules, and every other feature are untouched: a permission
error at proxy start means **"docker-env is unavailable"**, not "Scrye is
broken." Fix `DOCKER_GID` and restart the sidecar alone.

### The master key

The application **master key** is always read from a **file** — **never** an
environment variable and never baked into an image layer. Stored credentials are
encrypted with a key derived from it (HKDF-SHA256 → AES-256-GCM).

**Where it lives, in precedence order.** The first source that has a key file
wins, and nothing further is consulted:

1. **`SCRYE_APP_SECRET_KEY_FILE`** (default `/run/secrets/app_secret_key`) — the
   Docker secret you supply. Recommended for production.
2. **`SCRYE_APP_SECRET_KEY_AUTOGEN_FILE`** (default `/data/app_secret_key`) — the
   key Scrye generated for itself on an earlier start.
3. **A key generated now**, written to (2), used only when neither file exists and
   `SCRYE_APP_SECRET_KEY_AUTOGENERATE` is on (it is, by default).

**Auto-generation on first run.** With no key supplied, first launch mints one
from the OS CSPRNG — 48 random bytes, base64-encoded, the exact equivalent of
`openssl rand -base64 48` — writes it with mode `0600` owned by the container's
uid, verifies those permissions came back correctly off disk, and logs one INFO
line saying where it went and that it must be backed up. Concurrent starts cannot
both generate: the file is created with `O_CREAT|O_EXCL` and whoever loses reads
the winner's key.

**An existing key file is never replaced.** If a key file exists but cannot be
loaded — unreadable, empty, not base64, too short, malformed — Scrye **refuses to
start** instead of generating a replacement. That refusal is the point: a second
key would leave every already-encrypted secret undecryptable while the app looked
perfectly healthy. For the same reason, setting `SCRYE_APP_SECRET_KEY_FILE` and
then not mounting the file is a startup error, not a cue to generate one; and if a
supplied secret and a previously auto-generated key are both present and differ,
startup fails until you reconcile them (carry the old key forward as a version —
see **Key rotation** below — or delete it if nothing was stored under it).

**If you lose the key, the secrets are gone.** There is no recovery path, no
reset, and no backdoor: the plaintext exists nowhere else. Scrye still starts and
scan history, findings, users, and settings are all intact, but every stored
secret (registry credentials, git tokens, the OIDC client secret, MFA seeds,
scheduled-backup passphrases) fails to decrypt and must be re-entered — and
existing MFA enrollments must be reset. **So back the key file up, and keep the
copy somewhere other than the volume it lives on.** See
[Backup & restore](#backup--restore) for how this interacts with backup bundles.

**Trade-off of the generated key's location.** `/data/app_secret_key` sits on the
same volume as the database it protects, which is what makes zero-touch first run
possible — but it also means anyone who obtains a copy of that volume has both the
ciphertext and the key. Field encryption then still protects against narrower
disclosure (a leaked `.db` file, a stray artifact copy, log exposure) but not
against whole-volume compromise. If you want the key and the data separated, supply
the key as a Docker secret from a different mount, or point
`SCRYE_APP_SECRET_KEY_AUTOGEN_FILE` at one — source 1 keeps its precedence, so
adopting it later is a supported move.

**Checking which key is in force.** **Settings → About** shows the master key's
source and path (admin-only, and never any key material): either "auto-generated
at `<path>`", with the reminder to back it up, or "supplied as a secret file at
`<path>`". The same fact appears once per start in the container log
(`Master key loaded from … (auto-generated|configured secret file)`).

**High-entropy key required.** The key file must be **valid base64 that decodes to
at least 32 bytes** — exactly what `openssl rand -base64 48` produces. A raw
passphrase (anything that isn't valid base64) is **rejected** on startup, because a
low-entropy key could be brute-forced offline against a stolen database at HKDF
speed. If you are upgrading a deployment that used a passphrase key, set
`SCRYE_ALLOW_WEAK_MASTER_KEY=1` to boot **just long enough to rotate** to a proper
key — it logs a warning on every start and is not meant to be left enabled.

**Key rotation.** The key file may hold multiple versions, one per line, as
`v<N>:<base64>` entries (a plain single-line key is version 1). New secrets are
encrypted under the highest version and older versions remain readable, so you can
add a new version and restart safely. Note that v1 does **not** yet ship an
admin-facing bulk re-encryption action, so existing rows stay wrapped under the
version they were written with until each is next updated; keep the older key line
in place until that tool lands (tracked on the [roadmap](./docs/ROADMAP.md)).

---

## Reverse proxy (TLS)

Scrye serves **plain HTTP** internally and (with the compose above) binds to
**loopback**. In production you front it with a TLS-terminating reverse proxy.
Any proxy that sets `X-Forwarded-For` works — the client-IP logic is
proxy-agnostic.

**One setting is required:** `SCRYE_FORWARDED_ALLOW_IPS` must be the IP/CIDR the
proxy connects to Scrye **from**, so Scrye trusts that proxy's `X-Forwarded-For`
(the client IP used by the auth rate limiter and audit log) **and** its
`X-Forwarded-Proto` (which tells Scrye the client is really on HTTPS even though
Scrye itself sees HTTP — see [If you're not using HTTPS](#if-youre-not-using-https)).
Both headers are honoured **only** from the addresses you list here; from anyone
else they are ignored, so no client can forge its source IP or claim an HTTPS
transport. If the value doesn't match your proxy, Scrye **fails safe** — it
ignores both headers and uses the raw peer IP and the real (plain-HTTP) scheme.
**Never set it to `*`.** See [Security model](#security-model) for the full
rationale.

Make sure your proxy actually sends `X-Forwarded-Proto`. Caddy and Traefik do by
default; for nginx, the `proxy_set_header X-Forwarded-Proto $scheme;` line in the
example below is required, not optional.

There are two common topologies:

- **Proxy as a container on the same Docker network as Scrye.** The proxy reaches
  Scrye at `scrye:8089` over the internal network; you can drop the host port
  mapping entirely. `SCRYE_FORWARDED_ALLOW_IPS` is the proxy's Docker subnet (or
  its exact container IP). Put both services on one Compose network.
- **Proxy on the host** (installed directly, not in Docker). It reaches Scrye at
  the published `127.0.0.1:8089`. `SCRYE_FORWARDED_ALLOW_IPS=127.0.0.1`.

Examples below assume your DNS name is `scrye.example.com`.

### Caddy

Caddy fetches/renews TLS automatically and sets `X-Forwarded-For` for you.

```caddyfile
# Caddyfile — Caddy as a container on the same Docker network as Scrye
scrye.example.com {
    reverse_proxy scrye:8089
}
```

Set `SCRYE_FORWARDED_ALLOW_IPS` to Caddy's Docker subnet (the shipped default
`172.16.0.0/12` covers the default bridge). Host-installed Caddy proxying to
`127.0.0.1:8089` instead → `SCRYE_FORWARDED_ALLOW_IPS=127.0.0.1`.

### nginx

Host-installed nginx terminating TLS and proxying to the loopback-published port:

```nginx
server {
    listen 443 ssl;
    server_name scrye.example.com;

    ssl_certificate     /etc/letsencrypt/live/scrye.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/scrye.example.com/privkey.pem;

    # SPA + API are same-origin; one proxy_pass covers everything.
    location / {
        proxy_pass         http://127.0.0.1:8089;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s; # allow long-running scan requests
    }
}
```

With host nginx → `SCRYE_FORWARDED_ALLOW_IPS=127.0.0.1`.

### Traefik

Traefik v3 as a container, discovering Scrye via Docker labels (both on the same
Docker network; no host port needed). Add to the `scrye` service in your Compose:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.scrye.rule=Host(`scrye.example.com`)"
  - "traefik.http.routers.scrye.entrypoints=websecure"
  - "traefik.http.routers.scrye.tls.certresolver=letsencrypt"
  - "traefik.http.services.scrye.loadbalancer.server.port=8089"
```

Traefik forwards `X-Forwarded-For` and `X-Forwarded-Proto` by default. Set
`SCRYE_FORWARDED_ALLOW_IPS` to Traefik's Docker network subnet (e.g.
`10.89.0.0/24`) or its exact container IP.

### If you're not using HTTPS

By default Scrye marks its session and CSRF cookies **`Secure`**. Browsers store
a `Secure` cookie only on an `https://` page, so **over plain HTTP a login can
never take effect**: the credentials are accepted, the cookie is silently
discarded by the browser, and every request after that is unauthenticated. What
you see is repeated **401s with a password you know is correct**.

Scrye does not let that happen quietly. It refuses such a sign-in outright with
an explicit message on the login screen, logs the reason at `ERROR` — including
whether the credentials were valid — and records a distinct
`auth.login_blocked_insecure_transport` audit entry. It also states the situation
at startup:

```text
HTTPS enforcement is ON (SCRYE_SESSION_COOKIE_SECURE=true): ... LOGINS OVER
PLAIN HTTP WILL FAIL ... If this deployment is intentionally plain HTTP (LAN or
evaluation), opt out with SCRYE_SESSION_COOKIE_SECURE=false and restart.
```

There are three shapes you can be in.

**1. Scrye is reached over HTTPS directly.** Nothing to do.

**2. A reverse proxy terminates TLS** (the normal production setup, and the case
most people who hit this are actually in). Scrye's own listener speaks plain HTTP
here, so it cannot see that the *client* is on HTTPS — the proxy has to tell it.
Keep `SCRYE_SESSION_COOKIE_SECURE=true` and:

- have the proxy send **`X-Forwarded-Proto: https`** (Caddy and Traefik do this
  by default; for nginx add `proxy_set_header X-Forwarded-Proto $scheme;`), and
- set **`SCRYE_FORWARDED_ALLOW_IPS`** to the address the proxy connects from.

Both are needed. The header is honoured **only** from the addresses listed in
`SCRYE_FORWARDED_ALLOW_IPS` — never from an arbitrary client, which could
otherwise just claim HTTPS — so if that setting is wrong or unset, a correctly
configured HTTPS deployment still looks like plain HTTP to Scrye and sign-in is
refused. The scheme is only ever *upgraded* by the header, never downgraded: real
TLS at Scrye's own listener always wins.

**3. Plain HTTP on purpose** (a trusted LAN, or a quick evaluation). This
requires an explicit opt-out — Scrye will not guess:

```yaml
environment:
  SCRYE_SESSION_COOKIE_SECURE: "false"
```

Restart the container after changing it.

> **Security caveat — read before setting this.** With `Secure` off, the session
> cookie is transmitted **in cleartext on every request**. Anyone able to observe
> the network path — another host on the LAN, a compromised switch or Wi-Fi AP, a
> router in between — can copy it and use it to act as that user, including an
> admin, for the cookie's full lifetime (`SCRYE_SESSION_LIFETIME_HOURS`, 7 days by
> default). An active attacker can also inject content over plain HTTP to steal
> it. No password is needed for any of that, and MFA does not help — the stolen
> cookie is already past authentication. Scrye scans for vulnerabilities and its
> database holds registry credentials and git tokens, so treat this as a
> deliberate, temporary trade-off on a network you control — not a default to
> leave in place. Everything else about the cookies is unchanged: they stay
> `HttpOnly` and `SameSite=Lax`, and CSRF protection still applies.

Scrye **never** drops `Secure` automatically based on the scheme it happens to
observe. That would look convenient and would silently downgrade every deployment
in shape 2 — where the app legitimately sees HTTP while the user is on HTTPS — so
turning it off is always the operator's explicit decision.

---

## Optional sidecars

Both sidecars are **off by default** and gated behind Compose **profiles** in the
bundled `docker/docker-compose.yml`. A normal deployment does not need either.
Enable one only if you want the specific capability it adds.

### `trivy-server` — shared Trivy vulnerability-DB cache

- **Optional.** Runs a `trivy server` that holds one shared Trivy vulnerability
  DB; point Scrye at it with `SCRYE_TRIVY_SERVER_URL=http://trivy-server:4954`.
- **Without it:** Scrye downloads and maintains its own Trivy DB on the `/cache`
  volume. This is completely fine — for a single Scrye instance it is the normal
  setup and costs nothing extra.
- **When you'd want it:** you run **multiple** Scrye instances (or other Trivy
  consumers) and want them to share one DB cache to save bandwidth and disk, or
  you want to control DB refresh centrally. Not worth it for a single instance.

### `docker-socket-proxy` — "scan running images"

- **Optional.** A **read-only** proxy ([`wollomatic/socket-proxy`](https://github.com/wollomatic/socket-proxy),
  digest-pinned, a from-scratch Go binary running as uid `65534`) in front of the
  Docker socket that lets Scrye **enumerate** the images on a Docker host. Point
  Scrye at it with `SCRYE_DOCKER_PROXY_URL=http://docker-socket-proxy:2375` and
  register the environment under Settings → Docker environments.
- **Prerequisite: `DOCKER_GID`.** The proxy runs unprivileged, so it needs the
  **host's** docker group id to open `/var/run/docker.sock` (`root:docker`, mode
  0660). Set `DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"` before bringing
  the profile up — including if you copy the service into your own Compose file.
  **Derive it, don't guess:** the Compose fallback of `999` is only a convention
  and was `989` on the Debian host this was last verified against. Getting it
  wrong crash-loops this sidecar (STATUS `Restarting`) and nothing else — Scrye
  starts and runs normally (see [Configuration](#configuration)).
- **Without it:** you simply don't get the image-enumeration convenience. You can
  still scan **any** image by typing its reference into New scan — nothing else is
  lost.
- **When you'd want it:** you want to browse images running on a Docker host from
  Scrye's UI and scan them by picking from a list instead of typing references.
- **What it exposes:** exactly one Docker API endpoint — `GET /images/json`, the
  image listing, which is the only request Scrye ever makes of it. Every other
  path (`/containers/…`, `/info`, `/events`, `/version`, `/_ping`, and every
  non-listing `/images/…` route) is refused with **403**, and every method other
  than `GET` with **405**, before it reaches the socket. Only the `scrye`
  container may connect at all.
- **Reading a 403 from the proxy.** The `-allowfrom` source check is evaluated
  **before** the path and method rules — wollomatic resolves the client address
  back to a hostname and compares it to `scrye`, and a request from any other
  source is refused with **403** whatever it asked for, including methods that
  would otherwise answer 405. A wrong source and a disallowed path are therefore
  indistinguishable from the client. If you renamed the app service, or you are
  probing by hand from another container or from the host, that 403 is the
  source check, not the `-allowGET` regex; the proxy logs
  `blocked request … forbidden IP` when it is. Check the proxy's log before
  editing the allowlist pattern.
- **Residual risk:** this is the **only** place a Docker socket is mounted (read-
  only). Anyone who can reach the proxy can enumerate the host's image list, so
  enable it deliberately, keep it on the internal network (no host port), and see
  the [Security model](#security-model).

To enable a sidecar from the bundled Compose file (build-from-source layout):

```bash
docker compose -f docker/docker-compose.yml --profile trivy-server up -d

# The socket proxy runs unprivileged, so it needs the host's docker group id to
# read the socket. Without this it starts but cannot reach the daemon.
export DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"
docker compose -f docker/docker-compose.yml --profile docker-env up -d
```

Both sidecars carry a `mem_limit` in the bundled Compose file; their CPU caps are
in the opt-in
[CPU-limit overlay](#resource-limits-and-nas-platforms), which you can add to
either command above with a second `-f`.

If you deploy from the published image with your own Compose file, copy the
matching service definition from
[`docker/docker-compose.yml`](docker/docker-compose.yml) (they carry the hardened
settings and residual-risk notes) and set the corresponding `SCRYE_*` URL.

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

- Scrye uses generic OIDC (authorization-code + PKCE, RS256). ID-token signature
  and `iss`/`aud`/`exp`/`nonce`/`sub` claims are verified, and each login is bound
  to the initiating browser (defeating login-CSRF/session fixation).
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
- **Repository (Trivy)** — enter a **remote clone URL** (`http`, `https`, `ssh`,
  or `git`) and optionally a branch/commit/tag. A local filesystem path is
  refused with a 422 — repositories are always cloned from a remote, and local
  paths are reachable only through the filesystem allowlist below. For a private
  repo, select a **git credential** (Settings →
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
page. Operators and admins can **delete** a completed scan there (behind a
confirmation) — this permanently removes the scan and all of its findings, stored
artifacts, and tags, so it drops out of history, diffs, and the dashboard totals.

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
  HKDF-derived key, key-version tagged, and **row-bound** associated data —
  `<table>.<column>:<row-id>` — so a ciphertext can't be replayed into another
  row of the same column). Binding is applied on write and falls back to the
  older column-only tag on read, so pre-existing ciphertext keeps decrypting and
  upgrades the next time its row is written. The database never holds plaintext
  secrets.
- **Master key from a file, never the environment.** The key comes from a Docker
  secret file (`SCRYE_APP_SECRET_KEY_FILE`) or, when none is supplied, from a
  0600 key file Scrye generates itself on first launch
  (`SCRYE_APP_SECRET_KEY_AUTOGEN_FILE`, default `/data/app_secret_key`) — never an
  env var and never an image layer. An existing key file is always used and never
  replaced: a key file that fails to load stops startup instead of being
  regenerated, because a second key would silently orphan stored ciphertext. See
  [The master key](#the-master-key), including the trade-off of the generated
  key's default location.
- **Authentication.** Local accounts use **argon2id** with revocable server-side
  sessions (opaque token, only its SHA-256 stored); generic **OIDC** (Authlib,
  PKCE + nonce, ID-token signature/claim validation, browser-bound login) runs
  alongside local auth; optional **TOTP MFA** with an enforceable policy adds a
  second factor. **API tokens** are bearer credentials stored only as a SHA-256
  hash, scoped to a role no higher than their owner's. Cookie sessions require a
  CSRF token (`X-CSRF-Token`) on every state-changing request; bearer tokens are
  CSRF-exempt (not sent cross-site). Auth endpoints are rate-limited per client IP.
- **HTTPS enforcement on sign-in.** Session cookies are `HttpOnly`,
  `SameSite=Lax`, and `Secure` by default. Because a browser silently discards a
  `Secure` cookie on an `http://` page, Scrye **refuses** a sign-in it can see
  would not stick, rather than returning a success the browser throws away: the
  login screen explains it as a transport problem, the log says explicitly whether
  the credentials were valid, and a distinct
  `auth.login_blocked_insecure_transport` audit entry is recorded. The refusal
  itself — status, message, and timing — is identical for valid, invalid, and
  unknown accounts, so it reveals nothing about credentials. `Secure` is **never**
  dropped automatically from an observed scheme (that would downgrade every
  deployment behind a TLS-terminating proxy); turning it off is an explicit
  operator decision. See [If you're not using HTTPS](#if-youre-not-using-https).
- **Write-only secret API + log redaction.** Secret fields accept values on write
  and return a mask + timestamp on read. A logging filter redacts secret fields,
  bearer/basic tokens, and URL userinfo across messages and tracebacks (and is
  attached to uvicorn's loggers). Scanner subprocesses don't inherit Scrye's
  `SCRYE_*` config.
- **Baseline security headers.** Every response carries `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`,
  and a **Content-Security-Policy** tuned for the SPA (`script-src 'self'` with no
  inline scripts, `connect-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`).
  Externally-derived data — e.g. a finding's scanner-supplied reference URL — is
  rendered as a link only when it is a valid `http(s)` URL, and never with a
  `javascript:`/`data:` scheme, so a crafted advisory can't turn a finding row into
  a script-execution sink.
- **Scan-time only.** Secrets are decrypted in memory into transient credential
  files on **tmpfs** (Docker `config.json`, `GIT_ASKPASS` helper), used for the
  scanner subprocess, then shredded.
- **`SCRYE_FILESYSTEM_SCAN_ROOTS` is the only gate on local-path scanning.**
  Filesystem (Grype `dir:`) scanning is off unless an admin sets that allowlist,
  and targets outside it are refused. No other target type may reach a local
  path: a **repository** target must be a remote clone URL
  (`http`/`https`/`ssh`/`git`), rejected at request validation with a 422
  otherwise — Trivy's `repo` subcommand also accepts a bare filesystem path, so
  without that check a target like `/data` or `/run/secrets` would have walked
  the container filesystem and published the results as a downloadable artifact,
  around the allowlist. Scheduled scans inherit the same validation.
- **CIS-aligned container posture.** Base images are pinned by digest;
  `trivy`/`grype`/`syft` are installed from the publishers' release archives and
  **cosign-verified** before extraction (never `curl | bash` — see
  [Supply chain](#supply-chain)); the image runs as a **non-root** user with `cap_drop: ALL`,
  `no-new-privileges`, a **read-only** root filesystem + tmpfs, memory limits, a
  healthcheck, and loopback-only port binding. CPU limits are an
  [opt-in overlay](#resource-limits-and-nas-platforms) rather than a default,
  because the Compose key that carries them isn't accepted on every container
  platform; memory limits — the ones that bound an OOM blast radius — are always
  on.
- **Writable scratch under a read-only root.** The only writable paths are the
  `/data` and `/cache` volumes and a small `/tmp` tmpfs (mounted owned by uid
  1000, holding only in-memory credential files). Every scanner invocation —
  scans **and** the About-tab version/DB-status probes — is pointed at the
  persistent `/cache` volume via `TRIVY_CACHE_DIR`, `GRYPE_DB_CACHE_DIR`,
  `XDG_CACHE_HOME`/`HOME`, and `TMPDIR`, so nothing falls back to the read-only
  `$HOME/.cache` or overflows the tmpfs, and the vuln DBs persist across restarts.
- **Docker socket residual risk.** "Scan running images" uses a **read-only**
  `wollomatic/socket-proxy` sidecar. The Scrye app **never** mounts
  `/var/run/docker.sock`; the proxy is the only place the socket is mounted
  (read-only), so enable that profile deliberately and keep it on the internal
  network. The proxy allowlists requests by **regex per HTTP method** and is
  pinned to the single endpoint Scrye uses, `GET /images/json` — everything else
  is rejected at the proxy (403 for any other path, 405 for any other method) and
  never reaches the socket. A `-allowfrom` source allowlist additionally limits
  connections to the `scrye` container, so nothing else on the Compose network
  can reach it; that source check runs **first**, ahead of the path and method
  rules, so a connection from anywhere else is refused with 403 regardless of
  what it requests. The container itself is a from-scratch image (no shell, no
  package manager) running as uid 65534 with a read-only root filesystem, no
  writable path at all, `cap_drop: ALL`, and `no-new-privileges`. It needs the
  host's docker GID (`DOCKER_GID`) purely to read the socket. The residual
  exposure is therefore the host's **image list** — not container environment
  variables, logs, or filesystems.
- **Outbound egress / SSRF.** Admin-configured fetch targets — notification
  transports (webhook/Discord/Matrix/SMTP), the registry connectivity probe, and
  the Docker socket proxy — are resolved and screened before Scrye connects.
  Loopback and link-local/**cloud-metadata** (`169.254.169.254`) addresses are
  **always** refused; RFC-1918/private addresses are refused **by default** and
  permitted only when `SCRYE_ALLOW_INTERNAL_EGRESS=true` (for deployments that use
  an internal SMTP relay or private registry). This is a best-effort,
  defense-in-depth control on an already admin-gated, CSRF-protected surface.
- **Trusted reverse-proxy hops (`SCRYE_FORWARDED_ALLOW_IPS` — required per
  deployment).** Scrye honors `X-Forwarded-For` (uvicorn `--proxy-headers`) so the
  auth rate limiter and audit log see the **real** client IP. The logic is
  **proxy-agnostic** — it works behind any proxy that sets `X-Forwarded-For`
  (Caddy, nginx, Traefik, HAProxy, …). uvicorn trusts the header only when the
  connecting peer is in `SCRYE_FORWARDED_ALLOW_IPS`, then takes the first address
  that is **not** in that set, discarding any spoofed leftmost entry.

  Set it to the IP/CIDR your proxy actually connects from. The default
  (`172.16.0.0/12`) fits a proxy container on the default Docker bridge.
  **Fail-safe on mismatch:** if the configured value doesn't include the real
  connecting peer, `X-Forwarded-For` is ignored and the raw proxy IP is used — no
  spoofing possible, but per-client rate-limit buckets and accurate audit IPs
  don't take effect until you set it correctly. **Never set it to `*`** and never
  include the client LAN range — that trusts every hop and re-opens the spoofing
  hole. See [Reverse proxy](#reverse-proxy-tls) for per-topology values.

  The same boundary governs **`X-Forwarded-Proto`**, which is how a
  TLS-terminating proxy tells Scrye the client is on HTTPS even though Scrye's own
  listener sees HTTP. It is honored only from these peers — an arbitrary client
  cannot claim an HTTPS transport to satisfy the sign-in check — and it only ever
  *upgrades* the observed scheme `http` → `https`, never downgrades it, so real
  TLS at Scrye's listener always wins.
- **MFA scope for OIDC (accepted limitation).** The mandatory-MFA policy
  (`required_all` / `required_admin`) is enforced on **local** password login.
  OIDC logins delegate the second factor to the identity provider — Scrye has no
  local TOTP challenge in the OIDC handshake, and provisioned OIDC accounts carry
  no usable local password. If you require MFA for OIDC users, enforce it at the
  IdP. When a mandatory policy would otherwise apply, the OIDC login is recorded
  in the audit log with `mfa_delegated_to_idp` so you can confirm the IdP is
  carrying that second factor. When group→role mapping is configured it re-applies on each login, but an
  **absent** groups claim preserves the user's current role rather than demoting
  them, and an OIDC sync can never remove the last admin.
- **Forced-enrollment window (accepted limitation).** When a mandatory-MFA policy
  applies to an account that has never enrolled, enroll-on-first-login means
  whoever presents a valid **password** completes the first-factor setup — so
  during the window before the legitimate user enrolls, a password-only attacker
  could bind **their own** authenticator (the exact threat mandatory MFA targets).
  This is inherent to self-service enrollment; the durable mitigation is
  out-of-band/admin-provisioned enrollment. Until then, each policy-forced
  first-enrollment is recorded in the audit log with `forced_by_policy`, so an
  unexpected enrollment is detectable — enroll promptly after enabling the policy.

**Reporting a vulnerability:** please do it privately — see
[SECURITY.md](./SECURITY.md).

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

**The master key and backups.** Which backup you take decides whether you also
need [the master key](#the-master-key):

- **A Scrye backup bundle is self-sufficient.** Secrets are decrypted under the
  host master key and **re-wrapped under your passphrase** as the bundle is built,
  so restoring needs only the passphrase — never a master-key transplant. Restoring
  onto a brand-new deployment therefore needs no key provisioning at all: that
  instance generates its own key on first launch and the restore re-encrypts every
  secret under it.
- **A volume/file-level backup does need the key.** The rows in `scrye.db` are
  master-key ciphertext. Copying the whole `scrye_data` volume carries the
  generated key along (`/data/app_secret_key`) and so restores intact — but a
  backup of *just* the database, or a deployment whose key is a Docker secret from
  elsewhere, has to include the key file too or the secret columns are permanently
  unreadable. And because a whole-volume copy holds the key **and** the ciphertext
  together, protect it accordingly.

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

The published image lives on GHCR as **`ghcr.io/tyler-rich/scrye`** (`:latest` and
`:<version>` from tagged releases; `:dev` nightly from `dev`). To build locally
instead — single-arch for the host you're on:

```bash
docker build -f docker/Dockerfile -t scrye:0.2.0 .
```

For a **multi-arch** image (`linux/amd64` + `linux/arm64`), use Buildx; the
Dockerfile is arch-aware and pulls the correct `trivy`/`grype`/`syft` binaries per
target platform:

```bash
docker buildx create --use --name scrye-builder   # once
docker buildx build -f docker/Dockerfile \
  --platform linux/amd64,linux/arm64 \
  -t scrye:0.2.0 .
```

CI builds both architectures and **dogfoods** the result: it scans Scrye's own
image with Trivy and Grype and fails on any **fixable HIGH/CRITICAL** finding in
Scrye's own attack surface — its base-image OS packages (including the `git`
runtime dependency), Python and JS dependencies, and application code (the whole
image filesystem is scanned). The **bundled `trivy`/`grype`/`syft` binaries** are
the one thing excluded from the gate (they still appear in the informational scan
report): they're unmodified upstream Go binaries Scrye can't rebuild, so CVEs in
their embedded Go modules track upstream's release cadence — keeping the pinned
scanner versions current is how those are addressed. CI never publishes; GHCR
publishing lives in separate release and nightly workflows.

The dogfood gate only runs when code changes, so a **weekly scheduled re-scan**
(`.github/workflows/rescan.yml`) pulls the already-published `:latest` and `:dev`
images and re-runs the same Trivy/Grype gate against them. A newly disclosed,
fixable HIGH/CRITICAL CVE in a shipped image opens (or comments on) a tracking
issue rather than gating a merge — so a quiet period can't hide a fresh CVE in the
image you're running.

---

## Supply chain

Scrye is a security tool, so its own build pipeline is held to the same standard
as what it scans. Every input is pinned and verified, and every published image
carries attestations you can check yourself.

**Verifying an image you pulled.** Both publish paths attach a BuildKit **SLSA
provenance** attestation (`mode=max`) and an **SPDX SBOM** to the image manifest,
plus a **GitHub-signed** build-provenance attestation. Confirm a pulled image was
built by this repository's workflow, from a known commit:

```bash
gh attestation verify oci://ghcr.io/tyler-rich/scrye:latest --owner tyler-rich
```

**What is pinned and verified at build time:**

- **Bundled scanner binaries.** `trivy`, `grype`, and `syft` are downloaded from
  their publishers' GitHub releases, and the release `checksums.txt` is verified
  with **cosign** (keyless, certificate identity pinned to the upstream project's
  own release workflow and the GitHub Actions OIDC issuer) *before* the tarball is
  checked with `sha256sum -c` and extracted. That raises the guarantee from
  "matches what GitHub served" to "signed by the upstream project's release
  pipeline". A signature *or* checksum mismatch fails the build.
- **Python dependencies.** `backend/pyproject.toml` pins the direct runtime deps
  and `backend/requirements.lock` is their fully-resolved transitive closure with
  **hashes for every artifact**; the image installs it with
  `pip install --require-hashes`, so an unpinned or substituted transitive package
  cannot enter the image. The PEP 517 build backend (`setuptools`) is pinned and
  hash-locked the same way. CI fails if the lock drifts from `pyproject.toml`.
- **Base and sidecar images** are pinned by **digest**, not tag — including the
  `docker/dockerfile` frontend syntax directive and the socket-proxy sidecar.
- **GitHub Actions.** Every external `uses:` in every workflow *and* in the
  composite build action is pinned to a full **commit SHA** (with the human-readable
  version as a trailing comment), so a moved tag can't change what CI runs.
- **Dependabot** watches `pip` (`/backend`), `npm` (`/frontend`), `docker` and
  `docker-compose` (`/docker`), and `github-actions` for both `/` and the composite
  action directory — which Dependabot does not otherwise recurse into. All updates
  target `dev`.

**What ships in the image.** The runtime stage carries only what the app needs:
the built SPA, the backend package, Alembic migrations, and the three scanner
binaries. The pytest suite (`backend/tests/`) and dev helper scripts
(`backend/scripts/`) are excluded from the build context, and CI asserts against
the real built image that they are absent.

**Continuous verification.** CI dogfoods every code change by scanning Scrye's own
image with Trivy and Grype, gating on fixable HIGH/CRITICAL findings, and the
weekly re-scan applies the same gate to the already-published `:latest` and `:dev`
images (see [Building the image yourself](#building-the-image-yourself)).

---

## Roadmap

Scrye is feature-complete for its core mission. Forward-looking work — open
features, known limitations, and candidate improvements — is tracked in
**[`docs/ROADMAP.md`](./docs/ROADMAP.md)**.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for local development setup, project
layout, coding standards, testing, the branching model and PR process, and the
release procedure. To report a security issue, see [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE). Bundled Trivy, Grype, and Syft are Apache-2.0 — see
[`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/README.md).
