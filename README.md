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

> **Project status — feature-complete (v1).** All six build phases (see the
> [Roadmap](#roadmap)) have shipped: the application skeleton (FastAPI +
> React/Mantine SPA, SQLite/Alembic, hardened CIS-aligned image); the **auth &
> secrets foundation** — local accounts (argon2id) with revocable server-side
> sessions, first-run admin bootstrap, RBAC (viewer/operator/admin), CSRF
> protection, auth rate limiting, an audit log, and AES-256-GCM field encryption
> for stored secrets; **core scanning** (Trivy/Grype across image, repository,
> filesystem, and SBOM targets with private-registry and git credentials);
> **history, reports & exports** — a filterable, sortable, paginated history view
> with saved presets, scan-to-scan diff, and CSV/Markdown/JSON exports; the
> **settings, OIDC & backup/restore** layer — the full settings section, generic
> **OIDC** login (Authlib) alongside local auth, optional **TOTP MFA**, personal
> **API tokens**, and passphrase-protected **backup/restore** with scheduled
> backups; and the final **dashboard & automation** layer — an aggregate
> **dashboard**, event-driven **notification dispatch** to the configured
> channels, **scheduled/recurring scans** on a cron cadence, **Trivy VEX &
> ignore-rule** management, a Prometheus **`/metrics`** endpoint, a
> result-**retention** policy that prunes old raw artifacts, and a **multi-arch**
> (amd64/arm64) image with a **dogfooding** CI job that scans Scrye's own image
> with Trivy and Grype.

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
- **Dashboard** — aggregate widgets (totals, 30-day trend, top vulnerable
  targets, open critical/high, scanner-DB freshness, recent scans, failed-scan
  alerts).
- **Scheduled scans** — recurring scans on a standard 5-field **cron** cadence,
  per target/profile, with a "run now" action.
- **Notifications** — event-driven dispatch (scan completed / failed /
  critical-or-high) to **webhook / Discord / SMTP / Matrix** channels, each
  subscribing to the events it cares about.
- **Trivy policy** — managed **VEX documents** (OpenVEX / CycloneDX / CSAF) and
  structured **`.trivyignore`** rules, materialized into the scan at run time.
- **Result retention** — optionally prune the raw scanner artifacts of old scans
  to bound disk usage while keeping history and normalized findings.
- **Metrics** — a Prometheus **`/metrics`** endpoint (authenticated) exposing
  scan counts, open critical/high posture, and schedule counts.
- **Authentication** — local accounts (argon2id) with sessions and optional TOTP
  MFA, plus generic **OIDC** (Pocket ID / RS256). **RBAC**: viewer / operator /
  admin.
- **Secrets handling** — stored credentials are field-encrypted with
  **AES-256-GCM**; the master key comes from a Docker secret file; secret API
  fields are write-only. (See [Security model](#security-model).)
- **Backup & restore** — portable, passphrase-protected bundles that re-key
  secrets on restore; optional scheduled backups.
- **API tokens** — personal bearer tokens for automation, scoped to a role no
  higher than their owner's.

## Integrations

- **Trivy**, **Grype**, **Syft** — official binaries, orchestrated and parsed
  from their JSON output (Scrye never reimplements scanner logic). All three
  are Apache-2.0; their license and notice files are bundled unmodified in
  the image at `/THIRD_PARTY_LICENSES` (see
  [`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/README.md) in this repo).
- **OIDC** — generic, validated against Pocket ID.
- **Docker** — image enumeration via a **read-only** `docker-socket-proxy`
  sidecar (the app never mounts the Docker socket itself).
- **Private registries** — static credentials and ECR/GCR/ACR helpers.
- **Notification channels** — webhook / Discord / SMTP / Matrix, dispatched on
  scan events.
- **Prometheus** — an authenticated `/metrics` endpoint for scraping.

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
  Compose). This is sufficient for scanning images around 1 GB unpacked,
  including SBOM generation; raise the Compose memory limit for substantially
  larger images.
- **Disk for the `/cache` volume — plan for ≥ 10 GB.** Everything the scanners
  read and write at scan time lives on this named volume (`scrye_cache`):
  - **Trivy vulnerability DB:** ~1.2 GB on disk (measured; downloads once,
    persists across restarts, refreshed incrementally).
  - **Trivy Java index DB:** up to ~1 GB more, downloaded on demand the first
    time a Java artifact is scanned.
  - **Grype vulnerability DB:** ~1.5–2 GB on disk (downloads once, then daily
    incremental updates).
  - **Transient image staging:** while an image scan runs, the scanners unpack
    layer data under `/cache/tmp` — budget roughly the **uncompressed size of
    the largest image you scan** (measured: a ~330 MB-compressed image staged
    ~1.1 GB, cleaned up when the scan finished).
- **The `/tmp` tmpfs stays small (200 MB) on purpose.** tmpfs is **RAM-backed,
  not disk-backed** — every byte written there is memory charged against the
  container's limit. `/tmp` holds only transient credential files (a few KB);
  all large scanner writes (vulnerability DBs, image-layer staging) are
  deliberately routed to the disk-backed `/cache` volume instead. Do **not**
  "fix" a disk-space error by enlarging the tmpfs — a multi-GB tmpfs would let
  image staging consume multiple GB of RAM and OOM the container well before
  the 2 GB default limit.
- Optional sidecars: a **Trivy server** (shared vuln-DB cache) and a read-only
  **docker-socket-proxy** (to scan running images).
- For native (non-container) development: **Python 3.13**, **Node 20+**, and the
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
| `SCRYE_BACKUPS_DIR`         | `/data/backups`              | Directory holding backup bundles (manual and scheduled).          |
| `SCRYE_FILESYSTEM_SCAN_ROOTS` | _(empty)_                  | Comma-separated absolute paths under which filesystem (`dir:`) scans are allowed. Empty disables filesystem scanning. |
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

**Running scans:**

- **Image scans** — from **New scan**, pick target type **Image**, choose
  **Trivy** or **Grype**, and enter a reference (e.g. `alpine:3.19` or
  `ghcr.io/org/app:tag`). For a private registry, select a **registry
  credential** (Settings → Registries); Scrye materializes a transient Docker
  config in tmpfs for the scan and shreds it afterward. For Trivy, pick which
  scanners run and an optional severity filter. Optionally toggle **Generate
  SBOM** to also produce a Syft SBOM artifact.
- **Repository scans (Trivy)** — target type **Repository**, enter an HTTPS
  clone URL, and optionally set a branch / commit / tag. For a private repo,
  select a **git credential** (Settings → Git providers): GitHub/GitLab use
  Trivy's provider token env vars, and a generic host is cloned into tmpfs with
  the system `git` binary via a transient `GIT_ASKPASS` helper — so the
  credential never appears in the process argument list, and is never stored or
  logged.
- **Filesystem scans (Grype)** — target type **Filesystem**, enter an absolute
  path. Filesystem scanning is off by default; an admin must allow paths via
  `SCRYE_FILESYSTEM_SCAN_ROOTS`, and targets outside those roots are rejected.
- **SBOM scans (Grype)** — target type **SBOM**, upload a CycloneDX / SPDX /
  Syft JSON file; Scrye stores it as the scan input and runs `grype sbom:…`.
- **Scan running images** — Settings → Docker environments: register a
  read-only `docker-socket-proxy` URL, acknowledge the residual risk, then
  **enumerate** images and scan any listed reference as an image target.
- **Read results & raw artifacts** — the **scan detail** page shows live status,
  a severity summary, and a normalized findings table; every completed scan
  stores the scanner's original JSON (and any generated SBOM) verbatim as the
  source of truth, downloadable from the scan detail page.
- **Browse & filter history** — the **Scan history** page filters by scanner,
  target type, target full-text search, status, date range, initiator, highest
  severity, severity threshold, and tags, with sortable columns and pagination.
  Save a filter set as a **preset** to recall it later, and tag any scan for
  grouping (operator role).
- **Diff two scans** — select two scans of the same target and compare them to
  see **new vs. fixed** findings and the per-severity change over time.
- **Export reports** — download a single scan's findings, or a whole filtered
  history set, as **CSV**, **Markdown**, or **JSON** from the Export menu.

**Settings, OIDC, MFA & backup/restore (Phase 5).** The full **Settings** area
(admin) covers general options, authentication policy, users & roles, scanner
defaults/ignore rules, registries, git providers, Docker environments,
notification channels, API tokens, and backup & restore, plus an about/health
tab. **Sign-in** supports local accounts and generic **OIDC** (enable it under
*Settings → Authentication*, then a "Sign in with …" button appears on the login
screen); any user can enable optional **TOTP MFA** and manage their password,
API tokens, and sessions from the **Account** page. **Backups** are created and
restored from *Settings → Backup & restore* (see [Backup & restore](#backup--restore)).

**Dashboard, automation & policy (Phase 6).** The landing **Dashboard**
summarizes your posture — total scans, a 30-day trend, top vulnerable targets,
open critical/high counts, scanner-DB freshness, recent scans, and failed-scan
alerts. **Scheduled scans** (*Settings → Scheduled scans*, operator role) run a
saved scan template on a 5-field **cron** cadence, with a "run now" action.
**Notification channels** (*Settings → Notifications*, admin) subscribe to scan
events — completed, failed, or critical/high findings — and Scrye dispatches a
summary to each matching webhook / Discord / SMTP / Matrix channel when a scan
finishes. **Trivy policy** (*Settings → Trivy policy*, admin) manages **VEX
documents** and structured **ignore rules** that are applied to every Trivy scan
(via `TRIVY_VEX` / `TRIVY_IGNOREFILE`, materialized into tmpfs at scan time).
**Retention** (*Settings → Retention*, admin) optionally prunes the raw
artifacts of scans older than a chosen age. A Prometheus **`/metrics`** endpoint
exposes operational gauges — see [Monitoring](#monitoring).

Scanner options that stay write-only and secret (registry / git / OIDC
credentials, API tokens) are entered once and never returned in plaintext — the
API returns a mask and a "last updated" timestamp, and plaintext is only ever
decrypted in memory at scan time.

---

## Security model

- **Field-level encryption.** Stored secrets (registry creds, git tokens, OIDC
  client secret, notification secrets, TOTP MFA secrets, and the scheduled-backup
  passphrase) are encrypted with **AES-256-GCM** (random per-secret nonce,
  HKDF-derived key, key-version tagged). The database never holds plaintext
  secrets.
- **Master key via secret file.** The key comes from a Docker secret file
  (`SCRYE_APP_SECRET_KEY_FILE`) — never an env var or image layer.
- **Authentication.** Local accounts use argon2id with revocable server-side
  sessions; generic **OIDC** (Authlib, PKCE + nonce, ID-token signature/claim
  validation) runs alongside local auth; optional **TOTP MFA** adds a second
  factor. **API tokens** are bearer credentials stored only as a SHA-256 hash,
  scoped to a role no higher than their owner's; token auth is exempt from CSRF
  (bearer headers are not sent cross-site) while cookie sessions require a CSRF
  token on every state-changing request.
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
- **Writable scratch under a read-only root.** The only writable paths are the
  `/data` and `/cache` volumes and a small `/tmp` tmpfs. The tmpfs is mounted
  **owned by the container's uid** (`uid=1000,gid=1000`) — a bare tmpfs is
  root-owned, so a non-root process could not write to it — and holds only the
  in-memory credential files. Every scanner invocation (image/repo/filesystem/
  SBOM scans **and** the About-tab version / DB-status probes) is pointed at the
  persistent `/cache` volume through environment variables — `TRIVY_CACHE_DIR`,
  `GRYPE_DB_CACHE_DIR`, `XDG_CACHE_HOME`/`HOME`, and `TMPDIR` — so nothing ever
  falls back to the read-only default `$HOME/.cache` (`/app/.cache`) or overflows
  the tmpfs. The vulnerability DB therefore downloads **once** and persists
  across restarts (the volume outlives the container) instead of re-downloading
  into a transient or broken location every scan.
- **Docker socket residual risk.** "Scan running images" uses a **read-only**
  `docker-socket-proxy` restricted to read endpoints (`POST=0`). The Scrye app
  **never** mounts `/var/run/docker.sock`. The proxy is the only place the
  socket is mounted (read-only); anyone who can reach it can _enumerate_ images
  and containers, so enable that profile deliberately and keep it on the
  internal network.
- **Trusted reverse-proxy hops (`SCRYE_FORWARDED_ALLOW_IPS` — required per
  deployment).** Scrye honors `X-Forwarded-For` (via uvicorn `--proxy-headers`)
  so the auth rate limiter and audit log see the **real** client IP. The
  client-selection logic is **proxy-agnostic** — it works identically behind any
  proxy that sets/appends `X-Forwarded-For` (Caddy, **nginx**, **Traefik**,
  HAProxy, …). uvicorn trusts the header only when the connecting peer is in
  `SCRYE_FORWARDED_ALLOW_IPS`, then takes the first address that is **not** in
  that set (the client the proxy appended), discarding any spoofed leftmost
  entry.

  **`SCRYE_FORWARDED_ALLOW_IPS` must be set to the IP/CIDR your reverse proxy
  actually connects from.** The shipped default (`172.16.0.0/12`) assumes Caddy
  running as a Docker container on the default bridge network. If you use nginx,
  Traefik, a host-networked proxy, or any other topology, you must set this to
  match your actual setup — otherwise the rate-limiter and audit-log fix will not
  take effect correctly. It is deployment-specific; nothing else in the code
  assumes Caddy or that subnet.

  **Fail-safe on mismatch.** If the configured value does not include the real
  connecting peer, the app **fails safe**: `X-Forwarded-For` is ignored entirely
  and the raw proxy IP is used, so a client can never spoof its address — the
  only cost is that per-client IPs (and thus per-client rate-limit buckets and
  accurate audit IPs) do not take effect until you set it correctly. Conversely,
  **never set it to `*`** and never include the client LAN range — that trusts
  every upstream hop and re-opens the spoofing hole.

  Examples:
  - Caddy as a Docker container (default): `SCRYE_FORWARDED_ALLOW_IPS=172.16.0.0/12`
    (or tighten to Caddy's exact container IP).
  - Host-networked nginx (proxying to Scrye's published `127.0.0.1:8089`):
    `SCRYE_FORWARDED_ALLOW_IPS=127.0.0.1`.
  - Traefik in its own Docker network (e.g. subnet `10.89.0.0/24`):
    `SCRYE_FORWARDED_ALLOW_IPS=10.89.0.0/24` (or Traefik's exact container IP).
- **OIDC login-CSRF binding.** Each OIDC login is bound to the browser that
  started it: a random token is stored in an `HttpOnly` cookie (a `__Host-`
  prefixed, host-locked, `Secure` cookie in production, so no sibling subdomain
  under a shared parent domain can plant it) and only its hash is kept on the
  flow row, so an authorization-code flow cannot be completed in a different
  browser (defeating login-CSRF / session fixation).
- **MFA scope for OIDC (accepted limitation).** The mandatory-MFA policy
  (`required_all` / `required_admin`) is enforced on **local** password login.
  **OIDC logins delegate the second factor to the identity provider** — Scrye has
  no local TOTP challenge in the OIDC handshake and provisioned OIDC accounts
  carry no usable local password. If you require MFA for OIDC users, enforce it
  at the IdP (e.g. Pocket ID). When group→role mapping is configured, an OIDC
  login re-applies it, but an **absent** groups claim (e.g. an IdP that ships
  groups only via UserInfo) preserves the user's current role rather than
  demoting them, and an OIDC sync can never remove the last admin.

---

## Backup & restore

Backups are **portable, passphrase-protected bundles** (a logical database dump
plus a manifest with the app/schema version). Because secrets are encrypted under
the host master key (which does not travel), on backup each secret is
**re-wrapped** under a user-supplied passphrase (a scrypt-derived AES-256-GCM
key), and the whole bundle is encrypted under that passphrase too; on restore you
supply the passphrase and Scrye **re-encrypts** the secrets under the new host's
master key. A restore therefore works on a fresh host with only the passphrase —
no master-key transplant.

Manage backups under **Settings → Backup & restore** (admin): create a bundle,
download or delete stored bundles, restore from an uploaded bundle (a
**destructive** action that replaces all data and signs you out), and configure
**scheduled backups** — an interval, a retention count, and an encrypted
passphrase the in-process scheduler uses to produce bundles unattended. Restore
in v1 requires the bundle's schema version to match the running installation, and
is **refused while a scan is queued or running** (finish or cancel it first).

**What a bundle contains.** The bundle is a logical dump of the database —
scan history, normalized findings, users, settings, and (re-wrapped) secrets.
It does **not** carry the **raw scanner-output artifact files** (the raw Trivy/
Grype JSON and generated SBOMs), which live on disk under `SCRYE_ARTIFACTS_DIR`
and are re-created by re-running a scan; their bookkeeping rows are therefore
omitted from the bundle and cleared on restore, so a restored database never
points at missing files. Copy `SCRYE_ARTIFACTS_DIR` separately if you need the
raw outputs preserved across a move.

**Size note.** A bundle is assembled and encrypted in memory in a single pass,
so back up and restore on an instance with a very large findings table (roughly
hundreds of thousands of rows and up) need container memory headroom
proportional to the dump size; a warning is logged past that threshold.

---

## Monitoring

Scrye exposes Prometheus metrics at **`/metrics`** in the text exposition format
— `scrye_scans_total{status=…}`, `scrye_open_findings{severity=critical|high}`,
`scrye_scan_schedules{state=…}`, `scrye_build_info`, and account/token/channel
counts. Because these reveal scan volume and vulnerability posture, the endpoint
is **authenticated** (viewer role): configure a Prometheus scrape with a personal
**API token** as a bearer credential rather than exposing it publicly.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: scrye
    metrics_path: /metrics
    authorization: { credentials: '<a Scrye API token>' }
    static_configs: [{ targets: ['scrye.internal:8089'] }]
```

---

## Building the image

The image is **built locally** — there is no published registry image (a locked
decision for v1). A single-arch build for the host you are on:

```bash
docker build -f docker/Dockerfile -t scrye:0.1.0 .
```

For a **multi-arch** image (so it runs on both `linux/amd64` and `linux/arm64`),
use Buildx. The `docker/Dockerfile` is arch-aware and pulls the correct
`trivy`/`grype`/`syft` binaries per target platform:

```bash
docker buildx create --use --name scrye-builder   # once
docker buildx build -f docker/Dockerfile \
  --platform linux/amd64,linux/arm64 \
  -t scrye:0.1.0 .
```

CI builds both architectures on every PR to catch arch-specific breakage, and
**dogfoods** the result: it scans Scrye's own image with Trivy and Grype and
fails on any fixable HIGH/CRITICAL finding in Scrye's own attack surface — its
base-image OS packages (including the `git` runtime dependency), Python and JS
dependencies, and application code (the whole image filesystem is scanned, so
the bundled `THIRD_PARTY_LICENSES/` directory is covered too). No publish/registry
step runs in CI.

The **bundled `trivy`/`grype`/`syft` binaries** are the one thing **excluded from
the gate** (they still appear in the informational scan report): they are
unmodified upstream Go binaries Scrye ships as-is and cannot rebuild, so CVEs in
their embedded Go modules or Go standard library track upstream's release cadence.
Keeping the pinned scanner versions current is how those are addressed.

Everything else — the base image (including the CPython interpreter), OS packages
(including `git`), Python and JS dependencies, and the application code — is gated
as above.

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
- **Phase 2 — Core scanning** ✅ — Trivy image + Grype image, async worker,
  normalized findings, scan detail + raw artifacts.
- **Phase 3 — Targets & registries** ✅ — Trivy repo + git creds; Grype
  filesystem/SBOM; Syft SBOM generation; registry credentials with transient
  tmpfs docker-config materialization; Docker-environment enumeration.
- **Phase 4 — History, reports & exports** ✅ — history, filters, saved presets,
  scan diff/trend, CSV/Markdown/JSON exports.
- **Phase 5 — Settings, OIDC & backup/restore** ✅ — full settings, OIDC + MFA,
  API tokens, notification channels, backup/restore, scheduled backups.
- **Phase 6 — Dashboard & automation** ✅ _(this release)_ — dashboard,
  notification dispatch, scheduled/recurring scans, Trivy VEX & ignore-rule
  management, `/metrics`, result retention, multi-arch build, self-scanning CI.

**Deferred (not in v1):** arq/Redis scale-out, SQLCipher full-DB encryption,
container-registry publishing.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for local development setup, project
layout, coding standards, testing, the PR process, and how to report security
issues privately.

## License

[MIT](./LICENSE).
