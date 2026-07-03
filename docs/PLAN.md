# Scrye — Build Plan

> **Scrye** — a unified, self-hosted web UI for the **Trivy** and **Grype** scanners.
> ("Scry": to perceive hidden things, fused with "scan.")
> **Audience:** Claude Code. This is the build specification. `CLAUDE.md` is the condensed
> operating contract; this document is the detailed reference. Execute in the order given by
> "Implementation Roadmap" (§12).

---

## 0. Locked Decisions

These were decided and are not open for re-litigation during the build:

1. **Name:** Scrye.
2. **Job model:** single-container **in-process async worker** (DB-backed `scans` table +
   concurrency semaphore). Redis/arq is **not** used in v1; design the worker behind a small
   interface so it *could* be swapped later, but do not build it now.
3. **"Scan running images" (Docker environment):** **included in v1**, via a read-only
   `docker-socket-proxy` (never a raw socket mount in the app).
4. **Secrets at rest:** **application-layer field encryption (AES-256-GCM envelope)** is the
   default and is required. Full-DB SQLCipher encryption is **deferred** (optional future
   hardening, not in v1).
5. **Frontend:** **Mantine v7**.
6. **Distribution:** Docker image is **built locally only** for now. **Do not** add Docker Hub
   (or any registry) publishing — no registry slot available yet. The image must build cleanly
   and run locally; publishing is a later concern.

---

## 1. Overview & Goals

A clean, modern, professional, browser-based application providing a unified UI over two
open-source scanners:

- **Trivy** (Aqua Security) — OS packages & dependencies (SBOM), CVEs, IaC misconfigurations,
  secrets, and software licenses.
- **Grype** (Anchore) — vulnerability scanning of images, filesystems, and SBOMs.

Scrye must be self-hostable, ship as a (locally built) Docker image, store all secrets securely,
support local + OIDC auth, expose a full settings area, support backup/restore, keep a filterable
scan history, export results to CSV/Markdown/JSON, and include complete project documentation
(README + CONTRIBUTING).

### Non-negotiable principles
1. **Security-first.** No plaintext secrets anywhere — DB, logs, API responses, or image layers.
2. **Self-host friendly.** Default deployment is one container (plus optional sidecars).
3. **Component library, not hand-rolled UI.** Mantine v7.
4. **Teal-primary theming** with first-class light and dark modes.
5. **Scanner-faithful.** Orchestrate the official binaries; parse their JSON output. Don't
   reimplement scanner logic.

---

## 2. Tech Stack

| Layer | Choice | Notes |
|-------|--------|-------|
| Frontend | **React 18 + TypeScript + Vite** | |
| Component library | **Mantine v7** (+ `mantine-datatable`, `@mantine/form`, `@mantine/notifications`, `@mantine/modals`) | Native light/dark, trivial teal `primaryColor`, rich tables/forms. |
| Backend | **Python 3.12 + FastAPI + Pydantic v2** | Consistent with the Lacunarr stack; strong async subprocess handling. |
| ORM / migrations | **SQLAlchemy 2.0 + Alembic** | Typed models; migrations gate backup/restore. |
| Database | **SQLite** | Secrets field-encrypted at the app layer (§6). |
| Auth | **Authlib** (OIDC) + **argon2-cffi** (local) + **pyotp** (optional TOTP MFA) | Generic OIDC → Pocket ID (RS256). |
| Job execution | **In-process async worker** + `scans` table + concurrency semaphore | Locked (§0.2). |
| Scanners | Bundled `trivy` + `grype` + `syft` binaries via `asyncio.create_subprocess_exec`; optional **Trivy server** sidecar for shared vuln-DB cache | |
| Reverse proxy / TLS | Existing **Caddy + acme.sh** wildcard (`*.home.platform934.dev`) | App serves plain HTTP internally. |

### Teal theme
```ts
// theme.ts
import { createTheme } from '@mantine/core';
export const theme = createTheme({
  primaryColor: 'teal',
  primaryShade: { light: 6, dark: 8 },
  defaultRadius: 'md',
  fontFamily: 'Inter, system-ui, sans-serif',
});
// MantineProvider defaultColorScheme="auto" + a color-scheme manager + header toggle.
```

---

## 3. High-Level Architecture

```
                         ┌───────────────────────────────────────────────┐
   Browser ── HTTPS ──▶  │  Caddy (existing reverse proxy + TLS)          │
                         └───────────────────────────────────────────────┘
                                            │ HTTP (loopback / internal net)
                                            ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │  Scrye container (single image)                                    │
        │  ┌────────────────────┐   ┌──────────────────────────────────┐    │
        │  │ FastAPI API + SPA  │   │ In-process async scan worker     │    │
        │  │ - REST endpoints   │◀─▶│ - polls `scans` table            │    │
        │  │ - serves React build│  │ - runs trivy/grype subprocesses  │    │
        │  │ - auth/session     │   │ - parses JSON → findings         │    │
        │  └────────┬───────────┘   └───────────────┬──────────────────┘    │
        │           ▼                                ▼                      │
        │   ┌───────────────┐              ┌──────────────────┐            │
        │   │ SQLite (/data)│              │ trivy/grype/syft │            │
        │   │ field-encrypted│             │ binaries + DBs   │            │
        │   │   secrets     │              │ (/cache)         │            │
        │   └───────────────┘              └──────────────────┘            │
        └──────────────────────────────────────────────────────────────────┘
              │ optional sidecars (compose):
              ├── trivy-server        (shared vuln DB cache)
              └── docker-socket-proxy (read-only) ── "scan running images" (v1)
```

### Docker-environment access (v1 feature)
Enumerating images from a Docker daemon needs Docker API access. The app **must not** mount
`/var/run/docker.sock` (CIS 5.21/5.22). Use **Tecnativa `docker-socket-proxy`** restricted to
read endpoints (`IMAGES=1`, `CONTAINERS=1`, `INFO=1`, `POST=0`, everything else `0`), on the
internal network. Scrye talks to the proxy over HTTP and can only *list* — never control — Docker.
Surface the residual risk in the UI when a Docker environment is enabled, and require an explicit
risk acknowledgment.

---

## 4. Feature Breakdown

### 4.1 Trivy scanning
**Targets**
1. **Single container image** — registry ref or uploaded tar → `trivy image`.
2. **Images running in a Docker environment** — enumerate via socket proxy, multi-select, scan
   each → `trivy image`.
3. **Git repository (public/private)** — HTTPS URL (+ optional branch/ref); private uses stored
   git credential → `trivy repo <url>`.

**Scanners (all selectable; default all)**
- Vulns/CVEs (`--scanners vuln`)
- SBOM (OS packages + dependencies) generated alongside (`--format cyclonedx`/`spdx-json`), stored
  as an artifact.
- IaC misconfig (`--scanners misconfig`)
- Secrets (`--scanners secret`)
- Licenses (`--scanners license`)

Example (image, all scanners):
```
trivy image --quiet --format json \
  --scanners vuln,misconfig,secret,license \
  --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL <image-ref>
```
Per-scan UI options: scanner selection, severity filter, `--ignore-unfixed`, VEX policy,
`.trivyignore` rules, repo branch/ref, SBOM format. Use the **Trivy server** sidecar
(`--server http://trivy-server:4954`) for a shared vuln-DB cache.

### 4.2 Grype scanning (vulnerabilities only — Grype's scope)
Per Anchore docs, Grype scans **container images, directories/filesystems, and existing SBOMs**.
There is **no Grype server mode** — run the binary per scan.

**Targets**
1. Container image (registry ref or tar).
2. Filesystem/directory (uploaded archive or mounted path).
3. Existing SBOM (feed the Syft-generated SBOM directly: `grype sbom:./sbom.json`).

```
grype <image-ref | dir:/path | sbom:./sbom.json> -o json
```

**Private registries (per Anchore docs):** Grype authenticates via a Docker config file. At scan
time, materialize a transient `config.json` from the stored (encrypted) registry credential into
**tmpfs**, set `DOCKER_CONFIG=/that/dir`, run, then shred it. Support:
- Static creds/tokens → `auths` block.
- Credential helpers (ECR/GCR/ACR) → `credHelpers` block (helper binaries present only if that
  registry type is enabled).

**Grype DB:** scheduled `grype db update`; support offline/air-gapped DB import.

> **Syft is bundled.** Generate one SBOM per artifact with Syft, hand it to both Grype and store
> it as a downloadable artifact. One cataloging pass, consistent results.

### 4.3 Results, normalization & reports
- Persist **raw scanner JSON** as an artifact (source of truth).
- Parse into a **normalized findings model** (§7) so Trivy and Grype render in one table.
- Aggregate severity counts per scan.
- **Exports — CSV / Markdown / JSON**, per-scan and for filtered history sets:
  - JSON — normalized findings + metadata (+ option to download raw scanner JSON).
  - CSV — one row per finding.
  - Markdown — readable report (summary + findings grouped by severity) for tickets/Matrix/email.

### 4.4 Scan history
Filterable table (mantine-datatable): scanner, target type, target name (full-text), status,
date range, initiator, highest severity, severity-threshold presence, tags. Sortable, paginated,
saved filter presets. Row → scan detail (findings + exports + raw artifacts).
**Scan diff:** compare two scans of the same target → new vs fixed vulnerabilities over time.

### 4.5 Settings (full section)
General · Authentication (local toggle, OIDC config, optional MFA) · Users & Roles (RBAC) ·
Scanners (versions, Trivy server URL, DB schedule, offline DB import, default options/thresholds,
`.trivyignore`/Grype ignore rules) · Registries (encrypted creds + test) · Git providers
(encrypted) · Docker environments (proxy config + risk ack) · Notifications (webhook/Discord/SMTP/
Matrix) · API tokens · Backup & restore · About/health.

### 4.6 Dashboard
Aggregate widgets: total scans, scans over time, top vulnerable targets, open critical/high,
scanner-DB freshness, recent scans, failed-scan alerts.

---

## 5. Auth & Authorization
- **Local:** argon2id password hashing; server-side sessions in SQLite (revocable); `Secure`,
  `HttpOnly`, `SameSite=Lax` cookies; optional TOTP MFA.
- **OIDC:** generic via Authlib → Pocket ID (`https://pocket-id.home.platform934.dev`, RS256).
  Configurable issuer/client/secret/scope/claim mapping. Local + OIDC concurrently.
- **Bootstrap:** first login → `admin`; later OIDC users default `viewer` (configurable
  auto-provision).
- **RBAC:** `viewer` (read/export), `operator` (+ launch scans, own API tokens), `admin`
  (+ settings/users/credentials/backup).
- CSRF on state-changing endpoints; rate limiting on auth; audit log of security-relevant actions.

---

## 6. Secrets storage (required)
**Threat model:** DB read access must not reveal registry passwords, git tokens, OIDC client
secret, or API tokens.

- **Master key** from a **Docker secret file** (`APP_SECRET_KEY_FILE`), never an env var or image
  layer.
- Each secret encrypted with **AES-256-GCM**, random per-secret nonce, key derived via HKDF; store
  `ciphertext||nonce||tag` + key-version.
- Secrets are **write-only** over the API; reads return a mask (`••••`) + "last updated".
- Decrypt **only at scan time**, in memory, to build transient credential files in **tmpfs**;
  shred after the subprocess exits.
- Logging filter redacts known secret fields. Support **key rotation** (re-encrypt under new
  version).
- SQLCipher (full-DB-at-rest) is **deferred** — leave a clean seam to add it later, but do not
  implement in v1.

---

## 7. Data Model (SQLite / SQLAlchemy)
`users`, `oidc_identities`, `sessions`, `api_tokens`, `registries`, `git_credentials`,
`docker_environments`, `scan_profiles`, `scans`, `findings`, `artifacts`, `settings`, `backups`,
`audit_log`, `schedules` (optional). Column sketch is in §7 of the prior detailed notes; key
indices: `findings(scan_id, severity, vuln_id)`, `scans(scanner, status, started_at)`. Secret
columns store ciphertext only.

---

## 8. Backup & Restore
**Bundle** = SQLite dump + app/schema version + manifest (checksums) + optionally stored artifacts.

**Portable secrets:** secrets are master-key-encrypted, which doesn't travel in the bundle. So:
1. On backup, **re-wrap** each secret under a **user-supplied backup passphrase** (AES-256-GCM,
   scrypt/PBKDF2-derived).
2. Encrypt the whole bundle with that passphrase.
3. On restore, prompt for passphrase → decrypt → **re-encrypt** secrets under the current host's
   master key.

A restore works on a fresh host with only the passphrase — no master-key transplant.
**Restore flow:** upload → validate version → migrate if older → confirm (destructive) → import →
re-key → audit-log. **Scheduled backups:** optional cron to a mounted path (e.g., the PR4100 NAS)
with retention.

---

## 9. Deployment

### 9.1 Image
Multi-stage build, CIS-aligned:
- Stage 1: build the React/Vite frontend.
- Stage 2: install Python deps.
- Final: slim Python base (pinned by digest), copy in **checksum-verified** `trivy`/`grype`/`syft`
  binaries (never `curl | bash`), copy SPA, create non-root user, `HEALTHCHECK`, run non-root.
- **Multi-arch** build (`linux/amd64` + `linux/arm64`) so it runs on docker-host and the Mac Studio.
- **No registry publishing.** Build locally (`docker build -t scrye:0.1.0 .` /
  `docker buildx` for multi-arch). Tag locally as `scrye:<version>`. Do **not** add Docker Hub
  steps, CI publish jobs, or `securedbytyler/...` references.

Dockerfile must: pin base by digest, non-root `USER`, no secrets in layers, comprehensive
`.dockerignore`, `COPY` not `ADD`, `HEALTHCHECK`, combined `RUN apt-get update && install` + clean.

### 9.2 Compose (hardened, CIS-aligned)
```yaml
services:
  scrye:
    image: scrye:0.1.0           # locally built; no registry
    user: "1000:1000"
    read_only: true
    security_opt: [ "no-new-privileges:true" ]
    cap_drop: [ "ALL" ]
    networks: [ scrye_net ]
    ports:
      - "127.0.0.1:8089:8089"    # behind Caddy; never 0.0.0.0
    environment:
      - APP_SECRET_KEY_FILE=/run/secrets/app_secret_key
      - DATABASE_PATH=/data/scrye.db
      - TRIVY_SERVER_URL=http://trivy-server:4954
      - DOCKER_PROXY_URL=http://docker-socket-proxy:2375
    secrets: [ app_secret_key ]
    volumes:
      - scrye_data:/data
      - scrye_cache:/cache
    tmpfs:
      - /tmp:size=200m,mode=1700  # transient registry/git cred files
    deploy:
      resources:
        limits: { cpus: "2.0", memory: 2G }
        reservations: { memory: 256M }
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:8089/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
    logging: { driver: json-file, options: { max-size: "10m", max-file: "3" } }

  trivy-server:                   # optional: shared vuln DB cache
    image: aquasec/trivy:0.66.0@sha256:<digest>
    command: ["server", "--listen", "0.0.0.0:4954"]
    networks: [ scrye_net ]
    read_only: true
    security_opt: [ "no-new-privileges:true" ]
    cap_drop: [ "ALL" ]
    volumes: [ trivy_cache:/root/.cache/trivy ]
    tmpfs: [ "/tmp" ]
    deploy: { resources: { limits: { cpus: "1.0", memory: 1G } } }
    restart: unless-stopped
    logging: { driver: json-file, options: { max-size: "10m", max-file: "3" } }

  docker-socket-proxy:            # v1: read-only, "scan running images"
    image: tecnativa/docker-socket-proxy:0.3.0@sha256:<digest>
    environment:
      - IMAGES=1
      - CONTAINERS=1
      - INFO=1
      - POST=0
    networks: [ scrye_net ]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro   # documented residual risk
    read_only: true
    security_opt: [ "no-new-privileges:true" ]
    cap_drop: [ "ALL" ]
    restart: unless-stopped
    logging: { driver: json-file, options: { max-size: "10m", max-file: "3" } }

networks:
  scrye_net: { driver: bridge }

volumes:
  scrye_data:
  scrye_cache:
  trivy_cache:

secrets:
  app_secret_key:
    file: ./secrets/app_secret_key   # not committed; outside the image
```

### 9.3 Tyler's environment
- Deploy as a **DockHand** stack on `docker-host` (`10.1.10.7`); env vars set in the DockHand stack
  editor (no `.env` on disk). The **app secret key** is a Docker secret file, not an env var.
- Front with **Caddy** at `scrye.home.platform934.dev`, TLS via acme.sh wildcard.
- Persistent paths under `/mnt/appdata/scrye`.
- OIDC against Pocket ID.

---

## 10. Required Project Documentation

These are **build deliverables**, not optional.

### 10.1 `README.md` (full)
Must include, at minimum:
- **Project name + tagline** and a one-paragraph description of what Scrye is and the problem it
  solves (unified UI over Trivy + Grype).
- **Badges** (build status placeholder, license).
- **Screenshots / GIF placeholders** (dashboard, new scan, results, history) with a note to add
  real captures.
- **Features** — full bulleted breakdown: Trivy targets & scanner matrix, Grype targets, private
  registry support, exports (CSV/MD/JSON), history & diff, dashboard, RBAC, OIDC + local auth,
  secrets handling, backup/restore, scheduled scans, notifications, API tokens.
- **Integrations** — Trivy, Grype, Syft, OIDC (Pocket ID and generic), Docker (via read-only
  socket proxy), private registries (incl. ECR/GCR/ACR helpers), notification channels.
- **Architecture** — the diagram from §3 and a short component description.
- **Requirements** — Docker/Compose versions, resource guidance, optional sidecars.
- **Quick start** — clone, generate `app_secret_key`, build image, `docker compose up`, first-run
  admin bootstrap, where data lives.
- **Configuration** — full table of environment variables and settings, the secret-key mechanism,
  Trivy-server and socket-proxy toggles, OIDC setup steps.
- **Usage** — running each scan type; reading/exporting results; managing credentials safely.
- **Security model** — how secrets are stored (field-level AES-GCM, master key via secret file,
  write-only API, tmpfs at scan time), the socket-proxy risk note, CIS-aligned container posture.
- **Backup & restore** — how it works and the passphrase/portability behavior.
- **Roadmap** — deferred items (arq/Redis scale-out, SQLCipher, registry publishing).
- **Contributing** — link to `CONTRIBUTING.md`.
- **License** — link to `LICENSE`.

### 10.2 `CONTRIBUTING.md` (full)
Must include:
- **Code of conduct** pointer (or a short statement).
- **Local development environment** — step-by-step:
  - Prereqs (Python 3.12, Node 20+, Docker, `trivy`/`grype`/`syft` for native runs).
  - Backend: create venv, install deps, configure a local `app_secret_key`, run Alembic
    migrations, start FastAPI with reload.
  - Frontend: install deps, start the Vite dev server, proxy config to the API.
  - Running with Compose for an integrated environment.
  - Seeding a first admin user.
- **Project layout** — quick map of the repo.
- **Coding standards** — Python (ruff/black, type hints, docstrings, no hardcoded secrets),
  TypeScript (ESLint/Prettier), commit style (Conventional Commits), branch naming.
- **Testing** — how to run `pytest` and frontend tests; expectations for new code.
- **Pull request process** — fork/branch, sign-off if desired, PR checklist (tests pass, lint
  clean, docs updated, no secrets committed).
- **Reporting security issues** — a private disclosure note (do not open public issues for vulns).

A `LICENSE` file (MIT recommended) should also be created.

---

## 11. Repository Structure
```
scrye/
├── CLAUDE.md
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── .gitignore
├── .env.example
├── docs/
│   └── PLAN.md                 # this document
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/                # auth, scans, registries, git, docker_envs, settings, backup, tokens
│   │   ├── core/               # config, security (crypto/envelope), logging, deps, rbac
│   │   ├── db/                 # models, session, alembic
│   │   ├── scanners/           # base.py, trivy.py, grype.py, syft.py
│   │   ├── workers/            # in-process async scan worker
│   │   ├── reports/            # csv / markdown / json exporters
│   │   ├── backup/             # bundle build/restore + secret re-wrap
│   │   └── auth/               # local + OIDC + sessions + MFA
│   ├── alembic/
│   ├── tests/
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── theme.ts
│   │   ├── pages/              # dashboard, scan/new, history, scan/[id], settings/*
│   │   ├── components/
│   │   ├── api/
│   │   └── auth/
│   ├── vite.config.ts
│   └── package.json
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
└── .github/workflows/ci.yml    # build + lint + test + self-scan; NO publish job
```

---

## 12. Implementation Roadmap (execution order)

**Phase 0 — Scaffold**
Repo structure; FastAPI serving a Vite/Mantine SPA; SQLite + SQLAlchemy + Alembic baseline;
`/healthz`; teal theme + light/dark toggle; Dockerfile (non-root, checksum-verified
`trivy`/`grype`/`syft`); **initial `README.md`, `CONTRIBUTING.md`, `LICENSE`, `.gitignore`**.

**Phase 1 — Auth & secrets foundation**
Local auth (argon2id) + sessions + RBAC + first-user bootstrap; envelope-encryption module +
master key from secret file; write-only secret API + log redaction; audit log.

**Phase 2 — Core scanning (Trivy image + Grype image)**
Scan model + in-process async worker + concurrency control; Trivy `image` (all scanners) and Grype
`image`; JSON → normalized findings; scan detail page + raw artifact storage.

**Phase 3 — Targets & registries**
Trivy `repo` (public/private + git creds); Grype filesystem/SBOM; Syft SBOM generation; registry
credential management + transient docker-config materialization; **Docker-environment enumeration
via socket proxy**.

**Phase 4 — History, reports, exports**
History view + full filters + presets; scan diff/trend; CSV/Markdown/JSON exporters.

**Phase 5 — Settings, OIDC, backup/restore**
Full settings section; OIDC (Pocket ID) + optional MFA; backup/restore with passphrase re-wrap;
scheduled backups.

**Phase 6 — Polish & extras**
Dashboard widgets; notifications; scheduled scans; VEX/ignore management; API tokens; `/metrics`;
retention policy; multi-arch build; CI that self-scans. **Finalize README/CONTRIBUTING** to match
the shipped app.

---

## 13. Future / Deferred (do not build in v1)
- arq + Redis scale-out worker.
- SQLCipher full-DB-at-rest encryption.
- Container registry publishing (Docker Hub or other).

---

## 14. Deviations from this plan

Running log of anywhere the implementation diverged from what's written above. Add a dated entry
at the time the deviation is made — don't batch these up for later. Format:

```
### YYYY-MM-DD — Phase PX — <short title>
**What changed:** <the actual deviation>
**Why:** <reason — constraint discovered, better approach found, plan ambiguity resolved, etc.>
**Plan section affected:** <§ reference>
```

### 2026-06-30 — Phase 0 — Scanner versions bumped to current releases
**What changed:** Bundled scanner versions pinned to the current releases —
Trivy `0.71.2`, Grype `0.115.0`, Syft `1.46.0` — in `docker/Dockerfile`. The
optional `trivy-server` sidecar in `docker/docker-compose.yml` is pinned to the
matching `aquasec/trivy:0.71.2` (digest-locked) rather than the `0.66.0` shown
in the plan's Compose example.
**Why:** The plan's `0.66.0` was an illustrative example; CLAUDE.md
§ Dependency hygiene requires pinning to current, actively-maintained versions
with no known vulnerabilities, and the bundled Trivy binary and the trivy-server
image should share a version.
**Plan section affected:** §9.1, §9.2.

### 2026-06-30 — Phase 0 — Optional sidecars gated behind Compose profiles
**What changed:** The `trivy-server` and `docker-socket-proxy` services in
`docker/docker-compose.yml` are placed behind Compose `profiles`
(`trivy-server`, `docker-env`) so the default `docker compose up` starts only
the Scrye app. Both sidecar images are pinned by resolved multi-arch digest.
**Why:** Phase 0 only needs the app and a healthy `/healthz`; the sidecars are
consumed by later phases (Trivy server cache in Phase 2+, Docker-environment
enumeration in Phase 3). Gating them keeps the default bring-up minimal and
avoids mounting the Docker socket until that feature is actually built, while
leaving the hardened definitions ready to enable.
**Plan section affected:** §9.2.

### 2026-07-03 — Phase P1 — First-admin bootstrap via explicit setup endpoint
**What changed:** §5 says "Bootstrap: first login → `admin`." Implemented as an
explicit `POST /api/auth/setup` endpoint plus a first-run setup screen in the
SPA: it creates the first account as `admin` and logs it in, works only while
the users table is empty, and permanently 409s afterwards.
**Why:** With local-only auth (OIDC arrives in Phase 5) there are no
credentials to "log in" with before any account exists, so "first login →
admin" cannot be taken literally. A self-disabling setup flow is the standard,
least-surprising materialization and keeps the bootstrap auditable
(`auth.setup` audit action).
**Plan section affected:** §5 (Bootstrap).

### 2026-07-03 — Phase P1 — Master key file supports optional multi-version format
**What changed:** The Docker secret file referenced by `APP_SECRET_KEY_FILE`
may now contain either a single base64 key (treated as version 1 — the
documented default) or one `v<N>:<base64>` entry per line. New secrets encrypt
under the highest version; older versions stay available for decryption and
for `SecretCipher.rotate()` re-encryption.
**Why:** §6 requires "support key rotation (re-encrypt under new version)" but
doesn't define where old and new keys live during a rotation. Encoding
versions in the existing key file keeps the locked "master key from a Docker
secret file" rule intact (no second secret, no env vars) while making rotation
actually operable: add `v2`, restart, re-encrypt, then drop `v1`.
**Plan section affected:** §6 (Secrets storage).

### 2026-06-30 — Phase 0 — Branch name `phase/P0`
**What changed:** Phase 0 work is developed on branch `phase/P0`.
**Why:** Matches the repo convention in CLAUDE.md § Git & PR conventions
(`phase/PX`), per explicit instruction in the build session. (Noted for the
record; the session harness had suggested a different default branch name.)
**Plan section affected:** §12 (process, not output).

### 2026-07-03 — Phase P2 — Raw artifact bytes stored on the filesystem
**What changed:** The `artifacts` table stores metadata + a SHA-256 checksum +
a path relative to a configurable artifacts directory (`SCRYE_ARTIFACTS_DIR`,
default `/data/artifacts`); the raw scanner JSON bytes live on disk under that
directory (one subdirectory per scan), not as a BLOB column in SQLite.
**Why:** §4.3/§7 require persisting the raw scanner JSON as the source-of-truth
artifact but don't specify where the bytes live. Keeping large blobs out of
SQLite keeps the database small, backups cheap, and downloads streamable, while
the checksum still lets restore/backup verify integrity. `/data` is already the
persistent volume in the Compose definition, so no new mount is needed.
**Plan section affected:** §4.3, §7.

### 2026-07-03 — Phase P2 — Frontend routing via `react-router-dom` v7
**What changed:** Added `react-router-dom` (pinned `7.18.1`) for SPA routing —
the plan's tech stack (§2) lists Mantine helpers but no router. Chose v7 rather
than v6 because every 6.x release carries known advisories (`npm audit`), and
CLAUDE.md § Dependency hygiene requires versions with no known vulnerabilities.
**Why:** The scan detail page needs client-side routing (list → detail → new).
Router choice is a routine implementation detail under CLAUDE.md § When to ask
vs. decide; logged here for the record and to explain the v7 pin.
**Plan section affected:** §2 (Tech stack).

### 2026-07-03 — Phase P2 — Scan views use Mantine `Table`, not `mantine-datatable`
**What changed:** The scans list and findings table use the base Mantine
`Table` component instead of `mantine-datatable` (listed in §2).
**Why:** Phase 2 needs only a plain, sortless table; `mantine-datatable`'s
value (sortable/paginated/filterable history with saved presets) belongs to the
Phase 4 history view, where it will be introduced. Deferring the dependency
keeps the bundle smaller until the feature that needs it lands.
**Plan section affected:** §2, §4.4.

### 2026-07-03 — Phase P2 — Scan cancellation limited to queued scans
**What changed:** `POST /api/scans/{id}/cancel` cancels only scans still in the
`queued` state; a scan already `running` cannot be canceled.
**Why:** The plan calls for "concurrency control" but does not specify
cancellation semantics. The in-process worker (locked §0.2) has no channel to
interrupt a live scanner subprocess, so cancelling a running scan cannot be done
safely in v1; queued cancellation is the useful, well-defined subset.
**Plan section affected:** §12 (Phase 2 scope), §0.2.

### 2026-07-03 — Phase P3 — Filesystem scans gated behind an allowlist
**What changed:** Filesystem (Grype `dir:`) scanning is disabled unless the admin
sets `SCRYE_FILESYSTEM_SCAN_ROOTS` to one or more absolute paths; a scan target
must resolve to a path within an allowed root or it is rejected (at create time
and again in the worker).
**Why:** §4.2 lists "filesystem/directory (mounted path)" as a target but does
not constrain which paths are scannable. Allowing arbitrary absolute paths would
let an operator read sensitive host files (the SQLite DB, the master-key file) as
scan output. Restricting to configured roots (empty = feature off) is a
security-model hardening consistent with the plan's security-first principle. The
new non-sensitive setting is emitted in `.env.example`.
**Plan section affected:** §4.2 (Grype filesystem target).

### 2026-07-03 — Phase P3 — Git authentication mechanism per provider
**What changed:** Private `trivy repo` clones authenticate by provider:
GitHub/GitLab credentials are passed via the `GITHUB_TOKEN` / `GITLAB_TOKEN`
environment variables Trivy honors, while a `generic` provider embeds
`username:token` into the transient HTTPS clone URL (never stored, never logged).
A URL-userinfo redaction pattern was added to the logging filter and applied to
stored scan errors so an embedded credential can never surface via logs or a
scanner stderr.
**Why:** §4.1 requires "private uses stored git credential → `trivy repo <url>`"
but does not specify the mechanism. Env tokens are Trivy's documented, no-leak
path for the hosted providers; URL embedding is the generic fallback, hardened
with redaction.
**Plan section affected:** §4.1 (Trivy repo target), §6 (logging redaction).

### 2026-07-03 — Phase P3 — SBOM generation is an opt-in per-scan pass
**What changed:** Syft SBOM generation is a per-scan option (`generate_sbom` +
`sbom_format`) on image and filesystem scans that runs Syft as a second pass and
stores the SBOM as a downloadable artifact. Grype SBOM *targets* are launched via
a dedicated multipart upload endpoint (`POST /api/scans/sbom`) that stores the
uploaded SBOM as the scan's input artifact.
**Why:** §4.2's note ("generate one SBOM per artifact with Syft, hand it to both
Grype and store it") describes the intent but not the UX. Making SBOM generation
explicit (rather than always-on) keeps default scans fast, and a dedicated upload
endpoint is the natural way to feed an "existing SBOM" that arrives as a file
rather than a JSON reference. Feeding the generated SBOM back into the same Grype
run (one cataloging pass) is left as a future optimization.
**Plan section affected:** §4.2 (Grype SBOM/filesystem, Syft).

### 2026-07-03 — Phase P3 — Registry credential helpers configured but not bundled
**What changed:** Registry auth types include `aws_ecr` / `google_gcr` /
`azure_acr`, which generate a Docker `credHelpers` config at scan time. The helper
binaries themselves are **not** bundled in the v1 image; those auth types work
only where the matching helper is present in the runtime environment. The two
static auth types (`username_password`, `token`) are fully supported end to end.
**Why:** §4.2 explicitly notes helper binaries are "present only if that registry
type is enabled." Bundling cloud helper binaries by default would bloat the image
and pull in unvetted dependencies; generating the correct config while leaving the
binary as a deployment add-on matches the plan and keeps the base image lean.
**Plan section affected:** §4.2 (private registries, credential helpers).

### 2026-07-03 — Phase P3 — Runtime deps (httpx, python-multipart) and read scope
**What changed:** `httpx` (Docker-proxy + registry-test HTTP) and
`python-multipart` (SBOM upload) were moved/added to runtime dependencies.
Registry/git-credential **read** (masked list) is allowed for the `operator` role
so operators can select a credential when launching a scan; all mutations and the
registry connectivity test remain `admin`-only.
**Why:** §2's tech-stack table did not enumerate these transport/runtime libs;
both are pinned, current, and vetted. §5 assigns credential *management* to admin
but scanning is an operator action that must reference a credential by name, so a
masked read for operators is required and exposes no secret material.
**Plan section affected:** §2 (Tech stack), §5 (RBAC).

### 2026-07-03 — Phase P3 — Security Review #2: generic-host git auth off-argv
**What changed:** Generic (non-GitHub/GitLab) private-repo scanning no longer
embeds `username:token` in the clone URL passed to `trivy repo` (which put the
credential on the process argv, visible via `/proc/<pid>/cmdline`). Instead,
generic HTTPS hosts are now cloned locally with the system `git` binary: the
credential is delivered through a transient tmpfs `GIT_ASKPASS` helper (mode
`0700`, echoing the credential from the clone subprocess's own environment — never
argv, never the parent process env, never the script file, never persisted), the
requested ref is checked out, and Trivy then scans the local checkout. Both the
helper and the checkout are shredded/removed in a `finally` block on success,
failure, or cancellation. `git` is added to the runtime image (unpinned, tracking
the digest-pinned base like the other apt packages). GitHub/GitLab are unchanged
and keep Trivy's native `GITHUB_TOKEN`/`GITLAB_TOKEN` env path (already off-argv).
**Why:** Resolves finding #2 of the Phase 3 security review. Trivy clones via
`go-git`, which never invokes the system git binary and so ignores `GIT_ASKPASS`,
`.netrc`, and credential helpers; for generic hosts its only credential channel is
the URL, which necessarily lands on argv. Cloning with the real `git` binary is the
only way to keep the credential off the process list while still supporting generic
hosts. Decision and implementation approach are per
`docs/reviews/phase3-finding2-resolution.md` (Option 1). Two adaptations to that
spec, both preserving its security mechanics: the askpass script is `0700` rather
than `0600` because git *execs* it (a non-executable helper fails with `EACCES`),
and the clone runs through the existing async `run_command` seam on the container's
tmpfs `/tmp` (matching `docker_config_env`) rather than a sync `subprocess.run` and
a bespoke mount, so it doesn't block the event loop.
**Plan section affected:** §4.1 (Trivy repo target), §6 (secrets at scan time), §9.1
(image dependency).

### 2026-07-03 — Phase P3 — Security Review #5: credential lists are admin-only
**What changed:** `GET /api/registries` and `GET /api/git-credentials` (the full
metadata views) are now **admin-only**; operators previously had read access.
Because launching a scan still requires an operator to pick a credential by name,
two new operator-accessible endpoints — `GET /api/registries/options` and
`GET /api/git-credentials/options` — return only `{id, name}` (enabled registries
for the registry list), exposing no host, username, provider, auth type, or secret.
The New Scan page now populates its credential pickers from these option endpoints.
**Why:** Resolves finding #5 of the Phase 3 security review. The masked list already
withheld the secret, but it still exposed credential *metadata* (registry host,
username, git provider/host) to operators. Narrowing the operator surface to bare
id/name keeps that metadata admin-only while preserving the scan-launch selection
flow. Supersedes the operator-read decision logged in the 2026-07-03 “Runtime deps
… and read scope” entry above.
**Plan section affected:** §5 (RBAC).
