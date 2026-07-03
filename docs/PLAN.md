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
| Reverse proxy / TLS | Existing **Caddy + acme.sh** wildcard (`*.your-domain.tld`) | App serves plain HTTP internally. |

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
- **OIDC:** generic via Authlib → Pocket ID (`https://pocket-id.your-domain.tld`, RS256).
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
- **Multi-arch** build (`linux/amd64` + `linux/arm64`) so it runs on the deployment host and an arm64 host.
- **No registry publishing.** Build locally (`docker build -t scrye:0.1.0 .` /
  `docker buildx` for multi-arch). Tag locally as `scrye:<version>`. Do **not** add Docker Hub
  steps, CI publish jobs, or `<dockerhub-user>/...` references.

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
- Deploy as a **DockHand** stack on `<the deployment host>` (`<your-deployment-host-ip>`); env vars set in the DockHand stack
  editor (no `.env` on disk). The **app secret key** is a Docker secret file, not an env var.
- Front with **Caddy** at `scrye.your-domain.tld`, TLS via acme.sh wildcard.
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

### 2026-07-03 — Phase P4 — History exposed via a dedicated `/scans/history` endpoint
**What changed:** The filtered/sorted/paginated history view is a new
`GET /api/scans/history` endpoint returning a `{total, items}` envelope, plus
`GET /api/scans/filter-options` for the distinct initiators/tags that populate the
filter controls. The pre-existing `GET /api/scans` (a plain newest-first list with
basic scanner/status filters) is left unchanged.
**Why:** §4.4 requires a full history view with a total count for pagination; the
simple list endpoint returns a bare array and is still used elsewhere. Adding a
separate endpoint avoids changing the existing contract while giving history its
own richer shape. Endpoint layout is a routine implementation detail under
CLAUDE.md § When to ask vs. decide.
**Plan section affected:** §4.4 (Scan history).

### 2026-07-03 — Phase P4 — Scan tags modeled as a `scan_tags` table, set by operators
**What changed:** §4.4 lists "tags" in the history filter set but §7 defines no tag
storage. Tags are stored in a new indexed `scan_tags(scan_id, tag)` association
table (rather than a JSON column on `scans`) so history can filter by tag with an
indexed SQL predicate and enumerate the distinct tag set. Tags are replaced as a
set via `PUT /api/scans/{id}/tags` (operator role, CSRF-guarded); values are
trimmed, lowercased, de-duplicated, and capped (≤20 tags, ≤64 chars each). Tag
filtering is conjunctive (a scan must carry *all* requested tags).
**Why:** A relational table keeps tag filtering index-friendly and lets the UI list
all known tags; making tags an operator action mirrors the existing "operators
launch scans" split. The exact storage/RBAC shape is unspecified by the plan, so
these are recorded decisions.
**Plan section affected:** §4.4 (tags), §7 (data model).

### 2026-07-03 — Phase P4 — Saved filter presets are owner-scoped
**What changed:** §4.4 requires "saved filter presets" but §7 lists no table. Presets
live in a new `filter_presets(owner_id, name, filters JSON)` table and are
**per-user**: every `/api/filter-presets` endpoint operates only on the caller's own
presets, any authenticated user (viewer+) may manage their own, and writes are
CSRF-guarded. `(owner_id, name)` is unique.
**Why:** Private, per-user presets are the least-surprising default and carry no
cross-user exposure. Scope and storage are unspecified by the plan, so logged here.
**Plan section affected:** §4.4 (saved filter presets), §7 (data model).

### 2026-07-03 — Phase P4 — Export scope semantics and diff constraints
**What changed:** Exports (§4.3) are split by scope: a **per-scan** export
(`GET /api/scans/{id}/export`) renders that scan's normalized findings (CSV = one
row per finding; JSON = scan metadata + findings; Markdown = summary grouped by
severity), while a **filtered-history** export (`GET /api/scans/export`) renders the
matching scan set (CSV = one row per scan; JSON = filters + scan summaries; Markdown
= a summary table). The scan **diff** (`GET /api/scans/{id}/diff/{other_id}`) requires
both scans to share the same scanner *and* target, matches findings by
`(class, vuln_id, package)` (falling back to title/location when there is no vuln id),
and reports added/removed/unchanged plus a per-severity delta.
**Why:** §4.3 says CSV is "one row per finding" and Markdown is "summary + findings
grouped by severity" — that describes the per-scan report; a history export naturally
summarizes at the scan level instead. §4.4's "compare two scans of the same target"
is enforced by the same-target/same-scanner check; the identity key is the scanners'
own dedupe convention so version churn isn't counted as change.
**Plan section affected:** §4.3 (exports), §4.4 (scan diff).

### 2026-07-03 — Phase P4 — History view uses the base Mantine `Table`, not `mantine-datatable`
**What changed:** The Phase 4 history view (filters, saved presets, sortable columns,
pagination, per-row compare selection, exports) is built with the base Mantine
`Table` plus `Pagination`/`Select`/`MultiSelect`, continuing the Phase 2 decision to
not add `mantine-datatable` (listed in §2/§4.4). No new frontend dependency was added.
**Why:** The base components already deliver the required sortable/paginated/filterable
history with saved presets, and avoiding the extra dependency keeps the bundle and
lockfile lean and consistent with the rest of the app (which uses base `Table`).
Library choice is a routine implementation detail under CLAUDE.md § When to ask vs.
decide. This supersedes the Phase 2 note that anticipated introducing
`mantine-datatable` here.
**Plan section affected:** §2 (Tech stack), §4.4 (history table).

### 2026-07-03 — Phase P5 — Runtime settings stored in a generic `settings` table
**What changed:** General, authentication-policy, and scanner-default settings are
persisted as one JSON row per group in a generic `settings(key, value)` table, with a
typed `SettingsService` (Pydantic models) supplying defaults and validation. §7 lists a
`settings` table but not its shape.
**Why:** A small, typed key/value store keeps the runtime-editable, non-secret settings
in one place while leaving secret-bearing configuration in its own field-encrypted
columns. Grouping by namespace keeps reads/writes to a single row and lets the Pydantic
models be the single source of truth for defaults.
**Plan section affected:** §4.5 (Settings), §7 (data model).

### 2026-07-03 — Phase P5 — Dependencies added: Authlib and pyotp
**What changed:** `authlib==1.7.2` (OIDC) and `pyotp==2.10.0` (TOTP MFA) were added to
the pinned runtime dependencies, and `SCRYE_BACKUPS_DIR` was added to the `Settings`
model (emitted in `.env.example`, default `/data/backups`).
**Why:** §2 names Authlib and pyotp for auth; both are pinned to current,
actively-maintained releases per CLAUDE.md § Dependency hygiene. The backups directory
lives under the existing `/data` volume, so no new mount is required.
**Plan section affected:** §2 (Tech stack), §11 (config).

### 2026-07-03 — Phase P5 — OIDC uses Authlib's `jose`, isolated behind an import shim
**What changed:** ID-token validation uses `authlib.jose` (JWKS import + RS256 verify).
Authlib deprecates that submodule in favor of `joserfc` but keeps it supported until
Authlib 2.0; rather than add a second JOSE dependency, the import is isolated in
`app/auth/_jose.py`, which suppresses the one benign deprecation warning. The OIDC login
flow's per-request `state`/`nonce`/PKCE verifier are persisted in a new
`oidc_login_flows` table instead of a server-side session middleware, and links live in
`oidc_identities` (`(issuer, subject)` unique).
**Why:** Keeping the JOSE dependency surface to just Authlib (as the plan specifies)
avoids pulling in `joserfc`; a DB-backed flow store avoids adding Starlette session
middleware and cookie-signing infrastructure just for the OAuth handshake.
**Plan section affected:** §2 (Tech stack), §5 (OIDC), §7 (data model).

### 2026-07-03 — Phase P5 — OIDC provisioning: username sanitization and admin-group mapping
**What changed:** On first OIDC login (when `auto_provision` is on) a local account is
created from the username claim, sanitized to the allowed `[a-z0-9._-]` charset and made
unique (suffixed with the subject on collision) so an OIDC login can never hijack an
existing local username. Provisioned users get the configured default role, upgraded to
`admin` when a configured `admin_group` appears in the groups claim. Auto-provisioned
accounts get a random (unusable) local password hash.
**Why:** §5 specifies auto-provisioning and a configurable default role but not the
collision/sanitization rules; these are security-model details (avoid account takeover,
keep OIDC users off local password auth) resolved conservatively.
**Plan section affected:** §5 (Bootstrap/RBAC/OIDC).

### 2026-07-03 — Phase P5 — TOTP MFA: two-step enrollment and in-process login challenge
**What changed:** MFA is enabled via an explicit enroll → activate handshake (the secret
is stored encrypted but inactive until a code is confirmed). The password step of an
MFA-enabled login returns a short-lived challenge token held in an in-process store (the
same single-container pattern as the auth rate limiter), and the second step
(`/auth/mfa/verify`) exchanges the token + TOTP code for a session. Enrollment surfaces
the `otpauth://` provisioning URI and manual key; no QR-image dependency was added.
**Why:** §5 lists "optional TOTP MFA" without a UX. A two-step, self-disabling enrollment
is the least-surprising materialization; an in-process challenge store fits the locked
single-container model (§0.2) and needs no schema. Omitting a QR renderer avoids an extra
frontend dependency while keeping enrollment usable (manual key + URI).
**Plan section affected:** §5 (MFA).

### 2026-07-03 — Phase P5 — API tokens: bearer auth, CSRF exemption, and role capping
**What changed:** Personal API tokens authenticate via `Authorization: Bearer <token>`
(SHA-256-hashed at rest, prefix retained for display). `AuthContext.session` is now
optional so token requests resolve without a session; CSRF is enforced only for cookie
logins (bearer tokens are not sent cross-site automatically, so they are exempt). A
token's effective role is the lesser of its minted role and the owner's current role.
**Why:** §5 assigns operators "their own API tokens" but not the transport/CSRF/role
mechanics; hashing-at-rest mirrors the session-token posture, and capping the effective
role means downgrading an account also downgrades its tokens.
**Plan section affected:** §5 (RBAC/API tokens).

### 2026-07-03 — Phase P5 — Notifications: channels + test-send now; event dispatch deferred
**What changed:** Notification channels (webhook / Discord / SMTP / Matrix) are fully
manageable with a field-encrypted per-channel secret and a live "send test message"
action. Event-driven dispatch (e.g. scan-complete alerts) is left to Phase 6, which the
roadmap already scopes for notifications.
**Why:** §4.5 places notification *configuration* in the Settings section (Phase 5) while
§12's Phase 6 covers notifications as a feature; building the configurable, testable
transport now and wiring triggers in Phase 6 matches both.
**Plan section affected:** §4.5 (Notifications), §12 (Phase 5/6 split).

### 2026-07-03 — Phase P5 — Scanner DB schedule/offline-import stored but not yet actuated
**What changed:** The Scanners settings tab persists default severities, ignore-unfixed,
`.trivyignore`/Grype ignore rules, and a DB auto-update toggle/interval. Actually running
scheduled scanner-DB updates and offline/air-gapped DB import (both listed in §4.5) are
deferred to the Phase 6 scanner-DB work; only the configuration is stored in Phase 5.
**Why:** Keeps Phase 5 focused on the settings surface; scanner-DB lifecycle management is
naturally part of the Phase 6 scanning polish and would otherwise expand this phase.
**Plan section affected:** §4.5 (Scanners settings), §12 (Phase 6).

### 2026-07-03 — Phase P5 — Backup bundle is a logical row dump with passphrase re-wrap
**What changed:** A backup is a logical, per-row JSON dump of the database (not a raw
SQLite file). Each field-encrypted secret is decrypted under the host master key and
re-wrapped under a scrypt-derived passphrase key (reusing the AES-256-GCM `SecretCipher`),
and the whole inner dump is then encrypted under the same passphrase key; restore reverses
this, re-wrapping secrets under the new host's master key. The secret columns are sourced
from a single `SECRET_COLUMNS` registry so new encrypted fields become portable
automatically. Transient/bookkeeping tables (`sessions`, `oidc_login_flows`, `backups`)
are excluded, and restore requires the bundle's schema version to match the running schema
(cross-version bundle migration is deferred; §8's "migrate if older" is a future pass).
**Why:** A logical dump is portable across SQLite on-disk formats and makes the secret
re-wrap (§8) straightforward. Reusing the existing cipher keeps one audited crypto path.
Requiring a matching schema keeps v1 restore simple and safe; the migration path can be
added when a second schema version exists.
**Plan section affected:** §8 (Backup & restore).

### 2026-07-03 — Phase P5 — Scheduled backups run on an in-process asyncio loop
**What changed:** Scheduled backups are driven by an in-process `BackupScheduler` asyncio
task (started in the app lifespan alongside the scan worker), checking a singleton
`backup_schedules` row on a timer and running due backups in a worker thread. The schedule
passphrase is field-encrypted so the loop can produce bundles unattended, and retention
prunes older *scheduled* bundles only.
**Why:** The locked single-container model (§0.2) rules out an external scheduler; an
asyncio loop mirrors the existing in-process scan worker. Encrypting the passphrase keeps
the "no plaintext secrets at rest" rule intact while allowing unattended runs.
**Plan section affected:** §8 (Scheduled backups), §0.2.

### 2026-07-03 — Phase P5 — Self-service Account page; role-gated Settings tabs
**What changed:** Password change, MFA management, and session review live on a dedicated
`/account` page available to every authenticated user, while the operator-and-up
`/settings` area gates admin-only tabs (general, authentication, users, registries, git,
Docker, notifications, backups) behind the admin role and shows operators only the
Scanners, API tokens, and About tabs. API tokens remain a Settings tab per §4.5.
**Why:** Self-service auth actions apply to all roles (including viewers, who cannot see
Settings), so they belong on a per-user page; gating the admin tabs avoids showing
operators panels whose endpoints would 403.
**Plan section affected:** §4.5 (Settings), §5 (RBAC).

### 2026-07-03 — Phase P5 — Security review hardening: OIDC alg allowlist + scrypt work factor
**What changed:** Two hardening items from the Phase 5 pre-merge security review were
applied. (1) `verify_id_token` now pins the accepted ID-token signing algorithms to an
explicit allowlist — the provider's discovered `id_token_signing_alg_values_supported`
(with `none` stripped) when advertised, falling back to `["RS256"]` — using a per-call
`JsonWebToken(<allowlist>)` instead of the library-default decoder, so a token presented
with an unexpected `alg` (`none`, or an HS/RS confusion attempt) is rejected before its
claims are trusted. Discovery now captures the advertised algorithm set on `OidcMetadata`.
(2) The backup passphrase KDF work factor was raised from scrypt `N=2**15` to `N=2**17`
(r=8, p=1 → ~128 MiB per derivation, per current OWASP guidance) in `core/passphrase.py`,
and the parameter comment's memory estimate corrected (the prior "~64 MiB" was inaccurate
at both the old and new N). New tests cover both: real RSA-signed ID-token verification
(valid RS256 accepted; `none`, HS256-confusion, wrong-audience, expired, and nonce-mismatch
tokens rejected; discovery parsing of the advertised algs) and the scrypt parameters/
derivation round-trip.
**Why:** Both were low-severity, defense-in-depth findings raised in the review — not live
bugs — accepted for hardening before merge. Explicit algorithm pinning removes any
reliance on library defaults for JWS `alg` handling; the higher scrypt cost strengthens
offline brute-force resistance of the portable, passphrase-encrypted backup bundle.
**Plan section affected:** §5 (OIDC), §8 (Backup & restore).

### 2026-07-03 — Phase P6 — Branch name `phase/P6`
**What changed:** Phase 6 work is developed on branch `phase/P6`.
**Why:** Matches the repo convention in CLAUDE.md § Git & PR conventions
(`phase/PX`) and the explicit build-session instruction, continuing the pattern of
phases 0–5. (Noted for the record; the session harness had suggested a different
default branch name.)
**Plan section affected:** §12 (process, not output).

### 2026-07-03 — Phase P6 — Cron scheduling via a self-contained evaluator
**What changed:** Scheduled/recurring scans use an in-repo 5-field cron evaluator
(`app/core/cron.py`, standard `* , - /` syntax with Vixie dom/dow semantics) rather
than a third-party cron dependency. Schedules live in a new `scan_schedules` table
(a scan template + cron), and an in-process `MaintenanceScheduler` (mirroring the
existing backup scheduler) fires due schedules on a one-minute tick and hands the
created scans to the worker. Schedule *management* is an `operator` action (like
launching scans) with `viewer` reads; SBOM targets cannot be scheduled (they need a
file upload); `PUT` replaces a whole schedule and a `run now` action fires one
immediately.
**Why:** §4.6/§12 call for "cron per target/profile" without specifying the engine or
storage. A small, tested evaluator avoids adding an unvetted dependency (CLAUDE.md
§ Dependency hygiene) and keeps full control of the semantics; an in-process loop fits
the locked single-container model (§0.2).
**Plan section affected:** §4.6, §7 (data model), §12 (Phase 6).

### 2026-07-03 — Phase P6 — Notification dispatch: per-channel event subscriptions
**What changed:** Phase 5 built the notification channels + test-send; Phase 6 wires
dispatch. A per-channel `events` JSON column records which events a channel is notified
about — `scan_completed`, `scan_failed`, and `scan_high_severity` (a completed scan with
any CRITICAL/HIGH finding). When a scan finishes the worker calls a best-effort dispatcher
(`app/core/notification_dispatch.py`) that sends a plain-text summary to each enabled,
subscribed channel; a transport failure is logged, never raised into the scan.
**Why:** §4.5/§4.6 place notification *configuration* in Phase 5 and *dispatch* in Phase 6
but do not define the event taxonomy or routing. Per-channel opt-in (rather than a global
rule table) is the least-surprising materialization and needs only one additive column.
**Plan section affected:** §4.5, §4.6, §7 (data model).

### 2026-07-03 — Phase P6 — Trivy VEX/ignore applied via env vars, ignore rules structured
**What changed:** VEX documents (`vex_documents`) and structured ignore rules
(`trivy_ignore_rules`, an id + optional reason + optional expiry) are admin-managed and
applied to every Trivy scan by materializing them into the container's tmpfs `/tmp` at
scan time and passing Trivy's `TRIVY_VEX` / `TRIVY_IGNOREFILE` environment variables
(the env equivalents of `--vex` / `--ignorefile`) — so the scanner argv-builders are
unchanged and the transient paths stay off the process argv. The rendered `.trivyignore`
combines the global blob from scanner settings (a Phase 5 gap now actually applied) with
the active managed rules.
**Why:** §4.1/§4.5 list "VEX policy" and "`.trivyignore` rules" without a storage or
plumbing design. Env-var delivery is Trivy's documented equivalent of the flags and needs
no scanner changes; a structured rule table (rather than only a raw blob) lets rules carry
a reason and an expiry and be toggled individually.
**Plan section affected:** §4.1, §4.5, §7 (data model).

### 2026-07-03 — Phase P6 — Dashboard "open" posture from the latest scan per target
**What changed:** The dashboard's open critical/high counts and top-vulnerable-targets
widget are computed from the **latest succeeded scan per (scanner, target)**, not a running
total across all scans. Scanner-DB freshness probes `trivy --version --format json` and
`grype db status -o json` best-effort (a missing binary degrades to "unknown").
**Why:** §4.6 lists the widgets but not their semantics. Deriving "open" from the most
recent scan per target makes re-scanning a fixed target lower the number, which is the
useful live-posture reading; a running total would only ever grow.
**Plan section affected:** §4.6.

### 2026-07-03 — Phase P6 — `/metrics` is authenticated; hand-rolled exposition
**What changed:** The Prometheus `/metrics` endpoint requires the `viewer` role rather than
being public, and renders the text exposition format directly (no `prometheus_client`
dependency) from DB-derived gauges. A Prometheus scrape authenticates with a personal API
token as a bearer credential.
**Why:** The metrics reveal scan volume and open-vulnerability posture, so exposing them
unauthenticated conflicts with the security-first principle (§1); API-token bearer auth is
the standard Prometheus mechanism and needs no new auth path. Hand-rolling the (simple)
exposition format for point-in-time gauges avoids an added dependency (CLAUDE.md
§ Dependency hygiene).
**Plan section affected:** §1 (security-first), §12 (Phase 6 `/metrics`).

### 2026-07-03 — Phase P6 — Retention prunes raw artifacts only; config in the settings table
**What changed:** The result-retention policy (a new `retention` group in the existing
`settings` table: `enabled` + `max_age_days`) prunes the **raw** artifacts (scanner JSON +
SBOMs) of scans older than the age, removing the files and their `artifacts` rows while
keeping the scan row and its normalized findings. The maintenance scheduler runs it on each
tick when enabled.
**Why:** §12 says "prune old raw artifacts" — keeping the scan and normalized findings
preserves history, trends, and severity counts while reclaiming the bulk of the disk
footprint. Storing the policy in the typed settings store matches the Phase 5 settings
pattern and needs no new table.
**Plan section affected:** §4.3, §12 (Phase 6 retention).

### 2026-07-03 — Phase P6 — Dogfood self-scan gates on fixable High/Critical with triage allowlists
**What changed:** CI adds an `image` job that builds the image (amd64, loaded) and scans it
with Trivy and Grype pinned to the versions Scrye bundles, plus an `image-multiarch` job that
builds `linux/amd64,linux/arm64` to prove both architectures build. The gate fails on any
**fixable HIGH/CRITICAL** finding (Trivy `--ignore-unfixed --severity HIGH,CRITICAL`; Grype
`--only-fixed --fail-on high`); fixable lower-severity items are reported but non-gating, and
triaged exceptions live in `ci/trivyignore` and `ci/grype.yaml` with dated justifications.
Because the whole image filesystem and OS package set are scanned, the bundled
`THIRD_PARTY_LICENSES/` directory and the `git` runtime dependency (added in Phase 3) are
covered automatically. No registry publishing is added (locked §6): the image is only
loaded/saved within the job.
**Why:** CLAUDE.md § Dependency hygiene requires dogfooding Trivy + Grype against Scrye's own
image and resolving all *fixable* findings, with only genuinely-unfixable items remaining.
Gating on fixable HIGH/CRITICAL (with an audited allowlist for the rare fixable item that
cannot be bumped immediately) is the practical, low-churn enforcement of that rule while
still surfacing everything.
**Plan section affected:** §9.1 (multi-arch build), §12 (Phase 6 self-scanning CI),
CLAUDE.md § Dependency hygiene.
