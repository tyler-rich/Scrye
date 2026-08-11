# Scrye — Build Archive (historical record)

> **Scrye** — a unified, self-hosted web UI for the **Trivy** and **Grype** scanners.
> ("Scry": to perceive hidden things, fused with "scan.")
>
> **This is the historical build record — preserved, not maintained.** It was the original
> build specification (`PLAN.md`) and is kept verbatim as the archive of *how Scrye was built
> and why*: the phase-by-phase build order (§12), the locked decisions and their revisions
> (§0), the data model and architecture as originally specified, the full **Deviations log**
> (§14 — every place the implementation diverged from the plan, dated, with rationale: the
> Python 3.13 bump, the INF-2 → GHCR-nightly migration, the post-promotion back-merge process
> fix, the multi-tier security-audit remediation, etc.), the **finding-ID index** (§15 — the
> decoder for the bare `SC-12`/`P3-4`/`QUA-17` citations §14 is full of, which replaced the
> deleted `docs/reviews/` reports), and the durable **Build performance** notes at the end.
>
> §14 opens with a **newest-first index of all its entries** — use that rather than scrolling;
> the entries themselves are not in one consistent order, and §14 explains why.
>
> It is **not** forward-looking. For what's next — open work, known limitations, and planned
> features — see [`ROADMAP.md`](./ROADMAP.md). For what Scrye is and how to run it, see the
> [`README.md`](../README.md). `CLAUDE.md` remains the condensed, authoritative operating
> contract.
>
> _Section numbers and the "Plan section affected" cross-references below refer to this
> document as it stood during the build; they are retained unchanged for the historical trail._

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
6. **Distribution:** the image builds locally **and** is published to **two registries with two
   distinct roles**:
   - **Docker Hub `<dockerhub-user>/scrye` — releases only** (`.github/workflows/publish.yml`,
     `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` secrets): pushing a semver tag `v*.*.*` builds the
     multi-arch (amd64/arm64) image and pushes `<dockerhub-user>/scrye:<version>` (tag minus the
     leading `v`) **and** `<dockerhub-user>/scrye:latest`. Runs **only** when the tagged commit is on
     `main`. No Docker Hub credentials are referenced outside this workflow.
   - **GHCR `ghcr.io/tyler-rich/scrye` — dev only** (`.github/workflows/dev-nightly.yml`, GHCR login
     via the built-in `GITHUB_TOKEN`): a **nightly scheduled** build (04:00 UTC) of the `dev` branch
     pushes the single **moving** tag `ghcr.io/tyler-rich/scrye:dev` (always overwritten — not a
     version, not `latest`). The scheduled run skips when `dev` has had no new commits in 24h;
     `workflow_dispatch` always builds. It does **not** build on every dev merge — CI already
     lints/tests/builds each dev PR, and the image is batched nightly. GHCR package visibility
     inherits from the (private) repo.
   `latest`/`:<version>` come only from tagged main releases on Docker Hub; `:dev` only from the
   nightly GHCR build. No other registries or tags. (Originally locked to local-build-only, then to
   a Docker Hub merged-PR `:dev` trigger; revised again to the GHCR nightly split — see
   § Deviations, 2026-07-06.)
7. **Backend runtime:** **Python 3.14** (floor **3.14.6** — never 3.14.0–3.14.4, whose
   incremental GC leaked resident memory in long-running servers and was reverted in 3.14.5).
   (Originally locked to Python 3.12; revised to 3.13 in Phase 6 to resolve Grype-flagged CPython
   interpreter CVEs whose fixes are only available in 3.13+; revised again to 3.14 post-v1. Note
   that the second bump did **not** deliver the CVE clearance it was scoped for: released 3.14.6
   carries neither the CVE-2025-15366 (`imaplib`) nor the CVE-2025-15367 (`poplib`) guard, so it
   cleared nothing at the version the image pins. The two have since diverged, though —
   CVE-2025-15366's backport **did** land on the `3.14` maintenance branch (2026-07-07) and closes
   on **3.14.7**, tracked in issue **#98**; only CVE-2025-15367 remains a standing acceptance below
   3.15, tracked in **#52**. See § Deviations (2026-07-25 and both 2026-07-26 entries) for the full
   rationale of both bumps and that correction.)

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
| Backend | **Python 3.14 + FastAPI + Pydantic v2** | Consistent with the Lacunarr stack; strong async subprocess handling. (Bumped from 3.12 in Phase 6, then from 3.13 post-v1 — see § Deviations.) |
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
- **Registry publishing (Docker Hub).** Build locally (`docker build -t scrye:0.1.0 .` /
  `docker buildx` for multi-arch) for dev; automated publishing to `<dockerhub-user>/scrye` on
  Docker Hub is handled by `.github/workflows/publish.yml` (locked decision §0.6) — tagged main
  releases push `:<version>` + `:latest`, and `dev`-branch pushes push the moving `:dev` tag. The
  multi-arch build steps are defined once in `.github/actions/build-image` and reused by both
  `publish.yml` and `ci.yml`'s build-check.

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
- **Roadmap** — deferred items (arq/Redis scale-out, SQLCipher).
- **Contributing** — link to `CONTRIBUTING.md`.
- **License** — link to `LICENSE`.

### 10.2 `CONTRIBUTING.md` (full)
Must include:
- **Code of conduct** pointer (or a short statement).
- **Local development environment** — step-by-step:
  - Prereqs (Python 3.14, Node 20+, Docker, `trivy`/`grype`/`syft` for native runs).
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

(Docker Hub publishing was originally deferred here; it is now **in scope** — see locked decision
§0.6 and `.github/workflows/publish.yml`. See § Deviations.)

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

**Document names in these entries.** Entries below cite the 2026-07 review reports by bare
filename — `security-review.md`, `00-summary.md`, `full-audit-2026-07-05.md`,
`claude-md-compliance.md`, `STATUS.md`, `python-3.14.md` and the rest. Those files lived under
`docs/reviews/` and `docs/upgrades/` and were **deleted on 2026-07-26**; the names are kept
because they are how the entries identify their sources, not because the paths still resolve.
**[§15](#15-finding-id-index-decoder-for-14s-citations) is the decoder** for every finding ID
they defined, and records how to recover any of the originals from git.

**Ordering — read this before you go looking for something.** This log is **not** in one
consistent order, and reordering it is not worth the cost: sixteen entries refer to each other
*relatively* ("the entry below", "superseded by the entry above", "the two 2026-07-03 entries
above"), and every one of those would silently invert. The three regimes as they actually stand:

1. **Newest-first** from the first entry (2026-07-25) back to 2026-07-07.
2. **Oldest-first** from 2026-06-30 forward through the 2026-07-09 GHCR consolidation.
3. **Oldest-first** again for the tail, 2026-07-09 → 2026-07-26 — the twelve entries that were
   misfiled under `## Build performance` until 2026-07-26 and are now back under this section.

**New entries go at the top of regime 1**, immediately below this index: that is where the most
recent work already sits and where a reader looks first. The index itself is sorted **newest-first
regardless of physical position**, so it — not the scroll order — is the reliable way to find an
entry, and the anchors jump straight to it.

### Index of §14 entries (167, newest first)

- [2026-08-11 — Post-v1 — #176 part 2: findings 4 and 6 replaced (keyed remount; reconcile-in-load), and `set-state-in-effect` enabled at `'warn'` rather than the preset `'error'`](#2026-08-11--post-v1--176-part-2-findings-4-and-6-replaced-keyed-remount-reconcile-in-load-and-set-state-in-effect-enabled-at-warn-rather-than-the-preset-error)
- [2026-08-11 — Docs/Process — `.claude/settings.json` deleted outright after three failed settings-layer attempts; the strip-`PATCH` rule reinstated with a one-attempt cap](#2026-08-11--docsprocess--claudesettingsjson-deleted-outright-after-three-failed-settings-layer-attempts-the-strip-patch-rule-reinstated-with-a-one-attempt-cap)
- [2026-08-11 — Post-v1 — #176 part 1: findings 1, 2, 3 and 5 refactored off synchronous setState-in-effect; findings 4 and 6 and the rule flip deferred to a follow-up](#2026-08-11--post-v1--176-part-1-findings-1-2-3-and-5-refactored-off-synchronous-setstate-in-effect-findings-4-and-6-and-the-rule-flip-deferred-to-a-follow-up)
- [2026-08-11 — Docs/Process — `includeGitInstructions: false` added to `.claude/settings.json`; a standing PR-body content rule added to CLAUDE.md](#2026-08-11--docsprocess--includegitinstructions-false-added-to-claudesettingsjson-a-standing-pr-body-content-rule-added-to-claudemd)
- [2026-08-11 — Security/Process — Issue #52 (CVE-2025-15367, poplib) re-verified against the now-pinned v3.14.7 tag; cross-references to the closed #98/#116 retargeted to their new tracking location](#2026-08-11--securityprocess--issue-52-cve-2025-15367-poplib-re-verified-against-the-now-pinned-v3147-tag-cross-references-to-the-closed-98116-retargeted-to-their-new-tracking-location)
- [2026-08-11 — Docs/Process — Attribution moved to the settings layer via a committed `.claude/settings.json`; the strip-PATCH instruction removed from CLAUDE.md and CONTRIBUTING.md](#2026-08-11--docsprocess--attribution-moved-to-the-settings-layer-via-a-committed-claudesettingsjson-the-strip-patch-instruction-removed-from-claudemd-and-contributingmd)
- [2026-08-11 — Process — Issues #98 and #116 closed on source-verification evidence rather than Grype-DB agreement; Group A tracking moves into `ci/grype.yaml` plus this log](#2026-08-11--process--issues-98-and-116-closed-on-source-verification-evidence-rather-than-grype-db-agreement-group-a-tracking-moves-into-cigrypeyaml-plus-this-log)
- [2026-08-11 — Security/Infra — Runtime base image moved to Python 3.14.7; all six Group A interpreter fixes verified at the source, and the waivers kept anyway because Grype's DB has not caught up](#2026-08-11--securityinfra--runtime-base-image-moved-to-python-3147-all-six-group-a-interpreter-fixes-verified-at-the-source-and-the-waivers-kept-anyway-because-grypes-db-has-not-caught-up)
- [2026-08-11 — Process — Locked runtime floor raised 3.14.6 → 3.14.7 (locked decision §2), on a second independent reason rather than a replacement one](#2026-08-11--process--locked-runtime-floor-raised-3146--3147-locked-decision-2-on-a-second-independent-reason-rather-than-a-replacement-one)
- [2026-08-09 — Docs/Process — `dependabot.yml`'s "Deliberately NOT ignored" rationale rewritten: the instruction outlived the reason it was written on](#2026-08-09--docsprocess--dependabotymls-deliberately-not-ignored-rationale-rewritten-the-instruction-outlived-the-reason-it-was-written-on)
- [2026-08-09 — Infra/Process — The `@types/node` majors-ignore removed now that 26.2.0 has landed; no `typescript` ignore added, deliberately, because that regenerating PR is the TS7 signal](#2026-08-09--infraprocess--the-typesnode-majors-ignore-removed-now-that-2620-has-landed-no-typescript-ignore-added-deliberately-because-that-regenerating-pr-is-the-ts7-signal)
- [2026-08-09 — Infra — `@types/node` 24.13.3 → 26.2.0: the sweep's one declined package taken deliberately, after step 4 had already shrunk its blast radius to one file](#2026-08-09--infra--typesnode-24133--2620-the-sweeps-one-declined-package-taken-deliberately-after-step-4-had-already-shrunk-its-blast-radius-to-one-file)
- [2026-08-09 — Docs/Process — Roadmap updated for the completed #86 sweep, the re-cut react-router advisory, and the React-19-blocked router major](#2026-08-09--docsprocess--roadmap-updated-for-the-completed-86-sweep-the-re-cut-react-router-advisory-and-the-react-19-blocked-router-major)
- [2026-08-09 — Infra — #86 sweep step 8 landed: `globals` 17.9.0, `@testing-library/user-event` 14.6.3, `postcss` 8.5.26 — the sweep is complete, and its reminder-surface PR had already closed itself](#2026-08-09--infra--86-sweep-step-8-landed-globals-1790-testing-libraryuser-event-1463-postcss-8526--the-sweep-is-complete-and-its-reminder-surface-pr-had-already-closed-itself)
- [2026-08-09 — Infra — #86 sweep step 7 landed: Vite 6.4.3 → 8.2.1 + `@vitejs/plugin-react` 4.3.4 → 6.0.5; the partial oracle was closed by a pixel diff, but only after its noise floor was calibrated](#2026-08-09--infra--86-sweep-step-7-landed-vite-643--821--vitejsplugin-react-434--605-the-partial-oracle-was-closed-by-a-pixel-diff-but-only-after-its-noise-floor-was-calibrated)
- [2026-08-09 — Infra — #86 sweep step 6 landed: jsdom 26.1.0 → 30.0.1; the selector-drift shim diffed empty, but only after the shim itself had to be fixed](#2026-08-09--infra--86-sweep-step-6-landed-jsdom-2610--3001-the-selector-drift-shim-diffed-empty-but-only-after-the-shim-itself-had-to-be-fixed)
- [2026-08-09 — Infra — #86 sweep step 5 landed: Vitest 3.2.7 → 4.1.10 on the pinned Vite 6; the "no config changes" prediction held, the "low breakage" one did not](#2026-08-09--infra--86-sweep-step-5-landed-vitest-327--4110-on-the-pinned-vite-6-the-no-config-changes-prediction-held-the-low-breakage-one-did-not)
- [2026-08-09 — Infra — #86 sweep step 4 landed: TypeScript 5.7.2 → 6.0.3 with the ceiling re-checked; the `this`-less inference change surfaced, silently and benignly](#2026-08-09--infra--86-sweep-step-4-landed-typescript-572--603-with-the-ceiling-re-checked-the-this-less-inference-change-surfaced-silently-and-benignly)
- [2026-08-09 — Post-v1 — `L17`/`P2-2`'s reset effect finally has a regression test; the protection #176 relies on was never actually enforced](#2026-08-09--post-v1--l17p2-2s-reset-effect-finally-has-a-regression-test-the-protection-176-relies-on-was-never-actually-enforced)
- [2026-08-09 — Infra — #86 sweep step 3 landed: React Compiler rules adopted, `set-state-in-effect` held back over 12 findings with no honest fix (#176)](#2026-08-09--infra--86-sweep-step-3-landed-react-compiler-rules-adopted-set-state-in-effect-held-back-over-12-findings-with-no-honest-fix-176)
- [2026-08-09 — Infra — #86 sweep step 2 landed: the ESLint 10 family, with the React Compiler rule set held inert; three of the doc's four predictions held](#2026-08-09--infra--86-sweep-step-2-landed-the-eslint-10-family-with-the-react-compiler-rule-set-held-inert-three-of-the-docs-four-predictions-held)
- [2026-08-09 — Docs/Process — Scoping doc corrected post-step-1; #170 (Dependabot's regenerated unsatisfiable frontend group) closed](#2026-08-09--docsprocess--scoping-doc-corrected-post-step-1-170-dependabots-regenerated-unsatisfiable-frontend-group-closed)
- [2026-08-09 — Infra — #86 sweep step 1 landed: `typescript-eslint` 8.19.0 → 8.66.0; the scoping doc's rule-set claim was wrong in two independent ways](#2026-08-09--infra--86-sweep-step-1-landed-typescript-eslint-8190--8660-the-scoping-docs-rule-set-claim-was-wrong-in-two-independent-ways)
- [2026-08-09 — Security — Frontend lockfile refreshed to clear two HIGH advisories in the build toolchain (js-yaml, nanoid); kept separate from the #86 sweep](#2026-08-09--security--frontend-lockfile-refreshed-to-clear-two-high-advisories-in-the-build-toolchain-js-yaml-nanoid-kept-separate-from-the-86-sweep)
- [2026-08-09 — Docs/Process — #86 frontend toolchain sweep scoped into an ordered sequence; TypeScript 7 ruled out at the source; #153's red check re-diagnosed](#2026-08-09--docsprocess--86-frontend-toolchain-sweep-scoped-into-an-ordered-sequence-typescript-7-ruled-out-at-the-source-153s-red-check-re-diagnosed)
- [2026-08-09 — Docs/Process — PR #169 reversed the attribution-stripping ban hours after it was recorded; the reversal itself went undocumented until now](#2026-08-09--docsprocess--pr-169-reversed-the-attribution-stripping-ban-hours-after-it-was-recorded-the-reversal-itself-went-undocumented-until-now)
- [2026-08-09 — Security/Process — Settings audit: four previously-unreachable toggles verified, Secret Protection enabled, SHA-pinning confirmed clean, attribution-stripping banned](#2026-08-09--securityprocess--settings-audit-four-previously-unreachable-toggles-verified-secret-protection-enabled-sha-pinning-confirmed-clean-attribution-stripping-banned)
- [2026-08-09 — Infra/Process — Dependabot round closed out: queue merged and closed, bundled scanners bumped, the display-name option declined, prior claims corrected](#2026-08-09--infraprocess--dependabot-round-closed-out-queue-merged-and-closed-bundled-scanners-bumped-the-display-name-option-declined-prior-claims-corrected)
- [2026-08-09 — Infra/Process — Open-Dependabot-queue audit: only #149 was on `main`, and it was already superseded; `.github/dependabot.yml`'s `ignore` list is read from `main`, so `dev`-only edits to it are inert](#2026-08-09--infraprocess--open-dependabot-queue-audit-only-149-was-on-main-and-it-was-already-superseded-githubdependabotymls-ignore-list-is-read-from-main-so-dev-only-edits-to-it-are-inert)
- [2026-08-08 — Docs/Process — `docs/ROADMAP.md` replaced wholesale with an externally-drafted two-track revision (Track A carried forward verbatim, Track B added)](#2026-08-08--docsprocess--docsroadmapmd-replaced-wholesale-with-an-externally-drafted-two-track-revision-track-a-carried-forward-verbatim-track-b-added)
- [2026-08-08 — Security/Infra — `cryptography` bumped 49.0.0 → 50.0.0 for CVE-2026-69247; the dogfood gate caught it on an unrelated PR](#2026-08-08--securityinfra--cryptography-bumped-4900--5000-for-cve-2026-69247-the-dogfood-gate-caught-it-on-an-unrelated-pr)
- [2026-08-03 — Infra/Process — Post-v0.3.0 Dependabot triage: three grouped PRs reapplied on `dev`, an annotated-tag SHA-pin corrected, eight toolchain majors held back](#2026-08-03--infraprocess--post-v030-dependabot-triage-three-grouped-prs-reapplied-on-dev-an-annotated-tag-sha-pin-corrected-eight-toolchain-majors-held-back)
- [2026-08-03 — Release/Process — v0.3.0 release prep: version bumped to 0.3.0, CHANGELOG cut with an upgrade-notes block for migration 0009](#2026-08-03--releaseprocess--v030-release-prep-version-bumped-to-030-changelog-cut-with-an-upgrade-notes-block-for-migration-0009)
- [2026-08-03 — Post-v1 — PR #142 verified green on the pinned Python 3.14.6 in CI; `test_undeterminable_presence_fails_startup`'s local-sandbox failure was 3.13-specific](#2026-08-03--post-v1--pr-142-verified-green-on-the-pinned-python-3146-in-ci-test_undeterminable_presence_fails_startups-local-sandbox-failure-was-313-specific)
- [2026-08-03 — Post-v1 — `test_cancel_queued_scan` de-flaked: worker slot acquisition made observable, sleep removed](#2026-08-03--post-v1--test_cancel_queued_scan-de-flaked-worker-slot-acquisition-made-observable-sleep-removed)
- [2026-08-03 — Post-v1 — Deprecated Starlette status-code constants retired across 24 call sites](#2026-08-03--post-v1--deprecated-starlette-status-code-constants-retired-across-24-call-sites)
- [2026-08-03 — Process/Governance — Dogfood self-scan added to required status checks, closing #136](#2026-08-03--processgovernance--dogfood-self-scan-added-to-required-status-checks-closing-136)
- [2026-08-03 — Process/Governance — protect-tags ruleset created, closing #137](#2026-08-03--processgovernance--protect-tags-ruleset-created-closing-137)
- [2026-08-03 — Process/Governance — Signed-commit enforcement declined, not deferred](#2026-08-03--processgovernance--signed-commit-enforcement-declined-not-deferred)
- [2026-08-02 — Security/Process — CodeQL migrated from default setup to a committed workflow; the two settings edits that finish it](#2026-08-02--securityprocess--codeql-migrated-from-default-setup-to-a-committed-workflow-the-two-settings-edits-that-finish-it)
- [2026-08-02 — Security/Process — Symlink-containment regression guard for filesystem scans (#135); Syft is the probe, and it runs against the binaries the image ships](#2026-08-02--securityprocess--symlink-containment-regression-guard-for-filesystem-scans-135-syft-is-the-probe-and-it-runs-against-the-binaries-the-image-ships)
- [2026-08-02 — Post-v1 — Log redaction moved from the `LogRecord` to the formatted line; uvicorn's access logger stops raising on every request](#2026-08-02--post-v1--log-redaction-moved-from-the-logrecord-to-the-formatted-line-uvicorns-access-logger-stops-raising-on-every-request)
- [2026-08-02 — Post-v1 — OIDC account linking: authenticated self-link, guarded self-unlink, and stale-link detection (#114)](#2026-08-02--post-v1--oidc-account-linking-authenticated-self-link-guarded-self-unlink-and-stale-link-detection-114)
- [2026-08-02 — Security/Process — Filesystem-gate symlink and TOCTOU residual risks closed out (neither is real); CodeQL advanced-setup migration assessed](#2026-08-02--securityprocess--filesystem-gate-symlink-and-toctou-residual-risks-closed-out-neither-is-real-codeql-advanced-setup-migration-assessed)
- [2026-08-02 — Security/Process — CodeQL code scanning enabled via default setup; first-run triage: six alerts, all false positives](#2026-08-02--securityprocess--codeql-code-scanning-enabled-via-default-setup-first-run-triage-six-alerts-all-false-positives)
- [2026-08-02 — Infra/Process — GHSA-qwww-vcr4-c8h2 closed by a 7.x backport (`react-router` 7.18.2), not the 8.3.0 major; the advisory's "Patched versions" field is stale](#2026-08-02--infraprocess--ghsa-qwww-vcr4-c8h2-closed-by-a-7x-backport-react-router-7182-not-the-830-major-the-advisorys-patched-versions-field-is-stale)
- [2026-08-02 — Infra — Frontend builder and CI moved Node 22 → 24 (Active LTS); the Dependabot major-ignore re-pointed at the 24 line](#2026-08-02--infra--frontend-builder-and-ci-moved-node-22--24-active-lts-the-dependabot-major-ignore-re-pointed-at-the-24-line)
- [2026-08-02 — Infra/Process — Post-v0.2.0 dependency cleanup: three closed Dependabot PRs reapplied, the base-branch anomaly traced to `dev`'s deletion, the brace-expansion waiver retired](#2026-08-02--infraprocess--post-v020-dependency-cleanup-three-closed-dependabot-prs-reapplied-the-base-branch-anomaly-traced-to-devs-deletion-the-brace-expansion-waiver-retired)
- [2026-08-02 — Process/Governance — Public-repo governance checklist verified in GitHub Settings; five of eight items closed](#2026-08-02--processgovernance--public-repo-governance-checklist-verified-in-github-settings-five-of-eight-items-closed)
- [2026-08-02 — Infra/Process — Auto-delete-on-merge deleted `dev` during the v0.2.0 promotion; the ruleset's admin bypass is why "Restrict deletions" did not stop it](#2026-08-02--infraprocess--auto-delete-on-merge-deleted-dev-during-the-v020-promotion-the-rulesets-admin-bypass-is-why-restrict-deletions-did-not-stop-it)
- [2026-08-02 — Infra — Dependabot's docker run fails on our own local build tag `scrye:0.2.0`](#2026-08-02--infra--dependabots-docker-run-fails-on-our-own-local-build-tag-scrye020)
- [2026-07-31 — Process — `dev` → `main` promotions merge with a merge commit, not a squash](#2026-07-31--process--dev--main-promotions-merge-with-a-merge-commit-not-a-squash)
- [2026-07-31 — Release/Process — v0.2.0 release prep: CHANGELOG cut, brace-expansion reapplied on `dev`, Dependabot security-PR routing documented](#2026-07-31--releaseprocess--v020-release-prep-changelog-cut-brace-expansion-reapplied-on-dev-dependabot-security-pr-routing-documented)
- [2026-07-31 — Infra/Process — Grype gate keeps its verdict *and* lists its waivers, from one scan](#2026-07-31--infraprocess--grype-gate-keeps-its-verdict-and-lists-its-waivers-from-one-scan)
- [2026-07-30 — Infra/Process — Three `tarfile` interpreter CVEs waived as Group A-2 (issue #116); the grype.yaml blocks made self-describing](#2026-07-30--infraprocess--three-tarfile-interpreter-cves-waived-as-group-a-2-issue-116-the-grypeyaml-blocks-made-self-describing)
- [2026-07-29 — Post-v1 — App version bumped 0.1.0 → 0.2.0; the three independent declarations put under a drift guard](#2026-07-29--post-v1--app-version-bumped-010--020-the-three-independent-declarations-put-under-a-drift-guard)
- [2026-07-29 — Post-v1 — HTTPS enforcement made legible; `X-Forwarded-Proto` honored from configured proxies only](#2026-07-29--post-v1--https-enforcement-made-legible-x-forwarded-proto-honored-from-configured-proxies-only)
- [2026-07-29 — Post-v1 — Master-key source surfaced on the About tab (the durable channel chosen over a per-boot log line)](#2026-07-29--post-v1--master-key-source-surfaced-on-the-about-tab-the-durable-channel-chosen-over-a-per-boot-log-line)
- [2026-07-29 — Post-v1 — Master key auto-generated on first launch; the Docker secret keeps its precedence](#2026-07-29--post-v1--master-key-auto-generated-on-first-launch-the-docker-secret-keeps-its-precedence)
- [2026-07-28 — Post-v1 — Compose `deploy:` keys retired for NAS portability; memory limits made portable, CPU limits moved to an opt-in overlay](#2026-07-28--post-v1--compose-deploy-keys-retired-for-nas-portability-memory-limits-made-portable-cpu-limits-moved-to-an-opt-in-overlay)
- [2026-07-26 — Infra/Process — `node:22-bookworm-slim` digest refreshed; the Node 24 move and the #86 frontend tooling majors recorded in the roadmap](#2026-07-26--infraprocess--node22-bookworm-slim-digest-refreshed-the-node-24-move-and-the-86-frontend-tooling-majors-recorded-in-the-roadmap)
- [2026-07-26 — Docs/Process — Review documents retired; §14 made contiguous and indexed; a false CVE claim removed from the CHANGELOG](#2026-07-26--docsprocess--review-documents-retired-14-made-contiguous-and-indexed-a-false-cve-claim-removed-from-the-changelog)
- [2026-07-26 — Post-v1 — Socket-proxy operational behavior from a live Debian run documented (docs only)](#2026-07-26--post-v1--socket-proxy-operational-behavior-from-a-live-debian-run-documented-docs-only)
- [2026-07-26 — Post-v1 — Stale socket-proxy wording retired from the code and Compose file](#2026-07-26--post-v1--stale-socket-proxy-wording-retired-from-the-code-and-compose-file)
- [2026-07-26 — Infra/Process — Group A interpreter CVEs re-verified against the 3.14 branch; waivers re-pointed at a Group-A-only tracking issue (#98)](#2026-07-26--infraprocess--group-a-interpreter-cves-re-verified-against-the-314-branch-waivers-re-pointed-at-a-group-a-only-tracking-issue-98)
- [2026-07-26 — Infra/Process — CVE-2025-15366 (imaplib) regrouped from Group B to Group A: the backport did land on 3.14](#2026-07-26--infraprocess--cve-2025-15366-imaplib-regrouped-from-group-b-to-group-a-the-backport-did-land-on-314)
- [2026-07-26 — Infra/Process — Dependabot told to stop proposing Mantine/React majors (locked decision §2)](#2026-07-26--infraprocess--dependabot-told-to-stop-proposing-mantinereact-majors-locked-decision-2)
- [2026-07-25 — Docs/Process — README + CONTRIBUTING audited against the post-remediation codebase](#2026-07-25--docsprocess--readme--contributing-audited-against-the-post-remediation-codebase)
- [2026-07-25 — Docs/Process — Interpreter CVEs must be verified at the source before a bump is justified on security grounds](#2026-07-25--docsprocess--interpreter-cves-must-be-verified-at-the-source-before-a-bump-is-justified-on-security-grounds)
- [2026-07-25 — Post-release — Backend runtime bumped Python 3.13 → 3.14 (locked decision revised)](#2026-07-25--post-release--backend-runtime-bumped-python-313--314-locked-decision-revised)
- [2026-07-25 — Post-v1 — List-response envelope standardized behind shared helpers (L13 / APIR-8 deferred half)](#2026-07-25--post-v1--list-response-envelope-standardized-behind-shared-helpers-l13--apir-8-deferred-half)
- [2026-07-25 — Post-v1 — Socket-proxy follow-ups: API-version bound and `DOCKER_GID` blast radius documented (docs only)](#2026-07-25--post-v1--socket-proxy-follow-ups-api-version-bound-and-docker_gid-blast-radius-documented-docs-only)
- [2026-07-24 — Post-release — P3-8 closed: `noUncheckedIndexedAccess` + type-aware ESLint](#2026-07-24--post-release--p3-8-closed-nouncheckedindexedaccess--type-aware-eslint)
- [2026-07-24 — Post-release — #83: a completed authentication is never undone by an in-flight refresh](#2026-07-24--post-release--83-a-completed-authentication-is-never-undone-by-an-in-flight-refresh)
- [2026-07-24 — Post-release — Test-debt back-fill for M19, M20, and M21 (tests only)](#2026-07-24--post-release--test-debt-back-fill-for-m19-m20-and-m21-tests-only)
- [2026-07-24 — Post-release — P3-4: sequence auth refresh against session invalidation](#2026-07-24--post-release--p3-4-sequence-auth-refresh-against-session-invalidation)
- [2026-07-24 — Post-release — Frontend Priority-3 polish batch (P3-1, P3-2, P3-5, P3-6, P3-7, P3-8)](#2026-07-24--post-release--frontend-priority-3-polish-batch-p3-1-p3-2-p3-5-p3-6-p3-7-p3-8)
- [2026-07-24 — Post-v1 — Docker socket proxy migrated `tecnativa` → `wollomatic/socket-proxy` (issue #63, M23/SC-7 deferred half)](#2026-07-24--post-v1--docker-socket-proxy-migrated-tecnativa--wollomaticsocket-proxy-issue-63-m23sc-7-deferred-half)
- [2026-07-20 — Post-release — SC-12: pin and hash-lock the setuptools build backend](#2026-07-20--post-release--sc-12-pin-and-hash-lock-the-setuptools-build-backend)
- [2026-07-20 — Post-release — D5b: pin ruff isort first-party classification so import ordering is version-stable](#2026-07-20--post-release--d5b-pin-ruff-isort-first-party-classification-so-import-ordering-is-version-stable)
- [2026-07-20 — Post-release — SC-14: keep the backend test suite and dev scripts out of the runtime image](#2026-07-20--post-release--sc-14-keep-the-backend-test-suite-and-dev-scripts-out-of-the-runtime-image)
- [2026-07-20 — Post-release — P3-3: surface credential/filter option-fetch failures instead of silently swallowing them](#2026-07-20--post-release--p3-3-surface-credentialfilter-option-fetch-failures-instead-of-silently-swallowing-them)
- [2026-07-20 — Docs/Process — CLAUDE.md: strip auto-appended PR-body attribution footers after opening](#2026-07-20--docsprocess--claudemd-strip-auto-appended-pr-body-attribution-footers-after-opening)
- [2026-07-20 — Post-v1 — Frontend jsdom + React Testing Library test harness](#2026-07-20--post-v1--frontend-jsdom--react-testing-library-test-harness)
- [2026-07-13 — Post-release — H1/SEC-1: repository scan targets must be remote clone URLs (local-path arbitrary-read closed) [back-fill]](#2026-07-13--post-release--h1sec-1-repository-scan-targets-must-be-remote-clone-urls-local-path-arbitrary-read-closed-back-fill)
- [2026-07-13 — Post-release — H9/SC-2 + H10/SC-3: SHA-pin all Actions, expand Dependabot, harden publish checkouts [back-fill]](#2026-07-13--post-release--h9sc-2--h10sc-3-sha-pin-all-actions-expand-dependabot-harden-publish-checkouts-back-fill)
- [2026-07-13 — Docs/Process — CLAUDE.md compliance-drift closure (D1, D2, R1–R6) [back-fill]](#2026-07-13--docsprocess--claudemd-compliance-drift-closure-d1-d2-r1r6-back-fill)
- [2026-07-13 — Post-release — Backend dev-dependency bumps (pytest, pytest-asyncio, black) [back-fill]](#2026-07-13--post-release--backend-dev-dependency-bumps-pytest-pytest-asyncio-black-back-fill)
- [2026-07-13 — Post-release — CON-4 (H5): scanner JSON parse/normalize hopped off the event loop](#2026-07-13--post-release--con-4-h5-scanner-json-parsenormalize-hopped-off-the-event-loop)
- [2026-07-13 — Docs/Process — Squash-merge authorship follows the GitHub profile display name (D4 doc-side)](#2026-07-13--docsprocess--squash-merge-authorship-follows-the-github-profile-display-name-d4-doc-side)
- [2026-07-13 — Docs/Process — dev→main promotion PRs use a plain "Promote dev to main: …" title](#2026-07-13--docsprocess--devmain-promotion-prs-use-a-plain-promote-dev-to-main--title)
- [2026-07-13 — Post-release — Security + supply-chain review batch (H11, M2–M5, M22–M26, L1–L4, L23)](#2026-07-13--post-release--security--supply-chain-review-batch-h11-m2m5-m22m26-l1l4-l23)
- [2026-07-13 — Post-release — Frontend-review wave 2 (M19–M21, L16–L22)](#2026-07-13--post-release--frontend-review-wave-2-m19m21-l16l22)
- [2026-07-13 — Post-release — API-review batch (APIR-1…APIR-10)](#2026-07-13--post-release--api-review-batch-apir-1apir-10)
- [2026-07-13 — Post-release — CON-2/CON-14 remediation: process-group kills for scanner subprocesses](#2026-07-13--post-release--con-2con-14-remediation-process-group-kills-for-scanner-subprocesses)
- [2026-07-13 — Post-release — CON-1/CON-11/CON-3/SEC-2 remediation; worker seam gains optional hooks](#2026-07-13--post-release--con-1con-11con-3sec-2-remediation-worker-seam-gains-optional-hooks)
- [2026-07-13 — Post-release — CON-5–CON-20 remediation: async-path, shutdown, and pool hygiene](#2026-07-13--post-release--con-5con-20-remediation-async-path-shutdown-and-pool-hygiene)
- [2026-07-13 — Security — account-takeover chain fix: XSS sink containment + baseline security headers](#2026-07-13--security--account-takeover-chain-fix-xss-sink-containment--baseline-security-headers)
- [2026-07-13 — Infra — runtime-stage curl/libcurl explicitly version-pinned for CVE-2026-5773](#2026-07-13--infra--runtime-stage-curllibcurl-explicitly-version-pinned-for-cve-2026-5773)
- [2026-07-13 — Infra/Process — CPython interpreter CVEs on 3.13 accepted as tracked risk; 3.14 deferred](#2026-07-13--infraprocess--cpython-interpreter-cves-on-313-accepted-as-tracked-risk-314-deferred)
- [2026-07-09 — Infra/Process — repo goes public; distribution consolidated to GHCR-only](#2026-07-09--infraprocess--repo-goes-public-distribution-consolidated-to-ghcr-only)
- [2026-07-09 — Post-v1 — teal hue refinement, scan deletion, nav active-match fix](#2026-07-09--post-v1--teal-hue-refinement-scan-deletion-nav-active-match-fix)
- [2026-07-09 — Post-v1 — v0.1.0 bundled-binary CVE check: no upstream fix available yet](#2026-07-09--post-v1--v010-bundled-binary-cve-check-no-upstream-fix-available-yet)
- [2026-07-07 — Process — back-merge step after promotion; Dependabot retargeted to `dev`](#2026-07-07--process--back-merge-step-after-promotion-dependabot-retargeted-to-dev)
- [2026-07-06 — Infra — dev publishing moved to a nightly GHCR build (registry split + INF-2 resolved)](#2026-07-06--infra--dev-publishing-moved-to-a-nightly-ghcr-build-registry-split--inf-2-resolved)
- [2026-07-05 — Post-P6 audit remediation (P0) — token-mint capping, backup/restore, webhook URLs](#2026-07-05--post-p6-audit-remediation-p0--token-mint-capping-backuprestore-webhook-urls)
- [2026-07-05 — Post-P6 audit remediation (P1) — availability/performance under real volume](#2026-07-05--post-p6-audit-remediation-p1--availabilityperformance-under-real-volume)
- [2026-07-05 — Post-P6 audit remediation (P2) — supply chain / deployment hardening](#2026-07-05--post-p6-audit-remediation-p2--supply-chain--deployment-hardening)
- [2026-07-05 — Post-P6 audit remediation (P3) — feature gaps that mislead users](#2026-07-05--post-p6-audit-remediation-p3--feature-gaps-that-mislead-users)
- [2026-07-05 — Post-P6 audit remediation (P4) — frontend correctness / UX](#2026-07-05--post-p6-audit-remediation-p4--frontend-correctness--ux)
- [2026-07-05 — Deviation-logging debt from the audit (FE-2, INF-10, API-12, FEAT-4)](#2026-07-05--deviation-logging-debt-from-the-audit-fe-2-inf-10-api-12-feat-4)
- [2026-07-05 — Post-P6 audit remediation (P5) — maintainability, process, long tail](#2026-07-05--post-p6-audit-remediation-p5--maintainability-process-long-tail)
- [2026-07-04 — Post-P6 — Full-repo security audit remediation](#2026-07-04--post-p6--full-repo-security-audit-remediation)
- [2026-07-04 — Post-P6 — Security-audit hotfix (follow-up to the merge above)](#2026-07-04--post-p6--security-audit-hotfix-follow-up-to-the-merge-above)
- [2026-07-04 — Post-P6 — Scanner/report review fixes: diff identity and dashboard grouping revised](#2026-07-04--post-p6--scannerreport-review-fixes-diff-identity-and-dashboard-grouping-revised)
- [2026-07-04 — Phase 6 — Docker Hub publishing (tagged releases + dev continuous build)](#2026-07-04--phase-6--docker-hub-publishing-tagged-releases--dev-continuous-build)
- [2026-07-04 — Process — Adopted a dev/main branching model ahead of going public](#2026-07-04--process--adopted-a-devmain-branching-model-ahead-of-going-public)
- [2026-07-03 — Phase P1 — First-admin bootstrap via explicit setup endpoint](#2026-07-03--phase-p1--first-admin-bootstrap-via-explicit-setup-endpoint)
- [2026-07-03 — Phase P1 — Master key file supports optional multi-version format](#2026-07-03--phase-p1--master-key-file-supports-optional-multi-version-format)
- [2026-07-03 — Phase P2 — Raw artifact bytes stored on the filesystem](#2026-07-03--phase-p2--raw-artifact-bytes-stored-on-the-filesystem)
- [2026-07-03 — Phase P2 — Frontend routing via `react-router-dom` v7](#2026-07-03--phase-p2--frontend-routing-via-react-router-dom-v7)
- [2026-07-03 — Phase P2 — Scan views use Mantine `Table`, not `mantine-datatable`](#2026-07-03--phase-p2--scan-views-use-mantine-table-not-mantine-datatable)
- [2026-07-03 — Phase P2 — Scan cancellation limited to queued scans](#2026-07-03--phase-p2--scan-cancellation-limited-to-queued-scans)
- [2026-07-03 — Phase P3 — Filesystem scans gated behind an allowlist](#2026-07-03--phase-p3--filesystem-scans-gated-behind-an-allowlist)
- [2026-07-03 — Phase P3 — Git authentication mechanism per provider](#2026-07-03--phase-p3--git-authentication-mechanism-per-provider)
- [2026-07-03 — Phase P3 — SBOM generation is an opt-in per-scan pass](#2026-07-03--phase-p3--sbom-generation-is-an-opt-in-per-scan-pass)
- [2026-07-03 — Phase P3 — Registry credential helpers configured but not bundled](#2026-07-03--phase-p3--registry-credential-helpers-configured-but-not-bundled)
- [2026-07-03 — Phase P3 — Runtime deps (httpx, python-multipart) and read scope](#2026-07-03--phase-p3--runtime-deps-httpx-python-multipart-and-read-scope)
- [2026-07-03 — Phase P3 — Security Review #2: generic-host git auth off-argv](#2026-07-03--phase-p3--security-review-2-generic-host-git-auth-off-argv)
- [2026-07-03 — Phase P3 — Security Review #5: credential lists are admin-only](#2026-07-03--phase-p3--security-review-5-credential-lists-are-admin-only)
- [2026-07-03 — Phase P4 — History exposed via a dedicated `/scans/history` endpoint](#2026-07-03--phase-p4--history-exposed-via-a-dedicated-scanshistory-endpoint)
- [2026-07-03 — Phase P4 — Scan tags modeled as a `scan_tags` table, set by operators](#2026-07-03--phase-p4--scan-tags-modeled-as-a-scan_tags-table-set-by-operators)
- [2026-07-03 — Phase P4 — Saved filter presets are owner-scoped](#2026-07-03--phase-p4--saved-filter-presets-are-owner-scoped)
- [2026-07-03 — Phase P4 — Export scope semantics and diff constraints](#2026-07-03--phase-p4--export-scope-semantics-and-diff-constraints)
- [2026-07-03 — Phase P4 — History view uses the base Mantine `Table`, not `mantine-datatable`](#2026-07-03--phase-p4--history-view-uses-the-base-mantine-table-not-mantine-datatable)
- [2026-07-03 — Phase P5 — Runtime settings stored in a generic `settings` table](#2026-07-03--phase-p5--runtime-settings-stored-in-a-generic-settings-table)
- [2026-07-03 — Phase P5 — Dependencies added: Authlib and pyotp](#2026-07-03--phase-p5--dependencies-added-authlib-and-pyotp)
- [2026-07-03 — Phase P5 — OIDC uses Authlib's `jose`, isolated behind an import shim](#2026-07-03--phase-p5--oidc-uses-authlibs-jose-isolated-behind-an-import-shim)
- [2026-07-03 — Phase P5 — OIDC provisioning: username sanitization and admin-group mapping](#2026-07-03--phase-p5--oidc-provisioning-username-sanitization-and-admin-group-mapping)
- [2026-07-03 — Phase P5 — TOTP MFA: two-step enrollment and in-process login challenge](#2026-07-03--phase-p5--totp-mfa-two-step-enrollment-and-in-process-login-challenge)
- [2026-07-03 — Phase P5 — API tokens: bearer auth, CSRF exemption, and role capping](#2026-07-03--phase-p5--api-tokens-bearer-auth-csrf-exemption-and-role-capping)
- [2026-07-03 — Phase P5 — Notifications: channels + test-send now; event dispatch deferred](#2026-07-03--phase-p5--notifications-channels--test-send-now-event-dispatch-deferred)
- [2026-07-03 — Phase P5 — Scanner DB schedule/offline-import stored but not yet actuated](#2026-07-03--phase-p5--scanner-db-scheduleoffline-import-stored-but-not-yet-actuated)
- [2026-07-03 — Phase P5 — Backup bundle is a logical row dump with passphrase re-wrap](#2026-07-03--phase-p5--backup-bundle-is-a-logical-row-dump-with-passphrase-re-wrap)
- [2026-07-03 — Phase P5 — Scheduled backups run on an in-process asyncio loop](#2026-07-03--phase-p5--scheduled-backups-run-on-an-in-process-asyncio-loop)
- [2026-07-03 — Phase P5 — Self-service Account page; role-gated Settings tabs](#2026-07-03--phase-p5--self-service-account-page-role-gated-settings-tabs)
- [2026-07-03 — Phase P5 — Security review hardening: OIDC alg allowlist + scrypt work factor](#2026-07-03--phase-p5--security-review-hardening-oidc-alg-allowlist--scrypt-work-factor)
- [2026-07-03 — Phase P6 — Branch name `phase/P6`](#2026-07-03--phase-p6--branch-name-phasep6)
- [2026-07-03 — Phase P6 — Cron scheduling via a self-contained evaluator](#2026-07-03--phase-p6--cron-scheduling-via-a-self-contained-evaluator)
- [2026-07-03 — Phase P6 — Notification dispatch: per-channel event subscriptions](#2026-07-03--phase-p6--notification-dispatch-per-channel-event-subscriptions)
- [2026-07-03 — Phase P6 — Trivy VEX/ignore applied via env vars, ignore rules structured](#2026-07-03--phase-p6--trivy-vexignore-applied-via-env-vars-ignore-rules-structured)
- [2026-07-03 — Phase P6 — Dashboard "open" posture from the latest scan per target](#2026-07-03--phase-p6--dashboard-open-posture-from-the-latest-scan-per-target)
- [2026-07-03 — Phase P6 — `/metrics` is authenticated; hand-rolled exposition](#2026-07-03--phase-p6--metrics-is-authenticated-hand-rolled-exposition)
- [2026-07-03 — Phase P6 — Retention prunes raw artifacts only; config in the settings table](#2026-07-03--phase-p6--retention-prunes-raw-artifacts-only-config-in-the-settings-table)
- [2026-07-03 — Phase P6 — Dogfood self-scan gates on fixable High/Critical with triage allowlists](#2026-07-03--phase-p6--dogfood-self-scan-gates-on-fixable-highcritical-with-triage-allowlists)
- [2026-07-03 — Phase P6 — Fix wrong `debian:bookworm-slim` base digest](#2026-07-03--phase-p6--fix-wrong-debianbookworm-slim-base-digest)
- [2026-07-03 — Phase P6 — Dogfood gate excludes the bundled scanner binaries](#2026-07-03--phase-p6--dogfood-gate-excludes-the-bundled-scanner-binaries)
- [2026-07-03 — Phase P6 — Dogfood-driven dependency bumps (FastAPI/Starlette/multipart)](#2026-07-03--phase-p6--dogfood-driven-dependency-bumps-fastapistarlettemultipart)
- [2026-07-03 — Phase P6 — Grype gate excludes the CPython interpreter binary](#2026-07-03--phase-p6--grype-gate-excludes-the-cpython-interpreter-binary)
- [2026-07-03 — Phase P6 — Bundled Trivy bumped 0.71.2 → 0.72.0](#2026-07-03--phase-p6--bundled-trivy-bumped-0712--0720)
- [2026-07-03 — Phase P6 — Backend runtime bumped Python 3.12 → 3.13 (locked decision revised)](#2026-07-03--phase-p6--backend-runtime-bumped-python-312--313-locked-decision-revised)
- [2026-07-03 — Phase P6 — Scanner temp/cache dirs pinned to the writable `/cache` volume; `/tmp` tmpfs owned by the app uid](#2026-07-03--phase-p6--scanner-tempcache-dirs-pinned-to-the-writable-cache-volume-tmp-tmpfs-owned-by-the-app-uid)
- [2026-07-03 — Phase P6 — Scanner cache redirected via env vars for **every** invocation (incl. probes)](#2026-07-03--phase-p6--scanner-cache-redirected-via-env-vars-for-every-invocation-incl-probes)
- [2026-07-03 — Post-P6 bug-fix round — `/tmp` tmpfs kept at 200 MB; footprint documented; cache/staging fix re-verified live end-to-end](#2026-07-03--post-p6-bug-fix-round--tmp-tmpfs-kept-at-200-mb-footprint-documented-cachestaging-fix-re-verified-live-end-to-end)
- [2026-06-30 — Phase 0 — Scanner versions bumped to current releases](#2026-06-30--phase-0--scanner-versions-bumped-to-current-releases)
- [2026-06-30 — Phase 0 — Optional sidecars gated behind Compose profiles](#2026-06-30--phase-0--optional-sidecars-gated-behind-compose-profiles)
- [2026-06-30 — Phase 0 — Branch name `phase/P0`](#2026-06-30--phase-0--branch-name-phasep0)

---

### 2026-08-11 — Post-v1 — #176 part 2: findings 4 and 6 replaced (keyed remount; reconcile-in-load), and `set-state-in-effect` enabled at `'warn'` rather than the preset `'error'`

**What changed:** the two remaining genuine `react-hooks/set-state-in-effect` sites — the ones
#176's "Do not fix 4 and 6 blind" section covers — are replaced behaviour-preservingly, and the
rule's override in `frontend/eslint.config.js` moves from `'off'` to **`'warn'`**, a maintainer
decision recorded below. The rule now takes effect for the first time. #176 stays open for the
maintainer to close by hand.

**Finding 4 (`ScanDetailPage`, `L17`/`P2-2`) — the reset effect became a keyed remount.** The
per-`:scanId` reset effect (11 setStates plus 2 ref writes) is deleted. In its place `App.tsx`
mounts the page through a new `ScanDetailRoute` wrapper in `ScanDetailPage.tsx` —
`<ScanDetailPage key={scanId} />` — so React unmounts and remounts the component whenever the id
changes, which is the compiler-idiomatic replacement #176 itself names. Behaviour is preserved
because a remount resets strictly everything the effect reset: all state and both refs come back
to their initial values, and the mount effects then run for the new id in the same order the reset
path produced (`getScan`, then artifacts/findings once the new scan's own status allows).

**The remount enumeration** — what could have depended on component instance identity across
`/scans/:id` navigations, checked item by item:

- **State.** The effect reset 11 of the component's stateful values; a remount resets those 11
  plus the three the effect never covered — `savingTags`, `deleting`, and the delete-confirm
  modal's `confirmOpened`. That is the one observable delta, and it is fully characterised: a
  delete-confirm modal open at the moment of navigation previously *stayed open and re-targeted
  the new scan* (its text and its `remove()` closure both read the post-navigation id), where it
  now closes; an in-flight `saveTags` previously left its button loading and, on settling, wrote
  the **old** scan's server response into the view now showing the new id. Both deltas are in the
  safe direction — the lingering modal could delete a scan the operator never confirmed.
- **Refs.** `findingsGuard` and `lastSyncedTags` are recreated fresh, equivalent to the effect's
  `begin()` / `[]` resets.
- **In-flight requests of the old scan.** Their resolutions now land on the unmounted instance as
  no-ops. Under the effect version, a late `getScan(oldId)` resolution could repaint the old
  scan's header and tags *over* the new id's loading view — `loadScan` has no latest-wins guard,
  and the reset effect could not cancel an already-started promise. The remount closes that
  window outright.
- **The status poll.** Its effect cleanup (`cancelled = true`, `clearTimeout`) runs on unmount
  exactly as it ran on dependency change; no timer survives.
- **Scroll and focus.** Identical under both versions: navigation collapses the subtree to the
  "Loading scan" state either way, and the app has no scroll restoration.
- **Nothing outside the component consumes its instance** — it provides no context, registers no
  external listeners, and no parent holds a ref into it. Other routes are untouched.
- **The key granularity.** The key is the raw `:scanId` param string where the effect keyed on
  `Number(scanId)`; the two differ only for aliasing spellings of one id (`/scans/01` vs
  `/scans/1`), which no in-app link produces — and there the keyed version remounts where the
  effect would not have reset, the safe direction.

**The test-harness consequence, stated because a regression-test file changed:**
`ScanDetailPage.scanIdReset.test.tsx` mounted `<ScanDetailPage />` bare inside its own `<Routes>`,
bypassing `App.tsx` — with the protection now living on the route element, that harness would have
exercised nothing and failed. Its route element is now `<ScanDetailRoute />`, the exact
arrangement the app ships; every assertion in the test is unchanged.
(`ScanDetailPage.findingsSpinner.test.tsx` still mounts the page bare — it never navigates, so no
id changes under it.)

**Finding 6 (`ScansPage`, `P3-2`) — the reconcile effect moved into `load()`.** `load()` is the
only place `data` — the visible rows — is ever set, so the effect that reconciled the compare
selection "whenever the rows change" fires on exactly the renders that follow a `load()`
resolution and no others. The same reconciliation (drop any selected id not in the incoming
rows, keep the array identity when nothing was dropped) now runs inside `load()` immediately
after `setData`, behind the same latest-wins guard. Behaviour is preserved — same trigger set,
same reconciliation — minus one frame: the effect version committed a render in which the new
rows and the stale selection coexisted (the phantom "1/2 selected") before correcting itself;
the two setStates now batch into a single commit.

**Fail-first verification, per regression test.** Naive version = the effect deleted with no
replacement (for finding 4, the wrapper rendering `<ScanDetailPage />` without the key; for
finding 6, `load()` without the reconcile block):

- `ScanDetailPage.scanIdReset.test.tsx` — against naive: **FAILED on its first in-flight
  assertion**, exactly as #176 predicted (`findByText('Loading scan')` times out with scan 1's
  target still rendered). Against the replacement: passes.
- `ScansPage.compare.test.tsx`, "drops a selection that filters/pages out" — against naive:
  **FAILED** (the phantom "Compare scans" button survives the reload). Against the replacement:
  passes.
- `ScansPage.compare.test.tsx`, "drops a selected scan that was deleted" — against naive:
  **passed; it failed to fail.** All three of its assertions held vacuously: the deleted row's
  checkbox leaves the DOM because the row itself left the table, the surviving scan's checkbox
  reads checked from the stale snapshot too, and the Compare button is present under both
  versions. The observable that actually discriminates — the bar reads "Comparing 1/2 selected"
  with Compare disabled, versus a stale "2/2" with Compare *enabled against the deleted scan* —
  was never asserted. With maintainer approval the test was strengthened by exactly those two
  assertions, then re-proven: against naive it now **FAILS** (`Comparing 1/2 selected` not
  found), against the replacement it passes. The gap predates this change — the test was added
  by #178 for an effect that already worked, so its fail-first property was never established
  the way the scanIdReset test's was.

**How the rule-flip tension resolved, and on what evidence.** Part 1 flagged that #176's
definition of done — override removed *and* `npm run lint` clean *and* the fetch-on-mount
findings not suppressed — cannot all hold. Measured on the refactored tree: the installed
`eslint-plugin-react-hooks@7.1.1`'s `configs.recommended` assigns `set-state-in-effect` severity
**`error`** (read from the plugin's config object directly); with the override removed,
`npm run lint` (bare `eslint .`, no `--max-warnings` anywhere, including CI's identical
invocation) reports **13 problems (13 errors, 0 warnings)** and exits 1. Findings 4 and 6 no
longer report; the 13 are the fetch-on-mount population — the 12 loaders plus
`ScanDetailPage`'s `void loadFindings()`, the migrated finding-5 line part 1 documented. Every
path to a clean lint therefore suppresses them in some form, which is the decision #176 did not
contain. The maintainer chose **`'warn'`** (2026-08-11) over the alternatives — 13 per-site
`eslint-disable`s (honest but heavy against the disables-are-last-resort rule), keeping the rule
`'off'` (the rule never takes effect), or the data-fetching refactor (out of scope, its own
decision). Result: the rule is live and visible, lint and CI pass at 0 errors / 13 warnings, and
the accepted cost is that a **new, genuine** synchronous-setState site also arrives as a warning
rather than an error — the config comment tells reviewers to read any change in this rule's
report count rather than scroll past it.

**The 12 fetch-on-mount findings are deliberately untouched:** no `eslint-disable`, no call-site
wrapping, no loaders-behind-a-hook refactor. Per #176 there is no fix for them that is an actual
improvement — the report tracks what the compiler can see, not a behavioural difference — so they
now warn, undisguised.

**Verification:** `npm run lint` exit 0 — **0 errors, 13 warnings**, all
`react-hooks/set-state-in-effect` · `npm run format:check` clean · `npm test` **26 files / 96
tests** passing (unchanged from part 1) · `npm run build` (`tsc -b` + Vite) clean.

**Plan section affected:** §14 (this log); `docs/upgrades/frontend-toolchain-86.md` Step 3, whose
held-back rule is now enabled at `'warn'`. No locked decision, schema, security-model, routing
behaviour beyond the one route element, or data-fetching layer was touched.

---

### 2026-08-11 — Docs/Process — `.claude/settings.json` deleted outright after three failed settings-layer attempts; the strip-`PATCH` rule reinstated with a one-attempt cap

**What changed:** the committed `.claude/settings.json` is **deleted from the repository in full**,
and the strip-`PATCH` instruction it was supposed to make unnecessary is **reinstated in CLAUDE.md
and CONTRIBUTING.md, capped at one attempt per body**. The two halves are one decision: the settings
file was the entire reason the strip rule was removed, so removing the file puts the burden back
where it was.

**1. The settings file is gone — every key, not a subset.** `.claude/settings.json` held the
`attribution` block added by **#197** (`commit: ""`, `pr: ""`, `sessionUrl: false`) and the
`includeGitInstructions: false` key added by **#200**. Nothing from it survives; there is no
partial preservation of either key set, and no replacement file. The `.gitignore` comment block
that explained why the file was tracked is rewritten to say the opposite — the file is deliberately
absent — while still ignoring `.claude/settings.local.json` and still barring a blanket `.claude/`
rule, so a future committed setting is an explicit choice rather than something silently ignored.

**Why: three sequential attempts at the settings layer, none of which stopped the footer.**

1. **#197** added the `attribution` block on the reasoning that the footer is a harness feature
   configured in settings, and that project scope is the only scope reaching a Cloud session.
2. **#199** opened after that block was live and its PR body still carried a "Generated by Claude
   Code" footer with a session URL. **#200** read that as the block not reaching the PR-creation
   path specifically, and added `includeGitInstructions: false` as a second, independent lever —
   explicitly recording that its real test would be the first PR opened by a session running with
   the merged file.
3. **#201** was that test. It ran with both #197's and #200's keys merged and live, and **still got
   a footer on its PR body**, which that session attributed to **"the harness"** rather than to
   anything Claude Code settings govern.

That is three attempts, each addressing the previous one's diagnosed gap, with the observable
outcome unchanged. **The settings-file approach is judged not to have worked, and is fully
abandoned — not paused, not deferred pending a better key.** Do not reintroduce a
`.claude/settings.json` to suppress the footer; a future session that finds this entry and thinks
"they just needed one more key" is repeating a loop that has already run three times. (What "the
harness" actually is remains undiagnosed and was deliberately not investigated here.)

**2. The strip is reinstated, with a hard cap of one attempt per body.** CLAUDE.md § Attribution
and CONTRIBUTING.md § Pull request process step 4 now both say: after opening a PR or posting an
issue comment, re-read the live body via the API; if a footer is present, issue **one** `PATCH` to
remove it and re-read once to confirm; if the footer is re-appended, **stop** and report it in the
session summary as *"strip attempted, did not hold."* Never a second attempt on the same body.

**The cap's reason is stated inline in both files, not just here**, because the cost it bounds is
real and was the entire basis for #197's prohibition: each `PATCH` executes under a **bot identity**
and leaves a permanent, publicly visible **"claude (Bot)"** entry in GitHub's edit history. **#196**
recorded exactly two such entries from two attempts, with the footer surviving both. One attempt
still tries to produce a clean body; the second has never once changed the outcome and only doubles
the visible bot attribution. So this is not a straight revert of #197 — it accepts #197's evidence
in full and prices it, rather than disputing it.

**CLAUDE.md now states plainly that this strip is the *only* mechanism suppressing the footer**,
since no settings-level backstop exists any more. The commit-authorship half is untouched: the
`git log --format="%an <%ae>%n%B"` verification and the repo-local git-identity commands stay exactly
as they were, and the section says so explicitly — that part has always worked and is independent of
the strip. The § Git & PR conventions git-identity bullet and § Definition of done item 8, both of
which described the old state, are corrected to match.

**This is the fourth reversal of this policy. Read the chain before changing it a fifth time:**

| # | When | State |
|---|------|-------|
| — | 2026-07-20 | Strip rule first written: re-read the PR body after opening and strip the footer. |
| 1 | 2026-08-09 (settings audit) | Stripping **banned**. |
| 2 | 2026-08-09 (**#169**) | Ban **reversed** hours later, back to strip-and-reverify — with no §14 entry, which is why the same-PR-entry requirement exists. |
| 3 | 2026-08-11 (**#197**) | Stripping **prohibited** again, on the #196 bot-attribution evidence, with the settings file as the replacement fix. |
| 4 | 2026-08-11 (**this entry**) | Strip **reinstated**, capped at one attempt, because the replacement fix demonstrably did not work. |

Stated plainly so the pattern is visible rather than rediscovered: this policy has flipped four
times in three weeks, twice on the same day. Each flip was locally reasonable on the evidence in
front of it. What is *new* here is not another argument about bot identity versus footer visibility
— #197 already settled that trade in the abstract — it is the empirical result that the alternative
#197 traded *for* does not exist. If a fifth change is proposed, the thing to check first is whether
it brings new evidence or merely re-weighs the same two costs.

**First outcome, recorded immediately: the strip held on this PR's own body.** #202 was opened, its
live body re-read, a footer found (`_Generated by [Claude Code](…/session_…)_`), **one** `PATCH`
issued per the reinstated rule, and the confirming re-read came back clean. That is the first time
a strip has succeeded in this project. Two things bound how much that result proves:

- **It says nothing about the append, only possibly about the re-append.** The footer *appeared on
  creation* in the session that wrote this entry, with #197's `attribution` keys and #200's
  `includeGitInstructions` still live and merged — the same outcome #201 got. So the settings keys
  demonstrably did **not** suppress the append itself. The only step where they could have
  contributed is the **re-append after the `PATCH`** — whether `attribution.pr` suppresses the
  server's rewrite on a body edit. That remains an **open question, and it is now unfalsifiable**
  from inside this repo: the file is deleted, so the configuration under which this success
  happened cannot be reproduced here. Do not read this outcome as evidence that the keys were
  worthless, and do not read it as evidence they helped — neither claim is supported.
- **The next PR is a harder test than this one was.** The deletion does not take effect until this
  PR merges, so the session that opened #202 still ran with both key sets loaded. Every session
  after the merge runs with no settings file at all. The first PR opened by such a session is the
  real test of the reinstated rule, against a strictly weaker starting position than the one that
  just succeeded. If the strip fails there, that is not a contradiction of this entry — it is the
  harder case finally being run.

Also note the surface difference from the failures that motivated #197: **#196's two failed strips
were on an issue comment; this success was on a PR body.** A single success on a different surface
does not refute #196, and the one-attempt cap is calibrated for the case where it fails, not the
case where it holds.

**Addendum (2026-08-11, after #203): the harder test ran, and the strip held again.** #203 — the
first PR opened by a session running with **no `.claude/settings.json` at all**, the strictly
weaker starting position the paragraph above predicted — got a footer appended on creation, one
`PATCH` per the rule, and a clean confirming re-read. That is **two strip successes in a row on PR
bodies since the reinstatement**: #202's under both key sets still live, #203's with nothing at the
settings layer — no `attribution` keys, no `includeGitInstructions`. Two-for-two post-reversal is a
real trend, not one lucky data point. It also narrows the open question above in the only direction
available: whatever role the settings keys played in #202's hold, #203 held **without them**, so
they are not *needed* for a strip to hold (whether they ever *contributed* remains unfalsifiable
here, as stated). **Still no signal either way on issue comments** — none has been posted since the
reinstatement, so #196's failed surface remains untested against the capped rule.

**Known drift, outside this repo:** the synced `scrye` skill
(`~/.claude/skills/synced/scrye/SKILL.md`) carries its own copy of the prohibition in its
§ "Git identity and attribution", including the #196 reasoning and a paragraph asserting the footer
"is addressed at its source by the committed `.claude/settings.json`". After this change the skill
is stale on **both** points — it forbids what CLAUDE.md now requires, and it points at a file that
no longer exists. It lives outside the repository and could not be changed in this PR; per the
2026-08-11 precedence entry (#198), repo files win over the synced skill where they disagree, so a
session reading both should follow CLAUDE.md. Flagged here so the skill's source gets re-synced.

**Deliberately not done:** no retroactive cleanup of footers on existing PRs, issues, or comments;
no investigation into what "the harness" is; nothing touched on #201's branch; no replacement
settings key of any kind.

**Plan section affected:** CLAUDE.md § Attribution (rewritten), § Git & PR conventions
(git-identity bullet), § Definition of done (item 8); CONTRIBUTING.md § Pull request process step 4;
`.gitignore` § Claude Code comment block; `.claude/settings.json` (deleted). Docs/settings only — no
application code, schema, API contract, security-model, job-model, auth, gate threshold, or
waiver-membership change.

---

### 2026-08-11 — Post-v1 — #176 part 1: findings 1, 2, 3 and 5 refactored off synchronous setState-in-effect; findings 4 and 6 and the rule flip deferred to a follow-up

**What changed:** four of the six genuine `react-hooks/set-state-in-effect` sites #176 enumerates
were refactored so they no longer call setState synchronously from an effect body. Behaviour is
preserved at every site. **`frontend/eslint.config.js` is untouched** — the rule stays `'off'`, its
override and comment exactly as they were.

**Why the issue is being done in two sittings.** #176's own "Do not fix 4 and 6 blind" section is
the reason: findings 4 (`ScanDetailPage`'s per-`:scanId` reset, `L17`/`P2-2`) and 6 (`ScansPage`'s
compare-selection reconciliation, `P3-2`) are deliberate effects that each closed a real bug, and
each has a regression test standing over it. Replacing them needs its own reasoning — finding 4's
compiler-idiomatic replacement is a `key` prop on the route element, i.e. a change in a *different*
file with its own check that nothing depends on instance identity across navigations. That work,
and the removal of the override, are a follow-up. Neither effect was touched here beyond the single
substitution recorded below, and neither regression test was edited.

**The sites, re-located rather than trusted.** #176's line numbers predate #177 and have shifted, so
the rule was temporarily enabled against a throwaway config that extends the real one, and the
sites read out of its output. It reported **18**, and the 6-vs-12 split matched the issue exactly —
including that `NewScanPage.tsx:124` (`if (canLaunch) void loadTargets()`) is the twelfth
fetch-on-mount site, not finding 3.

**What replaced each of the four:**

1. **`LoginPage.tsx` — `oidc_error` banner.** The mount effect that called `setError(...)` and then
   `history.replaceState` is split. The message is now seeded by a lazy `useState` initializer via a
   module-level `oidcErrorCode()` helper — the value is knowable from the URL before anything
   renders, so nothing about it needs an effect. The effect that remains does only the
   `replaceState`, which is the part that genuinely touches something outside React.
2. **`components/settings/OidcLinkCard.tsx` — `oidc_link` / `oidc_link_error` banners.** Same shape,
   same treatment: both banners are seeded by lazy initializers over a shared `linkParams()` helper,
   and the effect keeps only the `replaceState`. Both parameters are still honoured independently,
   including the unknown-code fallbacks.
3. **`NewScanPage.tsx` — scanner clamped to the target type.** The effect maintaining derived state
   (`if (!allowed.includes(scanner)) setScanner(allowed[0])`) is gone; the clamp moved into a
   `chooseTargetType` handler wired to the target-type control. That control is the only thing that
   can invalidate the pairing — the scanner picker only ever offers the current type's own scanners
   — so the invariant is unchanged and now holds at every commit rather than from the second one.
   **Deliberately not** a derive-during-render (`allowed.includes(scanner) ? scanner : allowed[0]`):
   that would *shadow* the displaced choice instead of overwriting it, so leaving a target type and
   returning would resurrect a scanner the user is no longer on. The clamp stays destructive, as it
   was. A test pins that specific difference.
4. **`ScanDetailPage.tsx` — findings loading state.** `findingsLoading` existed only to be flipped
   `true` synchronously at the top of `loadFindings`, which *was* the report. It is replaced by
   `findingsSettledKey` plus a derived
   `findingsLoading = scan?.status === 'succeeded' && findingsSettledKey !== findingsKey`, where
   `findingsKey` is `${id}|${severityFilter}|${classFilter}`. The settle now happens in both
   post-`await` branches of `loadFindings` rather than in a `finally`. Superseded requests still
   leave the spinner up, because the latest-wins guard makes them return before settling the key.
   **This fixes a real flash:** the commit in which the scan became `succeeded` previously rendered
   an empty findings list with the loader already down, i.e. "No findings match the current filters"
   over a request that had not answered yet.

**The one touch to finding 4, and the maintainer decision behind it.** Removing `findingsLoading`
leaves `setFindingsLoading(false)` inside the per-`:scanId` reset effect uncompilable. The
maintainer was asked and chose **substitution over deletion**: the line is now
`setFindingsSettledKey(null)`. The effect keeps its structure, its comment and its intent — reset
every piece of per-scan state — and `ScanDetailPage.scanIdReset.test.tsx` is unaffected and still
passes. (Deletion would also have been correct: `findingsKey` embeds the scan id, so a settled key
from the previous scan can never match the new one. Substitution was preferred as the smaller
touch.)

**Fail-first verification, per site.** Each site got a test that fails against the pre-refactor
version of *that file* and passes against the new one, checked by reverting the single file with
`git checkout HEAD --` and re-running. Because these are behaviour-preserving refactors, the
biting assertion in each case is about *which commit* the correct value appears in — which is
exactly what the rule is about — while the surrounding assertions pin the behaviour and pass
against both versions:

| Site | New test file | The assertion that bites | Pre-refactor result |
|---|---|---|---|
| 1 | `pages/LoginPage.oidcError.test.tsx` | the banner is present in the **first** commit | `expected false to be true` |
| 2 | `components/settings/OidcLinkCard.callback.test.tsx` | exactly **1** commit before the status fetch lands | `expected 2 to be 1` |
| 3 | `pages/NewScanPage.scannerClamp.test.tsx` | **no** commit has zero scanner options selected | `[1,1,…] to not include +0` |
| 5 | `pages/ScanDetailPage.findingsSpinner.test.tsx` | **no** commit says "no findings match" while the first request is in flight | `[Array(11)] to not include true` |

Per-commit observation is done with React's `<Profiler onRender>`, which fires once per commit with
that commit's DOM already in place. Testing Library's `render` flushes passive effects inside
`act`, so a plain post-render assertion cannot see the intermediate state at all and would have
passed against both versions.

**The measurement afterwards, and where it does not match #176's expectations.** With the rule
temporarily re-enabled the count is **15**, not the 14 a clean removal of four sites would predict.
Sites 1, 2 and 3 are gone outright. **`ScanDetailPage.tsx`'s `void loadFindings()` still reports** —
and the reason matters for whoever takes the follow-up:

- **The genuine defect #176 named for finding 5 is fixed.** The issue's own words are that it is
  "reported because `loadFindings` opens with a synchronous `setFindingsLoading(true)` before its
  first `await`". There is no longer any setState before the first `await`.
- **What remains is the analyser artifact #176 documents for the other 12.** Probed against the
  installed 7.1.1 with four-shape variants: `void load()` reports even when `load`'s *only* setState
  follows an `await` and there is no `try`/`catch` at all; adding a `try`/`catch` reports even when
  the `catch` calls no setState whatsoever. The only shapes that went silent were ones where the
  compiler evidently bails on the function (a ref read guarding an early return after the `await`) —
  a bailout, not a fix. So there is no honest shape that clears this line, which is precisely
  #176's own finding about the fetch-on-mount population.
- **Therefore finding 5 has migrated into that population.** The line is now reported on exactly the
  same footing as the 12 the issue puts out of scope, and #176's attribution of the report to the
  synchronous flip was, on this evidence, imprecise — the report would have stood without it.

**A consequence the follow-up has to confront, recorded here so it is not rediscovered late.**
#176's definition of done pairs "remove the override" with "`npm run lint` is clean". Those cannot
both hold: the 12 fetch-on-mount findings are reported at `error`, they are explicitly out of scope,
and the issue says there is no fix for them that is an improvement. Enabling the rule therefore
needs a decision the issue does not currently contain — a per-site disable, a `'warn'` severity, the
data-fetching-layer refactor, or leaving the rule off. Not resolved here; flagged for the session
that does findings 4 and 6.

**Verification:** `npm run lint` clean · `npm run format:check` clean · `npm test` **26 files / 96
tests** passing (was 22/80 at #178; +4 files, +16 tests) · `npm run build` clean · `tsc -b` clean.

**Plan section affected:** §14 (this log); `docs/upgrades/frontend-toolchain-86.md` Step 3, which
now records that its held-back rule closes out in two parts. No locked decision, schema, security
model, routing configuration or data-fetching layer was touched. #176 stays **open**.

---

### 2026-08-11 — Docs/Process — `includeGitInstructions: false` added to `.claude/settings.json`; a standing PR-body content rule added to CLAUDE.md

**What changed:** two related fixes for the same underlying problem — a session's PR bodies
carrying attribution/process boilerplate — landed together because CLAUDE.md § Attribution
requires an attribution-policy change to carry its §14 entry in the same PR.

**1. `.claude/settings.json` gained `"includeGitInstructions": false`.** Nothing else in the file
changed; the `attribution` block (added by PR #197) stays exactly as it was. `includeGitInstructions`
is a real, released settings key (Claude Code changelog v2.1.64) that removes the built-in
commit/PR workflow instructions from the system prompt — the counterpart env var is
`CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS`. It is undocumented in the settings reference table as of
this writing but present in the published JSON schema
(`https://json.schemastore.org/claude-code-settings.json`) as a top-level boolean, default `true`,
with no scope restriction; the settings file was validated against that schema before this landed
(strict validation, since project-scope settings reject the whole file on a schema failure).

**Why this and not just the attribution block.** #199 ran after PR #197's attribution block was
already live, in the same session that later did a clean, footer-free direct API edit to issue
#52's body. That pairing is the evidence: #199's PR body still came back with a
"Generated by Claude Code" footer carrying a session URL, while the same session's issue-body edit
came back clean. So the attribution keys are not inert — the footer append is specific to the
PR-creation path, a different mechanism than `attribution.pr` governs, and `includeGitInstructions`
is what actually controls the built-in PR-workflow instructions that path runs on.

**This is a second attempt at the same problem, not a replacement for the first.** The attribution
block stays untouched and is still the intended fix for the footer itself; this is an additional,
independent lever aimed at the mechanism #199 showed the block alone didn't reach on the
PR-creation path. Whether it actually suppresses the footer is untested as of this entry — the test
is the first PR opened by a session after this change merges to `dev`, not this PR's own body
(`includeGitInstructions` only takes effect for sessions that load the merged settings file).

**Known tradeoff, accepted:** sessions running with `includeGitInstructions: false` lose the
built-in git/PR workflow guidance from the system prompt, so `CLAUDE.md` becomes the sole source of
git conventions for this repo. `CLAUDE.md` § Git & PR conventions already documents branching, the
squash-vs-merge-commit distinction, the promotion procedure, and git identity setup in enough
detail that this is judged an acceptable cost, not a gap — but it is a real cost, taken
deliberately, not a side effect that went unnoticed.

**2. CLAUDE.md gained a standing PR-body content rule**, in § Git & PR conventions, immediately
after the deviations-logging bullet: a PR body describes the change, for a reader of the
repository, not a session report. It bars four categories from ever appearing in a PR body, issue
body, or issue comment — git-identity/authorship self-verification, attribution-footer status
narration, statements about the session's own merge permissions or what CLAUDE.md allows it to do,
and meta-commentary about task scope or which stop conditions fired — and says where that content
belongs instead (the session's chat summary to the maintainer). The rule states its own reason
inline (this content reads as process boilerplate to anyone outside the session, on a public repo)
so a future session encountering it doesn't reinstate the pattern as a helpful addition.

**This entry's own PR is the first test of the CLAUDE.md rule, immediately.** Its body covers only
the settings change and the CLAUDE.md rule with their evidence — no authorship-check narration,
footer-status commentary, merge-permission statements, or scope/stop-condition meta-commentary. If
a footer appears on that PR body regardless (plausible, since `includeGitInstructions` isn't live
until this PR merges), it is left in place per the unchanged never-PATCH rule and reported in the
session's chat summary, not folded into the PR body itself.

**Not changed, deliberately:** the never-PATCH rule in CLAUDE.md and CONTRIBUTING.md, both left
exactly as PR #197 wrote them — this is the settings fix being tested in isolation first, and if it
works there is nothing to strip and the never-PATCH rule is harmless dead text; the `attribution`
block; anything on #199's branch; any footer already posted on an existing PR, issue, or comment
(no retroactive cleanup); `CONTRIBUTING.md`, which does not get the PR-body rule for now.

**Plan section affected:** CLAUDE.md § Git & PR conventions, § Attribution (cross-reference only —
its own text is unchanged). Docs/settings only — no application code, schema, API contract,
security-model, job-model, auth, gate threshold, or waiver-membership change.

---

### 2026-08-11 — Security/Process — Issue #52 (CVE-2025-15367, poplib) re-verified against the now-pinned v3.14.7 tag; cross-references to the closed #98/#116 retargeted to their new tracking location

**What changed:** #52's issue body and `ci/grype.yaml`'s Group B comment block, both re-verified
and re-dated — **not** a change of decision. The acceptance stands unchanged: CVE-2025-15367
remains waived on any interpreter below 3.15.

**Why this was needed.** #52's source-verification table was dated 2026-07-26 and named
`v3.14.6` as "the pinned runtime." PR #195 moved the runtime to 3.14.7 that same day (2026-08-11,
see the two entries above). Per this repo's issue convention (§ Issue conventions), a body's
verification section must cover exactly the state it claims to cover — a stale "the pinned
runtime" row naming a version the project no longer runs is precisely the failure mode that
convention exists to prevent. Separately, #52 cross-referenced #98 as a live Group A tracker;
#98 (and #116, though #52 never named #116 directly) were closed the same day, with their
tracking moved into `ci/grype.yaml` plus this log (see the entry above). A body pointing at a
closed issue as a live tracker is stale in the same way.

**Re-verification method.** Per CLAUDE.md § Dependency hygiene, verified independently at the
source rather than trusting #52's existing table, PR #195's archive entry, or Grype's `FIXED IN`
column: `Lib/poplib.py` fetched directly from the `v3.14.7` tag and from `main` (shallow clone,
`git show v3.14.7:Lib/poplib.py` / `git show origin/main:Lib/poplib.py`). Result — unchanged from
2026-07-26:

| ref | `POP3._putcmd()` guard |
| --- | --- |
| `main` | present — `if re.search(b'[\x00-\x1F\x7F]', line): raise ValueError('Control characters not allowed in commands')` |
| `v3.14.7` (the pinned runtime) | **absent** — `_putcmd()` hands the line straight to `_putline()` |

Also re-checked gh-143923 for any backport PR that has appeared since 2026-07-26: none has. PR
#143924 (the `main` fix, merged 2026-01-20) carried backport labels for 3.10–3.14 before merge;
all were removed prior to merging over a stated backward-compatibility concern (control characters
such as tab/backspace are RFC-violating but in current use, and a backport would break that). No
open backport PR exists against any maintenance branch as of 2026-08-11.

**Reachability re-confirmed.** `grep -r poplib backend/` returns no matches — this covers Scrye's
own code only, and is not a claim that no bundled third-party dependency ever imports `poplib`
(the same scope #52's original verification stated).

**#52's body changes:**
- The source-verification table's heading moved from `(2026-07-26)` to
  `(2026-07-26; re-verified 2026-08-11)`; its `v3.14.6 (the pinned runtime)` row was replaced with
  `v3.14.7 (the pinned runtime)`, still absent, plus a sentence recording the backport-label
  removal detail above and the 2026-08-11 re-check of gh-143923.
- The "Group A tracker" section's `tracked in **#98**` line was rewritten: #98 was closed
  2026-08-11 once its resolution trigger fired (all three fixes verified present in 3.14.7), and
  its tracking now lives in `ci/grype.yaml`'s Group A-1 block plus this file's §14, not a numbered
  issue. #98 is kept as a historical link.
- The "Closing this issue" section's `Ref:` line gained `2026-08-11` and a parenthetical on #98's
  closure and where its tracking moved.
- The argument itself — why this is a standing acceptance, not a deferral; why no 3.15 upgrade
  should be scoped off it — is unchanged, per the explicit scope of this re-verification.

**`ci/grype.yaml`'s Group B block changes:** the source-verification paragraph now cites
`v3.14.7` rather than `v3.14.6` as the pinned runtime and records the 2026-08-11 re-check
(including the gh-143923/PR #143924 backport-label detail); the block-index row at the top of the
interpreter section gained `, 2026-08-11` alongside its existing `verified 2026-07-26`; the
`REVIEW ANNUALLY` paragraph gained a clause noting the annual cadence (next 2027-07-25) is
unchanged by this re-verification, and its `#52` reference now explicitly contrasts with Group
A's #98/#116 — #52 stays open because its fix is `main`-only with no point-release trigger,
unlike the two closed issues.

**Not changed, deliberately, per explicit task scope:** the CVE-2025-15367 waiver itself; #52's
review date or its annual cadence (still 2027-07-25); the Group A-1/A-2 waiver blocks and their
2026-11-01 review date (settled in the #196 work, only described here where #52 references them);
any argument for or scoping of a 3.15 upgrade; #52 remains open.

**Plan section affected:** CLAUDE.md § Dependency hygiene (interpreter-CVE source verification),
`ci/` triage allowlists, § Issue conventions. Docs/process only — no application code, schema,
API contract, security-model, job-model, auth, gate threshold, or waiver membership change.

---

### 2026-08-11 — Docs/Process — Attribution moved to the settings layer via a committed `.claude/settings.json`; the strip-PATCH instruction removed from CLAUDE.md and CONTRIBUTING.md

**What changed:** two separate problems, two separate fixes, landed together because they are the
same subject and this document's own rule requires an attribution-policy change to carry its §14
entry in the same PR.

**1. The footer itself is now disabled at the settings layer, in project scope.** A new committed
`.claude/settings.json` sets `attribution.commit: ""`, `attribution.pr: ""`, and
`attribution.sessionUrl: false` — the documented combination for hiding all attribution. The
footer that has appeared on PR bodies and issue comments throughout this project's history is a
**Claude Code harness feature configured through settings**, not text any session composed, which
is why five prior rounds of instructing sessions harder never moved it.

**Why project scope specifically, and not the maintainer's own config.** The maintainer's
user-scope `~/.claude/settings.json` already carried this configuration. It has never applied to a
single session here: **each Cloud session is a fresh VM with no home-directory provisioning**, so
that file does not exist in the environment where the work actually happens — confirmed by a
diagnostic session, and re-confirmed in this one (`$HOME/.claude/` exists and holds hook scripts
and synced skills, but no `settings.json` of any kind). Project scope is the fix because the repo
*is* cloned into every VM, so a committed settings file travels with it, and project scope also
outranks user scope in the precedence order. **The generalisation is the durable part and is now
in `CLAUDE.md` § Attribution:** any Claude Code setting that must apply to this repo has to live in
the committed `.claude/settings.json`; user-scope config is inert here.

**Verified rather than assumed.** User and project settings files are validated **strictly** — a
malformed key rejects the file as a whole and would silently disable the entire fix — so the file
was checked, not eyeballed: it parses as JSON, and it validates with **zero errors** against the
published `https://json.schemastore.org/claude-code-settings.json`, whose `attribution` block
declares exactly `commit: string`, `pr: string`, `sessionUrl: boolean` with
`additionalProperties: false`. Nothing about the fix's *effect* is claimed here — that is verified
empirically on the next real session, deliberately not by opening a throwaway PR to test it.

**DECLINED — `includeGitInstructions` / `CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS`.** Not deferred,
not overlooked. That key strips all built-in git/PR guidance out of the session's system prompt,
which is a real capability cost, and it is **not needed** once the three `attribution` keys are
set — they target the footer directly. Do not add it as a belt-and-braces measure.

**2. The strip-`PATCH` instruction is removed from both files that carried it.** `CLAUDE.md`
§ Attribution's "read the posted body back from the API … edit it out and re-read to confirm the
edit held" is replaced with a flat prohibition: **never issue a follow-up `PATCH` to a PR body or
an issue comment for the purpose of removing an attribution footer**; if a footer appears, report
it in the session summary and leave it alone.

**The reason is stated inline in `CLAUDE.md`, not just the rule, and that is load-bearing.**
Without a reason a future session reads "don't strip the footer" as an oversight and helpfully
restores the old instruction — which is precisely how this policy already flip-flopped once, via
**#169** (see the 2026-08-09 entry below). The reason: **a strip `PATCH` executes under a bot
identity.** On **PR #196** the edit-history dropdown shows the comment created by `tyler-rich`,
then **two** edits attributed to **"claude (Bot)"** — those two edits are exactly the two strip
attempts recorded in the 2026-08-11 entry below — and the footer was re-appended anyway. Every
other write in this project's workflow (posting the comment, opening the PR, editing a body as
ordinary work) lands correctly as `tyler-rich`. So the strip instruction is the **sole** cause of
bot-attributed writes in this repository, it has **never once succeeded**, and its net effect is a
permanent, public, more-visible attribution leak in GitHub's edit history in exchange for a footer
that stays put regardless.

**This is the third state of this policy, and it is not a re-run of the flip-flop.** The
2026-08-09 audit entry below banned stripping; **#169** reinstated it hours later with no §14
entry; the 2026-08-09 correction entry below recorded that reversal and left #169's
strip-and-reverify text standing as policy. This entry ends that cycle on **new evidence the
earlier rounds did not have** — the #196 edit-history attribution, which reframes stripping from
"unreliable" to "actively harmful" — and, more importantly, **removes the reason anyone was
stripping in the first place** by fixing the footer at its actual source. The two prior entries
stand as written; this one supersedes both on the operative instruction.

**The full attribution-instruction surface was audited, not just `CLAUDE.md`.** `CONTRIBUTING.md`
§ Opening a PR, step 4 carried the same instruction in one line ("If your tooling appends one,
re-read the PR body after opening and strip it") and is rewritten to match — no-footer requirement
and the `git log --format="%an <%ae>%n%B"` authorship check kept, the strip clause replaced with
the prohibition and a pointer to `CLAUDE.md` § Attribution. A full grep of `CONTRIBUTING.md` for
`strip|footer|attribution|co-author|generated by|session link|re-read|patch|by hand` confirms
line 480 was its **only** stripping reference; the other hits are unrelated (`.gitattributes`
line-ending stripping, hand-editing lockfiles, hand-merging Dependabot bumps). Two files
contradicting each other on the same action is the #169 failure mode this PR exists to end, so
both moved together.

**One surface is outside this repository and could not be fixed here:** the synced `scrye` skill
(`~/.claude/skills/synced/scrye/SKILL.md`) still says to "edit the PR body in place" and "re-read
the live body after every edit". It is not a repo file, so **no commit from any session can reach
it** — the maintainer updates it by hand, out of band.

**Precedence, stated explicitly so it is not rediscovered:** where the synced skill and the repo
files disagree on attribution, **`CLAUDE.md` and `CONTRIBUTING.md` win**, and the skill is to be
treated as **known-stale on this subject pending a manual sync**. This is not a judgement call for
a future session to make on the evidence in front of it — a session that reads a strip instruction
in the skill and follows it is reproducing the **#169** failure mode exactly: two sources
disagreeing on the same action, the wrong one followed, and nothing written down saying which
governed. It is written down here. The skill carries one further staleness of the same class — it
asserts the merging account's profile display name "must read `tyler-rich`", which the 2026-08-09
display-name decision (below, and `CLAUDE.md` § Git & PR conventions) **declined** — so the skill
is stale on both attribution points, not just the strip one.

**3. `CLAUDE.md`'s git-identity step is restated as a hard gate.** Unchanged in substance, but it
was reading as a suggestion and it is the single point of failure for commit authorship. The Cloud
VM image ships with **both** the repo-local *and* the global identity preset to
`Claude <noreply@anthropic.com>` — verified directly in this session before anything was staged —
so wrong authorship is the **default state of every session**, not an edge case. There is **no
settings-level backstop**: `.claude/settings.json` has no git-identity key, so
`git config user.name "tyler-rich"` / `git config user.email
"170156756+tyler-rich@users.noreply.github.com"` (repo-local, never `--global`) are the *only*
thing producing correctly-authored commits. The consequence of skipping them is now stated
explicitly in the rule.

**4. Ignore files.**

- **`.gitignore` — `.claude/settings.local.json` added, with the specific path and not a blanket
  `.claude/` rule**, which would have excluded the very file this change adds. Claude Code writes
  permission approvals and personal overrides into `settings.local.json` automatically, and the
  documented auto-ignore mechanism for it writes to the **global** git excludes file, which does
  not exist in an ephemeral Cloud VM — so the repo has to cover it explicitly. Both outcomes were
  verified after the edit rather than assumed: `git check-ignore -v .claude/settings.json` exits 1
  (not ignored — the file is trackable, and it is present in the pushed tree), and
  `git check-ignore -v .claude/settings.local.json` exits 0, matching `.gitignore:143`. Nothing in
  `.gitignore` previously mentioned `.claude` in any form — the directory was not deliberately
  excluded, it simply had never existed.
- **`.dockerignore` is denylist-style** (an ordered list of exclusions; no leading `*` with `!`
  re-includes), which means an **unlisted directory is sent to the build context by default**.
  `.claude/` was therefore reachable in principle and is now listed alongside `.git/`, `.github/`,
  and `docs/`. In practice no build context has ever carried it — the directory did not exist in
  this repository until this commit — so this is a pre-emptive exclusion, not the discovery of
  something that shipped. It matters here specifically because this project **dogfoods a Trivy +
  Grype scan of its own image**, and session tooling config has no business in the context that
  scan is computed over. **No other `.dockerignore` line was touched and no `docker/Dockerfile`
  change was made**, so the build context is altered in exactly one way: `.claude/` is excluded.

**Deliberately not done:** no retroactive cleanup of footers on existing PRs, issues, or comments;
no change to how sessions authenticate to GitHub or to the MCP tooling; no `docker/Dockerfile`
change; no empirical test of the settings fix (the maintainer verifies it on the next real
session). The footer on **this** PR's own body, if one appears, is left in place — this is the PR
that makes that the rule.

**Plan section affected:** new file `.claude/settings.json`; `CLAUDE.md` § Attribution (rewritten
— Cloud-scope note added, strip-and-reverify replaced with the prohibition plus its reason) and
§ Git & PR conventions (git-identity bullet strengthened); `CONTRIBUTING.md` § Opening a PR step 4;
`.gitignore`; `.dockerignore`. No application code, schema, API contract, security model, job
model, auth, CI behaviour, gate threshold, or dependency version changed; no locked decision
re-opened.

---

### 2026-08-11 — Process — Issues #98 and #116 closed on source-verification evidence rather than Grype-DB agreement; Group A tracking moves into `ci/grype.yaml` plus this log

**What changed:** **#98** (Group A-1 — `html.parser` / `getpath.py` / `imaplib`) and **#116**
(Group A-2 — the three `tarfile` CVEs) were **closed**, each with a comment recording why. In
`ci/grype.yaml`, both Group A comment blocks were rewritten so they stand alone as the tracking
record now that the issues they cited are closed:

- the forward-looking *"Tracked in issue #98 (…)"* pointer and A-2's equivalent are replaced with
  a statement that the CVEs are **verified fixed in the pinned interpreter** — cited to **PR #195**,
  which read CPython at the released `v3.14.7` tag — and are **waived only pending a Grype-DB
  refresh**, tracked by **this file plus `docs/ARCHIVE.md` §14** rather than a numbered issue;
- the *"WHICH BLOCK IS TRACKED WHERE"* index at the top of the interpreter section is re-pointed
  the same way, with `(was issue #98, closed 2026-08-11)` / `(was issue #116, closed 2026-08-11)`
  kept as the historical link. Group B's row still reads `issue #52 (still open)`;
- the shared review date moves **2026-10-25 → 2026-11-01**, quarterly thereafter if extended past
  that, and is now labelled explicitly as advisory (see below);
- the file-header NOTE stops saying interpreter waivers are for CVEs "unfixable on the current
  3.14.x line", since half of them are now the opposite.

One stale pointer of the same class lived **outside** `ci/grype.yaml` and was caught by reading the
dogfood job's own log rather than by grepping the file under edit: `.github/workflows/ci.yml`'s
*"Waived by ci/grype.yaml (informational)"* step hardcodes a header line, which printed
`Blocks: A-1 (issue #98) · A-2 (issue #116) · B (issue #52)` on **every** run. It now reads
`A-1 · A-2 (no open issue — tracked in ci/grype.yaml + docs/ARCHIVE.md §14) · B (issue #52)`. It is
a bare `echo` string — no `jq` filter, gate threshold, `--exclude`, `--fail-on`, step condition, or
job structure changed, and the waiver listing it heads is computed from the report exactly as
before.

**Membership, waiver format, and gate behaviour are unchanged.** The `ignore:` list still parses
to the same ten entries — three `package.location` excludes for the bundled scanner binaries, and
the same seven `vulnerability` IDs. Every fact already in the blocks is kept verbatim: the CVE
lists, both per-CVE source-evidence tables, the observed dogfood scan output, the `FIXED IN`
mechanism, and the "DELETE both blocks outright when the DB catches up" instruction. This was a
reference-target and review-date change, not a rewrite of the evidence. Group B (#52, poplib) is
untouched in both the file and its issue.

**Why close instead of waiting for the scanner to agree.** #98 and #116 were opened as *deferrals
with a stated resolution trigger*: a released 3.14.x carrying the backports. That trigger **fired**
— 3.14.7 shipped on 2026-08-05, the digest moved to it, and PR #195 verified all six fixes present
by reading `Lib/html/parser.py`, `Modules/getpath.py`, `Lib/imaplib.py` and `Lib/tarfile.py` at the
`v3.14.7` tag and diffing against `v3.14.6` (the entry below has the per-file table). What is left
behind the waivers is **only** that Grype's DB records these as fixed in 3.15.x and has no entry
for the 3.14 maintenance-branch backports, so it compares `3.14.7 < 3.15.0b4` and matches anyway.

Scanner data-lag is a materially weaker reason to hold a tracking issue open than an active risk
acceptance. Both issues themselves predicted it in as many words ("expect the waivers to outlive
3.14.7 by a Grype-DB refresh cycle"), so the lag is the *expected* state, not a new finding needing
a tracker. Keeping them open would have left two issues whose entire remaining content was "waiting
for a third party's database to refresh", while the substantive record — what was verified, how,
and what to do about it — lives in `ci/grype.yaml` and here regardless. The evidence sections in
both issues are also now superseded: they compared the **`3.14` branch** against `v3.14.6` and
could only show a fix was *queued*, whereas #195 read the released tag and showed it *shipped*.

**This does not change the convention for future waivers.** A new CVE waiver still gets its own
tracking issue, exactly as before. This is a one-off for a pair whose resolution trigger had
already fired, and `ci/grype.yaml` says so in the same paragraph that records the closure, so a
reader of the file cannot mistake it for a general policy. It also does not touch the review-date
convention for any **other** open waiver issue — **#52** (Group B, poplib) keeps its standing
annual re-confirmation, next 2027-07-25, and remains an open issue because its fix is `main`-only
and no 3.14.x will ever clear it.

**The 2026-11-01 re-check date is advisory, and nothing in this repo enforces it.** There is no
scheduled workflow, no webhook, and no bot watching for a Grype-DB refresh, and none was built —
that was explicitly out of scope. When the DB does catch up, the waivers simply **go inert**: they
stop matching anything, the gate stays green either way, and no signal is emitted. The only ways
anyone finds out are (a) reading `ci/grype.yaml` for some other reason and noticing the blocks no
longer match, or (b) checking deliberately. The date is therefore a documented **intention** for a
human to act on. It is stated in exactly that form in all three places it appears — the two close
comments and the file's `REVIEW BY` note — rather than left to look like a mechanism.

**When the trigger does fire, the action is deletion, not re-dating.** Both Group A blocks come out
of `ci/grype.yaml` **outright** — that instruction predates this change and is kept unedited. Until
then, removing them turns the gate red over three HIGHs whose fixes are already in the image.

**Attribution note.** The two close comments were posted through the GitHub API, which appended a
"Generated with Claude Code" footer server-side. A direct `PATCH` to each comment stripping the
footer was attempted and did **not** hold: the API re-appends it on write, so the re-read after the
patch still shows it. Recorded here as a property of this posting path, since CLAUDE.md
§ Attribution requires the strip to be attempted and its outcome reported — nothing was composed
with a footer, and no other surface (commits, PR body, files) carries one.

**Not changed:** which CVEs are waived; the waiver/gate logic (`--only-fixed --fail-on high`, the
`--exclude` list, `check-for-app-update`); `CLAUDE.md` § Locked decisions #2, whose "Group A-1 (#98)
/ Group A-2 (#116)" wording is a historical identification of the two sets and still resolves to
the closed issues; #52's review-date convention; the pinned base-image digest; the historical `#98`
/ `#116` references in past §14 entries, in PR #195's own record, and in the "the Grype-DB lag both
#98 and #116 predicted" line inside the file — all describe what happened and stay as written.

**Plan section affected:** §9.1 (dogfood self-scan triage), §12 (Phase 6 self-scan), CLAUDE.md
§ Dependency hygiene (interpreter-CVE source verification), `ci/` triage allowlists. Process and
comments only — no application code, schema, API contract, security-model, job-model, auth, gate
threshold, or waiver membership change.

### 2026-08-11 — Security/Infra — Runtime base image moved to Python 3.14.7; all six Group A interpreter fixes verified at the source, and the waivers kept anyway because Grype's DB has not caught up

**What changed:** `docker/Dockerfile`'s two `FROM python:3.14-slim-bookworm@…` lines — the
`backend-builder` stage and the `runtime` stage, which must always move together — went from
`sha256:86f975aca15cf04a40b399eebede9aea7c82eae084d1f1a0a6ef6bcaae871a30` (**3.14.6**) to
`sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52` (**3.14.7**, released
**2026-08-05**). `ci/grype.yaml`'s Group A-1 (#98) and Group A-2 (#116) blocks keep all six
waivers but are rewritten to rest on a different reason, and the runtime stage now deletes `pip`
(see "The bump's own side effect" below). CONTRIBUTING's Python prerequisite moves to
3.14.7-or-later. The locked floor moves in the entry below, deliberately separate.

**The one number this was for.** 3.14.7 was the resolution trigger both #98 and #116 name.
Baseline first, per the fail-first rule: with the six `- vulnerability:` entries lifted and the
digest **still 3.14.6**, the Grype gate reported exactly those six and exited 2
(CI run 31456533896) — proof the waivers were suppressing what they claimed, no more and no
fewer. After the digest bump, with the waivers still lifted, the same gate reported **the same
six, unchanged, against `python 3.14.7`** and exited 2 again (CI run 31457878086):

```
NAME    INSTALLED  FIXED IN  TYPE    VULNERABILITY   SEVERITY
python  3.14.7     3.15.0b4  binary  CVE-2026-11940  High
python  3.14.7     3.15.0    binary  CVE-2026-15308  High
python  3.14.7     3.15.0b4  binary  CVE-2026-11972  High
python  3.14.7     3.15.0a6  binary  CVE-2025-15366  Medium
python  3.14.7     3.15.0b3  binary  CVE-2026-12003  Medium
python  3.14.7     3.15.0b4  binary  CVE-2026-0864   Medium
```

So **no waiver was retired.** That is the Grype-DB lag #98 and #116 each predicted verbatim
("expect the waivers to outlive 3.14.7 by a Grype-DB refresh cycle"), and the `FIXED IN` column
is the mechanism: Grype's DB knows these only as fixed in 3.15.x, has no record of the 3.14
backports, compares 3.14.7 < 3.15.0b4, and matches. The gate was **not** forced green and the
findings were **not** re-labelled as fixed.

**Source verification — the thing that actually establishes the fix, per CLAUDE.md § Dependency
hygiene.** Each file was read at the `v3.14.7` tag and diffed against `v3.14.6`. This is the
second verification for every one of the six; the earlier ones (2026-07-26, 2026-07-30) compared
the **`3.14` branch** against `v3.14.6` and could therefore only show a fix was *queued*. Reading
the released tag is what shows it *shipped* — the distinction the 2026-07-26 imaplib entry was
written to teach.

| CVE | File | In `v3.14.7` | In `v3.14.6` |
| --- | --- | --- | --- |
| CVE-2026-15308 | `Lib/html/parser.py` | `feed()` accumulates into `_pending`/`_pending_len` and only joins+parses past `_parse_threshold` (which doubles when nothing parsed); `close()` flushes the pending list | `self.rawdata = self.rawdata + data; self.goahead(0)`, unguarded |
| CVE-2026-12003 | `Modules/getpath.py` | no `BUILD_LANDMARK` constants, no `isfile(joinpath(real_executable_dir, BUILD_LANDMARK))` fallback; an inline `gh-151544; CVE-2026-12003` comment sits where they were | both constants (posix + nt) and the fallback |
| CVE-2025-15366 | `Lib/imaplib.py` | `_control_chars = re.compile(b'[\x00\r\n]')` and `raise ValueError("NUL, CR and LF not allowed in commands")` inside `IMAP4._command()`'s argument loop, before each arg is appended | neither the constant nor the guard |
| CVE-2026-11972 | `Lib/tarfile.py` | `_Stream.seek()`: `data = self.read(self.bufsize)` then `if not data: break` | `self.read(self.bufsize)`, result discarded (CWE-252) |
| CVE-2026-11940 | `Lib/tarfile.py` | `makelink_with_filter()` calls `filter_function(unfiltered.replace(name=tarinfo.name, deep=False), extraction_root)` before the fallback, and `_extract()` passes `filter_function=filter_function` into `_extract_one()` | neither |
| CVE-2026-0864 | `Lib/tarfile.py` | `_EXTHEADER_READ_CHUNK = 1024 * 1024` + `_safe_read()`, used by both `_proc_gnulong()` and `_proc_pax()` | `tarfile.fileobj.read(self._block(self.size))` directly in both |

`Include/patchlevel.h` reads `PY_VERSION "3.14.7"` / `PY_MICRO_VERSION 7` at the tag, and
`Misc/NEWS.d/3.14.7.rst` carries all seven upstream issues behind the six CVEs — gh-153030,
gh-151544, gh-143921, gh-151981, gh-151558, gh-151987, gh-151497 — with
`.. release date: 2026-08-05`.

**What the waiver blocks now say.** Their membership is unchanged (seven entries, same as
before); their *reason* is inverted, which is the whole point of rewriting rather than re-dating
them:

| | before 2026-08-11 | now |
| --- | --- | --- |
| why waived | unfixable at the pinned version; waiting on a 3.14.x release carrying the backports | **fixed** in the pinned interpreter, verified at the source; waived only because the scanner's data lags |
| trigger | 3.14.7 ships and the digest moves to it | a Grype-DB refresh that records the 3.14 backports — then **delete** both blocks outright |
| review | 2026-10-25 | 2026-10-25, kept rather than pushed out: the pending event is a daily-cadence DB refresh, not a release months away |

A file-level note above both blocks carries that table's substance plus the observed scan output,
so the next reader does not have to reconstruct why a waiver survived its own trigger.

**Group B (#52, poplib) is untouched, and was re-checked to earn that.** `Lib/poplib.py` is
**byte-identical** between `v3.14.6` and `v3.14.7`, so 3.14.7 clears nothing there and the
standing acceptance is unaffected. Its block is byte-identical to `dev`'s. Two sentences inside it
point at "Group A above" as where CVE-2025-15366 went in 2026-07-26; that reference still
resolves, since Group A still exists.

**The bump's own side effect, and why it is a fix rather than a waiver.** The 3.14.7 image turned
the **Trivy** gate red with two fixable HIGHs that had never appeared before — `msgpack` 1.1.2
(GHSA-6v7p-g79w-8964, fixed 1.2.1) and `setuptools` 70.3.0 (CVE-2025-47273, fixed 78.1.1). Both
versions are exactly pip's vendored pins (`pip/_vendor/vendor.txt`), and neither is a Scrye
dependency: `requirements.lock` pins setuptools **83.0.0** and carries no msgpack at all. 3.14.6
bundles pip **26.1.2** and 3.14.7 bundles **26.2.1** (`Lib/ensurepip/__init__.py: _PIP_VERSION`),
which is what surfaced them — though note both pip versions vendor those *same two pins* and both
ship `vendor.txt` in the wheel, so the pins themselves did not change and a Trivy-DB refresh
between the two runs (four minutes apart, each downloading fresh from `mirror.gcr.io`) cannot be
excluded as a contributing cause. Either way they are not ours to bump, and the fix chosen was
**not** a `ci/trivyignore` entry: the runtime stage now deletes pip from both prefixes that carry
one — `/opt/venv` (seeded by `python -m venv`) and `/usr/local` (the base image's
`--with-ensurepip` build) — plus `ensurepip`, whose entire payload is that same pip wheel.
`backend-builder` keeps pip, since it installs the hash-pinned lock with it (SC-1). Nothing in the
runtime needs pip: the entrypoint runs `alembic upgrade head` then `exec uvicorn`, and no
application code imports pip, ensurepip or pkg_resources. The step asserts pip is off `PATH` and
that the venv still imports alembic/fastapi/sqlalchemy/uvicorn, so a version glob that stops
matching after a future base bump fails the build instead of silently shipping pip again. It is
guarded by a new static test in `backend/tests/test_dockerfile_supply_chain.py`, verified to fail
against the pre-strip Dockerfile. **Trivy went green on the next run**; no stage boundary, layer
ordering, or cache scope changed (§ Build performance § Invariants).

**How the digest was established, without trusting a rendered page.** `HEAD
/v2/library/python/manifests/3.14-slim-bookworm` on `registry-1.docker.io` returns
`docker-content-digest: sha256:23c59390…`, and the same request for `3.14.7-slim-bookworm` returns
the **identical** digest (`3.14.8-slim-bookworm` 404s, so 3.14.7 is current). The index is an OCI
image index carrying **linux/amd64 and linux/arm64** children — both legs `publish.yml` builds.
Its per-arch annotations name the build source
`docker-library/python@228f71e70a42ba9f9a092321b971031603bb88ff:3.14/slim-bookworm`, created
2026-08-05, whose Dockerfile declares `ENV PYTHON_VERSION 3.14.7`; the same lookup on the outgoing
digest resolves to rev `7914d06` with `ENV PYTHON_VERSION 3.14.6`, and the two recipes differ
**only** in `PYTHON_VERSION`/`PYTHON_SHA256`.

**Environment limitation — a property of where this ran, not a skipped check.** The authoring
sandbox's egress policy denies the registry blob hosts (`production.cloudfront.docker.com`,
`pkg-containers.githubusercontent.com`) and `www.python.org`, so **no image could be pulled or
built locally and no 3.14.x interpreter could be obtained there**. Consequently: the image build,
the dogfood Trivy/Grype scans, and the interpreter version all come from **CI**, which does pull
and build the real image — the `INSTALLED 3.14.7` column in the scan output above is the built
image reporting its own interpreter, and the Trivy report independently shows the image's pip
moving 26.1.2 → 26.2.1. The 3.14.7-vs-3.14.6 source diffs come from `raw.githubusercontent.com` at
the two tags, and the digest facts from the registry API. What is genuinely **not** evidenced:
`python -V` was never executed against the pinned digest locally, and the backend suite has
**not** run on 3.14.7 anywhere — CI's `Set up Python 3.14` resolves the hosted tool cache to
**3.14.6**, so the green `pytest` on this branch is 3.14.6 (`7 passed` for the symlink-containment
guard in the image job; the full backend job green). A future session with registry access should
close that by running the suite on a real 3.14.7.

**Issues #98 and #116 stay open.** Closing keywords are inert here regardless — GitHub only
auto-closes on a merge into the default branch, and this targeted `dev` — but more importantly
they should not be closed yet: each tracks a waiver that still exists. Their resolution trigger
(3.14.7 in the pinned image) is satisfied and their evidence sections are now superseded by the
released-tag verification above, but the correct close is by hand, after the Grype-DB refresh lets
both blocks be deleted.

**Index count corrected in passing.** The §14 index header read "157" while the index block and
the entry list both held **158** — a stale count, off by one, predating this change. With the two
entries added here it now reads **160**, which matches both the index lines and the dated `###`
headings (checked programmatically, not by eye).

**Plan section affected:** §0 (#7), §2 (tech stack), §9.1 (base image / dogfood self-scan),
§12 (Phase 6 self-scan), CLAUDE.md § Dependency hygiene (interpreter-CVE source verification),
`ci/` triage allowlists. No application code, schema, API-contract, security-model, job-model, or
auth change.

### 2026-08-11 — Process — Locked runtime floor raised 3.14.6 → 3.14.7 (locked decision §2), on a second independent reason rather than a replacement one

**What changed:** `CLAUDE.md` § Locked decisions #2 now states the runtime floor as **3.14.7**,
was 3.14.6. The existing incremental-GC rationale is kept verbatim in substance — never
3.14.0–3.14.4, whose GC work-estimate bug let a long-running server's cyclic-garbage backlog grow
resident memory several-fold, reverted in 3.14.5 — and the interpreter-CVE rationale is added
**alongside** it: 3.14.7 is the first release carrying the six Group A-1 (#98) / Group A-2 (#116)
fixes, so dropping below it reinstates all six. `CONTRIBUTING.md`'s prerequisite moves with it
(`3.14.6 or later` → `3.14.7 or later`).

**Why this is its own entry.** Two reasons. First, it is a **locked-decision edit** — the class of
change CLAUDE.md § When to ask vs. decide says to stop and ask about — and it was made on explicit
maintainer instruction, not folded in as a side effect of a dependency bump. Recording it
separately means the authorisation is legible next to the change instead of buried in the middle
of a CVE entry. Second, the two documents move for **different reasons on different evidence**:
the entry above is about six CVEs and what a scanner does or does not know about them; this is
about what interpreter Scrye is permitted to run on at all. Merging them would make the floor look
like a consequence of the scan result — and the scan result was that all six *still report*, which
would then read as an argument against the very floor being raised.

**The two reasons are independent and both load-bearing, which is why neither replaced the other.**
The GC reason bounds the floor from below at **3.14.5** and is about availability under long
uptime — exactly Scrye's workload. The CVE reason raises it to **3.14.7** and is about six fixes
present in the interpreter. Had the CVE reason been written as a replacement, a future reader
resolving the CVEs (once Grype's DB catches up and the waivers are deleted) could reasonably
conclude the floor could return to 3.14.5/3.14.6 — reintroducing the GC leak. The floor text
therefore states both and says explicitly that each binds separately.

**Not changed:** the `3.14` **minor**-version pins in `.github/workflows/ci.yml`
(`python-version: "3.14"`) and `backend/pyproject.toml` (`requires-python = ">=3.14"`), which
track the minor line deliberately and are not micro-version floors; `CLAUDE.md` § Dependency
hygiene's mention of 3.14.6, which is a historical statement about what the 3.13 → 3.14 bump did
and must stay as written; the released CHANGELOG sections naming 3.14.6, for the same reason; and
`frontend/src/components/settings/AboutPanel.test.tsx`'s `python_version: '3.14.6'`, which is a
mock API payload asserting the About tab renders whatever the backend reports, not a floor.

**Plan section affected:** CLAUDE.md § Locked decisions #2, §0 (#7), §2 (tech stack);
`CONTRIBUTING.md` § Prerequisites. Process/docs only — no code, schema, security-model, or
job-model change.

### 2026-08-09 — Docs/Process — `dependabot.yml`'s "Deliberately NOT ignored" rationale rewritten: the instruction outlived the reason it was written on

**What changed:** `.github/dependabot.yml` — the *"Deliberately NOT ignored"* comment paragraph in the
npm `/frontend` entry, rewritten — plus this entry. **Comment-only.** No `ignore` rule, `group`,
`schedule`, `target-branch`, `directory`, `commit-message` or any other key was added, removed, or
modified; no dependency, lockfile, source, test, or workflow file was touched; `main` was not
touched. The entry below flagged this paragraph as stale and left it as a maintainer call; this is
that call being made.

**The lapse, stated precisely, because it is the general pattern worth keeping.** The paragraph's
*instruction* — leave the frontend tooling majors unignored so Dependabot keeps surfacing them — is
still exactly right. Its *stated reason* was not: it described those majors as *"the deferred #86
sweep tracked in docs/ROADMAP.md"* and told the reader Dependabot *"should keep surfacing them until
that PR is done."* The sweep **is** done. So the comment, read literally on 2026-08-09, terminated
its own instruction: a future reader who checked the roadmap would find the work complete and
reasonably conclude the exemption had expired — and the obvious next move from there is to add the
`typescript` ignore, which is the one thing that must not happen. **A comment whose stated condition
has been met argues against its own instruction.** That is a sharper failure than mere staleness,
and it is why this was worth a PR rather than a cleanup-later note.

**The gate was checked before writing, not assumed.** The claim "the sweep is done" is the whole
premise of the rewrite, so it was read at the source rather than carried from this session's own
earlier entries: `docs/ROADMAP.md` § Track A carries the item **struck through** and marked **"Done
2026-08-09"**, enumerating all eight step PRs — **#171, #174, #177, #179, #180, #183, #185, #187** —
which matches the step entries below one-for-one.

**Before:**

```
    # Deliberately NOT ignored: the frontend tooling majors (typescript, eslint,
    # typescript-eslint, vite, vitest, jsdom and friends). Those are *wanted* —
    # they are the deferred #86 sweep tracked in docs/ROADMAP.md — so Dependabot
    # should keep surfacing them until that PR is done. An ignore rule says "a
    # bot may not make this decision"; it is not a parking space for work we
    # intend to do.
```

**After** — the instruction now rests on two current reasons instead of one spent one, and the
closing maxim is kept verbatim because it never depended on the sweep:

```
    # Deliberately NOT ignored: the frontend tooling majors (typescript, eslint,
    # typescript-eslint, vite, vitest, jsdom and friends). Those are *wanted* —
    # we want to see them, evaluate them, and land them, which is exactly what
    # the #86 sweep did (see docs/upgrades/frontend-toolchain-86.md).
    #
    # `typescript` is the one to leave unignored most deliberately. TypeScript 7
    # is wanted, and the only thing blocking it is upstream: typescript-eslint's
    # `typescript` peer range has never admitted 7 in any published version. So
    # the regenerating Dependabot PR proposing typescript 7.x is not noise — it
    # IS the notification that tells us when upstream ships support. Ignoring it
    # would suppress that signal while changing nothing about the blocker.
    # Re-check the range in one command:
    #
    #     npm view typescript-eslint@latest peerDependencies.typescript
    #
    # Support is expected to arrive as a new typescript-eslint MAJOR built
    # against TS 7's ./unstable/* API, not as a point-release range widen.
    #
    # An ignore rule says "a bot may not make this decision"; it is not a
    # parking space for work we intend to do.
```

**Three deliberate choices in the wording.** (1) The sweep is referenced in the **past tense as an
example of the policy working**, not as pending work — so completing it can never again read as
expiring the exemption; the pointer is to `docs/upgrades/frontend-toolchain-86.md` rather than to
`docs/ROADMAP.md`, because the sequence document explains *how* such a batch gets evaluated while
the roadmap item is now a struck-through history entry. (2) **The re-check command is inlined** so
the next reader can test the blocker in one command without opening a session — the same one-liner
§3.1 of the sequence document carries, kept in both places on purpose, since whoever is looking at
an ignore list is not necessarily reading the upgrade docs. (3) The expected **shape** of upstream
support (a new typescript-eslint major, not a range widen) is stated so a point-release bump is not
misread as the all-clear. What the comment deliberately does **not** contain is the sweep's history,
the packument evidence, or the per-step record — the archive holds those, and a config comment that
grows into a changelog stops being read.

**Verified after editing, by parsing rather than by reading.** Both versions of the file were loaded
with `yaml.safe_load` and serialised to canonical JSON: the two structures are **byte-identical**,
SHA-256 `07e71c6c…` on each side. Independently, every changed line in the raw diff was confirmed to
be a comment line (`+18/−4`, all matching `^[+-]\s*#`). So the effective configuration — six
ecosystems, every `target-branch: dev`, every schedule and group, and all five surviving npm ignores
(`@mantine/*`, `react`, `react-dom`, `@types/react`, `@types/react-dom`) plus the `docker` /
`docker-compose` ones — is provably untouched. Worth doing at the parser rather than by eye: a
comment-only claim about a YAML file is exactly the kind that a stray indentation change would
falsify silently.

**Inert on `main` until the next promotion, like every prior change to this file.** Dependabot reads
its configuration from the **default branch**, so nothing here takes effect until a `dev` → `main`
promotion carries it. That has no practical consequence in this case — the paragraph is a comment,
and comments never had runtime effect on either branch — but it is stated because the same sentence
is true and load-bearing for every other edit to this file, and an exception that goes unstated is
how a future reader concludes the rule has exceptions.

**What was deliberately not done.** No `ignore` entry was added for `typescript` — the whole point
of the rewrite is to make that harder to do by accident, not to do it. No key of any kind changed.
**The currently-open Dependabot `typescript` PR was not touched** — not merged, not closed, not
commented on; its predecessor #191 was already closed with the full reasoning earlier today, and
re-litigating that on a successor was outside this brief. `docs/ROADMAP.md` was read but **not**
edited, `docs/upgrades/frontend-toolchain-86.md` was not edited, and no dependency, lockfile, or
other config file was touched. `main` was not touched.

**Plan section affected:** `.github/dependabot.yml` (one comment paragraph) and this entry. No code
behaviour, schema, API contract, security model, job model, auth, dependency version, or CI
configuration changed; no locked decision re-opened — the ignores enforcing locked decision §2 are
untouched, and this change cannot alter Dependabot's behaviour at all.

---

### 2026-08-09 — Infra/Process — The `@types/node` majors-ignore removed now that 26.2.0 has landed; no `typescript` ignore added, deliberately, because that regenerating PR is the TS7 signal

**What changed:** `.github/dependabot.yml` — one `ignore` entry and its nine-line explanatory comment removed — plus this entry. **No dependency, lockfile, source, test, or other config file was touched**, and **no other key in `dependabot.yml` moved**: the file's six ecosystems, every `target-branch: dev`, every `schedule`, every `commit-message` prefix, both `groups` blocks and the five remaining npm ignores are byte-identical. `main` was not touched.

**The gate was checked before the edit, not after.** Removing a majors-ignore for a version that has not landed would leave Dependabot free to propose a major nobody has evaluated. So `dev` was read directly: **#190 merged at 2026-08-09T18:41:00Z** as squash commit **`5948b73`**, and `git show origin/dev:frontend/package.json` reads `"@types/node": "26.2.0"`. Only then was the ignore removed.

**The exact diff — two removals, no additions:**

```diff
-    # @types/node is majors-locked for the SAME reason, against a different
-    # runtime: its major tracks Node's, and this repo builds and runs on Node 24
-    # (docker/Dockerfile's builder stage, ci.yml's `node-version`), with Node
-    # majors already declined on a support-lifecycle argument in the `docker`
-    # entry below. tsconfig.node.json sets `"types": ["node"]`, so a @types/node
-    # ahead of the pinned runtime describes APIs the build does not have and
-    # feeds them straight into the type-aware ESLint gate. #145 proposed
-    # @types/node 26 against Node 24; 24.x was applied instead. Lifting this line
-    # is part of moving the Node major, not a bump to take on its own.
-    #
...
-      - dependency-name: "@types/node"
-        update-types: ["version-update:semver-major"]
```

**Why the comment goes with the rule rather than being rewritten.** Its central claim — *"tsconfig.node.json sets `"types": ["node"]`, so a @types/node ahead of the pinned runtime describes APIs the build does not have and feeds them straight into the type-aware ESLint gate"* — was true of the tree it was written against and is no longer true of this one. Step 4 (#179) wrote an explicit empty `types` array into `tsconfig.app.json`, and the #190 entry below measures the consequence: the app project loads **1,063 files and zero of them are `@types/node`**, against 82 for the node project. The reach is one file, `vite.config.ts`. A comment whose premise has been retired is worse than no comment, because it reads as a live argument. Its factual content is not lost — it is preserved in the entry below alongside the measurement that superseded it.

**DELIBERATE NON-ACTION — no `ignore` rule was added for `typescript`, and none should be.** This is the half of this change most likely to be "fixed" by a future session, so it is recorded as a decision rather than an omission. TypeScript 7 is **wanted**; what blocks it is entirely upstream (`typescript-eslint`'s `typescript` peer range, whose upper bound has never exceeded `<6.1.0` across all 1,510 published versions — re-verified from the full packument today, not from `latest` alone). The regenerating Dependabot PR proposing `typescript@7.x` **is the notification mechanism** that tells us when upstream ships support: an ignore rule would silence exactly the signal we are relying on, while changing nothing about the blocker. This also stays consistent with the standing rule in the file's own surviving comment — an ignore says *"a bot may not make this decision"*, and it is not a parking space for work we intend to do.

**Dependabot itself suggested the opposite, on the PR closed today, which is worth recording.** Its automated reply to the closure reads: *"This pull request was built based on a group rule. Closing it will not ignore any of these versions in future pull requests. To ignore these dependencies, configure ignore rules in dependabot.yml."* Correct as a statement of mechanics and **wrong as advice here** — the PR reappearing is the desired behaviour, not a nuisance to suppress. A reply was posted on the PR saying so, so the reasoning is visible to anyone triaging the queue without reading this file.

**The reminder-surface chain moved twice more today, and the second move is the one that mattered.** The chain recorded in the step-8 entry below — #153 → #170 → #172 → #175 → #181 → #184 → #186 — continued to **#188** and then, minutes after #190 merged, to **#191**. #188 carried two updates (`@types/node` 24.13.3 → **26.1.2** and `typescript` 6.0.3 → 7.0.2) and was **auto-closed by Dependabot at 18:43:33**, not by hand; **#191** was opened four seconds later carrying **`typescript` alone**, its `frontend/package.json` diff a single line. Two observations worth keeping: the group really does collapse to exactly the declined item once everything else lands, as §8 anticipated; and #188's `@types/node` target had by then become a **downgrade** (26.1.2 against the 26.2.0 on `dev`), which is what a Dependabot PR held open across a merge looks like. **#191 was closed with a comment** recording the packument-wide check and stating that the PR should keep reappearing and be evaluated fresh each time rather than assumed permanently unsatisfiable.

**This file's edits are inert on `main` until the next promotion, exactly like every prior one.** Dependabot reads its configuration — `ignore` list included — from the repository's **default branch**, so a `dev`-only change to `.github/dependabot.yml` has no effect until a `dev` → `main` promotion carries it. That is the finding recorded in the queue-audit entry below, and the maintainer **declined** promoting this file to `main` on its own to close the lag (settings-audit entry below, 2026-08-09 — declined, not deferred). Two practical consequences of that, stated so neither is re-diagnosed: `main`'s copy has **never** carried the `@types/node` stanza (added on `dev` by #147, never promoted), so this removal deletes a rule that was **never live** — the file and the effective configuration are now *more* aligned, not less; and until the next release, Dependabot will keep offering `@types/node` majors regardless, because it always has been.

**What was deliberately not done.** No `ignore` entry was added for `typescript` or anything else. No other key in `dependabot.yml` was changed — not a `target-branch`, `schedule`, `directory`, `groups`, `commit-message`, nor any of the five surviving npm ignores (`@mantine/*`, `react`, `react-dom`, `@types/react`, `@types/react-dom`) or the `docker`/`docker-compose` ones. **One stale sentence in the file was left in place and is flagged rather than fixed:** the surviving *"Deliberately NOT ignored"* paragraph still describes the frontend tooling majors as *"the deferred #86 sweep tracked in docs/ROADMAP.md"* and says Dependabot should surface them *"until that PR is done"* — the sweep completed on 2026-08-09, so the paragraph's stated reason has lapsed even though its instruction must persist, now for the TS7-signal reason above. Rewriting it was outside this change's brief and is a maintainer call. No dependency, lockfile, source, test, or workflow file was touched; `docs/upgrades/frontend-toolchain-86.md` and `docs/ROADMAP.md` were not edited; `main` was not touched.

**Plan section affected:** `.github/dependabot.yml` (one npm `ignore` entry and its comment removed) and this entry. PR #191 (closed, not merged); #188 auto-closed by Dependabot. No code behaviour, schema, API contract, security model, job model, auth, or CI configuration changed; no locked decision re-opened — the `@mantine/*`, `react`, `react-dom` and `@types/react*` majors-ignores that enforce locked decision §2 are untouched.

---

### 2026-08-09 — Infra — `@types/node` 24.13.3 → 26.2.0: the sweep's one declined package taken deliberately, after step 4 had already shrunk its blast radius to one file

**What changed:** `frontend/package.json` (one line), `frontend/package-lock.json` (two entries),
plus `CHANGELOG.md` and this entry. **`@types/node` is the only package bumped.** No source, test,
or config file changed — `frontend/eslint.config.js`, both tsconfigs, `vite.config.ts` and
`postcss.config.cjs` are byte-identical to `dev`. `typescript` stays at **6.0.3** and no
`typescript-eslint` version moved; `main` was not touched.

**This is a deviation, and it is the maintainer's, made explicitly.** `docs/upgrades/frontend-toolchain-86.md`
§5 is titled *"The sweep does not need it. Keep it on the 24 line."*, the step-8 entry below records
`@types/node` as one of the sweep's **two deliberate exclusions**, and `.github/dependabot.yml`
carries a major-ignore for it whose comment says *"lifting this line is part of moving the Node
major, not a bump to take on its own."* All three still describe a decision that was correct when it
was made. The maintainer instructed this session to take 26.x anyway, on **currency** grounds rather
than on any claim that the sweep or a security finding requires it — and it does not: the only
`@types/node` constraints anywhere in the resolved tree are the **optional** peers of `vite@8.2.1`
(`^20.19.0 || >=22.12.0`) and `vitest@4.1.10` (`^20.0.0 || ^22.0.0 || >=24.0.0`), read from the
installed manifests, and the pinned 24.13.3 satisfied both. Nothing failed on it, before or after.

**The target was read live rather than from the sweep document.** `@types/node`'s
`dist-tags.latest` is **26.2.0**, not the 26.1.2 the reminder-surface PR proposes and not the 26.1.2
the document's §2 inventory lists — the same staleness §2 warns about, arriving again. Separately,
`dist-tags` carries a **`ts6.0` tag, and it also points at 26.2.0**, which is DefinitelyTyped's own
statement that this release is the one intended for the TypeScript 6.0 this repo pins. Both
packages declare `typeScriptVersion: "5.6"` and identical `typesVersions` redirects for `<=5.7`, so
TypeScript 6.0.3 reads the modern types on either side.

---

**Why §5's argument no longer applies, which is the finding that made the bump cheap.** §5's case —
inherited from #145's narrowing on 2026-08-03 — is that `tsconfig.node.json` sets
`"types": ["node"]`, so types ahead of the pinned Node 24 runtime *"describe APIs the build does not
have and feed them straight into the type-aware ESLint gate."* That was written while
`tsconfig.app.json` still **inherited** TypeScript's enumerate-everything `types` default and was
therefore ambiently pulling `@types/node` into all 80 files of `src/`. **Step 4 (#179) changed
that**, writing `"types": []` into `tsconfig.app.json` explicitly. Measured now rather than
reasoned about, with `tsc --listFiles`:

| Project | Files loaded | Of those, from `@types/node` |
|---|---:|---:|
| `tsconfig.app.json` (all of `src/`) | 1,063 | **0** |
| `tsconfig.node.json` (`vite.config.ts`) | — | **82** |

**The entire surface of this bump is one file, `vite.config.ts`**, whose only Node API use is
`process.env` at line 7 (grepped: `src/` contains zero references to `process`, `Buffer`,
`__dirname`, `__filename` or the `NodeJS.` namespace). And the declaration it consumes is
unchanged — `interface ProcessEnv extends Dict<string> {}` is character-identical in 24.13.3 and
26.2.0. Recorded because it means the §5 decision and this reversal are **not in conflict**: §5 was
right about a tree that no longer exists, and step 4 is what retired its premise.

---

**Node 24 compatibility was measured, not inferred from the major number — and the answer is
"yes, with an enumerated exception list."** `@types/node` majors track Node majors loosely, so
"26 types on a 24 runtime" is a claim that has to be checked in **both** directions. A first attempt
by grepping declaration text produced a 400-entry "removed" list that included `fs.readFileSync`,
which is obviously false: 26.2.0 declares its module members **without the `export` keyword** where
24.13.3 used it, so a text-shaped diff measures the formatting, not the API. That was caught by
spot-checking one implausible entry before believing the list — the same
noise-floor-before-measurement discipline the step 6 and step 7 entries below record, arrived at a
third time by a third route.

The real measurement enumerates every exported symbol of every `node:` module from both packages
using **the installed TypeScript 6.0.3 compiler API** (`createProgram` + `checker.getExportsOfModule`
over a synthetic file importing all 44/46 modules), classifies each by `SymbolFlags.Value`, and
diffs the two sets:

| | |
|---|---|
| Symbol rows | 1,235 (24.13.3) → 1,426 (26.2.0) |
| Modules | 44 → 46 — `node:ffi` and `node:quic` added, **none removed** |
| Added | 263 names — 65 value exports, 198 type-only |
| Dropped | 72 names — **31 value exports**, 41 type-only |

Both directions were then checked against a **real Node 24.19.0** — the head of the 24 line, which
is what `ci.yml`'s `node-version: "24"` resolves to — downloaded from `nodejs.org/dist` and run
directly, because this sandbox is on Node 22:

- **26 of the 31 dropped value exports still exist on Node 24.19.0**: 24 top-level `zlib.Z_*`
  constants (the aliases superseded by `zlib.constants.*`), plus `assert.CallTracker` and
  `buffer.SlowBuffer`. So **the new types really do stop describing a handful of APIs the pinned
  runtime still has** — the claim "26.x describes Node 24 correctly" is true in the aggregate and
  false in the particulars, and the particulars are these. The other 5 (`Z_ASCII`, `Z_BINARY`,
  `Z_DEFLATED`, `Z_TEXT`, `Z_UNKNOWN`) are absent from Node 24 too, so dropping them is a
  correction.
- **44 of the 65 added value exports do not exist on Node 24.19.0**, `node:ffi` and `node:quic`
  entirely (both `require()` throw), plus scattered additions such as
  `diagnostics_channel.boundedChannel`. This is precisely the hazard §5 named, now quantified: the
  types describe 44 runtime APIs the build's Node does not have.

**Neither list is referenced anywhere in this repository**, and neither is reachable from `src/` at
all, per the `--listFiles` result above. The residual is therefore real, bounded, and confined to
`vite.config.ts`: a future edit to that one file could type-check against a Node 26 API and fail at
build time under Node 24. It is written down rather than argued away.

---

**The `print-config` diff, run per §0.3's method note — on four files, not three.** App `.tsx`
(`src/pages/Dashboard.tsx`), library `.ts` (`src/lib/polling.ts`) and the test override
(`src/lib/polling.test.ts`) are the three classes the note prescribes; **`vite.config.ts` was added
as a fourth**, because it is the only file whose ambient type space this bump changes and the three
standard classes would have been structurally incapable of showing a difference. All four resolved
configs are **byte-identical before and after, 135 rules each** — nothing added, removed, or
re-severitied, and no parser or plugin identity string moved. That is the expected result for a step
that touches no linting package, and it is recorded as a measured result for the reason §0.3 exists:
the expected result is exactly the one that does not get checked.

**What moved in the lockfile: 306 → 306 packages, +8/−8.** Both lockfiles were parsed and compared
key by key: **zero added, zero removed, two bumped** — `@types/node` 24.13.3 → 26.2.0 and its sole
dependency `undici-types` **7.18.2 → 8.3.0**, a major, pulled by 26.2.0's `~8.3.0` requirement where
24.13.3 required `~7.18.0`. `undici-types` has no other requirer in either tree, and it contributes
`fetch`/`Response`/`Headers` typings into the **node** project's global space only, which `src/`
cannot see. `lockfileVersion` stays 3. The lockfile was written with **npm 11.19.0** installed into
a scratch prefix to match CI's Node 24 rather than the sandbox's Node 22 / npm 10.9.7 — the **ninth**
consecutive lockfile touch to use this method and the ninth clean diff — and `npm ci` was run
through the same npm 11 with the file's SHA-256 re-verified unchanged afterwards.

**Suites, measured on both sides, each from a fresh `rm -rf node_modules && npm ci`.** Baseline on
24.13.3: lint clean (13.2 s), `format:check` clean, **80 tests across 22 files**, build
**630.29 kB JS (`index-C771VE3z.js`) / 196.79 kB CSS (`index-BG7b_ejj.css`)**, `npm audit` **0**.
After the bump: lint clean (12.6 s), `format:check` clean, **80 tests across 22 files**, build
identical, audit **0**. `tsc -b --force` was run separately so the type check could not be served
from an incremental build info file. **The test comparison was made per test, not per total** — both
runs captured with `--reporter=json` and reduced to sorted `file :: full test name :: status`
triples, which **diff empty**. All three emitted assets are **byte-identical by SHA-256** to the
baseline, which is the right signal here: a types-only devDependency cannot reach the bundle.
**No lint finding was autofixed, in bulk or individually — there were none.**

**One stale record this bump creates, flagged rather than fixed.** `.github/dependabot.yml`'s
`@types/node` stanza is a **major**-ignore, and its comment now argues against a change that has
landed. Two reasons it was left alone: it was outside this session's explicit scope (`@types/node`
was to move, nothing else), and it is **inert on `dev` regardless** — Dependabot reads its `ignore`
list from the default branch, and `origin/main`'s copy of the file has no `@types/node` stanza at
all (the finding in the queue-audit entry below, re-confirmed here). Whether to drop the stanza,
keep it as a 27-major guard, or rewrite its rationale is a maintainer call, and the same is true of
§5 of the sweep document, which now describes a decision that has been reversed.

**What was deliberately not done.** No package other than `@types/node` moved, in `package.json` or
in the lockfile — **`typescript` stays at 6.0.3**, and no `typescript-eslint`, `eslint`, `vite`,
`vitest` or `jsdom` version was touched. **No lint rule was disabled, downgraded, or suppressed**,
and no pre-release or canary package was installed. No source, test, or config file changed.
`.github/dependabot.yml`, `docs/upgrades/frontend-toolchain-86.md` and `docs/ROADMAP.md` were
**not** edited. The separate TypeScript 7 investigation this session also ran was **investigation
only** — no install, no config edit, no PR — and its findings are the maintainer's to act on.
`main` was not touched.

**Plan section affected:** `frontend/package.json`, `frontend/package-lock.json`, `CHANGELOG.md`
§ Unreleased/Changed, and this entry. No code behaviour, schema, API contract, security model, job
model, auth, or CI configuration changed; no locked decision re-opened — React stays on 18 and
Mantine on v7, and `@types/node` declares no `react`, `react-dom`, `@types/react*` or `@mantine/*`
peer (it declares no peers at all).

---

### 2026-08-09 — Docs/Process — Roadmap updated for the completed #86 sweep, the re-cut react-router advisory, and the React-19-blocked router major

**What changed:** `docs/ROADMAP.md` only — three Track A items — plus this entry. **No
dependency version, lockfile, config file, workflow, or source file was touched**, no issue or
PR was actioned, and `main` was not touched. Each of the three edits was gated on a live check
made in this session rather than on a prior session's claim about it; all three premises held,
and what was checked is recorded per item below so the checks are not re-run from scratch.

**1 — The #86 frontend toolchain sweep item is struck as Done 2026-08-09.** The eight sweep
PRs were re-confirmed present on `dev` before the bullet was written, by reading `dev`'s own
history rather than by trusting the step entries below: **#171** (`typescript-eslint`
8.19.0 → 8.66.0, `a99815a`), **#174** (the ESLint 10 family, `4ad34c9`), **#177** (React
Compiler rules adopted with `set-state-in-effect` held off, `6902036`), **#179** (TypeScript
5.7.2 → 6.0.3, `9aa2dc2`), **#180** (Vitest 3.2.7 → 4.1.10, `306556d`), **#183** (jsdom
26.1.0 → 30.0.1, `265bf59`), **#185** (Vite 6.4.3 → 8.2.1 + `@vitejs/plugin-react`
4.3.4 → 6.0.5, `167b1c6`), **#187** (`globals`, `@testing-library/user-event`, `postcss`,
`7283801`). All eight are squash commits on `origin/dev`.

The replacement bullet names all eight and **both deliberately-excluded packages**, which is
the half most likely to be misread as an omission: **TypeScript 7** (no published
`typescript-eslint` accepts it — peer `>=4.8.4 <6.1.0` at `latest` and at canary — so the
ceiling is 6.0.3) and **`@types/node` 26** (nothing in the toolchain requires it; the pinned
24.x satisfies every peer in play). The bullet also states plainly that both will keep
appearing in Dependabot's grouped frontend PR until they are taken or ignored **on the default
branch**, which is the `ignore`-list-read-from-`main` finding recorded in the 2026-08-09
queue-audit entry below, restated in public-doc terms rather than cross-referenced.

**2 — The GHSA-qwww-vcr4-c8h2 re-cut request is struck, and the premise was verified live
rather than inherited.** The 2026-08-09 scoping entry below already reported the advisory as
re-cut; that report was treated as a hypothesis, not as grounds to strike the item. Two
independent live reads on 2026-08-09:

| Source | Result |
|---|---|
| The advisory record in `github/advisory-database` (`advisories/github-reviewed/2026/07/GHSA-qwww-vcr4-c8h2/…json`, via `raw.githubusercontent.com`) | **two** `affected` entries for `react-router`: `introduced 7.12.0 / fixed 7.18.2` and `introduced 8.0.0 / fixed 8.3.0`; `published` and `github_reviewed_at` both **2026-07-24T16:44:43Z**, `modified` **2026-08-07T18:14:58Z** |
| The npm registry's bulk advisory endpoint (`/-/npm/v1/security/advisories/bulk`) | the same advisory returned as two HIGH ranges, `>=7.12.0 <7.18.2` and `>=8.0.0 <8.3.0`; querying **7.18.2 alone returns `{}`** |

So the range really was re-cut to what the roadmap item asked for — `>= 7.12.0, < 7.18.2`,
with the 8.x range untouched — and the pinned 7.18.2 no longer matches. `api.osv.dev` was
attempted as a third source and is still unreachable from this environment (curl exit 56),
which is why the npm endpoint stands in as the independent corroboration; the two sources that
did answer agree exactly. The struck bullet keeps the *reason* the item existed (a standing
false HIGH in a vulnerability scanner's own pipeline teaches everyone to dismiss that
package's alerts) and the backport evidence, so the record survives the strike.

**3 — The `react-router` 7 → 8 item is reworded and moved out of the tooling-majors grouping.**
The old wording said it *"belongs with the tooling majors above"* and shared *"the same risk
the bumps above share."* That grouping is now doubly wrong: the tooling majors are done, and
the real blocker was never lint churn. Verified live at the published package on 2026-08-09 —
`react-router@8.3.0` is `dist-tags.latest` and declares `peerDependencies` of
`react: ">=19.2.7"` and `react-dom: ">=19.2.7"` — against `frontend/package.json`, which pins
`react` and `react-dom` at **18.3.1**. Both legs hold, so the item now says plainly that it is
blocked on a **React 19 decision, not a tooling bump**, and it moved from **Near-term** to
**Longer-term / speculative**, whose stated criterion is work *"gated on a scale threshold or
an explicit decision"* — the only section in the file whose framing fits a locked-decision
blocker. The migration's own cost (v8 folds `react-router-dom` back into `react-router`, so
all twelve import sites in `frontend/src/` move) is kept, now stated as what happens *after*
the decision rather than as a reason to batch it with the toolchain work.

**What was deliberately not done.** No dependency, lockfile, or config file was touched.
**#176 and its six deferred findings were not acted on** — the roadmap bullet links the issue
and says nothing more about it. **The currently-open Dependabot frontend-dependencies group PR
was not touched** — not merged, not closed, not commented on; the new bullet describes why the
two declined packages will keep being proposed, in general terms, without actioning the PR.
No advisory-improvement request was filed with GitHub: the re-cut had already happened, so
there was nothing to ask for. `docs/upgrades/frontend-toolchain-86.md` was **not** edited —
correcting the sequence document remains a maintainer call, and the sweep's completion is
recorded in the step-8 entry below and now in the roadmap. `CHANGELOG.md` was not touched:
nothing shipped. `main` was not touched.

**Plan section affected:** `docs/ROADMAP.md` § Track A (Near-term: the #86 sweep item and the
GHSA re-cut item both struck; the `react-router` item removed from Near-term) and § Track A
(Longer-term / speculative: the `react-router` item added, reworded), plus this entry. No code
behaviour, schema, API contract, security model, job model, auth, or CI configuration changed;
no locked decision re-opened — React stays on 18 and Mantine on v7, and the `react-router`
edit records that lock as the blocker rather than proposing to lift it.

---

### 2026-08-09 — Infra — #86 sweep step 8 landed: `globals` 17.9.0, `@testing-library/user-event` 14.6.3, `postcss` 8.5.26 — the sweep is complete, and its reminder-surface PR had already closed itself

**What changed:** `frontend/package.json` (three lines), `frontend/package-lock.json`, plus
`CHANGELOG.md` and this entry. This is **step 8 — the final step** of the eight-step sequence in
`docs/upgrades/frontend-toolchain-86.md`. **Those three packages are the only ones bumped.** No
source, test, or config file changed; `frontend/eslint.config.js`, both tsconfigs,
`vite.config.ts` and `postcss.config.cjs` are byte-identical to `dev`. `main` was not touched.

**Step 8's membership was read from the row rather than from the session brief, and the brief was
wrong.** The brief predicted step 8 was `@testing-library/user-event`, `globals`, `postcss` **and
`eslint-plugin-react-refresh` 0.4.16 → 0.5.3**, with the react-refresh bump described as the
non-trivial member needing a config migration. It is not in step 8. §6's Step 8 row names exactly
three packages, and **`eslint-plugin-react-refresh` belongs to Step 2**, where §6's Step 2 "Moves"
row places it and where it landed on 2026-08-09 as **#174** — `frontend/package.json` has read
`"eslint-plugin-react-refresh": "0.5.3"` since. Reported to the maintainer before anything moved,
per the standing instruction to follow the row and say so when the brief diverges.

**The three 0.5.x migration hazards were nevertheless re-verified against the *installed* 0.5.3**,
because the brief raised them and because step 2's entry recorded them as re-checked once, at
install time, rather than as permanently settled. All three are no-ops here, confirmed at the
artifact rather than from the changelog:

| 0.5.0 change | Checked against | Verdict |
|---|---|---|
| ESM-only, flat config required | installed `package.json`: `"type": "module"`, peer `eslint: "^9 \|\| ^10"` | no-op — this repo has been flat-config and ESM since Phase 0; there is no `.eslintrc*` anywhere |
| preferred export moved to a named `reactRefresh` exposing `plugin`/`configs` | `import()`ed the installed package: named exports are `default` and `reactRefresh`; `default` still carries `{rules, configs}` | no-op — `eslint.config.js` imports the **default** export and registers it as `plugins: {'react-refresh': reactRefresh}`, which still resolves `rules`, and `--print-config` lists the rule at the expected severity |
| `customHOCs` renamed to `extraHOCs`; HOC-call validation tightened | the rule's shipped `meta.schema`: `{extraHOCs, allowExportNames, allowConstantExport, checkJS}`, `additionalProperties: false` | no-op — the repo's single `react-refresh/only-export-components` usage passes `allowConstantExport` only, and sets no HOC option at all. Worth noting the failure mode it avoids: `additionalProperties: false` means a surviving `customHOCs` key would be a hard **config** error, not a silently-ignored option. |

**All three targets were re-checked at the registry before the bump; none had moved.**
`globals` 17.9.0, `@testing-library/user-event` 14.6.3 and `postcss` 8.5.26 are each still
`dist-tags.latest`, so no deviation from the document's targets was needed or proposed — the first
step in the sweep for which that is true of every member.

---

**The `globals` caution is the only judgement in this step, and it was answered by measurement.**
§6's Step 8 row carries an inherited warning: a `globals` bump can silently *shrink* a set, leaving
lint green while `eslint.config.js:20`'s `globals.browser` loses coverage — so inspect the set
rather than trust a green run. Inspected, on both sides, from the installed package:

| | 17.8.0 | 17.9.0 |
|---|---|---|
| `globals.browser` keys | 1,191 | **1,196** |
| added | — | `PerformanceMarkConditional`, `PermissionsPolicy`, `RTCIceCandidatePair`, `WebTransportDatagramsWritable`, `WebTransportSendGroup` (all `false`, i.e. read-only) |
| removed | — | **none** |

**Nothing shrank.** (For the record, since it costs nothing: `serviceworker` 324 → 326,
`sharedWorker` 292 → 294 and `worker` 343 → 347 also grew, and no set in the package lost an entry.
This repo consumes `browser` only.)

**The `print-config` diff, run on one representative file per file class, per §0.3's method note.**
App `.tsx` (`src/pages/Dashboard.tsx`), library `.ts` (`src/lib/polling.ts`) and the test override
(`src/lib/polling.test.ts`) all hold at **135 rules, with zero added, zero removed, and zero
severity or option changes**. The *only* difference in any of the three fully-resolved configs is
those five `languageOptions.globals` entries — no rule, no plugin identity string, no parser
setting moved. That is the expected result for a step that touches no linting package, and it is
recorded as a measured result rather than an assumed one because §0.3's whole lesson is that the
expected result is exactly what does not get checked.

**The build output is byte-identical, and that check was strengthened deliberately.** Prior steps
compared Vite's emitted **content hashes**; here all three artifacts were compared by **SHA-256 of
the file contents** — `index-C771VE3z.js`, `index-BG7b_ejj.css` and the sourcemap all match the
pre-bump baseline exactly. That is worth doing rather than inheriting the weaker check, because
unlike `globals` and `user-event`, **`postcss` is genuinely in the build path**: it runs via
`frontend/postcss.config.cjs` (`postcss-preset-mantine` + `postcss-simple-vars`) on every build. A
postcss patch that changed CSS output would be invisible to lint and to the test suite, and this is
the check that rules it out.

**What moved in the lockfile: 306 → 306 packages, and every line is accounted for.** Both lockfiles
were parsed and compared key by key rather than eyeballed: **zero added, zero removed, three
bumped** — `globals` 17.8.0 → 17.9.0, `@testing-library/user-event` 14.6.1 → 14.6.3, `postcss`
8.5.25 → 8.5.26 — plus the root manifest's three pins. `lockfileVersion` stays 3 and the file diff
is **+13/−13**, the smallest of the sweep. The one transitive *requirement* that moved is
`postcss`'s own `nanoid` range, `^3.3.16` → `^3.3.17`, which installs nothing: the tree already
carries **`nanoid@3.3.18`** from the 2026-08-09 advisory refresh, so 8.5.26 raising its floor past
GHSA-2v37-7h3g-55p8 is satisfied by a package that was already there. Nothing else in the resolved
tree changed — `eslint` (10.8.1), `typescript` (6.0.3), `vite` (8.2.1), `vitest` (4.1.10), `jsdom`
(30.0.1), `react`/`react-dom` (18.3.1) and `@mantine/*` (7.17.8) were read out of both lockfiles
rather than trusted from the diff.

The lockfile was written with **npm 11.19.0** installed into a scratch prefix to match CI's Node 24
rather than the sandbox's Node 22 / npm 10.9.7 — the **eighth** consecutive lockfile touch to use
this method and the eighth clean diff. `npm ci` was run through the same npm 11 and the lockfile's
SHA-256 re-verified unchanged afterwards, so what `--package-lock-only` produced is byte-identical
to what a real install writes.

**Suites, measured on both sides, each from a clean install.** Baseline (`npm ci` from the committed
lockfile): lint clean (14.0 s), `format:check` clean, **80 tests across 22 files**, build **630.29 kB
JS / 196.79 kB CSS**, `npm audit` **0 vulnerabilities**. After the bump, from a fresh
`rm -rf node_modules && npm ci`: lint clean (11.6 s), `format:check` clean, **80 tests across 22
files**, build identical, audit **0**. The test comparison was made **per test, not per total** —
both runs captured with `--reporter=json` and reduced to sorted `file :: full test name :: status`
triples, which **diff empty**. **No lint finding was autofixed, in bulk or individually — there were
none.**

---

**Sweep-completion assessment, made against #172's live diff rather than from memory.** Every one of
the thirteen packages **#172** proposes is now either landed or deliberately excluded:

| #172 proposes | Disposition |
|---|---|
| `typescript-eslint` 8.66.0 | landed, step 1 (#171) |
| `eslint` 10.8.0 · `@eslint/js` 10.0.1 · `eslint-plugin-react-hooks` 7.1.1 · `eslint-plugin-react-refresh` 0.5.3 | landed, step 2 (#174) — `eslint` at **10.8.1**, one patch *ahead* of the proposal |
| `typescript` 7.0.2 | **excluded** — §3.1's ceiling is 6.0.3; landed at **6.0.3** in step 4 (#179) |
| `vitest` 4.1.10 | landed, step 5 (#180) |
| `jsdom` 30.0.1 | landed, step 6 (#183) |
| `vite` 8.2.0 · `@vitejs/plugin-react` 6.0.5 | landed, step 7 (#185) — `vite` at **8.2.1**, ahead of the proposal |
| `@types/node` 26.1.2 | **excluded** — §5, "Action: none" |
| `globals` 17.9.0 · `@testing-library/user-event` 14.6.3 | landed here, step 8 |

Plus `postcss` 8.5.26, which #172 also carries and which the document assigns to step 0-or-8.

**Two exclusions, not one — and the second is worth stating plainly because it is easy to misread
as complete.** `@types/node` is the excluded member everyone remembers (§5). But **`typescript` is
excluded too**, because #172 proposes **7.0.2** and the sweep deliberately stopped at **6.0.3**.
Eleven of thirteen landed; two did not, and both non-landings are decisions rather than omissions.

**The TypeScript ceiling was re-checked on the day, and it has not moved.**
`typescript-eslint@latest` is still **8.66.0** peering `typescript: ">=4.8.4 <6.1.0"`, and its
canary `8.66.1-alpha.10` declares the same. Two consequences that point in opposite directions and
must not be conflated:

- **The installed `typescript@6.0.3` sits inside that range**, so nothing in the shipped toolchain
  is straining a peer bound — the sweep's end state is a satisfiable graph.
- **#172's own `typescript` member is still outside it.** `7.0.2` against `<6.1.0` is the same
  `ERESOLVE` that killed #153, #170 and every regeneration since. So #172 is *not* merely stale,
  it is **still unsatisfiable as composed**, and completing the sweep did not make it mergeable.

**#172 was already closed before this session, and not by a maintainer.** Read live: `state:
closed`, `merged: false`, `closed_at: 2026-08-09T11:27:01Z`, carrying exactly one comment — from
`dependabot[bot]`, *"Looks like these dependencies are updatable in another way, so this is no
longer needed."* Dependabot superseded it automatically when step 2 (#174) landed, three minutes
before. **No close action was taken here, and none was needed.**

**The reminder surface has moved four times in one day, which is the finding that generalises.**
The chain from the scoping document's #153 now reads **#153 → #170 → #172 → #175 → #181 → #184 →
#186**, each opened against the then-current `dev` and each auto-closed by Dependabot within
minutes of the next sweep step landing (#172 13 updates → #175 9 → #181 8 → #184 7 → **#186 5,
open**). §8's advice — *"close it only when Step 7 lands"* — was written for a PR expected to sit
still; in practice the group regenerates after **every** merge that touches `frontend/package.json`,
so a specific PR number is a snapshot, not a handle. **#186** is the live one: opened
2026-08-09T17:00:26Z from `167b1c6`, carrying five updates — this step's three (`globals` 17.9.0,
`@testing-library/user-event` 14.6.3, `postcss` 8.5.26) plus the two declined ones (`@types/node`
26.1.2, `typescript` 7.0.2). Once this step merges it should regenerate down to **exactly the two
declined items**, which is the honest end state §8 anticipated. **#186 was deliberately not
touched** — it was not in this step's scope, and closing or commenting on a PR the maintainer has
not seen is not a call this session makes.

**Which of the document's Step 8 predictions held.**

- **"`globals` 17.8.0 → 17.9.0, `@testing-library/user-event` 14.6.1 → 14.6.3, and `postcss`
  8.5.25 → 8.5.26 if not already taken in Step 0" — HELD, including the conditional.** Step 0 (the
  2026-08-09 lockfile refresh) took `js-yaml` and `nanoid` only and left `package.json` untouched,
  so `postcss` was still at 8.5.25 and belonged here.
- **"Mechanical, no config change, no coupling" — HELD**, and the no-coupling half is now
  measured rather than asserted: zero packages added or removed from the lockfile.
- **The inherited `globals` caution — HELD as a caution and answered in the favourable
  direction.** The set grew by five and lost nothing. The row prices this as *"a spot-check, not an
  investigation"*, which was right.
- **"Fold into whichever step is convenient, or take alone" — taken alone**, consistent with every
  other step in the sweep having exactly one plausible cause of failure.
- **Effort priced 15 min / very low — accurate for the bump**; essentially all the time went on the
  baseline/after measurements (two clean installs, two `print-config` sweeps, the globals set diff,
  the byte-level asset comparison), which is the sweep's standing exit criteria rather than this
  step's cost.

**What was deliberately not done.** No package other than the three step 8 names moved, in
`package.json` or in the lockfile — in particular **`@types/node` stays at 24.13.3** and
**`typescript` stays at 6.0.3**, both per the document's own decisions. No lint finding was
autofixed, in bulk or individually. No source, test, or config file changed. **#172 was not closed
(it already was, by Dependabot) and no comment was posted on it**; **#186 was not touched**;
`docs/ROADMAP.md` was **not** edited — marking Track A's sweep item complete is a maintainer call,
and one is proposed to the maintainer rather than made here.
`docs/upgrades/frontend-toolchain-86.md` was **not** edited either, on the same standing basis as
every prior step: correcting the sequence document is the maintainer's, and this entry is the
record of what its Step 8 row got right in the meantime — which, uniquely in this sweep, is all of
it. `main` was not touched.

**Plan section affected:** `frontend/package.json`, `frontend/package-lock.json`, `CHANGELOG.md`
§ Unreleased/Changed, and this entry. No code behaviour, schema, API contract, security model, job
model, auth, or CI configuration changed; no locked decision re-opened — React stays on 18 and
Mantine on v7, and none of `globals`, `@testing-library/user-event` or `postcss` declares a
`react`, `react-dom`, `@types/react*` or `@mantine/*` peer.

---

### 2026-08-09 — Infra — #86 sweep step 7 landed: Vite 6.4.3 → 8.2.1 + `@vitejs/plugin-react` 4.3.4 → 6.0.5; the partial oracle was closed by a pixel diff, but only after its noise floor was calibrated

**What changed:** `frontend/package.json` (two lines), `frontend/package-lock.json`, plus
`CHANGELOG.md` and this entry. This is **step 7 of the eight-step sequence** in
`docs/upgrades/frontend-toolchain-86.md` — the step §8 ranks as the highest-risk of those that must
happen, on the grounds that it is *"the only step whose worst failure passes CI."* **`vite` and
`@vitejs/plugin-react` are the only packages bumped.** `frontend/vite.config.ts`, both tsconfigs,
`frontend/eslint.config.js`, `postcss.config.cjs`, and every production source and test file are
byte-identical to `dev`. No step 8 work was started; `main` was not touched.

**The targets were re-checked at the registry, and one had moved — escalated rather than assumed.**
The session brief named **vite 8.2.0**. `vite`'s `dist-tags.latest` is **8.2.1** (published
2026-08-06; 8.2.0 was 2026-07-30), which is inside the same constraints — same major, satisfies
plugin-react 6.0.5's `vite: ^8.0.0` peer, same `engines.node` — and the scoping document's §2
inventory already flags 8.2.0 as stale and prescribes *"Take 8.2.1"*. Per the maintainer's standing
instruction to ask when a newer version exists inside the same constraints, **this was put to the
maintainer rather than decided**; 8.2.1 was authorised. `@vitejs/plugin-react@6.0.5` is still
`latest` and needed no deviation. 8.2.1 over 8.2.0 moves `rolldown ~1.2.0 → ~1.2.1` and
`postcss ^8.5.23 → ^8.5.25` — the former mattering here precisely because Rolldown is the thing
whose output this step exists to compare.

**§3.3 is half wrong, and the correction was put to the maintainer because it could have changed
the step's shape.** The document states there is *"no version of the plugin that spans the
boundary"* and that plugin-react 5.x supports only Vite 6 and 7. Read from the published manifests:

| plugin-react | `peerDependencies.vite` | Babel deps |
|---|---|---|
| 4.3.4 *(pinned)* | `^4.2.0 \|\| ^5.0.0 \|\| ^6.0.0` | 4 |
| 5.0.0 | `… \|\| ^7.0.0` | 4 |
| **5.2.0** | **`… \|\| ^7.0.0 \|\| ^8.0.0`** | 4 |
| 6.0.0 / 6.0.5 | **`^8.0.0` only** | **0** |

So **5.2.0 does span Vite 6→8**, and "Vite 8 alone, holding the plugin on 5.x" is a resolvable
graph that would have separated the bundler major from the plugin major. The maintainer was offered
that split and **declined it**, keeping step 7 as one step: the plugin's 4→5→6 span is where Babel
was dropped, and splitting would land a plugin version nobody intends to keep and then immediately
replace it. **The other half of §3.3 holds and was verified**: plugin-react 6 peers `^8.0.0` alone,
non-optional, so it genuinely *requires* Vite 8 rather than tolerating it.

**Vitest 4 does not constrain the Vite major — re-verified at the manifest, not inherited.**
`vitest@4.1.10` declares `vite: "^6.0.0 || ^7.0.0 || ^8.0.0"` as a required peer (`optional: false`)
*and* as a real `dependencies` entry at the same range. Vite 8.2.1 satisfies it, so step 5's landing
neither blocks nor is broken by this step. `engines.node` on both new packages is
`^20.19.0 || >=22.12.0`; CI's Node 24, the pinned `node:24-bookworm-slim` (24.18.1) and this
sandbox's 22.22.2 all satisfy it, and **jsdom 30's floor from step 6 still dominates**, so
`README.md`, `CONTRIBUTING.md`, `ci.yml` and `docker/Dockerfile` needed no edit.

---

**The Babel question, answered before anything was changed: nothing to move, nothing to drop.**
plugin-react 6.0.0 removed every Babel-related feature, and the migration path for a repo that
passes a `babel` option is to move that config to `@rolldown/plugin-babel` or drop it. **This repo
passes no such option.** `frontend/vite.config.ts` is `plugins: [react()]` with no arguments; there
is no `.babelrc*`, no `babel.config.*`, and no occurrence of the string `babel` in any `.ts`,
`.tsx`, `.js`, `.cjs`, `.mjs` or `.json` file under `frontend/` outside the lockfile. So the hazard
is a **no-op here**, and no babel configuration was relocated or removed — there was none to touch.

**React Fast Refresh was smoke-tested rather than assumed, because the mechanism genuinely
changed.** plugin-react 4 implemented Refresh through Babel plus the `react-refresh` npm package,
both of which leave the tree in this step; Vite 8 implements it through Oxc. The dev server was
started on the new toolchain and confirmed to (a) boot (`VITE v8.2.1 ready in 305 ms`), (b) serve
the runtime at `/@react-refresh`, and (c) inject `$RefreshReg$` / `RefreshRuntime` into the
transform of `src/App.tsx`. Worth doing by hand: nothing in the test suite or the production build
exercises Refresh, so its loss would have been silent until a contributor noticed HMR stopped
working.

---

**Build-output comparison, which is the substance of this step.** Measured from a clean
`rm -rf node_modules && npm ci` on each side, both installs and both lockfile writes performed with
**npm 11.19.0** in a scratch prefix to match CI's Node 24 rather than the sandbox's npm 10.9.7 —
the **seventh** consecutive lockfile touch to use this method.

| | Vite 6.4.3 | Vite 8.2.1 | Δ |
|---|---|---|---|
| modules transformed | 7,035 | 7,018 | −17 |
| JS | 645.14 kB / `index-Vvdzytcz.js` | 630.29 kB / `index-C771VE3z.js` | **−14,845 B (−2.30%)** |
| JS gzip | 193.61 kB | 187.36 kB | −6.25 kB |
| CSS | 201.38 kB / `index-D2wHtcHV.css` | 196.79 kB / `index-BG7b_ejj.css` | **−4,586 B (−2.28%)** |
| CSS gzip | 29.30 kB | 28.63 kB | −0.67 kB |
| sourcemap | 2,959,362 B | 2,734,561 B | −224,801 B |
| build time | 7.30 s | 1.28 s | −5.7× |
| lint / `format:check` / audit | clean / clean / 0 | clean / clean / 0 | — |
| tests | 80 across 22 files | 80 across 22 files | diffed per test name, empty |

**Asset content hashes changed on both files, and that is the correct signal here** — unlike steps
1, 2, 4, 5 and 6, where an unchanged hash was the proof the step could not reach the bundle. A
bundler and a CSS minifier both changed engine; identical output would have meant the bump had not
taken effect.

**The module delta was attributed by census, not explained by plausible story.** A throwaway
`vite.modules.config.ts` spread the real config and added a plugin recording `this.getModuleIds()`
at `buildEnd`; it was run under both toolchains and the two lists diffed, then the probe was
deleted. **19 ids exist only under Vite 6** — `commonjsHelpers.js` plus the `?commonjs-es-import` /
`?commonjs-exports` / `?commonjs-module` proxy modules that `@rollup/plugin-commonjs` mints when
converting `react`, `react-dom`, `scheduler`, `cookie`, `fast-deep-equal` and `set-cookie-parser`
from CJS to ESM. Rolldown handles CommonJS in the bundler core and mints none. **1 id is new**:
`vite/preload-helper.js`, a Vite-internal helper. 7,035 − 19 + 1 = 7,017 census ids against the
reporter's 7,018, a one-module accounting difference in the reporter. **No application or library
module was added or removed** — the delta is interop scaffolding only.

**The CSS was diffed declaration by declaration, because §8's whole argument for ranking this step
above jsdom is that a Lightning CSS regression fails nothing.** Eyeballing a minified diff is not a
check: both minifiers reformat everything. So both stylesheets were parsed into
(at-rule context, selector, declarations); every comma-joined selector list was **split into
individual selectors** so that rule merging on one side and rule splitting on the other cancel out;
colours were canonicalised to a common `rgba` form; and the shorthands Lightning CSS introduced
(`inset`, `padding-inline`, …) were expanded back to longhands.

| | |
|---|---|
| individual (context, selector) keys | **1,171 on each side** |
| keys only in baseline / only after | **0 / 0** |
| declarations lost / added | **0 / 0** |
| declarations differing | 46, all semantics-preserving rewrites |

The 46 break down as **29 vendor prefixes dropped where the unprefixed property is present**
(`-moz-appearance` ×14, `-webkit-appearance` ×14, `-webkit-transform` ×1) and 17 value rewrites, of
which 13 are `.15s ease` → `.15s` (`ease` is the initial `transition-timing-function`, so the
elision is exact) and the remaining four are `transparent` → `#00000000`,
`background-position: center` → `50%`, a whitespace trim inside a custom-property value, and
`linear-gradient(… C 25%, C 50% …)` → `… C 25% 50%` (multi-position colour stops, CSS Images 4).
Structural rewrites that the per-selector normalisation absorbed, each checked by hand:
`:nth-of-type(1)` → `:first-of-type`, `*:before` → `:before`, `:where(*:not(style))` →
`:where(:not(style))`, `-.24s` → `-240ms`, `0rem` → `0`, `top/right/bottom/left: 0` → `inset: 0`,
adjacent rules with identical declaration blocks merged, and **the six `::-webkit-*`
spin/search-button selectors split out of one comma list into six separate rules** — which is a
correctness *improvement*, since a browser that cannot parse one selector in a comma list discards
the entire rule.

**The browser target rose, and that is the one genuine behaviour change in this step.** Vite 8
defaults `build.target` to `baseline-widely-available`, which resolves — read out of the installed
`vite/dist/node/` rather than from the guide — to **chrome111 / edge111 / firefox114 / safari16.4**,
against esbuild's `modules` default of roughly Chrome 87 / Firefox 78 / Safari 14. §6's Step 7 row
predicted exactly this. Every syntax Lightning CSS newly emitted was checked against that floor:
Media Queries Level 4 range syntax (`@media screen and (device-width<=31.25em)`, replacing
`max-device-width`) needs Safari 16.4 — *exactly* the floor, with no margin; multi-position colour
stops need Safari 12.1; unprefixed `appearance` needs Safari 15.4. All inside the target. **No
project document states a browser-support floor**, so nothing needed correcting — recorded here
because the change is real and invisible, and a future decision to support an older browser would
have to set `build.target` explicitly rather than inherit it.

---

**The render check, and the methodological finding worth keeping.** §6's Step 7 row asks for
*"actually run the app — `docker compose up` and click through the SPA in both light and dark
mode."* No Docker daemon is available in this sandbox (the CLI is present, as the 2026-08-09
scoping entry records), so the equivalent was built from the pre-installed Chromium: serve each
`dist/` over a static server, stub `/api/**` with fixtures so the SPA settles deterministically,
and screenshot **six routes** (dashboard, scans list, new scan, scan detail, settings, account) in
**both colour schemes** — twelve views per build — then diff the PNGs pixel by pixel. This is
strictly stronger than a human click-through, which cannot detect a two-pixel shift.

**The first pass diffed non-empty, and taking it at face value would have been wrong.** One view
(`scans-light`) differed by 171 pixels. Before interpreting that as a Lightning CSS regression, the
same build was rendered **twice** and the two runs diffed: **three views differed from themselves,
by 133–138 pixels** — the same order of magnitude. In-flight Mantine animations (the fixture set
includes a `running` scan, hence a live `Loader`) were being caught at different frames. **A
measurement whose noise floor is unknown is not a measurement** — the identical lesson step 6's
entry recorded about the selector-drift shim, arrived at independently by a different route, which
is the reason to write it down twice.

The fix was to freeze animations at their final state via Playwright's
`screenshot({ animations: 'disabled', caret: 'hide' })` rather than to suppress them with injected
CSS, which would have masked the very animation declarations the CSS diff had just examined.
Re-calibrated: **two runs of the same build are now identical across all twelve views — a noise
floor of exactly zero.** Against that floor:

**All twelve views are pixel-identical between Vite 6.4.3 and Vite 8.2.1, in both light and dark
mode.** That is the result this step needed, and it closes §9's still-open question 6 (*"whether
Vite 8's Lightning CSS minification changes Mantine's rendered output"*) by measurement.

**What the pixel diff does not cover, stated so it is not over-read.** Screenshots reach only
rendered, settled states: the `@media (hover: hover)` and `:active` blocks (a large share of the
merged rules), the `::-webkit-*` spin-button rules, and modal/popover/accordion-open states are not
in the twelve views. Those were covered textually instead, by the declaration-level diff above,
which is exhaustive over the stylesheet in a way the screenshots are not. The two checks are
complementary, and neither alone would have been enough.

---

**What moved in the lockfile: 339 → 305 packages, every movement attributed to a requirer.** Both
lockfiles were parsed and each added/removed/bumped package's requirers resolved in both trees:

- **30 added.** `rolldown@1.2.3` (required by `vite`) plus its 15 `@rolldown/binding-*` platform
  packages and `@oxc-project/types@0.143.0`; `lightningcss@1.33.0` (required by `vite`) plus its 12
  `lightningcss-*` platform packages and `detect-libc`; and `@rolldown/pluginutils@1.0.1`, the sole
  runtime dependency of `@vitejs/plugin-react@6.0.5`.
- **61 removed**, each checked to have no surviving requirer: `esbuild@0.25.12` and its 25
  `@esbuild/*` platform packages; `rollup@4.62.2` and its 25 `@rollup/rollup-*` platform packages;
  plugin-react 4's Babel subtree (`@babel/plugin-transform-react-jsx-self`,
  `…-jsx-source`, `@babel/helper-plugin-utils`, and the four `@types/babel__*`); and
  `react-refresh@0.14.2`. `esbuild` retains one *optional peer* reference from `vite@8.2.1`
  (`^0.27.0 || ^0.28.0`) and is therefore not installed.
- **3 bumped.** The two targets, plus `picomatch` — a nested `4.0.4` copy deduping into the single
  top-level `4.0.5`.

**The one entry that could plausibly have been shared was checked specifically.** `@babel/core` and
`@babel/parser` **survive at 7.29.7** and are *not* in the removed list: their only requirer is now
`eslint-plugin-react-hooks@7.1.1`. This is the exact inverse of what step 2's entry recorded — there,
plugin-react 4 already supplied them so react-hooks 7 cost zero new packages; here plugin-react 6
drops them and react-hooks is the sole reason they remain. Had the two steps landed in the other
order, this step would have shown four Babel packages leaving rather than three plus four types.
`react`, `react-dom` (18.3.1), `@mantine/*` (7.17.8), `typescript` (6.0.3), `eslint` (10.8.1),
`vitest` (4.1.10), `jsdom` (30.0.1) and `postcss` (8.5.25) are unchanged in the resolved tree, read
out of both lockfiles rather than trusted from the diff.

`lockfileVersion` stays 3 and the file diff is **+556/−978** — proportionate to 61 removals against
30 additions, with no whole-file re-normalisation. `npm ci` was run through the same npm 11 and the
lockfile's SHA-256 re-verified unchanged afterwards, so what `--package-lock-only` produced is
byte-identical to what a real install writes. The build was additionally re-run from a second clean
install and produced **identical content hashes**, so the output is reproducible rather than
incidentally equal.

**Which of the document's Step 7 predictions held.**

- **"Moves both, in lockstep — peer-forced" — HELD for the destination, but its stated reason is
  wrong.** plugin-react 6 does require Vite 8. But *"no version of the plugin spans the boundary"*
  is false as of 5.2.0 (§3.3 correction above). The step stayed whole by the maintainer's decision,
  not by the constraint the document claims.
- **"Config changes: none required in `vite.config.ts`" — HELD**, and each supporting clause
  re-verified against the file: no `build.rollupOptions`, no `esbuild`/`optimizeDeps`/`manualChunks`
  keys, `plugins: [react()]` with no options, and `server.proxy` / `build.outDir` /
  `build.sourcemap` all still honoured (the sourcemap is emitted).
- **"plugin-react 6's Babel removal is a no-op because the repo passes no `babel` option" — HELD**,
  verified by search across the whole `frontend/` tree rather than by reading the config alone.
- **"This is the only step that can change what ships" — HELD.** JS −2.30%, CSS −2.28%, both asset
  hashes new, and the browser target raised.
- **"The default browser target rises to Chrome/Edge 111, Firefox 114, Safari 16.4" — HELD
  exactly**, resolved from the installed package.
- **"CSS minification moves to Lightning CSS — which matters here because Mantine emits 201 kB of
  CSS" — HELD as to mechanism, and the feared outcome did not occur.** Lightning CSS rewrote
  pervasively; it changed nothing semantically and nothing observable.
- **"Verifies it: compare the emitted bundle against the baseline, then actually run the app… a CSS
  minifier change does not fail a build; it fails a render" — HELD, and it is the row's most
  valuable sentence.** It is the reason a pixel diff was built at all. The row's *"run it and click
  through"* prescription is weaker than what it motivates, though — see the noise-floor finding
  above, and note that a human click-through has no noise floor to calibrate and no way to detect a
  sub-perceptual shift.
- **"Effort L / half a day, risk medium–high" — came in mid-band on effort**, essentially all of it
  spent on the two comparison harnesses (module census, pixel diff) rather than on the bump, which
  was a two-line edit that was green first run. **Risk, in hindsight, was priced correctly**: the
  step really did change the shipped bytes, and nothing but a purpose-built comparison would have
  told the difference between "changed and fine" and "changed and broken."

**What was deliberately not done.** No package other than `vite` and `@vitejs/plugin-react` moved,
in `package.json` or in the lockfile — in particular **step 8's `globals`, `@testing-library/user-event`
and `postcss` were not touched**, and no lint finding was autofixed, in bulk or individually
(there were none). No source, test, or config file changed. **Both measurement probes were deleted
before the PR** — `vite.modules.config.ts` removed and the working tree confirmed to carry only
`package.json` and `package-lock.json` under `frontend/`; the Playwright harness lived entirely in
the scratch directory and never entered the repository, and `playwright` was installed into a
scratch prefix rather than into `frontend/`, so it appears in neither `package.json` nor the
lockfile. `build.target` was **not** pinned to preserve the old browser floor — the raised target is
Vite 8's documented default and no project document contradicts it; pinning it would be a product
decision, not a bump. `docs/upgrades/frontend-toolchain-86.md` and `docs/ROADMAP.md` were **not**
edited — correcting the sequence document is a maintainer call, and this entry is the record of what
its Step 7 row and §3.3 got right and wrong in the meantime. No step 8 work was started; `main` was
not touched.

**Plan section affected:** `frontend/package.json`, `frontend/package-lock.json`, `CHANGELOG.md`
§ Unreleased/Changed, and this entry. No code behaviour, schema, API contract, security model, job
model, auth, or CI configuration changed; no locked decision re-opened — React stays on 18 and
Mantine on v7, and neither `vite@8.2.1` nor `@vitejs/plugin-react@6.0.5` declares a `react`,
`react-dom`, `@types/react*` or `@mantine/*` peer.

---

### 2026-08-09 — Infra — #86 sweep step 6 landed: jsdom 26.1.0 → 30.0.1; the selector-drift shim diffed empty, but only after the shim itself had to be fixed

**What changed:** `frontend/package.json` (one line), `frontend/package-lock.json`, `README.md`
(one line) and `CONTRIBUTING.md` (one bullet) for the raised Node floor, plus `CHANGELOG.md` and
this entry. This is **step 6 of the eight-step sequence** in
`docs/upgrades/frontend-toolchain-86.md`. **`jsdom` is the only package bumped.** `vite` stays at
**6.4.3** (step 7); `frontend/vite.config.ts`, both tsconfigs, `frontend/eslint.config.js`,
`src/test/setup.ts` and every production source and test file are untouched. No step 7 work was
started; `main` was not touched.

**The target was re-checked at the registry before anything moved.** `jsdom`'s `dist-tags.latest`
is still **30.0.1**, and the 30 line contains exactly two releases — 30.0.0 and 30.0.1 — so there
is no newer 30.x and no deviation from the document's target was needed or proposed.

**The Node floor was verified across all three runtimes, because this is the one step whose
`engines` constraint reaches outside the test run.** `jsdom@30.0.1` declares
`engines.node: "^22.22.2 || ^24.15.0 || >=26.0.0"`, read from the published manifest:

| Runtime | Version | Satisfies `^22.22.2 \|\| ^24.15.0 \|\| >=26.0.0`? |
|---|---|---|
| CI — `ci.yml` `node-version: "24"` | resolves to **24.19.0** (current head of the 24 line, `nodejs.org/dist/index.json`) | yes, `^24.15.0` |
| Image — `docker/Dockerfile:27` `node:24-bookworm-slim@sha256:235600a8…` | **24.18.1** | yes, `^24.15.0` |
| This sandbox | **22.22.2** | yes — and it is *exactly* the `^22.22.2` floor, with no margin |

**The Dockerfile's digest is unchanged from the one §9 resolved, and was re-resolved rather than
inherited**, by the two independent methods that entry records, which agree: Docker Hub's tag index
maps `sha256:235600a8…` to exactly `24.18.1-bookworm-slim` and `24.18-bookworm-slim` (both last
updated 2026-07-30), and the image's `linux/amd64` config blob — fetched through `mirror.gcr.io`,
since Docker Hub 307-redirects blobs to the egress-blocked `production.cloudfront.docker.com` —
carries `NODE_VERSION=24.18.1`, `created: 2026-07-30T19:05:08Z`. **So `ci.yml` and the Dockerfile
need no edit**, exactly as §7.5 predicts. Worth doing by hand rather than trusting a green CI run:
there is no `.npmrc`, so `engine-strict` is off and a violation would be a non-fatal `EBADENGINE`
warning, not a failure.

**The sandbox sitting exactly on the floor is a coincidence worth flagging, not a comfort.** Node
22.22.2 satisfies `^22.22.2` by one patch. Any local run on a 22.x below that — or on a 24.x below
24.15.0 — would silently execute the suite on a runtime jsdom does not support. That is precisely
the contributor-facing hazard §7.4 names, and it is why the two docs edits are in this PR.

**`README.md` and `CONTRIBUTING.md` raised from "Node 22+" to "Node 22.22.2+ or 24.15+".** Both
previously stated a floor a contributor on Node 22.13 would satisfy — that runtime installs
cleanly (npm does not enforce `engines` here) and then runs `npm test` under an unsupported jsdom.
`CONTRIBUTING.md` additionally names the constraint's source inline, because "22.22.2" is
otherwise an arbitrary-looking number that a future edit would round back down to "22".

---

**The step 6 checklist measurement — the selector-drift shim.** jsdom 27.0.0 swapped the CSS
selector engine (`nwsapi` → `@asamuzakjp/dom-selector`). §8's audit establishes that a green suite
catches a query finding *nothing* or *too much*, but not a query resolving to a **different**
element while every downstream assertion still passes — and it explicitly declines to argue that
residual away, handing it to this step as a two-run measurement instead. That is what was done, and
it is the substantive content of this step.

**What the shim did.** A throwaway `frontend/src/test/drift-shim.ts`, added as a second entry in
the jsdom project's `setupFiles`, wrapped every own function property of `screen` matching
`/^(get|query|find)(All)?By[A-Z]/` and appended one line per resolved element to a log file named
by a `DRIFT_LOG` env var. Each line is keyed
`<test file> :: <full test name> :: #<nth query in that test> :: <method>(<args>)` and carries the
resolved element's description. Async `find*By*` results are logged on settle, and a throw or
rejection is logged as such rather than dropped, so a "found nothing" outcome is part of the
diffed record rather than a hole in it. Set-valued results (`getAllBy*`) log every element.

**The shim as the document prescribes it does not work, and this is the transferable finding.**
§8 and Step 6's checklist specify logging `element.outerHTML.slice(0, 120)` keyed by test name and
call index. Written exactly that way, **two runs on the *same* jsdom version diff non-empty** —
verified before touching the version, which is the only reason it was caught. Two independent
causes:

- **Mantine's `useId` mints a fresh random id per run.** 20-odd lines differed only in
  `id="mantine-2hy2ovekj"` versus `id="mantine-0z1njuojt"`. Pure noise, but it is *inside* the
  first 120 characters of most Mantine elements, so it dominates the diff.
- **One line differed in real content**, not just ids: `BackupsPanel.test.tsx`'s
  `getByRole('button', {name: 'Save schedule'})` at call #005 logged `len=760` in one run and
  `len=314` in the other — the same button, caught with and without its transient loading state,
  a timing-dependent DOM state rather than a different element.

**A measurement whose noise floor is unknown is not a measurement.** Had the shim been written to
spec, run once per version, and diffed, it would have produced ~20 differing lines on a bump that
in fact changed nothing — and the honest reading of that output is indistinguishable from real
drift without doing this calibration anyway. The fix was to log an element **identity** rather than
its rendered bytes: the element's DOM index path from the document root
(`html>body>div[0]>…>button[1]`) alongside a normalised `outerHTML` slice with
`mantine-[a-z0-9]{6,}` collapsed to `mantine-ID`. The index path is what "resolved to a different
element" actually means, and unlike `outerHTML` it does not move when the element's own contents
are mid-transition. **The normalisation is the only edit made to what gets logged**, and it was
validated the only way it can be: by re-running the unmodified suite twice on jsdom 26.1.0 and
confirming the two logs are byte-identical. They are.

> **Standing note — the shim specification in `docs/upgrades/frontend-toolchain-86.md` §8 is
> methodologically broken, and not only for this step. Use the shape below instead, in any future
> drift check.**
>
> This is a defect in the *technique*, not a one-off miss in one step's execution, and it recurs
> anywhere the app under test mints identifiers per render. §8 prescribes logging
> `element.outerHTML.slice(0, 120)` keyed by test name and call index. Any React app on Mantine
> hits `useId` on essentially every labelled control, input, alert and popover — and React's own
> `useId`, Emotion, Radix, Headless UI, Chakra and MUI all do the same thing — so a fresh random
> id appears *inside the first 120 characters* of most elements, on every run. The log is then
> re-randomised per run and a diff of two logs measures the id generator, not the DOM. A second,
> subtler source is the same: `outerHTML` captures the element's **contents**, so any element
> caught mid-transition (a button with and without its loading spinner, a list mid-fetch) differs
> between runs while being the same element. Both were live here.
>
> **Why it is worse than merely noisy.** The failure is silent and points the wrong way. A
> spec-conformant shim run once per version produces a large non-empty diff on a bump that changed
> nothing, and "non-empty diff" is exactly the signal the check exists to raise. Reading that
> output honestly means investigating ~20 phantom drifts, or — the likelier outcome under time
> pressure — concluding the whole measurement is unreliable and waving it through on the green
> suite, which is the state §8 built the checklist item to escape. A check that cries wolf is worse
> than no check, because it discredits itself.
>
> **The template.** Two properties, both required:
>
> 1. **Log element *identity*, not rendered bytes.** The element's **DOM index path** from the
>    document root (`html>body>div[0]>…>button[1]`) is what "the query resolved to a different
>    element" actually means. It is stable against the element's own contents changing, and it
>    moves precisely when the resolved node moves. Keep a normalised `outerHTML` slice alongside it
>    as a human-readable label for reading a non-empty diff — not as the identity.
> 2. **Normalise the generated ids** — here `mantine-[a-z0-9]{6,}` → `mantine-ID`. Adapt the
>    pattern to whatever the app mints (`:r0:`-style for bare React `useId`, `css-…` for Emotion,
>    `radix-…` for Radix). Normalisation is the only edit permitted to what gets logged; anything
>    further starts hiding the thing being measured.
>
> **And the step that makes it a measurement rather than a hope: calibrate the noise floor first.**
> Run the shim **twice on the unchanged version** and confirm the two logs are byte-identical
> *before* touching the dependency. That costs one extra test run — ~20 s here — and it is the only
> thing that distinguishes "the diff is empty because nothing drifted" from "the diff is empty
> because I got lucky with the ordering." It is also what caught this defect: the non-determinism
> was found on jsdom 26.1.0, with the version still untouched, so there was never a moment where a
> phantom diff had to be told apart from a real one.
>
> Recorded here rather than in the sweep document, which is the maintainer's to correct.

**The result, which is the point of the exercise:**

| | |
|---|---|
| Logged query resolutions | **176**, across **46 tests** in **17 of the 18 jsdom test files** (`src/api/client.test.tsx` makes no `screen` query) |
| By method | 46 `getByRole`, 36 `getByText`, 28 `getByLabelText`, 19 `queryByText`, 19 `getByTestId`, 16 `findByText`, 5 `findByLabelText`, 2 `queryByLabelText`, 2 `getAllByText`, 2 `findByRole`, 1 `queryByRole` |
| Determinism, jsdom 26.1.0 | two runs, logs **identical** |
| Determinism, jsdom 30.0.1 | two runs, logs **identical** |
| **26.1.0 vs 30.0.1** | **176 lines either side, `diff` is EMPTY** |

**Every query in the suite resolved to the same element before and after the engine swap.** That
is the result this step needed, and stating it is the point — a green suite alone does not prove
it, and §8 was right that it could not be settled by argument. The shim was deleted and
`vite.config.ts` restored with `git checkout --` before the PR; `git status` shows only
`package.json` and `package-lock.json` modified in `frontend/`.

**Why the empty diff is credible rather than vacuous.** The measurement covers `getAllByText` —
the suite's one set-valued query, at `NewScanPage.prefill.test.tsx:54`, which §8 names as the
natural home for silent drift — at both of its runtime invocations, and it covers all 46
`getByRole` resolutions, the query type §6's channel table identifies as the only one where the
engine has real discriminating power. The ~17 interaction targets §8 could not argue away are
inside the 176, because the shim logs at the query, not at the assertion.

---

**The other four channels were re-verified inert against the installed tree, not inherited.**
§0.3's method note is binding, and the "already established" facts in the session brief were
treated as hypotheses:

| Channel | Re-verified how | Verdict |
|---|---|---|
| CSSOM rewrite (29.0.0) | `vite.config.ts`'s `test` block has **no `css` key**, so Vitest's default `css: false` applies and Mantine's stylesheets never enter jsdom | inert — no author CSS to re-parse |
| `element.click()` → `PointerEvent` (27.0.0) | `grep -rn "\.click()" src/` → **zero hits**; all **26** interactions are `userEvent.click`/`fireEvent.click`, which construct and dispatch their own events | unreachable |
| Passive-by-default events (27.0.0) | `grep -rn "preventDefault" src/` → **zero hits** | cannot bite |
| `matchMedia` / `ResizeObserver` / `scrollIntoView` | grepped the **installed** `node_modules/jsdom/lib/` on **both** sides: **0 files** in 26.1.0, **0 files** in 30.0.1 | `src/test/setup.ts`'s `if (!…)` guards behave identically across the span |

**jsdom 30.0.0's release notes are still unreachable, and were not guessed at.** Re-probed at the
correct ref: `Changelog.md` and `CHANGELOG.md` both 404 at `refs/tags/v30.0.0` and
`refs/tags/v30.0.1`, while `README.md` returns **200** at those same refs and `Changelog.md`
returns 200 at `v29.0.0`. That is the document's own ref-versus-file discipline applied: the 404 is
about the file, not the ref. The gap stands as §9 item 2b describes it. **The response was to
measure behaviour rather than infer it** — the shim diff and the four channel checks above are
what stands in for the notes, and they are stronger evidence about *this* suite than a changelog
would have been.

---

**What moved in the lockfile: 338 → 340 packages, every movement attributed to a requirer.** Both
lockfiles were parsed and each added/removed/bumped package's requirers resolved in both trees,
rather than eyeballing the diff:

- **12 added.** The new selector engine and CSSOM stack: `@asamuzakjp/dom-selector@8.3.2`,
  `css-tree@3.2.1` → `mdn-data@2.27.1`, `@bramus/specificity@2.4.2`,
  `@csstools/css-syntax-patches-for-csstree@1.1.7`, `bidi-js@1.0.3` → `require-from-string@2.0.2`;
  `undici@8.10.0` and `@exodus/bytes@1.15.1`, both direct dependencies of `jsdom@30.0.1`; plus
  three nested copies (`lru-cache@11.5.2` under jsdom and under `@asamuzakjp/dom-selector`,
  `whatwg-url@16.0.1` under `data-urls`).
- **10 removed**, each checked to have **no surviving requirer**: `nwsapi` (the replaced selector
  engine), `cssstyle` → `rrweb-cssom` (the replaced CSSOM), `whatwg-encoding` → `iconv-lite` →
  `safer-buffer`, and `ws` / `http-proxy-agent` / `https-proxy-agent` / `agent-base`, the
  networking stack `undici` supersedes.
- **19 version bumps**, all inside jsdom's closure: `whatwg-url` 14.2.0 → 17.1.0, `tough-cookie`
  5.1.2 → 6.0.2 (with `tldts`/`tldts-core` 6.1.86 → 7.4.10), `parse5` 7.3.0 → 8.0.1 (with
  `entities` 6.0.1 → 8.0.0), `data-urls` 5.0.0 → 7.0.0, `@asamuzakjp/css-color` 3.2.0 → 6.0.7 and
  its four `@csstools/*` dependencies, `tr46` 5.1.1 → 6.0.0, `webidl-conversions` 7.0.0 → 8.0.1,
  `html-encoding-sniffer` 4.0.0 → 6.0.0, `whatwg-mimetype` 4.0.0 → 5.0.0.

**Nothing moved that is not jsdom or required by it, and the two entries that could plausibly have
been shared were checked specifically.** `entities` crossing 6 → 8 would matter if anything outside
jsdom's subtree required it; its **only** requirer in either tree is `parse5`, whose only requirer
is `jsdom`. And the top-level `lru-cache@5.1.1` that `@babel/helper-compilation-targets` depends on
is **untouched** — all three `11.5.2` copies are nested under jsdom's subtree. `vite` (6.4.3),
`vitest` (4.1.10), `typescript` (6.0.3), `eslint` (10.8.1), `postcss` (8.5.25), `react` and
`react-dom` (18.3.1) are unchanged in the resolved tree, read out of both lockfiles rather than
trusted from the diff.

`lockfileVersion` stays 3 and the file diff is **+275/−231** — proportionate to 12 additions
against 10 removals and 19 bumps, with no whole-file re-normalisation, because the lockfile was
written with **npm 11.19.0** installed into a scratch prefix to match CI's Node 24 rather than the
sandbox's Node 22 / npm 10.9.7. That is the **sixth** consecutive lockfile touch to use this method
and the sixth clean diff. `npm ci` was additionally run through the same npm 11 and the lockfile's
SHA-256 re-verified unchanged afterwards, so the file a `--package-lock-only` resolution produced is
byte-identical to what a real install writes.

**Suites, measured on both sides, each from a clean install.** Baseline on 26.1.0 (`npm ci` from
the committed lockfile): lint clean (18.1 s), `format:check` clean, **80 tests across 22 files**,
build **7,035 modules → 645.14 kB JS (`index-Vvdzytcz.js`) / 201.38 kB CSS (`index-D2wHtcHV.css`)**,
`npm audit` **0 vulnerabilities**. After the bump, from a fresh `rm -rf node_modules && npm ci`:
lint clean (15.3 s), `format:check` clean, **80 tests across 22 files**, build **7,035 modules →
645.14 kB / 201.38 kB**, audit **0**. The emitted assets carry the **same content hashes** on both
sides — the right signal here, since jsdom is a devDependency the bundle never sees.

**The count comparison was made per test, not per total**, as step 5 established. Both runs were
captured with `--reporter=json` and reduced to sorted `file :: full test name :: status` triples,
and the two lists **diff empty** — the same 22 files, the same 80 test names, all `passed`. The
baseline half of that comparison was taken by reinstalling 26.1.0 from the committed lockfile
after the bump, not quoted from an earlier note.

**Which of the document's Step 6 predictions held.**

- **"Moves `jsdom` only" — HELD.** Nothing else in `package.json`; nothing outside its closure in
  the lockfile.
- **"No config changes in `vite.config.ts`" — HELD.** The file is byte-identical to `dev`.
- **"Two docs edits are required (§7.4)" — HELD**, and the floor is worth stating precisely:
  §7.4 offers "Node 22.22.2+ / 24.15+ **or simply Node 24**". The first was taken. Native
  development on Node 22 is still viable and this repo has no reason to forbid it; a bare "Node 24"
  would have over-tightened a doc statement to match a build image.
- **"Prerequisite check ✅ resolved — the pinned digest ships 24.18.1" — HELD**, re-resolved by
  both of §9's methods rather than inherited.
- **"Verifies it: `npm test` — expect 21 files / 79 tests" — the mechanism HELD, the numbers are
  stale.** 22 files / 80 tests is the current figure, corrected in the step 4 and step 5 entries.
  This is the third and last place in the document quoting 79/21; a step comparing against it would
  read a genuine regression as a match.
- **"Effort S–L, risk medium" — came in at the bottom of the effort band**, and essentially all of
  it went on the shim: writing it, discovering it was non-deterministic, and re-basing it on DOM
  identity. The bump itself was a one-line edit whose suite was green first run.
- **§6's channel-table counts are stale in this tree, and the direction matters.** The table is
  written against "12 `.tsx` test files, 17 of the 79 tests, 116 query call sites". Today it is
  **18 `.tsx` files, 59 jsdom tests, 135 static `screen.*` call sites** (136 counting the
  line-wrapped `getAllByText`), resolving to 176 runtime queries. Step 5's entry already flagged
  the "17 jsdom tests" figure as a stale `.tsx` **file** count quoted as a test count, and warned
  that a step budgeting 17 jsdom tests would under-price its own oracle. It would have: the oracle
  is roughly 3.5× the size the table implies, in the favourable direction.
- **§8's "~17 interaction targets" residual — CLOSED by measurement, as §8 intended.** They are
  inside the 176 logged resolutions and none of them drifted.

**What was deliberately not done.** No package other than `jsdom` moved, in `package.json` or in
the lockfile — in particular **`vite` and `@vitejs/plugin-react` were not touched**, which is the
whole point of the step 6/7 boundary. No source, test, or config file changed. No lint finding was
autofixed, in bulk or individually — there were none. **The shim was not committed**: it was
deleted and `vite.config.ts` restored before the PR, and the working tree confirmed to carry only
the two dependency files under `frontend/`. jsdom 30.0.0's changelog contents were **not guessed
at** — the gap was re-probed, confirmed still open, and answered by measurement instead. No step 7
work was started. `docs/upgrades/frontend-toolchain-86.md` and `docs/ROADMAP.md` were **not**
edited — correcting the sequence document is a maintainer call, and this entry is the record of
what its Step 6 row got right and wrong in the meantime, including the shim's specification.
`main` was not touched.

**Plan section affected:** `frontend/package.json`, `frontend/package-lock.json`, `README.md`,
`CONTRIBUTING.md`, `CHANGELOG.md` § Unreleased/Changed, and this entry. No code behaviour, schema,
API contract, security model, job model, auth, or CI configuration changed; no locked decision
re-opened — React stays on 18 and Mantine on v7, and `jsdom` declares no `react`, `react-dom`,
`@types/react*` or `@mantine/*` peer.

---

### 2026-08-09 — Infra — #86 sweep step 5 landed: Vitest 3.2.7 → 4.1.10 on the pinned Vite 6; the "no config changes" prediction held, the "low breakage" one did not

**What changed:** `frontend/package.json` (one line), `frontend/package-lock.json`,
`frontend/src/components/settings/OidcLinkCard.test.tsx` (an import, two lines, and a comment
explaining them), plus `CHANGELOG.md` and this entry. This is **step 5 of the eight-step sequence**
in `docs/upgrades/frontend-toolchain-86.md`. **`vitest` is the only package bumped.** `jsdom` stays
at **26.1.0** (step 6) and `vite` at **6.4.3** (step 7); `frontend/vite.config.ts`, both tsconfigs,
`frontend/eslint.config.js` and every production source file are untouched. No step 6 or later work
was started; `main` was not touched.

**Step 5's row was confirmed to name `vitest` alone before anything moved.** The maintainer's
instruction was to stop if it also named jsdom, because the 5-Vitest/6-jsdom/7-Vite order exists to
spend the cheap total oracle before the expensive partial one. It does not: the "Moves" cell reads
*"`vitest` only (stays on the pinned `vite@6.4.3`)"*, and jsdom is step 6's sole member. No
divergence, nothing to escalate.

**The target and the peer range were re-checked at the registry, not taken from the document.**
`vitest`'s `dist-tags.latest` is still **4.1.10**; the only published version beyond it is
`5.0.0-beta.7` on the `beta` tag, which is a prerelease and out of scope. So the document's target
is current and no deviation was needed. The ordering question — whether Vitest 4 forces the Vite
major that is not due until step 7 — was answered at the published manifest:

| Field on `vitest@4.1.10` | Value |
|---|---|
| `peerDependencies.vite` | `^6.0.0 \|\| ^7.0.0 \|\| ^8.0.0` |
| `peerDependenciesMeta.vite.optional` | `false` (a **required** peer) |
| `dependencies.vite` | `^6.0.0 \|\| ^7.0.0 \|\| ^8.0.0` (same range) |
| `engines.node` | `^20.0.0 \|\| ^22.0.0 \|\| >=24.0.0` |

The pinned **`vite@6.4.3` satisfies it**, so §3.4's finding holds and the sequence order is sound.
CI's Node 24 and the pinned `node:24-bookworm-slim` (Node 24.18.1) both satisfy the engine floor;
no `ci.yml` or Dockerfile change is needed.

**Config claims re-verified against the shipped 4.1.10 tarball, per §0.3's method note.** All three
legs the Step 5 row asserts held, checked in the artifact rather than in the migration guide:

| Claim | Where it was checked | Verdict |
|---|---|---|
| `declare module "vite"` still augments `UserConfig` with `test` | `dist/config.d.ts:33` | **holds** — `/// <reference types="vitest/config" />` + `defineConfig` from `'vite'` still types the `test` key |
| project configs still accept `extends?: string \| true` | `dist/chunks/reporters.d.*.d.ts:3614` | **holds** — `vite.config.ts:32,40` are fine |
| `projects` is the current spelling | `…:2859` `projects?: TestProjectConfiguration[]` | **holds** — the `workspace` → `projects` rename is a no-op |

The rest of Vitest 4's breaking surface was checked against the repo rather than assumed inert:
`vite.config.ts` carries no `coverage`, `poolOptions`, `maxThreads`/`maxForks`, `minWorkers`,
`reporters`, `deps.*`, `environmentMatchGlobs`/`poolMatchGlobs`, `css` or `restoreMocks` key; there
are **zero** snapshot files and no `toMatchSnapshot`/`toMatchInlineSnapshot` call sites, so the
custom-element shadow-root printing change has nothing to act on; and no `test`/`describe` call
passes an options object as a third argument. The **narrowed default `exclude`** was measured on
both sides rather than reasoned about — v3 resolves to five patterns
(`node_modules`, `dist`, `cypress`, the dot-dirs, and the `*.config.*` union), v4 to two
(`node_modules`, `.git`) — and it collects nothing new here because both projects' `include` globs
are confined to `src/**`, which contains no `dist`, no `cypress` and no config file matching a test
glob. `jsdom` remains a builtin environment in 4.1.10 (`dist/environments.d.ts`).

**Net: `frontend/vite.config.ts` needed no edit, exactly as the row predicts.**

**The row's *"Expected breakage: Low"* did not hold, and the miss is a type error rather than a test
failure.** `npm run build` failed at its `tsc -b` half:

```
src/components/settings/OidcLinkCard.test.tsx(65,65): error TS2345:
  Argument of type 'Mock<Procedure | Constructable>' is not assignable to parameter of type
  '(data: any, unused: string, url?: string | URL | null | undefined) => void'.
```

**The mechanism, read from the installed `@vitest/spy@4.1.10` declarations rather than inferred.**
`fn` is declared `fn<T extends Procedure | Constructable = Procedure>(…): Mock<T>`; under 3.2.7 the
constraint was `Procedure` alone. The widening is the *"`spyOn` and `fn` Support Constructors"*
change the migration guide leads with — but its cost here arrives through a route the guide does not
mention. `ReturnType<T>` instantiates a generic signature at its **constraint**, not its default, so
the alias `ReturnType<typeof vi.fn>` silently moved from `Mock<Procedure>` to
`Mock<Procedure | Constructable>`, whose call signature is
`NormalizedProcedure<Procedure | Constructable>` — a union with a construct-only branch that no
longer matches a plain call signature. `OidcLinkCard.test.tsx` used that alias for a mock passed to
`.mockImplementation()` on a `History.replaceState` spy, which is the one position in the suite that
demands an exact signature.

**Fixed at that one site, by making the type more accurate rather than looser.** The mock is now
declared `Mock<typeof window.history.replaceState>` and created with
`vi.fn<typeof window.history.replaceState>()` — the real method signature, which is what the alias
was always standing in for. No `as`, no `any`, no `@ts-expect-error`, and **no autofix, in bulk or
individually**. `Mock` is exported from `vitest` itself, so the import is type-only and nothing at
runtime changed: `vi.fn<T>()` erases to `vi.fn()`.

**The sibling occurrence was found and deliberately left alone.** `stubLocation()` at line 49 also
returns `{ assign: ReturnType<typeof vi.fn> }`. It still compiles, because `assign` is only ever
passed to `expect(...)` and stored as an object property — never into a position requiring an exact
signature. It is a latent instance of the same loose idiom, not a defect, and editing non-erroring
code is outside this step's scope. Recorded so it is not rediscovered as a mystery: **if a future
step ever passes `assign` to a typed callback parameter, this is the same error waiting.** A grep
confirms these two are the only `ReturnType<typeof vi.fn>` uses in `frontend/src/`.

**One semantic change reaches the suite, and it was measured on both versions rather than argued.**
Vitest 4's `vi.restoreAllMocks()` restores only spies created with `vi.spyOn`; Vitest 3's also reset
plain `vi.fn()` implementations. A standalone probe — two scratch projects, one per version, running
the identical file — settles it:

| | `vi.fn()` implementation survives `restoreAllMocks()` | `vi.spyOn` spy restored |
|---|---|---|
| `vitest@3.2.7` | **no** | yes |
| `vitest@4.1.10` | **yes** | yes |

Two files call `vi.restoreAllMocks()`. **`api/client.test.tsx` is structurally inert** — it has no
`vi.spyOn`, no `vi.mock` factory and no module-level `vi.fn()`; its only mocks are per-test
`vi.fn()`s handed to `vi.stubGlobal('fetch', …)` and removed by `vi.unstubAllGlobals()` in
`afterEach`, so nothing exists for the call to act on under either version.
**`OidcLinkCard.test.tsx` is the one file that combines a `vi.mock` factory's `vi.fn()`s with
`restoreAllMocks()` in `afterEach`**, so its three mocks now carry implementations across tests
where they previously did not.

**Whether that changes any test's behaviour was measured, not reasoned.** The real file was
temporarily instrumented to print, per test, each mock's call count and whether it still held an
implementation; the instrumentation was then removed and the file re-verified as carrying only the
type fix. The carryover is **real and provably inert**: `startOidcLink` holds an implementation from
the *"navigates to the provider URL"* test onward and `unlinkOidcIdentity` from *"sends fresh
credentials when unlinking"* onward — under Vitest 3 both would have been wiped after each test —
yet both record **zero calls** in every subsequent test, and all ten tests set
`getOidcLinkStatus`'s own resolved value before rendering, so its carryover is always overwritten
before it can be read. **No test passes for a different reason than it did on 3.2.7.**

**What moved in the lockfile: 346 → 338 packages, every movement attributed to a requirer.** Both
lockfiles were parsed and each added/removed/bumped package's requirers resolved, rather than
eyeballing the diff:

- **2 added** — `obug@2.1.4` (a direct dependency of `vitest@4.1.10`) and
  `@standard-schema/spec@1.1.0` (required by `@vitest/expect@4.1.10`).
- **10 removed** — `vite-node` and its private `cac`, replaced by Vite's Module Runner; `tinypool`,
  which v4 removes outright when it rewrote the pool architecture; `tinyspy`, dropped by
  `@vitest/spy@4`; `strip-literal` and its nested `js-tokens`, dropped by `@vitest/runner@4`; and
  `check-error`, `deep-eql`, `loupe`, `pathval`, the chai-5 subtree orphaned by the move to chai 6.
  Each was checked to have **no surviving requirer**.
- **13 version bumps** — the seven `@vitest/*` packages to 4.1.10, plus `vitest` itself and its
  closure moving in step: `chai` 5.3.3 → 6.2.2, `es-module-lexer` 1.7.0 → 2.3.1, `std-env` 3.10.0 →
  4.2.0, `tinyexec` 0.3.2 → 1.3.0, `tinyrainbow` 2.0.0 → 3.1.1.

**Nothing moved that is not `vitest` or required by it, and the one case that looked like it could
have been was checked specifically.** `es-module-lexer` crossing a major (1 → 2) is the entry that
would matter if `vite@6.4.3` also required it, since a single hoisted copy serves both. It does not:
before the bump its **only** requirer was `vite-node@3.2.4` at `^1.7.0`, and after it is `vitest` at
`^2.0.0` — Vite bundles its own copy and declares no dependency on the package. `vite` stays 6.4.3
and `jsdom` 26.1.0 in the resolved tree, verified by reading both entries out of the lockfile rather
than trusting the diff.

`lockfileVersion` stays 3 and the file diff is **+131/−209** — proportionate to 10 removals against
2 additions, with no whole-file re-normalisation, because the lockfile was written with **npm
11.19.0** installed into a scratch prefix to match CI's Node 24 rather than the sandbox's Node 22 /
npm 10.9.7. That is the **fifth** consecutive lockfile touch to use this method and the fifth clean
diff. `npm ci` was additionally run *through the same npm 11* and the lockfile's SHA-256 re-verified
unchanged afterwards, so the file a `--package-lock-only` resolution produced is byte-identical to
what a real install writes.

**Suites, measured on both sides, each from a clean install.** Baseline on 3.2.7 (`npm ci` from the
committed lockfile): lint clean (11.6 s), `format:check` clean, **80 tests across 22 files**, build
**7,035 modules → 645.14 kB JS (`index-Vvdzytcz.js`) / 201.38 kB CSS (`index-D2wHtcHV.css`)**,
`npm audit` **0 vulnerabilities**. After the bump, from a fresh `rm -rf node_modules && npm ci`:
lint clean (9.5 s), `format:check` clean, **80 tests across 22 files**, build **7,035 modules →
645.14 kB / 201.38 kB**, audit **0**. The emitted assets carry the **same content hashes** on both
sides — the same signal steps 1, 2 and 4 produced, and the right one here, since a test-runner
devDependency and a type-only test edit cannot reach the bundle.

**The count comparison was made per test, not per total.** A matching 80/22 pair proves less than it
looks like: the same totals could hide a renamed, moved or re-parented test. Both runs were captured
with `--reporter=json` and reduced to a sorted `file :: full test name :: status` triple, and the two
lists **diff empty** — the same 22 files, the same 80 test names, the same statuses.

**Baseline note: 80/22 is the current figure; the document's Step 5 row says 79/21.** The row's
*"expect 21 files / 79 tests"* was written before `ScanDetailPage.scanIdReset.test.tsx` landed on
`dev`. The step-4 entry above already records the correction; it is repeated here because Step 5's
row is one of the two places in the document that still quotes the stale pair, and a future step
comparing against it would read a genuine regression as a match.

**Which of the document's Step 5 predictions held.**

- **"Moves `vitest` only, stays on `vite@6.4.3`" — HELD**, and the peer range was re-verified at the
  published manifest rather than inherited: `^6.0.0 || ^7.0.0 || ^8.0.0`, required, satisfied by the
  pin.
- **"Config changes: none required" — HELD**, and all three of its supporting artifact claims
  re-checked in the 4.1.10 tarball. This is the first Step-5-style prediction in the sweep to
  survive verification unamended.
- **"The narrowed default `exclude` collects nothing new" — HELD**, and upgraded from an argument to
  a measurement by resolving `defaultExclude` under both versions.
- **"Residual risk is the `vite-node` → ModuleRunner swap changing module resolution under the 17
  jsdom tests" — DID NOT MATERIALISE.** All jsdom-project tests pass unchanged, by name and status.
  (The count in that phrasing is doubly wrong and is worth correcting once, since §6's jsdom channel
  analysis reuses it: the jsdom project today is **18 `.test.tsx` files carrying 59 tests**, against
  4 `.test.ts` files carrying 21 under Node. "17" appears to be a stale `.tsx` **file** count quoted
  as a test count — a step 6 that budgets 17 jsdom tests will badly under-price its own oracle.)
- **"Expected breakage: Low… `npm test` is what verifies it" — DID NOT HOLD, and the framing is the
  reason it was nearly missed.** The row names `npm test` as the oracle, and `npm test` was green on
  the first run. The failure was in `npm run build`'s `tsc -b` half, which the row does not mention
  at all — it is caught only because the sweep's standing exit criteria run all five commands. The
  transferable point is the same one step 4 recorded from the other direction: **a step's named
  oracle is not necessarily the oracle that fails.** A runner bump was priced as a runtime-only
  change, and Vitest ships types that the type-checked build consumes.
- **Effort priced S / under 1 h, risk low — came in at the top of the S band**, the extra time spent
  entirely on diagnosing one `TS2345` and measuring the `restoreAllMocks` change.

**What was deliberately not done.** No package other than `vitest` moved, in `package.json` or in
the lockfile — in particular **`jsdom` and `vite` were not touched**, which is the whole point of
the step boundary. No lint finding was autofixed, in bulk or individually — there were none; the one
type error was fixed by hand at a single site. No production source file changed. The
`ReturnType<typeof vi.fn>` at `OidcLinkCard.test.tsx:49` was left as it stands. The temporary
instrumentation used to measure mock carryover was removed before the PR, and the file confirmed to
carry only the type fix. `docs/upgrades/frontend-toolchain-86.md` and `docs/ROADMAP.md` were **not**
edited — correcting the sequence document is a maintainer call, and this entry is the record of what
its Step 5 row got right and wrong in the meantime. No step 6 or later work was started; `main` was
not touched.

**Plan section affected:** `frontend/package.json`, `frontend/package-lock.json`,
`frontend/src/components/settings/OidcLinkCard.test.tsx`, `CHANGELOG.md` § Unreleased/Changed, and
this entry. No code behaviour, schema, API contract, security model, job model, auth, or CI
configuration changed; no locked decision re-opened — React stays on 18 and Mantine on v7, and
`vitest` declares no `react`, `react-dom`, `@types/react*` or `@mantine/*` peer.

---

### 2026-08-09 — Infra — #86 sweep step 4 landed: TypeScript 5.7.2 → 6.0.3 with the ceiling re-checked; the `this`-less inference change surfaced, silently and benignly

**What changed:** `frontend/package.json` (one line), `frontend/package-lock.json` (one entry),
`frontend/tsconfig.app.json` (an explicit `"types": []` plus the comment explaining why an
apparently-inert line is there), plus `CHANGELOG.md` and this entry. This is **step 4 of the
eight-step sequence** in `docs/upgrades/frontend-toolchain-86.md`, executed exactly as its
checklist specifies. **No source file changed.** `eslint.config.js` was not touched, no other
package moved, no step 5 or later work was started, and `main` was not touched.

**The ceiling was re-checked before anything was edited, because the document says it has a shelf
life.** §3.1's one-liner, plus two checks it does not ask for:

| Package | `peerDependencies.typescript` |
|---|---|
| `typescript-eslint@8.66.0` (`latest`) | `>=4.8.4 <6.1.0` |
| `typescript-eslint@8.66.1-alpha.10` (`canary`) | `>=4.8.4 <6.1.0` |
| `@typescript-eslint/parser@8.66.0` | `>=4.8.4 <6.1.0` |
| `@typescript-eslint/typescript-estree@8.66.0` | `>=4.8.4 <6.1.0` |

**The ceiling holds unchanged.** `latest` is still 8.66.0 — no new typescript-eslint major has
appeared, which §3.1 names as the shape TS 7 support would arrive in. The umbrella and both
underlying packages agree, so the "checking the umbrella is sufficient" claim was verified rather
than inherited. Separately, **6.0.3 is still the head of the 6.x line**: `typescript`'s published
versions inside `<6.1.0` are `6.0.0-beta`, a long run of `6.0.0-dev.*`, `6.0.1-rc`, **6.0.2**
(2026-03-23) and **6.0.3** (2026-04-16). There is no newer 6.x patch and no 6.1.x at all, so no
deviation from the document's target was needed and none was proposed. `dist-tags.latest` is
`7.0.2` and `next` is `7.1.0-dev.*` — the offers will keep coming and stay declined.

**One engine fact worth recording so it is not re-derived:** `typescript@6.0.3` declares
`engines.node: ">=14.17"`, identical to 5.7.2's, and still ships **both** `tsc` and `tsserver`
bins — the second is the cheap artifact-level confirmation that 6.0.3 really is the last JS-based
TypeScript, since 7.0.2 drops `tsserver` entirely.

**The `types` edit was verified as a no-op twice, and the second method is the one that carries
the weight.** The document's §7.2 audit was re-run against `src/` rather than trusted, and every
leg held: **zero** references to `process`, `Buffer`, `__dirname` or `__filename`; **zero**
`NodeJS.` namespace uses; all **22** test files import their globals from `'vitest'`, with
`vite.config.ts` setting no `globals: true` (so nothing *could* be relying on ambient test
globals); and all five timer call sites go through `window.setTimeout`/`window.clearTimeout`
(`ScansPage.tsx:198-199`, `ScanDetailPage.tsx:338-343`) — DOM lib, not `@types/node`. The one
`process` use in the repo is `vite.config.ts:7`, which belongs to `tsconfig.node.json` and its
existing `"types": ["node"]`.

That is a grep audit, and a grep audit cannot see an ambient dependency that has no identifier of
its own. So the edit was **applied first under TypeScript 5.7.2**, where the old
enumerate-everything default was still live and the app project was ambiently pulling in all
fourteen installed `@types` packages (`aria-query`, `babel__*`, `chai`, `deep-eql`, `esrecurse`,
`estree`, `json-schema`, **`node`**, `prop-types`, `react`, `react-dom`): `tsc -b --force` and
`npm run lint` both stayed clean. Withdrawing the enumeration is therefore proven inert
*independently of the compiler move*, which is the whole reason to sequence it that way — had it
broken something, the failure would have had one cause instead of two.

**The residual risk the document names did surface, and `tsc -b` would never have shown it.**
§7.2 flags *"less context-sensitivity on `this`-less functions"* as the one change no config audit
can pre-empt, and prices it as *"can produce genuinely new errors in generic callback positions."*
Against this tree it produced **no error and no `TS6xxx` deprecation diagnostic** — `tsc -b
--force` is clean on both projects. Stopping there would have been the §0.3 mistake in a new
costume: a green oracle reported as if it bounded the change. So inference was measured directly,
by emitting declarations under both compilers from a throwaway probe config (a copy of
`tsconfig.app.json` with `emitDeclarationOnly`) and diffing the two trees. **79 `.d.ts` files
either side; exactly one line differs**, in `src/pages/ScanDetailPage.tsx`:

```
- export declare const FindingsTable: import("react").NamedExoticComponent<FindingsTableProps>;
+ export declare const FindingsTable: import("react").MemoExoticComponent<({ findings, findingsTotal,
+     findingsLoading, findingsLoaded, }: FindingsTableProps) => import("react/jsx-runtime").JSX.Element>;
```

`React.memo` is overloaded. Under 5.7.2 the argument — a `this`-less **named function expression**
(`ScanDetailPage.tsx:95`) — matched the `SFC<P>` overload, which needs the parameter contextually
typed; under 6.0.3 it falls through to the `T extends ComponentType<any>` overload, which infers
`T` as the function type itself. This is precisely the documented change, observed at the only
`memo`/`forwardRef` site in `src/` (grepped — there is exactly one).

**It is benign, established by probe rather than by reasoning about the two type aliases.** A
scratch file asserted `ComponentProps<typeof FindingsTable>` three ways — the exact prop object
accepted, an extra prop rejected, a missing prop rejected — and **both compilers agree on all
three**. The probe was deleted. The repo also emits no declarations (`noEmit: true` in both
tsconfigs; no library build), so the printed form has no consumer at all. **Reported, not
"fixed":** no annotation was added to steer overload resolution back, because the contract did not
move and an edit would be churn against a compiler default.

**The `print-config` diff, run on one representative file per file class, per §0.3's method note.**
App `.tsx` (`src/pages/Dashboard.tsx`), library `.ts` (`src/lib/polling.ts`) and the test override
(`src/lib/polling.test.ts`) are **byte-identical before and after**, 135 rules each, nothing added,
removed, or re-severitied, and — unlike step 1 — not even a parser identity string moved, since
`typescript-eslint` did not. The three files differ from each other only in
`react-refresh/only-export-components` (`1` in app/library, `0` under the test override), which is
the override doing its job. This is the first step in the sweep whose resolved config diff is
empty, and that is the expected result: a compiler bump changes what the type-aware rules *see*,
not which rules run.

**What moved in the lockfile: one package, and that is the whole diff.** Both lockfiles were
parsed and compared key by key rather than eyeballed: **346 packages before, 346 after**, zero
added, zero removed, and exactly one entry changed —
`node_modules/typescript` 5.7.2 → 6.0.3, its `version`/`resolved`/`integrity` triple plus the root
manifest's pin. `lockfileVersion` stays 3 and the file diff is **+5/−5** with no normalisation
churn, because the lockfile was written with **npm 11.19.0** installed into a scratch prefix to
match CI's Node 24 rather than the sandbox's Node 22 / npm 10.9.7. That is the **fourth**
consecutive lockfile touch to use this method and the fourth clean diff; the standing-procedure
note from step 2 stands.

**Suites, measured on both sides, each from a clean install.** Baseline on 5.7.2 (`npm ci` from
the committed lockfile): lint clean (12.4 s), `format:check` clean, **80 tests across 22 files**,
build **7,035 modules → 645.14 kB JS (`index-Vvdzytcz.js`) / 201.38 kB CSS
(`index-D2wHtcHV.css`)**, `npm audit` **0 vulnerabilities**. After the bump, from a fresh
`rm -rf node_modules && npm ci`: lint clean (11.3 s), `format:check` clean, **80 tests across 22
files**, build **7,035 modules → 645.14 kB / 201.38 kB**, audit **0**. The emitted assets carry the
**same content hashes** on both sides, which is the proof that a type-only step changed nothing
that ships — the same signal steps 1 and 2 produced, and the one step 3 correctly did not.

**Baseline note: 80 tests, not 79.** Every prior sweep entry records 79/21. The
`ScanDetailPage.scanIdReset` test landed on `dev` immediately before this step, so 80/22 is the
current figure and the number future steps should compare against.

**Which of the document's Step 4 predictions held.**

- **The ceiling (6.0.3, not 7) — HELD**, re-verified at the registry on the day, across four
  packages rather than the one §3.1 asks for.
- **`types` defaulting to `[]` is a no-op here — HELD**, and upgraded from a grep audit to an
  empirical one by applying the edit under the old compiler first.
- **`rootDir` defaulting to `.` is a no-op here — HELD, and the guard was identified precisely.**
  §7.2 attributes it to `noEmit: true`, and that is exactly right: the declaration probe above, by
  turning emit on, made TypeScript 6.0 raise **`TS5011`** ("the `rootDir` setting must be
  explicitly set…") on a config the real build compiles silently. The probe needed an explicit
  `rootDir` to proceed. Recorded because it converts a prediction into a demonstrated mechanism —
  and as a standing caveat: **if either tsconfig ever turns emit on, `rootDir` becomes a required
  edit, not an inherited default.**
- **The `this`-less inference change is the one thing no config audit can pre-empt — HELD, and
  its failure mode is milder than priced.** The row expects *"genuinely new errors in generic
  callback positions"*; what happened is a silent overload re-resolution with an unchanged public
  contract. The transferable point is that **`tsc -b` is not a complete oracle for an inference
  change** — only a diff of inferred output is — which is the same lesson §0.3 taught about
  `--print-config` versus a plugin's own shipped config file.
- **Effort priced M / 2–5 h, risk medium — came in at the bottom of the band**, because the
  judgement-heavy part (per-type-error triage) had no input: there were no type errors.

**What was deliberately not done.** No package other than `typescript` moved, in `package.json` or
in the lockfile. `"ignoreDeprecations": "6.0"` was **not** set — the document is right that it
would silence the free preview of what TypeScript 7 removes, and there was nothing to silence
anyway. No lint finding was autofixed, in bulk or individually — there were none. No `.github/
dependabot.yml` ignore rule was added for `typescript`, per §6's Step 4 note and the standing rule
in that file that an ignore says *"a bot may not make this decision"* while TypeScript 7 is wanted.
`tsconfig.node.json` was not edited. `docs/upgrades/frontend-toolchain-86.md` and
`docs/ROADMAP.md` were **not** edited — correcting the sequence document is a maintainer call, and
this entry is the record of what its Step 4 row got right in the meantime, which this time is all
of it. No step 5 or later work was started; `main` was not touched.

**Plan section affected:** `frontend/package.json`, `frontend/package-lock.json`,
`frontend/tsconfig.app.json`, `CHANGELOG.md` § Unreleased/Changed, and this entry. No code
behaviour, schema, API contract, security model, job model, auth, or CI configuration changed; no
locked decision re-opened — React stays on 18 and Mantine on v7, and `typescript` declares no
`react`, `react-dom`, `@types/react*` or `@mantine/*` peer.

---

### 2026-08-09 — Post-v1 — `L17`/`P2-2`'s reset effect finally has a regression test; the protection #176 relies on was never actually enforced

**What changed:** one new file, `frontend/src/pages/ScanDetailPage.scanIdReset.test.tsx`, plus
`CHANGELOG.md` and this entry. **No production code changed** —
`frontend/src/pages/ScanDetailPage.tsx` is byte-identical to `dev`, verified with `git diff` after
the verification step below rather than assumed.

**The gap, and how it surfaced.** The `:scanId` reset effect has existed since the 2026-07-13
Frontend-review wave 2 entry (`L16 / P2-1, L17 / P2-2`, originally issue #62): React Router reuses
the `ScanDetailPage` instance across `/scans/:id` navigations, so without it the previous scan's
header, findings, artifacts, tag draft and poll state linger, and the status-gated artifacts and
findings effects fire for the new id against the old `scan.status`. It was never tested. The three
existing suites — `ScanDetailPage.findingsTable.test.tsx` (a memo-boundary render-count test that
never mounts the page), `.latestwins.test.tsx` and `.poller.test.tsx` (both of which mount the page
at a single `/scans/7`) — contain no navigation between two `:scanId` values. The effect could have
been deleted and all 79 tests would have stayed green.

This was found while auditing **#176**, which lists that effect as one of six sites a future change
to `react-hooks/set-state-in-effect` may touch, and warns against "fixing" it blind. That warning
was leaning on a test that did not exist. #176's body now says so explicitly, and this entry
records the fix.

**Why a new file rather than one of the three.** Placement was a judgement call and is recorded so
it is not re-litigated. `findingsTable` tests a child component in isolation with no router at all —
structurally wrong. `latestwins` and `poller` both mount the full page in a router and were the
plausible hosts, but each is deliberately scoped to one concern with minimal fixtures ("a finished
scan — not polled, so the findings fetches are the only traffic"), and this test needs two distinct
scans differing in id, target, tags, findings and artifacts. Folding those fixtures into either file
would blur a suite whose narrowness is the point. The repo's own convention is one concern per file,
named for it — `findingsTable`, `latestwins`, `poller`, and on `ScansPage` `compare`, `latestwins`,
`urlstate` — so `scanIdReset` follows the existing scheme.

**What the test asserts.** It renders `/scans/1`, waits for the header (`Scan #1`, `alpine:3.19`),
a finding (`CVE-SCAN-ONE`) and an artifact (`scan-one-raw.json`), then types `draft-only-tag` into
the tag input so the draft diverges from the server value — state that `loadScan` deliberately
preserves under `L16 / P2-1`, and which therefore only the reset can clear. It navigates to
`/scans/2` with scan 2's `getScan` held open by a deferred promise, so the assertions land in the
window the effect protects: after the id changes, before the new data arrives. In that window it
requires `Loading scan` to be present and all four families of scan-1 state to be absent. It then
resolves scan 2 and re-checks that the stale draft has not reappeared — a second, independent leg,
because an unreset draft would survive the load as well as the navigation.

**Verified to catch the regression, not merely to pass.** The reset effect was temporarily deleted
(the 11 `setState` calls plus 2 ref writes, removed as one block by an anchored replacement), the
test re-run, and it **failed** on the first in-flight assertion — `Loading scan` never appears
because scan 1's page is still mounted, with `alpine:3.19` visible in the failure dump. The effect
was then restored with `git checkout --` and the file confirmed byte-identical to `dev`. A test that
is only ever observed passing proves nothing about what it guards; this one was observed failing for
the right reason first.

**Suites:** lint clean, `format:check` clean, **80 tests across 22 files** (was 79/21 — this one
test), `npm run build` green, `npm audit` 0 vulnerabilities.

**What was deliberately not done.** The reset effect was not refactored toward the
`key`-prop-remount shape #176 names as the compiler-idiomatic replacement — this PR tests current
behaviour, it does not change it. None of the other five findings #176 tracks was touched.
`react-hooks/set-state-in-effect` stays `off`, and `frontend/eslint.config.js` was not edited.
#176's own Definition of Done was left as it stands — closing out its test prerequisite is part of
the work that issue tracks, not this PR. `main` was not touched.

**Plan section affected:** new file `frontend/src/pages/ScanDetailPage.scanIdReset.test.tsx`,
`CHANGELOG.md` § Unreleased/Added, and this entry. No code behaviour, schema, API contract, security
model, job model, auth, or CI configuration changed; no locked decision re-opened.

---

### 2026-08-09 — Infra — #86 sweep step 3 landed: React Compiler rules adopted, `set-state-in-effect` held back over 12 findings with no honest fix (#176)

**What changed:** `frontend/eslint.config.js` (the holding edit removed, one rule overridden off),
`frontend/src/pages/ScansPage.tsx` (six lines), plus `CHANGELOG.md`, this entry, and new issue
**#176**. This is **step 3 of the eight-step sequence** in
`docs/upgrades/frontend-toolchain-86.md` — the step the document flags as *"a separate decision;
may be declined"* and prices as *"unbounded until measured"*. **No dependency version moved:**
`frontend/package.json` and `frontend/package-lock.json` are byte-identical, SHA-256 unchanged
across the whole session. No step 4 or later work was started; `main` was not touched.

**The cost was measured before the config was edited, which is the whole point of the step.** The
maintainer asked for a finding count against the current tree before anything landed. It was
obtained with a throwaway `eslint.probe.config.js` — a copy of `eslint.config.js` with the spread
restored, run via `--config`, then deleted — so the tracked tree was never modified to take the
measurement. Result: **24 findings, from 2 of the 14 rules.**

| Count | Severity | Rule |
|---:|---|---|
| 18 | error | `react-hooks/set-state-in-effect` |
| 6 | error | `react-hooks/refs` |
| 0 | — | the other 12 |

**Twelve of the fourteen rules report nothing** — including `immutability`, `purity` and
`preserve-manual-memoization`, which the scoping document's Step 3 row named as *"the ones most
likely to fire in volume"* on a codebase with 23 `useEffect` and 15 `useMemo`/`useCallback` files.
That prediction did not hold, in the favourable direction. `set-state-in-effect` — which the row
also names — is the one that did.

**The rule population split, and this is the finding that decided the step.** `set-state-in-effect`
reports two populations that its own message does not distinguish, established by reading every one
of the 18 sites rather than trusting the count:

- **6 are genuine** — a synchronous `setState` reachable from the effect body, i.e. the cascading
  render during commit that the rule's rationale describes: `LoginPage.tsx:57`,
  `OidcLinkCard.tsx:90`, `NewScanPage.tsx:130`, `ScanDetailPage.tsx:293`, `ScanDetailPage.tsx:366`
  (reported because `loadFindings` opens with a synchronous `setFindingsLoading(true)` before its
  first `await`), and `ScansPage.tsx:225`.
- **12 are the fetch-on-mount idiom** — `void load()` in an effect where `load` is a local
  `useCallback` whose every `setState` runs *after* an `await`. Each of the twelve loaders was read
  to confirm no synchronous `setState` precedes the first `await`: `AuthContext:124`,
  `ApiTokensPanel:54`, `BackupsPanel:75`, `DockerEnvironmentsPanel:55`, `GitCredentialsPanel:52`,
  `ScheduledScansPanel:84`, `TrivyPolicyPanel:74`, `UsersPanel:44`, `AccountPage:276`,
  `NewScanPage:124`, `ScanDetailPage:309`, `ScansPage:214`.

**The second population was proven an artifact of analysis scope, not a behavioural claim — by
probe, not by argument.** A scratch file was linted under the probe config with three shapes of the
same fetch-on-mount code, `load` defined in the component body each time:

| Shape | Reported? |
|---|---|
| `void load()` | **yes** |
| `void (async () => { await load(); })()` | no |
| `load().catch(() => {})` | **yes** |

The first two are semantically identical. Separately, moving the identical `load` behind a custom
hook silences **all three**. And `ScanDetailPage:353`'s `listArtifacts(id).then(setArtifacts)` is
silent for the same reason — the callee is a module import, not a local callback the compiler can
trace into. So the report tracks what the compiler can see through, and the available "fixes" are
an async-IIFE wrapper that changes nothing, or hoisting twelve loaders behind hooks — which
silences the rule by hiding from it. **Neither is an improvement**, which is why the maintainer
scoped these twelve out of #176 entirely rather than deferring them: if a data-fetching refactor is
ever worth doing it is its own decision, not a rider on a lint step. This is the § Interpreter CVEs
rule — *check it against the artifact before believing the metadata* — applied to a lint report:
the message asserted "synchronously", the code said otherwise, and the probe settled it.

**What was done, per the maintainer's option 2.** All 14 rules enabled via the restored
`...reactHooks.configs.recommended.rules` spread; `react-hooks/set-state-in-effect: 'off'`
immediately after it, carrying the reason inline and a pointer to **#176**; the six `refs` findings
fixed by hand.

**The `refs` fix, and why it is a real improvement rather than a silencing.** All six were one
idiom in `ScansPage.tsx:132-139` — `const initialView = useRef(viewFromParams(searchParams))`
whose `.current` was read during render to seed six `useState` initializers. Reading a ref during
render is what the rule forbids and what the rules of React forbid. Replaced with
`const [initialView] = useState(() => viewFromParams(searchParams))`: a lazy initializer runs
`viewFromParams` exactly once on first render, which is precisely what the ref was there to do, so
the "read the URL once, then sync one-directionally" contract in the surrounding comment is
preserved rather than reinterpreted. `initialView` had no other use in the file (checked), and
`useRef` stays imported for `historyGuard` at line 175. The History deep-linking tests (`P3-1`)
still pass.

**#176 names the two archive-cited effects explicitly, at the maintainer's instruction, so nobody
"fixes" them blind.** Two of the six genuine findings are effects that each closed a real bug and
would be re-opened by deletion: `ScanDetailPage.tsx:293` is **`L17` / `P2-2`** (React Router reuses
the component instance across `/scans/:id`, so without the reset the previous scan's header,
findings, artifacts, tag draft and poll state linger and the status-gated effects fire against a
stale `scan.status` — §14, 2026-07-24 Priority-1/2 batch, originally issue #62), and
`ScansPage.tsx:225` is **`P3-2`** (the compare selection held row snapshots outliving a
filter/page change or a delete, showing a phantom "1/2 selected" and diffing a since-deleted scan —
§14, 2026-07-24 Priority-3 batch, with two jsdom regression tests). #176 records both, names the
compiler-idiomatic replacement for `L17`/`P2-2` (a `key` prop on the route element, which is a
change in a different file), and states that the tests must still pass.

**The before/after `print-config` diff, run on one representative file per file class.** This is
the check §0.3's method note prescribes, run against the installed tree both sides. App `.tsx`
(`src/pages/Dashboard.tsx`), library `.ts` (`src/lib/polling.ts`) and the test override
(`src/lib/polling.test.ts`) **all moved identically, 121 → 135 rules**, with 14 entries differing
and **nothing else changed at any severity**:

| Severity | Rules added |
|---|---|
| `error` (11) | `config`, `error-boundaries`, `gating`, `globals`, `immutability`, `preserve-manual-memoization`, `purity`, `refs`, `set-state-in-render`, `static-components`, `use-memo` |
| `warn` (2) | `incompatible-library`, `unsupported-syntax` |
| `off` (1) | `set-state-in-effect` |

**Nothing in the diff was surprising, and the counts reconcile against step 2's record.** The
installed `configs.recommended` is 16 rules; `rules-of-hooks` and `exhaustive-deps` were already
present at `[2]` and `[1]` from step 2's written-out pair and are unchanged, so the delta is exactly
+14. The scoping doc's §3.5 enumerates 12 at `error` and 2 at `warn`; here 11 sit at `error` and the
12th, `set-state-in-effect`, is the one overridden to `off` — the same 12, differently disposed.
`component-hook-factories` does not appear, consistent with step 2's finding that 7.1.1 registers it
as a deprecated no-op outside `configs.recommended`. No core rule, no `@typescript-eslint/*` rule,
and no plugin identity string moved.

**Suites, run from a fresh `rm -rf node_modules && npm ci`.** Lint clean, `format:check` clean,
**79 tests across 21 files**, `npm audit` **0 vulnerabilities**. **The build output moved, and that
is expected here where it was not in steps 1 and 2:** 7,035 modules → **645.14 kB** JS
(`index-Vvdzytcz.js`) / 201.38 kB CSS, against the baseline's 645.18 kB `index-BNB6IweX.js`. Steps
1 and 2 were provably lint-only and their asset hashes were identical; this step changes runtime
code in `ScansPage.tsx`, so a −0.04 kB shift and a new JS hash are the honest signal that it did.
The CSS is untouched and keeps its hash (`index-D2wHtcHV.css`). The lockfile SHA-256 was captured
before the baseline install and re-verified after the final one, unchanged.

**What was deliberately not done.** No dependency version, `package.json`, or lockfile touched — the
maintainer's out-of-scope line for this step, and it held. No `--fix`, in bulk or individually: the
six `refs` findings were edited by hand at one site. No rule disabled beyond the single override the
maintainer authorised, and the 12 fetch-on-mount findings were **reported rather than worked
around** — no async-IIFE wrapper, no hook extraction. No step 4 or later work.
`docs/upgrades/frontend-toolchain-86.md` and `docs/ROADMAP.md` were **not** edited — correcting the
sequence document is a maintainer call, and this entry is the record of what its Step 3 row got
right and wrong in the meantime (its "unbounded, possibly a multi-day refactor" pricing was
correct as a range; the actual answer is 24 findings, 6 fixed, 12 declined, 12 rules free).

**Plan section affected:** `frontend/eslint.config.js`, `frontend/src/pages/ScansPage.tsx`,
`CHANGELOG.md` § Unreleased/Changed, this entry, and new issue #176.
`frontend/package.json`, `frontend/package-lock.json`,
`docs/upgrades/frontend-toolchain-86.md` and `docs/ROADMAP.md` were deliberately **not** edited. No
schema, API contract, security model, job model, auth, or CI configuration changed; no locked
decision re-opened — React stays on 18 and Mantine on v7, and the React Compiler rules are static
analysis with no React runtime dependency, so enabling them pressures neither.

---

### 2026-08-09 — Infra — #86 sweep step 2 landed: the ESLint 10 family, with the React Compiler rule set held inert; three of the doc's four predictions held

**What changed:** `frontend/package.json` (four lines), `frontend/package-lock.json`,
`frontend/eslint.config.js` (the one required holding edit), plus `CHANGELOG.md` and this entry.
This is **step 2 of the eight-step sequence** in `docs/upgrades/frontend-toolchain-86.md`, executed
exactly as scoped: `eslint` 9.39.4 → **10.8.1**, `@eslint/js` 9.39.4 → **10.0.1**,
`eslint-plugin-react-hooks` 5.1.0 → **7.1.1**, `eslint-plugin-react-refresh` 0.4.16 → **0.5.3**.
**No source file changed.** `typescript` stays at 5.7.2 (step 4), no tsconfig was touched, the React
Compiler rules were not adopted (step 3), and `#153`/`#170`'s successors were left alone.

**Versions re-checked at the registry before the bump, not taken from the document.** `eslint`'s
`dist-tags.latest` is **10.8.1** — the document's Step 2 row already specifies 10.8.1 and flags
#153's 10.8.0 as stale, and 10.8.1 is still current, so no deviation was needed. `@eslint/js`
10.0.1, `eslint-plugin-react-hooks` 7.1.1 and `eslint-plugin-react-refresh` 0.5.3 are all still
`latest`. The §3.1 ceiling one-liner was re-run in passing: `typescript-eslint@latest` is still
8.66.0 peering `typescript: >=4.8.4 <6.1.0`, so **the TypeScript 6.0.3 ceiling holds as of this
date** and step 4's target is unchanged.

**Package membership: four, not three.** The session brief named three packages; the document's
Step 2 "Moves" row names four. The fourth — `eslint-plugin-react-refresh` — was confirmed with the
maintainer before being included, on the evidence that it is **not** peer-forced: 0.4.16 peers
`eslint: ">=8.40"`, an unbounded range that ESLint 10 satisfies, so it would have kept resolving.
It is in the step because the document puts it there, not because the bump required it.

**Every peer claim re-verified at the published manifest, per the method note.** `react-hooks`
5.1.0/6.0.0/7.0.0/7.0.1 all stop at `eslint ^9.0.0`; the `^10.0.0` clause first appears in **7.1.0**
and is present in 7.1.1 — so the plugin genuinely is peer-forced and taking ESLint 10 with the old
pin would have been the same `ERESOLVE` class that killed #153. `@eslint/js@10.0.1` peers
`eslint ^10.0.0` but marks it **optional**, confirming §3.6's "convention, not a hard peer";
`eslint@10.8.1` no longer lists `@eslint/js` in its own `dependencies` (9.39.4 pinned it exactly),
so it is fully external now. `eslint-plugin-react-refresh@0.5.3` peers `eslint: "^9 || ^10"` and is
`"type": "module"` where 0.4.16 was `"commonjs"` — the ESM-only change is real and, as predicted, a
no-op for a repo that has been flat-config and ESM since Phase 0.

**`component-hook-factories`, confirmed at the artifact.** 7.1.0's shipped bundle contains **zero**
occurrences of the string — the rule really was removed. 7.1.1 restores it as
`makeDeprecatedRule('7.1.0')`: `meta.deprecated: true`, `create() { return {}; }`. A registered
no-op. **We are on 7.1.1**, so nothing referencing that rule name can error out on an unknown rule.

**The holding edit, and proof that it is both necessary and behaviour-preserving.**
`frontend/eslint.config.js` spread `...reactHooks.configs.recommended.rules`. Resolved from the
**installed** 7.1.1, that object is **16 rules — 13 at `error`, 3 at `warn`** — where 5.1.0's,
resolved from its tarball, is exactly **2**: `react-hooks/rules-of-hooks: 'error'` and
`react-hooks/exhaustive-deps: 'warn'`. So the bump alone would have enabled 14 React Compiler rules
(12 new at `error`, 2 at `warn`) inside the ESLint-10 PR. The spread was replaced by those two rules
written out, which is byte-equivalent to what 5.1.0 contributed. **The document's §3.5 enumeration
held exactly** — all 12 `error` names and both `warn` names match the installed bundle, and the
counts reconcile: 16 total = 2 basic + 14 added, or equivalently 13 `error` + 3 `warn`.

**The gate the maintainer set — "the React Compiler rules must be absent or off" — passes at the
resolved config.** `eslint --print-config` on all three file classes reports exactly **two**
`react-hooks/*` rules, at `[2]` and `[1]`, identical to the pre-bump baseline. Zero compiler rules
present at any severity.

**The before/after `print-config` diff, run on one representative file per file class.** This is the
check §0.3's method note prescribes, and it was run against the installed tree both sides. App
`.tsx` (`src/pages/Dashboard.tsx`), library `.ts` (`src/lib/polling.ts`) and the test override
(`src/lib/polling.test.ts`) **all moved identically, 118 → 121 rules**, six entries differing:

| Rule | Before | After | Nature |
|---|---|---|---|
| `no-unassigned-vars` | absent | `[2]` | **new in `eslint:recommended`** |
| `no-useless-assignment` | absent | `[2]` | **new in `eslint:recommended`** |
| `preserve-caught-error` | absent | `[2]` | **new in `eslint:recommended`** |
| `no-shadow-restricted-names` | `[2, {reportGlobalThis: false}]` | `[2, {reportGlobalThis: true}]` | **real default change** |
| `no-constant-binary-expression` | `[2]` | `[2, {checkRelationalComparisons: false}]` | new option, default off — inert |
| `no-unused-vars` | `[0]` | `[0, {…7 options…}]` | new `defaultOptions`; rule is **off** here |

(The only non-rule difference is the `plugins` identity string.)

**The three added rules were attributed to `@eslint/js` by resolving its config object, not by
reading release notes.** Both packages' `src/configs/eslint-recommended.js` were `require`d from
unpacked tarballs and their `rules` maps diffed: **61 → 64 entries**, and the delta is exactly
`no-unassigned-vars`, `no-useless-assignment`, `preserve-caught-error`, all at `"error"`. **Nothing
removed, nothing re-severitied.** 10.0.1 additionally carries the `name: "@eslint/js/recommended"`
property that 9.39.4's lacks, confirming §3.6's second leg at the artifact.

**The last two rows are not behaviour changes, and the distinction was established rather than
asserted.** Both are ESLint 10 adding or revising `meta.defaultOptions`, which `--print-config` then
materialises. The tempting reading — "v10 expands defaults for everything, so these are formatting
noise" — is wrong and was tested: **25 of the 72 core rules in this config carry
`meta.defaultOptions` under ESLint 10, yet only these two moved**, so the diff is confined to rules
whose defaults are new or changed, not a blanket format shift. `no-constant-binary-expression`'s new
option defaults to `false`, so it is opt-in. `no-unused-vars` sits at severity `0` here regardless —
typescript-eslint's `eslint-recommended` layer disables it in favour of `@typescript-eslint/no-unused-vars`.

**Which of the document's Step 2 predictions held, and which did not.**

- **(a) three new `eslint:recommended` rules — HELD, exactly.** Named correctly and complete; the
  artifact diff found no fourth and no removal.
- **(c) `no-shadow-restricted-names` now reports `globalThis` — HELD.** Confirmed as a default flip
  in the resolved config. It reports nothing in this codebase.
- **(d) `eslint-plugin-react-refresh` 0.5.3 is not a routine bump — HELD, and its two no-op claims
  re-checked against the installed package as the row asks.** ESM-only/flat-config-required: a
  no-op, this repo has no `.eslintrc*` and `eslint.config.js` is ESM. `customHOCs` → `extraHOCs`:
  a no-op, the repo's single `react-refresh/only-export-components` usage passes only
  `allowConstantExport` and sets no HOC option at all.
- **(b) JSX reference tracking changes `no-unused-vars` / `no-undef` results across 51 `.tsx` files
  — DID NOT HOLD, and could not have.** Both rules are at severity **`0`** in this repo's resolved
  config — `no-unused-vars: [0, …]` and `no-undef: [0, {typeof: false}]` — because typescript-eslint
  disables them on the grounds that TypeScript already reports both. A reference-resolution change
  cannot produce a report through a rule that is off. The prediction was written from the ESLint 10
  migration guide without checking whether the affected rules were enabled here, which is the same
  class of error §0.3 was corrected for: a claim about a mechanism, not verified against the
  composite this repo actually resolves. It is the widest-blast-radius item in the row, and it is
  structurally inert. **This does not generalise to a repo that enables those rules.**

**Net lint result: zero problems.** Not one of the three new rules fired, `no-shadow-restricted-names`
found no shadowed `globalThis`, and no report appeared from any implementation change across the
ESLint 9 → 10 span. Unlike step 1, no source edit was needed — so nothing was autofixed, in bulk or
otherwise, because there was nothing to fix.

**`@eslint/eslintrc` and `js-yaml` are gone from the tree, which is §0.4 discharged.**
`npm ls @eslint/eslintrc` and `npm ls js-yaml` both report empty. `eslint@9.39.4` depended on
`@eslint/eslintrc: ^3.3.5`; `10.8.1` depends on neither, and eslintrc was this repo's only path to
`js-yaml`. The lockfile refresh of 2026-08-09 had closed GHSA-5p4m-2wfm-xmqj by version; this
removes the path.

**None of ESLint 10's removals touch this repo, verified by search rather than by inheriting the
document's "Doesn't apply here" row.** Zero `.eslintrc*` files anywhere in the repository; zero
`eslint-env` comments (which v10 reports as errors); no `getSourceCode`/`context.getScope`/
`context.getAncestors`/`context.getFilename` use, no `RuleTester`, no `new Linter`, no import of
`eslint` from source — so the removed deprecated `SourceCode` and rule-context methods have no
consumer; no `jiti` (v10's only peer, and optional); no `--flag v10_config_lookup_from_file`; no
bracket expressions in any ignore glob. **The engine floor is satisfied everywhere it matters:**
`eslint@10.8.1` and `@eslint/js@10.0.1` both declare `node: "^20.19.0 || ^22.13.0 || >=24"`, CI's
`node-version: "24"` satisfies it, and the pinned `node:24-bookworm-slim@sha256:235600a8…` ships
Node 24.18.1 (resolved in the scoping entry below). No `ci.yml` or `Dockerfile` change is needed.

**What moved in the lockfile: 362 → 346 packages, every movement attributed to a target or its
transitive closure.** Both lockfiles were parsed and each added/removed package's requirers
resolved, rather than eyeballing the diff:

- **5 added.** `hermes-parser` + its `hermes-estree`, `zod`, and `zod-validation-error` — all
  required by `eslint-plugin-react-hooks@7.1.1`; and `@types/esrecurse`, required by
  `eslint-scope@9.1.2`, which ESLint 10 pulls in.
- **A prediction correction worth recording: `@babel/core` and `@babel/parser` were already in the
  tree.** §3.5 lists them among the five "real runtime dependencies it did not have" that 7.1.1
  gains. They are real dependencies of the plugin, but both were already present at **7.29.7** via
  `@vitejs/plugin-react@4.3.4`, so they cost **zero** new packages. The plugin's dependency growth
  against *this* tree is three packages plus one transitive, not five.
- **21 removed.** The entire `@eslint/eslintrc` subtree — eslintrc itself, its nested
  `globals@14.0.0`, `js-yaml` → `argparse`, `import-fresh` → `parent-module` → `resolve-from` →
  `callsites`, `strip-json-comments`, `lodash.merge`, `concat-map`, and the `chalk` chain
  (`ansi-styles`, `color-convert`, `color-name`, `has-flag`, `supports-color`). Plus **four nested
  duplicates that step 1 itself created**: `@typescript-eslint/typescript-estree`'s private
  `minimatch@10.2.6`, `brace-expansion@5.0.9`, `balanced-match@4.0.4` and
  `@typescript-eslint/visitor-keys`'s `eslint-visitor-keys@5.0.1` existed only because the
  top-level copies stayed pinned for ESLint 9. ESLint 10 requires those same versions at top level,
  so they dedupe away — the step-1 entry's "nested copies" note is now discharged.
- **16 version bumps.** The four targets, plus ESLint 10's own closure moving in step:
  `@eslint/config-array`, `config-helpers`, `core`, `object-schema`, `plugin-kit`, `eslint-scope`,
  `eslint-visitor-keys`, `espree` (and its `acorn`), and the hoisted `minimatch`/`brace-expansion`/
  `balanced-match`. **Nothing moved that is not a target or required by one.**

`lockfileVersion` stays 3 and the diff is **+158/−359** — proportionate to 21 removals against 5
additions, with no whole-file re-normalisation, because the lockfile was written with **npm 11.19.0**
installed into a scratch prefix to match CI's Node 24 rather than the sandbox's Node 22 / npm 10.9.7.
That is the third consecutive lockfile touch to use this method and the third time it produced a
clean diff; it should be treated as the standing procedure, not a per-session detour.

**Suites, measured here rather than quoted, from a clean `npm ci` on both sides.** Baseline on
9.39.4: lint clean (15.9 s), `format:check` clean, **79 tests across 21 files**, build **7,035
modules → 645.18 kB JS / 201.38 kB CSS**, `npm audit` **0 vulnerabilities**. After the bump, from a
fresh `rm -rf node_modules && npm ci`: lint clean (14.1 s), `format:check` clean, **79 tests across
21 files**, build **7,035 modules → 645.18 kB JS / 201.38 kB CSS**, audit **0**. The build output is
identical down to the **content hashes** (`index-BNB6IweX.js`, `index-D2wHtcHV.css`), which is the
proof that this step cannot have changed what ships — it is lint-only, as the document prices it.

**One cosmetic upstream defect, recorded so it is not re-derived.** `eslint-plugin-react-hooks@7.1.1`
reports `meta.version === "7.0.0"` while its `package.json` says `7.1.1`, so `--print-config`'s
`plugins` array prints `react-hooks:eslint-plugin-react-hooks@7.0.0`. **That string is not a
reliable way to confirm the installed version** — read `package.json` or `npm ls`. Nothing in this
repo depends on the value.

**Standing consequence for steps 3 onward.** The method note is earning its keep: three of Step 2's
four predictions held precisely, and the fourth failed for the same structural reason §0.3 failed —
a mechanism was read from upstream documentation without checking whether this repo's *resolved*
config exposes it. Steps 3 and 4 should keep resolving the composite, not the guide. Step 3's cost
in particular is now measurable rather than estimated: the 16-rule `configs.recommended` is
installed and one line of `eslint.config.js` away, so its report count can be obtained without any
dependency change.

**What was deliberately not done.** No package outside Step 2's four moved. No lint finding was
autofixed, in bulk or individually — there were none. No React Compiler rule was activated. No step
3 or later work was started. The sequence's membership and order were not edited.
`docs/upgrades/frontend-toolchain-86.md` and `docs/ROADMAP.md` were **not** edited — correcting the
sequence document is a maintainer call, and this entry is the record of what its Step 2 row got
right and wrong in the meantime. `main` was not touched.

**Plan section affected:** `frontend/package.json`, `frontend/package-lock.json`,
`frontend/eslint.config.js`, `CHANGELOG.md` § Unreleased/Changed, and this entry. No code
behaviour, schema, API contract, security model, job model, auth, or CI configuration changed; no
locked decision re-opened — React stays on 18 and Mantine on v7, and no package in this step
declares a `react`, `react-dom`, `@types/react*` or `@mantine/*` peer.

---

### 2026-08-09 — Docs/Process — Scoping doc corrected post-step-1; #170 (Dependabot's regenerated unsatisfiable frontend group) closed

**What changed:** `docs/upgrades/frontend-toolchain-86.md` §0.3 and the Step 1 and Step 2 rows in
§6, plus a note in the ranking discussion in §8 that cited §0.3's original claim. No dependency
version, lockfile, or config file was touched; the sweep's sequence, its membership, and its
ordering are unchanged. Separately, **#170** — Dependabot's regenerated frontend-dependencies
group, opened after #168 merged and #153 stopped matching — was closed.

**#170, verified before acting rather than assumed.** Its file diff was read directly: `typescript`
5.7.2 → **7.0.2** is still proposed, alongside `typescript-eslint` 8.19.0 → 8.66.0, which peers
`typescript: ">=4.8.4 <6.1.0"`. Same unsatisfiable graph #153 carried — `npm ci` fails at
`ERESOLVE` before ESLint runs, for the reasons `docs/upgrades/frontend-toolchain-86.md` §3.1 and
§0.2 already establish. Closed with a comment stating the group is unsatisfiable as composed, that
the #86 sweep is running as the ordered sequence in that document, that step 1 landed as #171, and
that the doc is the tracking surface rather than this PR. **Not merged, not cherry-picked from** —
same reasoning as the doc's §8 recommendation for #153. Dependabot will regenerate an equivalent
group weekly, at newer targets, with the same unsatisfiable pairing, until the `dev`-only ignore
rules for the toolchain majors' individual members (none exist; the sweep is deliberately
unignored) or the sequence completes — closing it changes nothing about that cadence, and this
entry records that explicitly so a future close isn't read as having fixed it.

**The scoping doc's methodological error, found by executing step 1 rather than by inspection.**
The entry immediately below this one (`#86 sweep step 1 landed`) diffed the *fully-resolved* ESLint
config before and after the bump and found `no-with` had moved from `error` to `off` — a change
the doc's §0.3 said could not have happened, because §0.3 claimed the shipped `recommendedTypeChecked`
config was "byte-for-byte identical… nothing added, removed, or re-severitied" between 8.19.0 and
8.66.0. The claim was wrong, and the way it was wrong matters more than the specific miss:
`tseslint.configs.recommendedTypeChecked` is a **three-layer composite** (`base` +
`eslint-recommended` + `recommended-type-checked`), and the scoping session diffed only the third
file — `dist/configs/recommended-type-checked.js`, 50 entries either side, genuinely identical —
then generalised that result to the whole composite. The undiffed `eslint-recommended-raw.js` layer
went 22 → 23 entries across the same span, adding `no-with: 'off'`, which changes the resolved
config because `frontend/eslint.config.js` extends `js.configs.recommended` ahead of the tseslint
layers.

**This is scope, not sloppiness, and the correction says so.** Every claim in the document is
cited to a published peer range, an upstream guide, or an unpacked tarball — eleven tarballs were
pulled apart to check artifacts directly rather than trust documentation, which is real evidentiary
discipline. The failure was narrower than that discipline: one file was diffed and the finding was
stated about a three-file composite it was only one third of. Nothing about the method that
produced the other headline findings (§0.1's TypeScript-7 package-export read, §0.4's
`@eslint/eslintrc` dependency-graph check, §0.5's GHSA re-cut verified at the advisory database) is
implicated — those each read the actual artifact the claim was about, completely. §0.3 read one
artifact out of three and described all three.

**What §0.3 now says, and what was added alongside it.** Rewritten to separate what was verified
(the third layer, genuinely identical) from what was not (the other two layers, one of which
changed) and from a second, independent point the original headline conflated with the first: an
unchanged rule set does not imply an unchanged set of *findings*, because rule implementations get
stricter across a 47-minor span regardless of which rules are selected — step 1's own two
`no-unnecessary-type-assertion` reports are the proof, on code that was in the tree, unedited, the
whole time. Step 1's own row had already priced this correctly ("only detection improves," S–M,
"dominated by however many reports appear"); it was the headline in §0.3 that read as a stronger,
outcome-level promise and got cited as one. A method note was added, binding on every step in §6
that has not yet run: re-verify each step's config/rule-set claim against the **installed** tree
when the step executes, checking **every layer** of any composite config, using
`eslint --print-config <file>` on one representative file per file class (app `.tsx`, library
`.ts`, test override) before and after — not a diff of the plugin's own shipped config file, which
is exactly the check that would have caught this the first time.

**Package-ownership check requested for six packages; five were already correctly scoped, one
row was thin and was filled in.** Checked against the doc's actual step assignments in §6, not
against memory of what the doc probably says:

| Package | Owning step | Verdict |
|---|---|---|
| `@vitejs/plugin-react` 4.3.4 → 6.0.5 | Step 7, lockstep with Vite 8 | **Already correctly scoped.** §3.3 and Step 7's row already state the Babel-removal no-op and the Vite-8-only peer; no routine-bump treatment to correct. |
| `@testing-library/user-event` → 14.6.3 | Step 8 | **Already correctly scoped** as a routine patch; no coupling exists to misstate. |
| `globals` → 17.9.0 | Step 8 | **Already correctly scoped**, and already carries a non-routine caution (a minor can silently shrink the `globals.browser` set — inspect it, don't trust green). |
| `postcss` → 8.5.26 | Step 0 and/or Step 8 (either) | **Already correctly scoped**, explicitly optional/either-step. |
| `@types/node` → 26.1.2 | None — §5 explicitly declines it | **Correct as a non-member.** §5's "Action: none" is a decision the sweep doesn't need it, not an omission. |
| `eslint-plugin-react-refresh` 0.4.16 → 0.5.3 | Step 2 | **Owned, but the row treated it as routine and it isn't quite.** Step 2's "Moves" line listed the version bump with no accompanying breakage note, unlike the other three packages in that step. 0.5.0 is ESM-only and requires flat config (a no-op here — this repo has been flat-config since Phase 0), renames `customHOCs` to `extraHOCs` (also a no-op here — the repo's one `react-refresh/only-export-components` usage sets no HOC option), and tightens HOC validation generally. Step 2's row now names all three; the ESM/flat-config and rename points are confirmed no-ops for this repo's current config, but — per the new method note — should be re-checked against the installed 0.5.3 package when Step 2 actually runs rather than trusted from this pass. |

None of the six needed reordering or a new owning step; the sequence's membership and order are
unchanged by this entry.

**What was deliberately not done.** No dependency, lockfile, or config file was changed. No
sweep step was executed. `main` was not touched. The sequence's membership and ordering were not
altered — §6's steps 0–8 still name the same packages in the same order for the same peer-range
reasons; only the claims describing what Step 1 and Step 2 will find, and the headline in §0.3,
were corrected. `docs/ROADMAP.md` was not edited.

**Plan section affected:** `docs/upgrades/frontend-toolchain-86.md` §0.3, the Step 1 and Step 2
rows of §6, one clause in §8's risk-ranking discussion, and this entry. PR #170 (closed, not
merged). No code, schema, API contract, security model, job model, auth, or CI behaviour changed;
no locked decision re-opened.

---

### 2026-08-09 — Infra — #86 sweep step 1 landed: `typescript-eslint` 8.19.0 → 8.66.0; the scoping doc's rule-set claim was wrong in two independent ways

**What changed:** `frontend/package.json` (one line), `frontend/package-lock.json`, two lines of
`frontend/src/pages/NewScanPage.tsx`, plus `CHANGELOG.md` and this entry. This is **step 1 of the
eight-step sequence** in `docs/upgrades/frontend-toolchain-86.md`, executed exactly as scoped: only
`typescript-eslint` moved, no ESLint or TypeScript config was edited, and no later step was touched.
`typescript` stays at 5.7.2, `eslint` at 9.39.4, and `#153` remains open and unactioned.

**Why it goes first and alone** is unchanged from the scoping entry below and was re-confirmed from
the installed lockfile rather than re-derived: the pinned 8.19.0 declared `typescript: >=4.8.4
<5.8.0` and `eslint: ^8.57.0 || ^9.0.0`; 8.66.0 declares `>=4.8.4 <6.1.0` and `^8.57.0 || ^9.0.0
|| ^10.0.0`. Those two range widenings are the whole reason this step exists — they are what
unblocks steps 2 (ESLint 10) and 4 (TypeScript 6.0.3). The version was re-checked against the
registry before the bump rather than taken from the document: `latest` is still **8.66.0**, with
only `8.66.1-alpha.*` canaries beyond it, so the doc's target was still current. The same one-liner
that §3.1 carries also still returns `typescript: >=4.8.4 <6.1.0`, so the TypeScript **6.0.3**
ceiling holds as of this date.

**The scoping document's headline prediction was checked against the installed configs rather than
believed, and it failed in two independent ways.** Both are recorded here because the remaining
steps' predictions were written with the same method and inherit the same weaknesses.

**Divergence 1 — an existing rule's implementation got stricter. This is the one the document's
framing actively obscures.** The prediction that the *rule set* is unchanged is **correct and was
confirmed at the artifact**: diffing 8.19.0's `dist/configs/recommended-type-checked.js` against
8.66.0's `dist/configs/flat/recommended-type-checked.js` yields **50 entries either side, identical**
— 43 `@typescript-eslint/*` rules plus 7 core-rule disables, same severities, same options. But an
unchanged rule set does not imply an unchanged set of *reports*. Across 47 minors,
`@typescript-eslint/no-unnecessary-type-assertion` learned to detect a case it previously missed, and
it fired twice on code that has been in the tree unchanged:

```
src/pages/NewScanPage.tsx  139:19  registryId: '' as string
src/pages/NewScanPage.tsx  140:24  gitCredentialId: '' as string
    error  This assertion is unnecessary since the receiver accepts
           the original type of the expression
```

Both assertions were genuinely redundant — `''` already widens to `string` as a mutable object-literal
property — and both were removed **by hand, at those two sites only**. No `--fix`, no bulk autofix.
`tsc -b` passes afterwards, confirming `useForm`'s inferred `initialValues` type is unchanged, and
the emitted bundle carries the **same content hashes** as the pre-bump baseline
(`index-BNB6IweX.js`, `index-D2wHtcHV.css`), which is the proof that a type-only assertion erases to
identical JavaScript.

**The transferable rule, and it applies to every remaining step: "no new rules" does not mean "no
new findings."** A rule set proven identical bounds *which* rules can report; it says nothing about
how well they report. The document's Step 1 row does budget for this — it says *"only detection
improves"* and prices the step **S–M / 1–3 h "dominated by however many reports appear"** — so the
budget was right. What is misleading is §0.3's headline, *"The typescript-eslint bump does not
change which rules run,"* which reads as a reassurance about outcomes and is repeatedly cited as
one. Two reports is at the very low end of the range, but the mechanism is real and will recur:
steps 2 and 4 both cross far more implementation change than config change.

**Divergence 2 — the effective rule set *did* change. The document's claim here is wrong, not
merely incomplete.** §0.3 states the shipped `recommendedTypeChecked` is *"byte-for-byte identical…
the same 50 rules at the same severities, nothing added, removed, or re-severitied."* The cause of
the error is a **scope mistake**: `tseslint.configs.recommendedTypeChecked` is a **three-layer
composite** (`base` + `eslint-recommended` + `recommended-type-checked`), and the document diffed
only the third file, then generalised the finding to the whole composite. The layer it did not
diff has changed:

| File | 8.19.0 | 8.66.0 | Verdict |
|---|---|---|---|
| `dist/configs/…/recommended-type-checked.js` *(diffed by the doc)* | 50 entries | 50 entries | **identical** |
| `dist/configs/eslint-recommended-raw.js` *(not diffed by the doc)* | 22 entries | 23 entries | **`+ no-with: 'off'`** |

Because `frontend/eslint.config.js` extends `js.configs.recommended` **before** the tseslint layers,
the resolved config that actually runs changes: `eslint --print-config` reports `no-with` going from
`error` (`[2]`) to `off` (`[0]`) for all three file classes — app `.tsx`, library `.ts`, and the
test override. Verified by dumping and diffing the fully-resolved config before and after, not from
package metadata. The only other resolved-config difference is the parser identity string
(`typescript-eslint/parser@8.19.0` → `@8.66.0`), which is expected.

**The relaxation was accepted rather than restored, and the premise was verified rather than
argued.** The case for accepting it is that `with` is already a hard compile error here — but that
argument only holds under strict mode, and a non-module `.ts` file is not strict by default. Both
`tsconfig.app.json` and `tsconfig.node.json` set `"strict": true` and `"moduleDetection": "force"`,
and rather than stop at reading the flags, a probe file containing a `with` statement was compiled:
`tsc -b` returns **`TS1101: 'with' statements are not allowed in strict mode`** and **`TS2410`**. The
probe was deleted. So the rule is genuinely redundant on this codebase and upstream's decision to
move it into the "TypeScript handles this" disable layer is sound. `no-with` was **not** re-added to
`eslint.config.js`; if that judgement is ever revisited, one line in the `rules` block restores it.

**Standing consequence for the rest of the sweep: the remaining steps' predictions were produced by
the same method and should be re-verified, not trusted.** The document's evidence discipline is
genuinely good — every claim is cited to a published peer range or an upstream guide, and eleven
tarballs were unpacked to check artifacts directly. The failure here was not sloppiness but
**scope**: one file was diffed and the conclusion was stated about a composite of three. Steps 2, 3
and 4 all rest on comparable single-artifact reads — the enumeration of the 14 React Compiler rules
from `eslint-plugin-react-hooks@7.1.1`'s bundle, the three new `eslint:recommended` rules from
`@eslint/js@10.0.1`, the option-by-option TypeScript 6.0 audit. Each should be re-checked against
the installed tree at the time its step is executed, exactly as this one was. The document's
§9 item 5 already says the report counts can only be learned by executing the sequence; this entry
extends that to the config claims themselves.

**What moved in the lockfile, and why 486 changed lines is not churn.** `frontend/package.json`
changed one line. The lockfile went **374 → 362 packages**, and every movement is inside the
`typescript-eslint` subtree or orphaned by it — attributed rather than assumed, by parsing both
lockfiles and resolving each removed package's requirers:

- **12 version bumps** — the ten `@typescript-eslint/*` packages 8.19.0 → 8.66.0, plus
  `ts-api-utils` 1.4.3 → 2.5.0 and, nested under `typescript-estree`, `minimatch` 9.0.9 → 10.2.6 and
  `brace-expansion` 2.1.4 → 5.0.9.
- **5 added** — `@typescript-eslint/project-service` and `@typescript-eslint/tsconfig-utils`, new
  first-party packages split out of `typescript-estree`; plus three *nested* copies that exist only
  because the top-level ones stay pinned for ESLint 9 (`ignore@7.0.6`, `eslint-visitor-keys@5.0.1`,
  `balanced-match@4.0.4`).
- **17 removed** — `typescript-estree` replaced `fast-glob` with `tinyglobby`, which was **already
  in the tree at 0.2.17** and satisfies its `^0.2.15`, so no new dependency landed. Dropping
  `fast-glob` orphaned its entire subtree: `@nodelib/fs.{walk,scandir,stat}`, `fastq` → `reusify`,
  `run-parallel` → `queue-microtask`, `merge2`, `micromatch` → `braces` → `fill-range` →
  `to-regex-range` → `is-number`, the top-level `picomatch@2.3.2`, and the nested
  `fast-glob/node_modules/glob-parent@5.1.2`. `graphemer` went with the `eslint-plugin`. **Each was
  checked to have no surviving requirer**; in particular `eslint`'s own top-level
  `glob-parent@6.0.2` and vite/vitest's nested `picomatch@4.x` are untouched.

`lockfileVersion` stays 3 and there is no normalization churn, because the lockfile was written with
**npm 11.19.0** installed into a scratch prefix — matching CI's Node 24 rather than the sandbox's
Node 22 / npm 10.9.7 — which is the method the lockfile-refresh entry below recorded for reuse. It
was worth repeating: a 486-line diff from a genuine dependency change is hard to audit if a whole-file
re-normalization is mixed into it.

**Suites, run from a clean install both before and after so the comparison is real.** The pre-bump
baseline was re-measured on 8.19.0 rather than quoted from the document, and it reproduced §1
exactly: lint clean, `format:check` clean, **79 tests across 21 files**, build **7,035 modules →
645.18 kB JS / 201.38 kB CSS**. After the bump and the two-line fix, every one of those is
unchanged, down to the emitted asset hashes, and `npm audit` reports **0 vulnerabilities** at every
severity (the two HIGHs from the entry below stay closed).

**Plan section affected:** `frontend/package.json`, `frontend/package-lock.json`,
`frontend/src/pages/NewScanPage.tsx`, `CHANGELOG.md` § Unreleased/Changed, and this entry.
`frontend/eslint.config.js`, both tsconfigs, `docs/upgrades/frontend-toolchain-86.md` and
`docs/ROADMAP.md` were deliberately **not** edited — correcting the sequence document's §0.3 is a
maintainer call, and this entry is the record of what it got wrong in the meantime. No code
behaviour, schema, API contract, security model, job model, auth, or CI configuration changed; no
locked decision re-opened.

---

### 2026-08-09 — Security — Frontend lockfile refreshed to clear two HIGH advisories in the build toolchain (js-yaml, nanoid); kept separate from the #86 sweep

**What changed:** `frontend/package-lock.json` only — two entries, six lines each way — plus a
`CHANGELOG.md` § Security entry and this one. `frontend/package.json` was **not** touched, no
package moved a major, and no `npm audit fix` was run in any form.

**The two advisories.** Both were already named in the entry below, which recorded them from the
#86 scoping session's baseline install; this entry is the one that acts on them.

- **`js-yaml` 4.3.0 → 4.3.1** — **GHSA-5p4m-2wfm-xmqj**, HIGH, CVSS 7.5, CWE-407: quadratic CPU
  consumption resolving a `!!omap`, the CVE-2026-59870 fix not having been backported to the
  3.x/4.x lines. Affected `>=4.0.0 <4.3.1`. One path in the tree: `eslint@9.39.4` →
  `@eslint/eslintrc@3.3.5` → `js-yaml`.
- **`nanoid` 3.3.16 → 3.3.18** — **GHSA-2v37-7h3g-55p8**, HIGH, CVSS 5.9, CWE-835: a custom
  generator loops indefinitely when `size` is zero. Affected `<3.3.17`. One path in the tree:
  `postcss@8.5.25` → `nanoid`.

Each package appears exactly once in the lockfile, so "one path" is the whole exposure, not the
shortest of several.

**Why a lockfile refresh sufficed — and a precision correction to how that was framed.** The
session brief said both fixed versions "fall inside the ranges `package.json` already declares."
The conclusion is right and the mechanism is not: `frontend/package.json` pins every dependency
to an **exact version** (`CLAUDE.md` § Dependency hygiene) and **names neither package** — both are
transitive. The ranges that actually decide this are the ones the *requiring* packages declare,
read from the published manifests rather than from `npm audit`'s `fixAvailable` summary:
`@eslint/eslintrc@3.3.5` requires `js-yaml: ^4.1.1` (4.3.1 satisfies; 4.3.1 is also the highest
4.x published), and `postcss@8.5.25` requires `nanoid: ^3.3.16` (3.3.17 satisfies). Both fixes are
therefore reachable without moving `eslint` or `postcss` — which *are* pinned exactly in the
manifest — so nothing in `package.json` had to change. Worth stating explicitly because the
distinction is what makes the "manifest untouched" claim true: it does not follow from a range in
`package.json`, because there is no range in `package.json`.

**Deviation — `nanoid` landed on 3.3.18, not the advisory's 3.3.17.** `npm update` resolves to the
highest version satisfying the declared range, and `^3.3.16` admits 3.3.18 (published 2026-08-07,
four days after 3.3.17). Taken rather than pinned back, because diffing the two published tarballs
shows 3.3.18 is a follow-up to the *same* defect: 3.3.17's zero-size guard did not cover the async
native entry point, and 3.3.18 adds `if (size <= 0) return Promise.resolve('')` there. It is the
more complete fix for the advisory, not an unrelated bump.

**The `js-yaml` fix was verified at the artifact, not from the advisory text** — § Interpreter CVEs'
rule applied to a dependency claim. Diffing the 4.3.0 and 4.3.1 tarballs, the sole functional change
is in the `!!omap` duplicate-key check: an array plus a linear `indexOf` per key — the quadratic
path the advisory describes — becomes an object plus an `Object.prototype.hasOwnProperty` lookup.
The advisory's account and the shipped code agree.

**Neither package ships in the image, and that was checked rather than assumed.** Both are `dev`
in the lockfile; `grep` over the built bundle finds no `nanoid`/`urlAlphabet` and no
`js-yaml`/`YAMLException` (`nanoid` runs inside PostCSS at build time, `js-yaml` only parses this
repo's own ESLint config); and `docker/Dockerfile`'s runtime stage copies
`--from=frontend-builder /build/frontend/dist` and no `node_modules`. So the exposure is the build
and development toolchain, and a deployed Scrye was never reachable. The fix is still taken —
fixable is what the dogfood gate keys on.

**What actually moved, which is the point of doing it this way.** The refresh was the documented
targeted command from `CONTRIBUTING.md` § Dependabot security updates target `main` (`npm update
<pkg>`), scoped to the two packages, and the diff was read before anything else: **exactly two
lockfile entries**, the `version`/`resolved`/`integrity` triple on each, no transitive requirement
moved, no unrelated churn, `package.json` byte-identical. `npm audit` afterwards reports **0** at
every severity — the two cleared, nothing new surfaced.

**Method note: the lockfile was written by npm 11, matching CI.** The sandbox's Node is 22 (npm
10.9.7) while `ci.yml` and the Dockerfile's `frontend-builder` both build on Node 24 (npm 11.x), so
`npm i -g npm@11` was attempted, failed on self-replacement, and npm 11.19.0 was installed into a
scratch prefix and invoked by path instead. This is cheap insurance against a whole-file
normalization diff from a different npm major — and the resulting six-line diff is the evidence it
was not needed here. Recorded so the next lockfile touch can skip the detour or repeat it knowingly.

**Suites, run against a clean `npm ci` from the refreshed lock:** ESLint clean, Prettier clean,
**79 tests across 21 files** passing, `npm run build` green at **7,035 modules → 645.18 kB JS /
201.38 kB CSS**. Those are byte-for-byte the numbers the baseline in the entry below records, which
is the useful signal: nothing observable moved.

**Kept deliberately separate from the #86 sweep, and it is not a step in it.** The entry below
turns `docs/ROADMAP.md` § Track A into eight ordered steps, each arranged so a failure has one
plausible cause. This change is none of them — it takes no major, edits no config, and touches no
package that sequence moves. Folding it into a sweep step would have given that step a second
plausible cause of failure for no benefit, and holding it until the sweep starts would have left
two HIGH advisories open across an unbounded number of releases for no benefit either. The sweep's
own framing of these two findings — "a lockfile refresh alone clears them, no part of the sweep
required" — is the same conclusion, and is now discharged. **#153 stays open and unactioned**, and
nothing here changes its state, its diagnosis, or the sweep's step order. Nothing from #153 and no
sweep step was touched.

**Plan section affected:** `frontend/package-lock.json`, `CHANGELOG.md` § Unreleased/Security, and
this entry. `frontend/package.json`, `docs/ROADMAP.md`, `docs/upgrades/frontend-toolchain-86.md`
and the backend lockfile were deliberately **not** edited. No code, schema, API contract, security
model, job model, auth, or CI behaviour changed; no locked decision re-opened.

---

### 2026-08-09 — Docs/Process — #86 frontend toolchain sweep scoped into an ordered sequence; TypeScript 7 ruled out at the source; #153's red check re-diagnosed

**What changed:** one new file, `docs/upgrades/frontend-toolchain-86.md`, plus this entry. **No
dependency version, lockfile, or config file was touched** — the session was scoping only, and
`frontend/package-lock.json`'s SHA-256 was captured before the baseline install and re-verified
after it. The deliverable turns `docs/ROADMAP.md` § Track A's *"Frontend tooling majors from
Dependabot #86"* — currently one PR (**#153**) carrying eleven majors behind a single red check —
into eight independently verifiable steps, each ordered so its failure has one plausible cause.

**Method, because it is the point.** Every constraint in the document is cited to one of two kinds
of source: a `peerDependencies` range in a **published package** read from the npm registry, or a
**statement in upstream's migration guide/changelog** fetched as raw markdown from that project's
own repository. Nothing was inferred from version-number proximity, and where a claim could be
checked against the shipped artifact rather than the documentation, it was — eleven tarballs were
downloaded and unpacked to compare config objects directly. The prior records' predictions about
what would break were treated as hypotheses to test, not as findings to carry forward, and two of
them did not survive.

**Finding 1 — TypeScript 7 is not part of this sweep, as of 2026-08-09.** `typescript@7.0.2` is the
Go-native compiler. Read from its published tarball: `"exports"."."` is `./lib/version.cjs`, so
`import ts from 'typescript'` yields the version string and nothing else; `lib/` contains
`getExePath.js`, `tsc.js`, `version.cjs` and **no `typescript.js`**; `bin` has dropped `tsserver`;
the package carries 20 platform-specific native-binary optional dependencies; and `unpackedSize`
falls from 24.3 MB (6.0.3) to 2.5 MB. The real API sits behind `./unstable/*` subpaths talking to
the Go binary over `vendor/vscode-jsonrpc`. Against that, `@typescript-eslint/typescript-estree@8.66.0`
calls `require("typescript")` in 11 places across `dist/*.js` and references **114 distinct `ts.*`
symbols** including `ts.createProgram`. `typescript-eslint`'s peer range is `>=4.8.4 <6.1.0` at
`latest` **and at its current canary** — no version published as of this date accepts TypeScript 7,
and the shape of the change means widening it is a rewrite upstream, not a range edit. **The
sweep's TypeScript ceiling is 6.0.3.** (Separately verified so it is not re-derived: `tsc -b` *does*
survive — running the 7.0.2 native binary, `--build, -b` is still in `--help` — so `npm run build`
is not what blocks TS 7. Only the linter is. This is § Interpreter CVEs' rule applied to a
toolchain claim: check it against the artifact before believing the metadata, in either direction.)

**This finding is written as a dated ceiling, not a permanent blocker**, and the document carries
the re-check with it: `npm view typescript-eslint@latest peerDependencies.typescript`, watching the
**stable** tag rather than a canary, with the note that support is expected to arrive as a new
typescript-eslint **major** built against TS 7's `./unstable/*` API rather than as a point-release
range widen. Corroborated from the TypeScript side by the 6.0 release notes, which call 6.0 a
transition release *"API compatible with TypeScript 5.9"* whose deprecated options are *"removed
entirely in TypeScript 7.0"* — which is precisely why step 4 (to 6.0.3) is safe and a step beyond
it is not.

**Finding 2 — #153's red check is not lint churn, and the prior records say it is.** The
`Frontend — lint + build` job (check run `93006217895`) failed after **six seconds**, at `npm ci`,
with `ERESOLVE`: `typescript-eslint@8.66.0` peer `typescript@">=4.8.4 <6.1.0"` against the proposed
`typescript@7.0.2`. ESLint never ran. **`docs/ROADMAP.md` § Track A and the 2026-08-09
Dependabot-queue-audit entry below both describe that failure as *"the type-aware-ESLint churn that
roadmap item predicts, arriving on schedule."* That is incorrect** — it is an unsatisfiable
dependency graph, and no amount of lint fixing would move it. The observation that #153 stays open
as the sweep's reminder surface stands; only the diagnosis of its red check is corrected. Recorded
here rather than fixed in `docs/ROADMAP.md`, which this session deliberately left unedited, and
**posted on the PR itself** so the correction reaches anyone triaging the queue without reading
this file:
[#153 (comment)](https://github.com/tyler-rich/Scrye/pull/153#issuecomment-5230438598). The PR was
**not** closed — closing it only makes Dependabot regenerate an equivalent grouped PR carrying the
same unsatisfiable pairing.

**Finding 3 — the `typescript-eslint` bump does not change which rules run.** The shipped
`recommendedTypeChecked` config is **identical** between 8.19.0 and 8.66.0 — the same 50 rules at
the same severities, nothing added, removed, or re-severitied (diffed from
`dist/configs/recommended-type-checked.js` in both tarballs). Across 47 minors, any new reports
come from rule *implementations* improving, not from the config growing. This materially lowers the
expected cost of what the sequence makes step 1.

**Finding 4 — the real ordering constraint, which no prior record states.** Read across every
stable `typescript-eslint` release from the pin forward, the peer ranges move at exactly two
points: **8.56.0** first admits `eslint ^10.0.0`, and **8.58.0** first raises the TypeScript cap to
`<6.1.0`. The pinned **8.19.0 caps TypeScript at `<5.8.0`** — it will not accept even 5.8. So
`typescript-eslint` is not merely "a minor that would need reviewing twice" (the 2026-08-03
framing); it is the **only** unblocking move in the set, and both the ESLint and the TypeScript
steps are gated behind it. It becomes step 1, alone.

**Finding 5 — ESLint 10 forces `eslint-plugin-react-hooks` 7, which forces a decision.** The
`^10.0.0` clause first appears in react-hooks **7.1.0**; 5.1.0/6.0.0/7.0.0/7.0.1 all stop at `^9`,
so ESLint 10 with the current pin is the same ERESOLVE class that killed #153. And from the 7.1.1
bundle, `configs.recommended.rules` is `basicRuleConfigs` **plus** every React Compiler rule at
preset `Recommended` — `frontend/eslint.config.js:31` spreads exactly that object, so the bump
silently takes it from 2 rules to 16 (12 new at `error`, 2 at `warn`, enumerated in the document).
The sequence therefore splits them: the ESLint-10 step writes the two classic rules out explicitly
(a behaviour-preserving edit, verified against 5.1.0's shipped config), and adopting the compiler
set is its own step that **may legitimately be declined**.

**Finding 6 — Vitest 4 does not require a Vite major**, contradicting an assumption worth naming.
`vitest@4.1.10`'s peer is `vite: ^6.0.0 || ^7.0.0 || ^8.0.0` and its migration guide's Prerequisites
callout says *"Vitest 4.0 requires Vite >= 6.0.0"*. It lands on the pinned `vite@6.4.3`.
Conversely **`@vitejs/plugin-react` 6 does require Vite 8** — peer `vite: "^8.0.0"` only, and a
changelog heading *"Drop Vite 7 and below support"* — so those two move in lockstep and Vitest does
not have to wait for them.

**Finding 7 — locked decisions are not at risk from anything in the sweep**, checked package by
package: no member declares a `react`, `react-dom`, `@types/react*`, or `@mantine/*` peer at all.
The React Compiler rules are static analysis with no React runtime dependency. **The one adjacent
item that *is* a locked-decision blocker is `react-router` 7 → 8**, which `docs/ROADMAP.md` groups
with the tooling majors: `react-router@8.3.0` declares `react: ">=19.2.7"` and
`react-dom: ">=19.2.7"`, so it is a React 19 requirement against a React 18 lock — a separate
decision, not a quiet inclusion. It is not in #153.

**Baseline recorded, and it moved since the last record.** `npm ci` from the committed lockfile,
then lint clean, `format:check` clean, **79 tests across 21 files** passing, and `npm run build`
green (vite 6.4.3, 7035 modules, 645.18 kB JS / 201.38 kB CSS). `npm audit` reports **two HIGH** —
`js-yaml` 4.3.0 via `eslint → @eslint/eslintrc`, and `nanoid` 3.3.16 via `postcss` — where §14
(2026-08-03) recorded the `react-router` HIGH as the only finding. Both new ones are **inside
existing semver ranges**, so a lockfile refresh alone clears them, no part of the sweep required;
ESLint 10 additionally removes the `@eslint/eslintrc` path permanently (`eslint@10.8.1` no longer
lists it as a dependency).

**Unrelated finding, surfaced by the same baseline and then verified at source: GHSA-qwww-vcr4-c8h2
was re-cut upstream — an amendment to the advisory itself, not a registry-side quirk.** The npm
registry's bulk endpoint returning two ranges was only the trigger; the claim was confirmed against
the **GitHub Advisory Database record**, read from the `github/advisory-database` repository via
`raw.githubusercontent.com` (`advisories/github-reviewed/2026/07/GHSA-qwww-vcr4-c8h2/…json`) after
`api.osv.dev` and `github.com/advisories/…` both proved unreachable from here. Three legs: the
record now carries **two `affected` entries** for `react-router` (`introduced 7.12.0 / fixed 7.18.2`
and `introduced 8.0.0 / fixed 8.3.0`); its `published` and `github_reviewed_at` are both
**2026-07-24T16:44:43Z** while `modified` is **2026-08-07T18:14:58Z**, so the record was edited
fourteen days after review; and §14 (2026-08-03) independently records `npm audit` reporting this
advisory as one contiguous **`7.12.0 - 8.2.0`** during the v0.3.0 release prep, which dates the
split to between 2026-08-03 and that `modified` stamp. What is **not** readable from here is the
per-revision diff — GitHub renders advisory revision history only on the web page, and the
advisory-database repo's git log is not exposed through raw content — so the `modified` timestamp
is the amendment evidence, not a revision-by-revision account.

**This is exactly what `docs/ROADMAP.md` § Track A asks for** under *"Ask GitHub to re-cut
GHSA-qwww-vcr4-c8h2's affected range for the 7.18.2 backport"*, down to its "leave the 8.x range as
it is" condition. Flagged rather than acted on, and `docs/ROADMAP.md` deliberately left unedited —
striking a Track A item is a maintainer call.

**Three of #153's targets are already stale**, which is the ordinary cost of holding a Dependabot
PR open as a reminder: `eslint` 10.8.0 → **10.8.1**, `vite` 8.2.0 → **8.2.1**, `@types/node` 26.1.2
→ **26.2.0**, all published 2026-08-06/07 after the PR was cut. Read targets from the registry when
the work starts, not from the PR.

**`@types/node` specifically: the sweep does not need it.** The only constraints in play are
*optional* peers (`vite@8.2.1` wants `^20.19.0 || >=22.12.0`; `vitest@4.1.10` wants
`^20.0.0 || ^22.0.0 || >=24.0.0`) and the pinned **24.13.3 satisfies both**. No step fails on it.
#153 proposes 26.1.2 anyway for the reason the entry below already diagnosed — Dependabot reads its
`ignore` list from `main`, and #147's `@types/node` stanza has not been promoted — and the
maintainer declined promoting the config on its own, so the offer will keep arriving and keep being
inert.

**Four lookups first reported as blocked were retried against different sources and resolved.** In
three of the four the block was not what it looked like, which is the transferable lesson:

- **TypeScript 6.0's breaking changes — resolved.** `typescriptlang.org` and
  `devblogs.microsoft.com` are genuinely egress-blocked, but the release notes are **source markdown
  in `microsoft/TypeScript-Website`, on its `v2` branch** (`packages/documentation/copy/en/
  release-notes/TypeScript 6.0.md`), which `raw.githubusercontent.com` serves. Fetch the docs
  repository, not the rendered site. The full option-by-option audit against both tsconfigs is now
  in the document's §7.2; the two changes upstream says *"will affect many projects"* — `types`
  defaulting to `[]` and `rootDir` defaulting to `.` — are **no-ops for this repo**, verified rather
  than assumed (`frontend/src/` has zero references to `process`/`Buffer`/`__dirname`/`__filename`,
  no `NodeJS.` namespace use, every test imports its globals from `'vitest'`, and timers go through
  `window.setTimeout`; `tsconfig.node.json` already sets `"types": ["node"]`). The residual risk is
  the *"less context-sensitivity on `this`-less functions"* inference change, which no config audit
  can pre-empt.
- **jsdom 27/28/29 — resolved, and the original report was my error.** The changelog **does** exist
  at `refs/tags/v29.0.0/Changelog.md`; it was deleted at `v30.0.0`. The first pass reported "all
  candidate paths 404" after probing `refs/tags/26.1.0` and friends — **jsdom's tags carry a `v`
  prefix**, so those refs simply do not exist, and a bad ref 404s identically to a missing file.
  Recorded because the failure mode is general: a 404 from `raw.githubusercontent.com` is evidence
  about the *path*, not about the file, until the ref is independently confirmed (fetching a known
  file such as `README.md` at the same ref is the cheap check).
- **The Node version behind the pinned digest — resolved: `node:24-bookworm-slim@sha256:235600a8…`
  ships Node 24.18.1**, which satisfies jsdom 30's `^24.15.0` floor, so that prerequisite is closed
  with no Dockerfile change. `docker run` was unavailable (CLI present, no daemon), so it was
  resolved against the registry by **two independent methods that agree**: Docker Hub's tag index
  maps that digest to exactly `24.18.1-bookworm-slim` and `24.18-bookworm-slim`, and the image's
  config blob carries `NODE_VERSION=24.18.1`. Method note for reuse: Docker Hub serves manifests
  directly but **307-redirects blobs to `production.cloudfront.docker.com`, which is egress-blocked
  here**, so the blob was pulled through **`mirror.gcr.io`**, a pull-through cache that serves blobs
  on its own domain.
- **The GHSA verification** described above, via the `github/advisory-database` repository.

**Still genuinely blocked**, with the stated method left in place in the document's §9: **jsdom
30.0.0's own release notes** (the changelog file is gone as of that tag — eight candidate filenames
probed at the correct `v30.0.0` ref, all 404 — and the notes live only in GitHub Releases, which
403 through the proxy), and **whether an upstream `typescript-eslint` issue tracks TS 7 support**.
The jsdom 30 gap is partly mitigated by artifact comparison rather than guesswork: `matchMedia`,
`ResizeObserver`, and `scrollIntoView` appear in **zero** files of the shipped `lib/` in 26.1.0,
29.1.1 *and* 30.0.1, so `src/test/setup.ts`'s `if (!…)` polyfill guards behave identically across
the span — retiring the specific "the polyfill silently steps aside" risk the first pass flagged.
The typescript-eslint gap does not block the decision at all, since §3.1's registry one-liner
answers "can we take TS 7 yet" without the issue tracker.

**Explicitly not done**, per the session's scope: no dependency version changed, no lockfile or
config edited, no PR opened that changes code, no action taken on #153, and no speculative install
run to "see what happens". `npm ci` was run only to establish the baseline against the **current**
lockfile, and that lockfile's hash is unchanged.

---

**Third pass (same date, follow-up PR): the estimates were re-derived against the newly-readable
changelogs, and two of them moved.** The first two passes wrote the per-step effort/risk table
while jsdom 27/28/29 were still listed as unreachable. With those changelogs in hand the jsdom
step was re-costed from the *actual test code* rather than from the changelog's tone, and the
result is worth recording because it cuts both ways:

- **Two channels are live.** The **selector-engine swap** (27.0.0, `nwsapi` →
  `@asamuzakjp/dom-selector`) sits under **116 Testing Library query call sites** across the 12
  `.tsx` test files — every query bottoms out in `querySelectorAll`. And the **re-derived UA
  stylesheet** (27.0.0, plus its `display`-resolution fix) reaches the suite through exactly one
  path, verified in the installed `@testing-library/dom@10.4.1`: `isSubtreeInaccessible()` reads
  `getComputedStyle(element).display`, `isInaccessible()` reads `.visibility`, `config.js` sets
  `defaultHidden: false`, and the repo never calls `configure()` — so all 34 `getByRole` sites run
  that filter.
- **Four channels are provably inert, including the two that sound worst.** The **CSSOM rewrite**
  (29.0.0) has no author CSS to act on: `vite.config.ts`'s `test` block sets no `css` key, so
  Vitest's default `css: false` applies and Mantine's stylesheets never enter jsdom. The
  **`element.click()` → `PointerEvent`** change (27.0.0) is unreachable: there is **no `.click()`
  anywhere in `frontend/src/`**, and all interaction goes through `userEvent.click` (8) or
  `fireEvent.click` (6), which build and dispatch their own events. **Passive-by-default events**
  cannot bite — no `preventDefault` anywhere in `src/`, no wheel/touch/scroll listeners. Resource
  loading, MIME sniffing, and bad-port blocking have no subresource loads to affect.
- **Net: effort widened S–M → S–L; risk held at medium.** The two directions roughly cancel. The
  reason it did not rise is the property that separates this step from the Vite one: **detection is
  complete and immediate** — 79 assertions in ~15 s, with no failure mode that survives a green
  run.

**The ordering changed as a result: jsdom and Vite 8 swapped, making jsdom step 6 and Vite step 7.**
Membership is unchanged. Steps 4–7 carry no dependency on each other, so their order was always a
judgement about verification cost rather than a constraint; the swap spends the cheap, total oracle
(`npm test`) before the expensive, partial one (a build plus a human pass over the running SPA),
keeps both test-harness steps adjacent, and stops the last test-harness change from landing on a
just-swapped bundler — the one arrangement in which a test failure has two plausible causes. The
original order is recorded as *not wrong*, since every step is verified green before the next
begins.

**The premise that prompted the re-check was half right, and the entry says so.** jsdom **is**
riskier than the `typescript-eslint` step — but it already was in the first draft (Step 1 low–med
versus jsdom medium), so the changelogs confirmed that relative order rather than overturning it;
and `typescript-eslint` was **never** the top of the ranking. Step 3 (React Compiler, unbounded)
and the Vite step have outranked it throughout. jsdom is now third, behind both. The document
carries the full ranking explicitly in §8 so this is not re-litigated from the table alone. Every
other row was re-checked and confirmed unchanged rather than left standing.

**The `"types": []` recommendation moved from prose into the step that performs it.** §7.2's audit
established that TypeScript 6.0's new `types` default is a no-op for this repo; that finding now
also appears as a checklist item under §6, Step 4 ("Edits this step makes"), alongside the
`package.json` bump and the PR-description note about the 6.0.3 ceiling. A verified no-op is
precisely the edit that gets skipped and later rediscovered as a mystery, and the explicit array
additionally pins the behaviour against TypeScript 7, where the old enumerate-everything default is
gone. §7.2 now points at the step rather than standing alone.

**Plan section affected (third pass):** `docs/upgrades/frontend-toolchain-86.md` only — §6 (step
order, jsdom channel analysis, Step 4 checklist), §7.2/§7.3/§7.4 (cross-references renumbered),
§8 (effort table plus a new explicit risk ranking). Still scoping only: no dependency version,
lockfile, or config file changed, and `docs/ROADMAP.md` still deliberately unedited.

---

**Fourth pass (same date): the jsdom rating's supporting claim was challenged, tested, and
narrowed — the rating survived, the wording did not.** The third pass justified jsdom's *medium*
with *"detection is complete — no failure mode that survives a green run."* The maintainer
challenged exactly the right seam: a green suite catches a query that finds **nothing** or **too
much**, but not a query that resolves to a **different** element while downstream assertions still
pass. That is silent drift, and the counts appeared to leave room for it (116 query call sites
against 79 tests). The claim was **asserted, not argued**, and an unqualified "complete" could not
be supported. It is replaced in §8 by a four-part audit against the suite itself:

- **`getBy*` semantics make most drift loud.** It throws on zero matches *and* on more than one, so
  silent one-to-one drift needs the engine to stop matching A *and* start matching exactly one B in
  the same pass; any widening raises *"found multiple elements"* instead.
- **62 of the 116 sites are discriminated by name, not by selector.** All 34 `getByRole(role,
  {name})` and 28 `getByLabelText(text)` filter candidates by accessible name / label text computed
  in JS; the engine only assembles the pool, so B would need an identical accessible name to A —
  which is the ">1 match" throw condition.
- **85 of the 116 are assertion subjects, categorised rather than estimated** — 74 directly inside
  `expect(...)`, 11 assigned or line-wrapped and then asserted.
- **The single set-valued query is pinned by exact equality.** There is exactly one `*AllBy*` call
  in the suite (`NewScanPage.prefill.test.tsx:54`), and it feeds a helper asserted with `toEqual`
  on the full ordered array — which also pins the suite's only raw selector use
  (`el.closest('[role="option"]')`). No `within(...)` scoping anywhere.

**What the audit could not argue away — ~17 interaction targets** (`user.click(getByRole(…))` and
similar), where the resolved element is acted on rather than asserted on — is **handed to Step 6 as
a checklist item** rather than reasoned about further: wrap `screen`'s query methods in a temporary
`setupFiles` shim that logs each resolved element's `outerHTML`, run before and after the bump, and
diff. That converts the residual from a judgement into a two-run measurement, and the shim is
deleted before the PR opens.

**Two corrections fell out of the same check.** (a) *"79 assertions"* was wrong in both prior
passes: **79 is the test count**; the suite runs **151 `expect` calls**. Quoting the test count as
an assertion count understated assertion density by roughly half, and it was the number the
challenge reasoned from — so the error was this document's, not the challenge's. (b) The channel
table's *"every query bottoms out in `querySelectorAll`"* was true but misleading about how much
the engine can actually move: read from the installed `@testing-library/dom@10.4.1`, `getByText`'s
candidate selector is `'*'` and `getByLabelText`'s are `'label'` / `'label,input'` / `'*'`, so the
engine has no discriminating power there at all. The real exposure is `getByRole`'s
`makeRoleSelector()` plus `node.matches()` against aria-query's element-role selectors — bare tag
names and simple attribute selectors, **not** the complex-selector territory (`:has()`, `:is()`,
`:scope`, nesting) where jsdom's "over 20 selector-related bugs" lived.

**Rating unchanged: jsdom stays medium and stays third.** The audit made the oracle's strength
specific rather than assumed, and every specific came back favourable. Step 7 (Vite 8) keeps the
property that actually separates them — a Lightning CSS regression fails nothing and no checklist
item can turn it into a test.

**Plan section affected (fourth pass):** `docs/upgrades/frontend-toolchain-86.md` only — §6 (the
selector channel row rewritten, the estimate paragraph's claim qualified, a drift-measurement
checklist item added to Step 6) and §8 (the new *"Does a green run actually prove anything?"*
subsection, plus a pointer in the revision note). No estimate, rating, ordering, or sequence
membership changed. Still scoping only; `docs/ROADMAP.md` still deliberately unedited.

---

**Plan section affected:** new file `docs/upgrades/frontend-toolchain-86.md`; this §14 entry
(including the correction to the 2026-08-09 queue-audit entry's characterisation of #153's red
check). `docs/ROADMAP.md` was deliberately **not** edited — three items in it are affected (the #86
sweep's framing, the `react-router` 7→8 grouping, and the GHSA re-cut request) and folding those in
is a maintainer call. No code, schema, API contract, security model, job model, auth, CI behaviour,
or dependency version changed; no locked decision re-opened — React stays on 18 and Mantine on v7,
and the document's §4 is the evidence that nothing in the sweep pressures either.

---

### 2026-08-09 — Docs/Process — PR #169 reversed the attribution-stripping ban hours after it was recorded; the reversal itself went undocumented until now

**What changed:** nothing in this entry — it is a correction to the record, written after the fact
once the conflict it describes was noticed and flagged by the maintainer. The §14 entry below
("Settings audit... attribution-stripping banned") rewrote `CLAUDE.md` § Attribution to ban
instruction-based PR-body footer stripping outright: never write a footer, and if one appears after
the fact, **leave it** — the maintainer removes it by hand at merge. **#169** ("docs: update
Attribution section to require verify-and-strip workflow"), opened and merged the same day at
09:30–09:35 UTC — a few hours after the ban was recorded — replaced that same section with the
opposite instruction: check outgoing text before submitting, and **read the posted PR/comment body
back from the API afterward, stripping and re-verifying if a footer appears.** That is the text
`CLAUDE.md` § Attribution carries today. **#169 has no §14 entry of its own** — grepping the archive
for "#169" or "verify-and-strip" turns up nothing before this entry — so the ban stood as the
written record for the rest of this document's history while the actual policy in `CLAUDE.md` had
already moved back to strip-and-reverify. Three later sessions (**#177**, **#180**) opened and
merged PRs under the reinstated instruction; their current bodies carry no footer and no comment
documents the check running, so nothing here confirms or disputes whether the ban's original
"a PATCH re-appends the footer server-side" finding still reproduces — that empirical question is
untouched by this entry.

**This entry does not relitigate which policy is correct.** `CLAUDE.md` § Attribution's current
text — strip-and-reverify, per #169 — is the standing policy, full stop. What this entry records is
narrower: the ban entry below is **superseded** by #169, and the supersession went unrecorded for
the length of time between #169 merging and this entry, in direct violation of `CLAUDE.md` § Git &
PR conventions' own rule that a deviation is logged in `docs/ARCHIVE.md` "the moment you implement
something differently than the plan specifies" — not as a later cleanup pass. A reader relying on
the archive's §14 index alone, without cross-checking `CLAUDE.md`'s live text, would have gone on
believing stripping was banned indefinitely.

**The gap this closes: a policy PR is not done until its own §14 entry lands in the same PR.**
`CLAUDE.md` § Attribution now says so directly, so a future attribution-policy change can't repeat
this — see `CLAUDE.md` § Attribution for the added line.

**Plan section affected:** `CLAUDE.md` § Attribution (one line added, see above). No code, schema,
API contract, security model, job model, or locked decision affected. This entry does not change
the ban entry's own text below — it stands as written, with this entry marking it superseded rather
than editing it in place, so both the original finding and its reversal remain on the record.

---

### 2026-08-09 — Security/Process — Settings audit: four previously-unreachable toggles verified, Secret Protection enabled, SHA-pinning confirmed clean, attribution-stripping banned

**What changed:** the maintainer manually verified, in the GitHub UI, four settings a code session
cannot read at all — the API paths are blocked from this environment, and no prior §14 entry
covers them. Recorded here as facts, per this document's own rule that a settings change leaves
no artifact in the repository and this section is the only durable record it happened.

**Actions secrets: none.** No repository or environment secrets, no variables. Every workflow —
`ci.yml`, `codeql.yml`, `dev-nightly.yml`, `publish.yml`, `rescan.yml` — runs on the built-in
`GITHUB_TOKEN` alone, matching what each workflow's header comments already claim (locked decision
§6: no Docker Hub, no PAT, no long-lived registry secret anywhere). Worth recording precisely
because it is invisible and can change silently — a secret added later would leave no diff for a
future session to notice, so this is the baseline to compare against.

**Dependabot: alerts on, malware alerts on, grouped security updates on, security updates on;
dependency graph on, automatic dependency submission off.** This is the **confirmed** mechanism
behind `#149` opening against `main` rather than `dev` — `CONTRIBUTING.md` § Dependabot security
updates target `main` and `CLAUDE.md` § Dependency hygiene described the *behavior* from observed
PRs; this is the first direct settings confirmation that the feature producing it is actually
enabled, not merely inferred from one PR's base branch. It is also the same underlying pattern as
the `ignore`-list finding in the entry below: both are repo-level Dependabot configuration that
GitHub resolves from the **default branch**, regardless of what `target-branch` says. `#153` (the
frontend #86-sweep PR) stays open and deliberately unactioned, unaffected by this entry.

**Workflow permissions: "Read repository contents and packages permissions", and "Allow GitHub
Actions to create and approve pull requests" unchecked.** Both hardened — no workflow can write
back to the repository or open its own PRs. Consistent with `CONTRIBUTING.md` § What gets
published, which already notes each publish workflow declares its own job-level `permissions:`
rather than depending on this repo-wide default.

**Code scanning: 0 open / 6 closed on both `branch:main` and `branch:dev`.** This closes the open
disposition item `docs/ROADMAP.md` left after the 2026-08-02 CodeQL entry (six alerts, all
assessed false positives, none formally dismissed pending a written reason). All six are now
closed on both branches — **CLOSED**, no further disposition action needed. `docs/ROADMAP.md`'s
CodeQL item is updated accordingly.

**Actions permissions: "Allow all actions and reusable workflows"; "Require actions to be pinned
to a full-length commit SHA" unchecked.** This was the open question this audit set out to answer:
whether it is safe to check that box. It is. Every `uses:` line across all five workflow files and
the composite `.github/actions/build-image/action.yml` — `actions/checkout`, `actions/setup-python`,
`actions/setup-node`, `docker/setup-buildx-action`, `docker/build-push-action`,
`docker/setup-qemu-action`, `docker/login-action`, `actions/attest-build-provenance`, and
`github/codeql-action/init` + `/analyze` — is already pinned to a full-length commit SHA, each
re-resolved against upstream via `git ls-remote --tags` this session rather than trusted from the
comment. **Zero references need pinning; the setting can be enabled with no workflow changes.**
The one place this bites is `github/codeql-action`, whose tags are annotated (§ The
annotated-tag SHA-pin trap in the project skill / `docs/ARCHIVE.md` §14 2026-08-03): `dev`'s
`codeql.yml` pins `5595ccaf912efad79be6eef63a5619ff05969be3`, which re-resolves to
`refs/tags/v4.37.6^{}` — the correct dereferenced-commit form — while `main`'s copy still pins
`v4.37.4` at `ea14db8afdef5d462e69d78c4ca45002d4522418`. **This is the normal promotion gap, not a
defect** — `dev` moved to v4.37.6 via `#154`, `main` hasn't had a promotion since — and it is
recorded here rather than fixed, per instruction: `main` is never edited outside a release
promotion.

**Secret Protection: disabled → enabled, 2026-08-09.** The maintainer turned this on directly in
Settings on the date of this entry. No prior state is recorded because nothing in the repository
reflects a Settings toggle; this entry is that record.

**BANNED — instruction-based PR-body attribution stripping, closed so no future session
re-attempts it.** `CLAUDE.md` and `CONTRIBUTING.md` previously instructed sessions to re-read a
PR's live body after opening it and strip any auto-appended attribution footer by hand. The
2026-08-09 audit entry below already documented, twice, that a `PATCH` stripping the footer gets
it **re-appended server-side** — verified against the live API, including a payload that itself
carried no footer — so the instruction was not merely unreliable, it was actively producing false
"verified clean" reports from sessions that believed the check had passed. `CLAUDE.md` § Attribution
now states the correct contract directly: never write a footer in the first place; if one appears
after the fact, leave it — it is not yours to remove, and the maintainer removes it by hand at
merge. This supersedes every prior instruction in `CLAUDE.md`/`CONTRIBUTING.md` telling a session
to re-check and strip a live PR body. **Closed, not open** — this is a settled fact about the
environment, not a standing task.

**DECLINED — promoting `.github/dependabot.yml` to `main` outside a release, to close the
ignore-list lag immediately.** The entry below identifies that a `dev`-only `ignore` rule (e.g.
`#147`'s `@types/node` major-ignore) has no effect until a promotion carries the file to `main`,
and names two options: accept the lag, or promote the file to `main` on its own. **The maintainer
declines the second option** — not defers it — on the standing rule that `main` is never edited
outside a deliberate release promotion (`CLAUDE.md` § Git & PR conventions). The lag is an accepted
cost of that rule, not a gap to close with a special-case exception. No review date; do not
re-propose a standalone `main` edit to fix this.

**Plan section affected:** `CLAUDE.md` § Attribution (rewritten), § Definition of done item 8
(rewritten), `.gitignore` (`.pr-body.md` added), `CONTRIBUTING.md` § Releasing (new subsection on
the `ignore`-list promotion lag), `docs/ROADMAP.md` (CodeQL disposition item closed). No SHA
changed on any action reference — the audit found nothing to fix. No schema, API contract, security
model, job model, or locked decision affected.

---

### 2026-08-09 — Infra/Process — Dependabot round closed out: queue merged and closed, bundled scanners bumped, the display-name option declined, prior claims corrected

**What changed:** the round the 2026-08-09 queue-audit entry below opened was finished. Merged
into `dev`, in order, each squash-merged with the base re-confirmed as `dev` and the required
checks (`Backend — lint + tests`, `Frontend — lint + build`, `Image — build + dogfood self-scan`,
plus the three CodeQL contexts) verified green **on the current head after its branch was updated
from `dev`** — never on a run predating a push or base move:

1. **#159** — the audit PR itself (uvicorn 0.52.1, alembic 1.19.1, the audit's §14 entry).
2. **#151** — `debian:bookworm-slim` digest refresh in `docker/Dockerfile`.
3. **#154** — `github/codeql-action` v4.37.6, its SHA re-resolved against upstream before merging:
   `5595ccaf…` is `refs/tags/v4.37.6^{}`, the dereferenced commit — the correct pin form for this
   repo's annotated tags, so Dependabot got the #146 lesson right this time.
4. **#160** — bundled scanners **Trivy 0.72.0 → 0.73.0, Grype 0.115.0 → 0.116.1, Syft 1.46.0 →
   1.50.0** (details below).
5. **#150** — the optional `trivy-server` sidecar 0.72.0 → 0.73.0, taken only after #160 so the
   sidecar never ran ahead of the bundled binary; its proposed digest was verified independently
   against the Docker Hub registry before merging.

**Closed without merging:** **#149** (cryptography 49.0.0 → 50.0.0, the one security update on
`main`) — closed after verifying in `dev`'s diff, not any summary, that #156 (`719f11b`) moved
both `pyproject.toml` and `requirements.lock` to 50.0.0; `main`'s open Dependabot alert (#7)
persists by design until a promotion carries the fix. **#157** — superseded by #159's merge.
**#158** — replaced by #159, below. **#153** stays open, deliberately unactioned: it is the #86
toolchain sweep's reminder surface (`docs/ROADMAP.md` § Track A now says so explicitly).

**#158 → #159: the audit PR was re-opened from a renamed branch.** #158's head branch carried a
tooling-generated `claude/` prefix. Two mechanics corrections for the future: **(a)** GitHub's
squash-commit title is the PR title plus number — a head-branch name never enters the target
branch's history, so the rename was about the PR page's permanent head-ref label, not the squash
title; **(b)** the branch-rename REST endpoint (which updates open PRs' head refs in place) is not
reachable from this execution environment, and neither `git push :ref` nor the git-refs DELETE API
is permitted, so the achievable equivalent was: push the same commit (`8c6815b`) under
`dependabot-queue-audit`, open #159 with an identical body, verify identical diff/base
(4 files, +193/−11, base `dev`), close #158. The stale refs
`claude/dependabot-main-branch-audit-fa8614` and `claude/v0.3.0-release-prep-8w9w4j` could not be
deleted from the session and await manual deletion.

**DECLINED — GitHub profile display name (not deferred; no review date, no resolution trigger).**
The option on the table since the 2026-07-13 squash-merge-authorship entry, asserted done in the
2026-08-02 governance entry, and re-raised as a violation by the audit entry below, was to set the
GitHub profile display name to `tyler-rich` so that web-UI/API merge commits match
session-authored commits. **The maintainer has declined it: the display name stays their real
name.** The authorship invariant that matters is that **no Claude/Anthropic identity appears in
commits or PRs**, and the maintainer's real name satisfies it. The accepted cost is two author
strings for the same person in history — `tyler-rich` on branch commits (repo-local git config,
unchanged and still enforced), the real name on web-UI/API merges, including the v0.3.0 promotion
merge commit — which is cosmetic. Those merge commits are **correct as they stand**: not drift,
not a violation, not something to fix. Consequences for prior records: the 2026-08-02 governance
entry's item 1 ("display name set to `tyler-rich`") does not describe the current state and its
implied obligation is void; the audit entry's "every web-UI merge violates § Git & PR
conventions" framing is superseded (its factual observations stand); `CLAUDE.md` § Git & PR
conventions and `docs/ROADMAP.md` were rewritten this round to record the decision so no future
session re-raises it.

**#160 — the bundled-scanner bump, and what "in lockstep" turned out to include.** Each target
version was confirmed current by resolving upstream tags (`git ls-remote`); release notes for
every release crossed document no breaking, deprecation, or CLI change, and Syft's JSON schema
moves only at patch level (`internal/constants.go`: 16.1.5 → 16.1.10 between the two tags), so
JSON parsing and persisted SBOMs are unaffected. Beyond the three `ARG`s: the `ci.yml` and
`rescan.yml` `aquasec/trivy` / `anchore/grype` scan-image pins are documented in-file as "pinned
to the version Scrye bundles" and moved with fresh registry-resolved digests (the old tags were
re-resolved first and matched the committed pins — methodology check); `THIRD_PARTY_LICENSES/`
was re-verified **fresh** per Apache-2.0 §4 — every `LICENSE` (and Trivy's `NOTICE`) fetched at
the new tags and `cmp`'d byte-identical, Grype/Syft still 404 on `NOTICE` — so only its version
table moved; README's Integrations versions and a CHANGELOG entry. The #135 symlink-containment
guard was re-run locally against the real downloaded syft 1.50.0 / grype 0.116.1 on CPython
3.14.6 (7 passed) before CI repeated it against the binaries the image ships.

**Verified and found already correct — no change made (recorded so the verification itself is on
the record):**

- **The alembic timing claim in #159's CHANGELOG entry.** Checked against PyPI's release index:
  1.19.0 published 2026-08-04T18:57Z, 1.19.1 published 2026-08-08T16:32Z, #157 opened
  2026-08-08T09:15Z — so "1.19.1 was published after #157 opened", about seven hours after, is
  accurate as written. A review reading had conflated 1.19.0's date with 1.19.1's ("four days
  apart" describes the two *releases*, not 1.19.1 versus #157). Nothing corrected.
- **The `ignore`-list-read-from-`main` finding in the audit entry below.** Re-verified on all
  three legs: `origin/dev:.github/dependabot.yml` carries the `@types/node` major-ignore (#147),
  `origin/main`'s copy does not, and #153 proposes `@types/node` 26.1.2 regardless. Accurate. The
  available fixes both touch `main` — wait for the next promotion to carry `dev`'s config (cost:
  ignored majors keep resurfacing in grouped PRs until then), or promote `.github/dependabot.yml`
  on its own outside a release (cost: a commit on `main` outside the release discipline, plus the
  back-merge). **Deliberately left as is** — both options are maintainer calls on `main`.

**Governance re-verification against the live API (2026-08-09).** GHCR package public (anonymous
manifest pull of `:latest` succeeds); private vulnerability reporting `{"enabled": true}`; all
three rulesets `active`. Two changes were found done that no §14 entry records being made — the
CodeQL migration's two settings edits: default setup is off (the committed workflow's checks run
and pass on `dev` PRs, impossible while it is enabled) and the three CodeQL contexts are in
`required_status_checks` on **both** `protect-dev` and `protect-main` (live ruleset read:
`protect-dev` requires Backend/Frontend/Image-dogfood + CodeQL×3 with strict up-to-date;
`protect-main` requires Backend/Frontend + CodeQL×3). When they were made is not recorded
anywhere — the same invisible-settings-change failure mode this checklist exists for, this time in
the happy direction. `docs/ROADMAP.md`'s CodeQL item was rewritten accordingly (open work is
alert disposition only). Not re-verifiable at this session's API permission level: the Actions
secrets, Dependabot alert toggles, workflow permissions (proxy-blocked paths), and CodeQL alert
states — their prior Settings verifications stand as the record.

**The sandbox-interpreter question, settled by installation rather than inference.** This
sandbox's system interpreters are 3.10–3.13 (default 3.11.15), and its preinstalled `uv 0.8.17`
resolves `3.14` to 3.14.0rc2 only — matching the 2026-08-03 and audit-entry reports. But a
**current uv (0.12.3) installs `cpython-3.14.6` from python-build-standalone in seconds**, so "no
3.14 here" is a statement about the tooling version, not the sandbox. On the real 3.14.6 the full
backend suite runs **728 passed / 11 skipped / 0 failed**. `test_undeterminable_presence_fails_startup`
was then re-reproduced on 3.13.12 and fails exactly as the 2026-08-03 entry records — the
monkeypatched `crypto.os.stat` intercepts the test's own `assert not autogen.exists()` via
`pathlib/_local.py`'s `os.stat()` call and raises the planted `PermissionError` — confirming the
diagnosis by reproduction rather than by matching the failure to the entry by name. Local runs on
an installed 3.14.6 are therefore valid evidence in this environment; upgrade uv first.

**Environment caveat, extending the 2026-08-02 issue-body observation: this environment's GitHub
ingress appends an attribution footer to every issue-comment and PR-body write, and a PATCH that
strips it gets the footer re-appended to the PATCHed body server-side** — verified twice against
the live API, including a direct authenticated PATCH whose payload contained no footer. Strips do
not stick; the footer (without session link — a PATCH does at least downgrade the session-link
variant to the generic one) remains on #149's and #150's closure/decision comments and #159's and
#160's bodies, and needs hand-cleanup in the web UI, as #135–#137 did. Merge-API squash commit
messages are **not** affected — every squash commit landed this round was re-read from `dev` and
carries no footer.

**Plan section affected:** `docker/Dockerfile`, `.github/workflows/ci.yml` + `rescan.yml`,
`THIRD_PARTY_LICENSES/README.md`, `README.md`, `CHANGELOG.md` (#160); `docker/docker-compose.yml`
(#150); `backend/pyproject.toml` + `requirements.lock` (#159); `CLAUDE.md` § Git & PR conventions
and `docs/ROADMAP.md` (display-name decision, CodeQL item, governance list, #86/#153 note). No
schema, API contract, security model, job model, or auth change; no locked decision re-opened.

---

### 2026-08-09 — Infra/Process — Open-Dependabot-queue audit: only #149 was on `main`, and it was already superseded; `.github/dependabot.yml`'s `ignore` list is read from `main`, so `dev`-only edits to it are inert

**What changed:** the whole open Dependabot queue (**#149, #150, #151, #153, #154, #157**) was
audited against the base-branch rules in `CLAUDE.md` § Dependency hygiene and `CONTRIBUTING.md`
§ Dependabot security updates target `main`. One PR's content — the mergeable half of **#157** —
was reapplied by hand (`uvicorn` 0.52.0 → **0.52.1**, `alembic` 1.18.5 → **1.19.1**, with
`backend/requirements.lock` regenerated by the pinned `uv 0.8.17`). Everything else was left in
place with a recorded decision; no PR was merged or closed in this pass. This entry is the durable
record of the four decisions that leave no diff.

**`main` is an ancestor of `dev`, and the branches have not diverged.**
`git merge-base --is-ancestor origin/main origin/dev` succeeds and
`git rev-list --left-right --count origin/main...origin/dev` returns **0 4** — nothing is on `main`
and absent from `dev`. `main` is at `a43b2eb` (the v0.3.0 promotion merge); `dev` carries four
commits on top of it (#147, #156, #148, #155). So the reconciliation debt that made **#110/#119**
painful on 2026-07-31 is not present, and the pre-promotion check in `CONTRIBUTING.md`
§ Promoting `dev` to `main` would pass today.

**The queue's base branches are correct — only #149 sits on `main`, and by design.** The premise
this audit started from (that the whole queue had been opened against `main`) did not hold:
**#150, #151, #153, #154 and #157 are all based on `dev`**, and every one of their head branches
carries the `/dev/` `target-branch` segment, which is the first signal in `CONTRIBUTING.md`'s
two-signal table. **#149** is the single exception, and it is a **security** update
(`dependabot/pip/backend/pip-18c674f953` — no `/dev/` segment; its body carries the
*"disable automated security fix PRs"* line only security PRs get), so `main` is where GitHub is
documented to put it. Nothing was retargeted: retargeting is explicitly not an option for a
security PR, and the five `dev`-based PRs had nothing to retarget.

**#149 — cryptography 49.0.0 → 50.0.0. Already superseded; recommended for closure, held pending
the maintainer.** The bump it carries landed on `dev` on 2026-08-08 as **#156** (`719f11b`) — the
documented response **(b)**, close-and-reapply-on-`dev`. `dev`'s `pyproject.toml` and
`requirements.lock` both read `cryptography==50.0.0` today, so merging #149 into `main` would add
nothing `dev` lacks while putting a commit on `main` outside a release. Its CI is red for the
reason every Dependabot pip PR is red here: it edits `pyproject.toml` only and leaves the lock
stale, so `Backend — lint + tests` fails the drift gate. **Not closed in this session** — a
cryptography bump is on the crypto/secrets code path, and that is a maintainer decision.

**#157 — uvicorn + alembic. Content reapplied here; the PR itself is superseded.** Dependabot
cannot produce a mergeable pip PR in this repo (`Backend — lint + tests` fails on lock drift;
everything else on #157 is green, including the dogfood gate, because #157 is the one queue member
based on `719f11b` and therefore already carries the cryptography fix). Two things were checked
rather than taken from the PR:
- **uvicorn 0.52.1** (2026-08-01) is four WebSocket-only fixes. `grep` over `backend/app/` and
  `frontend/src/` finds no WebSocket route and no `new WebSocket` — none of it is reachable in
  Scrye. Pure currency.
- **alembic 1.19.1 was taken instead of the 1.19.0 the PR proposes.** 1.19.0 (2026-08-04) added
  named-CHECK-constraint autogenerate detection; **1.19.1 (2026-08-08) fixes a defect in exactly
  that new feature**, and was published *after* #157 opened at 09:15 UTC that morning, so the PR
  was one patch stale before it was read. Verified against the PyPI release index and upstream's
  changelog, not the PR description. Both changes are confined to migration *authoring*; no shipped
  migration or runtime path moves. The lock diff is those two packages and their hashes — no
  transitive churn, `uv`'s preference set holding as in #147.

**#151 (debian digest) and #154 (codeql-action v4.37.4 → v4.37.6) are clean, and their red CI is
their base, not their content.** Both are based on `004d2b5`, which predates #156, so
`Image — build + dogfood self-scan` fails on `cryptography 49.0.0 / CVE-2026-69247 / HIGH / fixed`
— confirmed by reading #150's gate log, which prints that exact row. Updating each branch from
`dev` clears it and re-triggers CI as a `synchronize`, which is also what § Git & PR conventions
requires before a check may be treated as current. #154's pin was re-resolved upstream rather than
trusted: `git ls-remote --tags https://github.com/github/codeql-action` gives
`9e3211c9…  refs/tags/v4.37.6` and `5595ccaf…  refs/tags/v4.37.6^{}`, and **5595ccaf is what the PR
pins** — the dereferenced commit, i.e. the shape #146 corrected on 2026-08-03, held this time. This
is a real version bump (4.37.4 → 4.37.6), unlike #146.

**#150 — trivy sidecar 0.72.0 → 0.73.0. Deferred: it would desync the sidecar from the bundled
binary.** `docker/docker-compose.yml`'s optional `trivy-server` image is the *only* Trivy version
Dependabot can see. The Trivy that actually performs every scan is pinned as
`ARG TRIVY_VERSION=0.72.0` in `docker/Dockerfile` — a build arg, not a `FROM`, so **no Dependabot
ecosystem tracks it**, and the same is true of `GRYPE_VERSION` and `SYFT_VERSION`. Merging #150
alone would ship a 0.73.0 server against a 0.72.0 client. Whether Trivy hard-fails or merely warns
on a client/server version mismatch **could not be verified from this sandbox** (`trivy.dev` is
egress-blocked and the docs path in the repo 404s), so the recommendation rests on consistency
rather than a proven break — but the conservative move is to bump both in one PR either way.
0.73.0 itself is feature/bugfix only, **no CVE fixes**, read from upstream's `CHANGELOG.md`.

**The bundled scanner binaries are stale and nothing is watching them.** Resolved against upstream
tags during this audit: **trivy 0.72.0 → 0.73.0**, **grype 0.115.0 → 0.116.1**, **syft 1.46.0 →
1.50.0**. #150's own gate log makes the first one self-evident — Trivy prints
*"Version 0.73.0 of Trivy is now available, current version is 0.72.0"* from inside the image CI
just built. `docs/ROADMAP.md` § Known limitations already states that keeping these pins current is
how CVEs in the scanners' own Go modules get addressed; what was not written down is that the
mechanism for noticing is **entirely manual**. Worth its own PR.

**#153 — the frontend group. Reported, not actioned: it is the #86 sweep.** Its thirteen updates
are the same set §14 (2026-08-03) held back from **#145**, at the same targets — `typescript`
5.7.2 → **7.0.2**, `eslint` 9.39.4 → 10.8.0, `@eslint/js` → 10.0.1, `typescript-eslint` → 8.66.0,
`vite` 6.4.3 → **8.2.0**, `@vitejs/plugin-react` → 6.0.5, `vitest` 3.2.7 → **4.1.10**, `jsdom`
26.1.0 → **30.0.1**, `eslint-plugin-react-hooks` 5.1.0 → **7.1.1**,
`eslint-plugin-react-refresh` → 0.5.3 — plus `@types/node` 24.13.3 → 26.1.2 and two innocuous
bumps (`@testing-library/user-event` 14.6.3, `globals` 17.9.0). `docs/ROADMAP.md` § Track A tracks
this as **"Frontend tooling majors from Dependabot #86"** and says it wants a single deliberate PR.
`Frontend — lint + build` is **red** on the PR, which is the type-aware-ESLint churn that roadmap
item predicts, arriving on schedule. The two innocuous bumps cannot be split out without rewriting
the branch, so the group stays whole. Nothing locked by decision §2 is in it: no `@mantine/*`,
`react`, `react-dom` or `@types/react*` major appears — those ignores are on `main` and working.

**The finding worth keeping: `dependabot.yml`'s `ignore` list is read from the *default* branch.**
#153 proposes `@types/node` **26.1.2** even though `.github/dependabot.yml` on `dev` carries
`- dependency-name: "@types/node"` / `update-types: ["version-update:semver-major"]`, added by
**#147** on 2026-08-03 — and #153 was cut on 2026-08-07 from `004d2b5`, which *is* #147, so the
rule was in the tree the PR branched from. It still had no effect, because
**Dependabot reads its configuration from the repository's default branch (`main`), not from
`target-branch`**. `git show origin/main:.github/dependabot.yml` has no `@types/node` stanza at
all: #147 never reached `main`, and will not until the next promotion.

This generalises, and it is the sharp edge. **Every `ignore` rule added on `dev` is inert until a
promotion carries it to `main`**, while the `target-branch: dev` keys around it keep working
normally — because those are read from the same `main` copy, where they have been since before the
gap opened. So the config *looks* effective and partly is. The Mantine/React ignores work only
because they predate `main`'s last promotion. Practical consequences:
- A newly added `ignore` will be **silently ignored** for as long as it takes to cut a release.
  Do not read a re-proposed bump as Dependabot misbehaving; check `main`'s copy of the file first.
- This is a **third** distinct cause of surprising Dependabot behaviour in this repo, alongside
  security-updates-target-`main` (2026-07-31) and retarget-on-branch-deletion (2026-08-02). It is
  a *config-visibility* lag, not a base-branch problem, and none of the existing signals detect it.
- It is not fixable by configuration. The options are to accept the lag, or to promote
  `.github/dependabot.yml` changes to `main` on their own when a rule needs to bite immediately.
  No change is made here — this is a maintainer decision, recorded so the next re-proposal is not
  re-diagnosed from scratch.

**Unrelated finding, surfaced by the same verification pass: the GitHub profile display name is
still `Tyler Richardson`, so every web-UI merge violates § Git & PR conventions.** Updating #151's
and #154's branches from `dev` produced merge commits authored `Tyler Richardson
<170156756+tyler-rich@users.noreply.github.com>`, which prompted checking the rest of the history.
**Every** commit created through the GitHub web UI carries that name — `a43b2eb` (the v0.3.0
promotion merge), `004d2b5` (#147), `719f11b` (#156), `e5aa6ea` (#148), `984bfa5` (#155),
`0463ce7` (#142), `fb6864c` (#141) — while every commit pushed from a session over local `git`
correctly carries `tyler-rich` (`1b1f24a`, `f3fc929`, `cb3c350`). The split is exactly the one
§ Git & PR conventions predicts: *"GitHub authors a squash-merge commit — and the merge commit a
promotion produces — as the merging account's profile display name, which the repo-local
`git config user.name` cannot override."*

This is **not** something a code session can fix, and it is not new — `a43b2eb` predates this
audit by six days. It is noted because `docs/ROADMAP.md` § Finish the public-repo governance setup
lists the profile display name among the five items *"verified in GitHub Settings on 2026-08-02"*,
and the commits above show it was not actually changed (or was changed back). The fix is a
one-field edit at <https://github.com/settings/profile> — set **Name** to `tyler-rich` — after
which future merges comply; commits already written keep the old name and are not worth rewriting.
Flagged rather than resolved, and `docs/ROADMAP.md` deliberately left unedited.

**Verification notes.** Every version claim above was checked at its source rather than taken from
a PR description, per § Dependency hygiene's rule about scanner and advisory metadata being
evidence rather than proof: PyPI's release index for `alembic`/`uvicorn` (which also disproved a
first-pass reading that 1.19.0 did not exist — it does, published 2026-08-04), upstream changelogs
for uvicorn 0.52.1, alembic 1.19.0/1.19.1 and trivy 0.73.0, `git ls-remote` for the
`codeql-action`, `grype`, `syft` and `trivy` tags, and the PR check-run logs for every red gate
rather than inferring the cause from the job name.

**Plan section affected:** `backend/pyproject.toml`, `backend/requirements.lock`, `CHANGELOG.md`
(`[Unreleased]` § Changed). No locked decision changed; no code, schema, API contract, security
model, job model, auth, or CI-behaviour change. `docs/ROADMAP.md` was deliberately **not** edited —
the #86 match above is reported for the maintainer to fold in.

---

### 2026-08-08 — Docs/Process — `docs/ROADMAP.md` replaced wholesale with an externally-drafted two-track revision (Track A carried forward verbatim, Track B added)

**What changed:** `docs/ROADMAP.md` was **replaced in full** with a revision the maintainer drafted
outside this session and approved. The document is now split into two tracks. **Track A —
Engineering & hardening** is the entire previous roadmap (Near-term / Medium-term / Longer-term ·
speculative), carried across **verbatim**. **Track B — Features** is new: six phases (prioritization
& enrichment, triage & decisions, reporting & visibility, AI assist & MCP, continuous scanning &
supply chain, ecosystem & team workflow), followed by a **Deferred** list of candidate engines, an
**Out of scope (policy)** list, a **Licensing & bundling policy** table, and five **Guiding
principles**. A short *"Where Scrye is heading"* preamble (Decide / Watch / Corroborate /
Interoperate) and a rewritten front-matter blockquote frame the two tracks. **Known limitations &
accepted trade-offs** is carried across unchanged and still closes the document. No code, schema,
API contract, security model, job model, auth, or CI behavior is affected, and no locked decision
changed.

**The only edits to Track A's substance are three `†` prerequisite markers**, added where a Track A
item now gates a Track B feature: *Content-addressed SBOM target identity* (Phase 2 fix-watch),
*Cancel a running scan* (heavier engines and any future endpoint-scanning target class, i.e. the
deferred Nuclei entry), and *Generated API client* (the Phase 4 MCP server). Each `†` is matched by
a reciprocal pointer on the Track B side, so the dependency reads in both directions.

**Verified before replacing, not after.** Track A and Known limitations were diffed against the
outgoing file line by line under whitespace/line-wrap normalization; every open item, every
struck-through Done/Declined entry, every §14 pointer, and every standing warning — *"do not
re-argue it as a security fix"*, *"the evidence is already gathered; do not re-derive it"*, *"do not
re-scope from the original wording"*, the admin-bypass caveat, and the CodeQL disable-order and
required-context hazards — survives with its wording intact. Each §14 pointer was then checked
against the entry it names rather than against its presence in the old file: the `react-router`
tarball comparison (2026-08-03 v0.3.0 release prep), the `protect-dev` ruleset readout and
`bypass_actors: null` note (2026-08-02), the five-of-eight governance verification (2026-08-02), the
#136/#137/signed-commit entries (2026-08-03), and the two CodeQL entries (2026-08-02) all match.
`#123`, `#136` and `#137` were confirmed **closed** via the API; `./ARCHIVE.md` and `../README.md`
still resolve from `docs/`, and nothing outside this file links into a ROADMAP section anchor.

**One regression was caught and corrected rather than absorbed.** The draft's *Frontend tooling
majors from Dependabot #86* paragraph was the **pre-#147** version of that item — the draft was
written against `docs/ROADMAP.md` at `cb3c350`, and `004d2b5` (#147, 2026-08-03) rewrote the
paragraph afterwards. Taking the draft as written would have reverted the #145 shopping-list
refresh, dropped four toolchain members (`@eslint/js`, `@vitejs/plugin-react`,
`eslint-plugin-react-hooks`, `eslint-plugin-react-refresh`), reverted **jsdom 26 → 30** to the stale
`26 → 29`, and removed the closing sentence recording that these are **deliberately not** in
`.github/dependabot.yml`'s `ignore` list. That sentence is one half of a two-way reference —
`.github/dependabot.yml` carries the matching *"Deliberately NOT ignored … tracked in
docs/ROADMAP.md"* comment — so dropping it would have left the config pointing at a claim the
roadmap no longer made. The current paragraph was spliced in verbatim (re-wrapped to the new file's
column width, wording untouched) after the maintainer was asked; nothing else in the draft was
altered.

**One deletion is recorded rather than restored.** The outgoing preamble's sentence *"Scrye's
repository is now **public**, so items that were previously blocked on that (free CI runners,
fork-based contribution safety) are unblocked"* is not in the new front matter, which was
deliberately rewritten for the two-track structure. Its load-bearing half survives in place — the
*Native arm64 CI runners* item still states that public-repo arm64 runners are free and that the
cost concern is gone.

**Track B was checked against the locked decisions rather than assumed compatible.** Phase 5's
running-fleet drift goes *"via the existing read-only Docker socket proxy"* (locked decision §4 —
the app still never mounts `/var/run/docker.sock`); arq/Redis and SQLCipher stay where they are, in
Track A's longer-term section, so §3 and §5 are untouched; the licensing table's
subprocess-boundary rule is the same one CLAUDE.md § Scanner faithfulness and § Third-party license
attribution already state; and the MCP server is specified as authenticated, read-only at launch,
audit-logged, and disabled by default, reusing the existing API-token/RBAC model. One factual claim
was spot-checked at the source: Phase 3 offers ntfy and Gotify *"alongside the existing webhook,
Discord, SMTP, and Matrix channels"*, and `backend/app/db/models/notification.py:27-30` defines
exactly those four.

**Why:** the roadmap had accumulated a full engineering backlog and no statement of product
direction, so a reader could see every open chore and still not know what Scrye is trying to
become. The two-track split keeps the backlog exactly as it was — it is the part with dated
evidence behind it and the part sessions actually work from — while giving the feature direction
somewhere to live that is explicitly labelled as direction, not commitment. Replacing wholesale
rather than editing in place is what made the fidelity check tractable: a superset claim can be
verified by diff, whereas an incremental rewrite of the same size could not.

**Plan section affected:** `docs/ROADMAP.md` in full (Track A/Track B restructure; Track A and
Known limitations carried forward verbatim apart from the three `†` markers). §14 (this record).
No locked decision changed; no other file touched. Landed via
[#155](https://github.com/tyler-rich/Scrye/pull/155).

---

### 2026-08-08 — Security/Infra — `cryptography` bumped 49.0.0 → 50.0.0 for CVE-2026-69247; the dogfood gate caught it on an unrelated PR

**What changed:** `cryptography` moved **49.0.0 → 50.0.0** in `backend/pyproject.toml`, with
`backend/requirements.lock` regenerated by the pinned `uv 0.8.17` command from `CONTRIBUTING.md`
§ Backend dependency lock. The lock diff is that single package and its hashes — no transitive
churn, which is `uv`'s documented preference-set behaviour holding. No code change: nothing in
`backend/app/` needed touching. Recorded in `CHANGELOG.md` under `[Unreleased]` § Security.

**Why:** **CVE-2026-69247** (HIGH) — a Bleichenbacher-style oracle in the PKCS7 decryption
helpers. `pkcs7_decrypt_der` and its variants exposed distinguishable errors and timing while
unwrapping an encrypted key; upstream's fix substitutes a random key on failure, per RFC 3218.

**Verified at the source, not from the scanner's `FIXED IN` column.** This is the rule
`CLAUDE.md` § Interpreter CVEs earned the hard way on the 3.13 → 3.14 bump, and it applies to a
library bump argued on security grounds just as much as to an interpreter one. pyca/cryptography's
own `CHANGELOG.rst` records the PKCS7 fix under **50.0.0 (2026-07-31)** and names CVE-2026-69247
there; **49.0.0 (2026-06-12)** predates it. So the bump does clear the finding, and the claim rests
on upstream's changelog rather than on Trivy's metadata agreeing with itself.

**Scrye was never exposed, and that is not the reason to take the bump.** The library is used for
exactly four symbols, all in `backend/app/core/crypto.py` — `AESGCM`, `HKDF`, `hashes` and
`InvalidTag` — and PKCS7 is never called, so the vulnerable path is unreachable. The bump is taken
because the finding is **fixable**, which is what the dogfood gate keys on per `CLAUDE.md`
§ Dependency hygiene ("gates on fixable HIGH/CRITICAL findings … only genuinely unfixable
upstream/OS-level items may remain"). Unreachability is a reason not to panic, not a reason to
waive: a waiver is for findings with no fix, and this one has a fix one patch away. Contrast the
`react-router` GHSA-qwww-vcr4-c8h2 case (§14, 2026-08-02), which was *also* unreachable but where
the only offered fix was a major — there the reachability assessment carried the decision, because
the cost side was real.

**A major, and the breaking changes miss Scrye's surface.** 50.0.0 deprecates finite-field
Diffie-Hellman, stabilises the X.509 verification APIs, and tightens SCT-list and X.509 structure
validation — none of which Scrye touches. The ChaCha20 block-counter change that would have been
the sharp edge landed in **49.0.0** and was absorbed then. The four APIs in use were exercised
directly against 50.0.0 before the bump was proposed, including an AES-GCM round trip under a
row-bound AAD and the `InvalidTag` raise on an AAD mismatch — the behaviour `secret_store.py`'s
`row_aad()` binding depends on (L1/SEC-7, #64). Both held.

**How it surfaced, which is the part worth keeping.** Nothing proposed this bump — no Dependabot
PR, no release check. `Image — build + dogfood self-scan` went red on a **docs-only** pull request
(the ROADMAP replacement, #155) whose diff touched two files under `docs/`. The gate downloads a
fresh Trivy DB on every run, so a newly-published advisory against a pinned dependency reddens the
next PR to run regardless of what that PR changed; `dev`'s own last green run simply predated the
advisory. Two things follow. First, this is the dogfood gate doing exactly the job
`CLAUDE.md` § Dependency hygiene describes, and the second time it has caught a real finding
nobody went looking for (after CVE-2026-5773, §14 2026-07-13) — which is the concrete argument
behind making it a required check in #136. Second, since #136 landed it *is* required on
`protect-dev`, so an advisory published against any pinned dependency now blocks **every** open PR
until it is cleared. That is the intended behaviour, but it means an unrelated PR can be held by a
dependency finding, and the fix belongs in its own PR rather than folded into whatever change
happened to run first.

**Plan section affected:** `backend/pyproject.toml`, `backend/requirements.lock`, `CHANGELOG.md`
(`[Unreleased]` § Security). No locked decision changed; no code, schema, API contract, security
model, job model, auth, or CI-behaviour change.

---

### 2026-08-03 — Infra/Process — Post-v0.3.0 Dependabot triage: three grouped PRs reapplied on `dev`, an annotated-tag SHA-pin corrected, eight toolchain majors held back

**What changed:** the three Dependabot group PRs opened against `dev` after the v0.3.0 release —
**#144** (pip), **#145** (npm), **#146** (github-actions) — were triaged and their content
reapplied by hand in one PR rather than merged as-built. None was merged directly.

**Base branches checked first, and all three were correct.** Per § Dependency hygiene's two-signal
test: every head branch carries the `/dev/` `target-branch` segment
(`dependabot/pip/backend/dev/…`, `dependabot/npm_and_yarn/frontend/dev/…`,
`dependabot/github_actions/dev/…`) and no timeline carries `automatic_base_change_succeeded`. So
these are **version** updates routed as configured — neither the security-update-on-`main` case
(#120) nor the auto-retarget case (#126/#127/#128) applies. Nothing needed to be closed for
routing reasons.

---

**#144 — backend (pip). Applied in full, with the lockfile regenerated.**

Three bumps: `fastapi` 0.140.13 → **0.141.1**, `uvicorn[standard]` 0.51.0 → **0.52.0** (both
runtime), and `ruff` 0.16.0 → **0.16.1** (dev extra). Changelogs were read for both runtime deps,
since both move more than a patch:

- **FastAPI 0.141.x** adds `app.frontend(check_dir="auto")`, a `fastapi dev` convenience, plus a
  0.141.1 fix for background tasks/headers in that same new code path. No breaking changes and
  nothing touching routing, dependency injection, or response-model handling. Scrye does not call
  `app.frontend()` — the SPA is served by the existing static-files mount — so the added surface
  is unused.
- **uvicorn 0.52.0** adds an **experimental, opt-in** HTTP/1.1 parser (`--http zttp`, a sans-IO
  parser with Zig bindings) that upstream explicitly marks not-for-production, and fixes non-ASCII
  WebSocket request headers under websockets 17.0. Default parser selection is unchanged, and
  `docker/entrypoint.sh` passes no `--http` flag — verified, not assumed — so the default
  (`auto` → httptools) is what the image keeps running. No behavior change for Scrye.

`backend/requirements.lock` was regenerated with the pinned command from `CONTRIBUTING.md`
§ Backend dependency lock (`uv pip compile pyproject.toml --group build --generate-hashes
--python-version 3.14`, uv **0.8.17** — the same pin `ci.yml` installs). The resulting diff is
exactly two packages and their hashes; `starlette` held at **1.3.1**, which independently confirms
FastAPI 0.141.1 still accepts the pin carried for CVE-2025-62727 / CVE-2026-48818 /
CVE-2026-54283. **This is the step Dependabot cannot do** — it edits `pyproject.toml` only, so its
branch would have failed CI's lock-drift gate.

One thing Dependabot left stale and was fixed by hand: the comment above the `uvicorn` pin still
read *"0.51.0 is the current release."* Dependabot rewrites version strings, not the prose that
justifies them.

---

**#146 — github-actions. Not a version bump at all: it corrects an annotated-tag SHA-pin.**

The PR moves `github/codeql-action/init` and `.../analyze` from
`ea14db8afdef5d462e69d78c4ca45002d4522418` to `f205ea1c3313d32999d8d6a48b4f6530d4437b38` while
leaving the trailing comment at `# v4.37.4` — which reads like a bot error and is not. Resolving
the tag against upstream rather than trusting the bump description
(`git ls-remote --tags https://github.com/github/codeql-action`) shows both SHAs belong to the
**same release**:

```
ea14db8afdef5d462e69d78c4ca45002d4522418  refs/tags/v4.37.4
f205ea1c3313d32999d8d6a48b4f6530d4437b38  refs/tags/v4.37.4^{}
```

`codeql-action` publishes **annotated** tags, so `refs/tags/v4.37.4` is a *tag object* and
`refs/tags/v4.37.4^{}` is the commit it dereferences to. The advanced-setup migration
(#141, 2026-08-02) pinned the tag object; Dependabot is re-pinning to the commit. The two refs
name the same tree, so the content delta is **empty** — Dependabot's own "compare view" link spans
no commits.

**Consequences, stated precisely so this is not over- or under-sold:**
- **It did not fix an outage.** Actions dereferences a tag object fine, and the CodeQL workflow
  has been green on the old pin since #141 landed. This is pin *hygiene* — a SHA-pin is supposed
  to name an immutable commit, which is what the convention in § Git & PR conventions means and
  what every other pin in this repo does.
- **It changes nothing about code scanning.** Same release ⇒ same CodeQL bundle (2.26.2) and the
  same `queries: security-extended` suite. No query-suite or bundle-resolution change, despite
  `codeql-action` having joined this group only with the advanced-setup migration.
- **`codeql.yml` is not on the tag-gated publish path**, and nothing on that path moved. It runs
  on `push`/`pull_request` for `main` and `dev`, so this PR's own CI exercises the corrected pin
  directly. The publish-path actions (`checkout`, `login-action`, `attest-build-provenance`, and
  the `build-image` composite's `setup-qemu`/`setup-buildx`/`build-push`) were untouched by #146,
  so there is no CI-unexercisable change to reason about this round.

**Why only this one action was affected:** every other action pinned here — `actions/checkout`,
`actions/setup-python`, `actions/setup-node`, `actions/attest-build-provenance`,
`docker/login-action`, `docker/setup-buildx-action`, `docker/setup-qemu-action`,
`docker/build-push-action` — publishes **lightweight** tags, where `refs/tags/vX` *is* the commit
and there is no `^{}` to get wrong. All eight were re-resolved against their upstreams during this
triage and all eight already name commits. So this was a single-repo trap, not a systemic
mis-pinning, and it is not detectable by eyeballing the pins — only by dereferencing them.

---

**#145 — frontend (npm). 20 proposals: 8 applied, 1 narrowed, 11 held back.**

The Mantine/React ignores added 2026-07-26 did their job — the PR proposed **no** `@mantine/*`,
`react`, `react-dom`, or `@types/react*` major, so nothing in it was blocked by locked
decision §2. `@mantine/*` moved 7.15.2 → **7.17.8**, a minor *inside* v7, which is exactly what
those ignores were scoped to allow.

**Applied (8):** `@mantine/core`/`form`/`hooks` 7.17.8, `@tabler/icons-react` 3.46.0,
`@testing-library/react` 16.3.2, `postcss-preset-mantine` 1.18.0, `prettier` 3.9.6,
`globals` 17.8.0, `@testing-library/jest-dom` 7.0.0.

Two of those are majors and were checked rather than waved through:
- **`@testing-library/jest-dom` 6 → 7** breaks in exactly two ways: `@testing-library/dom` becomes
  a required *peer* (already a direct devDependency here at 10.4.1, so satisfied), and the Node
  floor moves to 22 (the builder and `ci.yml` are on 24). No matchers were removed — 7.0.0 only
  *adds* `toContainAnyBy*`/`toContainOneBy*`. All 79 tests pass.
- **`globals` 15 → 17** feeds `eslint.config.js`'s `globals.browser`. A globals major can silently
  *shrink* a set, which would leave lint passing while losing coverage, so the set was inspected
  rather than inferred from a green run: 1191 browser globals, `window`/`document`/`fetch` all
  present.

**`prettier` 3.4.2 → 3.9.6 reformats three source files** — `src/api/scans.ts`,
`src/api/targets.ts`, `src/pages/Dashboard.tsx`. Prettier 3.9 collapses short union types onto one
line instead of the leading-`|` multiline form. It is mechanical whitespace, 17 lines, no semantic
change, and it is simply what taking the bump means; the files are reformatted in this PR so
`format:check` stays the gate rather than being pinned to a stale formatter.

**Narrowed (1): `@types/node` 22.20.0 → proposed 26.1.2, applied 24.13.3.** `@types/node`'s major
tracks Node's, and this repo builds and runs on **Node 24** — the Dockerfile builder stage and
`ci.yml`'s `node-version` — with Node majors already declined for the `docker` ecosystem on a
support-lifecycle argument (24 is Active LTS to 2028-04-30; 26 does not enter LTS until
2026-10-28). `tsconfig.node.json` sets `"types": ["node"]`, so types ahead of the pinned runtime
describe APIs the build does not have and feed them straight into the type-aware ESLint gate
turned on 2026-07-24 — the same failure mode that put `@types/react*` in the ignore list. 24.13.3
is the current 24 line, aligns the types *with* the runtime (22 was behind it), and lints and
builds clean.

**Held back (11) — the deferred #86 toolchain sweep, unchanged in character since 2026-07-26:**
`typescript` 5.7.2 → 7.0.2, `eslint` 9.39.4 → 10.8.0, `@eslint/js` 9.39.4 → 10.0.1,
`typescript-eslint` 8.19.0 → 8.65.0, `vite` 6.4.3 → 8.2.0, `@vitejs/plugin-react` 4.3.4 → 6.0.5,
`vitest` 3.2.7 → 4.1.10, `jsdom` 26.1.0 → 30.0.1, `eslint-plugin-react-hooks` 5.1.0 → 7.1.1,
`eslint-plugin-react-refresh` 0.4.16 → 0.5.3, and `@types/node` 26 (narrowed above).

These are **not** blocked by any ignore rule and are not unwanted — they are tracked work in
`docs/ROADMAP.md`. They are held because they share one risk: every one lands on the type-aware
ESLint gate, and several cannot move alone. `@eslint/js` is ESLint's own package and must move
with `eslint`; `@vitejs/plugin-react` 6 is a Vite-major companion; `eslint-plugin-react-hooks` 7
pulls the React Compiler rules into its recommended set. `typescript-eslint` 8.19 → 8.65 is a
*minor* and would look routine in isolation — it is held anyway, because its support matrix pairs
with the TypeScript version the sweep is about to move, so taking it now means bumping it twice
and reviewing the lint churn twice. Picking off the members that happen to be minors is what makes
a sweep like this never happen.

---

**Two config/doc changes made alongside the bumps.**

1. **`.github/dependabot.yml` gains an `@types/node` major ignore**, beside the existing
   `@types/react*` ones and for the identical reason — a types major tracking a runtime major this
   repo has deliberately pinned. Without it, #145's `@types/node` 26 returns every week inside the
   grouped PR. The comment also records what is deliberately **not** ignored: the toolchain
   majors, which should keep being surfaced until the sweep lands. An ignore rule states that a
   bot may not make a decision; it is not a parking space for work we intend to do.
2. **`docs/ROADMAP.md`'s #86 sweep entry** is refreshed to the versions #145 actually surfaced
   (jsdom's target moved 29 → 30 since #86) and gains the four members that were not on the
   original list: `@eslint/js`, `@vitejs/plugin-react`, `eslint-plugin-react-hooks`, and
   `eslint-plugin-react-refresh`.

---

**Verification.** Backend: `ruff` and `black --check` clean, `.env.example` in sync,
`requirements.lock` regenerated with the pinned uv and byte-identical to what CI recomputes, and
**728 passed / 11 skipped** on **CPython 3.14.6** — the pinned runtime floor, obtained as a
python-build-standalone build because the sandbox's package sources offer no 3.14 at or above it.
Worth recording for the next person: the suite **cannot** run on **3.14.0rc2** (what `uv python
install 3.14` resolves to here). `typing._eval_type()` gained its `prefer_fwd_module` keyword
between rc2 and final, and pydantic 2.13.4 passes it unconditionally, so every model construction
raises `TypeError` at import. That failure was confirmed to be interpreter-caused, not
bump-caused, by reproducing it with the *pre-bump* `fastapi`/`uvicorn` pins in the same venv
before concluding anything — the rule from § Interpreter CVEs applied to a test failure rather
than an advisory: check it against the interpreter before blaming the diff.
Frontend: ESLint, Prettier, **79 tests across 21 files**, and `npm run build` all pass.
`npm audit`'s only finding is the pre-existing `react-router` HIGH (GHSA-qwww-vcr4-c8h2, #123),
unchanged by this PR and still fixable only by a downgrade.

**Version numbers held at 0.3.0** — confirmed after the regenerations in all five places that
carry one: `backend/pyproject.toml`, `backend/app/__init__.py`, `frontend/package.json`,
`frontend/package-lock.json`, and `docker/docker-compose.yml`'s `image: scrye:0.3.0`. A lockfile
regen must not move the app version, and neither `uv pip compile` nor `npm install` did.

**Why:** Dependabot's proposals are evidence about what is available, not decisions about what
this repo should take. Three specific gaps make merging them as-built wrong here: it does not
regenerate `backend/requirements.lock` (CI's drift gate rejects the branch), it cannot tell a
locked or deferred version policy from a stale pin, and — as #146 shows — its own description of a
bump ("from `ea14db8…` to `f205ea1c…`") can be true and still describe something entirely
different from what it looks like. Resolving the tag against upstream, reading the changelog for
anything moving more than a patch, and regenerating lockfiles with the real package manager is the
work; the version strings are the easy part.

**Plan section affected:** `CLAUDE.md` § Dependency hygiene (Dependabot triage, backend lockfile
regeneration); `.github/dependabot.yml` (npm `@types/node` major ignore);
`.github/workflows/codeql.yml` (SHA-pin corrected to the commit behind `v4.37.4`);
`backend/pyproject.toml` + `backend/requirements.lock`; `frontend/package.json` +
`frontend/package-lock.json`; `docs/ROADMAP.md` (#86 sweep list refreshed). No schema, API
contract, security model, job model, or auth change, and no locked decision re-opened — Mantine
stays on v7 and React on 18.

---

### 2026-08-03 — Release/Process — v0.3.0 release prep: version bumped to 0.3.0, CHANGELOG cut with an upgrade-notes block for migration 0009

**What changed:** the `CONTRIBUTING.md` § Releasing "Before you tag" checklist run for **v0.3.0**,
plus the version bump and the CHANGELOG cut, landing on `dev` before the promotion PR is opened. No
application code, schema, API-contract, security-model, job-model, auth, or CI-behavior change.

**1. Version bumped `0.2.0` → `0.3.0`, not `0.2.1`.** The release carries a new user-facing feature
(OIDC account linking) **and** a schema migration, so it is a minor under SemVer, not a patch — a
patch release should not move the database schema, and `0009_oidc_link_flows` is not reversible
except by dropping the columns it added.

Bumped in the three independent declarations the 2026-07-29 entry identified — `backend/app/__init__.py`
(`__version__`, the only runtime-load-bearing copy), `backend/pyproject.toml`, and
`frontend/package.json` plus `package-lock.json`'s two root fields (written by
`npm version 0.3.0 --no-git-tag-version`, not by hand) — and in the five documentation/Compose
references to the example image tag and the `/healthz` sample output (`docker/docker-compose.yml`,
`docker/Dockerfile`'s build-command comment, `README.md` ×3). `backend/tests/test_version.py` passes
on the result.

**Two occurrences were bumped that the 2026-07-29 list does not name**, found by grepping the whole
repo rather than working from that list:

- `.github/dependabot.yml` ×2 — the docker-ecosystem `ignore:` block's comment quotes the Compose
  pin verbatim (`pins \`image: scrye:0.2.0\``, and the rejected `ghcr.io/tyler-rich/scrye:0.2.0`
  alternative). The `dependency-name: "scrye"` rule itself is version-independent, so nothing
  behavioural moves; the comment would simply have stopped describing the file it cites.
- `frontend/src/components/settings/AboutPanel.test.tsx` ×2 — the `BASE_ABOUT` fixture's `version`
  and the version-stat assertion bound to it. Bumped on the precedent of the 0.1.0 → 0.2.0 bump
  (#115), which moved the same fixture. Nothing forces it — `test_version.py` does not reach the
  frontend fixture — but a mocked About response a release behind the app is the same trap the
  drift guard exists to prevent.

**Deliberately left at `0.2.0`,** matching the 2026-07-29 entry's reasoning: the `## [0.2.0]`
CHANGELOG section and its compare links, the prior §14 entries and `CONTRIBUTING.md` §
Releasing / `docs/ROADMAP.md` references to the *v0.2.0 promotion* (all release history — rewriting
them falsifies the record), and `backend/tests/test_trivy_policy.py:19`'s
`https://openvex.dev/ns/v0.2.0`, which is the OpenVEX spec's context version and has nothing to do
with Scrye's.

**2. `CHANGELOG.md` `[Unreleased]` cut to `[0.3.0] - 2026-08-03`,** with a fresh empty
`[Unreleased]` above it and the reference-link block gaining
`[0.3.0]: …/compare/v0.2.0...v0.3.0` with `[Unreleased]` re-pointed at `…/compare/v0.3.0...HEAD`.
As in the v0.2.0 cut, doing this **before** the promotion means `main` receives an already-correct
CHANGELOG rather than a commit landing on `main` after the fact.

**3. A new `### Upgrade notes` block opens the `[0.3.0]` section.** This release is the first since
v0.1.0 to change the schema, and nothing in the section said so — the OIDC-linking entry describes
the feature, not its deployment consequence. Three bullets: that starting 0.3.0 applies
`0009_oidc_link_flows` (two nullable columns on `oidc_login_flows`, no data rewritten, a transient
table excluded from backups, nothing to run by hand); that **downgrading to 0.2.0 is not
supported**, because the 0.2.0 image's migration history ends at `0008` and `alembic upgrade head`
fails on an unknown revision rather than starting against a mismatched schema, so the recovery path
is a backup bundle taken *before* the upgrade; and that no configuration or environment variable
moved. Placed above `Added` rather than folded into a bullet, because it is the only part of the
section a reader has to act on.

**4. `[Unreleased]` re-verified claim by claim rather than trusted,** per the checklist's first
item and the v0.2.0 cycle's false-CVE precedent. It held up; every externally-dependent claim was
re-checked at its source this session:

- **`react-router-dom` 7.18.2 "closes GHSA-qwww-vcr4-c8h2".** Verified in the published tarballs,
  not from the advisory. `throwIfPotentialCSRFAttack()` is byte-identical across 7.18.1, 7.18.2 and
  8.3.0 — the fix is entirely at the **call site** in `index-react-server.js`'s
  `generateMiddlewareResponse`. 7.18.1 runs the check and `processServerAction()` inside one `try`;
  7.18.2 isolates the check in its own `try`, records `potentialCSRFAttackError`, rewrites the
  request to `method: "GET"`, and gates the action behind `if (!potentialCSRFAttackError)` — and
  8.3.0's is the same code, differing only in the bundler's formatting and one local's name
  (`result2` vs `result`). Upstream's own `CHANGELOG.md` at 7.18.2 lists exactly one patch change,
  "Harden RSC CSRF codepaths (#15353)", confirming the entry's claim that the backport *is* the
  whole 7.18.1 → 7.18.2 diff.
- **The same entry's claim that `npm audit` will keep reporting it.** Still true: `npm audit`
  against the current lockfile reports `react-router` HIGH with range `7.12.0 - 8.2.0` — 7.18.2 is
  inside it — so the advisory has not been re-cut for the backport. The entry says so explicitly,
  which is what keeps the next reader from "fixing" it with the `npm audit fix --force` downgrade.
- **`postcss` 8.5.25.** The containment check the advisory names is present in the installed
  `node_modules/postcss/lib/previous-map.js` (`relative(dirname(cssFile), path)` guarded on `'..'`,
  `'..' + sep` and `isAbsolute`).
- **Pins and workflow claims** at the file: `fastapi==0.140.13` (was `0.140.0` on `main`),
  `react-router-dom@7.18.2`, `postcss@8.5.25`, `docker/login-action` at the v4.6.0 SHA in
  `publish.yml`/`dev-nightly.yml`/`rescan.yml`, `node:24-bookworm-slim` in the Dockerfile with
  `node-version: "24"` in `ci.yml`, CONTRIBUTING's "Node 22+" floor, and `codeql.yml`'s
  `security-extended` suite / three languages / `push`+`pull_request` on `main` and `dev` / Monday
  04:00 UTC cron / no `paths:` filters.
- **The OIDC entries against the implementation:** the `Your linked identity` card title, the
  `auth.oidc_identity_linked` / `_unlinked` / `_stale` audit actions, the quoted stale-link error
  matching `LoginPage.tsx`'s `identity_stale` text, and the README's re-link runbook and
  security-model widening.
- **The uvicorn log-volume entry's dating.** "Present since 2026-07-04" matches
  `git log -S "uvicorn.access"` on `backend/app/core/logging.py` (`f2806d6`), which precedes both
  v0.1.0 (2026-07-09) and v0.2.0 (2026-07-31) as the entry states; the ~144k lines/day figure is
  consistent with the 30s `HEALTHCHECK` interval in the Dockerfile and Compose file.
- **The SEC-8 widening** was already described substantively; the entry was expanded to name the
  concrete consequence (an MFA-enrolled admin's local TOTP challenge never runs on the linked path)
  and to cite `L2 / SEC-8` with the §15 decoder link, matching the one existing finding-ID citation
  in the file. It is the feature's main trade-off and should not need §14 to be legible.

**Not added to the CHANGELOG, deliberately.** Four items in the `main..dev` range change nothing a
user can observe and are recorded in §14 instead: the filesystem-scan symlink containment guard
(#135/#140 — a test), the Starlette status-code constant retirement (#142), the
`test_cancel_queued_scan` de-flake, and the docs/governance work. `brace-expansion` is **not** part
of this release despite appearing in the release-prep brief — it was reapplied on `dev` before the
v0.2.0 promotion and ships in `[0.2.0]`; `git diff origin/main..origin/dev -- frontend/package-lock.json`
carries no `brace-expansion` change.

**5. `THIRD_PARTY_LICENSES/` re-verified,** repeating rather than inheriting the 2026-07-31 check.
The version table still matches `docker/Dockerfile`'s `TRIVY_VERSION=0.72.0` / `GRYPE_VERSION=0.115.0`
/ `SYFT_VERSION=1.46.0` — none moved this cycle; the only Dockerfile change in the range is the Node
builder — and all four bundled files were re-fetched from upstream at those tags and compared with
`cmp`: `trivy/LICENSE`, `trivy/NOTICE`, `grype/LICENSE` and `syft/LICENSE` are byte-identical.
Grype and Syft still 404 on `NOTICE`, as the directory's README says.

**Why:** every item is one the "Before you tag" checklist exists to catch, and each is permanent or
expensive to undo once the tag exists. The version bump in particular has to land before the
promotion: nothing derives the app's version from the git tag, so tagging `v0.3.0` on an unbumped
`main` would publish `ghcr.io/tyler-rich/scrye:0.3.0` running an app that reports `0.2.0` on the
About tab, `/healthz`, the OpenAPI document, every backup bundle's `app_version`, and the
`scrye_build_info` metric.

**Plan section affected:** `CHANGELOG.md` (`[0.3.0]` cut, new `### Upgrade notes`, SEC-8 expansion);
`CONTRIBUTING.md` § Releasing (pre-tag checklist run); §10.1 (README image-tag and `/healthz`
examples). No locked decision changed.

---

### 2026-08-03 — Post-v1 — PR #142 verified green on the pinned Python 3.14.6 in CI; `test_undeterminable_presence_fails_startup`'s local-sandbox failure was 3.13-specific

**What changed:** nothing in the repository — this entry records a verification, not a code change.
PR #142's development-agent session had no Python 3.14.6 available locally (only 3.13.12 and a
3.14.0rc2 that fails to even import FastAPI/Pydantic under this codebase's dependency versions), so
its local test run was done under 3.13 with `requires-python` temporarily loosened in an uncommitted,
reverted copy of `pyproject.toml`. That run passed except for one failure,
`tests/test_master_key_autogeneration.py::TestExistingKeyIsNeverReplaced::test_undeterminable_presence_fails_startup`,
confirmed to reproduce identically on an unmodified checkout under the same 3.13 sandbox — i.e.
unrelated to the PR's own changes, but still unverified against the actual pinned runtime.

**CI on the real pinned interpreter is what settles it.** The `Backend — lint + tests` job on PR
#142's final commit (`74ce83d`) ran on `pythonLocation: /opt/hostedtoolcache/Python/3.14.6/x64` — the
exact pinned floor — and the suite came back **730 passed, 9 skipped, 0 failed**, including the test
above. So the failure is confirmed **sandbox-specific to Python 3.13's `pathlib`**, not a real defect:
`test_undeterminable_presence_fails_startup` monkeypatches `crypto.os.stat` to raise
`PermissionError` for one specific path, but because `os` is a shared module object, that patch is
visible to *every* caller of `os.stat` in the process — including the test's own
`assert not autogen.exists()`, which calls `pathlib`'s `Path.exists()` → `os.stat()` internally. On
3.13's `pathlib` implementation that assertion routes through the patched `os.stat` and raises instead
of returning `False`; on 3.14.6 it evidently does not (a `pathlib` internal-implementation difference
between the two versions, not tracked further here). **Do not re-diagnose this test as broken from a
future local run under Python 3.13** — check which interpreter is running first.

**Recorded so it isn't re-diagnosed:** this is a note, not a fix and not a new tracked item — the test
passed on the pinned interpreter, which is the bar this PR was held to. If a *future* local run under
Python 3.13 (or any interpreter where `pathlib.Path.exists()` routes through `os.stat`) reproduces this
failure, the cause is the sandbox's interpreter, not a regression in this test or in `crypto.py`.

**Plan section affected:** none (verification-only). Documented here per CLAUDE.md's rule that a
settings-adjacent or environment-specific finding with no code diff still needs a durable record so
it isn't re-diagnosed from scratch later.

---

### 2026-08-03 — Post-v1 — `test_cancel_queued_scan` de-flaked: worker slot acquisition made observable, sleep removed

**What changed:** `backend/tests/test_scans_api.py::test_cancel_queued_scan` no longer holds the
worker's only concurrency slot with a fixed `await asyncio.sleep(0.2)`. The fake scanner now blocks
on a `threading.Event` the test controls, and a second `threading.Event` fires the instant
`scan_image` actually starts executing — which only happens after the worker's semaphore has been
acquired, so it doubles as "the first scan now holds the only slot." The test waits on that signal
before submitting the second scan, so the second scan is deterministically still `queued` at the
moment it's canceled. Test-only change — no worker or production code touched.

**Why:** the ROADMAP item this closes explained the failure mode precisely: the old test's
correctness depended on the whole round-trip (submit first, submit second, cancel second) finishing
inside the 0.2 s window before the first scan's fake sleep ended and released the semaphore to the
second. Under a loaded CI runner that window could close before the cancel POST was processed, the
second scan would have already left `queued`, and the endpoint correctly returned 409 — the test was
wrong, not the code. Widening the sleep would only have lengthened the odds without removing the
race; making the first scan's execution point observable removes the wall-clock dependency entirely.
Run 20× locally with no failures, in ~0.35 s per run (down from a sleep-bound floor of 0.2 s per run
plus the race).

**Plan section affected:** `docs/ROADMAP.md` § Near-term (the de-flake item — struck).

---

### 2026-08-03 — Post-v1 — Deprecated Starlette status-code constants retired across 24 call sites

**What changed:** `status.HTTP_422_UNPROCESSABLE_ENTITY` → `status.HTTP_422_UNPROCESSABLE_CONTENT`
and `status.HTTP_413_REQUEST_ENTITY_TOO_LARGE` → `status.HTTP_413_CONTENT_TOO_LARGE` across all 24
call sites in the 8 files that used them (`scans.py` ×10, `scan_schedules.py` ×4, `registries.py`
×3, `notifications.py` ×2, and one each in `trivy_policy.py`, `git_credentials.py`, `backups.py`,
`uploads.py`).

**Why:** both old constants raised a `StarletteDeprecationWarning` on every attribute access and
have been standing warnings in the backend suite's output since at least the 2026-07-03 interpreter
bump. Before renaming, both old/new pairs were checked against the pinned `starlette==1.3.1` to
confirm the rename can't move a status code: `HTTP_422_UNPROCESSABLE_ENTITY` and
`HTTP_422_UNPROCESSABLE_CONTENT` both resolve to `422`; `HTTP_413_REQUEST_ENTITY_TOO_LARGE` and
`HTTP_413_CONTENT_TOO_LARGE` both resolve to `413`. Purely mechanical — no response behavior
changed.

**Plan section affected:** `docs/ROADMAP.md` § Near-term (the Starlette-constants item — struck).

---

### 2026-08-03 — Process/Governance — Dogfood self-scan added to required status checks, closing #136

**What changed:** `protect-dev`'s `required_status_checks` now lists three contexts —
`Backend — lint + tests`, `Frontend — lint + build`, and **`Image — build + dogfood self-scan`** —
where it previously named only the first two. **"Require branches to be up to date before merging"**
was also enabled on the same ruleset. No repository content changed; this entry is the record, for
the same reason the rest of this checklist is recorded here rather than only in the ROADMAP — a
settings change leaves no artifact in git.

**Why:** [#136](https://github.com/tyler-rich/Scrye/issues/136) — the dogfood self-scan job
(`ci.yml`'s `Image — build + dogfood self-scan`) ran and reported on every PR but was not on the
allowlist `required_status_checks` actually enforces, so a PR could merge into `dev` with the image
scan red. That job is not an ordinary CI check — it is the control `CLAUDE.md` § Dependency hygiene
mandates (gating on fixable HIGH/CRITICAL findings in Scrye's own image) and the one that caught
CVE-2026-5773 (§14, 2026-07-13) and verifies the SC-14 dev-tree exclusion. Requiring it converts
"merge with a red gate" from a silent non-event into an explicit act, for anyone other than the
repository-admin account on the bypass list.

**Note, closing the loop from #136's own text:** the issue was closed directly on 2026-08-02 with no
comment and no §14 entry — exactly the invisible-settings-change failure mode this checklist exists
to catch. This entry supplies the missing verification: the live ruleset readout above confirms the
required context really is in place, rather than trusting the closed state alone.

**Plan section affected:** `docs/ROADMAP.md` § Near-term (the public-repo governance checklist —
this closes the first of the two issue-tracked branch-protection gaps; struck from the checklist).
Closes #136.

---

### 2026-08-03 — Process/Governance — protect-tags ruleset created, closing #137

**What changed:** a new GitHub ruleset, **`protect-tags`**, was created (`target: "tag"`,
pattern `v*` — matches any tag beginning with `v`, not only the dotted semver form). It restricts
tag creation, update, and deletion to the bypass list, and blocks force pushes to matching tags.
**Repository admin** is on the bypass list, consistent with how
`protect-dev` and `protect-main` are configured (§14, 2026-08-02 — the admin bypass on those
rulesets is what let `dev` be deleted during the v0.2.0 promotion despite "Restrict deletions").
No repository content changed; this entry is the record, for the same reason the rest of the
public-repo governance checklist is recorded here rather than only in the ROADMAP — a settings
change leaves no artifact in git.

**Why:** [#137](https://github.com/tyler-rich/Scrye/issues/137) — nothing restricted tag pushes,
and a `v*.*.*` tag push is exactly what triggers `publish.yml` (GHCR push, the `:latest` move, and
provenance + SBOM attestation, per locked decision §6). Before this ruleset, anyone with write
access could push or force-move a `v*.*.*` tag and trigger a publish outside the normal `dev` →
`main` → tag flow. Theoretical on a sole-maintainer repo, but the fix belongs in place *before* any
collaborator is added, not after.

**Plan section affected:** `docs/ROADMAP.md` § Near-term (the public-repo governance checklist —
this closes the second of the two remaining tracked settings gaps; struck from the checklist).
Closes #137.

---

### 2026-08-03 — Process/Governance — Signed-commit enforcement declined, not deferred

**What changed:** the "require signed commits" item under the public-repo governance checklist is
**struck from `docs/ROADMAP.md`** as a declined decision, not left open as pending work. Neither
`protect-dev` nor `protect-main` carries a `required_signatures` rule, and none will be added under
the current commit workflow.

**Why:** every commit in this repository is authored by a Claude Code session committing locally
via `git` and pushing over the repository's normal push path — there is no signing key present in
those environments (that absence is exactly why every commit here shows GitHub's "Unverified"
badge today). Turning on "Require signed commits" on either protected-branch ruleset would reject
every one of those pushes outright, breaking the development workflow entirely rather than adding
friction to it.

The two workarounds available are both worse than the problem they'd solve:
- **Provisioning a GPG or SSH signing key into a sandboxed session** is precisely the kind of
  environment a signing key should not be placed into — it turns the key into something that
  exists in an ephemeral, non-interactive container rather than under a maintainer's direct
  control, which undermines the point of requiring a signature in the first place.
- **Switching sessions to create commits via the GitHub API** (which GitHub auto-signs on behalf
  of the authenticated actor) would work, but it is a significant change to how these sessions
  operate — moving off local `git commit`/`git push` entirely — for a benefit that is modest on a
  repository with a single maintainer and no other committers to authenticate against.

**Revisit trigger:** this decision is not permanent. Revisit it if either condition changes — a
collaborator with write access is added (at which point signed commits start doing real work,
distinguishing a maintainer's commits from a contributor's), or the commit workflow stops going
through local `git` (e.g. a move to API-authored commits for some other reason removes the cost
side of this trade-off).

**Plan section affected:** `docs/ROADMAP.md` § Near-term (the public-repo governance checklist —
this closes the last of its three previously-open items; struck from the checklist as declined,
not done).

---

### 2026-08-02 — Security/Process — CodeQL migrated from default setup to a committed workflow; the two settings edits that finish it

**What changed:** `.github/workflows/codeql.yml` (new — the repository's fifth workflow). CodeQL moves
from GitHub's **default setup** (configured in repository settings, no artifact in git) to **advanced
setup**: a workflow this repository owns, pins and reviews. This implements the recommendation the
assessment entry below reached and deliberately left to the maintainer. No application code changed,
and **nothing about the analysis changed** — same query suite, same three languages, same CodeQL
bundle, same action version. The only thing that moves is *when* CodeQL runs.

**Why: the trigger, not the queries.** Default setup's pull-request trigger targets the repository's
**default branch**. `main` is the default branch here and PRs go to `dev`
(CLAUDE.md § Git & PR conventions), so CodeQL never ran on a pull request at all — it ran on `main`
on push, *after* a promotion had already landed. At that point the change is merged and the remedy
for a finding is a revert, not a review comment. With several PRs regularly in flight, a finding that
surfaces on `main` is attributable to a **batch** rather than to the PR that introduced it. The
secondary gap is `:dev`: `dev-nightly.yml` builds and pushes that image from a branch CodeQL never
analysed. (`:latest` was **not** a gap — it is published by a tag push, not by the promotion merge;
the assessment entry below corrects that framing.)

#### The workflow's shape, element by element

| Element | Value | Why this and not something else |
| --- | --- | --- |
| Query suite | `queries: security-extended` | Reproduces **exactly** what default setup ran. `security-extended` is a member of `defaultSuites` in codeql-action's `src/analyze.ts` and resolves through `resolveQuerySuiteAlias()` to `<language>-security-extended.qls`. Omit it and the analysis silently falls back to the smaller `code-scanning` suite — 45 Python queries instead of 52. §14's triage entry below records a reproduction that made exactly that mistake and under-reported by one alert. |
| Languages | explicit 3-entry matrix: `python`, `javascript-typescript`, `actions`, each `build-mode: none` | Advanced setup **loses** default setup's automatic language detection, which is what added `actions` in the first place. The matrix is now the whole list, and it carries an inline comment tying it to **locked decision §2** so the stack pinning is visible at the point a language would be added. `build-mode: none` on all three: nothing here is a compiled language. |
| Action pins | `github/codeql-action/init` and `.../analyze` at `ea14db8afdef5d462e69d78c4ca45002d4522418` (`# v4.37.4`) | Repo convention (H9/SC-2): SHA-pinned with the tag as a trailing comment. v4.37.4 is the same action version default setup was running. **Pinning the action does not pin the queries** — `init`'s `tools:` input defaults to the recommended CodeQL bundle, so the CLI and query packs keep updating on GitHub's schedule. Dependabot's existing grouped weekly `github-actions` PR carries the SHAs forward. |
| Permissions | `security-events: write`, `contents: read`, `actions: read` | Least privilege, declared at both the workflow and the job level so the grant is visible where it is used. `security-events: write` is the SARIF upload; `actions: read` is what codeql-action needs to read run metadata on `pull_request`. |
| Triggers | `pull_request` **and** `push`, each filtered to `[main, dev]`, plus a weekly `schedule` | The whole point of the migration. `pull_request` is the per-PR gate on the branch that actually receives PRs; `push` keeps the post-merge analysis on both branches, which is what closes the `:dev` hole. The cron carries over default setup's weekly scan — see below for its scope, which is narrower than it looks. |
| Path filters | **none, deliberately** | These contexts are destined for `protect-dev`'s required list. A job skipped by an `if:` still reports a `skipped` conclusion and satisfies a required check — that is why `Image — multi-arch build check` showing `skipped` on `dev` PRs is harmless. A **workflow that never triggers reports nothing at all**, so a `paths:` filter would make a docs-only PR hang forever on a check that was never scheduled. The suite runs in ~60 s and Actions minutes are free on a public repo; there is nothing here worth saving. |
| `concurrency` | `codeql-${{ github.workflow }}-${{ github.ref }}`, `cancel-in-progress: true` | Mirrors `ci.yml`. Superseded runs on the same ref are cancelled. |
| `fail-fast` | `false` | One language failing must not cancel the other two. A partial result is still worth having, and the failure names its own language. |

**Default setup's weekly scan is carried over, not dropped — `schedule: - cron: "0 4 * * 1"`.**
The migration spec named `pull_request` + `push` for `dev` and `main`, and the workflow was first
built to exactly that, with the missing cron flagged rather than silently added; the maintainer then
asked for it in the same PR. It matters for a reason the push/PR triggers cannot cover: query packs
keep updating independently of the pinned action (see the pin row above), so **a newly published
query never runs against unchanged code** unless something schedules it — it would otherwise wait for
the next commit touching that language, which for a quiet subsystem can be a long time. Note this is
*not* the schedule-instead-of-per-PR arrangement the assessment below rejected; it is a supplement to
per-PR feedback, not a replacement.

**Its scope is narrower than it reads, and the difference is worth knowing before relying on it.**
`on: schedule` **always runs against the default branch**. The `branches: [main, dev]` filters apply
to `push` and `pull_request` only and do not constrain a cron, so this weekly run analyses **`main`,
never `dev`** — and, like the Settings row discussed below, **it does not fire at all until
`codeql.yml` has reached `main` via a `dev` → `main` promotion.** Merging into `dev` does not start
it. That is an acceptable shape rather than a gap: `dev` is covered continuously and at much higher
frequency by the push/PR triggers, and the cron's purpose is catching *new queries* against a stable
tree, which is precisely what `main` is. But do not read the cron as a safety net over `dev`.

04:00 UTC Monday is the same off-hours slot `dev-nightly.yml` uses. They share no runner, no GHA
cache scope and no registry, so the Monday overlap costs nothing.

#### Settings edit 1 — the exact required-status-check context strings

Required status checks are an **explicit allowlist of context strings**, and a string that matches no
reporting check is a context that never reports — which blocks every PR indefinitely. These are the
three, **verified against the check runs GitHub actually created** for run
[30739872403](https://github.com/tyler-rich/Scrye/actions/runs/30739872403) rather than derived from
the YAML:

```
CodeQL — python
CodeQL — javascript-typescript
CodeQL — actions
```

The separator is **U+2014 EM DASH with one ordinary space on each side** — the same character
`ci.yml`'s `Backend — lint + tests` and `Image — build + dogfood self-scan` use. Copy these strings
rather than retyping them; an en dash or a hyphen produces a context that never reports.

They come from the matrix job's `name: CodeQL — ${{ matrix.language }}`. **Renaming that job, or
changing a matrix `language:` value, renames the contexts and silently breaks the ruleset** — the
workflow keeps passing while the required check hangs. The workflow carries a comment saying so at
the job name.

**Add them to `protect-main` as well as `protect-dev`.** Both are safe and both are useful:

- **`protect-dev`** is the point of the exercise — it is where PRs land, and per §14 below its
  `required_status_checks` currently names only `Backend — lint + tests` and
  `Frontend — lint + build`. Until these three are on that list CodeQL runs, is visible, and goes red
  **without blocking a merge**.
- **`protect-main`** gets them for a different reason: the only PR that ever targets `main` is a
  `dev` → `main` promotion, i.e. the last reviewable moment before a release tag triggers
  `publish.yml`. The workflow triggers on `pull_request` with base `main` and on `push` to `main`
  with no job-level `if:`, so all three contexts always report there — unlike
  `Image — multi-arch build check`, which is `if:`-conditioned and is the reason #136 recommends
  requiring that one on `protect-main` only.

This differs from the `Image — build + dogfood self-scan` gap tracked as
[#136](https://github.com/tyler-rich/Scrye/issues/136) only in which strings get added; the hazard
and the reasoning are identical, and both edits can be made in one pass.

#### Settings edit 2 — when to disable default setup (and why there cannot be an overlap)

**The two setups are mutually exclusive. This is enforced server-side, and it was verified twice
rather than assumed.** In codeql-action's `src/upload-lib.ts`, `shouldConsiderConfigurationError()`
lists the API's rejection message verbatim:

```
CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled
```

and this repository then reproduced it live. The three CodeQL jobs on PR #141 ran the full analysis,
exported SARIF, and **uploaded successfully** — and the upload was then rejected at processing:

```
Uploading results
Successfully uploaded results
Waiting for processing to finish
Analysis upload status is failed.
##[error]Code Scanning could not process the submitted SARIF file:
CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled
...
CodeQL job status was configuration error.
```

So the answer to *"before or after merging?"* is neither of the naive options, and the stated goal —
"a gap of zero rather than a window with no scanning" — **is not achievable as literally stated**:
GitHub will not let both configurations produce results at the same time, so there is no overlap to
arrange. What *is* achievable is a gap measured in minutes, with the new workflow proven working
before the old one is switched off. The order below does that:

1. **Leave default setup enabled while the PR is open.** It keeps analysing `main` on push and on its
   weekly cron exactly as before. The PR's three CodeQL contexts will be **red**, with the
   configuration error above — expected, and *not* a defect in the workflow: everything up to and
   including the upload succeeds.
2. **Disable default setup** — Settings → Code security → Code scanning → CodeQL analysis → **⋯** →
   *Switch to advanced* (or *Disable CodeQL*). **Alert history is preserved** across the conversion;
   the six triaged alerts do not disappear.
3. **Re-run the failed CodeQL jobs on the PR** (Actions → the failed run → *Re-run failed jobs*).
   With default setup off, the upload processes and the three contexts go green. **This is the
   confirmation step** — it proves the committed workflow produces results *before* anything is
   merged and before any ruleset depends on it. If it does not go green, re-enabling default setup
   restores the previous state immediately.
4. **Merge the PR into `dev`** (squash, per the ruleset's `allowed_merge_methods`). Note
   `protect-dev` now also has **"Require branches to be up to date before merging"**
   (`strict_required_status_checks_policy`), so if `dev` has moved the branch must be updated first —
   which fires a `synchronize` and re-runs everything, including CodeQL, against the merged state.
   That is a feature here, not friction: the green run that gates the merge is a run against the
   code that will actually land.
5. **Only then add the three contexts to `protect-dev` and `protect-main`.** Doing this *before*
   step 4 would hang every other open PR: a PR whose branch predates the workflow has no CodeQL run
   to report, and a required context with nothing reporting blocks the merge. After step 4 the strict
   up-to-date rule forces every open PR to re-sync onto a `dev` that carries the workflow, so each
   one picks the checks up on its next run.

**The actual scanning gap** is therefore step 2 → step 3: roughly the ~60 s the re-run takes, plus
however long passes between the two clicks. Nothing is lost in that window — default setup only ran
on pushes to `main` and a weekly cron, and no push to `main` is involved in any of these steps.

**Do not skip step 3 and disable default setup after merging instead.** That order works, but it
inverts what the maintainer asked for: the workflow would be merged, and the ruleset possibly
edited, on the strength of a run that had never been allowed to complete.

**Two things the *Switch to advanced* flow does that are easy to misread. Both were hit live.**

- **It opens a workflow-file editor pre-filled with GitHub's generic template. Do not commit it.**
  Disabling default setup is the *first* half of that flow; the editor is the second, and it is
  redundant here because this repository supplies its own `codeql.yml`. Committing the template
  would (a) land a workflow directly on `main`, which per the branching model receives only
  promotions, (b) collide at the identical path with the migration PR, and (c) name its job
  `Analyze (${{ matrix.language }})` — producing contexts `Analyze (python)` &c., **not** the
  `CodeQL — <language>` strings the rulesets are being pointed at. It also carries a `schedule`
  cron, unpinned `@v4` action refs and `packages: read`. The correct action on that page is
  **Cancel changes**; the disable has already taken effect by the time it is shown, which was
  confirmed by re-running the PR's CodeQL jobs immediately afterwards — they went green with no
  file committed.
- **Settings will then report CodeQL as "not configured" / off, and that is not a failure.**
  The Settings → Code security row determines the CodeQL status from a workflow present on the
  **default branch** (`main`). With default setup off and `codeql.yml` living only on a feature
  branch — or, after the merge, only on `dev` — the row has nothing to point at and reads as
  though scanning were disabled. It is not: advanced setup is not an enablement flag anywhere, just
  a workflow holding `security-events: write` that uploads SARIF, and the uploads demonstrably
  process. **Expect the row to keep reading "not configured" until a `dev` → `main` promotion
  carries the workflow to the default branch.** Judge the migration by whether the analysis jobs
  go green and their results appear under the PR/branch in Security → Code scanning, never by that
  row.

**The sequence above was executed, not just proposed.** Attempts 1 and 2 of the PR's CodeQL run
(08:29 and 08:44 UTC) failed identically with the configuration error while default setup was still
enabled. Default setup was then disabled via *Switch to advanced*, the template editor cancelled
without committing, and attempt 3 (09:21 UTC) re-ran the same three jobs unchanged: **all green** —
`CodeQL — python` 51 s, `CodeQL — javascript-typescript` 60 s, `CodeQL — actions` 41 s. That is the
step-3 confirmation: the committed workflow uploads *and processes* results, proven on the PR before
the merge and before any ruleset edit.

#### What this PR's CodeQL run actually found

The analysis ran to completion on all three languages before the rejected upload, so the run itself
is evidence about the workflow; it is not evidence about the *findings*, because rejected SARIF never
reaches the Security tab and the alert list could not be read from the API at this session's token
scope (`metadata=read` — `GET /code-scanning/alerts` returns 403, the same limitation the triage
entry below hit). The findings were therefore obtained the same way that entry obtained them:
**reproduced locally at the PR's head commit** (`1b4dcd9`) with `codeql-bundle-v2.26.2` — the exact
CLI version the runner used, per the runner's `/opt/hostedtoolcache/CodeQL/2.26.2/` tool path — and
the `*-security-extended.qls` suites, matching the workflow's `queries:` input rather than assuming
the default suite.

**Result: parity with the six alerts already triaged — nothing new surfaced.** 6 findings, all
Python; **0** JavaScript/TypeScript; **0** Actions. Same rules, same files, same
`security-severity` values as the triage table below:

| Rule | Location | `security-severity` |
|------|----------|---------------------|
| `py/path-injection` | `backend/app/scanners/targets.py:138` | 7.5 |
| `py/path-injection` | `backend/app/scanners/targets.py:144` | 7.5 |
| `py/incomplete-url-substring-sanitization` | `backend/tests/test_credentials.py:320` | 7.8 |
| `py/incomplete-url-substring-sanitization` | `backend/tests/test_dockerfile_supply_chain.py:71` | 7.8 |
| `py/incomplete-url-substring-sanitization` | `backend/tests/test_redaction.py:222` | 7.8 |
| `py/log-injection` | `backend/app/api/scans.py:574` | 6.1 |

**One line number moved, and it is not a new finding.** The triage below recorded the third
`py/incomplete-url-substring-sanitization` at `test_redaction.py:120`; it is now `:222`. That file's
most recent change is `2e1e3ac` (#139, the log-redaction fix), which rewrote it — the flagged
assertion is the same one at a new line. Every other rule/file/line pair is unchanged. **Parity was
checked rather than assumed**, which is the point of saying so: the whole reason to reproduce is that
a migration could quietly change the query set, and "it looks the same" is not a check.

**Suite parity was verified at the source, not inferred from the workflow input.** Resolving the
suites with the same CLI gives `python-security-extended.qls` → **52** queries vs
`python-code-scanning.qls` → **45**; `javascript` → **105** vs **89**; `actions` → **24** vs **18** —
matching the counts the triage entry recorded for the default-setup run exactly. So
`queries: security-extended` in the committed workflow is running the same query set default setup
was.

**The workflow analyses itself, and comes back clean.** The `actions` database extracted six files —
the five workflows plus the composite `build-image` action — including the newly added `codeql.yml`,
and the Actions security queries (untrusted checkout, script injection, artifact poisoning) returned
nothing on any of them.

#### Verification performed

- Workflow YAML parses; the three check runs GitHub created are named exactly as the strings above
  (read back from the run's jobs API, not from the YAML).
- The rest of CI is unaffected — `Backend — lint + tests`, `Frontend — lint + build` and
  `Image — build + dogfood self-scan` all green on the PR; `Image — multi-arch build check` reports
  `skipped`, as it does on every `dev` PR.
- The default-setup/advanced-setup mutual exclusion confirmed both in `codeql-action`'s source and in
  the live job log (quoted above), rather than from documentation.
- `codeql-action` v4.37.4's commit SHA taken from `git ls-remote --tags` against the upstream
  repository, not from a docs snippet.

**Plan section affected:** §14 (this record); `docs/ROADMAP.md` § Near-term (the CodeQL item — the
migration sub-item struck, the remaining work restated); `CHANGELOG.md` § Unreleased → Changed. No
application code, schema, or locked-decision change. `.github/workflows/codeql.yml` is new; no
existing workflow was touched.

---

### 2026-08-02 — Security/Process — Symlink-containment regression guard for filesystem scans (#135); Syft is the probe, and it runs against the binaries the image ships

**What changed:** `backend/tests/test_scanner_symlink_containment.py` (new, 7 tests) plus four steps
in CI's `image` job that run it. No application code changed — this is the regression test the
2026-08-02 verification entry above proposed and deliberately did not write.

**Why it exists.** Containment of a symlink planted *inside* an allowed filesystem scan root is not
enforced by Scrye at all. `resolve_filesystem_path()` validates the target argument and is never
re-applied during the walk, so the guarantee is inherited from Syft's directory resolver — and it
hangs on `basePath()` defaulting `base` to the scan location, a line upstream itself annotates
`// FIXME why is the base always being set instead of left as empty string?`. Action that FIXME and
the re-rooting branch in `addSymlinkToIndex` is skipped, `indexAllRoots` starts adding out-of-root
link targets as additional roots, and the escape is real — silently, on a routine scanner bump, with
nothing in this repository that would notice. The full evidence chain is in the entry above.

---

#### Deviation 1 — Syft is the probe binary, not Grype

**#135 says "run the scan the way Scrye runs it (`dir:`)"**, which reads as "invoke `grype dir:`".
The test invokes `syft dir:` instead. Grype is unusable as the *instrument* here: its JSON carries
only vulnerability **matches**, never a package catalogue, so "was the out-of-root package
catalogued?" could only be observed through it by planting packages that carry live CVEs — making
the assertion depend on a vulnerability database that changes daily, in a test whose entire job is to
fail only when scanner *behaviour* changes. Syft's JSON lists the catalogue directly, needs no
database, and runs offline in ~1 s.

The substitution is sound because Grype's `dir:` source **is** Syft's directory source — the same
argument the verification entry above already rests on. It is pinned rather than assumed, by two
tests that need no fixture:

- `test_grype_embeds_the_pinned_syft` — `grype version -o json` reports `syftVersion`, and it must
  equal the `SYFT_VERSION` the Dockerfile pins (measured: grype 0.115.0 → `v1.46.0`). If a bump ever
  breaks that identity, the guard would be exercising code Scrye does not run, and this fails first.
- `test_scrye_scans_filesystems_through_the_directory_source` — `GrypeScanner.scan_filesystem()`
  must still emit `dir:<path>`, so the premise that a filesystem scan is a Syft directory source at
  all stays pinned. (No binary needed; this one runs in the ordinary backend suite.)

`test_syft_binary_is_the_version_the_image_pins` closes the loop from the other side, so a stale
local binary fails instead of passing quietly.

#### Deviation 2 — a sensitivity control beyond the positive control #135 requires

#135 requires a positive control asserted in the same run, because the 2026-08-02 verification hit a
false negative caused purely by a filename the JS cataloger does not glob. That control is present
(`left-pad 1.3.0` in-root must be catalogued), and a second one asserts the out-of-root manifest is
catalogued when scanned directly — so its absence is containment, not a cataloger blind spot.

A third was added: `test_probe_detects_an_escape_when_re_rooting_is_widened` passes
`--base-path <parent-of-root>`, moving the re-rooting anchor above the scan root. That is the closest
reachable analogue of the FIXME being actioned, and it flips the result — `lodash 4.17.15` is then
catalogued at `/outside/package-lock.json`. Measured, not assumed. Without it, "the out-of-root
package is absent" is an absence with no demonstration that the probe could ever have seen it.

**Hardlinks are asserted on nowhere**, per #135: they *are* followed, that is correct behaviour, and
a test that asserted against it would fail on a scanner doing the right thing.

#### Deviation 3 — the guard runs in CI's `image` job, not the backend `pytest` job

The tests need real binaries; the backend job has none, and downloading a second copy there would
mean either a same-origin checksum (weaker than the cosign-verified path `docker/Dockerfile` uses) or
reproducing cosign verification in YAML, plus duplicating the pinned versions. The `image` job
already holds the built image, so it extracts `/usr/local/bin/{syft,grype}` from it with
`docker create` + `docker cp` and runs the test against **the binaries the product actually ships** —
cosign- and checksum-verified at build time, and guaranteed to match the Dockerfile's ARGs. Cost is
one `setup-python` + `pip install -e ".[dev]"` in that job (~40 s, pip cache shared with the backend
job); the scan itself is ~1 s over a two-file fixture.

**Skips are made loud rather than tolerated.** A plain `pytest` run skips these tests with a reason;
setting `SCRYE_TEST_REQUIRE_SCANNER_BINARIES` turns a missing binary into a failure, and CI sets it.
So the guard cannot degrade into a permanent silent skip — the failure mode that makes
binary-gated tests worthless.

**Open item for the repository owner, not a code change.** `protect-dev`'s
`required_status_checks` lists exactly two contexts — `Backend — lint + tests` and
`Frontend — lint + build` (see the ruleset table in the CodeQL entry above). `Image — build +
dogfood self-scan` is **not** among them, so this guard runs and reports red on every PR but does not
*block* a merge. Adding that third context to the ruleset would close the gap; it is a GitHub
Settings change and is recorded here rather than done silently.

#### Verification performed

Against the pinned binaries (`syft` 1.46.0, `grype` 0.115.0), downloaded and `sha256sum -c`-verified
against each release's own `checksums.txt`: all 7 tests pass; the full backend suite is
**734 passed, 5 skipped**; `ruff` and `black --check` clean. Confirmed by hand that a bare `pytest`
skips 6 of the 7 with a reason and that `SCRYE_TEST_REQUIRE_SCANNER_BINARIES=1` with no binaries
present turns those into hard errors.

Closes #135 (closed by hand — a `Closes` keyword in a PR body targeting `dev` never fires).

---

### 2026-08-02 — Post-v1 — Log redaction moved from the `LogRecord` to the formatted line; uvicorn's access logger stops raising on every request

**What changed:** `SecretRedactionFilter` (a `logging.Filter` that rewrote each record in place) is
replaced by `RedactingFormatter` (a delegating `logging.Formatter` that masks a handler's rendered
output) plus `install_redaction(handler)`, which wraps a handler's existing formatter idempotently.
`configure_logging()` now wraps the formatters of every handler on the root logger and on
`uvicorn`/`uvicorn.access`/`uvicorn.error` instead of attaching a filter to them. Redaction coverage
is unchanged in intent and slightly wider in fact; no pattern in `redact()` was touched.

**The bug.** Every uvicorn access log line raised
`TypeError: cannot unpack non-iterable NoneType object` inside
`uvicorn/logging.py::AccessFormatter.formatMessage` and printed a ~50-line `--- Logging error ---`
traceback in place of the line. The app was unaffected — `GET /healthz` returned 200 throughout,
because `logging` routes a formatting failure to `Handler.handleError()` and carries on — so the
only symptom was log volume. With the container healthcheck at 30s that is ~2,880 failures/day from
the healthcheck alone and roughly **144,000 lines/day** into Docker's json-file driver. On a host
with no rotation configured that is a disk-filling defect, not a cosmetic one.

**Cause, verified at the source rather than inferred.** Reproduced against real uvicorn 0.51.0 on
CPython 3.14.6 by replaying the actual startup order (`dictConfig(uvicorn.config.LOGGING_CONFIG)`,
then `configure_logging()`) and emitting the exact record uvicorn's access middleware emits; the
traceback matched the reported one line for line. Two independent facts collide:

1. `AccessFormatter.formatMessage()` does not use `record.getMessage()` at all. It unpacks
   `record.args` into `(client_addr, method, full_path, http_version, status_code)` and rebuilds
   `%(client_addr)s`/`%(request_line)s`/`%(status_code)s` from the pieces. The five-tuple **is** the
   record's payload.
2. `SecretRedactionFilter.filter()` normalized every record it saw to a pre-rendered string:
   `if redacted != message or record.args: record.msg = redacted; record.args = None`. Note the
   `or record.args` — the collapse fired on **every** record carrying args, redaction or not, so a
   plain `GET /healthz` line was destroyed just as surely as one containing a token.

That normalization is not gratuitous. A secret routinely straddles the msg/args boundary —
`log.info("password=%s", pw)` has neither `"password=%s"` nor `"hunter2"` matching `_KV_PATTERN` on
its own — so `redact()` can only work after `%`-interpolation, and putting the result back into a
record means collapsing `msg`/`args` and clearing `args`. **Record-level redaction and a formatter
that reads `record.args` cannot both be satisfied.** So the fix is the one the alternative implies:
redact the formatted output, not the record. Exempting the access logger was explicitly rejected —
access lines carry query strings that can hold an `api_token`/`access_token`, which is why
`uvicorn.access` was brought under redaction in the first place.

Redacting output is also strictly *more* complete than the record-level pass was: the access line's
`client_addr`/`request_line` fields are rebuilt from `args` and never appear in `getMessage()`, so
the old filter could not have masked a secret sitting in them even when it did not crash. Exception
tracebacks and `stack_info`, previously handled by pre-formatting `exc_text` inside the filter, now
fall out for free — they are part of what the inner formatter returns.

**Ordering requirement (why wrapping handlers is sufficient).** `uvicorn.Config.__init__` applies
`LOGGING_CONFIG` via `dictConfig` before `Config.load()` imports `app.main` and reaches
`create_app()` → `configure_logging()`, so uvicorn's handlers already exist when we wrap them. The
wrapping is idempotent (`isinstance(handler.formatter, RedactingFormatter)`) and re-applied on every
`configure_logging()` call rather than being gated behind the one-shot `_CONFIGURED` flag, which now
guards only the `basicConfig` half.

**The truncation this first shipped with, and why it is now fixed rather than accepted.** The
initial fix left a secret-bearing access line reading
`127.0.0.1:54076 - "GET /api/scans?api_token=[REDACTED]` — the tempered-greedy unquoted-value branch
consumed to end of line, taking the HTTP version and the status code with it, and that was written
up as the same trade-off M3/SEC-4 recorded. **That framing was wrong**, and the maintainer
rejected it before merge. Masking the token is the requirement; eating the rest of the line is
collateral from the pattern being greedy to EOL, not a security necessity — and an access log
without status codes cannot show a spike in 500s or someone probing for 401s, which is most of why
it is kept. Both properties are achievable at once.

**What makes them compatible: free text has no delimiter grammar, a query string does.** Redaction
now runs a bounded query-string pass *before* the general key/value pass, as a pair of patterns:

- `_URL_WITH_QUERY_PATTERN` — `(?:https?://|/)[^\s"<>?#]*\?[^\s"<>]*` — first identifies a token
  that genuinely is a URL or an absolute path carrying a query.
- `_QUERY_PARAM_PATTERN` — `[?&][\w.-]*(?:<secret names>)=[^&#\s"<>]*` — then masks the secret
  parameters *inside* that token.

The terminator set is structural, not heuristic. `&` separates parameters and `#` ends the query
component outright (RFC 3986 §3.4); whitespace, `"`, `<` and `>` cannot appear in a URI unencoded at
all, `"` being the one that matters in practice since uvicorn wraps the request line in double
quotes. `'` is deliberately **not** a terminator: it is a legal sub-delim, so treating it as one
could leave a byte of a secret behind — over-consuming a closing quote is the safe direction. And
`+ / = . - ~`, the characters base64url and JWT-shaped tokens are made of, are not terminators
either, so such a value is consumed whole.

**The anchoring is the load-bearing part, and it is what keeps SEC-4 closed.** Applying the
parameter rule to a whole line would treat any `?key=`/`&key=` appearing in prose as a query
parameter and stop the value at the first space — re-opening exactly the hole SEC-4 fixed (a spaced,
unquoted secret leaking its tail). The distinction that resolves it: **inside a URL a raw space is
impossible, so stopping there is correct parsing rather than truncation** — a value that really
contained a space arrives percent-encoded and is consumed whole. Outside a URL no such guarantee
exists, so the tempered-greedy rule still applies there and still runs to end of line. So
`?password=my secret phrase` in prose is redacted whole, while the same text inside a real request
path is not, because in a URL it cannot occur. Restricting the bounded rule to genuine URLs is what
lets both hold; **neither case has to lose.**

One consequence worth stating: an unencoded `&` inside a query value splits the redaction
(`?password=a&b` → `?password=[REDACTED]&b`). That is not a leak of anything the value owned — an
unencoded `&` *is* a parameter separator, so the receiving server splits at the same place. The
redaction agrees with the grammar rather than second-guessing it.

`_KV_PATTERN`'s unquoted branch gained one guard, `(?!\[REDACTED\])`, so the general pass cannot
re-consume — and thereby re-truncate — a value the query pass already masked. That also makes
`redact()` idempotent, which is pinned by a test.

**Verified against the case SEC-4 was written for.** `password=p@ss w0rd here`,
`api_key=abc,def`, `smtp_password: my mail pass 123` and `form dump was ?password=my secret phrase`
are all still redacted whole; `api_key=AKIA123 region=us` still bounds at the following structured
field. Those tests were untouched and pass unchanged.

**When it was introduced — it predates M3/SEC-4 and is not that entry's fault.** Two ingredients,
neither harmful alone:

| | Commit | Date | What it added |
|---|---|---|---|
| Latent | `3def52a` `feat(crypto): AES-256-GCM envelope encryption and log redaction` | 2026-07-03 | `record.msg = redacted; record.args = None` — harmless while the filter only sat on root handlers, since nothing reaching root reads `args` |
| Trigger | `f2806d6` `fix(security): remediate full-repo security audit findings` | 2026-07-04 | `_INDEPENDENT_LOGGERS` — attached the filter to `uvicorn`/`uvicorn.access`/`uvicorn.error` (the "Secrets/logging (§6)" bullet of the 2026-07-04 audit-remediation entry) |

The bug went live with the **second**, on 2026-07-04. **M3/SEC-4** (`8e100ee`, 2026-07-13, #64) only
rewrote the unquoted-value branch of `_KV_PATTERN`; it never touched `filter()` or the logger
wiring, and reverting it would not have fixed anything. It is a plausible suspect only because it is
the most recent change to this file. Everything from the 2026-07-04 remediation onward — v0.1.0 and
v0.2.0 both — shipped with it.

**Why CI never surfaced it, and why the Definition-of-done smoke check didn't either.** Three
compounding reasons, none of them an oversight in any single check:

- **Nothing in CI starts a uvicorn server.** `ci.yml` runs `ruff`/`black`/`pytest`, the frontend
  lint/Vitest/build, and an image build + Trivy/Grype self-scan. There is no run step, no
  `docker compose up`, no request against a live server.
- **The test suite cannot reach the code path.** `pytest` drives the app through FastAPI's
  `TestClient` (ASGI in-process). uvicorn's access middleware never runs, so no record with a
  five-tuple `args` is ever emitted, and `test_redaction.py` only exercised the filter against
  records it constructed itself.
- **Even a live smoke check would have passed.** DoD item 4 is "`docker compose up` brings the stack
  up and `/healthz` returns healthy" — and it did, every time. The failure is inside `Handler.emit`,
  which catches it, and the response is unaffected. A green healthcheck is exactly what a broken
  access logger looks like from the outside. The observable is stdout volume, which nothing asserts
  on.

The general lesson worth keeping: a defect confined to the logging layer is invisible to every check
that asserts on *behavior*, and a record-mutating `logging.Filter` is a shared-mutable-state hazard
precisely because the mutation is invisible until some other component reads the field you cleared.

**Regression coverage.** `TestUvicornAccessLogging` in `backend/tests/test_redaction.py` builds a
handler with the real `uvicorn.logging.AccessFormatter` and a `StreamHandler` subclass that records
`handleError()` calls (stock `logging` swallows them, so a naive test passes against the broken
code). It asserts that an access record formats without raising, that the exact expected line is
emitted, that `record.args` is still the five-tuple after formatting and that re-formatting is
stable, that a token in the query string is redacted **with the status code intact**, and —
mirroring real startup — that `configure_logging()` after `dictConfig(LOGGING_CONFIG)` leaves a
`RedactingFormatter` on every handler of root and the three uvicorn loggers. The suite was verified
to **fail** when `install_redaction` is swapped back for the old filter, so it is a real regression
gate. `test_redaction.py::TestRedactingFormatter` additionally pins that the record is *not*
mutated.

`TestQueryStringRedaction` covers the bounding: the status code survives a redacted query secret;
every secret in a multi-parameter query is masked (three secrets → three masks, with `page=2` and
the status line untouched); base64url/JWT/percent-encoded values are consumed whole; non-secret
parameters are left alone; full `https://` URLs work as well as bare paths; a free-text secret later
on the same line is still redacted to end of line; SEC-4's prose cases are unchanged; and `redact()`
is idempotent. Five of those eight, plus both access-logger assertions, were verified to **fail**
against the previous unbounded pattern. The three that pass under both are guards on behavior that
has to hold either way (non-secret parameters, the SEC-4 prose cases, idempotence) — they exist to
catch a future over-correction, not to detect this one.

**Plan section affected:** CLAUDE.md § Hard security rules ("Add a logging redaction filter" — still
satisfied, now implemented as a formatter). Supersedes the "Secrets/logging (§6)" bullet of the
2026-07-04 audit-remediation entry on the mechanism only; the coverage it describes is intact.
Amends the M3/SEC-4 bullet of the 2026-07-13 entry only insofar as `SecretRedactionFilter` no longer
exists by that name. No schema, security-model, or job-model change.

---

### 2026-08-02 — Post-v1 — OIDC account linking: authenticated self-link, guarded self-unlink, and stale-link detection (#114)

**What changed:** An existing local account can now bind itself to an OIDC identity by running the
existing authorization-code handshake **while signed in**, and can unbind itself again. Built at the
minimal scope green-lit on 2026-07-29 in `docs/upgrades/oidc-id-autoretrieval.md`, which is
**deleted in this PR** per the 2026-07-26 review-documents-retired decision — this entry is the
durable record.

**The premise correction that shaped it.** The request was "stop making the admin determine and
paste their OIDC subject during setup." Scrye never had a subject field anywhere — not in
`OidcConfigUpdateIn`, not in `AuthenticationPanel`, not in the users area. What that request was
really describing is the one gap the automatic binding leaves: **an existing local account, above
all the first admin, could not be linked to an OIDC identity at all.** The three available paths
were all bad — `auto_provision` on mints a duplicate account (`tyler` plus a fresh
`tyler-a1b2c3d4` at `default_role`); `auto_provision` off dead-ends at `not_provisioned`; or DB
surgery into `oidc_identities`, which requires determining `sub` by hand at the IdP. That last one
is not merely tedious: `sub` is the only identifier OIDC guarantees stable and unique per issuer,
and on **Authentik's default hashed subject mode** and **Entra ID's pairwise subjects** it is not
displayed anywhere and exists only inside tokens issued to our client. Auto-retrieval via a real
flow is the only generally correct way to obtain it — a correctness fix, not a convenience.

**Shape — one handshake, two terminal actions.** The link flow reuses `discover()`,
`generate_pkce_pair()`, `build_authorization_url()`, `exchange_code()`, and `verify_id_token()`
unchanged; only the terminal action differs. Deliberately the **same registered redirect URI**: a
separate `/link/callback` would make every operator register a second URI at their IdP, and
Entra/Keycloak reject unregistered ones — turning a UX fix into a reconfiguration chore.

- **Schema (migration `0009_oidc_link_flows`)** — two nullable columns on `oidc_login_flows`:
  `purpose` (`NULL` reads as `login`) and `user_id` (link flows only, FK → `users.id`). Backward
  compatible; existing rows keep their meaning. Written with `batch_alter_table` because SQLite has
  no `ALTER … ADD CONSTRAINT` — safe here since the table holds only in-flight handshakes with a
  10-minute TTL and is excluded from backup bundles.
- **`POST /api/auth/oidc/link`** — authenticated **cookie session** (not a bearer token: a link is a
  browser round trip a token can start but never finish), `require_csrf`, the shared auth rate
  limiter, the same `session_cookie_would_be_dropped()` transport refusal as login, and **fresh full
  re-auth** — then a `purpose='link'` flow row and an authorization URL. A POST rather than the
  public login GET, correctly: login binds no identity, link does.
- **Callback** — branches on `flow.purpose` after the shared validation. For a link it requires a
  live session whose user matches `flow.user_id`, checks the collision rules, inserts one
  `OidcIdentity` row, records `auth.oidc_identity_linked`, and redirects to a **fixed** settings
  path. It creates no session, assigns no role, runs no group sync, and does no provisioning.
- **`DELETE /api/auth/oidc/link`** — same gates, plus the stranding guard.
- **Frontend** — `OidcLinkCard` in Settings → Authentication (status, `last_login_at`, Link/Unlink,
  the re-auth form, the MFA warning), a post-save CTA on the OIDC form, and callback-result
  handling. `SettingsPage` opens the Authentication tab when the callback's query parameter is
  present, since `Tabs` is `keepMounted={false}` and an unmounted panel would never show the result.

**The invariants, since this is an identity-binding primitive and a bug here is admin account
takeover.** The subject is read from exactly one expression — `claims["sub"]` of a token that
passed `verify_id_token()` — and no request field, header, or query parameter carries a subject
anywhere in the design; it is not returned either, since an opaque blob nobody can compare is
noise. Linking is **insert-only** against `uq_oidc_identity_iss_sub`: an in-use identity is
refused explicitly, never re-pointed, and re-linking your own is a no-op success. The link path
grants nothing. And a stolen session alone can never create a login path, because the re-auth gate
costs the password and the second factor too. `tests/test_oidc_linking.py` carries one test per
abuse case **A1–A12** plus the new controls (42 tests).

**The cost, recorded rather than buried: linking widens L2/SEC-8.** SEC-8 — mandatory-MFA policies
enforced on local login only, OIDC delegating the second factor to the IdP — previously had a blast
radius of OIDC-*provisioned* accounts, which carry no usable local password and no local TOTP
enrollment, so there was nothing to bypass. A **linked** account is different: an admin with TOTP
enrolled who links gains a sign-in path on which their local TOTP challenge never runs, and their
effective second factor becomes whatever the IdP enforces. SEC-8 now reads "any linked account,
including MFA-enrolled admins." The compensating control is the **fresh full re-auth gate on link
and unlink** (current password + current TOTP when enrolled), which is why it is a hard requirement
and not a nicety: it is what stops a session-only attacker from minting the bypass path. Plus the
UI warning at link time, the existing `mfa_delegated_to_idp` marker on logins under a mandatory
policy, and the new `auth.oidc_identity_linked` / `_unlinked` events making the path's creation and
removal auditable. Documented in the README security model and `docs/ROADMAP.md`
§ Known limitations. **Rejected:** refusing to link MFA-enrolled accounts (it guts the feature for
exactly its target user, whose IdP likely runs passkeys/MFA stronger than Scrye's TOTP), and adding
a local TOTP step inside the OIDC handshake (already rejected when SEC-8 was accepted — it locks
out provisioned accounts and second-guesses the IdP).

**Stale links — the failure mode this feature would otherwise have introduced.** A link row is a
standing claim that `(issuer, sub)` keeps identifying the same person, and the IdP can break it
silently: an account deleted and recreated gets a fresh subject, and changing an **Authentik**
provider's subject mode **re-keys every user at once** from one un-warned toggle. The stale row
still renders "Linked ✓", so the next sign-in either mints a duplicate account (auto-provision on)
or dead-ends at `not_provisioned` — i.e. the operator experiences precisely the bug this feature
was built to remove, with the settings screen asserting everything is fine, and the
plausible-but-wrong diagnosis is "the linking feature regressed." So the login callback's
no-identity branch now checks, *before* provisioning or dead-ending, whether the token's configured
username/email claims match an account already holding a link for this issuer under a different
subject; if so it fails closed with `oidc_error=identity_stale`, records
`auth.oidc_identity_stale` (issuer, the existing row id, and which claim matched — never raw
subject values), and the login screen points at the README re-link runbook. This is a
**refuse-and-explain heuristic and never a binding**: auto-rebind on a claim match is the
account-takeover vector §5 of the scoping ruled out, and it stays ruled out. Fail-closed is the
worst an attacker extracts — someone at the same IdP who sets their email to the admin's converts
"get provisioned a viewer account" into "get an error," strictly safer than before.

**Two implementation choices worth naming, neither in the scoping doc:**

1. **The unlink stranding guard is two checks, not one.** The doc says unlink is "refused when the
   account has no usable local password." There is no such flag to test — an OIDC-provisioned
   account simply holds a random argon2 hash nobody knows — and adding one would exceed the
   sanctioned two-nullable-column schema change. That case is therefore enforced *by* the
   fresh-password gate, which such an account cannot satisfy by construction (covered by a test).
   The separately detectable stranding case — **local login disabled instance-wide**, where the
   link is the only way in — gets an explicit `409` with an explanation, rather than a `403` the
   operator would misread as a typo.
2. **A second subject for an already-linked issuer is refused** (`issuer_already_linked`) rather
   than accumulating a second identity row, so the re-link runbook has one unambiguous shape:
   unlink, then link.

Also added: `app/auth/reauth.py` (the shared gate plus `enforce_auth_rate_limit`, which
`api/auth.py::_enforce_rate_limit` now delegates to, so every password-checking surface shares one
limiter) and the `auth.reauth_failed` audit action.

**Explicitly not built** (and recorded in `docs/ROADMAP.md` so they are not re-proposed): an admin
binding an identity to *another* user — obtaining someone else's `sub` requires *them* to
authenticate at the IdP, so the future shape is an invite-link flow, not a text field; **any**
subject text-entry field anywhere; and **email-based auto-linking**, rejected outright as a
classic account-takeover vector (email is neither verified nor stable, and an IdP that lets users
self-set one turns "same email" into "attacker controls the admin account").

**Why:** The pain was real even though the premise was slightly off, and the fix reduces almost
entirely to controls Scrye already had — state + nonce + PKCE + browser binding + verified-token-only
subjects — plus two new ones (session-match at the callback, fresh full re-auth to link or unlink).

**Plan section affected:** §5 (OIDC/auth), §7 (data model — `oidc_login_flows` gains `purpose` and
`user_id`), §10.1 (README: link walkthrough, per-provider subject/claim table, re-link runbook,
security model). No locked decision changed; no job-model or distribution change.

---

### 2026-08-02 — Security/Process — Filesystem-gate symlink and TOCTOU residual risks closed out (neither is real); CodeQL advanced-setup migration assessed

**What changed:** Docs only. Two items: (1) the two residual risks the CodeQL entry below named "for
the record, not as proposed work" were verified against the scanners' actual behavior and are
**closed — neither is exploitable**; (2) the CodeQL advanced-setup migration was assessed and a
recommendation recorded. **No code, config, workflow, or scanner version changed, and no fix was
implemented.**

---

#### Item 1 — the symlink and TOCTOU residual risks on `resolve_filesystem_path()`

**Why this needed verifying rather than assuming.** The claim was that Grype's `dir:` walk might
follow a symlink planted *inside* an allowed root and read out-of-root files. That would be the same
class as **H1/SEC-1** — a route around the containment gate to arbitrary host files — which was the
headline HIGH of the remediation cycle. The gate is a pre-flight check on the *target argument*
(`backend/app/scanners/targets.py:138-146`); it is not re-applied during the walk, so the concern was
structurally plausible.

**Scope: there is only one code path.** Filesystem targets are **Grype-only**
(`backend/app/scanners/support.py:18` — `TargetType.FILESYSTEM: frozenset({Scanner.GRYPE})`), so
Trivy cannot run a filesystem target at all. The invocation is
`grype -o json -- dir:<resolved-path>` (`grype.py:50-68`, `:210-211`).

**Verdict: the symlink escape is not real.** Four independent lines of evidence:

1. **Version identity.** Grype 0.115.0's embedded Go build info records
   `github.com/anchore/syft v1.46.0` — the same Syft version Scrye pins, and the same binary tested
   standalone here. Grype's `dir:` source *is* Syft's directory source, so the Syft test exercises
   the identical walk code Grype runs.
2. **Mechanism, at the source.** Syft's directory provider defaults `base` to the scan directory
   itself — `basePath()` in `syft/source/directorysource/directory_source_provider.go:60-65`. A
   non-empty `base` activates chroot-style re-rooting in `addSymlinkToIndex`
   (`syft/internal/fileresolver/directory_indexer.go:362-406`): an absolute link target becomes
   `filepath.Join(base, Clean(target))`, and a relative one
   `filepath.Join(base, Clean(Join("/", dir, target)))`. Both collapse to a path **under the scan
   root**, so a link out of the root resolves to something that does not exist and is dropped.
3. **Empirically, five variants — none followed.** Planted inside an allowed root: an absolute
   symlink to an outside directory, a relative one (`../outside/sensitive`), an absolute symlink to
   an outside file, a relative one, and a symlink to `/etc`. A `package-lock.json` outside the root
   declared `lodash 4.17.15`; an identical in-root file declared `left-pad 1.3.0`. **Only `left-pad`
   was catalogued.** Debug logging shows exactly the re-rooting from (2): `escape` →
   `<root>/tmp/.../outside/sensitive`, `etc_escape` → `<root>/etc`, `rel_escape` →
   `<root>/outside/sensitive`, each followed by *"points to unresolved path …, ignoring target as new
   root."*
4. **Trivy agrees.** `trivy fs --scanners secret` over the same fixture reported only the two real
   in-root files and no out-of-root path. Not reachable in Scrye, but the answer does not differ
   between the scanners.

**A comment in that code says the opposite — do not stop reading at it.** `indexAllRoots`
(`directory_indexer.go:66`) is introduced with *"why account for multiple roots? To cover cases when
there is a symlink that references above the root path, in which case we need to additionally index
where the link resolves to."* Read alone, that says the escape is real. It is not, because the
re-rooting in `addSymlinkToIndex` runs **first**, so an out-of-root target never becomes a new root.
The comment describes an intent the surrounding code no longer implements. Behavior was measured;
the comment was not trusted.

**The load-bearing caveat, and the one thing worth acting on — now tracked as [#135](https://github.com/tyler-rich/Scrye/issues/135).**
The containment rides entirely on `basePath()` defaulting `base` to the scan location — a function
upstream annotates:

```go
// FIXME why is the base always being set instead of left as empty string?
```

If that FIXME is ever actioned, `base` becomes `""`, the re-rooting branch is skipped
(`directory_indexer.go:374`), and `indexAllRoots` *would* add out-of-root symlink targets as new
roots. **The escape would become real silently, on a routine Grype/Syft version bump, with no code
change on Scrye's side.** Nothing in this repository would notice. A regression test — plant a
symlink in a temp root, assert the out-of-root package is absent from Grype's output — would pin the
behavior to the dogfood/test suite and fail loudly on the bump that changes it. **Opened as
[#135](https://github.com/tyler-rich/Scrye/issues/135) on 2026-08-02; not implemented here.** That
issue carries the mechanism, the `FIXME` reference, the inventory-disclosure severity ceiling (so it
is not later mis-rated against H1/SEC-1), and the positive-control requirement the false-negative
below taught. **Built later the same day** as
`backend/tests/test_scanner_symlink_containment.py` — see the entry above, which records why Syft
rather than Grype is the probe and where in CI it runs.

**Hardlinks are followed, and that is fine.** A hardlink from inside an allowed root to a file
outside **is** read — demonstrated: `lodash 4.17.15` catalogued via `/sub/package-lock.json`, same
inode as the outside file. This is not a containment bypass. A hardlink is a second name for one
inode, not a reference that containment could resolve; creating one requires write access inside the
root **and** read access to the source (the kernel's `fs.protected_hardlinks`, normally `1`, blocks
linking files you cannot read), and it cannot cross filesystems — so `/data/app_secret_key` on the
data volume can only be linked from within that same volume. Anyone who can do it could already read
the file.

*Methodology note, because the first result was wrong:* the initial hardlink probe came back negative
only because the planted file was named `hardlink-lock.json`, which the JavaScript cataloger does not
glob. Renaming it to `package-lock.json` flipped the result to positive. **A negative from a
cataloger-based probe means nothing unless the filename is one the cataloger actually looks for.**

**Impact ceiling — this class cannot reproduce H1/SEC-1, even if an escape existed.** Grype `dir:`
output carries **no file contents**. The SBOM's `files` entries expose `digests`, `id`, `location`,
and `metadata` only; a marker string planted in a hardlinked secret file **never appeared anywhere in
the output**. So the worst case here is disclosure of package inventory and file digests — not secret
values. H1/SEC-1's severity came from `trivy repo <local path>` surfacing secret *contents* as
downloadable scan output; that is a different and strictly worse primitive. Any future finding in
this area should be severity-rated against inventory disclosure, not against H1/SEC-1.

**TOCTOU: mechanism confirmed, not exploitable.** The window is real —
`NormalizeRootDirectory` calls `filepath.EvalSymlinks(root)` at scan time
(`chroot_context.go:69-75`), so a target directory swapped for a symlink between the worker's
`resolve_filesystem_path()` (`backend/app/workers/inprocess.py:560`) and the walk **would** be
followed, with `base` becoming the new real path — the containment above would then protect the
attacker's substituted root rather than the configured one. What makes it non-exploitable is the
preconditions, all of which must hold at once:

- **Filesystem scanning must be switched on at all.** `filesystem_scan_roots` defaults to empty
  (`config.py:243`), which disables the feature.
- **Host write access to the parent of the scan target.** The attacker must be able to replace the
  directory with a symlink — i.e. they already have write access to a host path the admin
  deliberately mounted and allowlisted.
- **A concurrent operator-triggered scan.** `POST /api/scans` requires the `operator` role and
  passes CSRF (`scans.py:79`, `:159-166`); `operator` is rank 1 of 3 (`db/models/user.py:28`).
- **Winning a sub-second race** between the worker's re-check and the subprocess `exec`.

And the payoff is still package inventory, not file contents. Closing it properly would require
handing the scanner an already-opened directory handle (`O_PATH`/fd) rather than a path string, which
the subprocess interface — `grype … dir:<path>` — cannot express. **Accepted as a documented residual
risk; no work proposed.**

**Both risks are closed by this entry.** The prose in the CodeQL entry below that named them is
superseded; do not re-open either without new evidence about scanner behavior, and re-verify against
the pinned Grype/Syft versions if those move.

---

#### Item 2 — should CodeQL move to advanced setup for trigger control?

**Recommendation: migrate, and do it together with a one-line ruleset edit. No sequencing dependency.**

> **Corrected 2026-08-02 (same day), after reading the `protect-dev` ruleset via the API.** This
> section originally recommended migrating *after* the branch-protection governance item, on the
> premise that "until branch protection lands, a CodeQL check on a `dev` PR cannot block a merge."
> **That premise was wrong** — branch protection on `dev` had already landed. The conclusion survives
> for a sharper reason, but the sequencing does not. Both are corrected in place below, and the
> superseded argument is marked withdrawn rather than deleted.

**Correcting the premise first.** The concern was that in a dev-first workflow, findings "arrive after
code is already published to `:latest`." That is **not** what happens for `:latest`. Publishing is
triggered by a **semver tag push**, not by the promotion merge (`publish.yml`, locked decision §6),
so the sequence is: promotion merges to `main` → CodeQL runs on push to `main` (~1 min) → someone
pushes the tag → publish. Unless the tag is pushed within about a minute of the merge, CodeQL
findings land *before* `:latest` exists. The premise **is** correct for **`:dev`**: `dev-nightly.yml`
builds and pushes `:dev` from a branch CodeQL never analyses. So the real published-artifact gap is
`:dev`, not `:latest`.

The gap that actually justifies migrating is simpler and doesn't depend on publishing at all:
**CodeQL never sees a change while it is still reviewable.** It runs after a promotion has landed on
`main`, at which point the code is merged and a revert — not a review comment — is the remedy.

**What the workflow needs, and whether the suite is reproducible.** Confirmed at the source, not from
docs: `github/codeql-action/init` exposes a `queries:` input, and `security-extended` is a member of
`defaultSuites` in `src/analyze.ts:361-367`, resolved by `resolveQuerySuiteAlias()` to
`<language>-security-extended.qls`. So `queries: security-extended` in a committed workflow
reproduces **exactly** what runs today. The workflow would need: SHA-pinned `init` + `analyze` (repo
convention, H9/SC-2), `permissions:` narrowed to `security-events: write`, `contents: read`,
`actions: read`, a three-entry language matrix (`python`, `javascript-typescript`, `actions`), and
`on: pull_request` + `push` for **both** `dev` and `main`.

**CI cost: effectively zero added wall-clock — measured, not estimated.** The first CodeQL run's
longest job was **62 s** (javascript-typescript; python 56 s, actions 41 s, all parallel). The
current PR pipeline's longest job is **121 s** (image build + dogfood self-scan), with a 130 s
wall-clock across all four. CodeQL's jobs run in parallel with those and finish at roughly half the
time of the critical-path job, so **the PR gate stays bounded by the image build either way**. Money
cost is zero — the repository is public, so Actions minutes are free. A schedule-plus-PR trigger is
*not* better here: the whole point is per-PR feedback, and the marginal cost of per-PR is nil.

**Maintenance cost: near zero marginal, contrary to expectation.** `github/codeql-action` ships
frequently — **40 `v4.x` releases between 2025-10-07 and 2026-07-30**, roughly four a month — which
looks like exactly the churn this repo has been managing. It is not, because
`.github/dependabot.yml` already **groups every `github-actions` bump into a single weekly PR**
(`groups: github-actions: patterns: ["*"]`, `interval: weekly`). `codeql-action` would become one
more line in a PR that already exists, not a new stream. The honest cost is that the grouped weekly
PR becomes non-empty more often than it is today.

**What migrating actually loses — less than assumed.**

- **Managed query-pack updates are *not* lost.** This is the misconception worth naming: advanced
  setup pins the **action**, not the CodeQL bundle. `init`'s `tools:` input defaults to *"the
  recommended version of the CodeQL Bundle"*, so query packs keep updating on GitHub's schedule
  exactly as they do now. Pinning the action does not freeze the queries.
- **Automatic language detection *is* lost.** The matrix becomes explicit. Note that default setup's
  auto-detection is what silently added the third language (`actions`) in the first place — a real
  freebie that an explicit matrix would not have produced. Against that: locked decision §2 fixes the
  stack, so a new language appearing unnoticed is close to impossible, and the matrix should carry a
  comment tying it to §2.
- **A fifth workflow to own.** It can break in ways a GitHub-managed one cannot, and CLAUDE.md
  § Build performance warns that workflow shapes here are load-bearing. The repo already maintains
  four workflows and a composite action, so this is familiar rather than new capability.

**What the `protect-dev` ruleset actually says (read via `GET /repos/…/rulesets/18504510`).** The
premise that branch protection on `dev` is "still open" does not survive contact with the API.
`protect-dev` is **`enforcement: active`** on `refs/heads/dev` and carries four rules:

| Rule | Parameters that matter |
| --- | --- |
| `pull_request` | 1 approving review, `dismiss_stale_reviews_on_push`, `required_review_thread_resolution`, `allowed_merge_methods: ["squash"]` |
| `required_status_checks` | **exactly two contexts** — `Backend — lint + tests`, `Frontend — lint + build`; `strict_required_status_checks_policy: false` |
| `deletion` | — |
| `non_fast_forward` | — |

So "Require status checks to pass" **is** live on `dev`. That kills the original sequencing argument.

**But the conclusion survives, for a sharper reason: `required_status_checks` is an explicit
allowlist of contexts, not a switch.** The list names two jobs. Neither image job is on it — note
`Image — build + dogfood self-scan` and `Image — multi-arch build check` run on every PR and are
**not** required — and a migrated CodeQL workflow's contexts (`Analyze (python)` &c.) would not be on
it either. CodeQL would run, be visible, and go green or red **without blocking a merge**, until
someone adds its contexts to that list.

The difference from the original claim is the size of the remedy. "Wait for branch protection" framed
it as a governance project; in fact it is **adding two or three strings to a ruleset that already
exists**, done at the same time as the migration. There is no reason to sequence one behind the
other.

**Does the admin bypass change the answer? Only for one of the two things "required" buys.** For the
repository owner it changes little — an actor who can bypass the ruleset can merge past any required
check, so "required" is not an enforcement boundary against that person. What it still buys:

1. **Real enforcement for anyone who is not that actor.** The repo is public and `CONTRIBUTING.md`
   invites external contributions; for a contributor, a required check is a hard stop.
2. **A deliberate bypass instead of a silent merge.** This is the part that matters most here,
   because this project has already documented itself normalizing red: the same §14
   (2026-07-31, flaky cancellation test) records that *"a test that reddens CI intermittently trains
   everyone to re-run without reading the failure"*, and warns that the habit costs most on a
   security tool. A visibly-red-but-optional check is exactly the artifact that habit erodes. Making
   it required does not stop an admin, but it converts "merge anyway" from a non-event into an
   explicit act.

So: **a visibly-red check is not sufficient on its own**, not because of what the ruleset can enforce
against an admin, but because this repository has written down that it stops reading advisory red.
Required-ness is worth having even where it is bypassable.

*Not independently confirmed:* the API returns `bypass_actors: null` and
`current_user_can_bypass: "never"` for **both** rulesets, but that reflects *this session's token
identity*, not the repository admin's — the bypass list is not readable at this permission level.
Taking as given the maintainer's statement that Repository admin has *Always allow*, corroborated by
§14 (2026-08-02), which records `dev` being deleted during the v0.2.0 promotion **despite** the
`deletion` rule above being active.

**One operational hazard if CodeQL's contexts are made required.** A required context that never
**reports** blocks a PR indefinitely. A job skipped by an `if:` condition still reports a `skipped`
conclusion and satisfies the requirement — that is why `Image — multi-arch build check` showing
`skipped` on these PRs is harmless — but a *workflow that never triggers* reports nothing at all. So
if the CodeQL workflow's contexts go on the required list, it must not carry `paths:`/`paths-ignore:`
filters, or a docs-only PR will hang forever waiting on a check that was never scheduled. Given the
suite runs in ~60 s and costs nothing on a public repo, the right answer is simply not to add path
filters.

**The case against this recommendation**, stated plainly because it is not weak:

- **The empirical yield so far is 0 true positives in 6 alerts.** Every finding from the first run
  was a false positive, three of them in test files. Paying any ongoing complexity for a check with
  that hit rate is a bet on future regressions, not a response to demonstrated value. One more
  scheduled run on `main` would have caught the same nothing.
- **The `:latest` exposure argument does not survive contact with `publish.yml`** (above). Strip it
  out and what remains is "findings arrive post-merge instead of pre-merge" — a real but ordinary
  workflow-quality complaint, not a security gap.
- ~~**Branch protection is still open.**~~ **Withdrawn — this argument was factually wrong.** See
  the ruleset findings below: `protect-dev` is active and already requires status checks. The
  surviving version of the point is much weaker: CodeQL's contexts would not be on the required list
  *initially*, and putting them there is a settings edit made alongside the migration, not a
  prerequisite for it.
- **Default setup keeps giving things away for free** — the `actions` language arrived without being
  asked for, and future additions would too. An explicit matrix ends that.

**On balance:** migrate whenever convenient, and **add the CodeQL contexts to `protect-dev`'s
required-checks list in the same change** — that is what turns it from advisory decoration into a
gate, and it is a settings edit, not a project. Treat the **`:dev`** coverage hole, not `:latest`, as
the concrete thing being fixed. **Not implemented in this session; the decision is the maintainer's.**

---

#### Follow-up (same day) — the two ruleset gaps tracked, and one checklist item found already done

**The ruleset readout above produced two settings-level gaps. Both are now issues, not prose**, on
the same reasoning that created the governance checklist in the first place: a settings gap leaves no
artifact in the repository, so if it is not tracked it is invisible.

- **[#136](https://github.com/tyler-rich/Scrye/issues/136) — `Image — build + dogfood self-scan` is
  not a required status check**, on either ruleset, so a PR can merge into `dev` with the dogfood
  scan red. That job is the control CLAUDE.md § Dependency hygiene mandates; it is what caught
  CVE-2026-5773, what verifies the SC-14 dev-tree exclusion (`ci.yml:171`), and what demonstrates the
  seven waived interpreter CVEs (#98 ×3, #116 ×3, #52 ×1) are the *only* outstanding findings — a
  guarantee that is unverifiable if the gate can be merged past. Safe to require: the job has no
  job-level `if:` and `ci.yml` carries no `paths:` filters, so it always reports.
  `Image — multi-arch build check` is a different case — it is `if:`-conditioned to skip on `dev` PRs
  (`ci.yml:316`), so requiring it on `protect-dev` would be vacuous; require it on `protect-main`
  only, if at all.
- **[#137](https://github.com/tyler-rich/Scrye/issues/137) — no ruleset restricts tag pushes.** Both
  rulesets are `"target": "branch"`; there is no tag-targeted ruleset. A `v*.*.*` tag push triggers
  `publish.yml` — multi-arch build, GHCR push, the `:latest` move, and a GitHub-signed provenance
  attestation plus SBOM (`publish.yml:23-26`, `:52-56`). Every *branch* route to the published
  artifact is gated; the *tag* route, which is the one that actually publishes, is not. `publish.yml`
  does bound the blast radius on its own — the `github.repository ==` guard (`:46`) and the
  `git merge-base --is-ancestor` main-ancestry check (`:73`) mean an arbitrary tag on an arbitrary
  commit does not publish — but neither constrains *who* may tag, or which main-reachable commit gets
  promoted to `:latest`, and nothing prevents a release tag being moved or deleted afterwards.
  Theoretical with a single maintainer; the resolution trigger is **before any collaborator is
  added**, because that is precisely the moment nobody re-audits ref rules.

**Split into two issues rather than one**, following the #98/#116 precedent that an issue closes on
its own trigger: #136 is actionable now and closes on a settings edit; #137 is latent and closes on
an event that may be far off. One issue could not close on both.

**Separately, a checklist item was found already done.** `docs/ROADMAP.md` listed *"Private
vulnerability reporting — enable in the repo's Security settings"* as open;
`GET /repos/tyler-rich/Scrye/private-vulnerability-reporting` returns **`{"enabled": true}`**. It is
now struck. When it was enabled is not recorded anywhere — it may have been on since the repository
went public and simply never removed from the list. That is the same drift the checklist exists to
prevent, arriving from the opposite direction: not a settings change that went unrecorded, but a
completed item that stayed listed as outstanding. **Verify checklist items against the API before
working them, not just before closing them.**

By contrast, **signed-commit enforcement is confirmed genuinely open** — neither ruleset carries a
`required_signatures` rule.

**Attribution footers on issues could not be removed.** Per this environment's convention the issue
bodies were authored with the Claude Code footer; a subsequent `PATCH` to strip it from #135 was
re-appended by the same ingress layer that does this to the PR body (§14 records the same behaviour
there). #135, #136, and #137 therefore each carry a trailing
`_Generated by [Claude Code](https://claude.ai/code)_` that has to be deleted by hand in the GitHub
UI to match #98/#116. Noted here so the inconsistency is explained rather than looking like a style
lapse.

**Plan section affected:** §14 (this record); §4/§6 (filesystem-scan gate — verified, unchanged);
`docs/ROADMAP.md` § Near-term (the CodeQL item's remaining work, and the governance checklist —
branch-protection re-scoped, private vulnerability reporting struck). Issues #135, #136, #137
opened. No code, schema, workflow, or locked-decision change.

---

### 2026-08-02 — Security/Process — CodeQL code scanning enabled via default setup; first-run triage: six alerts, all false positives

**What changed:** GitHub **code scanning (CodeQL) was enabled on 2026-08-02** via **default setup**.
This entry records the enablement, why default was chosen over advanced, and the full triage of the
first scan. **Nothing was fixed, dismissed, or excluded** in this session — it is docs-only, and the
disposition of every alert is left to the maintainer.

**What the first run actually was.** Run
[30731557142](https://github.com/tyler-rich/Scrye/actions/runs/30731557142), `dynamic` event,
`main` @ `bb354a5` (the v0.2.0 promotion merge), 2026-08-02 03:59 UTC, 67 s wall-clock, all jobs
green. CodeQL CLI **2.26.2**, `codeql-action` **4.37.4**, query packs `python-queries` **1.8.7** and
`javascript-queries` **2.4.2**.

**The suite is `security-extended`, not the default `code-scanning` one.** This is worth stating
because it is easy to assume otherwise — "default setup" names the *setup mode*, not the query suite,
and the suite is a separate dropdown in the same settings pane. The evidence is exact rather than
inferred: the Python job interpreted **52** queries, `python-code-scanning.qls` resolves to **45**,
and `python-security-extended.qls` resolves to **52** — and the runner's 52 interpreted query paths
are a **set-identical** match to `security-extended`'s resolved list (zero on either side of the
diff). The same distinction exists for the other two languages (`javascript`: 89 vs 105; `actions`:
18 vs 24), though it changes nothing there, since both return zero findings under either suite.
Anyone reproducing this analysis must pass `*-security-extended.qls` or they will silently run a
smaller query set — see the reproduction note below, where exactly that happened.

**Default setup enabled *three* languages, not the two that were scoped.** The roadmap item asked
for Python and TypeScript; language auto-detection also added **`actions`** (the workflow-analysis
pack), so the run has three analyze jobs: `Analyze (python)`, `Analyze (javascript-typescript)`,
`Analyze (actions)`. That is a gain, not a problem — the repo's five workflow files are now analysed
for the Actions-specific query set (untrusted checkout, script injection, artifact poisoning) that
the SHA-pinning work of H9/SC-2 + H10/SC-3 addressed by hand — but it is worth knowing the third
language is there before anyone reasons about which jobs a PR check covers.

**Coverage was total; nothing was skipped.** The runner reported *"CodeQL scanned 78 out of 78
TypeScript files, 5 out of 5 GitHub Actions files and 2 out of 2 JavaScript files"* and 174 Python
files. There is no vendored or generated tree in this repository, so no path filters were needed and
none were configured.

**Why default setup over advanced.** The roadmap item left this open and said to prefer advanced *if
paths need excluding*. They do not, and three things pointed the other way:

- **Managed action versions and query packs.** Advanced setup means a committed
  `.github/workflows/codeql.yml` pinning `github/codeql-action/*` by SHA, which this repo's
  convention would then require Dependabot to keep current — a fourth workflow and a recurring bump
  stream in exchange for control this repo has no use for. Default setup has GitHub track the action
  and pack versions.
- **A conventional layout that needs no custom queries or path filters.** Note that *choosing the
  query suite is not an advanced-setup exclusive* — default setup exposes a Default/Extended
  dropdown, and this repository is on **Extended** (above). What advanced setup alone buys is custom
  query packs, path filters, and control over the trigger. Coverage is already 100% of every source
  file, and there is no generated or vendored code to exclude, so the first two do not apply. (The
  third turns out to matter — see the `dev`-PR note near the end of this entry, which was discovered
  after this decision was made.)
- **The configuration lives in repository settings, and *this entry* is its durable record.** Default
  setup's config is not a file in git, which puts it in the same class as the branch rulesets and the
  Dependabot security-update routing: a setting that leaves no artifact in the repository. §14 is
  where that class of change is recorded — see the 2026-08-02 governance-checklist entry, which
  exists precisely because settings work had been sitting invisible. **If path filters, custom queries, or a different
  trigger are ever needed, converting to advanced setup is the trigger to revisit this**, and it can
  be done without losing alert history.

**How this triage was performed, including the mistake in the first pass.** The session token used
here carries only `metadata=read`, so `GET /repos/tyler-rich/Scrye/code-scanning/alerts` and
`.../analyses` both return **403 "Resource not accessible by integration"**. The alerts could not be
read from the API. Instead the analysis was **reproduced locally at the same commit**:
`codeql-bundle-v2.26.2` (the exact CLI the run used, hence the exact `python-queries` 1.8.7 /
`javascript-queries` 2.4.2 packs), databases built from a worktree at `bb354a5`.

**The first reproduction used the wrong suite and under-reported by one alert.** It ran
`*-code-scanning.qls` on the assumption that "default setup" implies the default suite. That is 45 of
the 52 Python queries, and the 7 it omits are `py/log-injection`, `py/tarslip`, `py/partial-ssrf`,
`py/shell-command-constructed-from-input`, `py/jinja2/autoescape-false`, `py/overly-permissive-file`,
and `py/request-without-cert-validation`. It therefore produced **five** findings and missed **#6**
below. The gap was caught only when the Security tab was seen directly and showed six. Two lessons,
both of which this repository has learned before in other forms: **a reproduction is not equivalent
until its query set is checked against the run's**, and **matching file-extraction counts prove
nothing about query coverage** — the first pass matched the runner's 174/78/5 file counts exactly
while running seven fewer queries.

The corrected run uses `*-security-extended.qls` and reproduces the Security tab **exactly**: six
findings, same rules, same files, same lines, same severities. Extraction coverage also matches the
runner file-for-file (**174 `.py`**, **49 `.tsx` + 29 `.ts` = 78 TypeScript**, **5 workflow `.yml`**).
`main` and `dev` have **no** differing `.py`/`.ts`/`.tsx` files at this point, so the reproduction is
equally valid for `dev`. The alert numbers below are the real ones, read off the Security tab.

**Result: 6 alerts, all Python. 0 JavaScript/TypeScript. 0 Actions.**

| Alert | Rule | Location | GitHub severity | Verdict | Recommended disposition |
|-------|------|----------|-----------------|---------|-------------------------|
| #1 | `py/path-injection` | `backend/app/scanners/targets.py:138` | High (7.5) | **False positive** | Dismiss — "Used in tests" is wrong; use **"False positive"** with the reasoning below |
| #2 | `py/path-injection` | `backend/app/scanners/targets.py:144` | High (7.5) | **False positive** | Dismiss — **"False positive"**, same reasoning |
| #3 | `py/incomplete-url-substring-sanitization` | `backend/tests/test_credentials.py:320` | High (7.8) | **False positive** | Dismiss — **"Used in tests"** |
| #4 | `py/incomplete-url-substring-sanitization` | `backend/tests/test_dockerfile_supply_chain.py:71` | High (7.8) | **False positive** | Dismiss — **"Used in tests"** |
| #5 | `py/incomplete-url-substring-sanitization` | `backend/tests/test_redaction.py:120` | High (7.8) | **False positive** | Dismiss — **"Used in tests"** |
| #6 | `py/log-injection` | `backend/app/api/scans.py:574` | Medium (6.1) | **False positive** | Dismiss — **"False positive"** |

**Counts by severity: 5 High, 1 Medium, 0 Critical, 0 Low.** The five Highs read worse than they are
— GitHub derives severity from each *rule's* `security-severity` property (7.5 and 7.8, both in the
7.0–8.9 band), which is a property of the query, not of the match.

---

#### Alerts #1 and #2 — `py/path-injection`, `backend/app/scanners/targets.py:138` and `:144`

**The flagged code** is `resolve_filesystem_path()` (`backend/app/scanners/targets.py:119-146`) — the
filesystem-scan containment gate:

```python
resolved = Path(target).resolve()                                     # line 138  ← sink 1
within_root = any(
    resolved == (root := Path(raw).resolve()) or root in resolved.parents for raw in roots
)
if not within_root:
    raise TargetError("The target path is not under an allowed filesystem scan root.")
if not resolved.is_dir():                                             # line 144  ← sink 2
    raise TargetError("The target path does not exist or is not a directory.")
return str(resolved)
```

CodeQL's reported flow is `scans.py:161` (the `ScanCreateIn` request body) → `scans.py:200` →
`targets.py:119` → the two sinks.

**Why the code is correct.** The check canonicalizes first (`Path.resolve()` collapses `..` *and*
resolves symlinks along every component) and only then tests containment, using **`root in
resolved.parents`** — a component-wise membership test on path objects, not a string comparison. That
ordering and that idiom are what make it sound:

- `/allowed/../etc/shadow` resolves to `/etc/shadow` before the check runs, so it fails containment.
- A symlink at `/allowed/link → /etc` resolves to `/etc` before the check runs, so it fails too.
- `/data/scans-evil` is **not** accepted against a root of `/data/scans`: `Path('/data/scans-evil')
  .parents` is `[/data, /]`, which does not contain `/data/scans`. A `startswith` check on the same
  two strings would wrongly accept it.
- The feature is **off** unless an admin sets `SCRYE_FILESYSTEM_SCAN_ROOTS` (`filesystem_scan_roots`
  defaults to an empty list, `backend/app/core/config.py:243`), in which case line 138 is never
  reached at all — the empty-roots branch raises first.
- The reported "user-provided value" is an **authenticated operator**: `POST /api/scans` requires
  `require_csrf` *and* the `_operator` role dependency (`backend/app/api/scans.py:159-166`).
- The check runs **twice** — at request time (`scans.py:200`, 422 on failure) and again in the worker
  (`backend/app/workers/inprocess.py:560`), so a row edited between queue and execution is re-gated.
- Coverage exists: `backend/tests/test_targets.py:88-111` asserts disabled-by-default, out-of-root
  rejection, and in-root acceptance.

Sink 2 (`resolved.is_dir()`, line 144) sits **after** the containment check, so it is not even an
existence oracle for out-of-root paths — an out-of-root target raises at line 143 and never reaches
it.

**Why CodeQL is wrong here, specifically.** This is not "the analyzer was cautious"; the query
**cannot** clear this code as written, and the reason is mechanical. `PathInjectionQuery.qll` is a
two-state configuration:

1. A source starts in state `NotNormalized`.
2. Only a `Path::PathNormalization` node moves it to `NormalizedUnchecked`.
3. Only a `Path::SafeAccessCheck` barrier clears `NormalizedUnchecked`.

In `python-all` 7.2.2, `Path::PathNormalization::Range` has exactly **three** implementations —
`os.path.normpath`, `os.path.abspath`, `os.path.realpath` (`semmle/python/frameworks/Stdlib.qll`
:1108, :1118, :1128). **`pathlib.Path.resolve()` is not one of them.** It appears in that file only
as a Path-returning method (`pathlibPathMethod`, :2623) and as a *file-system access* whose
vulnerable path argument is its receiver (`PathlibFileAccess`, :2713-2731) — which is precisely why
`Path(target)` on line 138 and `resolved` on line 144 are the two reported sinks.

So the taint **never leaves `NotNormalized`**, and step 3's barrier is unreachable for this code *no
matter what check is written between the two lines*. The containment logic is invisible to the query
by construction.

And even if `resolve()` had been modelled as a normalization, it would still not have helped: the
only `Path::SafeAccessCheck::Range` implementation in the whole pack is **`str.startswith`**
(`Stdlib.qll:5134`). This code deliberately does not use `startswith`, because `startswith` is the
idiom with the `/data/scans` vs `/data/scans-evil` prefix-confusion bug described above. **The code
is flagged because it avoided the buggy pattern that is the analyzer's only recognized safe one.**

**Overlap with already-resolved work — do not re-litigate this.** These two alerts land on the exact
control that two prior §14 entries deliberately built and then deliberately kept:

- [2026-07-03 — Phase P3 — Filesystem scans gated behind an allowlist](#2026-07-03--phase-p3--filesystem-scans-gated-behind-an-allowlist)
  is where this function and `SCRYE_FILESYSTEM_SCAN_ROOTS` came from, and why "empty = feature off".
- [2026-07-13 — H1/SEC-1 (#53)](#2026-07-13--post-release--h1sec-1-repository-scan-targets-must-be-remote-clone-urls-local-path-arbitrary-read-closed-back-fill)
  closed the `trivy repo <local path>` route **around** this gate and records the decision that
  `SCRYE_FILESYSTEM_SCAN_ROOTS` is the **sole** way any scan can be pointed at a local path. That was
  the headline HIGH of the security-review batch; the design that came out of it is the design CodeQL
  is now flagging.

Accepting a local path *under an admin-configured root* is the feature, not the vulnerability. The
open question H1/SEC-1 settled was whether any **other** code path could reach local paths, and the
answer was made "no."

**Residual risk worth naming (neither is what CodeQL found, and neither is new).** (a) A TOCTOU
window exists between the check and the scanner subprocess reading the directory — a symlink swapped
in that window is not caught. (b) Grype's `dir:` walk of an allowed root may follow symlinks that
point outside it; containment covers the *target*, not the tree beneath it. Both are properties of
handing a directory to an external scanner, both require local write access inside an
admin-configured root, and neither is reachable by an API caller. Recording them here so they are on
the record, not proposing work.

> **Superseded 2026-08-02 — both verified and closed; (b) was wrong.** Grype/Syft do **not** follow a
> symlink out of the scan root: Syft re-roots every link target under the scan directory, so (b) does
> not happen at the pinned versions. (a) is a real mechanism but is not exploitable. See
> [the entry above](#2026-08-02--securityprocess--filesystem-gate-symlink-and-toctou-residual-risks-closed-out-neither-is-real-codeql-advanced-setup-migration-assessed)
> for the evidence, the hardlink case that *is* followed (and why it is not a bypass), and the
> upstream `FIXME` that makes the containment worth pinning with a regression test.

---

#### Alerts #3, #4, and #5 — `py/incomplete-url-substring-sanitization`, all three in `backend/tests/`

The three flagged lines:

- `backend/tests/test_redaction.py:120` — `assert "ghcr.io" in output`
- `backend/tests/test_credentials.py:320` — `assert "git.example.com" in strip_url_credentials(text)`
- `backend/tests/test_dockerfile_supply_chain.py:71` — `assert "token.actions.githubusercontent.com" in text`

**What the query is for.** A real `py/incomplete-url-substring-sanitization` catches a broken host
check — `if "example.com" in url:` accepts `https://evil.com/?x=example.com` and
`https://example.com.evil.com`. That is a genuine and common bug.

**Why it is wrong about all three.** Read the query
(`Security/CWE-020/IncompleteUrlSubstringSanitization.ql`) and the reason is unambiguous: it is
**purely syntactic**. Its entire condition is a `Compare` using the `In` operator whose left operand
is a `StringLiteral` matching a hostname-shaped regex. There is **no dataflow, no requirement that
the right-hand operand is a URL, and no requirement that the comparison's result is used in a
security decision at all.** Any `"<something>.com" in <anything>` matches.

None of the three right-hand operands is a URL, and none of the three comparisons is a check:

- `output` in `test_redaction.py` is **captured log text** from a `logging` stream handler. The
  assertion's job is the opposite of sanitization: it proves the redaction filter *preserved* the
  non-secret context (`ghcr.io`) while consuming the adjacent secret. Rewriting it as an exact-host
  comparison would break the test's purpose.
- `strip_url_credentials(text)` in `test_credentials.py` returns a **redacted log line**
  (`"cloning https://deploy:tok@git.example.com/team/repo.git failed"`, defined three lines above),
  and the assertion's trailing comment — `# host preserved` — states exactly that. Note that the
  `assert "git.example.com" not in ...` on line 309 of the same file is **not** flagged: the query
  matches `In` and not `NotIn`, which on its own shows how little semantics it is using.
- `text` in `test_dockerfile_supply_chain.py` is the **contents of `docker/Dockerfile`**, and the
  assertion checks that the cosign keyless verification is identity-pinned to
  `token.actions.githubusercontent.com`. Substring search over a Dockerfile is the correct operation;
  there is no URL and no parsing to be done.

All three are test oracles over fixed, in-repo strings, with no attacker anywhere in the picture.
`"Used in tests"` is the accurate dismissal reason for these three — and, importantly, **not** for
alerts #1, #2, and #6, which are in shipped code and need the "False positive" reason plus the
mechanical explanation.

---

#### Alert #6 — `py/log-injection`, `backend/app/api/scans.py:574`

**The flagged line** is the last statement of `delete_scan()`:

```python
@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: int,                                                     # line 527  ← reported source
    ...
) -> Response:
    ...
    logger.info("Deleted scan %d and all associated data.", scan_id)  # line 574  ← sink
```

CodeQL's flow is two nodes long: the path parameter at `:527` straight to the logging call at `:574`.

**Why it cannot be exploited.** Log injection means smuggling `\r`/`\n` into a log record to forge log
lines. That requires attacker-controlled **string** content reaching the sink. It cannot happen here:

- `scan_id` is annotated **`int`**. FastAPI validates and coerces every path parameter through
  Pydantic **before** the handler body runs, so a non-integer path segment is rejected with a 422 and
  line 574 is never reached. The value at the sink is a Python `int`, not the raw request bytes.
- It is rendered with **`%d`**, which can only ever emit `[-]digits`. There is no formatting path by
  which an `int` produces a newline.
- The endpoint is also behind `require_csrf` and the `_operator` role, though that is beside the
  point — the type is what closes this, and it closes it completely.

**Why CodeQL is wrong here, specifically.** Its Python taint model treats a framework route parameter
as an `ActiveThreatModelSource` **regardless of the parameter's type annotation** — there is no
"this was coerced to `int`" step in the model, so the annotation on line 527 is not read as anything.
And the sanitizer set for this query is small and entirely syntactic
(`LogInjectionCustomizations.qll`): a comparison against a constant (`ConstCompareBarrier`), an
explicit `.replace("\n", …)` / `.replace("\r\n", …)` call, and models-as-data barriers. A type
annotation is not among them, and no rewrite of this line short of `str(scan_id).replace("\n", "")`
— which would be nonsense on an `int` — would clear it. As with alerts #1 and #2, the analyzer is
not being cautious about something uncertain; it simply has no way to express the fact that makes the
code safe.

**Not to be confused with the redaction layer.** `SecretRedactionFilter` (`app/core/logging.py`,
covered by `backend/tests/test_redaction.py`) exists to keep *secrets* out of log output. It is a
different control for a different problem and is not what makes this line safe. (It was replaced by
`RedactingFormatter` in the 2026-08-02 access-logger entry above; the point stands unchanged.)

---

**What the run did *not* flag, stated explicitly so absence is on the record.** The
`security-extended` suites ran the full injection / traversal / deserialization / crypto / SSRF / XSS
/ tarslip / unsafe-shell-construction sets against all 174 Python files and all 78 TypeScript files
and returned **nothing** on the scanner subprocess-argv construction, the credential materialization
and shredding path, the crypto and secret-store modules, the auth and CSRF layer, or the frontend.
The Actions pack returned nothing on the five workflows. That is a clean result for exactly the code
the roadmap item was written to get looked at — and it is a stronger result than it would have been
under the default suite, since `security-extended` is the larger query set. It is still *coverage*,
not proof of absence, and note that neither suite contains a "missing authorization" check for Python
— one of the patterns the roadmap item hoped for. RBAC coverage remains the pytest suite's job.

**A `dev` PR gets no CodeQL check at all — confirmed, not inferred.** Default setup's pull-request
trigger targets the **default branch**, and `main` is the default branch here while `dev` is where
day-to-day work is PR'd (§ Git & PR conventions). The PR carrying this entry (**#134**, into `dev`)
was checked after its checks settled: **four check runs, none of them CodeQL.** So the roadmap item's
worry that switching CodeQL on would "join the per-PR gate the moment it is switched on" is the
opposite of what happened — on the branch that actually receives PRs, CodeQL does not run. In
practice CodeQL currently analyses `main` on push (i.e. **after** a promotion has already landed) and
on its weekly schedule. **Closing that gap needs advanced setup** — a committed workflow is the only
way to add `dev` to the trigger — and it is the **strongest** reason to revisit the default-vs-
advanced choice, stronger than the path-filter and custom-query reasons, since those remain
hypothetical while this one is a live gap in coverage.

**Not done here, and left to the maintainer.** No alert was dismissed, no code was changed, and no
issue was opened. The recommended dispositions above are recommendations. One related item also stays
open: even once CodeQL does run on the right branch, the check **cannot gate a merge** until its
contexts are added to `protect-dev`'s required-checks list.

> **Corrected 2026-08-02.** This originally attributed the gap to the "still-open **branch
> protection** governance item." That was wrong — `protect-dev` is already active *and* already
> carries `required_status_checks`. The rule is an explicit allowlist of contexts, so the blocker is
> adding CodeQL's contexts to that list (a settings edit), not the governance item. See the entry
> above for the full ruleset readout.

**Plan section affected:** §14 (this record); `docs/ROADMAP.md` § Near-term (the CodeQL item, now
struck). No code, schema, workflow, or locked-decision change.

---

### 2026-08-02 — Infra/Process — GHSA-qwww-vcr4-c8h2 closed by a 7.x backport (`react-router` 7.18.2), not the 8.3.0 major; the advisory's "Patched versions" field is stale

**What changed:** `react-router-dom` bumped **7.18.1 → 7.18.2** in `frontend/package.json`, with
`package-lock.json` regenerated (`react-router` moves 7.18.1 → 7.18.2 with it — `react-router-dom`
pins its core exactly). **Issue #123 is closed.** No application code changes; no other dependency
moves; the runtime image is byte-identical in everything but the hashed asset name.

The bump is taken because **the fix for GHSA-qwww-vcr4-c8h2 exists on the 7 line** — verified in the
published tarball, not inferred from a version number. The react-router 7 → 8 major migration #123
contemplated is **not needed for this advisory** and is not part of this change.

---

**1. The 7.x patch exists, and it was already published when #123 last said it was not.**

`react-router@7.18.2` and `react-router-dom@7.18.2` were published **2026-07-28T21:53Z**. The
per-release re-confirmation comment posted on **2026-08-02T02:25Z** — five days later — states *"No
7.x fix has appeared, so the cheap exit still does not exist."* That was wrong at the moment it was
written.

**How it went wrong is the reusable part.** The check was made against the **advisory's own
metadata**, and that metadata is stale: GHSA-qwww-vcr4-c8h2 still reads

| Field | Value (as of 2026-08-02) |
| --- | --- |
| Affected versions | `>= 7.12.0, < 8.3.0` |
| Patched versions | `8.3.0` |

There is no 7.x entry in the "Patched versions" field, and the affected range still swallows 7.18.2.
Reading the advisory therefore produces exactly the false statement that landed in the issue. The
registry is what actually answers the question — `dist-tags` on `react-router` carry a
**`version-7: 7.18.2`** line alongside `latest: 8.3.0`, and `react-router-dom`'s own `latest` **is**
7.18.2 (the package does not exist on the 8 line at all; v8 consolidates into `react-router`). This
is the npm-side counterpart of the interpreter-CVE rule already in `CLAUDE.md` § Dependency hygiene:
**an advisory's "first patched version" is a claim about one release line, not a survey of every
maintained line.** The maintainers backported without asking GitHub to re-cut the range, which they
are under no obligation to do.

**2. Verified at the source: 7.18.2 carries the same fix as 8.3.0, and nothing else.**

Per `CLAUDE.md` § Dependency hygiene, the changelog line was treated as evidence and not proof. Both
changelogs claim the fix, under *different PR numbers* — 8.3.0 cites
[#15311](https://github.com/remix-run/react-router/pull/15311) (the PR the advisory itself
references), 7.18.2 cites [#15353](https://github.com/remix-run/react-router/pull/15353), the shape
of a backport. So all four tarballs (7.18.1, 7.18.2, 8.2.0, 8.3.0) were unpacked and the vulnerable
function diffed directly.

The vulnerable path is `generateRenderResponse`'s mutation branch in `dist/*/index-react-server.*` —
the RSC server entry. **7.18.1 and 8.2.0 are identical here**, and both are shaped like this:

```js
if (isMutationMethod(request.method)) try {
  throwIfPotentialCSRFAttack(request, allowedActionOrigins);
  ctx.runningAction = true;
  let result = await processServerAction(request, /* … */);   // ← inside the same try
  // …
} catch (error) {
  potentialCSRFAttackError = error;                            // ← catches *any* of the above
}
let staticContext = await query(
  request,                                                     // ← still the mutation request
  skipRevalidation || !!potentialCSRFAttackError ? { filterMatchesToLoad: () => false } : void 0,
);
if (potentialCSRFAttackError) { /* … */ staticContext.statusCode = 400; }
```

Two defects, both matching the advisory's title — *action execution before a 400 response*. The
`catch` cannot distinguish "the origin check rejected this request" from "the action ran and threw",
so an error raised by an **already-executed** server action is relabelled a CSRF error and served as
a 400: the response asserts the request was blocked when its side effects have already happened. And
on a genuine origin-check failure the **unmodified mutation-method request** is still handed to
`query()`, so downstream sees a rejected mutation as a mutation.

**7.18.2 and 8.3.0 are, again, identical to each other** — and fix both:

```js
if (isMutationMethod(request.method)) {
  try {
    throwIfPotentialCSRFAttack(request, allowedActionOrigins);  // ← alone in the try
  } catch (error) {
    onError?.(error);
    potentialCSRFAttackError = error;
    request = new Request(request.url, {                        // ← neutralized to GET
      method: "GET", headers: request.headers, signal: request.signal,
    });
  }
  if (!potentialCSRFAttackError) {                              // ← action gated on the check
    ctx.runningAction = true;
    let result = await processServerAction(request, /* … */);
    // …
  }
}
let staticContext = await query(request, skipRevalidation ? { filterMatchesToLoad: () => false } : void 0);
```

The origin check is alone in its `try`, so only it can set `potentialCSRFAttackError`; the action is
gated behind `!potentialCSRFAttackError`, so it cannot run in a request that will answer 400; the
rejection is surfaced through `onError`; and the rejected request is rewritten to `GET` before it
reaches `query()`. Same four changes, same order, in both releases.

**The backport is also the *entire* 7.18.1 → 7.18.2 diff.** Normalizing the hashed chunk filenames,
the only textual differences across every published bundle are the version banner and the block
above. No API surface moves, no dependency moves, no behaviour outside the RSC server entry changes.
As patch bumps go this is the lowest-risk shape available — which is precisely why it is worth
taking even for an unreachable path.

**3. The reachability assessment in #123 was independently re-verified, and holds.**

Checked against the tree rather than carried forward from the issue text. Every `react-router-dom`
import in `frontend/src/` is declarative — `BrowserRouter` (`main.tsx`), `Routes`/`Route`/`Link`/
`Navigate`/`useLocation` (`App.tsx`), `useNavigate`/`useParams`/`useSearchParams` in the five pages,
and `MemoryRouter` in `src/test/render.tsx`. There is **no** `createBrowserRouter`, no
`react-router.config.ts`, no `@react-router/*` package, and no route `action` export anywhere. The
vulnerable code lives behind the `index-react-server` entry point, which nothing in the SPA imports,
so Vite never pulls it into the bundle. Beyond that, `docker/Dockerfile` copies only
`/build/frontend/dist` out of the `frontend-builder` stage — no `node_modules`, no `package.json` —
so the npm dependency graph is not in the runtime image at all, and the CI dogfood Trivy/Grype image
scan was never going to see this advisory in the first place. It surfaced only through `npm audit`
and Dependabot against the source tree.

So #123's central claim was correct. What it got wrong was the *cost of exiting* — it framed the
only way out as a major migration, and on that basis set up a long-lived acceptance with a
per-release review. The exit was a patch bump.

**4. The Dependabot/`npm audit` alert will *not* clear, and that is expected.**

Because the advisory's affected range still reads `>= 7.12.0, < 8.3.0`, `npm audit` continues to
report both `react-router` and `react-router-dom` as HIGH at 7.18.2, and still proposes the same
`react-router-dom@7.11.0` **downgrade** as its "fix". That proposal was wrong before and is now
doubly wrong: 7.11.0 is *below* the fix as well as below the range. **The alert is a metadata
artifact, not a code finding** — the vulnerable code is gone from the tree, verified above.

Nothing is being waived to suppress it. It gates nothing: `npm audit` is not run in CI, and the
image-level dogfood gate never saw the package (point 3). The correct upstream resolution is for the
advisory to gain a `>= 7.12.0, < 7.18.2 → 7.18.2` range; until it does, this entry is the record of
why the alert can be left alone. **Do not "fix" it by downgrading, and do not scope a react-router 8
migration in response to it.**

**5. What react-router 8 now is, and is not.**

Removing this advisory from the argument leaves the 7 → 8 major as a pure **currency** decision,
which is where it belongs — alongside the other frontend majors tracked from #86 in
`docs/ROADMAP.md` (TypeScript 7, ESLint 10, Vite 8, Vitest 4, jsdom 29) and gated on that toolchain
sweep, since v8 folds `react-router-dom` back into `react-router` and would touch every import site
in `frontend/src/`. It is not security work and carries no deadline. Per `CLAUDE.md` § Dependency
hygiene it must not be sold as a fix for GHSA-qwww-vcr4-c8h2 — as of 7.18.2 there is nothing left
for it to fix.

**Verified:** `npm ci` installs `react-router@7.18.2` / `react-router-dom@7.18.2`; the installed
`node_modules/react-router/dist/development/index-react-server.mjs` carries the gated-action fix;
`npm run build` succeeds; ESLint, Prettier and the 20-file / 69-test Vitest suite all pass — the
four page-level suites (`ScansPage.urlstate`, `ScansPage.compare`, `ScanDetailPage.poller`,
`ScanDetailPage.latestwins`) included, since they mount real routers.

**Plan section affected:** `CLAUDE.md` § Dependency hygiene; §14 (2026-08-02, item 6 of the
post-v0.2.0 cleanup entry, whose #123 re-confirmation this corrects); `docs/ROADMAP.md`.

---

### 2026-08-02 — Infra — Frontend builder and CI moved Node 22 → 24 (Active LTS); the Dependabot major-ignore re-pointed at the 24 line

**What changed:** the SPA is now built on **Node 24 (`krypton`)** in both places it is built — the
image's `frontend-builder` stage and CI's `frontend` job — with the stated local-development
requirement updated to match and `.github/dependabot.yml`'s node major-ignore re-pointed from the
22 line to the 24 line. This is the `docs/ROADMAP.md` § Near-term item written up on 2026-08-02
(§14, "Post-v0.2.0 dependency cleanup", part 3), executed as the standalone PR that item said it
had to be. **No application code, dependency version, schema, API contract, security model, or
build structure changes** — nothing in `frontend/package.json` or `package-lock.json` moves, and
the Dockerfile's stage boundaries and layer ordering are untouched (`CLAUDE.md` § Build
performance).

---

**1. Why 24, stated as a lifecycle argument rather than a preference.**

Read from `nodejs/Release`'s `schedule.json` at the source, not from a release-notes page:

| Line | LTS from | Maintenance from | End of life |
| --- | --- | --- | --- |
| **20** (`iron`) | 2023-10-24 | 2024-10-22 | **2026-04-30** — already past |
| **22** (`jod`) | 2024-10-29 | 2025-10-21 | **2027-04-30** |
| **24** (`krypton`) | 2025-10-28 | 2026-10-20 | **2028-04-30** |
| **25** | never — odd lines get no LTS | 2026-04-01 | **2026-06-01** — already past |
| **26** | **2026-10-28** | 2027-10-20 | 2029-04-30 |

24 is the Active LTS today and buys the longest supported window available: twelve months more
than 22. **26 was considered and deliberately declined for now** — it became current on 2026-05-05
but does not enter LTS until **2026-10-28**, so adopting it today would put the builder on a
*current* line, which is the same class of mistake as the Node 25 proposal in #126. The 24 line
does not even enter maintenance until 2026-10-20, so there is no pressure to revisit; the roadmap
item now says exactly that instead of holding an open "move to 24" task.

**This is a support-lifecycle bump, not a security fix, and it is not recorded as one.** No CVE is
claimed to be cleared by it — the parallel to `CLAUDE.md` § Dependency hygiene's interpreter-CVE
rule is deliberate. Node here is a **build-time** toolchain that never reaches the runtime image
(the `frontend-builder` stage's only output is the compiled `dist/`), so the argument for currency
is the supported-window one and nothing more.

---

**2. The digest was resolved against the registry, and the interpreter inside it verified.**

`docker buildx imagetools inspect node:24-bookworm-slim` resolves the tag to the multi-arch index
**`sha256:235600a8101ab264e117b1768e925532262668dc9b581ef1dd7d96ced463b8e7`**, which is what the
`FROM` now pins — an index digest, matching how every other base in this Dockerfile is pinned, and
carrying both platforms the multi-arch build needs (`linux/amd64`
`sha256:a09aabc6…` and `linux/arm64/v8` `sha256:c39335f4…`, alongside a `linux/ppc64le` leg the
build never selects).

**Which Node that digest actually contains was confirmed, not inferred from the tag.** The index's
`org.opencontainers.image.revision` annotation points at `nodejs/docker-node` commit
`53252eea9caacaa50bdf58f4d34f0bff8d259999`, path `24/bookworm-slim`; that file's
`ENV NODE_VERSION=24.18.1`. So the pinned image is **Node 24.18.1**, the current 24.x release
(2026-07-28, npm 11.16.0). The container itself could not be run to check `node --version`
directly — this environment has the docker CLI but no daemon, and registry blob fetches through the
proxy return 403 — so the tag→commit→`NODE_VERSION` chain is the verification, and it is stated
that way rather than as an executed check.

---

**3. Verified on a real Node 24, not on the assumption that a major is a no-op.**

The whole frontend gate was run against **Node v24.18.1** — the exact version inside the pinned
image — installed from `nodejs.org/dist` and checksum-verified against that release's
`SHASUMS256.txt` (`d6c664df…`) before use:

| Step | Result |
| --- | --- |
| `npm ci` | clean install from the unchanged lockfile |
| `npm run lint` (ESLint, type-aware) | clean |
| `npm run format:check` (Prettier) | clean |
| `npm test` (Vitest) | **20 files, 69 tests, all passed** |
| `npm run build` (`tsc -b && vite build`) | built in 6.5 s, 6634 modules |

**CI's own frontend job confirms the change took effect**, which is worth stating separately from
the local run: its log shows `node-version: 24` resolving to **v24.18.0** with **npm 11.16.0**,
then the same 20 files / 69 tests and the same successful build. Note the **patch difference** —
the runner's tool-cache carries 24.18.0 while the pinned image carries 24.18.1, because
`node-version: "24"` is a major-line spec and `setup-node` takes whatever 24.x the runner already
has. That is expected and is not the drift this item exists to prevent: the lockstep requirement is
the **major**, since that is what changes language and npm behaviour.

**Nothing in the toolchain broke**, so the deferred frontend-tooling sweep (`docs/ROADMAP.md`
§ Near-term, the #86 majors — TypeScript 7, ESLint 10, Vite 8, Vitest 4, jsdom 29) stayed out of
this PR, which is the point of keeping the two separate. Vite 6.4.3, Vitest 3.2.7, jsdom 26.1.0 and
the React Testing Library harness all run on 24 unmodified.

**One behavioural difference is worth recording even though it changed nothing here.** Node 24
ships **npm 11** (11.16.0) where 22 ships npm 10, and npm 11 no longer runs dependency install
scripts by default — `npm ci` now prints an `allow-scripts` warning for `esbuild@0.25.12`'s
`postinstall`. The build is unaffected because esbuild's platform binary arrives through its
`@esbuild/linux-*` optional dependency rather than through that script, which is why the Vite build
succeeds with the postinstall skipped. Noted because it is the kind of difference that would
matter for a future dependency that genuinely needs its install script.

---

**4. The three-file lockstep, and the fourth file that had drifted.**

The roadmap item's whole reason for existing is that bumping the Dockerfile alone leaves **CI on 22
while the image builds on 24**, so a version-specific failure first appears in a published image
instead of in a check. All of them moved together:

1. `docker/Dockerfile` — `node:22-bookworm-slim@sha256:6c74791e…` → `node:24-bookworm-slim@sha256:235600a8…`, with the stage comment rewritten to state the lockstep as a rule rather than to describe a pending move.
2. `.github/workflows/ci.yml` — `node-version: "22"` → `"24"` (and the step's display name), with a comment naming the Dockerfile as the thing it must match.
3. `CONTRIBUTING.md` § Prerequisites and `README.md` § Requirements — the stated Node requirement.

**The stated requirement was also *raised*, not just re-worded, and that is a small deviation worth
flagging.** Both files said **"Node 20+"**, which named a line that reached end-of-life on
**2026-04-30** — i.e. the documented floor for local development was an unsupported runtime. It is
now **"Node 22+"** with the image/CI version (24) named alongside it. 22 is kept as the floor
rather than 24 so a contributor on the previous LTS is not turned away by a docs change; the two
supported lines are exactly 22 and 24.

**Checked for other references before calling the sweep complete**, since the roadmap item listed
three files but the search space is larger: there is **no `.nvmrc`** anywhere in the repo, and
`frontend/package.json` has **no `engines` field** — so neither needed updating, and neither was
silently left behind. `CHANGELOG.md`'s single `node:22-bookworm-slim` mention is inside the v0.1.0
release entry describing what shipped then, which is history and must not be rewritten. The
`@types/node` devDependency stays at 22.20.0: it is a *typings* package pinned as part of the
frontend dependency set, and moving it is a `package.json` change that belongs with the #86
tooling sweep, not here — the SPA is browser-targeted and does not type against Node 24 APIs.

---

**5. The Dependabot ignore keeps its shape and changes its target.**

`.github/dependabot.yml`'s `docker` entry still carries:

```yaml
- dependency-name: "node"
  update-types: ["version-update:semver-major"]
```

The **rule is unchanged** — block majors, let digest refreshes through — because the reason for it
is unchanged: a major here spans four files and a lifecycle decision, and the
`version-update:semver-major` scoping is what keeps Dependabot proposing digest refreshes of the
pinned tag instead of going silent (the failure mode that left the 22 digest stale until #107).
Only the **comment** moved: it now names 24 as the line in use and 2028-04-30 as its EOL, records
the Node 26 revisit date as a deliberate decision rather than a bump to accept, and keeps the
Node 25 / #126 history as the example of why odd lines are declined.

**The open question from the 2026-08-02 entry is still open, and this PR does not close it.** That
entry noted the ignore's digest-still-arrives behaviour was confirmed from *documented semantics*
plus reported behaviour, not from an observed Dependabot run in this repository, and that the next
scheduled `docker` run is the test. Re-pointing the ignore at 24 does not change that: the same
test applies, now against the `24-bookworm-slim` tag. If no `node` update ever arrives, the
fallback remains the one #107 used — refresh the digest by hand and say so here.

---

**Verification.** Frontend lint, format, Vitest and build all green on Node v24.18.1 as tabled
above. **CI's image build is the real gate** and is reported from the PR's actual run, not
predicted here — the local checks exercise the SPA toolchain but not the multi-stage image build,
and this environment has no docker daemon to build it with.

**Files touched:** `docker/Dockerfile`, `.github/workflows/ci.yml`, `.github/dependabot.yml`,
`CONTRIBUTING.md`, `README.md`, `docs/ROADMAP.md` (item struck as done, Node 26 revisit retained),
`docs/ARCHIVE.md` (this entry).

**Plan section affected:** §9.1 (image build), process.

---

### 2026-08-02 — Infra/Process — Post-v0.2.0 dependency cleanup: three closed Dependabot PRs reapplied, the base-branch anomaly traced to `dev`'s deletion, the brace-expansion waiver retired

**What changed:** the three Dependabot PRs closed on 2026-08-02 as unmergeable-as-built (#126, #127,
#128) applied by hand and correctly; `.github/dependabot.yml` given the two `ignore` entries that
stop the same PRs recurring; the base-branch question those closures raised diagnosed to a root
cause; and the three advisory tracking issues re-verified against the tree after the v0.2.0 tag —
with **`postcss` bumped by hand to close #124**, because with the Dependabot queue empty nothing
was going to propose it. No application code, schema, API contract, security model, job model, or
auth behavior changes.

---

**1. `fastapi` 0.140.0 → 0.140.13, with `requirements.lock` regenerated (was #127).**

#127 failed CI because Dependabot edits `pyproject.toml` without touching
`backend/requirements.lock`, and CI's drift gate recompiles the lock and fails on any difference.
That is the gate working — a Dependabot pip bump in this repo is *never* mergeable as opened, and
the fix is always to reapply the bump and regenerate the lock with the pinned command from
`CONTRIBUTING.md` § Backend dependency lock (`uv pip compile pyproject.toml --group build
--generate-hashes --python-version 3.14`, uv 0.8.17). The regenerated lock moves **three lines** —
`fastapi`'s version and its two wheel hashes — and nothing else; `starlette` stays at the
explicitly-pinned 1.3.1, which 0.140.13 still accepts.

**The thirteen patch releases were read before applying, and none of them touches a path Scrye
uses.** Grouped by what they are:

| Releases | Change | Reaches Scrye? |
| --- | --- | --- |
| 0.140.1 – 0.140.7 | Internal refactors: stop retaining flat dependency trees, avoid re-flattening for OpenAPI/body/param handling, retune the dependency `lru_cache` limit | No behavior change — memory/OpenAPI-generation performance only |
| 0.140.8, .11, .12, .13 | Streaming fixes: stream item type lost through `include_router()`, `response_model_*` ignored for `Iterable[…]` returns, SSE line-splitting, `status_code` ignored on SSE/JSONL endpoints | **No** — the backend has no SSE, JSONL, or streaming endpoint, and no `response_model_*` parameter anywhere |
| 0.140.9 | `exclude_defaults` not propagated to dict keys/values in `jsonable_encoder` | **No** — `jsonable_encoder` is never called |
| 0.140.10 | Sequences with nested `Annotated` types mishandled | **No** — the only nested `Annotated[list[str], …]` in the tree is `pydantic-settings`' `NoDecode` in `app/core/config.py`, not a request parameter |

Verified by grep across `backend/app/`: no `jsonable_encoder`, no `StreamingResponse`, no SSE
helper, no `response_model_*`. Every response in `app/api/` is a plain `Response`,
`PlainTextResponse`, `RedirectResponse`, or `FileResponse`. So this is a currency bump that fixes
nothing Scrye was hitting and risks nothing either — which is the honest way to describe it.

**Confirmed against the regenerated lock, not just against the version pin.** A throwaway venv on
**CPython 3.14.6** was built the way the image builds: `pip install --require-hashes -r
requirements.lock`, then `pip install --no-deps --no-build-isolation .`. The full backend suite
passes there — **666 passed, 5 skipped**, byte-identical to the pre-bump baseline on the same
interpreter, with the same 18 warnings (the standing Starlette `HTTP_422_UNPROCESSABLE_ENTITY`
deprecations already tracked in `docs/ROADMAP.md`). Running the suite against the hash-verified
closure rather than against an editable install is the point: the lock is what ships, so it is what
has to be green.

---

**2. `docker/login-action` 4.5.1 → 4.6.0, SHA-pinned (#128 proposed 4.5.2).**

Pinned at `dbcb813823bdd20940b903addbd779551569679f # v4.6.0` in all three workflows that
authenticate to GHCR — `publish.yml`, `dev-nightly.yml`, `rescan.yml` — keeping the tag as a
trailing comment per the convention every other `uses:` in this repo follows (H9/SC-2).

**Why 4.6.0 rather than the 4.5.2 that #128 proposed.** 4.5.2's only substantive commit,
["surface Docker Hub OIDC error responses"](https://github.com/docker/login-action/pull/1058),
improves the error text when a **Docker Hub OIDC** login fails — a path none of the three call
sites can reach, since all three log in to `ghcr.io` with the built-in `GITHUB_TOKEN` as
username/password. 4.6.0 supersedes it a day later and is the one whose changed code is at least
*adjacent* to what this repo does: it hardens the **buildx-scoped config path** used by the
login → buildx-builder → push chain, and it carries the action's own bundled dependency bumps
(`@aws-sdk/client-ecr`, `js-yaml`, `postcss`). Taking the newer release also avoids pinning to a
version that was already superseded on the day it was applied.

**The SHA was resolved from upstream, not read off a changelog or release page.** `git ls-remote
--tags https://github.com/docker/login-action` maps `refs/tags/v4.6.0` to that commit. Trusting a
rendered SHA is precisely the substitution a SHA pin exists to prevent; the tag→commit mapping has
to come from the repository that owns it. Note that upstream's **moving `v4` tag currently points
at the same commit** — the pin here is the immutable `v4.6.0` commit, not the alias.

**The changelog matters more than usual here**, because this action runs only on the tag-gated
publish path and the nightly — paths CI *cannot* exercise, so a breaking change would surface at
release time on a protected branch. So 4.6.0 was read at the source rather than from its release
notes, comparing `v4.5.2...v4.6.0`:

- **`action.yml` is byte-identical.** No input added, removed, renamed, or re-defaulted.
- **`src/main.ts` and `src/docker.ts` are unchanged.** The login flow itself does not move.
- **The entire change is in `src/context.ts`'s buildx-scoped config-dir helper.** It now resolves
  the buildx config root and the per-registry directory with `path.resolve` and rejects a
  `registry` whose resolved path escapes the config root; validates the `scope` input (at most one
  `@` separator, actions matching `^[a-z]+(,[a-z]+)*$`); and rejects a scope path that escapes the
  registry directory — via a new `isChildPath()` helper doing the usual `relative()` /
  `startsWith('..')` / `isAbsolute()` containment test.

**And the honest reading of what that buys Scrye: nothing behavioural, today.** That helper
short-circuits on its first line — `if (scopeDisabled() || !scope || scope === '') return ''` —
and none of the three call sites passes a `scope` input (each passes exactly `registry`,
`username`, `password`; no `ecr`, no `logout`, no OIDC, and no `DOCKER_CONFIG` is set anywhere in
the repo). So every line 4.6.0 adds sits behind a gate this repo does not open. Two of the three
sites (`publish.yml`, `dev-nightly.yml`) do go on to run buildx through
`.github/actions/build-image`, so the hardened area is on the chain they use; `rescan.yml` only
does a plain `docker pull` afterwards. The bump is therefore **currency plus defence-in-depth
against a future `scope` being introduced** — not a fix for anything currently reachable, and it
is not recorded as one.

---

**3. Node: majors ignored, and the 22 → 24 move written up as tracked work (was #126).**

#126 proposed **`node:22-bookworm-slim` → `25-bookworm-slim`**. Declining it is a lifecycle
argument, not a preference: per the [Node release schedule](https://github.com/nodejs/Release),
**v25 has no LTS date at all** — odd-numbered lines never get one — and its `end` is
**2026-06-01**, i.e. it was *already end-of-life* when the PR was opened on 2026-07-31. The 22 line
Scrye builds on runs to **2027-04-30**. Accepting the "upgrade" would have moved the builder from a
supported runtime to an unsupported one.

So `.github/dependabot.yml`'s `docker` entry now ignores `node` majors:

```yaml
- dependency-name: "node"
  update-types: ["version-update:semver-major"]
```

**Scoped so digest refreshes still arrive.** An `ignore` condition whose `update-types` are all of
the `version-update:semver-*` form suppresses only *semver version* updates; a digest refresh of
the same `22-bookworm-slim` tag is not one, and still comes through. That scoping is load-bearing
rather than incidental: the previous round of declining a major left Dependabot offering nothing at
all for this image, and the pinned digest went stale until it was refreshed by hand in **#107**
(§14, 2026-07-26). The config *can* express "ignore majors, allow digests", so no workaround was
needed and the question the ignore had to answer does not need reopening.

**Stated evidence, since this repo does not accept "the docs say so" as proof.** What is confirmed
is the *documented semantics* of `update-types` (it filters semver version updates) plus reported
behaviour of the docker updater continuing to raise digest-only PRs against ignored majors. What
is **not** yet confirmed is an observed Dependabot run *in this repository* doing so — the first
scheduled `docker` run after this lands is the actual test. **If the next run produces no `node`
update at all, the assumption is wrong** and the fallback is the one #107 already used: refresh the
digest by hand, and say so here.

The `docs/ROADMAP.md` § Near-term Node item was rewritten rather than left as it was. It now states
plainly that the move is **22 → 24** (Active LTS, supported to **2028-04-30**), that it **must be
its own PR**, and that it spans **three files which have to change together** —
`docker/Dockerfile`'s `frontend-builder` digest, `.github/workflows/ci.yml`'s
`node-version: "22"`, and `CONTRIBUTING.md`'s stated Node requirement (plus `README.md`
§ Requirements). The reason is spelled out because it is the failure mode, not a formality:
**bumping the Dockerfile alone leaves CI building on 22 while the image builds on 24**, so a
version-specific build or lint failure would first appear in a published image rather than in a
check. The new base must be **digest-pinned, resolved against the registry**. Node **26** is
recorded as a post-2026-10-28 reconsideration (it becomes LTS then), not as a competing target
today.

---

**4. The self-referencing image tag ignored (`scrye`).**

Dependabot's docker run has been failing with **`private_source_authentication_failure`** because
`docker/docker-compose.yml` pins `image: scrye:0.2.0` — Scrye's own **locally built** tag, which
Dependabot resolves as Docker Hub's `library/scrye` and gets a 401 for. The diagnosis is the
2026-08-02 entry below; this is the fix it said would land here.

**Which ecosystem entry actually scans the file was verified, not assumed.** `.github/dependabot.yml`
has *separate* `docker` and `docker-compose` entries, both on `directory: "/docker"`. Reading the
files: `docker/docker-compose.yml` carries the only `image: scrye:0.2.0` reference (its other two
images, `aquasec/trivy` and `wollomatic/socket-proxy`, are fully qualified and public), and
`docker/Dockerfile` contains **no** `scrye` image reference at all — its `scrye` occurrences are a
build-command comment, the `groupadd`/`useradd` for the runtime user, and `SCRYE_*` env vars, none
of which any updater parses as a dependency. So the compose file is scanned by the
**`docker-compose`** entry, and that is where the substantive ignore and its explanation live.

The ignore was added to the **`docker` entry as well**, deliberately. The failing run's ecosystem is
visible only in the Dependabot UI/job logs, which are not reachable from a code session and are not
in the public API — so the entry the UI attributes it to could not be verified from here. Adding
the same `dependency-name: "scrye"` to an entry whose only file never mentions `scrye` suppresses
nothing and costs nothing, and it removes the failure mode where the fix is filed against the wrong
half of a two-entry pair. Both entries carry a comment saying the tag is a local build artifact
rather than a registry dependency.

**The image tag itself was deliberately left alone.** Qualifying it as
`ghcr.io/tyler-rich/scrye:0.2.0` would make the compose file **pull a published image instead of
building locally**, changing what the documented quick start does; dropping the tag loses the
version pin. Both were rejected in the diagnosis entry and both are still rejected.

---

**5. Why #110, #120, #126, #127 and #128 all opened against `main` — two different causes, and only
one of them was the documented one.**

This is the finding with the longest reach, so it is written out in full.

**#110 and #120 are the documented case.** Both are npm **security** updates. `target-branch` is
honoured for version updates only; security updates always open against the repository's default
branch. Their head-branch names corroborate it —
`dependabot/npm_and_yarn/frontend/npm_and_yarn-…`, with **no target-branch segment**, because
Dependabot never intended `dev` for them. Nothing new here; this is the rule added to `CLAUDE.md`
§ Dependency hygiene on 2026-07-31.

**#126, #127 and #128 are not that case, and the "grouped security updates" hypothesis is wrong.**
Three facts rule it out:

- All three are **version** updates. `node` 22→25, `fastapi` 0.140.0→0.140.13 and
  `docker/login-action` 4.5.1→4.5.2 are none of them security-advisory-driven, and Dependabot's own
  closing comment on #128 says the PR "was built based on a group rule" — a version-update group.
- All **three different ecosystems** (`docker`, `pip`, `github-actions`) were affected identically
  and simultaneously. A grouped-security override would hit only ecosystems that actually had a
  security update to group.
- Their head branches **do** carry the target-branch segment —
  `dependabot/docker/docker/dev/docker-images-…`, `dependabot/pip/backend/dev/backend-dependencies-…`,
  `dependabot/github_actions/dev/github-actions-…`. Dependabot reads `target-branch: dev` and
  encodes it in the branch name. **The configuration worked.**

**The actual cause, with direct evidence.** Each of the three PRs' timelines carries an
**`automatic_base_change_succeeded`** event:

| PR | Head branch | Base-change event |
| --- | --- | --- |
| #126 | `dependabot/docker/docker/dev/docker-images-0e8fc498de` | 2026-08-01T23:56:09Z |
| #127 | `dependabot/pip/backend/dev/backend-dependencies-fd4d557a46` | 2026-08-01T23:56:09Z |
| #128 | `dependabot/github_actions/dev/github-actions-85123b4e12` | 2026-08-01T23:56:10Z |

The v0.2.0 promotion PR **#122** merged at **2026-08-01T23:56:07Z**. All three base changes land
**two to three seconds later**, and all three PRs' `base.sha` is `bb354a5` — the promotion's merge
commit.

Neither #110 nor #120 carries an `automatic_base_change_succeeded` event. Note the distinction
that matters when reading a timeline: #120 *does* carry two ordinary **`base_ref_changed`** events
(2026-07-31T05:06:53Z by `tyler-rich`, 05:09:23Z by `dependabot[bot]`) — that is the **manual**
retarget-to-`dev`-and-back already documented in the 2026-07-31 release-prep entry, a different
event type produced by a person changing the base in the UI. `automatic_base_change_succeeded` is
emitted only by GitHub's retarget-on-base-branch-deletion, and it is the one to look for.

GitHub **automatically retargets open pull requests whose base branch is deleted**, moving them to
the merged pull request's base. A `dev` → `main` promotion has `dev` as its **head** branch; with
"Automatically delete head branches" enabled, merging it deleted `dev`, and every open PR based on
`dev` was silently moved to `main` in the same instant. The three Dependabot PRs were opened
against `dev` **correctly** on 2026-07-31 and were moved afterwards by GitHub, not by Dependabot,
not by `.github/dependabot.yml`, and not by any repository security setting.

**This is the same incident as the entry below**, which recorded that the v0.2.0 promotion deleted
`dev` and that the `protect-dev` ruleset's admin bypass is why *Restrict deletions* did not stop
it. What was not appreciated then is that the branch deletion had a **second blast radius**: it did
not only remove a branch that had to be restored, it re-based the entire open-PR queue onto the
protected release branch. Three PRs were then closed as "opened against main despite the head
branch being built for dev" — a description that is accurate about the symptom and wrong about the
cause.

**Recommended fix: nothing further to change, and specifically not `target-branch`.** The remedy is
already in place — "Automatically delete head branches" was disabled on 2026-08-02 — and it
addresses this directly, because with no head-branch deletion there is no retarget. Concretely:

- **Do not** alter `target-branch: dev` on any ecosystem. It is doing exactly what it should; the
  branch names prove Dependabot honoured it.
- **Do not** trade grouped security updates for one-PR-per-advisory. Grouping is not implicated,
  and unpicking it would multiply the PR volume for no benefit.
- **Do not** re-enable auto-delete-on-merge. The entry below already says this for the
  branch-recovery reason; this entry adds a second, independent reason.
- If a promotion is ever merged with auto-delete re-enabled by accident, expect the whole open-PR
  queue on `main` afterwards and **check the head-branch name before assuming a routing bug**.

Written into `CLAUDE.md` § Dependency hygiene and a new `CONTRIBUTING.md` subsection, § *A version
update on `main` means something else went wrong*, with the two-signal table (head-branch segment,
timeline event) for telling the two causes apart.

---

**6. The three advisory tracking issues re-verified after the v0.2.0 tag — two of the three closed.**

v0.2.0 was released 2026-08-02T00:03:32Z, so the "re-confirm at each release" cadence each issue
sets for itself is due. All three were checked against the tree and against current advisory data.
**#124 and #125 both closed** — the first by applying the bump, the second because the advisory had
moved under it. #123 stays open, unchanged.

- **#123 (GHSA-qwww-vcr4-c8h2, `react-router`) — still accurate, no change.** `react-router-dom` is
  still pinned 7.18.1 resolving `react-router@7.18.1`; `frontend/src/main.tsx` still uses
  `<BrowserRouter>`; there is still no `react-router.config.ts` and no `@react-router/*` package.
  The advisory range is unchanged at `>=7.12.0 <8.3.0`, no 7.x fix has appeared, and `npm audit`
  still offers only the `react-router-dom@7.11.0` **downgrade** as its "fix". The acceptance holds
  exactly as written.
- **#124 (GHSA-r28c-9q8g-f849, `postcss`) — bumped by hand, 8.5.16 → 8.5.25, and closed.**
  Detailed below.
- **#125 (GHSA-mh99-v99m-4gvg, `brace-expansion`) — materially wrong, corrected and closed.**

---

**`postcss` 8.5.16 → 8.5.25, applied by hand (closes #124).**

**Why by hand.** `.github/dependabot.yml` targets `dev` for npm version updates and would normally
propose this, but it has **not**, and after the three closures above there are **no open Dependabot
PRs at all**. A HIGH advisory waiting on a bot that is not going to act is worse than the small
diff, so the bump was applied directly. The original plan to defer it to its own PR was wrong for
the same reason.

**Which version actually clears it — verified in the published source, not from the range.** The
advisory reports affected `<=8.5.17`, first patched **8.5.18**. That number was checked rather than
taken, because the `brace-expansion` case immediately above is a live example of an advisory range
being wrong mid-flight. Unpacking the tarballs, `lib/previous-map.js`'s `loadFile()` in **8.5.18**
gains the containment check the advisory describes and 8.5.17 does not have:

```js
if (cssFile) {
  let relativePath = relative(dirname(cssFile), path)
  if (relativePath === '..' || relativePath.startsWith('..' + sep) || isAbsolute(relativePath)) {
    return undefined
  }
}
```

That is exactly the fix for "path traversal in previous source-map auto-loading" — a
`sourceMappingURL` can no longer point outside the stylesheet's own directory. **8.5.18 is
therefore the real floor**, confirmed independently of the advisory metadata. The same check is
still present in **8.5.25** (renamed `relativePath` → `rel`, semantics identical), which is what
was pinned: it is the current release on the pinned 8.5 line, and `CLAUDE.md` § Dependency hygiene
asks for current, actively-maintained pins rather than the bare minimum that clears a finding.

**No `overrides` entry was needed, and no parent was bumped.** `postcss` is a **direct
`devDependency`** in `frontend/package.json`, not only transitive as first assumed — the six
packages that also reach it (`vite`, `postcss-preset-mantine`, `postcss-mixins`, `postcss-js`,
`postcss-nested`, `postcss-simple-vars`, `sugarss`) declare it as a **peer** or caret range
(`^8.4.21`, `^8.2.14`, `>=8.0.0`, `vite`'s `^8.5.3`), all of which 8.5.25 satisfies. So raising the
single direct pin lifts the whole tree, and `npm ls postcss --all` shows every consumer deduped
onto one 8.5.25 copy. The escalation condition — *"if the fix requires a major bump of a parent
package, stop"* — did not arise.

**Regenerated with npm, not by editing version strings** (`npm pkg set` + `npm install
--package-lock-only`), so `resolved` URLs and `integrity` hashes moved with the version. The diff
is three lock hunks and one `package.json` line: `postcss` 8.5.16 → 8.5.25, its `nanoid` floor
`^3.3.12` → `^3.3.16`, and the resulting `nanoid` 3.3.15 → 3.3.16 — all `dev: true`, no new
packages.

**Verified after:** `npm ci` installs 8.5.25 and the installed
`node_modules/postcss/lib/previous-map.js` carries the containment check; ESLint, Prettier, the
20-file / 69-test Vitest suite and `npm run build` all pass; and **`npm audit` no longer reports
`postcss`** — the remaining two highs are the `react-router` / `react-router-dom` pair from #123.
Nothing ships either way: PostCSS runs during `vite build` and the runtime image copies only
`dist/`.

#124 was closed on its own stated criterion — *"close by hand once `postcss` is pinned at 8.5.25+
and the frontend build and Vitest suite pass"* — the same standard applied to #125.

---

**What #125 asserted**, on 2026-07-31: the advisory covers `<=5.0.7`, so Scrye's 1.1.18 and 2.1.4
are both still inside the affected range; there is no fixed release on the 1.x or 2.x lines; the
bump taken in #121 is "currency, not a clearance" and "clears nothing"; the only route out is
ESLint 10.

**What is actually true.** The advisory was **revised on 2026-07-31**, the same day #125 was
written, from a single flat `<=5.0.7` range into per-major ranges:

| Affected | First patched |
| --- | --- |
| `>= 4.0.0, < 5.0.8` | 5.0.8 |
| `>= 3.0.0, < 3.0.3` | 3.0.3 |
| `>= 2.0.0, < 2.1.3` | 2.1.3 |
| `< 1.1.17` | 1.1.17 |

Scrye carries **1.1.18** and **2.1.4**. Both are at or above their line's first patched version, so
**neither copy is affected** — the #121 bump did clear the advisory after all. `npm audit` agrees:
`brace-expansion` no longer appears in its output at all (the three remaining highs are the
`postcss` and `react-router`/`react-router-dom` entries from #123 and #124).

**Verified at the source, not from the advisory metadata** — which is the whole point of `CLAUDE.md`
§ Dependency hygiene, and doubly so here, since it was believing a flat advisory range that put the
wrong claim into #125 in the first place. Unpacking the published tarballs: **1.1.17** adds
`EXPANSION_MAX_LENGTH = 4000000`, bounding the total character count the expansion accumulator may
hold, and rewrites `expand()` to iterate rather than recurse — with the code comments naming
**CVE-2026-14257**, the CVE behind this GHSA, explicitly. 1.1.16 has none of it. **2.1.3** carries
the identical fix. 1.1.18 and 2.1.4 extend the same bound to sequence expansion. Both copies
installed under `frontend/node_modules/` were checked directly and contain `EXPANSION_MAX_LENGTH`.

**#125 was corrected and closed** rather than left open with a note, on its own stated criterion:
"close by hand once every `brace-expansion` copy resolves to 5.0.8+, **or a backport lands on the
1.x and 2.x lines**." The backport landed. Its "review cadence" section had also anticipated this
exact outcome — "check whether a 1.x or 2.x backport has appeared (which would close this cheaply)
before assuming the major is still the only route" — so the issue contained the instruction that
resolves it. No duplicate was opened.

**What this does *not* change:** the ESLint 10 / frontend-tooling-majors item in
`docs/ROADMAP.md` stands on tooling-currency grounds, exactly as #125 said it should. It was never
justified by this advisory, so retiring the advisory does not touch it.

**And the shipped `CHANGELOG.md` is left as published.** Its `[0.2.0]` § Security text describes
the brace-expansion bump as currency that clears nothing, which was true against the advisory data
available when v0.2.0 was tagged and is a published release record. Rewriting shipped release notes
to match later advisory revisions would make the changelog a moving document; this entry is the
correction, and it is where a reader is pointed.

---

**7. A roadmap item added for GitHub code scanning (CodeQL).**

Scrye gates on *dependency* vulnerabilities every PR — Trivy and Grype dogfood the image — but
nothing analyses Scrye's own source for injection, path-traversal, unsafe-deserialization or
missing-authorization patterns. CodeQL covers both languages in this repo and is **free for public
repositories**, which this one is.

Recorded in `docs/ROADMAP.md` § Near-term as work needing **its own scoped session**, not a
settings-page click, for two stated reasons: default setup **adds a workflow that runs on every
push and pull request**, so it joins the per-PR gate immediately and interacts with the
still-open branch-protection item; and the first run **typically surfaces a batch of findings that
all need triage at once** — genuine issues, false positives needing written dismissals, and
generated or vendored code that should be excluded from analysis. The item also flags the
default-vs-advanced-setup decision (advanced fits this repo's SHA-pinned, explicitly-configured
workflow convention and is the only option that can tune query suites or path filters), and
requires triage decisions to be written down, on the same reasoning as the governance entry below:
a dismissal with no recorded reason is indistinguishable from an unread finding.

---

**Plan section affected:** `backend/pyproject.toml` + `backend/requirements.lock` (fastapi);
`frontend/package.json` + `frontend/package-lock.json` (postcss);
`.github/workflows/{publish,dev-nightly,rescan}.yml` (login-action SHA);
`.github/dependabot.yml` (node-major and `scrye` ignores); `docker/Dockerfile` (comment pointer);
`docs/ROADMAP.md` (Node 22→24 item rewritten, CodeQL item added); `CLAUDE.md` § Dependency hygiene
and `CONTRIBUTING.md` § Releasing (the version-update-on-`main` cause). No locked decision is
touched: the runtime stays Python 3.14.6, the frontend builder stays Node 22, Mantine v7 and React
18 are untouched, distribution stays GHCR-only, and `docker/docker-compose.yml` still builds the
app image locally. Extends the two 2026-08-02 entries below — the auto-delete finding (whose second
blast radius is item 5) and the `scrye:0.2.0` diagnosis (whose fix is item 4).

---

### 2026-08-02 — Process/Governance — Public-repo governance checklist verified in GitHub Settings; five of eight items closed

**What changed:** the public-repo governance checklist under `docs/ROADMAP.md` § Near-term was
worked through in GitHub Settings and **five of its eight items are now closed**; those five were
struck from the checklist and the three that remain open were left in place. Nothing in the
repository changed as a consequence — this entry *is* the change, for the reason given under
**Why** below. No code, schema, API contract, security model, job model, auth, or CI behavior is
affected.

**Closed — verified, and the state each is now in:**

1. **GitHub profile display name set to `tyler-rich`.** This closes **R7/D4** (the 2026-07-13
   squash-merge-authorship entry). GitHub authors a merge performed through the web UI — the
   squashed commit of a feature PR, and the merge commit of a promotion — as the merging account's
   *profile display name*, which repo-local `git config user.name` cannot override. While the
   profile read "Tyler Richardson", every such merge silently violated `CLAUDE.md`'s
   author-identity rule no matter how carefully the branch commits were authored. With the display
   name changed, the rule now holds end-to-end.
2. **`DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` repo secrets deleted.** Unreferenced by any workflow
   since the GHCR consolidation (§14 2026-07-09) — dormant registry credentials sitting on a
   public security-tool repo.
3. **GHCR package `ghcr.io/tyler-rich/scrye` confirmed public.** §14 2026-07-06 asked to confirm it
   was *private*, which inverted when the repo went public on 2026-07-09; it is public, as locked
   decision §6 requires.
4. **Dependabot security alerts confirmed enabled, and Dependabot malware alerts enabled.** The
   `.github/dependabot.yml` file only schedules *version* updates; alerting is a separate repo
   setting. Malware alerts were not on the original checklist and were switched on in the same
   pass.
5. **Actions workflow permissions confirmed set to "read repository contents and packages"
   only, with "Allow GitHub Actions to create and approve pull requests" unchecked.** Both were
   **already correct — verified, not changed.** Recording that distinction is the point: an item
   found already-correct and an item never looked at are indistinguishable from inside the
   repository, and this checklist existed because exactly that ambiguity let items sit. The
   restrictive default breaks nothing, including GHCR push, because every workflow declares its
   own explicit `permissions:` block and an explicit block takes precedence over the repo default
   rather than being capped by it.

**Still open — unchanged, and not to be treated as done:** branch protection on `main` and `dev`;
the signed-commit-enforcement decision; enabling private vulnerability reporting so `SECURITY.md`'s
stated channel actually exists. The branch-protection item picked up a scoping note from the
auto-delete finding in the entry below — an existing ruleset's *Restrict deletions* did not hold
against an admin — but the item itself is untouched.

**Why this is logged here at all:** a repository-settings change produces **no artifact in the
codebase**. There is no diff, no file, no CI run, nothing a later session can grep for. That
invisibility is not incidental — it is precisely why several of these items sat undone for weeks
after first being written down in §14 prose, until they were collected into a ROADMAP checklist so
they were at least visible in one place. Striking an item from that checklist without a dated
record here would restore the original failure mode in a worse form: the list would say "done"
with nothing behind it, and no way to tell a verified setting from an assumed one. So the rule
this entry establishes is that **the checklist tracks what is open; §14 records what was actually
verified and when** — including, explicitly, which items were found already correct.

**Plan section affected:** `docs/ROADMAP.md` § Near-term (governance checklist reduced to its
three open items, with a pointer here and a scoping note on branch protection). Closes R7/D4 from
the 2026-07-13 squash-merge-authorship entry, and the settings-side items carried from §14
2026-07-06, 2026-07-09, and 2026-07-20.

---

### 2026-08-02 — Infra/Process — Auto-delete-on-merge deleted `dev` during the v0.2.0 promotion; the ruleset's admin bypass is why "Restrict deletions" did not stop it

**What changed:** the repository setting **"Automatically delete head branches" has been
disabled**. Stale branches are pruned by hand instead. No repository content changed; this entry
is the record.

**What happened:** merging the v0.2.0 `dev` → `main` promotion PR (#122) **deleted the `dev`
branch**. `dev` is the *head* branch of a promotion PR, so auto-delete-on-merge treated it as a
spent feature branch. The ref was still available and `dev` was recovered with GitHub's **Restore
branch**.

**Why the ruleset did not prevent it — this is the part worth remembering:** the `protect-dev`
ruleset has **"Restrict deletions" enabled**, and it made no difference. The ruleset's **bypass
list grants Repository admin "Always allow"**, and auto-delete-on-merge runs with the **merging
user's** authority — an admin. So the deletion was performed by a principal the ruleset
unconditionally exempts, and the restriction was never evaluated as a block. Nothing was
misconfigured in the ruleset; it did exactly what its bypass list says.

Two consequences follow, and both matter more than the one-off recovery:

- **This would recur on every release.** It is not a fluke of #122. Every `dev` → `main`
  promotion PR has `dev` as its head branch, and promotions are merged by an admin by
  construction — so with auto-delete on, `dev` gets deleted at each release, and each recovery
  depends on the ref still being restorable.
- **The ruleset alone is not protection while admin bypass is on.** Do **not** re-enable
  "Automatically delete head branches" on the belief that *Restrict deletions* covers it. It does
  not, for the repository owner, which is the only account that merges promotions. Re-enabling it
  would need the bypass list narrowed first — and that is a separate decision with its own
  friction, since the same bypass is what makes ordinary admin operations possible on a
  single-maintainer repo. The chosen mitigation is the cheap one: leave auto-delete off.

This also sharpens the still-open branch-protection item in `docs/ROADMAP.md` § Near-term, which
now carries a pointer to this entry: a rule configured on a protected branch should be assumed
**advisory for the repository owner** until the bypass list has been examined. A ruleset that
reads "enabled" in the UI is not evidence that it will stop an action taken by an admin.

**Plan section affected:** none of the plan proper — repository settings and operational process.
`docs/ROADMAP.md` § Near-term gains the scoping note on branch protection. Related: the
2026-07-31 promotion-merge-method entry above, which is what made the v0.2.0 promotion a merge
commit; the deletion is independent of the merge method.

---

### 2026-08-02 — Infra — Dependabot's docker run fails on our own local build tag `scrye:0.2.0`

**What changed:** nothing yet in this PR — this records the diagnosis. The fix (an `ignore` entry
for `dependency-name: "scrye"` in `.github/dependabot.yml`) is being applied in the follow-up
dependency PR. **It landed** — see the 2026-08-02 post-v0.2.0 dependency-cleanup entry above,
item 4, which also confirms by reading both files that the compose file is the one carrying the
reference and adds the ignore to both docker entries.

**The failure:** Dependabot's docker run reports
**`private_source_authentication_failure`**. The cause is `docker/docker-compose.yml`'s app
service, which pins `image: scrye:0.2.0` — Scrye's **own local build tag**, built from
`docker/Dockerfile` by whoever runs the stack (released images publish to
`ghcr.io/tyler-rich/scrye`, per locked decision §6). Dependabot has no way to know that tag is
local: an unqualified name resolves to Docker Hub, so it looks up `library/scrye`, gets a **401**,
and reports the run as an authentication failure against a private source.

**Why the diagnosis is confident:** the other two images in the same file —
`aquasec/trivy` and `wollomatic/socket-proxy`, both fully qualified and both public — resolve
fine. So the ecosystem, the directory configuration, and Dependabot's access to the file are all
working; the failure is specific to the one reference that does not name a real registry image.
This has never affected the images Dependabot is actually there to track.

**The fix, and where it goes:** an `ignore` entry for `dependency-name: "scrye"` on the ecosystem
entry that scans `docker/docker-compose.yml` — in this repo that is the **`docker-compose`**
entry (`.github/dependabot.yml` has both a `docker` entry for `docker/Dockerfile`'s base images
and a `docker-compose` entry for the compose file's sidecars). If the failing run is surfaced
under `docker` rather than `docker-compose` in the UI, adding the same ignore to both entries is
harmless — the Dockerfile has no `scrye` reference for it to suppress. The alternative fixes were
rejected: qualifying the tag as `ghcr.io/tyler-rich/scrye:0.2.0` would make the compose file pull
a published image instead of the locally-built one, changing what the documented quick start does,
and dropping the tag entirely loses the version pin.

**Plan section affected:** `.github/dependabot.yml` (in the follow-up PR). No effect on the build,
the image, or locked decision §6 — `docker/docker-compose.yml` keeps building the app image
locally.

---

### 2026-07-31 — Process — `dev` → `main` promotions merge with a merge commit, not a squash

**What changed:** `CONTRIBUTING.md` § Releasing step 1 and `CLAUDE.md` § Git & PR conventions now
require promotions to be merged with GitHub's **"Create a merge commit"**, where they previously
said promotions are **squash**-merged (the rule adopted 2026-07-04 with the branching model, and
restated in the 2026-07-13 promotion-title entry). Feature and contribution PRs into `dev` are
**unchanged** — those are still squash-merged. Documentation and process only; no code, schema, API
contract, security model, job model, auth, or CI behavior is affected.

Three dependent passages were corrected in the same pass rather than left to contradict the new
rule:
- `CONTRIBUTING.md` § Releasing step 3 and the matching `CLAUDE.md` back-merge bullet both described
  the post-promotion back-merge as an exercise in resolving `main`'s squashed copy of already-
  promoted work against `dev`'s newer versions. Under a merge commit that conflict does not exist —
  `dev`'s tip is already an ancestor of `main`'s, so the back-merge of a promotion **fast-forwards**.
  Both now say so, and both keep the "resolve in favour of `dev`" rule for the one case that still
  produces conflicts: a commit that landed on `main` independently of a promotion.
- The `CLAUDE.md` git-identity note said a **squash-merge** authors its commit as the merging
  account's GitHub *profile display name*. That is equally true of a merge commit, so the note was
  generalized to anything merged through the web UI, with the clarification that a merge commit
  leaves the individual promoted commits' own authorship intact.

**Why:** the argument is the divergence this session had to reconcile, not a preference. Squashing a
promotion replaces `dev`'s commits with one new commit on `main` that has **no ancestry link** to
them, so `main` and `dev` diverge the instant the promotion lands. Every subsequent back-merge is
then a conflict-resolution exercise against a squashed copy of work `dev` already has — which is
precisely the failure the 2026-07-07 entry documented and tried to manage procedurally rather than
remove.

It got worse than "manage procedurally." Because `main` was not an ancestor of `dev`, **#110** (a
Dependabot security update, which lands on `main` — see the entry below) could not be back-merged
cheaply, so **#119** *replicated* its change on `dev` as a separate commit instead of merging
`main`. Both branches had then independently edited `frontend/package-lock.json`, and the v0.2.0
promotion PR (#122) opened `dirty`. Resolving it required merging `origin/main` into `dev` and
hand-picking a side of the lockfile — on a file where picking wrong silently reverts a security
fix. That is a bad place to be for a purely mechanical reason.

A merge commit removes the cause: `main` keeps the individual commits a release is supposed to
preserve, `dev` stays an ancestor of `main`, the back-merge becomes a fast-forward, and a later
promotion cannot open `dirty` merely because the previous one squashed. The cost — a busier
first-parent history on `main` — is the thing a release branch actually wants to record.

**What this does not change.** Squash-merging remains correct for PRs into `dev`: those are the
PRs whose intermediate commits are noise, and `dev`'s one-commit-per-PR history is what makes a
promotion's commit list readable in the first place. The rule is asymmetric on purpose. The
existing § Git & PR conventions rule about **retargeting a stacked child PR after its parent was
squash-merged** is likewise untouched — it is about feature PRs into `dev`, where squashing still
applies.

**Plan section affected:** `CLAUDE.md` § Git & PR conventions (new promotion merge-method rule,
back-merge bullet rewritten, git-identity note generalized); `CONTRIBUTING.md` § Releasing (step 1
merge method, step 3 back-merge guidance plus a new pre-promotion reconciliation check). Supersedes
the squash-merge half of the 2026-07-04 branching-model entry and the 2026-07-07 back-merge entry;
both are left in place as the record of what was believed then.

---

### 2026-07-31 — Release/Process — v0.2.0 release prep: CHANGELOG cut, brace-expansion reapplied on `dev`, Dependabot security-PR routing documented

**What changed:** the `CONTRIBUTING.md` § Releasing "Before you tag" checklist run for **v0.2.0**,
plus the three items it turned up that had to land on `dev` before the promotion PR was opened. No
application code, schema, API-contract, security-model, job-model, auth, or CI-behavior change.

**1. `CHANGELOG.md` `[Unreleased]` cut to `[0.2.0] - 2026-07-31`.** A fresh empty `[Unreleased]`
sits above it and the reference-link block gained
`[0.2.0]: …/compare/v0.1.0...v0.2.0` with `[Unreleased]` re-pointed at `…/compare/v0.2.0...HEAD`.
`CONTRIBUTING.md` § Releasing describes this as a tag-time maintainer step; doing it **before** the
promotion means `main` receives an already-correct CHANGELOG rather than a commit landing on `main`
after the fact, outside a release.

A new **`### Security`** entry was added to the 0.2.0 section, because nothing in the section
answered the question the release actually exists to answer. Issue **#75** — the weekly
`rescan.yml` tracking issue — has been reporting fixable HIGH/CRITICAL CVEs against the published
`:latest` since 2026-07-20, and `:latest` has been the **v0.1.0 image from 2026-07-09** the whole
time. None of those findings is a defect in Scrye; they are advisories disclosed against the base
image and dependency tree after that image was built, and only a rebuild clears them. The entry
enumerates what actually moved since v0.1.0 (both Python stages 3.13 → 3.14.6; refreshed
`debian:bookworm-slim` and `node:22-bookworm-slim` digests; `fastapi`, `uvicorn`, `pydantic`,
`pydantic-settings`, `sqlalchemy`, `alembic`, new `greenlet`; `setuptools` pinned exactly and
hash-locked; the frontend `brace-expansion` bumps below) and — deliberately — what it does **not**
clear: the seven waived CPython interpreter CVEs, split across #98, #116 and #52.

The rest of `[Unreleased]` was re-verified claim by claim against the tree rather than trusted, per
the checklist's first item. It held up: the false-CVE correction from the 2026-07-26 entry is
present and accurate; the four waived CVEs it names, the `SCRYE_APP_SECRET_KEY_*` setting names,
the `mem_limit`/`mem_reservation` values and the CPU-limits overlay, the wollomatic uid 65534 /
`GET /images/json` allowlist / `DOCKER_GID` fallback of 999, the thirteen enveloped endpoints
(exactly thirteen `full_page(` call sites across `backend/app/api/`), the 3.14 dependency versions,
and all six cross-document references (four README anchors, `CONTRIBUTING.md` § API conventions,
`docs/ARCHIVE.md` §15) were each checked at the file. One sentence
was amended: "All four stay waived in the dogfood scan" was true but read as a total, and three
further `tarfile` CVEs had been waived after it was written (2026-07-30 entry), so it now says so
and points at § Security.

**2. `THIRD_PARTY_LICENSES/` re-verified.** The version table (Trivy 0.72.0, Grype 0.115.0, Syft
1.46.0) still matches the `TRIVY_VERSION`/`GRYPE_VERSION`/`SYFT_VERSION` args in
`docker/Dockerfile`, and all four bundled files were re-fetched from upstream at those tags and
compared byte-for-byte — `trivy/LICENSE`, `trivy/NOTICE`, `grype/LICENSE`, `syft/LICENSE` are
identical; Grype and Syft still 404 on `NOTICE`. No change was needed. This repeats the 2026-07-26
verification rather than inheriting it, which is the point of the checklist item.

**3. `brace-expansion` bumped on `dev` — 1.1.16 → 1.1.18, and the nested
`@typescript-eslint/typescript-estree` copy 2.1.3 → 2.1.4.** Dependabot proposed exactly this as
**#120**, but opened it against **`main`**, and retargeting left the diff stale, so #120 was closed
and the bump reapplied here. Regenerated with `npm update brace-expansion --package-lock-only` —
not by editing version strings — so `resolved` URLs and `integrity` hashes moved with the versions;
the resulting diff is 6 lines in each of the two entries and nothing else. `npm ci` installs
1.1.18 and 2.1.4, `npm run build` and the 20-file / 69-test Vitest suite both pass.

`dev` and `main` were confirmed to agree on `brace-expansion` **before** the promotion: #110
(1.1.15 → 1.1.16) was merged directly into `main` and back-merged to `dev` in #119, so both
branches read 1.1.16/2.1.3 at the promotion's merge base and the promotion cannot resolve away from
the earlier security fix.

**Known and deliberately not acted on:** GHSA-mh99-v99m-4gvg covers `brace-expansion` **`<=5.0.7`**,
so 1.1.18 and 2.1.4 are still inside the affected range — there is no fixed release on the 1.x or
2.x lines, and `npm audit fix --force` would resolve it by installing `eslint@10`. The bump is
therefore currency, not a clearance, and the CHANGELOG entry does not claim otherwise (CLAUDE.md
§ Dependency hygiene — advisory metadata is evidence, not proof). Both copies are `devDependencies`
reached only through the ESLint tree; neither ships in the image or the browser bundle. Tracked in
**#125**, which exists specifically because this invites one wrong conclusion: a bot proposed the
bump as a *security* update, the bump was taken, and the advisory is still open afterwards — without
a written record the next person reads that as dropped work rather than an accepted, unfixable-at-
this-major finding.

**4. Dependabot security-PR routing documented** — the actual lesson from #120, in `CLAUDE.md`
§ Dependency hygiene and a new `CONTRIBUTING.md` § Releasing subsection. `.github/dependabot.yml`
sets `target-branch: dev` on all six ecosystems, and that key is honoured for **version** updates
only; **security** updates ignore it and always open against the repository's **default branch**,
`main`. That is a GitHub limitation with no config-level workaround, so a Dependabot PR's base is
not predictable from the config and must be read off the PR. Two responses are correct — merge to
`main` and back-merge, or close and reapply on `dev` — and **retargeting is not a third one**: the
diff is not recomputed against the new base, so it goes stale as `dev` moves ahead and merging it
can revert newer work, up to and including the fix the PR exists to deliver. Retargeting also does
not re-run CI, since `on: pull_request` never fires on `edited` (already recorded in § Git & PR
conventions, and the same failure mode from the other direction). The stale parenthetical at
`CONTRIBUTING.md` § Releasing step 3 — "Dependabot targets `dev`, so promotion squashes are
normally the only thing the back-merge has to reconcile" — was corrected in the same pass; it is
exactly the belief that made #120 surprising.

**5. The `[0.2.0]` section was missing everything between v0.1.0 and the 2026-07-24 work.** The
first draft of the cut carried only what had been written into `[Unreleased]` since roughly
2026-07-24 — the socket proxy, the list envelope, the 3.14 move, the Compose and master-key work.
Everything promoted in **#70** (2026-07-13, i.e. #53–#67) and the #77–#88 batch that followed it had
never been changelogged at all, because v0.1.0 was tagged 2026-07-09 and #70 landed four days later.
That is roughly two dozen PRs of security and correctness work that genuinely ships in 0.2.0.

This was caught because the release notes drafted from the **commit range** described work the
CHANGELOG did not contain, so the notes' "full details" link pointed at a document missing half of
what a reader had just read. Backfilled from the #70 commit range and the §14 entries for that
batch — not from the release-notes draft, which is downstream of the same reading and would have
laundered any error in it.

Merged into the existing `Added`/`Fixed`/`Changed`/`Security` sections rather than added as a
separate "previously unreleased" block: 0.2.0 is one release, and a changelog-within-a-changelog
would make a reader track which half of it applies to them. Where an item was already covered —
the `setuptools` pin and `requirements.lock`, both already named in § Security — the existing bullet
was left and the new one written to complement rather than restate it.

Three of the six upgrade-affecting items in the release live in this backfill and were invisible
before it: the **SSRF egress guard** (`SCRYE_ALLOW_INTERNAL_EGRESS`, default off — likely to bite a
self-hosted deployment whose SMTP relay or registry is on the LAN), the **remote-clone-URL
requirement** for repository targets, and the **master-key entropy floor**, which will refuse to
start a v0.1.0 deployment whose key file holds a raw passphrase. The last is the sharpest: the
CHANGELOG now spells out that the fix is the `SCRYE_ALLOW_WEAK_MASTER_KEY` boot-and-rotate escape
hatch followed by a backup/restore cycle, **not** generating a fresh key, which would leave every
stored secret undecryptable.

Also recorded from that range: three API response changes narrower than the envelope but still
contract-visible — timestamps now serialize with an explicit `Z` (APIR-5), `/api/audit` renamed its
envelope key `entries` → `items` (APIR-8), and scan rows in list/history/dashboard responses dropped
`options`/`error` in favour of `has_error` (APIR-9).

**6. `README.md` stopped advertising a release that does not exist.** The image-tag table and the
`docker pull` block both used `:1.4.0` as the "pin a release" example, for a project whose only
release is v0.1.0. Corrected to `:0.2.0`. Cosmetic, but it is in the *Quick start* path on the page
a reader lands on the day the release goes out.

**7. Three dependency findings given live tracking issues.** All three are non-blocking and all
three would otherwise have been visible only in an `npm audit` run nobody makes a habit of:
- **#123** — GHSA-qwww-vcr4-c8h2, `react-router` 7.18.1. The only one on a **runtime** dependency.
  Not reachable: the advisory is specific to RSC mode, and Scrye is a declarative SPA
  (`<BrowserRouter>` in `main.tsx`, no data-mode router, no `@react-router/*` server package, no
  `react-router.config.ts`, no server actions, no react-router server process in the image). The fix
  is 8.3.0, a major; `npm audit fix --force` would "fix" it by **downgrading** to 7.11.0, below the
  vulnerable range, giving up sixteen patch releases to close an unreachable path. The reachability
  assessment is stated explicitly in the issue, in the shape #52 uses for the poplib acceptance.
- **#124** — GHSA-r28c-9q8g-f849, `postcss` 8.5.16, dev-only. Unlike the other two the fix is a
  patch-level bump (8.5.25) inside the pinned major, so there is no policy obstacle — just a routine
  bump.
- **#125** — the brace-expansion finding above.

**Also observed, not changed here.** `main`'s push CI is **red** at `086fb1e`: its image job still
builds on Python **3.13.14** and trips the Grype gate on CVE-2026-11940 (`tarfile`) and
CVE-2026-15308 (`html.parser`), both HIGH. `dev` waived them in #117 and moved to 3.14.6 in #91, so
the promotion is what fixes `main`'s CI — not a regression introduced by it. Relatedly, `main` also
carries the default-branch copies of `dev-nightly.yml` and `rescan.yml`, which is the copy scheduled
and tag-triggered runs execute, so both have been running versions of themselves that predate every
workflow change on `dev`; the promotion is what lands those too.

**Why:** every item is one the "Before you tag" checklist exists to catch, and all four are
permanent or expensive to undo once the tag exists — a CHANGELOG ships verbatim as published
history, a mis-verified `THIRD_PARTY_LICENSES/` is an Apache-2.0 §4 compliance defect in a
distributed image, and an un-triaged security PR left pointing at the wrong branch is how a fix
gets silently reverted. Items 1, 3 and 4 land on `dev` **before** the promotion PR so they flow to
`main` through it rather than as follow-up commits on a protected branch.

**Plan section affected:** `CLAUDE.md` § Dependency hygiene (new Dependabot security-update rule);
`CONTRIBUTING.md` § Releasing (checklist bullet, new § Dependabot security updates target `main`,
step-3 parenthetical corrected); `CHANGELOG.md` (`[0.2.0]` cut, new § Security, and the v0.1.0 →
2026-07-24 backfill across all four sections); `README.md` § image tags;
`frontend/package-lock.json`. No plan-level decision changed by this entry — the promotion
merge-method change is a separate decision, recorded in the entry above.

---

### 2026-07-31 — Infra/Process — Grype gate keeps its verdict *and* lists its waivers, from one scan

**What changed:** two edits to the Grype gate in `.github/workflows/ci.yml`, no change to
`ci/grype.yaml`'s entries or to `ci/trivyignore`:

1. The gate invocation gains `-o table -o json=/out/grype-gate.json` — **two outputs from one
   `docker run`**. `table` keeps the human verdict on stdout; the JSON is written to a mounted
   `/tmp/grype-out` for the next step.
2. A new **non-gating** step, *"Waived by ci/grype.yaml (informational)"*, `jq`-filters that JSON
   and prints exactly the CVEs waived by `vulnerability:` rules, labelled as deliberate exceptions
   rather than findings. It runs `if: always()`, so the waiver list still prints when the gate
   fails — precisely when you want to know what was already excused.

The gate's flags (`--only-fixed --fail-on high -c /.grype.yaml`, the three `--exclude`s) are
otherwise unchanged, so pass/fail behaviour is identical to before.

**Why:** the gate's output was `No vulnerabilities found`, **ambiguous between "nothing matched"
and "everything that matched was waived."** Grype's `ignore:` rules drop matched findings from the
report before it prints, so a clean-looking line is exactly what a seven-entry waiver list also
produces. Confirming a waiver had taken effect therefore required a controlled comparison against a
run from before it landed, rather than reading the log in front of you — a bad property for the
gate on a security product, where the reassuring output and the suppressed-into-silence output were
the same string.

**The naive fix does not work, and the reason is worth knowing: `--only-fixed` is itself
implemented as an ignore rule.** Simply adding `--show-suppressed` to the gate was tried first and
rejected on the evidence. Because `--only-fixed` is an ignore rule like any other, its matches land
in the same `ignoredMatches` bucket as the by-ID waivers, so `--show-suppressed` printed **every
won't-fix / unfixed package** as well: roughly **250 rows** (`curl`, `perl`, `libexpat1`,
`libssh2-1`, `libc6` …) against the 7 that were wanted. Worse, having rows to print, Grype emits the
table *instead of* the `No vulnerabilities found` line — so the verdict disappeared and confirming
"nothing real matched" meant checking that no row among ~250 lacked `(suppressed)`. That trades one
legibility problem for a bigger one. Filtering `appliedIgnoreRules` for entries carrying a
`vulnerability` key is what separates the deliberate by-ID waivers from the `--only-fixed` set and
from the location-based bundled-binary rules.

**One invocation, not two.** The JSON is a second output of the *existing* scan rather than a second
`grype` run. A second invocation would repeat the vulnerability-DB download and the full image scan,
and the image job is already the slowest in CI — paying that twice for log legibility would not be a
trade worth making.

**Exit code unaffected.** The gate's flags are unchanged and the new step is non-gating, so nothing
about pass/fail moved. Verified on this change's own run: three of the seven waivers are HIGH
(CVE-2026-15308, plus the tarfile pair CVE-2026-11940 / CVE-2026-11972) against a `--fail-on high`
gate, and the job passed while the follow-on step listed all seven.

**Not changed:** the waiver list itself — no CVE added, removed, or re-severitied; this only makes
the existing seven legible. The two informational scans (`if: github.event_name == 'push'`) are
untouched and still run only on pushes to `main`.

**Plan section affected:** CLAUDE.md § Dependency hygiene (dogfood gate), `.github/workflows/ci.yml`.

### 2026-07-30 — Infra/Process — Three `tarfile` interpreter CVEs waived as Group A-2 (issue #116); the grype.yaml blocks made self-describing

**What changed:** `ci/grype.yaml` gained a second Group A block waiving three CPython
interpreter-binary CVEs in the **`tarfile`** stdlib module, tracked in new issue **#116**. The
existing blocks were relabelled `Group A-1` (#98) / `Group A-2` (#116) / `Group B` (#52), and a
**"WHICH BLOCK IS TRACKED WHERE"** index was added at the top of the interpreter section so the
block → issue mapping is legible from the file without opening GitHub.

| CVE | Sev | Gates? | Defect |
| --- | --- | --- | --- |
| CVE-2026-11940 | HIGH | yes | Hardlink referencing a symlink stored deeper than itself makes the extraction fallback recreate the symlink at the shallower path, escaping the destination dir. Incomplete fix of CVE-2025-4330. |
| CVE-2026-11972 | HIGH | yes | Streaming mode (`mode="r\|"`) mishandles EOF: `_Stream.seek()` discarded `read()`'s result, so a truncated archive parses in an infinite loop. CWE-252. |
| CVE-2026-0864 | MEDIUM | no | Oversized extended-header (GNU long name/link, pax) size field caused a single huge pre-allocating read. |

**Why now:** the two HIGHs turned CI red on 2026-07-30, on a **docs-only commit** in the v0.2.0
version-bump PR (#115). Nothing in that diff touched a build input — the only `docker/Dockerfile`
change was a comment, no dependency or base-image digest moved — and the same job had passed on the
prior commit a day earlier. These are new advisories reaching Grype's DB, not a regression.

**Verification (2026-07-30), per CLAUDE.md § Dependency hygiene.** All three fixes are merged to the
`3.14` maintenance branch and absent from released `v3.14.6`, so all three close on **3.14.7** —
the same trigger as the #98 trio. Method: shallow blobless clone of `python/cpython`,
`git log -- Lib/tarfile.py` for the commits, `git merge-base --is-ancestor <commit> v3.14.6` for
release membership, plus a direct `3.14`-vs-`v3.14.6` file diff. **`v3.14.6` = commit `c63aec6`,
released 2026-06-10.**

| CVE | Upstream | 3.14 backport commit | Merged | vs. 3.14.6 cut | Ancestor of `v3.14.6`? |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-11972 | gh-151981 / GH-151982 | `e86666c` (#151992) | 2026-06-23 | +13 days | no |
| CVE-2026-11940 | gh-151558 | `79c06bd` (GH-151559) | 2026-06-23 | +13 days | no |
| CVE-2026-11940 (companion) | gh-151987 / GH-151988 | `5e0ef3f` (#152609) | 2026-06-29 | +19 days | no |
| CVE-2026-0864 | gh-151497 / GH-151498 | `2cf26d0` (GH-151979) | 2026-06-24 | +14 days | no |

Code-level: `3.14`'s `_Stream.seek()` has `if not data: break` where `v3.14.6` discards the read;
`makelink_with_filter()` re-filters against the hardlink's own name before the fallback and
`_extract()` threads `filter_function` into `_extract_one()`, neither present in `v3.14.6`;
`_safe_read()` + `_EXTHEADER_READ_CHUNK` bound the extended-header read, with an in-tree comment
citing `gh-151497`. Release state: `3.14` patchlevel reads `"3.14.6+"` and no `v3.14.7` tag exists.

**Does Scrye use the module?** **No** — `tarfile` appears nowhere in the repository; backup bundles
are a JSON envelope (`app/backup/bundle.py`), not tar. So the residual risk is unreachable stdlib
code present in the image, the same rationale the `poplib` acceptance (#52) rests on. Recorded per
CVE because the poplib precedent showed module reachability materially changes the acceptance.

**Grype was wrong in the pessimistic direction, again.** It reports `FIXED IN 3.15.0b4` for all
three. Read literally that means "unfixable below 3.15" and argues for a runtime bump — the precise
mistake CLAUDE.md's source-verification rule was written to prevent, and the third time this
column has misreported the 3.14 line (see 2026-07-25 and the two 2026-07-26 entries). **No 3.15
move is warranted and none should be scoped off the back of this.**

**Why a new issue rather than extending #98.** #98 carries its own source-verification evidence
dated 2026-07-26 and a review date scoped to its specific trio. Appending CVEs verified on a
different date against different files would leave that issue's evidence section not covering half
its own contents — which defeats the point of recording the evidence at all. Both are Group A with
the same 3.14.7 trigger and the same **2026-10-25** review date (deliberately aligned so one review
covers both), and each issue cross-references the other so the split reads as intentional rather
than as duplicate trackers to be merged later. The in-file index exists for the same reason: a
single shared "tracked in #NN" header is exactly what previously made two unrelated decisions look
like one (2026-07-26).

**Not changed:** #115 (the v0.2.0 version bump) is untouched — it stays clean release prep and goes
green on a re-run once this lands.

**Plan section affected:** CLAUDE.md § Dependency hygiene (dogfood gate, interpreter-CVE
source verification), `ci/` triage allowlists.

### 2026-07-29 — Post-v1 — App version bumped 0.1.0 → 0.2.0; the three independent declarations put under a drift guard

**What changed:** ahead of tagging `v0.2.0`, the app version moved `0.1.0` → `0.2.0` in the three
places that declare it — `backend/app/__init__.py` (`__version__`), `backend/pyproject.toml`, and
`frontend/package.json` (plus `package-lock.json`'s two root `version` fields, written by
`npm version --no-git-tag-version`). Four documentation/Compose references to the example image tag
`scrye:0.1.0` and the `/healthz` sample output were updated alongside them
(`docker/docker-compose.yml`, `docker/Dockerfile`'s build-command comment, `README.md` ×3).

New tests pin this so the next release cannot half-land:

- `backend/tests/test_version.py` (new) asserts `pyproject.toml`, `frontend/package.json` and
  `package-lock.json` all agree with `app.__version__`. Verified non-vacuous: reverting
  `pyproject.toml` to `0.1.0` fails the suite.
- `tests/test_settings_api.py::TestAbout::test_about_reports_version_and_counts` was asserting only
  that `body["version"]` was **truthy**. It now asserts `== __version__`, which is the property the
  About tab actually depends on.
- `frontend/src/components/settings/AboutPanel.test.tsx` gained a version-stat test binding the
  rendered value to its own card (`previousElementSibling` is the `Version` label) — the Scanners
  table has a `Version` column header, so the label alone does not identify the stat.

**Why:** the three declarations are **independent hardcoded literals** — nothing derives one from
another, and nothing derives any of them from the git tag. `publish.yml` computes the *image* tag
from the pushed ref (`${GITHUB_REF_NAME#v}`) but never stamps a version into the image: no
`--build-arg`, no `LABEL org.opencontainers.image.version`. So tagging `v0.2.0` would have published
`ghcr.io/tyler-rich/scrye:0.2.0` running an app that reported `0.1.0` on the About tab, `/healthz`,
the OpenAPI document, every backup bundle's `app_version`, and the `scrye_build_info` metric. That
is the exact drift this bump closes, and the drift guard is what stops it recurring silently.

Only `backend/app/__init__.py` is load-bearing at runtime — `pyproject.toml`'s is packaging metadata
and `frontend/package.json`'s is never bundled (no `define` in `vite.config.ts`, no import of it in
`src/`). They are still bumped together because a lockstep set with a test is honest, whereas two
stale copies are a trap for whoever greps for the version next.

**Deliberately not changed.** Historical `0.1.0` references in `CHANGELOG.md` (the `## [0.1.0]`
release section and its compare/tag links) and in this file's own prior entries are **release
history**, not the current version, and rewriting them would falsify the record. The backup-record
fixtures `backend/tests/test_backup.py:317` and
`frontend/src/components/settings/BackupsPanel.test.tsx:47` carry `app_version: '0.1.0'` as the
version stamped on a *previously stored* backup — arbitrary historical data, and arguably more
realistic left as an older version than the running one. `CHANGELOG.md`'s `## [Unreleased]` heading
is **not** converted to `## [0.2.0]` here: per `CONTRIBUTING.md` § Releasing that is a tag-time
maintainer step carrying the release date, and doing it in a pre-tag PR would date the release
wrongly.

**Recommendation recorded, not implemented (single-sourcing).** The duplication should collapse to
one source, and that source should be `backend/app/__init__.py` — it is the only copy with runtime
consumers, it needs no build step to be readable, and it is importable by everything backend-side
that already uses it. `backend/pyproject.toml` can stop restating it via setuptools' dynamic
version (`[project] dynamic = ["version"]` +
`[tool.setuptools.dynamic] version = {attr = "app.__version__"}`), which removes one copy outright.
`frontend/package.json` cannot read Python, and the SPA already gets the version from the About/
health API at runtime rather than from the bundle — so the honest options there are to drop the
field to a fixed placeholder (it is `private: true`, so npm never publishes it and the number is
decorative) or to leave it and let `test_version.py` keep it honest. Deferred rather than done
because it is a build-configuration change that wants its own PR and its own green CI run, not a
rider on a release-prep bump; see `docs/ROADMAP.md`.

The roadmap item pairs this with a second, related half: **stamping the version into the image**.
No `LABEL` exists in `docker/Dockerfile` and no `labels:`/`build-args:` in `publish.yml`,
`dev-nightly.yml` or `ci.yml` (none uses `docker/metadata-action`), so `docker inspect` on a
published image says nothing about what is inside it. That is metadata hygiene rather than a
defect — the running app reports its version correctly because `app/__init__.py` is baked in — but
it is the same problem seen from the outside, so the two belong together.

**Plan section affected:** §10.1 (README), CLAUDE.md § Definition of done (docs updated),
`CONTRIBUTING.md` § Releasing (pre-tag checklist).

### 2026-07-29 — Post-v1 — HTTPS enforcement made legible; `X-Forwarded-Proto` honored from configured proxies only

**What changed:** A real onboarding failure: a user deployed over plain HTTP and got 401s with valid
credentials, with nothing in the logs or the UI explaining why. The app was behaving correctly — the
session cookie is `Secure`, and a browser silently discards a `Secure` cookie set on an `http://`
page, so the login response was a `200` whose cookie never landed and every request after it was
unauthenticated. Nothing observable said so from either end. **The cookie posture is unchanged; the
failure is now legible**, in five parts:

- **Startup line** (`app.main.log_https_enforcement`). One INFO line states that HTTPS enforcement
  is ON, that **logins over plain HTTP will fail**, which peers forwarded headers are trusted from,
  and the exact opt-out — variable *and* value (`SCRYE_SESSION_COOKIE_SECURE=false`). With
  enforcement off it is a WARNING that session cookies now travel in cleartext. `*` in
  `SCRYE_FORWARDED_ALLOW_IPS`, unparseable entries, and an empty value each get their own warning.
- **Refusal at every session-minting path** rather than a session the browser will throw away.
  `POST /auth/login`, `/auth/setup`, `/auth/mfa/verify`, and the OIDC login start now check
  `session_cookie_would_be_dropped()` and return **503** with a transport-specific `detail` (OIDC
  redirects with `oidc_error=insecure_transport`). Setup is refused **before** the admin is created:
  creating it and then failing to log in would leave bootstrap permanently 409ing with nobody able
  to sign in.
- **A distinct log and audit path.** `app.api.auth._refuse_insecure_transport` logs at ERROR and, on
  the password-login flow, states which way the credentials came out — a valid-credential rejection
  says `THE SUBMITTED CREDENTIALS WERE VALID` and `This is NOT a bad-password rejection`. A new
  audit action `auth.login_blocked_insecure_transport` carries `{flow, scheme, credentials_valid}`.
  Bad credentials on this path still also record `auth.login_failed`, so failed-login accounting is
  not lost.
- **A login/setup banner** (`InsecureTransportAlert`), driven by two new **transport-only** fields on
  `GET /auth/status` — `https_enforced` and `transport_secure`. It states that this is an HTTPS
  configuration issue and not wrong credentials, and names all three remedies.
- **`X-Forwarded-Proto` support** (`app/core/forwarded.py`): a new `ForwardedProtoMiddleware` plus a
  `TrustedProxies` parser, wired as the outermost middleware in `create_app` and fed from a new
  `Settings.trusted_proxies` property.

**Non-disclosure (deliberate design, not incidental).** The credential check still runs on
`/auth/login` before the refusal — that is what lets the log distinguish a valid from an invalid
login — but the **client-visible** result is byte-identical for valid, invalid, and unknown accounts:
same status, same `detail`, and the same work performed, since `service.authenticate` already burns
an argon2 verification for an unknown user. The banner is rendered from `/auth/status` before
anything is submitted, so it cannot reflect credential state either. Only the server-side log and the
admin-only audit log carry the distinction. `tests/test_https_enforcement.py` asserts the identical-
response property directly.

**Why auto-detection was rejected.** The obvious "fix" — drop `Secure` when the request looks like
plain HTTP — is a silent security downgrade: a reverse proxy terminating TLS makes the app see HTTP,
so auto-detection would strip `Secure` on genuinely-HTTPS deployments, putting the session cookie of
a correctly-configured production install on the wire in cleartext. `Secure` is therefore never
dropped from an observed scheme; the scheme is used **only** to detect and explain a sign-in that
cannot succeed, and turning enforcement off stays an explicit operator decision.

**Trusted-proxy design.** Shape 2 (behind a TLS-terminating proxy) is the case most affected users
are actually in, and the real fix for them. uvicorn was already started with `--proxy-headers
--forwarded-allow-ips` by `docker/entrypoint.sh`, so `X-Forwarded-Proto` was in fact honored in the
shipped image — but only there: it was untested, invisible to the app-level code, absent under
`TestClient`, and absent in a dev server started without those flags. The new middleware makes it
explicit and testable, reusing `SCRYE_FORWARDED_ALLOW_IPS` (the boundary the deployment already
configures for `X-Forwarded-For`) rather than adding a second, divergable setting. Two properties are
load-bearing:

- **Upgrade-only.** The middleware may change the scheme `http` → `https`, never the reverse. This is
  what makes it compose with uvicorn's own `ProxyHeadersMiddleware`: uvicorn rewrites
  `scope["client"]` to the *forwarded client* once it trusts a hop, so by the time this middleware
  runs the peer is no longer the proxy's address and a downgrade decided from it would be wrong.
  Real TLS at Scrye's own listener also always wins.
- **Never blanket.** A peer that is not a parseable IP inside a configured network — including the
  `"testclient"` placeholder and any hostname — is untrusted, so an arbitrary client cannot claim an
  HTTPS transport. `*` is accepted for parity with uvicorn's flag (diverging would confuse more than
  it protects) but draws a loud startup warning; unparseable entries are reported and ignored rather
  than silently widening or narrowing the boundary.

**Status code.** `503 Service Unavailable`, not `401`: the credentials are not what is being
rejected, and the whole point is that this must not read as a bad password. `421 Misdirected Request`
is the closer semantic match for a scheme mismatch but was rejected — browsers give `421` special
retry handling on HTTP/2 connection coalescing, which would make a refused login retry oddly.

**Tests:** `backend/tests/test_https_enforcement.py` (29 tests) covers cookie attributes under all
three deployment shapes (direct HTTPS, behind a TLS-terminating proxy, plain HTTP with and without
the opt-out), the distinct valid- vs. invalid-credential log path and its audit record, the
identical-response property, `X-Forwarded-Proto` honored only from trusted sources (bare IP, CIDR,
untrusted peer, non-IP peer, proxy chain, upgrade-only), and the startup log's contents.
`frontend/src/pages/LoginPage.httpsAlert.test.tsx` covers the banner.

**Why:** The app was working correctly and appeared broken — the worst kind of onboarding failure,
and one no amount of correct behaviour fixes on its own.

**Plan section affected:** § Hard security rules (additive: the cookie posture and CSRF model are
unchanged; this adds a refusal + explanation path and an explicitly-bounded forwarded-header trust).
No schema, data-model, job-model, or locked-decision change. README § Reverse proxy (TLS) gains
"If you're not using HTTPS"; § Security model, § Configuration, and § Troubleshooting first-run
issues updated; `.env.example` regenerated from the amended `Settings` descriptions.

### 2026-07-29 — Post-v1 — Master-key source surfaced on the About tab (the durable channel chosen over a per-boot log line)

**What changed:** Settings → About gained one row reporting which master key is in force — its
**source** (`auto_generated` / `secret_file`) and its **path**, rendered as either "Auto-generated at
`<path>` — back this up; a Docker secret gives stronger at-rest separation" or "Supplied as a secret
file at `<path>` — keep your copy backed up". `core/system_info.py` gains `master_key_info()`
alongside `host_info()`, and `api/settings.py` adds `AboutOut.master_key`; the frontend renders it in
`AboutPanel.tsx`. No new endpoint, no new setting, no schema change.

**Why here rather than in the log:** the entry above (auto-generated master key) logs the
back-this-up warning once, at generation. The reviewer's question was what an operator who deploys
and returns six months later sees — nothing, in that design. The rejected alternative was a per-boot
warning that the generated key shares a volume with the database: it would fire on every start of the
**documented default** for most deployments, which is how operators learn to skip startup logs, and it
would cost the generation-time warning that actually matters. It also wouldn't work — nobody reads
startup logs at month six. The About tab is where an admin actually looks, so the fact lives there and
the per-boot log line stays as it was (a single-line source record, unchanged by this entry).

**Constraints the row is built to:**

- **No key material, and nothing else new.** Source and path only — deliberately *not* the key
  version, which is visible nowhere else and would be a new disclosure rather than a relocation of an
  existing one. A test asserts the response body does not contain the key file's contents and that the
  object's keys are exactly `{source, path}`.
- **Admin-only, on an endpoint that is not.** `GET /settings/about` is readable by every role (the SPA
  needs the instance name and health), so the row is populated per-request for admins and omitted
  otherwise; the path is deployment layout a viewer has no need for. The gate is
  `AuthContext.effective_role`, not `user.role`, so an **admin's role-capped API token** sees exactly
  what its role sees — the same capping rule as everywhere else.
- **Accurate for both sources, not autogen text shown unconditionally.** A deployment using a Docker
  secret gets the secret-file wording. Both variants say to back the key up, because losing it is
  equally fatal either way; only the separation advice is specific to the generated case.
- **Never the reason a page fails.** `master_key_info()` reads the *cached* startup resolution, so it
  does no filesystem work and cannot generate a key from a request; if the key does not resolve at all
  (a development instance, where the lifespan warns instead of failing) it returns `None` and the row
  is omitted rather than erroring the whole About response.

**Testing** matches how the other About rows are covered — through the API, since `host_info()` has no
unit test of its own either: both sources, the no-key-material/no-extra-fields assertions, omission for
a viewer, omission for a role-capped admin token, and omission when the resolution raises.

**Plan section affected:** §4.5 About/health tab — additive (one response field, admin-gated). No
schema, security-model, or job-model change; the key handling from the entry below is untouched.

---


### 2026-07-29 — Post-v1 — Master key auto-generated on first launch; the Docker secret keeps its precedence

**What changed:** A new deployment could not start until the operator had produced a master key by
hand (`openssl rand -base64 48 > docker/secrets/app_secret_key`). Because Compose validates a
file-backed `secrets:` entry *before* it reads the rest of the stack, a missing file failed
`docker compose up` outright rather than producing a startup error anyone could act on — a user hit
this as a first-run blocker. The key is now generated on first launch when none is supplied.

**The precedence order, which had exactly one entry before this change** (the file at
`SCRYE_APP_SECRET_KEY_FILE`, default `/run/secrets/app_secret_key`), is now, first match wins:

1. `SCRYE_APP_SECRET_KEY_FILE` — the Docker secret. **Unchanged, still highest.**
2. `SCRYE_APP_SECRET_KEY_AUTOGEN_FILE` (new, default `/data/app_secret_key`) — the key a previous
   start generated.
3. A key generated now and written to (2) — only when neither file exists and
   `SCRYE_APP_SECRET_KEY_AUTOGENERATE` (new, default true) is on.

No key is read from an environment variable or an image layer, as before;
`SCRYE_ALLOW_WEAK_MASTER_KEY` remains a validation opt-out, not a key source. Generation is
`os.urandom(48)` base64-encoded — byte-for-byte the documented `openssl rand -base64 48` form — so it
clears the SEC-3 entropy floor (valid base64 decoding to ≥ 32 bytes; see the 2026-07-13 security
batch entry, M2/SEC-3) without the weak-key opt-out. It is written `O_CREAT|O_EXCL` + `fsync`,
`chmod`-ed 0600 (the `O_CREAT` mode is a umask-masked ceiling, not a guarantee), then **re-stat
verified** for mode 0600 and owner-uid before use.

**The invariants are the substance of this change; the convenience is not.** A second master key
silently orphans every field-encrypted secret in the database — registry credentials, git tokens, the
OIDC client secret, TOTP seeds, scheduled-backup passphrases — while the app looks perfectly healthy,
so:

- **A key file that exists is used, never replaced.** If it is unreadable, empty, not base64, too
  short, or malformed, startup **fails**. Generation follows only from a *proven absent* file, never
  from a failed load. Absence itself must be proven: `_key_file_exists()` treats only
  `ENOENT`/`ENOTDIR` as absence and raises on any other `stat` error, so an unreadable parent
  directory can never read as "no key here".
- **An explicitly configured path is an assertion.** If `SCRYE_APP_SECRET_KEY_FILE` was set by any
  configuration source (env, `.env`, kwargs — tracked via pydantic's `model_fields_set`, exposed as
  `Settings.app_secret_key_file_is_explicit`) and the file is missing, startup fails rather than
  substituting a generated key: on an existing deployment that state means an unmounted secret, not a
  fresh install. Auto-generation applies when the setting is left at its default.
- **The two files may not disagree.** When a supplied secret is in force and a previously
  auto-generated file also exists, every `version → material` pair in the generated file must be
  present **under the same version** in the file in use, else startup fails. Version-aware, not
  material-aware: stored tokens name their key version, so the same key present under a different
  version number would still not be found at decrypt time.
- **A generation race cannot mint two keys.** The `O_EXCL` loser reads the winner's file. This
  surfaced a real bug the test caught: a third process that merely *saw the path exist* read the
  winner's zero-length file and failed. `O_CREAT|O_EXCL` publishes the file before its content, so
  the loader now retries — but only on the empty-file case, which is why the empty-file failure got
  its own `MasterKeyFileEmptyError` subclass. An earlier attempt gated the retry on `st_size == 0`
  *after* the failed read and had its own TOCTOU (content arriving between the two re-raised a
  failure the retry had already resolved); retrying the load itself is race-free.
- **A key that fails its permission check is removed by the call that created it** — nothing has read
  it, so no ciphertext exists under it, and leaving it would have the next start silently adopt the
  file this one refused. That is the only place in the codebase that deletes a key file.

**No crypto change:** the KDF, the token format, and every existing ciphertext are untouched
(regression-tested), and existing deployments resolve their key exactly as before.

**Compose/docs:** `docker/docker-compose.yml` and the README paste-in stack no longer require the
secret — the `secrets:` blocks and the `SCRYE_APP_SECRET_KEY_FILE` line are kept, commented out, with
the reason. README § The master key now documents the precedence order, what auto-generation does,
that the file must be backed up, what is lost if it isn't, and the **trade-off** that the generated
key sits on the same volume as the database it protects (field encryption then still covers narrower
disclosure — a leaked `.db`, a stray copy, log exposure — but not whole-volume compromise; supply a
Docker secret, or repoint `SCRYE_APP_SECRET_KEY_AUTOGEN_FILE`, to separate them).

**One documentation premise was corrected rather than repeated.** The task framing said a backup
bundle without the master key is useless for the encrypted fields. That is not true of Scrye's
bundles: §8's design decrypts each secret and **re-wraps it under the user's passphrase**, so a
bundle restores on a host with a different master key — and now onto a fresh deployment that
generated its own. The master key *is* required for a volume/file-level backup, where the rows are
master-key ciphertext, so README § Backup & restore now draws that line explicitly instead.

**Deviation from CLAUDE.md's hard security rule, stated plainly:** the rule read "the master key
comes from a Docker secret file (`APP_SECRET_KEY_FILE`), never an env var or image layer". The
Docker secret file is still the recommended production mechanism and still takes precedence, and the
key is still never an env var or an image layer — but it is no longer the *only* source. CLAUDE.md's
rule was amended in the same commit to say so, rather than leaving the file contradicting the code.
`docker/Dockerfile` deliberately does **not** set `SCRYE_APP_SECRET_KEY_FILE` as an image `ENV`: that
would make the path explicit for every deployment and re-break the zero-touch first run.

**Tests:** `backend/tests/test_master_key_autogeneration.py` (35 cases) covers generation on a clean
volume, the entropy floor without the opt-out, mode 0600 and owner, the one-time INFO backup notice,
existing keys reused verbatim, every malformed/unreadable/undeterminable case failing rather than
regenerating, the explicit-but-missing refusal, the two-key interlock (including the same key under a
different version, and the documented carry-forward that is accepted), eight-thread concurrent
startup producing exactly one key, the permission-check cleanup, and a generated key still decrypting
its data across a restart. Verified end-to-end against a running instance: first boot generated the
key at 0600 and reported `/healthz` healthy, a registry secret was stored, and after a restart the
same key was reused and a backup bundle built successfully (which decrypts every stored secret to
re-wrap it).

**The adjacent first-run blocker was fixed in the same PR, on review.** Tracing the NAS case the
original report came from (a bind-mounted `/data` whose ownership doesn't match the container uid)
produced a result worth recording, because it is not the obvious one:

| `/data` bind mount | `O_CREAT\|O_EXCL` | `chmod 0600` | owner re-stat | Outcome |
| --- | --- | --- | --- | --- |
| `0755`, foreign owner (not writable by the app uid) | EACCES | — | — | refuses, nothing left behind |
| `0777`, foreign owner (world-writable share) | ✓ | ✓ | ✓ | **works** — key `0600`, owned by the app uid |
| `2775` setgid, group-writable, gid matches | ✓ | ✓ | ✓ | **works** (file gid follows the dir; harmless at `0600`) |
| ownership-synthesizing fs (CIFS `uid=`, NFS squash) | ✓ | ✓ | ✗ | refuses, file deleted |

The load-bearing fact: **on Linux a newly created file always belongs to the creating process's
euid**, so a foreign-owned *directory* never trips the owner check. The ordinary NAS bind mount
(rows 2–3) passes. The owner check only fires where the filesystem *fakes* ownership, and there its
`0600` is meaningless anyway — the refusal is correct, and SQLite is already unsupported over CIFS.

Row 1 is **not** a new blocker introduced here: `docker/entrypoint.sh` runs `alembic upgrade head`
before the app starts, so an unwritable `/data` already killed the container with
`sqlite3.OperationalError: unable to open database file` — which names neither the path nor the fix.
That pre-existing failure is the same first-run-blocker class this entry is about, so it was fixed
here rather than deferred: the entrypoint now **preflights** the database directory (exists +
writable) before Alembic, and fails with the path, the container `uid:gid`, a literal
`chown -R <uid>:<gid> <host path>`, the `user:`-matching alternative, and the note that a named
volume inherits the right ownership from the image while a bind mount keeps the host's. Kept to a
dozen lines of `sh` — a probe file created and removed, no validation framework.

The two master-key messages in the same class were made equally actionable: the unwritable-directory
error carries the same uid/`chown` guidance, and the synthesized-ownership error now states that
`chown` **cannot** help and offers matching `user:` or a Docker secret instead. README
§ Troubleshooting first-run issues leads with both cases.

**Testing the entrypoint.** `backend/tests/test_entrypoint_preflight.py` executes the shipped script
with `sh` against real directory permissions, stubbing `alembic`/`uvicorn` on `PATH` (so "did the boot
stop before migrations?" is observable as an absent marker file) and rewriting only `cd /app/backend`,
a path that exists solely in the image. Every line under test — probe, ordering, message text — is the
shipped one. Two cases are skipped when the suite runs as **root**, which bypasses directory
permission bits; they were verified locally under uid 1000 and run for real in CI, which is non-root.
This is not a substitute for booting the image; CI's image job covers that.

**Also fixed in passing:** this section's index heading said "107 entries" while the index and the
section both held 108; it now reads 109, matching the count after this entry.

**Deliberately not done here:** a per-boot warning that the auto-generated key shares a volume with
the database. It would fire on every start of the documented default for most deployments, which is
how operators learn to skip startup logs — costing the generation-time backup warning that actually
matters. The existing one-line per-boot source record
(`Master key loaded from … (auto-generated, current key version v1)`) is the right size. The durable
channel for that fact is the admin **System panel** (`core/system_info.py` → `api/settings.py`), which
is where someone looks months later; that is a separate follow-up PR, not folded in here.

**Plan section affected:** §6 secrets-at-rest — additive (a second key *source*, no format or KDF
change); CLAUDE.md § Hard security rules (master-key sourcing) and § Required deliverables
(`.env.example` wording); two new `Settings` fields → regenerated `.env.example`; `docker/
entrypoint.sh` gains a data-directory preflight (startup behavior only — it fails a deployment that
was already broken, sooner and with a usable message). No schema, job-model, or API change.

---


### 2026-07-28 — Post-v1 — Compose `deploy:` keys retired for NAS portability; memory limits made portable, CPU limits moved to an opt-in overlay

**What changed:** `docker/docker-compose.yml` carried a `deploy.resources` block on **all three**
services and nothing else under `deploy:` — no `replicas`, `restart_policy`, `placement` or
`update_config`. A fourth copy of the same block sat in the paste-in stack in `README.md` § 3. All
four are gone; the constraints they expressed are not.

| Service | Was (`deploy.resources`) | Now |
|---|---|---|
| `scrye` | `limits.cpus "2.0"`, `limits.memory 2G`, `reservations.memory 256M` | `mem_limit: 2g` + `mem_reservation: 256m` in the base file; `cpus: 2.0` in the overlay |
| `trivy-server` (profile `trivy-server`) | `limits.cpus "1.0"`, `limits.memory 1G` | `mem_limit: 1g`; `cpus: 1.0` in the overlay |
| `docker-socket-proxy` (profile `docker-env`) | `limits.cpus "0.5"`, `limits.memory 64M` | `mem_limit: 64m`; `cpus: 0.5` in the overlay |

New file: **`docker/docker-compose.cpu-limits.yml`**, applied with a second `-f`
(`docker compose -f docker-compose.yml -f docker-compose.cpu-limits.yml up -d`), documented in
README § "Resource limits (and NAS platforms)" and in the file's own header.

**Why:** a user reported the stack would not deploy on their NAS. Several NAS container platforms
— Synology Container Manager and QNAP Container Station among them — reject or mishandle `deploy:`
keys, because the block is Swarm-oriented; Compose v2 honours it for a plain `docker compose up`,
but that only helps on a real Compose v2 host. A hardening measure that prevents deployment
outright is not providing the hardening, so the choice was between dropping the constraints and
re-expressing them.

**Why not just delete the limits.** They are a CIS-baseline containment control
(`CLAUDE.md` § Hard security rules), and the `0.5` cap on `docker-socket-proxy` is deliberate
rather than a round number: that sidecar is the only container in the stack that mounts
`/var/run/docker.sock`, and its cap is the documented bound on a wedged or runaway proxy. Deleting
the block would have discarded three tuned values and a documented control to fix a portability
problem that has a portable fix.

**Why the memory/CPU split is where it is.** Memory is the containment control that matters most
here: it bounds the OOM blast radius, and the RAM-backed `/tmp` tmpfs is charged against it (the
reason `docker-compose.yml` warns against enlarging that tmpfs). It also has a portable spelling
that predates `deploy:` — `mem_limit` / `mem_reservation` — accepted by every Compose
implementation, so it stays **on by default** and no platform has to opt in. CPU exhaustion
degrades where memory exhaustion kills, so CPU is the right half to make opt-in. It went to an
overlay rather than being deleted for the reason above; users whose platform rejects the overlay
too can set CPU caps in their platform's own container UI, which writes them straight to the
Docker API.

**Why the overlay uses `cpus:` and not `deploy:`.** The first draft of the overlay used a
`deploy.resources.limits.cpus` block — on the reasoning that opting in implies a platform that
supports `deploy:`. `docker compose config` rejected the merged project outright:

```
services.scrye: can't set distinct values on 'mem_limit' and 'deploy.resources.limits.memory'
```

Compose normalizes `mem_limit` and `deploy.resources.limits.memory` into one field and validates
that they agree; an overlay contributing a `deploy.resources.limits` map with no `memory` in it
therefore conflicts with the base file's `mem_limit`. The overlay would not have applied at all.
The portable `cpus:` key merges cleanly and is accepted by more implementations besides.

**`cpus:` is the same limit, not a weaker one — verified, not assumed.** Compose enforces the
identical normalization for CPU as for memory: a service setting both `cpus: 2.0` and
`deploy.resources.limits.cpus: "3.0"` is rejected with `can't set distinct values on 'cpus' and
'deploy.resources.limits.cpus'`, and setting both to the same value is accepted and normalizes to
one limit. A key that were merely parsed and ignored could not participate in that check. This is
the evidence the caps still bind; it is not a claim from documentation.

**Validation.** `docker compose config` was run on all four combinations — base alone and
base + overlay, each with no profiles and with `--profile trivy-server --profile docker-env` — and
all four parse. The merged config reports exactly the pre-change values: `cpus 2` / `mem_limit
2147483648` / `mem_reservation 268435456` for `scrye`, `cpus 1` / `1073741824` for `trivy-server`,
`cpus 0.5` / `67108864` for `docker-socket-proxy`. Only the Compose CLI is available in this
environment (no daemon), so **no container was started**: the claim verified here is that the
files parse and normalize to the original limits, not that a live container was inspected for
them. `docker compose up` / `/healthz` (§ Definition of done item 4) is unverified this session
for that reason.

Five regression guards were added to `backend/tests/test_compose_hardening.py` — no `deploy:` key
in either file, a `mem_limit` for every service, `scrye`'s `mem_reservation`, a `cpus` entry in the
overlay for every service the base file defines, and the overlay's use of the portable key. They
were exercised against seven mutations of the real files (a `deploy:` block returning, the overlay
deleted, `mem_limit`/`mem_reservation` dropped, a new uncapped service, the overlay reverting to
`deploy:`, and the socket-proxy cap loosened) and each fires on the regression it names, with the
unmodified files clean. They are string-level like the rest of that module, deliberately: the
backend declares no YAML parser, and PyYAML is only present transitively. The backend suite could
not be run here (this container has Python 3.11; the backend requires 3.14), so the test bodies
were executed standalone against the checked-in files rather than under `pytest` — CI is the gate.
`ruff` and `black` are clean.

**Plan section affected:** §9.2 (Compose stack), `CLAUDE.md` § Hard security rules (CIS baseline —
resource limits retained, one of the two now opt-in), § Required deliverables (README). No
application code, schema, API-contract, security-model, job-model, or auth change.

---


### 2026-07-26 — Infra/Process — `node:22-bookworm-slim` digest refreshed; the Node 24 move and the #86 frontend tooling majors recorded in the roadmap

**What changed:** Two small, related items.

**1. `docker/Dockerfile`'s `frontend-builder` base digest rolled forward.**
`node:22-bookworm-slim` was pinned at `sha256:53ada149…`; the tag now resolves to
`sha256:6c74791e…`, which is **Node 22.23.1** (`jod`), pushed 2026-07-14. Verified against the
registry rather than taken from the bump metadata: `registry-1.docker.io`'s manifest endpoint
returns that digest for the `22-bookworm-slim` tag, the index it points at is an OCI image index
carrying both `linux/amd64` and `linux/arm64` (both legs of the multi-arch build), and Docker Hub's
tag listing shows the same digest shared by `22.23.1-bookworm-slim`, `22.23-bookworm-slim` and
`jod-bookworm-slim` — which is what actually establishes the version behind the moving tag. The
line also gained a comment recording why it stays on 22 and where the 24 move is tracked.
**Nothing structural changed** — no stage boundary, no layer ordering, no cache scope
(`CLAUDE.md` § Build performance, `§ Build performance` § Invariants). Only the digest moved.

**Why it was stale.** This is the same case as the `debian:bookworm-slim` refresh in #104, and it
has the same cause. Dependabot's `docker-images` group does not offer digest refreshes within a
major line — it offered **node 22 → 26**, a major on a line that is not LTS. Declining that major
is correct, but declining it is *all* that happened, so the 22 pin simply sat where it was. A
digest pin does not maintain itself, and the bot that would normally nag about it was proposing
something else entirely. Refreshing the digest is the actual maintenance action; the major was
never the same question.

**Why 22 and not 26 — and why 24 is the eventual answer.** From the upstream release schedule
(`nodejs/Release`): **22** (`jod`) entered maintenance 2025-10-21 and is supported through
**2027-04-30**. **24** (`krypton`) has been Active LTS since 2025-10-28 and is supported through
**2028-04-30** — it is the current Active LTS and the right target. **26** does not become LTS
until **2026-10-28**, so today it is `Current`, not a base for a build image. Staying on 22 is
therefore a hold, not a decision to stay: it is where the pin is until the 24 move is done
properly, since that move also touches `.github/workflows/ci.yml` (`node-version: "22"`) and
`CONTRIBUTING.md`'s Node floor and has to land as one change across all three.

**2. Three deferred items written into `docs/ROADMAP.md` § Near-term.** All three already
existed as decisions; none of them existed anywhere a reader would find them, which is the
failure mode this repo has hit before (see the 2026-07-26 governance-checklist entry — items sat
invisible in §14 prose for weeks).

- **Node 22 → 24**, with the three-file scope above and the note that Dependabot will keep
  offering 26 rather than the refresh.
- **The frontend tooling majors left over from Dependabot #86** after the Mantine/React ignores
  landed: TypeScript 5.7 → 7.0, ESLint 9 → 10, `typescript-eslint` 8.19 → 8.65, Vite 6 → 8,
  Vitest 3 → 4, jsdom 26 → 29 and the smaller bumps beside them. The 2026-07-26 Dependabot entry
  already said these were "not locked, wanted, and their own PR" — but that sentence was inside an
  entry about *ignoring Mantine and React*, so the wanted half was recorded only as an aside to
  the declined half. They share one real risk: every one of them lands on the type-aware ESLint
  gate turned on 2026-07-24, so the work is the lint-config churn, not the version numbers.
- **The deprecated Starlette status-code constants.** `status.HTTP_422_UNPROCESSABLE_ENTITY`
  emits a `StarletteDeprecationWarning` on every attribute access, at **22 call sites** across
  seven routers; the same rename hit `HTTP_413_REQUEST_ENTITY_TOO_LARGE` at 2 more in
  `uploads.py`. These have been noted as "pre-existing" in the validation paragraph of both
  interpreter-bump entries (2026-07-03, 2026-07-25) and cleared by neither — a warning described
  as pre-existing twice is a backlog item, not a footnote.

  Verified against the pinned **starlette 1.3.1**, not assumed from the warning text: both old
  names still resolve and both warn, the replacements `HTTP_422_UNPROCESSABLE_CONTENT` and
  `HTTP_413_CONTENT_TOO_LARGE` exist, and each pair is the same integer (422, 413) — so the
  cleanup cannot move a status code. The count is from the tree (`grep` over `backend/app`): **22**
  and **2** call sites, not the 44 the item was scoped at.

**Validation.** Lint and the test suites are CI's — the local container has no Python 3.14, so the
backend suite could not be run here and is not claimed to have been. The digest claim was checked
directly against `registry-1.docker.io` and the Docker Hub tag API; the Node dates against
`nodejs/Release`'s `schedule.json`; the Starlette constants against an install of the exact pinned
version. Backend code is untouched by this entry, so no test outcome changes; the image build is
the gate that matters and it runs in CI.

**Plan section affected:** §9.1 (image build), `CLAUDE.md` § Dependency hygiene, § Build
performance (invariants respected — read, not altered), § Required deliverables
(`docs/ROADMAP.md`). No application code, schema, API-contract, security-model, job-model, or auth
change.

---


### 2026-07-26 — Docs/Process — Review documents retired; §14 made contiguous and indexed; a false CVE claim removed from the CHANGELOG
**What changed:** A docs-only cleanup acting on the 2026-07-26 repository audit
(`docs/reviews/CLEANUP-AUDIT.md`, #101). No application code, CI, Compose, or configuration
behavior changed. The audit's own findings were **re-verified rather than inherited** — it was
explicit about what it had not checked, and two of its claims did not survive (see "Corrections"
below).

**1. `docs/reviews/` and `docs/upgrades/` are deleted; §15 replaces them.** Twelve review reports
and one upgrade handoff doc — every finding in them closed — sat at the same directory level as
the two live documents, so `docs/` read as twelve historical files next to two current ones. They
are gone. `docs/` now contains exactly `ARCHIVE.md`, `ROADMAP.md`, and `screenshots/`.

**A `docs/history/` subtree was considered and rejected.** The audit recommended moving the
reports under `docs/history/reviews/` with a README banner. The argument against deletion was
never "someone might want to read them" — it was that §14 cites bare finding IDs (`SC-12`,
`P3-4`, `QUA-17`, `H5/CON-4`) relentlessly and never re-explains them, so without the reports
those citations are unresolvable, and §14 is a document CLAUDE.md § Definition of done obliges us
to keep writing to. That argument is satisfied by a **decoder**, not by the reports themselves:
the new **§15** resolves every ID from all ten reports to one line and its resolving PR. Git is
the archive for the rest. Keeping a `history/` tree would have preserved 300 KB of superseded
reasoning to answer a question a 250-line table answers, and — as the audit itself observed about
archiving an audit of an archive — is how the folder reached twelve files in the first place.

**The originals are fully retrievable.** The commit immediately before the deletion is
**`0780b07e5e440dcc34ce23f0a9f43fffb4079477`**. Any of them prints verbatim with:

```
git show 0780b07e5e440dcc34ce23f0a9f43fffb4079477:docs/reviews/full-audit-2026-07-05.md
git show 0780b07e5e440dcc34ce23f0a9f43fffb4079477:docs/upgrades/python-3.14.md
```

§15 lists all thirteen paths. Nothing was rewritten before deletion, so what git holds is exactly
what was reviewed.

**Reference sweep.** Five live-document references were repointed —
`CONTRIBUTING.md` § Project layout (both directories dropped, `screenshots/` added, and the
`docs/` entry now names §14/§15), `CONTRIBUTING.md` § API conventions, `CHANGELOG.md`'s L13/APIR-8
citation, and both `.github/dependabot.yml` D3 comments — all now pointing at §15. Inside §14, 59
`docs/reviews/` and 7 `docs/upgrades/` path prefixes were stripped so the entries name the reports
as **documents** rather than as paths that no longer resolve; a note at the top of §14 states that
and sends the reader to §15. The dead link at the old `ARCHIVE.md:1004` —
`claude-md-compliance-review.md`, a filename that never existed — was corrected to
`claude-md-compliance.md` in the same pass. One reference was deliberately **left**: the
2026-07-25 entry's record that `CONTRIBUTING.md` § Project layout had omitted `docs/upgrades/` is
a statement about that document's state on that date, and editing it would falsify the record; it
is marked "(as it then was)".

**2. §14 is contiguous again, and indexed.** Twelve dated entries — every one from 2026-07-09
onward, i.e. all recent work — sat underneath `## Build performance` rather than under §14, so
scrolling §14 "to the end" stopped short of them. `## Build performance` was moved to the end of
the file instead of re-parenting the twelve: it is self-contained and cross-referenced by **heading
name** (`§ Build performance`) from CLAUDE.md and four workflow files, never by position, so the
move breaks nothing — verified by grep before making it. All **104** dated entries are now under
§14, confirmed programmatically.

§14 now opens with a **newest-first index**, one anchored line per entry, plus a stated ordering
convention: new entries go at the top. **The entries themselves were deliberately not reordered.**
Sixteen of them refer to each other *relatively* — "the entry below", "superseded by the entry
above", "the two 2026-07-03 entries above" — and a sort would silently invert every one of those,
corrupting the record to fix a navigation problem. The three ordering regimes are documented
instead, and because the index is sorted by date **regardless of physical position**, lookup no
longer depends on the scroll order at all. This is the "document the regimes" option the scoping
offered; it is strictly better here than a sort, not merely cheaper.

**3. The `[Unreleased]` CHANGELOG carried a false, user-facing CVE claim.** It stated that
CVE-2025-15366 and CVE-2025-15367 "remain unfixable until 3.15" because upstream declined the
backport to 3.10–3.14, and pointed at issue **#52** for all four waived CVEs. Both halves are
false as of the two 2026-07-26 entries below, and this text **ships verbatim as release notes** —
tagging would have made it permanent published history. Corrected against `ci/grype.yaml` as it
stands: three of the four (CVE-2026-15308, CVE-2026-12003 and **CVE-2025-15366**) have their fixes
merged on the CPython `3.14` maintenance branch, unreleased, closing on **3.14.7**, tracked in
**#98**; only CVE-2025-15367 (poplib) is genuinely 3.15-only and still tracked in **#52**. What
was true is kept and restated: released 3.14.6 carries neither guard, so the runtime bump cleared
nothing at the version the image pins.

The same false claim sat in **§0 locked decision #7** — the "what is locked" summary a reader
treats as current, unlike a dated entry — and was amended there too. The dated 2026-07-25 and
2026-07-13 entries that carry the original claim were **not** edited: they are superseded in place
by the entries below, and the trail is the point.

**4. `ROADMAP.md`.** Struck two completed items — "Pin GitHub Actions to commit SHAs" (#57;
verified: `ci.yml` 8 SHA-pinned `uses:`, `dev-nightly.yml` 3, `publish.yml` 3, `rescan.yml` 2) and
"Frontend test runner" (#78; verified: `vitest 3.2.7`, `"test": "vitest run"`, 20 test files). The
"Row-bound secret AAD" item was **false as stated** — it claimed secrets are bound to the column
and not the row, but `secret_store.py`'s `row_aad()` has composed `<table>.<column>:<row-id>` since
L1/SEC-7 (#64) and every write binds to the row. What actually remains is the *cutover*: the
decrypt path still falls back to the bare column tag for pre-#64 ciphertext, and that fallback can
only be dropped once every row has been re-encrypted. It is therefore folded into the existing
"Admin bulk secret re-encryption" item rather than struck, since that is the action that would do
it. Five settings-level items that existed only in §14 prose — and were therefore invisible for
weeks — were collected into the public-repo governance checklist: Actions workflow permissions →
read-only (2026-07-06), confirm the GHCR package is **public** (2026-07-06, a check whose premise
inverted when the repo went public on 2026-07-09 and which is still unverified in either
direction), delete the unused `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` secrets (2026-07-09), set the
GitHub profile display name to `tyler-rich` (R7/D4), and confirm Dependabot security alerts are
enabled.

**5. `CLAUDE.md` § Git & PR conventions gains two rules**, both learned the expensive way during
the stacked-PR work and unrecorded until now: retargeting a stacked child PR after its parent was
squash-merged requires `git rebase --onto` (flipping the base in the UI recomputes the merge base
against an absent history and balloons the diff to re-include everything the parent landed), and
`on: pull_request` without explicit `types:` does not fire on `edited`, so a base change never
re-runs CI and the green check shown after a retarget is from the *old* base.

**6. `CONTRIBUTING.md` § Releasing gains a "Before you tag" checklist.** The section documented the
promotion-title convention and the tag mechanics but had no pre-tag gate, while this cleanup alone
surfaced four things that must happen before a tag: review `[Unreleased]` for stale or false claims
(item 3 above is exactly that failure), verify `THIRD_PARTY_LICENSES/` against the scanner versions
actually pulled at build time, triage open Dependabot PRs, and regenerate `requirements.lock` if
backend deps moved. Plus the two after-tag steps: back-merge `main` into `dev`, and re-run
`rescan.yml`.

**Corrections to the audit that produced this work.** Both were caught by checking rather than
transcribing, which is the reason the scoping asked for verification:
- It reported **"fourteen dated deviation entries"** misfiled under `## Build performance`. There
  are **twelve**; the other two of the fourteen `###` headings under that section are Build
  performance's own sub-headings ("Why the build was slow…", "Invariants — do NOT undo these").
  Its own enumeration listed twelve line numbers, so the prose count was the error, not the list.
- It reported **33 prunable remote branches out of 39**. The repository carries **42** branches
  today: 36 merged leftovers, `dev`, `main`, and 4 Dependabot heads. Its own enumeration listed 35
  (29 named + 6 review branches), so "33" was an undercount even when written; its own branch has
  merged since.

**Verified, not assumed.** `THIRD_PARTY_LICENSES/` — which the audit explicitly flagged as
unchecked — was verified this session: the version table (Trivy 0.72.0, Grype 0.115.0, Syft
1.46.0) matches the `TRIVY_VERSION`/`GRYPE_VERSION`/`SYFT_VERSION` args in `docker/Dockerfile`, and
all four bundled files are **byte-identical** to what upstream ships at those tags
(`trivy/LICENSE`, `trivy/NOTICE`, `grype/LICENSE`, `syft/LICENSE`); the claim that Grype and Syft
ship no `NOTICE` was confirmed by 404 at both tags. Issues **#63** and **#83** were re-verified
resolved in code (`docker/docker-compose.yml`'s wollomatic allowlist and seven regression tests;
`AuthContext.tsx`'s `applyAuthenticated()` wired into all three authentication paths) and are safe
for the maintainer to close by hand — closing keywords never fired because PRs target `dev`, not
the default branch. No workflow, test, or source file references either deleted directory
(grepped before deleting), and the four `§ Build performance` workflow cross-references are by
heading name and survive the move.
**Why:** `docs/` had accumulated twelve closed-finding documents beside two live ones, §14's most
recent two weeks of entries were filed under an unrelated heading where nobody scrolling would
find them, and the CHANGELOG was one `git tag` away from publishing a false CVE claim as release
notes. The finding-ID index is the piece that makes deletion safe rather than lossy: it is what
§14's citations actually need, and it is maintained in the same file as the citations instead of
in a folder that drifts out from under them.
**Plan section affected:** §0 (#7 — CVE wording corrected), §14 (structure, index, ordering
convention), new §15 (finding-ID index), § Build performance (moved to end of file, content
unchanged). `CLAUDE.md` § Git & PR conventions; `CONTRIBUTING.md` § Project layout, § API
conventions, § Releasing; `CHANGELOG.md` `[Unreleased]`; `docs/ROADMAP.md`;
`.github/dependabot.yml` comments. Docs and comments only — no code, schema, API-contract,
security-model, job-model, auth, or CI-behavior change.

### 2026-07-25 — Docs/Process — README + CONTRIBUTING audited against the post-remediation codebase
**What changed:** A docs-only pass reconciling the two user/contributor-facing documents with the
state §14's remediation-cycle entries left the code in. No application code, CI, or configuration
was touched. Verified against the tree rather than against the prior entries — each claim below was
re-checked at `file:line` before being written or left alone.

`README.md`:
- **Field-encryption AAD was documented as "column-bound"** — stale since L1/SEC-7 (#64). The
  security model now describes the **row-bound** AAD (`<table>.<column>:<row-id>`), applied on
  write with the column-only tag as a read fallback so legacy ciphertext still decrypts and
  upgrades on next write (`backend/app/core/secret_store.py:54`).
- **H1/SEC-1 was absent from the security model.** Added a bullet naming
  `SCRYE_FILESYSTEM_SCAN_ROOTS` as the **sole** gate on local-path scanning, and the
  remote-clone-URL requirement on `repository` targets (422 at request validation, inherited by
  scheduled scans) that closes the `trivy repo <local path>` route around it. § Features and
  § Usage previously said "HTTPS clone URL"; both now say remote clone URL and name the four
  accepted schemes, matching `is_remote_repo_url()`.
- **New § Supply chain.** The supply-chain hardening from H11/SC-1, H9/SC-2, H10/SC-3, M24/SC-4,
  M26/SC-8, SC-12, and SC-14 had no user-facing home — a consumer had no documented way to verify
  a pulled image. The section covers the `gh attestation verify` command for the SLSA provenance +
  SPDX SBOM attestations, cosign keyless verification of the scanner `checksums.txt` before
  `sha256sum -c`, the hash-pinned `requirements.lock` (`pip --require-hashes`) and pinned build
  backend, digest-pinned base/sidecar images, SHA-pinned Actions, Dependabot's five ecosystems
  including the composite-action directory, and the exclusion of `backend/tests/` and
  `backend/scripts/` from the runtime image. The § Security model CIS bullet now says
  "cosign-verified" rather than the vaguer "verified against their signed checksum files" and links
  here.
- **§ Configuration.** The "one variable is not a Scrye setting" note listed only `DOCKER_GID`;
  `SCRYE_ALLOW_WEAK_MASTER_KEY` is also an env var absent from `.env.example` (it is read directly
  by `core/crypto.py:47`, not by the `Settings` model), so the note now covers both and explains
  why neither is generated.
- **§ Optional sidecars.** The socket-proxy entry described the wollomatic allowlist correctly but
  buried the `DOCKER_GID` prerequisite in a shell comment, where an operator copying the service
  into their own Compose file would miss it. It is now its own bullet, with the digest pin and
  uid 65534 named alongside.

`CONTRIBUTING.md`:
- **The TypeScript strictness gates were undocumented.** `noUncheckedIndexedAccess` and type-aware
  ESLint (`recommendedTypeChecked` + `projectService`) have been enforced since the P3-8 close
  (2026-07-24) and fail the build, but a contributor had no way to know. § Coding standards now
  documents both, the preference for encoding an invariant in the type over a non-null assertion
  (the tree has zero `!` assertions), and the `void`-operator idiom for the promise rules.
- **`eslint-disable` stance, stated accurately.** The scoping for this pass described the codebase
  as using none. It uses **nine** — two `react-refresh/only-export-components` with `--`
  justifications and seven `react-hooks/exhaustive-deps` on mount-only effects. What the P3-8 entry
  actually claims is that *that pass added zero*, which is a different statement. The rule is
  therefore written as: targeted `eslint-disable-next-line` only, never file-level, never on the two
  gates, always with a stated reason — and the nine existing ones are named so the next reader
  doesn't have to re-derive whether they are drift.
- **§ Project layout was stale.** It listed `ci.yml` as the only workflow (there are four), omitted
  `.github/actions/build-image/`, `dependabot.yml`, `CHANGELOG.md`, `SECURITY.md`, `` (as it then was),
  `frontend/src/lib/`, `frontend/src/test/`, and `api/pagination.py`.
- **§ Releasing lacked the promotion-title convention that `CLAUDE.md` points at it for.**
  CLAUDE.md § Coding standards cites "`CONTRIBUTING.md` § Releasing" as the source for the plain
  `Promote dev to main: …` title exception, but § Releasing never stated it — a dangling
  cross-reference between the two documents. Now stated where CLAUDE.md says it lives.
- **§ Pull request process** gained the lock-regeneration and dated-§14-deviation checklist items,
  `tsc -b`, the no-AI-attribution-footer requirement on commits *and* the PR body, and an explicit
  statement that CI is the merge gate — aligning the contributor-facing checklist with CLAUDE.md
  § Definition of done.

**Deliberately left alone.** § Backend dependency lock was re-verified end to end (pinned
`uv==0.8.17` matching `ci.yml:71`, `uv pip compile pyproject.toml --group build --generate-hashes
--python-version 3.14`, `pip --require-hashes`, the `--no-deps --no-build-isolation` app install,
and the CI drift gate) and is **accurate and complete after SC-12** — no change. The frontend test
conventions (`.test.ts`→node, `.test.tsx`→jsdom, `renderWithProviders`) were likewise already
correct and complete. The README's Python **3.14** prerequisite was confirmed against
`docker/Dockerfile` (both stages pin the 3.14.6 digest) rather than assumed from the scoping note,
which expected 3.13.
**Why:** The compliance audit's finding was three sources of truth drifting apart, so the value of
this pass is in the cross-document reconciliation, not the individual corrections. Two contradictions
were found and closed by editing the doc that was wrong, not the contract: the dangling CLAUDE.md →
CONTRIBUTING § Releasing promotion-title reference, and the `.env.example`-vs-README account of which
env vars are `Settings` fields. `CLAUDE.md` was **not** amended in this pass by instruction.
**Plan section affected:** §10.1 (`README.md`), §10.2 (`CONTRIBUTING.md`). Docs only — no code, CI,
configuration, schema, security-model, or job-model change.

### 2026-07-25 — Docs/Process — Interpreter CVEs must be verified at the source before a bump is justified on security grounds
**What changed:** A new standing rule in `CLAUDE.md` § Coding standards § Dependency hygiene:
scanner output, advisory "fixed in" fields, and this repo's own issue summaries are **evidence, not
proof**, and none is sufficient on its own to claim that moving the runtime to version X clears
CVE Y. Before a runtime bump is argued as a security fix, the fix must be confirmed present in the
target interpreter by reading the relevant stdlib module in that exact version (unpacking the pinned
base image if needed). Bumps justified on **support-lifecycle, ecosystem, or dependency-currency**
grounds need no CVE argument at all and are unaffected. `ci/grype.yaml`'s Group B waiver was also
re-cast in the same pass from a deferral into a **standing acceptance**: CVE-2025-15366 /
CVE-2025-15367 are accepted risk on **any interpreter below 3.15**, with an **annual** re-confirmation
review (next 2027-07-25) replacing the old upgrade-tied date, and an explicit note not to scope a 3.15
move as a reaction to them.
**Why:** Both interpreter bumps to date were decided from Grype's `FIXED IN` column without anyone
reading CPython — one unsound method with two different failure modes:
- **3.12 → 3.13** (2026-07-03) reached the right outcome by luck. The entry justifying it recorded
  the triggering CVEs' fixes as landing in "3.13+/3.14+/3.15+" — the metadata itself said some were
  *not* fixed in 3.13 — yet the post-bump scan, with the interpreter exclusion removed, came back
  clean. Metadata wrong in the pessimistic direction is still wrong; the decision just wasn't
  punished for it.
- **3.13 → 3.14** (2026-07-25, the entry below) reached the wrong one. The scoping doc and issue #52's
  resolution-trigger line both asserted 3.14.6 carried the CVE-2025-15366/-15367 fixes; it does not,
  and the bump cleared nothing. Issue #52 even held the correct fact — "declined backport to
  3.10–3.14" — in a different paragraph from the claim it contradicted.
Worth recording precisely, because the tempting summary ("two bumps, neither resolved its CVEs") is
**not** what happened and would make the rule easy to dismiss on inspection: the first bump did clear
what triggered it. What the two share is the method, not the result — which is the actual thing worth
banning. Source verification is also cheap, as this session showed: unpacking the pinned base image
and reading two stdlib functions took minutes and settled a question two documents had gotten wrong.
**Plan section affected:** CLAUDE.md § Coding standards (Dependency hygiene); `ci/grype.yaml`
(Group B waiver rationale and review cadence); no code, schema, security-model, or job-model change.

### 2026-07-25 — Post-release — Backend runtime bumped Python 3.13 → 3.14 (locked decision revised)
**What changed:** The locked backend runtime was revised from **Python 3.13 to Python 3.14** — the
second interpreter bump, mirroring the 3.12 → 3.13 precedent below (2026-07-03). Executed from the
scoping/handoff doc `python-3.14.md`, which the 2026-07-13 entry created when the move
was deferred. Concretely: the Dockerfile base image is now `python:3.14-slim-bookworm` (digest-pinned
to `sha256:86f975ac…`, which is **3.14.6**) for both the venv-builder and runtime stages;
`backend/pyproject.toml` `requires-python` is `>=3.14`; the CI backend job runs on Python `3.14` and
the lock-drift gate compiles with `--python-version 3.14`; and `CONTRIBUTING.md`/`README.md` name 3.14
as the native-dev prerequisite. The locked decision is updated in `CLAUDE.md` § Locked decisions #2
and §0 (#7) / §2 above.

**The 3.14.6 floor is load-bearing, not cosmetic.** Python 3.14.0 through 3.14.4 shipped an
incremental garbage collector whose work-estimate calculation could go negative, so a long-running
server never drained its cyclic-garbage backlog and resident memory grew up to ~5×. It was reverted
in 3.14.5, restoring the same generational GC 3.13 used; 3.14.6 is the first fully-safe release after
the revert. Scrye is exactly the long-lived-server workload that regression targets. The Dockerfile
carries this as a comment at both `FROM` lines so a future digest bump re-checks it. The other two
3.14 runtime changes are non-events here: free-threading (PEP 703) needs the separate `python3.14t`
build, and the JIT (PEP 744) is disabled by default on Linux — the standard slim image has neither.

**Dependency changes.** Three were flagged as hard blockers by the scoping doc and are done:
`pydantic` 2.10.4 → **2.13.4** (2.10.4 pins pydantic-core 2.27.2, which publishes no cp314 wheel and
does not build from source there — PyO3 caps at 3.13); `uvicorn[standard]` 0.34.0 → **0.51.0**
(official 3.14 support landed in 0.38.0); and an explicit **`greenlet==3.5.4`** pin, since SQLAlchemy's
async support needs it and no longer pulls it implicitly. Two more were found during the pass and are
**deviations from the scoping doc's dependency table**:

- **`sqlalchemy` 2.0.36 → 2.0.51.** 2.0.36 has no cp314 wheel, but unlike pydantic-core it does not
  fail — it also publishes a pure-Python `py3-none-any` wheel, so pip silently installs *that* on 3.14
  and the compiled accelerators disappear with no error anywhere. cp314 wheels first appear in
  2.0.45. Same 2.0.x series, so no API surface moved.
- **`ruff` 0.8.6 → 0.16.0.** 0.8.6 rejects `target-version = "py314"` outright (py313 is its ceiling),
  so the doc's "bump target-version to py314" is impossible without it. 0.16.0 reports **zero** new
  violations on the tree — the `known-first-party` isort pin added for D5b (2026-07-20) is what makes
  a ruff jump this large a no-op, exactly as intended.

`fastapi` 0.139.0, `starlette` 1.3.1, `cryptography` 49.0.0, `argon2-cffi` 25.1.0, `httpx` 0.28.1,
`authlib` 1.7.2, `pyotp` 2.10.0, `alembic` 1.14.0, `pydantic-settings` 2.7.1 and `black` 26.3.1 were
**verified**, not assumed, and are unchanged: every C/Rust-backed package in the resolved closure
(`cffi`, `argon2-cffi-bindings`, `cryptography`, `uvloop`, `httptools`, `watchfiles`, `websockets`,
`markupsafe`, `pyyaml`) already ships cp314 wheels at its pinned version. `requirements.lock` was
regenerated with the pinned `uv pip compile --group build --generate-hashes --python-version 3.14`.

**The pydantic bump got its own compatibility pass** (CLAUDE.md § When to ask vs. decide treats the
I/O-validation layer as a data-model surface). Scrye's usage is plain Pydantic v2 — `BaseModel`,
`ConfigDict(from_attributes=True)`, `Field`, `SecretStr`, `field_validator`, `model_validator`,
`PlainSerializer` via `Annotated`, plus pydantic-settings' `BaseSettings`/`SettingsConfigDict`/
`NoDecode` — with no `pydantic.v1` namespace use anywhere. The 2.11–2.13 change most likely to bite
was 2.12's "do not implicitly convert after model validators to class methods": every
`@model_validator(mode="after")` in the tree is already instance-style (`def _check(self)`), so it
does not apply. The empirical check was a full OpenAPI-schema diff, old stack vs new: **the only
difference across the entire 229 KB schema is nine `"additionalProperties": true` keys** that 2.12+
now emits explicitly on bare `dict` fields. That is semantically identical to what `{"type":
"object"}` already implied, and the frontend's API client is hand-written rather than generated from
the schema (FE-2), so **no code change was required** — the bump is code-neutral.

**`black` stays at `target-version = ["py313"]` — a deliberate deviation** from the scoping doc's
"bump target-version to py314", which applies to ruff only. black's target-version is the oldest
interpreter its *output* must parse on, and at py314 it applies PEP 758, rewriting `except (A, B):`
to `except A, B:` at four sites (`passwords.py`, `crypto.py`, `logging.py`, `trivy.py`). That is
valid 3.14 syntax, but it reads like Python 2's `except (A, B), e:` and buys nothing, so the
parenthesized form is kept; the reasoning is inline in `pyproject.toml` so it doesn't look like an
oversight. ruff's target-version gates only which lint rules apply and emits no syntax of its own, so
it does track the real runtime floor at `py314`.

**CVE outcome (issue #52) — the scoping doc's central premise turned out to be wrong, and this
upgrade clears none of the four CVEs.** Both `python-3.14.md` and issue #52's
resolution-trigger line asserted that **Python 3.14.6 already carries the CVE-2025-15366 /
CVE-2025-15367 fixes** (imaplib/poplib command injection, both MEDIUM), making "move off the 3.13
line" the practical way to clear them — that was the stated reason this upgrade project existed. It
is not true. The waivers were removed on that basis, and the CI dogfood scan on the upgrade PR
immediately reported both back against interpreter **3.14.6** with `FIXED IN 3.15.0a6`. Reading
3.14.6's own stdlib confirms the scanner rather than the doc: `imaplib._command()` and
`poplib._putcmd()` still concatenate arguments straight onto the wire with no CRLF/control-character
validation. Issue #52 in fact contradicted itself — its Group B paragraph correctly records that
upstream declined the backport to "3.10–3.14", which *includes* 3.14, while its resolution-trigger
line said the 3.14 upgrade would close them. The Group B paragraph was right. **Both waivers were
restored**, retargeted at 3.14 with the corrected rationale and no review trigger earlier than a 3.15
upgrade. CVE-2026-15308 (HIGH, `html.parser` quadratic-complexity CPU DoS) and CVE-2026-12003
(MEDIUM, `getpath.py` in-tree search-path fallback) are unchanged by the move, exactly as the doc did
correctly predict: merged to both the 3.13 and 3.14 maintenance branches, in no released point
version, closing on the next 3.14.x just as they would have on the next 3.13.x. Their review date
moves to 2026-10-25 — a real trigger, unlike Group B's, which is now an annual re-confirmation of a
standing acceptance (see the process entry above). Net: the waiver list is **unchanged at four
entries**, and the security
justification for this bump did not materialize — what remains is staying current on a supported
interpreter line ahead of 3.13's EOL, plus the dependency currency the move forced. Whether that
alone justifies the change is a call for the maintainer, not something this entry should paper over.

**Validation.** The full backend suite — **579 passed, 3 skipped** — runs green on a genuine CPython
**3.14.6** unpacked from the same `python:3.14-slim-bookworm` digest the image pins, against the
regenerated lock. Also verified there: a clean `import app.main`, and a full Alembic
upgrade → downgrade to base → upgrade cycle back to `0008_oidc_flow_browser_binding`. No new
warnings: the only ones are the pre-existing Starlette `HTTP_422_UNPROCESSABLE_ENTITY` /
`HTTP_413_REQUEST_ENTITY_TOO_LARGE` deprecations and the Starlette-TestClient httpx notice, none of
which involve a package this change touches. `uvicorn 0.51.0` still exposes the `--proxy-headers` and
`--forwarded-allow-ips` flags `docker/entrypoint.sh` depends on. The image build,
`docker compose up` + `/healthz`, and the Trivy + Grype dogfood self-scan were run **by CI on the
PR** — the authoring environment had no Docker daemon, which is also why the Grype waiver narrowing
above is confirmed by the CI dogfood report rather than a local scan.
**Plan section affected:** §0 (#7, new locked runtime), §2 (tech stack), §9.1 (base image),
§12 (Phase 6 self-scan), CLAUDE.md § Locked decisions #2; supersedes the 2026-07-13
"CPython interpreter CVEs on 3.13 accepted as tracked risk; 3.14 deferred" entry below and closes
out `python-3.14.md`.

### 2026-07-24 — Post-release — P3-8 closed: `noUncheckedIndexedAccess` + type-aware ESLint
**What changed:** The two TS-strictness flags P3-8 deferred to a dedicated pass are now on, in two
independently reviewable/revertible commits. **Re-measured against current `dev` first** (the #81
counts predate the M19/M20/M21 back-fills in #84 and the issue-83 work in #87): the actual scope is
**smaller** than the ~53 problems scoped then — 14 TS errors across 5 files, and **30** ESLint
problems across 15 files rather than 39, because #81's `parseResponse<T>` boundary already retired
the `no-unsafe-*` family. All 20 Vitest files lint clean under the typed rules, so the expected
test-file promise noise never materialized.

**1. `noUncheckedIndexedAccess`** (`frontend/tsconfig.app.json`) — 14 errors, fixed with **no**
non-null assertions:
- `NewScanPage.tsx`, `ScheduledScansPanel.tsx` — the two real `Scanner | undefined` mismatches the
  scoping flagged. `SCANNERS_FOR` retyped `Record<TargetType, Scanner[]>` →
  `Record<TargetType, readonly [Scanner, ...Scanner[]]>`. The "keep the scanner valid for the chosen
  target type" effect resets to `allowed[0]`, which was `Scanner | undefined` against a setter
  taking `Scanner`; the non-empty tuple encodes the actual invariant (every target type has at least
  one permitted scanner) so the read is `Scanner` by construction rather than by assertion.
- `RegistriesPanel.tsx`, `NotificationsPanel.tsx` — the per-row `tests[id]` lookup was performed
  three times per row (existence check, `.ok`, `.detail`). Hoisted to one `const test` inside the
  row callback, which satisfies the flag and drops two redundant lookups per row.
- `ScansPage.tsx` — `canCompare` indexed `compare[0]`/`compare[1]` behind a `length === 2` check TS
  does not narrow on; destructured to `compareA`/`compareB` with direct `undefined` checks.
  `runCompare` gained an `if (!a || !b) return` guard on the sorted pair — unreachable in practice
  (the button is gated on `canCompare`), so no behavior change.

**2. Type-aware ESLint** (`frontend/eslint.config.js`) — `tseslint.configs.recommended` →
`recommendedTypeChecked` with `projectService: true` + `tsconfigRootDir`. 30 problems, all fixed at
the call site with **zero `eslint-disable` comments added**:
- **`no-misused-promises` (25)** — an `async` handler in an `onClick`/`onChange` slot expecting a
  `void` return. Each of the 21 handler bodies was read to decide bug-vs-style: **every one wraps
  its entire body in `try/catch`** (with `finally` where it clears in-flight state), so none can
  produce an unhandled rejection — these are genuinely shape mismatches, not latent bugs. Marked
  with the `void` operator, the idiom already used for `void load()` here. The other 4 are
  `onClick={() => navigate(...)}`: react-router 7's `navigate()` returns `void | Promise<void>`.
  Three sites passed the async function directly (`onClick={disable}`, `{confirm}`, `{submitMfa}`)
  and are now arrow-wrapped; all three take no parameters, so dropping the click event is inert.
- **`no-floating-promises` (4)** — all four are bare `navigate(...)` statements (`NewScanPage` ×2,
  `ScanDetailPage`, `ScansPage`), the same react-router 7 return type. Prefixed with `void`.
- **`no-unnecessary-type-assertion` (1)** — `ApiTokensPanel.tsx:60` asserted
  `(user?.role ?? 'viewer') as Role` on an expression already typed `Role`. Dropped.

**No runtime behavior changed.** The `void` operator only discards a value that was already being
discarded; the tuple retype and the hoisted lookup are type/structure-only; every handler's error
path is untouched. Full suite (54 tests / 18 files), `tsc -b`, `eslint .`, Prettier, and
`npm run build` all green.
**Why:** Closes the last open item in `STATUS.md` — P3-8's strictness-flag half, split
out of #81 precisely so it could be reviewed on its own. Both flags are permanent gates from here:
new indexed reads and new unawaited promises now fail CI rather than accumulating.
**Plan section affected:** none — frontend build/lint configuration and type-level handling only; no
schema, API, security-model, or job-model change. Extends the Coding standards § TypeScript rule
(ESLint + Prettier clean) with the two stricter gates.

### 2026-07-24 — Post-release — #83: a completed authentication is never undone by an in-flight refresh
**What changed:** `frontend/src/auth/AuthContext.tsx` — the mirror of the P3-4 race fixed in #82,
running the other way. `login()`, `verifyMfa()`, and `setup()` wrote the authenticated user into
state without sequencing against a `refresh()` that was already in flight. That status request was
answered by the backend *before* the credential existed, so it carries `user: null`; resolving after
the sign-in, it overwrote the fresh session and dropped the shell back to the login screen (the next
`refresh()` or a re-login recovered it). The provider now enforces the companion invariant **a
successfully completed authentication — login, MFA verification, or first-admin setup — is never
undone by a `refresh()` that was already in flight when it completed**: the three success paths go
through one `applyAuthenticated()` helper that burns a token from the existing
`refreshGuard` (`createLatestGuard()`, `lib/latest.ts`) before writing the user, so any refresh
already running is superseded and returns without writing. No new mechanism — this is the same
latest-wins guard `refresh()` already uses against itself, just begun by an authentication instead
of a fetch. Deliberately **not** changed: `sessionGeneration` and its invalidation semantics, so the
P3-4 invariant (a logged-out session is never restored by a late refresh) is untouched; a superseded
refresh writing nothing at all cannot strand the app on the loading spinner here, because the
authentication path itself sets `loading: false`. Four new jsdom cases in `auth/AuthContext.test.tsx`
— one per authentication path (each holds a refresh open, authenticates, then resolves the stale
anonymous status and asserts the session stays signed in), plus a non-regression case proving a
refresh *started after* the sign-in still applies. The three race cases were confirmed to fail
against the pre-fix provider (`expected 'signed-out' to be 'signed-in:operator'`) by stashing the
fix and re-running; both P3-4 race tests pass unchanged in the same run.
**Why:** Issue #83. Pre-existing (predates #82, which scoped itself to the invalidation direction)
and fail-safe in direction — the failure is being logged *out*, never *in*, so no session is
presented that the backend hasn't authorized and there is no security edge; it is a UX/correctness
wart that #82's machinery made closeable in a few lines. Reuses the codebase's guard idiom rather
than introducing a third pattern, per the issue's scope note.
**Plan section affected:** none — frontend session-state sequencing only; no schema, API,
security-model, or job-model change. Companion to the P3-4 entry below
(`frontend-review.md` § Priority 3).

### 2026-07-24 — Post-release — Test-debt back-fill for M19, M20, and M21 (tests only)
**What changed:** Nothing in the application — this entry records **new tests only**, back-filling
the three fixes `STATUS.md` § "Test debt on already-shipped fixes" listed as
"resolved in code, proof absent". The fixes landed in #62, before the jsdom/RTL harness existed
(#78), so M19 had no coverage at all and M20/M21 were covered only at the pure-helper level
(`lib/polling.test.ts`, `lib/latest.test.ts`) with the page-effect wiring that consumes those
helpers untested. Six new jsdom files, one commit per finding:
- **M19 / P1-2** (settings-form clobber guard) — `RetentionPanel.test.tsx`, `GeneralPanel.test.tsx`,
  `BackupsPanel.test.tsx`, `NewScanPage.prefill.test.tsx`. The three panels assert the form is
  neither editable nor savable before the initial GET resolves (a Save attempt writes nothing) and
  that the fetched values, not the built-in defaults, are what a later Save sends.
- **M20 / P1-3** (poller backoff) — `ScanDetailPage.poller.test.tsx` drives the poll effect under
  fake timers: consecutive errors stretch the retry delay, the poller stops at `MAX_POLL_FAILURES`
  and renders the "Auto-refresh paused" alert, and a 404 halts on the first failure.
- **M21 / P1-4** (latest-wins) — `ScansPage.latestwins.test.tsx` and
  `ScanDetailPage.latestwins.test.tsx` hold an earlier request open across a filter change so the
  newer one resolves first, then assert the superseded response is discarded.

**Scope note — where the "dirty form is not clobbered" half of M19 is asserted.** In
`RetentionPanel`/`GeneralPanel` the inputs are themselves gated on `loaded`, so there is no
user-reachable path to dirty the form before the GET resolves; the disabled gate subsumes the
`isDirty()` check and a page-level "dirty" test there could only assert something unreachable.
That half is therefore asserted where it *is* reachable: `NewScanPage` (fields deliberately
ungated, so a late `getScannerSettings` prefill can land on an edited form) and `BackupsPanel`
(the `load()` re-fetch triggered by an unrelated list mutation, which must not rehydrate an
in-progress schedule edit). This is called out in a comment in `RetentionPanel.test.tsx` rather
than papered over with a hollow assertion.

**Why:** Every discriminating assertion was verified to **fail** against the pre-fix behavior by
temporarily reverting the guard locally and re-running — the same standard applied to the P3-4
race tests — so none of these can pass vacuously. Confirmed failure signatures: M19 — the Save
button is enabled and the defaults PUT before the GET lands (and, with `load()` rehydrating, the
edited interval reverts); M20 — 25 requests where the fixed version makes 6, and no paused alert;
M21 — the stale rows replace the current filter's rows. Two companion assertions (a pristine form
seeds from fetched values; a latest response still renders) pass both before and after by design —
they guard the fix's *non*-regression, and the pre-fix-failing assertions sit alongside them in
the same files.

**Plan section affected:** §12 Phase 6 / CLAUDE.md § Coding standards → Testing; closes the
"Test debt on already-shipped fixes" block in `STATUS.md` §1.

### 2026-07-24 — Post-release — P3-4: sequence auth refresh against session invalidation
**What changed:** `frontend/src/auth/AuthContext.tsx` — `refresh()` wrote the `fetchAuthStatus`
result into auth state unconditionally, with no sequencing against the `scrye:auth-invalidated`
event (dispatched by `api/client.ts` on any 401) or against `logout()`. A status request answered
by the backend *before* the credential was revoked but resolving *after* the invalidation would
write its stale `user` back, flashing the authenticated shell over the login screen until the next
401. The provider now enforces the session-lifecycle invariant **a logged-out session is never
restored by a late-arriving refresh**: a `sessionGeneration` ref is bumped by every invalidation
(both the 401 event handler and `logout()`, the latter *before* awaiting the request so a refresh
already in flight is covered); `refresh()` captures the generation before fetching and, if it
changed by the time the response lands, applies the session-independent facts (`needs_setup`,
`oidc`, `loading: false`) but forces `user: null`. Keeping the non-identity fields is what stops an
invalidation during the initial load from stranding the app on the loading spinner. `refresh()`
additionally takes a token from the existing `createLatestGuard()` helper (`lib/latest.ts`, the same
latest-wins guard the history/findings fetches use) so two overlapping refreshes can't resolve out
of order and clobber each other — an older refresh returns without writing at all, rather than
writing a logged-out state a newer in-flight refresh is about to contradict. New jsdom test
`auth/AuthContext.test.tsx` covers both races (invalidation event mid-refresh; `logout()`
mid-refresh) plus the happy path; both race tests were confirmed to fail against the pre-fix
provider. `src/test/render.tsx` re-exports `act` so tests keep importing the whole Testing Library
surface from one place.
**Why:** P3-4 (frontend review, LOW with a correctness/security edge) — the last open finding in
the Priority-3 batch, tracked in `STATUS.md` § 1. Low likelihood and self-healing, but
it is a session-lifecycle defect: the UI can present an authenticated shell for a session the
backend has already ended. A generation counter was chosen over aborting the request because the
invalidation must also invalidate a response that has *already* been received but not yet applied,
which an `AbortController` does not cover; it reuses the codebase's existing guard idiom rather
than introducing a new one.
**Plan section affected:** none — frontend session-state sequencing only; no schema, API,
security-model, or job-model change. `frontend-review.md` P3-4.

### 2026-07-24 — Post-release — Frontend Priority-3 polish batch (P3-1, P3-2, P3-5, P3-6, P3-7, P3-8)
**What changed:** Worked the frontend-review "Priority 3" backlog (`frontend-review.md`
§Priority 3; tracked in `STATUS.md`), one commit per finding:
- **P3-1 (`ScansPage.tsx`)** — history filters/date-range/sort/page were `useState`-only, so
  Back/bookmark/share reset the view. The active view is now read from the URL on mount and mirrored
  back into `useSearchParams` (`replace`, defaults omitted), making History deep-linkable. jsdom test.
- **P3-2 (`ScansPage.tsx`)** — the compare selection held full row snapshots that outlived a
  filter/page change or a delete, showing a phantom "1/2 selected" and diffing a since-deleted scan
  (404). Added an effect that reconciles the selection against the current rows whenever they change,
  dropping any selected id no longer present. jsdom tests (filter-out and deleted-scan).
- **P3-5 (`ScanDetailPage.tsx`)** — the ≤500-row findings table re-rendered on every tag keystroke
  and 2.5 s poll because it was co-located with `tagDraft`. Extracted a `memo`ized `FindingsTable`
  child keyed only on findings state. jsdom render-count test (SeverityBadge-spy).
- **P3-6 (new `components/StatusLoader.tsx`; loader sites; `Dashboard.tsx`)** — bare `Loader`s
  announced nothing to screen readers. Added a `StatusLoader` wrapping the spinner in a
  `role="status"` `aria-live="polite"` region with visually hidden text, used at the standalone
  loader sites (App shell, history, scan detail, diff, docker environments); gave the dashboard chart
  bars `role="img"` so their existing `aria-label` is honored. jsdom test.
- **P3-7 (`Dashboard.tsx`)** — severity colors re-stated as `"red"`/`"orange"` literals now reuse
  `SEVERITY_COLOR`; the scans-over-time chart switched from the pinned dark-mode `teal-6` to
  `var(--mantine-primary-color-filled)` so it tracks `primaryShade` per scheme. Pure token swap.
- **P3-8 (`api/client.ts`)** — the two blind `(await response.json()) as T` casts (the FE-2
  hand-written-client boundary) were consolidated into one documented `parseResponse<T>` helper
  (shared error/401/204 handling too). jsdom test for the client. **The two broader strictness
  flags in this finding were deferred by decision** (see Why).
**Why:** These are the LOW/UX/a11y/maintainability items the original `/code-review` frontend report
raised but `00-summary.md` never scheduled. Tests follow the post-v1 Vitest harness (`.test.tsx` +
jsdom via `renderWithProviders` for anything rendering, `.test.ts` + node for pure logic). On **P3-8**,
only the cited `as T` casts were fixed in this batch; enabling `noUncheckedIndexedAccess` (measured:
**14 new TS errors across 6 files**, some genuine `Scanner | undefined` mismatches, not just
non-null-assertion fixes) and switching ESLint to `recommendedTypeChecked`/type-aware rules
(measured: **39 problems** — 25 `no-misused-promises`, 4 `no-floating-promises`, 1
`no-unnecessary-type-assertion`, plus others) is a ~53-problem cleanup across ~10 files, so it is
tracked as its own dedicated pass rather than folded into this polish batch (the review itself framed
these as residual gaps, not violations). P3-3 was resolved earlier in #77; P3-4 remains open.
**Plan section affected:** none — frontend UX/a11y/maintainability polish only; no schema,
security-model, or job-model change. `frontend-review.md` §Priority 3;
`STATUS.md`.

### 2026-07-20 — Post-release — SC-12: pin and hash-lock the setuptools build backend
**What changed:** `backend/pyproject.toml`'s `[build-system].requires` was `setuptools>=75` — unpinned
and, as a PEP 517 build dependency, absent from the otherwise fully hash-pinned `requirements.lock`
(the one gap the lockfile left floating). Pinned it to exact `setuptools==83.0.0` and added a PEP 735
`[dependency-groups] build = ["setuptools==83.0.0"]` so the build backend flows through the same
`uv pip compile --generate-hashes` process as the runtime deps. The lock is now regenerated with
`--group build` (updated in `CONTRIBUTING.md` § Backend dependency lock and the CI drift gate in
`.github/workflows/ci.yml`), so `setuptools==83.0.0` now appears hash-pinned in `requirements.lock`.
The image's app-package build changed from `pip install --no-deps .` to
`pip install --no-deps --no-build-isolation .` (`docker/Dockerfile`), so the PEP 517 build reuses the
hash-verified setuptools already installed from the lock instead of pip fetching an unpinned, unhashed
setuptools into an isolated build environment. Regression guards added/updated in
`tests/test_dockerfile_supply_chain.py` (asserts the `--no-build-isolation` install form and that the
lock carries a hash-pinned `setuptools==`).
**Why:** SC-12 (supply-chain review, LOW; omitted from `00-summary.md` — see `STATUS.md`).
Closes the last floating/unhashed build-time dependency, so a build of a given commit resolves setuptools
identically and verifiably. A consequence is that setuptools (small, now hash-pinned) is present in the
final `/opt/venv` — an accepted trade for a fully hash-verified build with no isolated-build PyPI fetch;
`--group build` was chosen over a project-wide dependency because the fixed `uv pip compile pyproject.toml`
CI command emits only declared groups, keeping the lock reproducible and drift-gated. Verified end-to-end:
`pip install --require-hashes -r requirements.lock` installs setuptools==83.0.0 hash-verified, then
`pip install --no-deps --no-build-isolation .` builds the app against it (no standalone `wheel` needed);
the CI compile command is idempotent (no lock drift).
**Plan section affected:** none — build reproducibility / supply-chain hardening only. Locked decision §6
(no floating deps / hash-pinned build), Coding standards § Dependency hygiene (hash-pinned lockfile).
`supply-chain-review.md` SC-12.

### 2026-07-20 — Post-release — D5b: pin ruff isort first-party classification so import ordering is version-stable
**What changed:** `backend/tests/test_migrations.py`'s import block passed ruff's `I001` (import sorting)
check only because ruff is pinned at `0.8.6`; a newer ruff (e.g. `0.15.x`) reclassifies `alembic.config`
from first-party to third-party and would re-sort the block, failing CI on a future ruff bump. Root cause:
the repo ships a local `alembic/` migrations package whose name collides with the third-party `alembic`
distribution, and ruff's first-party auto-detection resolves that collision differently across versions.
Because the two ruff versions disagree on the **section** `alembic.config` belongs to (not merely the
ordering within a section), no pure reordering of the file satisfies both — so the deterministic fix is a
config pin: `[tool.ruff.lint.isort] known-first-party = ["alembic", "app"]` in `backend/pyproject.toml`.
That makes ruff classify the two local packages first-party on every version, so the whole tree's existing
(and already-correct) import ordering — `test_migrations.py` included — sorts identically under `0.8.6`
and current ruff, with **no** import reordering needed anywhere in the backend.
**Why:** D5b (claude-md-compliance review, TRIVIAL/latent; omitted from `00-summary.md`). Pinning the
classification the codebase already assumes is the minimal, faithful fix — the alternative
(`known-third-party = ["alembic"]`) is more semantically literal but reshuffles import blocks across ~8
files including the migration scripts, which is neither minimal nor in scope. The ruff pin itself is
intentionally **not** bumped in this change — that remains separate, deliberate work per the existing
§14 / `#59` note (bumping ruff needs its own review of new lint findings). Confirmed clean under both
ruff `0.8.6` (pinned/CI) and `0.15.22` across the whole backend.
**Plan section affected:** none — lint determinism only; no schema, security-model, or job-model change.
`claude-md-compliance.md` D5.

### 2026-07-20 — Post-release — SC-14: keep the backend test suite and dev scripts out of the runtime image
**What changed:** The final image stage copies the backend tree wholesale
(`COPY --chown=1000:1000 backend/ /app/backend/`), which shipped `backend/tests/` (the full pytest
suite) and `backend/scripts/` (the env-example generator) into the published image — needless bloat and
attack surface on a security tool's own image. Added `backend/tests/` and `backend/scripts/` to the root
`.dockerignore` so those dev-only trees are excluded from the build context; the final `COPY backend/`
now brings in only `alembic/`, `alembic.ini`, `app/`, `pyproject.toml`, and `requirements.lock`, which
is everything the runtime (Alembic migrations + `uvicorn app.main:app`) actually needs.
**Why:** SC-14 (supply-chain review, LOW/INFO). Verified no runtime code imports `tests`/`scripts`
(`app` and the Alembic `env.py` import only from `app`), so the exclusion is import-safe. The fix lives
in the **root** `.dockerignore` rather than a `backend/.dockerignore` because Docker only honors the
context-root ignore file for a normal build (a per-subdirectory `.dockerignore` is a silent no-op), and
in `.dockerignore` rather than a rewritten multi-line COPY to avoid restructuring the final stage's layer
ordering (CLAUDE.md § Build performance). This does not affect CI, which runs pytest on the host checkout,
not inside the image. Two guards were added: a static one in `test_dockerfile_supply_chain.py` (asserts
the `.dockerignore` carries both patterns), and — because the dogfood scan proves the image is *clean*
but not that these dirs are *absent* — a **content assertion in the CI dogfood job** (`ci.yml`, the
"Image — build + dogfood self-scan" job) that runs against the real built image and fails if
`/app/backend/tests` or `/app/backend/scripts` is present, or if the runtime `app`/`alembic` trees are
missing. No local `docker` daemon was available in the fix session, so image-content absence is confirmed
live by that CI step (and was pre-confirmed by a faithful `.dockerignore` pattern-match simulation).
**Plan section affected:** none — image-content hygiene only; no schema, security-model, or job-model
change. `supply-chain-review.md` SC-14; CLAUDE.md § Hard security rules (CIS baseline —
slim runtime image).

### 2026-07-20 — Post-release — P3-3: surface credential/filter option-fetch failures instead of silently swallowing them
**What changed:** `NewScanPage.tsx` and `ScansPage.tsx` each had an empty `catch` around the option
fetch (registry/git-credential pickers on New Scan; initiator/tag filter lists + presets on Scan
history). A failed fetch left the pickers/lists silently empty, which is indistinguishable from
"genuinely none configured" — so an operator could launch a **private-image or -repository scan
anonymously**, believing no credential was saved, when in fact the credential list just failed to load
(the scan then fails minutes later with an opaque registry/clone auth error). The empty catches now set
an `optionsError` state and reset the lists; the UI distinguishes the two cases: New Scan shows a yellow
warning `Alert` (with a Retry action) above the registry/git-credential picker telling the operator that
saved credentials couldn't be loaded and launching now would scan anonymously; Scan history shows a
non-blocking inline warning (with Retry) that the initiator/tag lists may be incomplete. A successful
(re)load clears the warning.
**Why:** P3-3 (frontend review, LOW with a security edge) — the silent-empty-catch made a failed load
look like "no credentials configured", the misleading path that could get a private target scanned
anonymously. No test added: the Vitest suite runs in the Node environment and covers only pure
`src/lib/` helpers — there is no jsdom/React-Testing-Library harness to render a page component, and
adding one is out of scope for a minimal LOW fix (consistent with the existing untested page-effect
posture noted in `STATUS.md` § 1).
**Plan section affected:** none — UI error-surfacing only; no schema, security-model, or job-model
change. `frontend-review.md` P3-3.

### 2026-07-20 — Docs/Process — CLAUDE.md: strip auto-appended PR-body attribution footers after opening
**What changed:** Added a rule to `CLAUDE.md` § Git & PR conventions requiring that, immediately after
opening (or editing) any PR, the **live** PR body be re-fetched via the GitHub API/CLI and any
auto-appended attribution footer — "Generated by Claude Code", a "🤖 Generated with…" line, a
session/`claude.ai` link, a co-author trailer — be stripped, so PR bodies carry no Claude/Anthropic
identity, matching the existing commit-authorship and no-attribution-footer rules.
**Why:** The environment's tooling has appended an attribution footer to the PR **body** on essentially
every PR in this remediation effort, frequently *after* a clean description was submitted — so "the body
looked right when I composed it" is not sufficient proof. The pre-existing "treat it as untrusted until
verified" bullet already told a session to check the PR description, but the failure kept recurring;
codifying an explicit post-open live-body check-and-strip step means a future session that doesn't catch
it still has the rule to follow. Docs/process only — no code, schema, security-model, or job-model
change. (The PR that added this entry, together with the four §14 back-fill entries below, applied the
new rule to its own body.)
**Plan section affected:** CLAUDE.md § Git & PR conventions. Process/docs only; no build-phase, schema,
security-model, or job-model change.

### 2026-07-13 — Post-release — H1/SEC-1: repository scan targets must be remote clone URLs (local-path arbitrary-read closed) [back-fill]
_Back-fill entry (written 2026-07-20): records a fix that merged earlier (#53) without a §14 entry — see `STATUS.md` § "ARCHIVE.md §14 gaps"._
**What changed:** A `target_type=repository` scan was validated only for length and a leading `-`, then
passed straight to `trivy repo --`. Trivy's `repo` subcommand also accepts a **local filesystem path**,
so a target like `/data` or `/run/secrets` made Trivy walk the container filesystem and persist the
results as a downloadable artifact — the exact arbitrary-host-file read (SQLite DB / master key exposure)
that the `SCRYE_FILESYSTEM_SCAN_ROOTS` allowlist exists to prevent, reached through an ungated code path.
The fix requires a `repository` target to be a **remote git clone URL** (scheme `http`/`https`/`ssh`/
`git`): new `is_remote_repo_url()` helper (`backend/app/scanners/credentials.py`) and a `ScanCreateIn`
model validator (`backend/app/api/scan_schemas.py`) that rejects a non-URL target at request time (422);
because `ScanScheduleIn` subclasses `ScanCreateIn`, scheduled scans are covered too. Regression tests
reject `/data`, `/run/secrets`, `/`, `/app`, and `file://` targets (scanner never reached) and confirm a
valid remote clone URL still runs to `succeeded`, plus direct unit coverage of `is_remote_repo_url`.
Landed in **#53**.
**Distinct from the older SEC-1 already in §14:** this SEC-1 is the *security-review* SEC-1 (Top 5 #1,
HIGH — repository local-path read). It is **unrelated** to the older webhook-URL "SEC-1" logged in the
2026-07-05 P0 remediation entry below (generic-webhook URL stored as a write-only credential, §4.5/§6).
Two different reviews reused the same "SEC-1" label — this entry is the scan-target one.
**Why:** SEC-1 / Top 5 #1, the headline HIGH of the review batch. Keeps `SCRYE_FILESYSTEM_SCAN_ROOTS` as
the **only** way any scan can be pointed at local paths. Requiring a remote URL (vs. routing bare paths
through the filesystem gate) fits the existing schema-layer validation and avoids *adding* a local-git-
repo capability Scrye never offered — the target field is documented as a clone URL with no UI/config for
local paths.
**Plan section affected:** §4 (scan targets / request validation), §6 (filesystem allowlist as the sole
local-path gate); `security-review.md` SEC-1. No schema or job-model change.

### 2026-07-13 — Post-release — H9/SC-2 + H10/SC-3: SHA-pin all Actions, expand Dependabot, harden publish checkouts [back-fill]
_Back-fill entry (written 2026-07-20): records a fix that merged earlier (#57) without a §14 entry — see `STATUS.md` § "ARCHIVE.md §14 gaps"._
**What changed:** Supply-chain hardening of the CI/publish workflows (#57):
- **SC-2 (H9).** Every external `uses:` in `.github/workflows/*.yml` **and** the composite action
  `.github/actions/build-image/action.yml` is pinned to a full commit SHA, with the human-readable
  version kept as a trailing comment (`uses: actions/checkout@<sha> # v7.0.0`).
- **SC-3 (H10).** `.github/dependabot.yml` expanded from the single `github-actions` entry to also watch
  `pip` (`/backend`), `npm` (`/frontend`), and `docker` + `docker-compose` (`/docker`, base + sidecar
  images) — all targeting `dev`, weekly, grouped — **plus** a separate `github-actions` entry for the
  composite-action directory, since Dependabot's `github-actions` ecosystem does not recurse into
  composite actions living outside `.github/workflows/` (what D3 flagged as already broken).
- **Publish-checkout hardening (L24/SC-11, publish side).** `persist-credentials: false` set on the
  checkout steps of the two token-bearing (`packages: write`) workflows, `publish.yml` and
  `dev-nightly.yml`. (The `ci.yml` checkouts got the same treatment later in **#67**, logged in the
  2026-07-13 CON-4 entry below — that entry does **not** cover #57's SHA-pins/Dependabot work.)
- **D3/SC-10/L25 version-skew convergence.** The composite build action pinned older action majors than
  `ci.yml`; aligned them to the same majors `ci.yml` uses (`setup-qemu-action`/`setup-buildx-action`
  v4.2.0, `build-push-action` v7.3.0). This is the only behavioral change to the composite action —
  otherwise SHA-pin only, no cache-scope, layer-ordering, or build-invocation change (per CLAUDE.md
  § Build performance).
**Why:** SC-2 and SC-3 are the two HIGH supply-chain findings (Top 5 #5): mutable action tags are a
supply-chain risk (SHA-pinning removes it), and Dependabot's coverage gap left pip/npm/docker deps and
the composite action un-updated. Hardening the publish checkouts drops the persisted `GITHUB_TOKEN` on
the only token-bearing workflows; converging D3/L25 removes the version skew between the composite action
and `ci.yml`.
**Plan section affected:** locked decision §6 (publish/CI supply-chain hardening), CLAUDE.md § Dependency
hygiene / CI; `supply-chain-review.md` SC-2/SC-3/SC-11, `claude-md-compliance.md` D3. No
schema, application-security-model, or job-model change.

### 2026-07-13 — Docs/Process — CLAUDE.md compliance-drift closure (D1, D2, R1–R6) [back-fill]
_Back-fill entry (written 2026-07-20): records a docs-only fix that merged earlier (#65) without a §14 entry — see `STATUS.md` § "ARCHIVE.md §14 gaps"._
**What changed:** Documentation-only reconciliation (#65) closing the drift flagged in
`claude-md-compliance.md`. **D1:** swept ~100 dead `docs/PLAN.md` → `docs/ARCHIVE.md`
cross-references across the backend, frontend, and Dockerfile (86 files, 106 references; section anchors
unchanged; historical files under `docs/ARCHIVE.md` and `` intentionally keep their PLAN.md
refs as build-history record). **D2:** corrected the stale "no registry publishing" comments in
`docker/Dockerfile` and `docker/docker-compose.yml` to match locked decision §6 (GHCR publishing).
**R1–R6:** amended CLAUDE.md text to describe current reality — hand-written typed API client (FE-2),
dogfood gate = fixable HIGH/CRITICAL (INF-10), Vitest frontend tests, stored secrets field-encrypted in
the DB rather than `.env.example` placeholders, extended deliverables list, and the PLAN→ARCHIVE
references. **R7** (squash-merge authorship) and **R8** (promotion-title exception) already have their
own dated §14 entries above and are not re-logged here. No code, test, Dockerfile-logic, or CI-behavior
change.
**Why:** These amendments bring CLAUDE.md and the in-repo comments **in line with deviations already
logged in §14** (FE-2, INF-10, Vitest, OIDC-secret env handling, the extended deliverables, the PLAN→
ARCHIVE rename) so a future session doesn't "fix" already-compliant code back toward the abandoned plan.
Recorded here as a short closure pointer to those existing entries rather than restating each one.
**Plan section affected:** CLAUDE.md (multiple sections) and in-repo doc comments; points at the
already-logged §14 deviations. Process/docs only; no schema, security-model, or job-model change.

### 2026-07-13 — Post-release — Backend dev-dependency bumps (pytest, pytest-asyncio, black) [back-fill]
_Back-fill entry (written 2026-07-20): records a fix that merged earlier (#59) without a §14 entry — see `STATUS.md` § "ARCHIVE.md §14 gaps"._
**What changed:** Bumped the `backend/pyproject.toml` dev extras (#59): `pytest` 8.3.4 → 9.0.3,
`pytest-asyncio` 0.25.1 → 1.4.0, `black` 24.10.0 → 26.3.1; **`ruff` deliberately left at 0.8.6**. This
corrected Dependabot's grouped pip bump (#58), which raised `pytest`/`black` but left `pytest-asyncio`
pinning `pytest<9` — an unsatisfiable combination that failed the backend job at install time
(`ResolutionImpossible`); #59 retargeted to `dev` and moved `pytest-asyncio` to a release allowing
`pytest<10` so the dev toolchain resolves. Verified: full suite **476 passed, 3 skipped**; `black --check`
and `ruff check` clean.
**Why:** A pinned-version refresh addressing the supply-chain review's dev-dependency staleness note;
because it changed pinned versions it warrants a §14 line under the dependency-pinning convention. `ruff`
was held at 0.8.6 on purpose — bumping it would surface the latent `test_migrations.py` I001 straggler
tracked as **D5b** (a separate follow-up), not something to fold into a routine bump. Dev/test-only pins:
the runtime image and hash-pinned `backend/requirements.lock` are unaffected.
**Plan section affected:** CLAUDE.md § Dependency hygiene (pinned dev deps); `supply-chain-review.md`
dev-dep staleness note. No runtime dependency, schema, security-model, or job-model change.

### 2026-07-13 — Post-release — CON-4 (H5): scanner JSON parse/normalize hopped off the event loop
**What changed:** Each scanner's `_execute` now runs its parse+normalize step in a worker thread via
`anyio.to_thread.run_sync` instead of calling it inline on the event loop:
`backend/app/scanners/trivy.py` (`findings = await anyio.to_thread.run_sync(parse_output, result.stdout)`)
and `backend/app/scanners/grype.py` (same, returning `(findings, version)`). Because both `parse_output`
functions call the shared `load_json_output` (`scanners/base.py`) internally, hopping `parse_output`
moves the `json.loads` *and* the per-finding normalization loop off the loop in one place — no separate
change at `base.py:362` was needed, and the parsing logic itself is untouched. A regression test
(`backend/tests/test_scanners.py`) proves it: a deliberately blocking stand-in parse runs while a
heartbeat coroutine keeps ticking on the loop (asserted responsive), plus thread-identity assertions
for both engines that the parse executes off the loop thread.
**Why:** CON-4 (concurrency review, filed as HIGH / verification-pass H5) — scanner stdout is capped at
`SCRYE_SCANNER_MAX_OUTPUT_BYTES` (512 MiB) and a large report (the archive's own run produced 7,072
findings) is seconds of pure CPU to parse; on the loop that froze every request, including the
`/healthz` poll the container healthcheck restarts on. This finding was missed in the CON-5–CON-20
remediation batch and had **no prior §14 entry** (it fell in the gap between the "Top 5 #2" and
"CON-5–CON-20" change-sets), so this entry also closes that record gap. The fix deliberately reuses the
**same** `anyio.to_thread.run_sync` primitive CON-5 used for blocking DB work — a mechanical thread hop,
no new concurrency primitive, no schema/security-model/job-model change (§0.2 single-container in-process
async worker unchanged).
**Plan section affected:** `concurrency-review.md` CON-4; no change to §0/§4/§7. Also folds
in L24/SC-11 (add `persist-credentials: false` to `.github/workflows/ci.yml` checkouts) as a separate
commit — CLAUDE.md hard security rules / CI hygiene.

### 2026-07-13 — Docs/Process — Squash-merge authorship follows the GitHub profile display name (D4 doc-side)
**What changed:** `CLAUDE.md` § Git & PR conventions (the author-identity rule) now records that a
GitHub **squash-merge** authors the squashed commit with the merging account's *profile display name*,
which the repo-local `git config user.name "tyler-rich"` cannot override. The rule therefore requires
the GitHub profile display name to also read `tyler-rich` for the identity convention to hold
end-to-end.
**Why:** The CLAUDE.md compliance audit (`claude-md-compliance.md`, GP4/D4) found 8
squash-merge promotion commits authored as "Tyler Richardson" (the account's display name) rather than
`tyler-rich` — same account, same mandated no-reply email, only the *name* diverging. This is not
something a session can fix via `git config`: squash authorship is assigned server-side at merge time
from the profile display name, so the operating contract must state the profile-alignment requirement
explicitly. This is the documentation counterpart to drift finding D4 (the actual display-name fix is a
GitHub profile setting made outside the repo, handled by the maintainer).
**Plan section affected:** CLAUDE.md § Git & PR conventions (author identity). Process/docs only; no
build-phase, schema, security-model, or job-model change.

### 2026-07-13 — Docs/Process — dev→main promotion PRs use a plain "Promote dev to main: …" title
**What changed:** `CLAUDE.md` § Coding standards (the "Commits: Conventional Commits" rule) now records
an explicit exception: `dev` → `main` **promotion** PRs use a plain `Promote dev to main: …` title
rather than a Conventional-Commit prefix, matching `CONTRIBUTING.md` § Releasing.
**Why:** Promotions are deliberate, maintainer-initiated release steps (not routine feature work); the
squash-merge subject names the release action rather than a code change, so a `feat:`/`fix:` prefix
would misdescribe it. The CLAUDE.md compliance audit (`claude-md-compliance.md`, GP6) noted
the promotion titles were not Conventional-Commit-shaped; recording the convention as a stated
exception — rather than "fixing" compliant release titles toward a prefix — matches the release process
already documented in `CONTRIBUTING.md` § Releasing.
**Plan section affected:** CLAUDE.md § Coding standards (Commits). Process/docs only; no build-phase,
schema, security-model, or job-model change.

### 2026-07-13 — Post-release — Security + supply-chain review batch (H11, M2–M5, M22–M26, L1–L4, L23)
**What changed:** Worked the security-review (`security-review.md`, SEC-*) and
supply-chain-review (`supply-chain-review.md`, SC-*) findings summarized in
`00-summary.md`, one commit per finding:
- **H11 / SC-1.** Added a hash-pinned backend lockfile (`backend/requirements.lock`, compiled with
  `uv pip compile --generate-hashes` — uv is build/dev-time only, pyproject stays PEP 621). The
  image installs runtime deps with `pip install --require-hashes -r requirements.lock` then the app
  with `pip install --no-deps .`; CI regenerates the lock with the pinned uv and fails on drift.
- **M2 / SEC-3.** Master-key entropy floor: the key file must be valid base64 decoding to ≥32 bytes;
  the raw-passphrase fallback is rejected unless the temporary `SCRYE_ALLOW_WEAK_MASTER_KEY` opt-out
  is set (logs a warning). **Input validation only** — the KDF and on-disk token format are
  unchanged, so all existing ciphertext still decrypts (regression-tested). Per the maintainer
  decision to use option 1 (entropy floor, no crypto-format change).
- **M5 / SEC-6.** New `core/egress.py` SSRF guard screens the notification/registry/docker-proxy
  fetchers: loopback + link-local/metadata always refused; RFC-1918/private refused unless the new
  `SCRYE_ALLOW_INTERNAL_EGRESS` setting (default off) is enabled; the docker proxy allows private
  (internal by design) but still refuses loopback/metadata. **New Settings field**
  `allow_internal_egress` → regenerated `.env.example`.
- **M3 / SEC-4.** Broadened log redaction: the unquoted secret-value branch is now tempered-greedy
  (consumes to EOL or the next `key=` pair, anchored to a non-space first char) so a spaced/comma-
  bearing secret is redacted whole. **Behavior change:** trailing free text after an unquoted
  single-token secret is now over-redacted (accepted trade-off; two tests updated).
- **M22 / SC-6, M23 / SC-7, L23 / SC-9.** Refreshed the stale `node:22-bookworm-slim` digest; bumped
  `tecnativa/docker-socket-proxy` 0.3.0 → v0.4.2 (image pull/boot could not be exercised in the
  egress-restricted environment — re-verify on a Docker-Hub-reachable host; wollomatic migration
  tracked in issue #63); digest-pinned the `# syntax=docker/dockerfile:1.7` frontend.
- **M24 / SC-4.** Publish workflows attach BuildKit SLSA provenance (`mode=max`) + SPDX SBOM and a
  GitHub-signed `attest-build-provenance` (job-level `id-token`/`attestations` write); CI build-only
  check leaves them off.
- **M25 / SC-5.** New `rescan.yml` weekly re-scan of the published `:latest`/`:dev` images (same
  Trivy/Grype gate), opening/commenting a tracking issue on a finding instead of gating a merge.
- **M26 / SC-8.** Dockerfile now cosign-verifies each scanner's `checksums.txt` (keyless, identity
  pinned to the upstream release workflow) before `sha256sum -c`; cosign pinned by digest via
  `COPY --from` the Sigstore image. **The exact upstream signature asset names / certificate
  identities could not be exercised here (release CDN + api.github.com blocked); the CI image build
  validates them.**
- **L1 / SEC-7.** Field-encryption AAD now optionally binds to the row id (`<table>.<column>:<id>`).
  Backward-compatible and **migration-free**: decrypt tries row-bound then falls back to the column
  tag, so existing ciphertext still decrypts and each secret upgrades on next write (MFA/OIDC bind
  immediately; API-resource creates bind on first update). The backup re-wrap preserves each value's
  existing binding across a cycle.
- **L2 / SEC-8, L3 / SEC-9.** Both are documented accepted limitations the review flagged as
  no-behavioral-change (OIDC delegates MFA to the IdP; enroll-on-first-login is inherent). Added
  audit visibility instead: OIDC logins under a mandatory policy record `mfa_delegated_to_idp`, and
  the policy-forced first-enrollment records `forced_by_policy`. README security model documents both
  windows. **No auth behavior changed.**
- **L4 / SEC-10.** The rate limiter now evicts fully-expired idle keys once the map grows past a
  threshold (amortized), and `PendingMfaStore` caps concurrent challenges per user.
**Why:** Remediate the confirmed security/supply-chain findings. Stop-and-ask items were resolved
with the maintainer up front: H11 lockfile tool (uv, build-time only), M2 crypto approach (entropy
floor, no format change), and M23 socket-proxy (bump tecnativa now, wollomatic as a tracked follow-up).
**Plan section affected:** §6 (secrets-at-rest hardening — additive, no format change), §6 locked
decision context (new `SCRYE_ALLOW_INTERNAL_EGRESS` / `SCRYE_ALLOW_WEAK_MASTER_KEY` operational
knobs), locked decision §6 publish pipeline (provenance/SBOM attestation + scheduled re-scan). No
schema or job-model change.

### 2026-07-13 — Post-release — Frontend-review wave 2 (M19–M21, L16–L22)
**What changed:** Worked the remaining confirmed frontend-review findings from
`frontend-review.md` (summarized in `00-summary.md`), one commit each.
No schema, security-model, or contract change — all fixes are client-side lifecycle/UX/a11y:
- **M19 / P1-2.** Settings forms (Retention, General, Backups schedule) no longer render editable
  with Save enabled before their initial GET resolves — they gate the inputs/Save on a `loaded`
  flag and only seed fetched values into a pristine form (`!form.isDirty()`), so a slow GET can't
  be overwritten with defaults and a late response can't clobber in-progress edits. Backups splits
  the schedule-form hydration out of the shared `load()` so list mutations stop re-hydrating it.
  The New scan FEAT-7 prefill applies only to a pristine form.
- **M20 / P1-3.** The scan-detail status poller uses exponential backoff (2.5s→30s) and halts after
  a failure ceiling (or on a 404), surfacing a paused/Retry state instead of hammering a failing
  endpoint behind a stale "running" badge. Backoff math is a unit-tested `lib/polling` helper.
- **M21 / P1-4, L18 / P2-3.** History and findings fetches use a unit-tested latest-wins guard
  (`lib/latest`) so out-of-order responses can't render results for a filter no longer selected.
  Findings also gain loading/loaded flags (Loader on first load, LoadingOverlay during filter
  changes) to remove the empty-state flash and stale rows.
- **L16 / P2-1, L17 / P2-2.** The status poll no longer wipes an in-progress tag edit (adopts the
  server tags only while the draft still matches the last synced value, via `lib/arrays`), and all
  per-scan state resets in an effect keyed on `:scanId` so navigating between scans can't mix state.
- **L19 / P2-4.** In-flight guards on mutation triggers (API-token create/revoke, user create,
  schedule create/run/delete, MFA enroll/confirm/disable, session revoke, change password) — most
  importantly stopping a double-click from minting an invisible second API token.
- **L20 / P2-5, L21 / P2-6, L22 / P2-7.** History table made keyboard-accessible (UnstyledButton
  headers + `aria-sort`, row links via `Anchor component={Link}`); accessible names added to the
  scan-detail filters/tags, New scan segmented controls, and MFA PinInput; a Burger+Drawer mobile
  nav fallback added below the `sm` breakpoint.
P1-1 (unsafe `primary_url` href) was already fixed in wave 1 (the `safeHttpUrl` helper) and is
reused, not re-touched.
**Why:** Remediate the confirmed frontend-review findings. Client-only changes; no plan decision
touched.
**Plan section affected:** none (bug/UX/a11y fixes; no schema, security-model, or job-model change).

### 2026-07-13 — Post-release — API-review batch (APIR-1…APIR-10)
**What changed:** Worked the API/data-model review findings from
`api-review.md` (summarized in `00-summary.md`), one commit each:
- **APIR-1 (H7).** `IgnoreRuleIn.expires_at` now normalizes aware datetimes to naive UTC via a
  new shared `core.timeutil.to_naive_utc` (which `scan_filters` also reuses), so a Trivy ignore
  rule's offset is no longer silently dropped.
- **APIR-2 (H8).** A `RequestValidationError` handler in `main.py` flattens schema-validation 422s
  into the string `detail` envelope hand-raised 422s already use, so the SPA renders the reason.
- **APIR-5 (M17).** Response models serialize timestamps with an explicit `Z` via a shared
  `UtcDatetime` field type (`api/schema_types.py`); storage stays naive. **Contract note:** the
  wire format for every timestamp changed from bare ISO-8601 to `…Z` (additive for correct
  consumers; `parseUtc` already accepted it).
- **APIR-3 (M15).** `DiffFindingOut` gains `location` (part of the diff identity for non-vuln
  classes) and the SPA's Compare gate now also checks `target_type`.
- **APIR-4 (M16).** Filtered-history export flags truncation (JSON metadata, Markdown/CSV note,
  `X-Scrye-Truncated`/`X-Scrye-Total` headers) when the 5 000-row cap fires.
- **APIR-6 (M18).** Update paths for secret-bearing resources re-establish create-path invariants:
  a mandatory notification secret can't be cleared, and registry update strips `name`/
  `registry_host` and refuses to blank a username_password username.
- **APIR-7 (L12).** Already resolved by the CON-17 fix in #60 (run-now stamps all three `last_*`
  fields); added the `last_status` assertion the review called out. No code change.
- **APIR-8 (L13).** Renamed the audit pagination envelope key `entries` → `items` to match the
  dominant `{total, items}` shape. **Scope decision (maintainer-directed):** deliberately *not*
  the broad rewrite — the unpaginated bare-array admin lists and the frozen `GET /api/scans` are
  left as-is. **Contract note:** `/api/audit` response key changed (admin-only, no SPA consumer).
- **APIR-9 (L14).** Split `ScanSummaryOut` (drops `options`/`error`, adds `has_error`) for list/
  history/dashboard rows from the full `ScanOut` (detail only). **Contract note:** those list
  payloads no longer carry `options`/`error`.
- **APIR-10 (L15).** Extracted the duplicated scanner↔target matrix to
  `app/scanners/support.py` (`SCANNER_TARGET_SUPPORT` / `scanner_supports`), consumed by both the
  scans and scan-schedules routers.
**Why:** Remediate the confirmed API-layer findings. APIR-5/8/9 change response shapes; per the
review's own guidance they were scoped narrowly (or, for APIR-8, held to the single-key rename per
maintainer direction) rather than taken as a broad contract-version bump.
**Plan section affected:** none (bug fixes / additive contract clarifications; no schema, security-
model, or job-model change).

### 2026-07-13 — Post-release — CON-2/CON-14 remediation: process-group kills for scanner subprocesses
**What changed:** `run_command` (`backend/app/scanners/base.py`) now spawns scanner/git subprocesses
with `start_new_session=True`, making the child its own process-group leader, and kills the whole
group (`os.killpg(proc.pid, signal.SIGKILL)` via a new `_kill_process_group` helper) on all three
abort paths — output-cap overflow, timeout, and shutdown cancellation — instead of `proc.kill()`,
which only signalled the direct child. The helper (and the pre-existing `wait()` guards) suppress
`ProcessLookupError` so a process group that has already exited can't replace the abort's own error
(CON-14; the timeout path previously lacked this suppression entirely).
**Why:** `git clone` spawns `git-remote-https`, and trivy/grype can spawn their own helpers; on
timeout, output-cap overflow, or worker-shutdown cancellation the direct child died but these
grandchildren kept running with `SCRYE_GIT_PASSWORD`/`GIT_ASKPASS` still in their environment
(`concurrency-review.md` CON-2, Top 5 #4) — a leaked credential-bearing process racing
`generic_repo_checkout`'s best-effort cache cleanup. Process-group kill is the review's recommended
fix and covers every current and future scanner child through the single `run_command` seam.
**Plan section affected:** none (bug fix; no schema, security-model, or job-model change).

### 2026-07-13 — Post-release — CON-1/CON-11/CON-3/SEC-2 remediation; worker seam gains optional hooks
**What changed:** Three coupled fixes from the 2026-07-12 review batch (`00-summary.md`
Top 5 #2), landed as one change-set because they compound into a single failure theme:
- **CON-1 + CON-11.** The worker's DB commits (the queued→running claim, `_persist_success`,
  `_fail`, `_store_failure_output`) now run through a bounded retry-with-backoff helper for SQLite
  lock-contention `OperationalError`s, and a successful scan's artifact files are unlinked only
  after the *final* commit attempt fails (previously the first failure deleted them). A stale-scan
  watchdog runs at the top of every maintenance tick: it re-submits `queued` scans older than a
  grace period with no live task (lost submits — shutdown races, restore pauses) and fails
  task-less `running` scans via an atomic conditional UPDATE, so both "stuck until restart"
  families self-heal within a tick. The claim/fail commits also moved off the event loop into
  threads (the highest-value subset of CON-5).
- **CON-3.** `restore_bundle` now takes the write lock up front (`BEGIN IMMEDIATE`) and re-checks
  the "no queued/running scans" guard *inside* the write transaction, raising a new
  `RestoreConflictError` (→ 409) — the endpoint's pre-check is check-then-act across the upload
  await and stays only as a fast-fail courtesy. The restore endpoint also pauses the worker for
  the duration (submissions still land; their tasks hold at a gate until resume).
- **SEC-2.** Restore-supplied scrypt parameters are clamped (`n<=2**20`, `r<=16`, `p<=4`, plus a
  memory-budget check) and `maxmem` is a fixed 512 MiB constant instead of being derived from the
  bundle's own untrusted `n`/`r`; malformed (non-numeric) KDF fields now fail as `BackupError`
  instead of a 500.
The `ScanWorker` interface (§0.2's "thin seam") gains three **optional, default-no-op** hooks —
`reconcile_stale()`, `pause()`, `resume()` — overridden only by the in-process worker; the core
seam (`submit`/`recover`/`shutdown`) is unchanged, so a future distributed worker still only has
to implement those three.
**Why:** The review showed a large findings flush, a restore, or a retention pass holding the
write lock past the 5 s `busy_timeout` permanently loses a concurrent scan's results and strands
it `running`; the restore guard raced scan creation across the upload await; and a crafted bundle
could OOM-kill the container before passphrase validation. The watchdog was the review's own
recommended mechanism ("retires CON-1 and CON-11 together"), as were the in-transaction re-check,
the worker pause, and the scrypt clamps. No DB schema change and no change to the locked job
model (§0.2) — the worker stays a single-container in-process async worker.
**Plan section affected:** §0.2 (worker seam — extended, not reshaped), §8 (restore semantics),
§12 (post-release hardening; no phase scope changed).

### 2026-07-13 — Post-release — CON-5–CON-20 remediation: async-path, shutdown, and pool hygiene
**What changed:** The remaining medium/low concurrency-review findings
(`concurrency-review.md`), each landed as its own commit with a regression test:
- **CON-5** (event-loop offload). The maintenance tick's scanner-DB policy read
  (`workers/db_update.py`), the worker's per-scan Trivy/Grype policy loads, and the scan-queue
  insert/audit/commit (`api/scans.py`) now hop off the loop via a worker thread, matching the
  pattern already used for result persistence and restore.
- **CON-6** (shutdown budget). Added `stop_grace_period: 30s` to `docker/docker-compose.yml`,
  shrank the worker drain grace `10s → 5s`, and bounded each scheduler's shutdown with
  `asyncio.wait` (not `wait_for`, which would block on a cancel-swallowing threaded pass) so a
  wedged task is abandoned after a timeout instead of running past SIGKILL.
- **CON-7** (unshielded lifespan). The lifespan teardown is wrapped in `asyncio.shield` and each
  component's shutdown runs under its own `try/except`, so a second cancellation or one failure
  can't skip `worker.shutdown()` and abandon live scanner subprocesses.
- **CON-8** (`PendingMfaStore`). `issue`/`consume`/`_prune` now hold a `threading.Lock`, mirroring
  the rate limiter, so concurrent threadpool logins can't raise "dictionary changed size".
- **CON-9** (backup snapshot). `build_bundle` reads every table inside one explicit `BEGIN` (a
  single WAL read snapshot) so a scan committing mid-dump can't tear the bundle; `run_due_backup`
  additionally defers (and logs, leaving `last_run_at` unset to retry) while any scan is
  queued/running, mirroring the manual-restore guard.
- **CON-10** (connection pinning). *User chose "Both" when presented the architectural option.* The
  worker now resolves all DB inputs up front into detached values (`_RunInputs`), rolls back to
  return its pooled connection to the pool, runs the minutes-long subprocess holding none, and
  re-acquires only for persistence. As defense-in-depth the pool is sized from
  `max_concurrent_scans` (`db/session.py`) and the setting is **newly capped at 1–32**
  (`core/config.py`; `.env.example` regenerated).
- **CON-12** (DB-update marker). `maybe_update_scanner_dbs` advances its interval marker only when
  at least one engine actually updated, so a transient failure retries next tick.
- **CON-13** (serialized tick). The scanner-DB refresh runs as its own detached maintenance task
  (guarded to one at a time), so a slow update no longer delays the next tick's schedules/retention.
- **CON-15** (semaphore-held notify). Notifications dispatch after the concurrency-semaphore block
  exits, so a slow/dead channel can't hold a scan slot.
- **CON-16** (task hygiene). The per-scan task's done callback retrieves and logs any escaped
  exception; the session-factory call is guarded; and `submit` caps live tasks (scaled from
  `max_concurrent`, floor 64) so a flood is deferred to the watchdog rather than piling up.
- **CON-17** (run-now race). "Run now" stamps `last_run_at`, so the cron tick doesn't fire the same
  schedule again the same minute.
- **CON-18** (dashboard gather). The dashboard `asyncio.gather` uses `return_exceptions=True` and
  handles each branch, so a DB error no longer abandons the in-flight scanner-DB probe subprocesses.
- **CON-19** (stale identity-map notify). `_notify` re-reads the scan with `populate_existing=True`,
  so a scan deleted the instant it finished isn't announced with a 404 link.
- **CON-20** (loop-blocking rmtree). `generic_repo_checkout` removes the (potentially multi-GB)
  checkout via a shielded thread hop instead of inline on the loop.
**Why:** All are direct remediations of the cited review findings. **CON-11** was verified against
current code and found **already retired** by Session 2's stale-scan watchdog (re-submits stranded
`queued` scans), so it was skipped, not re-fixed. **CON-10** was the one finding whose primary fix
is architectural; per the review-branch task it was raised with the user before implementing, who
chose the combined connection-release + pool-sizing/cap approach. No DB schema change; the locked
job model (§0.2, single-container in-process async worker) is unchanged — `max_concurrent_scans`
gaining an upper bound is a new operational guard, not a model change.
**Plan section affected:** §0.2 (worker internals — connection lifecycle refined, model unchanged),
§8 (backup snapshot consistency), §12 (post-release hardening; no phase scope changed).

### 2026-07-13 — Security — account-takeover chain fix: XSS sink containment + baseline security headers
**What changed:** Two coupled changes closing the audit's account-takeover chain (frontend FE-9 +
the missing response-header baseline):
- **Frontend URL sink hardened.** Added `frontend/src/lib/url.ts` `safeHttpUrl()`, which admits only
  well-formed `http:`/`https:` URLs (rejecting `javascript:`/`data:`/`vbscript:`/relative/malformed).
  `ScanDetailPage.tsx` now renders a finding's scanner-derived `primary_url` as an `<Anchor>` only
  when it passes `safeHttpUrl`, otherwise as inert text, and adds `rel="noopener noreferrer"`. This
  is the only place scanner-derived data was rendered as a link (all other `href`s are app-internal
  API endpoints).
- **Baseline security-header middleware.** Added `backend/app/core/security_headers.py`
  (`SecurityHeadersMiddleware`), wired as the outermost middleware in `create_app`. Every response
  now carries `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, and a Content-Security-Policy tuned for the
  built Mantine SPA (`script-src 'self'` — no inline scripts; `style-src 'self' 'unsafe-inline'` —
  Mantine injects theme CSS at runtime; `connect-src 'self'`; `object-src 'none'`;
  `frame-ancestors 'none'`; `base-uri`/`form-action 'self'`; `img-src 'self' data:`). The CSP was
  verified against the real built SPA under a headless browser (login shell renders with styles, zero
  `securitypolicyviolation` events). The interactive API docs (`/docs`, `/redoc`) are exempted from
  the CSP only — they need inline scripts + CDN assets a SPA CSP would break — but still receive the
  other three headers. The CSRF cookie's `httponly=False` double-submit design is unchanged, per the
  report.
- **Frontend test runner.** Added `vitest` (pinned `3.2.7`) as the frontend unit-test runner with a
  `test` script, a Node-environment `test` block in `vite.config.ts`, and a new CI step
  (`npm test`). `src/lib/url.test.ts` covers `safeHttpUrl`; `backend/tests/test_security_headers.py`
  asserts the headers (and the docs-CSP exemption). This is the first frontend test suite — the CI
  `frontend` job previously only linted + built.
**Why:** The audit flagged an unvalidated scanner-derived URL rendered as a link plus the absence of
any security-header baseline as a chain that could aid account takeover. Containing the sink and
shipping standard defence-in-depth headers closes it without touching the documented CSRF model.
**Plan section affected:** § Hard security rules; § Auth & Authorization (§5) — additive hardening,
no security-model or schema change. § Required deliverables (CI gains a frontend test step).

### 2026-07-07 — Process — back-merge step after promotion; Dependabot retargeted to `dev`
**What changed:** Two coupled changes to the `dev`/`main` branching model (adopted 2026-07-04) that
stop `dev` from silently drifting "behind" `main` after every release:
- **Documented back-merge step.** `CLAUDE.md` § Git & PR conventions and `CONTRIBUTING.md`
  § Releasing now require back-merging `main` into `dev` immediately after each `dev` → `main`
  promotion (and after any commit that lands on `main` directly). Because promotions are
  squash-merged, `main`'s squashed copy of already-promoted work conflicts with `dev`'s newer
  versions of those files; the rule is to resolve every such conflict in favour of `dev`, so the
  only content a back-merge introduces to `dev` is whatever landed on `main` independently.
- **Dependabot retargeted to `dev`.** `.github/dependabot.yml` gains `target-branch: "dev"`.
  Previously Dependabot targeted the default branch (`main`), so a github-actions bump merged onto
  `main` and never reached `dev` — one of the two drift sources. Routing bumps through `dev` (the
  integration branch) leaves only the unavoidable promotion-squash case for the back-merge step to
  handle, at much lower frequency.
This entry also records the one-time reconciliation performed the same day: `main` was back-merged
into `dev` to clear the accumulated drift (the #32 promotion squash + the #33 github-actions bump
that had landed directly on `main`), resolving conflicts in favour of `dev` so the only net change
to `dev` was #33's action version bumps.
**Why:** `dev` showed "behind" `main` after two successive promotions — an inherent side effect of
the squash-based promotion model plus Dependabot targeting `main`. Retargeting Dependabot removes
the avoidable source; the documented back-merge handles the unavoidable squash-divergence so the
branches stay reconciled and the "behind" count doesn't reappear as a surprise each release.
**Plan section affected:** Process — amends the 2026-07-04 "Adopted a dev/main branching model"
entry; § Git & PR conventions (CLAUDE.md), § Releasing (CONTRIBUTING.md). No build-phase or
architectural sections affected.

### 2026-07-06 — Infra — dev publishing moved to a nightly GHCR build (registry split + INF-2 resolved)
**What changed:** Three coupled CI/CD changes that together restructure dev-image publishing, plus a
general CI-minute-reduction pass. Treated as one entry because they are one architecture change:
- **Registry split.** Docker Hub (`<dockerhub-user>/scrye`) is now **release-only** — the tagged-
  `v*.*.*`-on-`main` path in `publish.yml` (→ `:<version>` + `:latest`). Dev images move to **GHCR**
  at `ghcr.io/tyler-rich/scrye:dev`, published by a new `.github/workflows/dev-nightly.yml` that
  authenticates with the built-in `GITHUB_TOKEN` (no PAT, no Docker Hub secret). The `dev` job and
  its `pull_request: types:[closed]` trigger were **removed** from `publish.yml`; Docker Hub is no
  longer referenced anywhere in the dev path.
- **Nightly cadence.** The per-merge multi-arch rebuild of `:dev` is replaced by a **04:00 UTC
  nightly** schedule (+ manual `workflow_dispatch`) that builds `dev` HEAD multi-arch (amd64+arm64)
  and pushes the moving `:dev` tag. A skip-check short-circuits the scheduled run when `dev` has had
  no new commits in the last 24h. **No dated history tags and no image-cleanup job in this pass**
  (deferred — the dev-tag scheme is expected to change). Immediate per-PR feedback is unchanged:
  `ci.yml` still lints, tests, and builds the amd64 image on every dev PR.
- **INF-2 resolved.** The fork-PR `:dev` publish gap (a `pull_request`-triggered job whose head is a
  fork gets no repository secrets) is eliminated: a `schedule`/`workflow_dispatch` trigger is not
  PR-triggered and runs in the base-repo context, and GHCR uses the always-present `GITHUB_TOKEN`
  rather than fork-withheld secrets. A fork PR merged into `dev` is picked up by the next nightly.
  The INF-2 caveat and its "revisit before going public" note are retired (marker added to the
  2026-07-05 P2 entry).
- **General minute reduction (`ci.yml`).** The two **informational** scanner reports (the non-gating
  `|| true` Trivy/Grype full reports in the `image` job) now run only on `push` events (main), not
  on PRs — dev PRs run just the two gate scans (the required checks are unchanged). A `cache-scope`
  input was added to `.github/actions/build-image` and wired through so amd64-only (`amd64-ci`) and
  multi-arch (`multiarch` for main/release, `dev-multiarch` for the nightly) builds use separate GHA
  cache scopes instead of evicting each other under the repo's 10 GB cache budget.
**Why:** Per-merge multi-arch (arm64-under-QEMU) rebuilds of the moving `:dev` tag were the largest
CI-minute cost relative to frequency (~10 dev merges in ~2 active days). Batching to a skip-guarded
nightly collapses that to ≤1 build/day. Moving dev images to GHCR keeps Docker Hub strictly for
releases, uses the free always-available `GITHUB_TOKEN`, and sidesteps the fork-secrets problem
INF-2 flagged. User-approved this session (registry choice, cadence, informational-scan gating, and
cache scoping).
**Operational follow-ups (must be verified in repo Settings / GHCR — cannot be done from CI):**
- **Settings → Actions → General → Workflow permissions** should be set to the restrictive
  **Read repository contents and packages permissions** (read-only) default — GHCR push does **not**
  require the repo-wide default to allow write. `dev-nightly.yml` declares its own explicit
  `permissions: { contents: read, packages: write }` block, which overrides the read-only default
  (an explicit block is exhaustive and takes precedence; it is not capped by the repo default). Each
  workflow declares exactly what it needs (`publish.yml` and `ci.yml` only `contents: read`), so the
  read-only default breaks nothing.
- **After the first nightly push, confirm the GHCR package `ghcr.io/tyler-rich/scrye` is Private**
  (it inherits the private repo's visibility by default; flag it if it publishes as public).
**Plan section affected:** §0.6 (distribution), §9.1 (image). Supersedes the INF-2 item in the
2026-07-05 P2 audit-remediation entry and the Docker Hub merged-PR `:dev` trigger in the 2026-07-04
publishing entry.

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
`phase3-finding2-resolution.md` (Option 1). Two adaptations to that
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

### 2026-07-03 — Phase P6 — Fix wrong `debian:bookworm-slim` base digest
**What changed:** The `scanners` build stage in `docker/Dockerfile` pinned
`debian:bookworm-slim` to `sha256:8a7e7cc0…`, which is actually the
`python:3.12-slim-bookworm` manifest digest (a copy-paste error latent since Phase 0).
Corrected it to the real `debian:bookworm-slim` multi-arch index digest
`sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df`.
**Why:** The new Phase 6 CI image job is the first time the image is actually built in
CI, which surfaced the bad digest (`… : not found`) — no earlier phase built the image,
so the error went unnoticed. The two python stages and the node stage were already
correct. Pinning to the current debian index digest keeps §9.1's digest-pinning intact.
**Plan section affected:** §9.1 (image), §12 (Phase 6 CI).

### 2026-07-03 — Phase P6 — Dogfood gate excludes the bundled scanner binaries
**What changed:** The CI dogfood gate skips the bundled `trivy`/`grype`/`syft` binaries
(`--skip-files` for Trivy, `--exclude` + a `package.location` ignore for Grype) while
still scanning them in the informational report and still gating on everything else in
the image. The first successful image build's scan flagged 7 fixable HIGH findings, all
inside those binaries' embedded Go modules / Go stdlib (containerd, oras-go, docker/docker,
crypto/x509, net/textproto); none were in Scrye's own OS packages, Python/JS deps, or app.
**Why:** Those are unmodified upstream Go binaries Scrye bundles under Apache-2.0 and
cannot rebuild — their embedded-dependency CVEs are fixed only when Aqua/Anchore cut a new
release built against a patched Go, so they are "genuinely unfixable upstream items" from
Scrye's side (CLAUDE.md § Dependency hygiene). Gating on them would make CI perpetually red
on the newest Go-stdlib CVE regardless of Scrye's own hygiene. Keeping them visible in the
informational report and keeping the pinned scanner versions current is how they are
tracked; the gate stays meaningful for Scrye's actual attack surface — including the `git`
runtime dependency and `THIRD_PARTY_LICENSES/`, which remain fully gated.
**Plan section affected:** §9.1, §12 (Phase 6 self-scan), CLAUDE.md § Dependency hygiene.

### 2026-07-03 — Phase P6 — Dogfood-driven dependency bumps (FastAPI/Starlette/multipart)
**What changed:** With the scanner binaries excluded, the dogfood gate correctly flagged six
fixable HIGH CVEs in Scrye's own Python deps: `python-multipart` 0.0.20 (CVE-2026-24486,
CVE-2026-42561, CVE-2026-53539) and `starlette` 0.41.3 (CVE-2025-62727, CVE-2026-48818,
CVE-2026-54283). Resolved by bumping `python-multipart` → `0.0.32`, adding an explicit
`starlette==1.3.1` pin (the version that fixes all three, previously an unpinned FastAPI
transitive), and bumping `fastapi` `0.115.6` → `0.139.0` (the release whose
`starlette>=0.46.0` constraint permits 1.3.1). All 325 backend tests pass on the new
versions; no application code changed.
**Why:** CLAUDE.md § Dependency hygiene requires resolving all fixable findings in Scrye's
own dependencies — these are exactly that (direct/transitive deps we control), unlike the
vendored scanner binaries. Pinning starlette explicitly guarantees the fixed version rather
than relying on FastAPI's floor.
**Plan section affected:** §2 (Tech stack pins), CLAUDE.md § Dependency hygiene.

### 2026-07-03 — Phase P6 — Grype gate excludes the CPython interpreter binary
**(Superseded by the "Backend runtime bumped Python 3.12 → 3.13" entry below — the
interpreter exclusion was removed once the runtime moved to 3.13.)**
**What changed:** With the app deps fixed, the Grype gate then failed on the CPython
interpreter binary (`python 3.12.13`, Grype `binary` type) from the
`python:3.12-slim-bookworm` base image — a run of HIGH CVEs (CVE-2026-7210, -6100, -4224,
-3298, -3644, -9669, -4786, …) whose "fixed in" versions are all Python 3.13+/3.14+/3.15+.
Excluded the `python` binary from the Grype gate (a `package: {type: binary, name: python}`
ignore in `ci/grype.yaml`) and added an informational Grype run so the finding stays
visible. The pinned base image was confirmed to already be the latest 3.12-slim-bookworm
digest, so the CVEs cannot be cleared without leaving Python 3.12.
**Why:** Python 3.12 is a locked decision (§2); these CVEs are fixed only by moving to
3.13+, so they are genuinely unfixable-by-us base-image runtime items — the same carve-out
CLAUDE.md § Dependency hygiene allows ("only genuinely unfixable upstream/OS-level items may
remain, noted in the README"). Trivy's OS-aware scan still gates the base image, and Grype's
binary classifier is the only thing that flags the interpreter binary at all.
**Plan section affected:** §2 (Python 3.12), §12 (Phase 6 self-scan), CLAUDE.md § Dependency
hygiene.

### 2026-07-03 — Phase P6 — Bundled Trivy bumped 0.71.2 → 0.72.0
**What changed:** The bundled Trivy version (`docker/Dockerfile` `TRIVY_VERSION`), the
digest-pinned `trivy-server` sidecar image in `docker/docker-compose.yml`, and the Trivy
image used by the CI dogfood job were bumped from `0.71.2` to `0.72.0` (the release Trivy's
own version notice flagged as current).
**Why:** CLAUDE.md § Dependency hygiene requires pinning to current, actively-maintained
versions; keeping the bundled binary and the matching `trivy-server` image on the latest
release continues the Phase 0 convention. Trivy self-verifies the new release against its
published checksums at build time, so only the version string changed.
**Plan section affected:** §9.1, §9.2 (bundled/sidecar Trivy version).

### 2026-07-03 — Phase P6 — Backend runtime bumped Python 3.12 → 3.13 (locked decision revised)
**What changed:** The locked backend runtime was revised from **Python 3.12 to Python 3.13**
and the Grype interpreter-binary exclusion added in the superseded entry above was **removed**.
Concretely: the Dockerfile base image is now `python:3.13-slim-bookworm` (digest-pinned) for
both the venv-builder and runtime stages; `backend/pyproject.toml` `requires-python` is
`>=3.13` and the black/ruff `target-version` are `py313`; the CI backend job runs on Python
`3.13`; and the `package: {type: binary, name: python}` ignore was deleted from
`ci/grype.yaml` so the CPython interpreter is scanned and gated like everything else. The
locked decision is updated in `CLAUDE.md` § Locked decisions #2 and `docs/PLAN.md` §0 (#7) and
§2. Verified locally on Python 3.13.12: a clean install of all dependencies (including the
C-extension/Rust ones — `cryptography`, `argon2-cffi`, `cffi`, `pydantic-core`), the full
325-test suite passing, a full Alembic upgrade/downgrade/upgrade cycle, and a clean app import,
with no new 3.13-specific deprecations or behavior changes (the only warnings are the
pre-existing Starlette `HTTP_422_UNPROCESSABLE_ENTITY` deprecation, unrelated to the runtime).
The CI dogfood self-scan — now with the interpreter exclusion removed — is the authoritative
confirmation that the interpreter CVEs are actually gone on 3.13 rather than merely assumed.
**Why:** The Grype-flagged CPython CVEs (CVE-2026-7210, -6100, -4224, -3298, -3644, -9669,
-4786, …) have fixes only in Python 3.13+/3.14+, none in the 3.12 line, and the 3.12 base image
was already the latest — so the only real fix is to move off 3.12. This reverses the original
lock. **Chose 3.13 over 3.14** for ecosystem/dependency maturity: at the time of this decision
3.13 has had roughly a year longer for the dependency ecosystem (especially C-extension and
Rust-backed wheels) to validate compatibility than 3.14 (~9 months), which reduces the risk of
missing/immature wheels while still resolving the interpreter CVEs. The interpreter-CVE
"treadmill" (new CPython CVEs vs. base-image rebuild lag) still exists in principle, but the
current 3.13 patch release clears the specific HIGH findings that motivated the change.
**Plan section affected:** §0 (#7, new locked runtime), §2 (tech stack), §9.1 (base image),
§12 (Phase 6 self-scan), CLAUDE.md § Locked decisions #2.

### 2026-07-03 — Phase P6 — Scanner temp/cache dirs pinned to the writable `/cache` volume; `/tmp` tmpfs owned by the app uid
**What changed:** Two coordinated fixes for `mkdir /tmp/trivy-XXXXXXXXX: permission
denied` under the hardened Compose config (§9.2). (1) `docker/docker-compose.yml`
now mounts the `/tmp` tmpfs with `uid=1000,gid=1000` in addition to `mode=1700`.
(2) A new `SCRYE_SCANNER_CACHE_DIR` setting (default `/cache`) plus a
`scanner_scratch()` helper in `app/scanners/base.py`: Trivy gets an explicit
`--cache-dir /cache/trivy`, Grype gets `GRYPE_DB_CACHE_DIR=/cache/grype/db`, and
all three engines (incl. Syft) get `TMPDIR=/cache/tmp` for the subprocess.
**Why:** A freshly mounted tmpfs is owned by **root**, and with the numeric
`user: "1000:1000"` (which leaves `HOME` unset → `$HOME/.cache` resolves under
the read-only `/`) the non-root process could neither write to `/tmp` (breaking
Trivy's temp-dir creation *and* the in-memory credential materialization) nor to
its default cache dir (breaking the vuln-DB download). Confirmed at the mount
level: `mount -t tmpfs -o size=200m,mode=1700` → owner uid 0, uid-1000 `mkdir`
fails; adding `uid=1000,gid=1000` → owner uid 1000, succeeds. Routing the large
databases and temp extraction onto the persistent `/cache` volume also keeps
them off the small (200 MB) tmpfs and lets the DB survive restarts. §9.2 left
the tmpfs root-owned and never pointed the scanners at a writable cache — the
plan pre-dated exercising a real scan under `read_only: true`.
**Plan section affected:** §9.2 (hardened Compose), §4 (scanner orchestration).

### 2026-07-03 — Phase P6 — Scanner cache redirected via env vars for **every** invocation (incl. probes)
**What changed:** Generalized the previous fix. `scanner_scratch(engine)` became
`scanner_cache_env()` in `app/scanners/base.py`, returning a full environment
overlay — `TMPDIR`, `HOME`, `XDG_CACHE_HOME`, `TRIVY_CACHE_DIR`,
`GRYPE_DB_CACHE_DIR` — all under the writable `/cache` volume. It is now applied
not only to the scans but also to the scanner **probes** in
`app/core/system_info.py` (`trivy --version --format json`, `grype db status`,
the version probes), which previously ran with no cache env.
**Why:** After the temp/cache fix, real image scans failed one step further with
`mkdir /app/.cache: read-only file system`. The numeric `user: "1000:1000"`
still resolves `HOME=/app` (from the image's `useradd --home-dir /app`), so a
scanner's default cache is `/app/.cache` on the read-only root. The image/repo
scan path set `--cache-dir`, but the About-tab DB-freshness probes did not —
`trivy --version --format json` reads the vuln-DB metadata under the cache dir
and `grype db status` reads its DB dir, both defaulting to `/app/.cache`. Moving
to env vars (rather than a per-subcommand flag) covers every invocation
uniformly. Verified end-to-end against the hardened Compose config: the real
Trivy DB downloads once to `/cache/trivy` and a real `trivy image` scan of
`alpine:3.19` reports CVEs; the DB persists across `docker compose down`/`up`
(offline `--skip-db-update` scan still succeeds). Grype's cache is redirected
identically (writes to `/cache/grype/db`, never `/app/.cache`); its DB registry
was unreachable from the CI sandbox's egress policy, so its download step is
covered by unit tests + the shared mechanism rather than a live pull.
**Plan section affected:** §9.2 (hardened Compose), §4 (scanner orchestration).

### 2026-07-03 — Post-P6 bug-fix round — `/tmp` tmpfs kept at 200 MB; footprint documented; cache/staging fix re-verified live end-to-end
**What changed:** No change to the hardened Compose posture (§9.2) or to the
scanner code — this round *confirmed* the existing posture and documented its
real resource footprint. A field report from the deployed stack showed both
scanners failing (`mkdir /app/.cache: read-only file system`) and Grype dying
with `no space left on device` while staging image layers under
`/tmp/stereoscope-…`; both failure signatures match the **pre-fix** image (the
two 2026-07-03 entries above shipped the fix on `main`), so the deployed
container needed a rebuild rather than new code. Faced with the tmpfs question
("grow `/tmp` or move staging off it"), the existing choice — keep `/tmp` at
**200 MB** and route all large scanner writes to the disk-backed `/cache`
volume via `TMPDIR`/`TRIVY_CACHE_DIR`/`GRYPE_DB_CACHE_DIR`/`HOME`/
`XDG_CACHE_HOME` — is retained deliberately: tmpfs is **RAM-backed**, so a
staging-sized tmpfs (multiple GB) would count image unpacking against the
container's 2 GB memory limit and trade a disk-space error for an OOM kill.
The README "Requirements" section now carries the measured footprint (Trivy DB
~1.2 GB, Grype DB ~1.5–2 GB, transient staging ≈ the uncompressed size of the
scanned image, `/cache` sizing guidance ≥ 10 GB, and the RAM trade-off note).
Re-verified live against the real hardened Compose config through the real
API path (admin bootstrap → `POST /api/scans` → worker → subprocess): a real
`trivy image` scan of a ~330 MB-compressed / ~1.1 GB-unpacked public image
succeeded (7 072 findings), the Trivy DB (1.17 GB) downloaded once to
`/cache/trivy/db` and survived `docker compose down`/`up` (post-restart scan
completed in ~5 s with no re-download), and a Syft SBOM pass staged ~1.07 GB
under `/cache/tmp` while the 200 MB `/tmp` tmpfs stayed completely empty —
the exact workload class that previously ENOSPC'd. Grype was verified to
resolve its DB to `/cache/grype/db/6/vulnerability.db` (volume, writable;
never `/app/.cache`) and to stage/catalog the image without any disk error;
its DB *download* could not be exercised from the verification sandbox
(`grype.anchore.io` is blocked by that environment's egress policy, as in the
prior entry) and the target image had to be substituted
(`mirror.gcr.io/library/node:20` for `ghcr.io/nezreka/soulsync:latest`, whose
ghcr.io blob host the sandbox also blocks — equivalent size class and code
path). On the deployed host, rebuilding the image from current `main` and
recreating the stack is the actionable fix.
**Why:** The task required confirming the fix with real scans against the
hardened config (not just unit tests), deciding the tmpfs size question
explicitly with the RAM cost called out, and documenting the disk/memory
footprint so deployments can size volumes and limits up front.
**Plan section affected:** §9.2 (confirmed, not changed), §10.1 (README
Requirements).

### 2026-07-04 — Post-P6 — Full-repo security audit remediation
**What changed:** A comprehensive security audit of the integrated codebase
surfaced a set of issues; the fixes touch several plan areas and are recorded
here together:
- **Scanner argv option-injection (§4):** scan `target`/`branch`/`commit`/`tag`
  now reject a leading `-`, and the Trivy/Grype/Syft argv builders insert a `--`
  end-of-options terminator before the positional, so an operator-supplied value
  can never be parsed as a scanner flag (e.g. `trivy image --reset`).
- **Third "hardened path" bug (§9.2):** the generic-host private `git clone`
  checkout now materializes under the writable `/cache` scratch volume instead of
  the 200 MB RAM-backed `/tmp` tmpfs (a large repo previously risked `ENOSPC`/OOM);
  the tiny `GIT_ASKPASS` credential helper stays in tmpfs.
- **MFA policy enforcement (§5):** a `required_all`/`required_admin` policy is now
  enforced at login for un-enrolled accounts via a forced-enrollment challenge
  (password success returns enrollment material + a challenge token; the login
  only completes once a TOTP code activates MFA — no full session before then).
  Re-enrolling while MFA is active now requires the current password, so a session
  alone cannot strip the second factor.
- **OIDC (§5):** the login flow is bound to the initiating browser via an HttpOnly
  cookie whose hash is stored on `oidc_login_flows.browser_binding` (migration
  0008), defeating login-CSRF/session-fixation; and when group→role mapping is
  configured, the role is re-applied on every login so an IdP admin-group removal
  downgrades the account here too.
- **Secrets/logging (§6):** the log-redaction filter now masks quoted multi-word
  secret values, covers exception tracebacks, and is attached to uvicorn's
  non-propagating loggers; uvicorn runs with `--proxy-headers` so the auth rate
  limiter and audit log see the real client IP behind Caddy; the Discord webhook
  URL (which embeds its token) is stored field-encrypted and masked on read; the
  Matrix access token moves from a URL query parameter to an Authorization header;
  a malformed secret token now raises `SecretDecryptError` instead of leaking a
  low-level error; and the registry-probe refuses to forward the stored credential
  to a non-HTTPS bearer realm (and no longer follows credentialed redirects).
- **Cron (§4.6):** day-of-week `7` is accepted as Sunday, `N/step` extends to the
  field maximum, and `*/step` in the day fields is treated as unrestricted for the
  Vixie OR/AND rule.
- **Hardening/hygiene (§9.1/§9.2):** the socket-proxy sidecar gains resource
  limits + a healthcheck and `trivy-server` gains a healthcheck; CI dogfood scanner
  images are digest-pinned; the `THIRD_PARTY_LICENSES` Trivy version is corrected to
  0.72.0; the Docker-environment proxy URL is constrained to http(s); scheduled-
  backup passphrases get the same minimum length as manual ones; and scanner
  subprocesses no longer inherit Scrye's `SCRYE_*` config vars.
**Intentionally deferred (documented, not fixed):** binding each secret's AAD to
its **row** id (not just its column) — it would invalidate every existing
ciphertext and needs a key-available re-encryption migration, and the threat (DB
*write*) is outside §6's DB-*read* model; and the backup restore continues to derive
the passphrase key from the module scrypt constants rather than the envelope's
advertised parameters (a compatibility seam, not a live bug).
**Why:** Re-verifying CLAUDE.md's hard security rules across the full, integrated
app (not per-phase) turned up these gaps; each fix keeps a locked decision intact
(single-container, field-encryption, CIS posture, no registry publishing) and ships
with tests. The MFA-enforcement UX and OIDC browser-binding are security-model
choices resolved conservatively (no user lockout; no new session concept).
**Plan section affected:** §4, §4.6, §5, §6, §9.1, §9.2, §7 (oidc_login_flows).

### 2026-07-04 — Post-P6 — Security-audit hotfix (follow-up to the merge above)
**What changed:** An independent review of the merged audit-remediation surfaced
two High and four Medium/Low defects it had introduced or left open; this hotfix
closes them (all with regression tests):
- **OIDC role sync — admin demotion/lockout (§5, High):** `_synced_role` now
  distinguishes "groups claim absent from this token" (common — many IdPs deliver
  groups via UserInfo or a specific scope, not the default ID token) from "user
  not in the admin group". An absent claim **preserves** the user's current role
  instead of resetting it to `default_role`, and a new last-admin guard refuses to
  demote the final active admin via OIDC sync. Provisioning of *new* users keeps
  the conservative `default_role` fallback.
- **Reverse-proxy IP trust (§9.2, High):** `docker/entrypoint.sh` no longer
  defaults `--forwarded-allow-ips` to `*` (which trusts any upstream hop and lets a
  client spoof `X-Forwarded-For`, bypassing the auth rate limiter and forging audit
  IPs). It defaults to the Docker bridge range `172.16.0.0/12`, overridable via the
  new `SCRYE_FORWARDED_ALLOW_IPS` setting (added to the `Settings` model so it is
  emitted in `.env.example`), and is documented for other topologies.
- **OIDC MFA scope (§5, Medium):** documented as an accepted limitation (OIDC
  delegates the second factor to the IdP; Scrye has no local TOTP step in the OIDC
  handshake) in code, this file, and the README security model. Not gated at this
  layer to avoid locking out OIDC accounts that have no local password.
- **OIDC binding cookie (§5, Medium):** the browser-binding cookie is now a
  `__Host-` prefixed, root-path, `Secure` cookie under TLS, so a sibling subdomain
  on the shared parent domain (`*.your-domain.tld`) cannot plant it; it falls
  back to the plain host name only over plain-HTTP dev (where `__Host-` is rejected)
  and is cleared on the binding-failure path too.
- **MFA re-enroll gate (§5, Medium):** `/auth/mfa/enroll` requires the current
  password whenever a secret already exists — **including the pending, not-yet-
  activated window**, not just active MFA — closing the gap where a session-only
  attacker could overwrite a pending secret. The password is skipped only for a
  genuine first enrollment with no prior secret.
- **Registry probe scheme (§4.5, Low):** `check_registry` refuses to send the
  stored credential to an `http://` host (fails closed before any request),
  consistent with the Docker-environment proxy-URL validator.
**Why:** #1 and #2 were exploitable on a running instance (silent admin lockout;
rate-limit/audit spoofing), so they are shipped as a hotfix rather than folded into
a later phase. Every fix preserves the locked decisions (single-container, field
encryption, CIS posture) and adds no new schema or session concept.
**Plan section affected:** §4.5, §5, §9.2, §11 (`SCRYE_FORWARDED_ALLOW_IPS`).

### 2026-07-04 — Post-P6 — Scanner/report review fixes: diff identity and dashboard grouping revised
**What changed:** A code review of the scanner, report, and dashboard backend
revised two previously logged decisions and hardened the parsers:
- **Diff finding identity (supersedes the Phase P4 "Export scope semantics and
  diff constraints" entry in part):** the identity key drops the location only
  for **vulnerability** findings that carry a vuln id. Trivy sets `vuln_id`
  for misconfigurations, secrets, and licenses too (the check/rule ID or
  license name), and one rule commonly fires in many files — the old
  "no location whenever vuln_id is set" rule collapsed those distinct per-file
  occurrences into a single diff key. The diff endpoint additionally requires
  both scans to share the same **target type** (not just scanner + target
  string), since the same string can name unrelated things across types.
- **Dashboard "open" posture (supersedes the Phase P6 "Dashboard open posture"
  entry in part):** the latest-succeeded-scan grouping is now per
  `(scanner, target_type, target)` for the same reason; `target_type` is
  included in the top-vulnerable-targets payload.
- **Parser hardening (§4):** shared `load_json_output` / `check_success` /
  shape-guard helpers in `scanners/base.py` make valid-JSON-of-the-wrong-shape
  scanner output fail as a diagnosable `ScannerOutputError` (instead of an
  unguarded `AttributeError`), and the worker now persists the raw output as
  the scan's artifact even when parsing fails. Grype's string-typed
  `urls`/`fix.versions` are rejected instead of producing garbage, its
  `fix.state: wont-fix` is surfaced in `fixed_version`, and Trivy scans now
  record the engine version via a best-effort `trivy --version` probe (the
  Trivy report JSON carries no engine version, unlike Grype's descriptor).
- **Exports/dashboard hygiene:** Markdown exports escape the report heading,
  initiator, tags, and history filter values and flatten `\r`; history-CSV
  severity columns derive from the shared enum; the scanner-DB freshness probes
  are TTL-cached and the dashboard's synchronous DB aggregation runs off the
  event loop; export/diff queries eager-load tags and stop fetching unused
  finding descriptions.
**Why:** Review findings on `backend/app/scanners/`, `backend/app/reports/`,
and `backend/app/api/dashboard.py`: the old diff key silently under/over-
reported change for non-vulnerability classes, target identity ignored the
target type, and malformed-but-valid scanner JSON crashed undiagnosably with
no raw artifact stored. All fixes ship with regression tests.
**Known limitation (future improvement):** two SBOM uploads with an identical
filename *and* target type still collapse into one target identity, since the
filename is all the identity the scan row carries. A real fix would key SBOM
targets on a content hash (e.g. the SHA-256 of the uploaded SBOM, already
computed for its artifact) rather than the filename.
**Plan section affected:** §4.3/§4.4 (diff identity/constraints), §4.6
(dashboard grouping), §4 (scanner orchestration/parsing).

### 2026-07-04 — Phase 6 — Docker Hub publishing (tagged releases + dev continuous build)
**What changed:** Locked decision §0.6 is expanded again. The image is now
published to Docker Hub as `<dockerhub-user>/scrye` through a new
`.github/workflows/publish.yml`, separate from `ci.yml`, via two independent
triggers:
- **Tagged main releases** (`on: push: tags: v*.*.*`) build the multi-arch
  (amd64/arm64) image and push `<dockerhub-user>/scrye:<version>` (the tag minus
  its leading `v`) **and** `<dockerhub-user>/scrye:latest`. The release job first
  fetches `main` and fails unless the tagged commit is an ancestor of `main`'s
  tip, so `:<version>`/`:latest` can only ever come from a real release cut from
  `main`.
- **dev continuous build** (`on: pull_request: types: [closed]` with base `dev`,
  gated on `github.event.pull_request.merged == true`) builds the multi-arch
  image and pushes the single **moving** tag `<dockerhub-user>/scrye:dev`, always
  overwritten — not a version, not `latest`. It fires **only when a PR is merged
  into `dev`** — not on every push touching the `dev` ref (e.g. conflict-
  resolution commits on an open PR) and not on PRs closed without merging — and
  builds the merged commit (`merge_commit_sha`). It exists only to test the
  current state of `dev` without cutting a release.
The multi-arch build invocation (QEMU + Buildx + `docker/build-push-action`
against `docker/Dockerfile`) was extracted into a reusable composite action at
`.github/actions/build-image`, and `ci.yml`'s `image-multiarch` build-check was
refactored to consume it, so the build is defined in exactly one place and not
duplicated between CI and publishing. Credentials come from the pre-configured
`DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` repo secrets; `ci.yml` still never
publishes. `CONTRIBUTING.md` gains a "Releasing" section documenting both paths.
Separately, `ci.yml`'s `image-multiarch` build-check is now **gated to main
pushes and PRs whose base is `main`** (`if: github.event_name != 'pull_request'
|| github.event.pull_request.base.ref == 'main'`). Its arm64 leg builds the
whole Dockerfile under QEMU emulation, which on a cold `type=gha` cache takes
multiple hours; only main-scoped runs reliably restore a warm arm64 cache, so
`dev`-based PRs would rebuild from scratch every time. Multi-arch buildability
stays continuously proven for `dev` by `publish.yml` (which builds amd64+arm64
on each PR merged into `dev` and on release tags), and `dev` PRs still run the
fast amd64-only image build + dogfood self-scan, so no coverage is lost.
**Trigger correction (same session):** the `:dev` path was first written as
`on: push: branches: dev`, which fired on *any* commit reaching the `dev` ref —
including conflict-resolution pushes to an open, unmerged promotion PR. It was
re-scoped to `on: pull_request: types: [closed]` (base `dev`) gated on
`pull_request.merged == true`, so `:dev` now publishes strictly when a PR is
merged into `dev`.
**Why:** Explicit user instruction this session, superseding the earlier
"local-build-only / publish-on-tagged-releases-only" state of §0.6 to add the
`dev` continuous-build path for testing dev without a release, then re-scoping
that path from push-based to merged-PR-based per follow-up instruction.
**Plan section affected:** §0.6 (distribution), §9.1 (image), §13 (moved out of
deferred).

### 2026-07-04 — Process — Adopted a dev/main branching model ahead of going public
**What changed:** Introduced a `dev` integration branch (cut from `main`). `main` is now treated
as protected and receives only tagged releases; day-to-day feature/fix branches and external
contributions branch from `dev` and PR into `dev` by default instead of `main`. Promotion from
`dev` to `main` is a separate, explicitly-requested PR made when cutting a release, followed by
tagging `main`. `CLAUDE.md` § Git & PR conventions and `CONTRIBUTING.md` (new § Branching model,
updated § Releasing and PR process) were updated accordingly; all other rules (git identity, no
attribution footers, CI-green, deviations logging) are unchanged, just applied against `dev` as
the usual PR target. GitHub branch protection on `main` is configured separately outside of this
repo's docs.
**Why:** Scrye is moving toward accepting public/external contributions. A protected `main` with
tagged releases, plus a `dev` integration branch for ongoing work, is the standard model for
letting contributors work freely without risking the release branch.
**Plan section affected:** § Git & PR conventions (CLAUDE.md), process only — no build-phase or
architectural sections affected.

### 2026-07-05 — Post-P6 audit remediation (P0) — token-mint capping, backup/restore, webhook URLs
**What changed:** First tier (P0) of the full-repo audit (`full-audit-2026-07-05.md`,
§10). Fixes carry their audit finding IDs:
- **QUA-1 (§5, privilege escalation):** `POST /api/api-tokens` capped minting against the owner's
  account role instead of the caller's effective (token-capped) role, so a low-privilege token
  belonging to an admin could mint an admin token. Now caps and defaults against
  `AuthContext.effective_role`; a regression test constructs a viewer token owned by an admin and
  confirms it cannot mint (or default to) an admin token.
- **API-2 (§8):** database restore (scrypt + full-DB rebuild) now runs in a threadpool
  (`run_in_threadpool`) so `/healthz` and the container healthcheck stay responsive and can't kill
  the container mid-restore.
- **API-3 (§8):** restore inserts rows with a chunked `executemany` instead of one statement per
  row; build streams rows with `yield_per` and no longer re-parses the finished bundle to read the
  app version; a warning is logged for very large findings tables and the practical size ceiling is
  documented in the README. (A framed streaming-encryption format is deferred — GCM is single-shot.)
- **API-10 (§8):** raw-artifact files are not carried in a bundle (plan §8 lists them as
  *optional*), so the `artifacts` table is now excluded from the dump **and** cleared on restore —
  a restored database no longer holds artifact rows that point at nonexistent files. Documented in
  the README ("Backup & restore").
- **API-11 (§8):** restore is refused with 409 while any scan is queued or running, so the table
  wipe can't race the worker committing findings against a replaced/vanished scan row.
- **SEC-1 (§4.5/§6):** a generic webhook's URL is treated as a write-only credential (Slack/Teams/
  Mattermost/Google Chat embed the token in the URL), stored field-encrypted in `secret_ciphertext`
  and masked on read exactly like the existing Discord handling — not echoed from the plaintext
  `config` column. The previously-separate optional bearer-token secret for generic webhooks is
  subsumed (the URL is the credential); the frontend renders the webhook URL as a write-only
  password field and no longer offers a separate secret input for webhook/Discord channels.
**Why:** These are the audit's P0 (correctness/security/data-loss) items. Each keeps the locked
decisions intact (no schema change, field encryption, single-container worker). SEC-1 follows the
audit's recommended fix (route the URL into `secret_ciphertext`, mask on read) rather than adding a
new encrypted column, avoiding a data-model change.
**Plan section affected:** §5 (RBAC/API tokens), §6 (secrets/webhook URL), §8 (backup/restore).

### 2026-07-05 — Post-P6 audit remediation (P1) — availability/performance under real volume
**What changed:** Second tier (P1) of the audit (§10). Carries the finding IDs:
- **API-5 (§4/§12):** the scan worker's result persistence (`_persist_success` /
  `_store_failure_output` — a 10k+-findings flush plus the raw-JSON artifact write) now runs via
  `anyio.to_thread.run_sync` instead of inline on the event loop; the module docstring is corrected.
- **SCN-1 (§4):** `run_command` streams a subprocess's stdout with a byte cap
  (`SCRYE_SCANNER_MAX_OUTPUT_BYTES`, default 512 MiB) — output past the budget kills the child and
  fails the scan as a `ScannerOutputError` (with the truncated bytes for diagnosis) rather than
  buffering unbounded JSON; stderr is capped modestly. New setting is emitted in `.env.example`.
- **API-4 (§4/§8):** SBOM and backup-restore uploads are read through `read_upload_capped`, which
  rejects an over-limit body via its reported size and by a chunked read, so an oversized upload is
  never fully materialized in memory before the size check.
- **API-7 (§4.6):** dashboard/metrics aggregation loads only the columns it reads per target
  (`load_only`, skipping the heavy `options`/`error` columns) and is served from a short (15 s)
  process-wide TTL cache shared by the dashboard endpoint and every Prometheus scrape, cleared on
  app startup (and in tests).
- **API-1 (§4.4):** the `GET /scans` and `GET /scans/history` list endpoints eager-load
  `Scan.tag_rows` (`selectinload`), removing the per-row N+1 tag query.
- **API-15 / API-6 (§12):** the maintenance tick runs `fire_due_schedules` and `run_retention` off
  the event loop (`anyio.to_thread.run_sync`), and retention deletes artifact rows in a single
  `DELETE … WHERE id IN (…)` instead of one ORM delete per row.
**Why:** The audit's P1 (availability/performance at real data volume) items — the systemic
"synchronous heavy work on the event loop" pattern (API-2/3/5, plus retention/maintenance) is
addressed consistently by hopping to a thread, and the unbounded-memory paths (scanner stdout,
uploads, dashboard hydration) are bounded. No schema change; the one new setting is non-sensitive.
**Plan section affected:** §4 (scanner orchestration), §4.4/§4.6 (list/dashboard perf), §8
(uploads), §12 (maintenance), §11 (`SCRYE_SCANNER_MAX_OUTPUT_BYTES`).

### 2026-07-05 — Post-P6 audit remediation (P2) — supply chain / deployment hardening
**What changed:** Third tier (P2) of the audit (§10). Finding IDs:
- **SCN-3 (§4.2):** `cors_origins` and `filesystem_scan_roots` now parse their documented
  comma-separated env form. pydantic-settings tries `json.loads` on a `list[str]` env value, so
  `SCRYE_FILESYSTEM_SCAN_ROOTS=/srv/scan` (the enable switch for the security-gated filesystem-scan
  feature) failed at startup; the fields are annotated `NoDecode` with a `field_validator(mode=
  "before")` that splits on commas. Tests construct `Settings` from the env var directly.
- **INF-1 (supply chain):** added `.github/dependabot.yml` (weekly, grouped) for the
  `github-actions` ecosystem so the workflow actions are tracked and rolled forward deliberately.
  **The remaining half — pinning each `uses:` to a full commit SHA — could not be completed in the
  remediation environment (its egress policy blocks GitHub outside this repo, so current action
  SHAs cannot be resolved/verified); pinning to an unverified SHA would risk a red CI. Flagged for a
  follow-up where SHAs can be resolved.**
- **INF-3 (§0.6):** `CLAUDE.md` §6's `:dev` wording is corrected to match the implemented
  merged-PR-into-`dev` trigger (it still said "every push to dev"), removing the doc-vs-code
  contradiction — a documentation alignment, **not** a behavior change.
- **INF-2 (§0.6, deferred — revisit before the repo goes public):** the fork-PR `:dev` publish gap
  (fork PRs get no repo secrets, so their merge can't push `:dev`) is documented in `publish.yml`
  as an accepted trade-off of the deliberate merged-PR trigger. Switching to a push-based trigger
  would fix it but reverses a distribution locked decision (§6) and reintroduces the double-publish
  the re-scope avoided. **The merged-PR-only trigger is kept as-is for now** (user decision,
  2026-07-05): while the repository is **private**, external fork-based contributions are not
  possible, so the bug cannot actually be triggered. **This must be revisited specifically before
  the repo is made public** — going public is exactly what enables fork PRs (and therefore the
  broken `:dev` publish), so the trigger decision (keep merged-PR-only with a documented caveat, or
  move to a push-based / `workflow_run` trigger with secrets) should be made deliberately at that
  point. INF-3's `CLAUDE.md` §6 wording is intentionally left matching the current merged-PR
  trigger. **[RESOLVED 2026-07-06:** dev publishing was moved off the merged-PR trigger to a
  nightly GHCR build authenticated with the built-in `GITHUB_TOKEN`, so the fork-withheld-secrets
  path no longer exists. See the 2026-07-06 deviation entry above.**]**
- **INF-4 (§9.2, documented exception):** the optional `trivy-server` sidecar runs as root; the
  upstream `aquasec/trivy` image ships no non-root USER and hard-codes its `/root/.cache`, so a
  non-root `user:` would break the DB cache on a root-owned named volume. Documented the residual
  risk and its mitigations (profile-gated, internal-net-only, read-only FS, no-new-privileges,
  cap_drop ALL, resource-limited) in the compose file, per the audit's accepted alternative.
- **INF-5 (§9.2):** added a small RAM-backed `tmpfs:[/run]` to the `docker-socket-proxy` sidecar
  (HAProxy needs a writable `/run` under a read-only root FS) with a note to live-verify the profile
  and add `cap_add:[SETUID,SETGID]` only if the proxy still cannot drop privileges.
**Why:** The audit's P2 (supply chain / deployment hardening). SCN-3 is a real startup bug on the
documented config path and ships with tests. The infra items that can be fully verified here are
applied; those requiring a live Docker daemon (INF-4/5) or GitHub egress (INF-1 SHA resolution) or a
locked-decision change (INF-2) are applied conservatively (defensive change + documentation) and
their residual scope is called out rather than shipped unverified.
**Plan section affected:** §0.6 (distribution docs), §4.2 (config parsing), §9.2 (compose
hardening), §11 (CI supply chain).

### 2026-07-05 — Post-P6 audit remediation (P3) — feature gaps that mislead users
**What changed:** Fourth tier (P3) of the audit (§10). Finding IDs:
- **FEAT-6 / QUA-3 (§4.5):** the stored **Grype ignore** config is now applied at scan time. A new
  `scanners/grype_policy.py` materializes the `ScannerSettings.grype_ignore` YAML into tmpfs and the
  worker hands it to Grype via a `-c <path>` config flag (mirroring the Trivy-policy materialization),
  carried on a private env-overlay key that the Grype runner converts to argv and never leaks to the
  child.
- **FEAT-7 / QUA-3 (§4.5):** the New Scan form now prefills its severity filter and ignore-unfixed
  toggle from the instance defaults (`GET /settings/scanners`) on mount, so changing
  `default_severities` / `default_ignore_unfixed` actually affects new scans instead of being
  overridden by hardcoded form values.
- **FEAT-4 / QUA-3 (§4.5):** the maintenance tick now honors `auto_update_db` +
  `db_update_interval_hours` — a new `workers/db_update.py` runs `trivy image --download-db-only` and
  `grype db update` best-effort when enabled and the interval has elapsed (in-process last-run marker;
  a restart re-checks). Failures are logged, never raised. This removes the "stored no-op" knobs
  (QUA-3): all three ScannerSettings fields the UI exposed now have real effect.
- **DOC-1 (§0.6):** README rewritten to reflect that Docker Hub publishing (`<dockerhub-user>/scrye`,
  `:latest`/`:<version>`/`:dev`) is in scope; the "no published registry image" claims are removed.
- **DOC-2 / DOC-5 / FEAT-1/2/3/8:** README wording aligned with reality — uploaded image-tar targets,
  Docker-environment multi-select scan launch, and filesystem-archive upload are marked not-yet-
  implemented; VEX/`.trivyignore` are described as global (Settings → Scanners), not per-scan; and the
  ECR/GCR/ACR credential-helper "binaries not bundled" caveat is stated.
- **FEAT-5 / FEAT-10:** offline/air-gapped DB import and an admin bulk secret re-encryption
  (key-rotation) action are explicitly listed as not-yet-implemented on the roadmap, and the README
  key-rotation note is corrected to stop implying a re-encryption tool exists.
**Why:** The audit's P3 ("feature gaps that mislead users"). The three dead Settings→Scanners knobs are
wired so the UI no longer lies; the remaining unimplemented features (image-tar upload, Docker-env
multi-select, filesystem-archive upload, offline DB import, key-rotation re-encryption) are explicitly
de-scoped in the docs per the audit's accepted alternative rather than built out in this tier.
**Plan section affected:** §4.5 (scanner settings actuation), §10.1 (README accuracy), §4.1/§4.2
(target/feature scope).

### 2026-07-05 — Post-P6 audit remediation (P4) — frontend correctness / UX
**What changed:** Fifth tier (P4) of the audit (§10). Finding IDs:
- **FE-1:** the API client dispatches a `scrye:auth-invalidated` window event on any 401; `AuthContext`
  listens and flips `user` to null, so a dead/revoked session drops the SPA back to the login screen
  instead of leaving a stale authenticated shell whose every action fails.
- **FE-3:** a shared `lib/dates.ts` (`parseUtc` / `formatWhen`) is the single place that renders a
  backend (naive-UTC) timestamp; the pages that rendered UTC as local (Account sessions, Backups
  list + schedule last-run, Scheduled-scans last-run) now use it, and the two pages that already had
  a private `formatWhen` (ScanDetail, Scans) were de-duplicated onto the shared helper.
- **FE-4:** `BackupsPanel`'s restore file moves from `useRef` to `useState`, so the selected file
  name actually re-renders on the destructive restore flow instead of showing "No file selected".
- **FE-5:** `ScheduledScansPanel` constrains the scanner Select by target type via a `SCANNERS_FOR`
  matrix (and auto-corrects the scanner when the target type changes), mirroring the New Scan page and
  the backend's combo validation; it also gates Add/Run/Delete behind an operator-or-admin check
  (`useAuth`), and `/settings` is now a **guarded route** (viewers hitting the URL are redirected to
  `/`, not just missing the nav link).
**Why:** The audit's P4 (frontend correctness/UX). All are client-only; the backend already enforces
the same RBAC/validation, so these close UX gaps (stale shells, wrong times, silent destructive-flow
labels, invalid-combo 400s, viewer-visible controls) rather than security holes. No dedicated frontend
test runner exists yet (FE-10, deferred to P5); changes are verified by `tsc`, ESLint, Prettier, and a
clean `vite build`.
**Plan section affected:** §5 (RBAC surfacing in the UI), §4.4/§4.6 (history/schedules UX), §10 (SPA).

### 2026-07-05 — Deviation-logging debt from the audit (FE-2, INF-10, API-12, FEAT-4)
The audit (§10) flagged four divergences from this plan that had never been recorded here. Logging
them now (independently of whether the underlying item is also fixed), per CLAUDE.md § Git & PR
conventions, which requires a dated entry at the time a deviation is made:
- **FE-2 — hand-rolled API client (§2).** The frontend API layer is a thin hand-written `fetch`
  wrapper (`frontend/src/api/*`), not a client generated from the FastAPI OpenAPI schema as
  § Coding standards specifies. This was a deliberate simplicity choice (one small `api()` helper +
  typed per-endpoint modules) and is **kept**; generating the client (e.g. openapi-typescript) over
  the thin wrapper remains a possible future improvement. Recorded here as the required deviation.
- **INF-10 — dogfood gate severity floor (§9.1 / CLAUDE.md § Dependency hygiene).** CI gates the
  Trivy/Grype self-scan on **fixable HIGH/CRITICAL** only (`ci.yml`), while § Dependency hygiene says
  "resolves all fixable findings". Fixable LOW/MEDIUM appear in the informational (non-gating) steps.
  The HIGH/CRITICAL floor is an intentional low-churn enforcement choice; recorded here as the
  deviation (the bundled-binary skip was already logged, this floor was not).
- **API-12 — scans composite index column (§7).** §7 promised `scans(scanner, status, started_at)`;
  the implemented composite index uses `created_at` (`db/models/scan.py`, migration `0003`). The
  implemented index is the more useful one for the newest-first/history queries (which order by
  `created_at`); only the deviation-logging was missing. Recorded here; no code change.
- **FEAT-4 — DB-update schedule actuation (§4.5).** Phase 5 stored the `auto_update_db` /
  `db_update_interval_hours` knobs and deferred actuation to Phase 6; Phase 6 shipped without it and
  never logged the drop. (Now actually **implemented** in the P3 entry above — the maintenance tick
  runs the DB updates — but the earlier un-logged gap is recorded here for the trail.)

### 2026-07-05 — Post-P6 audit remediation (P5) — maintainability, process, long tail
**What changed:** Sixth tier (P5) of the audit (§10). Finding IDs:
- **item (g) (§8):** backup restore now derives the passphrase key from the **bundle's advertised**
  scrypt parameters (`kdf.n/r/p`) instead of the module constants, so a bundle written under a
  different (e.g. older) work factor still restores. `derive_key` / `passphrase_cipher` take explicit
  `n/r/p` (defaulting to the current constants for new backups) and validate them; `restore_bundle`
  passes the recorded values. (Verified in the remediation environment there are **no** existing
  bundles that predate the 2^15→2^17 bump — `/data` is absent and no `.scryebak` files exist — so
  nothing was already unrestorable; this fix is forward-looking.)
- **QUA-23 (§7):** a new `tests/test_migrations.py` runs the **actual Alembic chain** to head against
  a throwaway database and asserts the resulting tables/columns match `Base.metadata`, catching a
  migration that drifts from the models (the rest of the suite builds the schema via `create_all`).
  `alembic/env.py` now respects a caller-provided `sqlalchemy.url` so the test can target its own DB.
**Intentionally deferred (recorded, not done) in P5:**
- **QUA-4 / QUA-9 (structural):** consolidating the four near-identical secret-CRUD routers and
  standardizing the list-envelope convention is a broad refactor across many endpoints; deferred to a
  dedicated change to keep this remediation batch reviewable and low-risk.
- **QUA-16 (type checker in CI):** adding mypy/pyright would first require resolving the existing
  annotation gaps the audit notes (QUA-17), which is a separate cleanup; deferred rather than shipped
  with a red gate.
- **FE-10 (frontend tests):** a frontend test runner is still absent; adding vitest + unit tests is a
  worthwhile follow-up. Deferred here to keep P5 scoped; the new `lib/dates.ts` helper is a natural
  first target.
**Why:** The audit's P5 (maintainability/process/long tail). The two concrete, self-contained,
fully-verifiable items (item (g), QUA-23) are implemented with tests; the larger refactors and the
type-checker/frontend-test additions are explicitly deferred with rationale rather than half-done.
**Plan section affected:** §7 (migration integrity), §8 (backup KDF portability), process.

### 2026-07-09 — Infra/Process — repo goes public; distribution consolidated to GHCR-only
**What changed:** The repository is being made **public**, and image distribution is consolidated
from two registries to **GHCR only**. Concretely:
- **Docker Hub removed entirely.** `.github/workflows/publish.yml` no longer pushes to
  `<dockerhub-user>/scrye` and no longer references the `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN`
  secrets. Those secrets are now unused by any workflow and can be deleted from the repo settings.
- **Releases publish to GHCR.** `publish.yml` (still `on: push: tags: v*.*.*`, still gated on the
  tagged commit being on `main`) now authenticates to GHCR with the built-in `GITHUB_TOKEN`
  (`permissions: packages: write`) and pushes `ghcr.io/tyler-rich/scrye:<version>` **and**
  `ghcr.io/tyler-rich/scrye:latest`. A `github.repository == 'tyler-rich/Scrye'` guard was added so
  a fork that pushes a tag just skips rather than failing. The nightly `:dev` build
  (`dev-nightly.yml`) was already GHCR/`GITHUB_TOKEN` and is unchanged except for comments; all
  three release/nightly/CI workflows and the composite build action had their Docker-Hub-era
  comments corrected.
- **INF-2 fully retired.** The fork-PR `:dev` secrets gap was previously "resolved" only by the
  nightly schedule trigger while the repo stayed private (2026-07-06 entry). With the repo going
  public — which is what makes fork PRs real — the fix is now complete and confirmed: **both**
  publish paths (release tag push, nightly schedule) are triggered outside `pull_request` and use
  `GITHUB_TOKEN`, so no `pull_request`-triggered workflow carries a registry secret. `ci.yml` runs
  on fork PRs but uses no secrets and never publishes (build/scan only, `load: true`). There is no
  remaining fork-unsafe secret path.
- **Public-repo governance.** Added `.github/CODEOWNERS` (`* @tyler-rich`) and a `SECURITY.md`
  (private vulnerability reporting via GitHub Security advisories, supported-tags table, scope).
  The remaining pre-public items are **repository settings, not files**, and are tracked on
  `docs/ROADMAP.md`: branch protection on `main`/`dev` (require CI + PR + Code Owner review),
  signed-commit enforcement (a decision to make), and enabling private vulnerability reporting /
  Dependabot security updates.
- **Docs.** `README.md` (GHCR-only distribution, standalone pull-from-GHCR compose that needs no
  clone, categorized env-var necessity, nginx/Caddy/Traefik proxy examples, clearer sidecar
  necessity, GHCR/CI badges), `CONTRIBUTING.md` (§ Releasing → GHCR), `docs/ROADMAP.md` (public-repo
  reality — free arm64 runners, governance checklist), and `CLAUDE.md` (locked decision §6 rewritten
  GHCR-only) were updated to match.
**Why:** Explicit user instruction this session, superseding the two-registry split locked in the
2026-07-06 entry. Going public makes fork-based contributions real, so the INF-2 caveat had to be
closed rather than deferred; using `GITHUB_TOKEN`→GHCR for releases too (rather than a long-lived
Docker Hub PAT) is also the safer posture for a public repo (no exfiltratable registry secret). The
locked decision `CLAUDE.md` §6 is updated accordingly.
**Plan section affected:** §0.6 (distribution — now GHCR-only), §9.1 (image publishing),
CLAUDE.md § Locked decisions §6. Supersedes the Docker Hub role in the 2026-07-06 entry; completes
and closes INF-2 (2026-07-05 P2 / 2026-07-06 entries).


### 2026-07-09 — Post-v1 — teal hue refinement, scan deletion, nav active-match fix
**What changed:** Three small frontend/backend changes:
- **Theme hue.** `frontend/src/theme.ts` now defines a custom `teal` ramp (the Tailwind teal
  scale) instead of relying on Mantine's built-in teal, whose mid-tones read as a bright mint.
  The primary lands on teal-700 (`#0f766e`) in light mode and teal-600 (`#0d9488`) in dark mode
  (`primaryShade: { light: 7, dark: 6 }`), with `autoContrast: true` + `luminanceThreshold: 0.2`
  so filled controls pick the higher-contrast label per mode. All primary usages clear WCAG AA:
  light filled/text 5.47:1, dark filled 5.61:1 (black label), dark text 4.60:1. This keeps locked
  decision §7 (teal primary, first-class light/dark) — only the exact shade changed.
- **Delete completed scans.** New `DELETE /api/scans/{id}` (operator role + CSRF, terminal-status
  only) removes the scan and cascades to its findings, artifact-metadata rows, and tags via the
  existing ORM `cascade="all, delete-orphan"` + `ON DELETE CASCADE` FKs; the on-disk artifact
  directory is removed via a new `remove_scan_artifacts()` helper. No schema change was needed
  (the cascade was already declared), so **no Alembic migration**. A confirmation modal + Delete
  button was added to the scan detail page. A deleted scan stops feeding the dashboard aggregates
  (they query the live tables) and drops out of history/diffs.
- **Nav active-state fix.** `frontend/src/App.tsx` used `pathname.startsWith(to)`, which lit both
  "Scans" and "New scan" on `/scans/new`. Now the active item is the *longest* matching nav path
  (matching `to` exactly or as a `to/` prefix), so each item highlights only for its own route;
  Dashboard (`/`) stays exact-match.
**Why:** User-requested polish: the teal read as mint, there was no way to delete a scan, and the
nav double-highlighted on the new-scan page.
**Plan section affected:** §7 (theme, hue only), §5 (RBAC — new destructive action), §4.6
(dashboard aggregates), frontend nav.

### 2026-07-09 — Post-v1 — v0.1.0 bundled-binary CVE check: no upstream fix available yet
**What changed:** Nothing in the image — a version-bump-if-available check across all severities
that concluded **no bump is applicable**, logged here per the "Bundled scanner binaries track
upstream for CVEs" limitation (README § Integrations; ROADMAP § Known limitations). A Docker Scout
scan of the published `ghcr.io/tyler-rich/scrye:0.1.0` image (`--only-fixed`, no severity filter)
surfaced ten distinct CVEs, **all** inside the bundled upstream scanner binaries
(`/usr/local/bin/{trivy,grype,syft}`) — none in Scrye's own base image, OS packages, Python/JS
deps, or application code (those stay fully gated by the CI dogfood). Grouped by the embedded
module and the upstream version that fixes each:

- **Go standard library** (grype + syft, built against `stdlib@1.26.3`):
  - CVE-2026-42504 (HIGH) — `net/textproto` MIME-header CPU exhaustion — fixed in Go **1.26.4**.
  - CVE-2026-42507 (MEDIUM) — `net/textproto` error-message injection — fixed in Go **1.26.4**.
  - CVE-2026-39822 (LOW) — `os.Root` symlink escape — fixed in Go **1.26.5**.
  - CVE-2026-42505 (LOW) — ECH pre-shared-key identity disclosure — fixed in Go **1.26.5**.
- **oras.land/oras-go/v2** (trivy, embeds `2.6.0`):
  - CVE-2026-50151 (HIGH) — SSRF / credential-forwarding via blob-upload `Location` header — fixed
    in oras-go **2.6.1**.
  - GHSA-vh4v-2xq2-g5cg (MEDIUM) — related oras-go issue — fixed in oras-go **2.6.1**.
  - CVE-2026-48978 (LOW) — SSRF / cleartext transmission via unvalidated bearer-challenge realm —
    fixed in oras-go **2.6.1**.
- **github.com/docker/docker (moby)** (grype, embeds `28.5.2+incompatible`):
  - CVE-2026-34040 (HIGH) — AuthZ-plugin bypass (incomplete fix for CVE-2024-41110) — fixed in
    moby **29.3.1**.
- **github.com/sigstore/timestamp-authority/v2** (trivy signing/attestation path, embeds `2.0.6`):
  - CVE-2026-49835 (MEDIUM) — unbounded memory growth via unauthenticated metrics-label injection
    — fixed in timestamp-authority **2.1.0**.

Per binary, the currently-pinned versions **are already the latest available upstream releases**
as of this date (verified against each project's release feed):

- **Trivy** — pinned `0.72.0` (released 2026-06-30); latest upstream is `0.72.0`. No newer release
  exists, so nothing rebuilds `oras-go` past `2.6.0` or `timestamp-authority` past `2.0.6`. **All
  four Trivy-side CVEs remain unresolved at latest.**
- **Grype** — pinned `0.115.0` (released 2026-06-26); latest upstream is `0.115.0`. Still built on
  Go `1.26.3` and moby `28.5.2`. **All Grype-side CVEs (the four Go-stdlib items shared with Syft,
  plus moby CVE-2026-34040) remain unresolved at latest.**
- **Syft** — pinned `1.46.0` (released 2026-06-26); latest upstream is `1.46.0`. Still built on Go
  `1.26.3`. **The four Go-stdlib CVEs remain unresolved at latest.**

Because the Scout scan found these CVEs *in the v0.1.0 image itself* — which was built with exactly
these pinned versions — the latest upstream releases by definition do not yet resolve any of them.
The relevant fixed dependencies are recent (Go `1.26.4` early June 2026, Go `1.26.5` on 2026-07-07
— two days before this check, oras-go `2.6.1`, moby `29.3.1`, timestamp-authority `2.1.0`), and
Aqua/Anchore have not yet cut a scanner release rebuilt against them. This is exactly the
"genuinely unfixable-by-us upstream item" carve-out (CLAUDE.md § Dependency hygiene): the fix path
is a scanner-version bump once upstream ships one, not a Scrye-side patch — no vendoring, no
binary workarounds. The three `*_VERSION` pins in `docker/Dockerfile` are therefore left unchanged,
and each is re-confirmed as the current latest so this is a tracked treadmill item, not a stale
pin. When Aqua/Anchore publish a release built against the patched deps, the fix is the usual
one-line `ARG` bump (the Dockerfile self-verifies each new asset against the publisher's signed
`checksums.txt`) plus a fresh Scout/Grype scan confirming the specific CVE IDs are gone.

Because no binary version changed and the image is byte-for-byte unaffected, this is **not** a new
release: Scrye's app version stays `0.1.0` (`backend/app/__init__.py`, `backend/pyproject.toml`,
`frontend/package.json`, `/healthz`), and no `## [0.1.1]` CHANGELOG entry is warranted — a version
bump and changelog entry are gated on an actual binary bump shipping, which did not happen here.
The next scanner-version bump that does resolve one or more of these CVEs is what cuts `0.1.1`.
**Why:** CLAUDE.md § Dependency hygiene requires keeping bundled scanner binaries current and
resolving fixable findings; this check verified all three are already current and that the ten
findings are upstream-embedded items with no fixed release available yet, so the correct action is
to record them as tracked limitations rather than bump or patch. Documented here (not a re-push of
the immutable `0.1.0` tag) so the check is on the record and the next person sees the exact CVE →
upstream-fix-version mapping to re-test against.
**Plan section affected:** §9.1 (bundled scanner pins), CLAUDE.md § Dependency hygiene, README §
Integrations / ROADMAP § Known limitations (bundled-binary CVE tracking).

### 2026-07-13 — Infra — runtime-stage curl/libcurl explicitly version-pinned for CVE-2026-5773
**What changed:** The CI dogfood self-scan flagged `curl` / `libcurl3-gnutls` / `libcurl4`
`7.88.1-10+deb12u14` (HIGH, CVE-2026-5773, fixed in `7.88.1-10+deb12u15`) in the runtime image.
Rather than the usual "apt packages are unpinned, tracking the digest-pinned base image" pattern
(§9.1, the Phase 3 git-package note), `docker/Dockerfile`'s runtime-stage `apt-get install` now
pins these three packages to the exact fixed version `7.88.1-10+deb12u15`, since that version is
already present in the base image's frozen apt snapshot — no base-image digest bump needed.
**Why:** The fix is available at the package level without moving the base image, so a targeted
version pin is the smaller, more surgical change; it also serves as a deliberate exception to the
"apt packages track the base snapshot" convention, recorded here so a future session doesn't read
these three explicit pins as stray/accidental and "clean them up" back to unpinned. When the base
image digest is next bumped for an unrelated reason, these three pins should be reviewed — if the
new base snapshot already carries `7.88.1-10+deb12u15` or later as the default, the explicit pins
can be dropped.
**Plan section affected:** §9.1 (Dockerfile / apt packages).

### 2026-07-13 — Infra/Process — CPython interpreter CVEs on 3.13 accepted as tracked risk; 3.14 deferred
**(Superseded by the "Backend runtime bumped Python 3.13 → 3.14" entry above, 2026-07-25 — the
deferral ended, 15366/15367 are cleared, and the Group B waivers were removed.)**
**What changed:** The CI dogfood Grype self-scan flags four CPython interpreter-binary CVEs on the
runtime base image (`python:3.13-slim-bookworm`, interpreter 3.13.14 — current latest 3.13.x). Two
have fixes merged to the 3.13 maintenance branch but not yet in any released point version —
CVE-2026-15308 (HIGH, `html.parser` quadratic-complexity CPU DoS) and CVE-2026-12003 (MEDIUM,
`getpath.py` in-tree search-path fallback); two were explicitly declined for backport to the 3.13
line by upstream and are fixed only in 3.15+ — CVE-2025-15366 and CVE-2025-15367 (both MEDIUM,
`imaplib`/`poplib` command injection). Under the gate (`grype --only-fixed --fail-on high`) only
CVE-2026-15308 (HIGH) actually trips the threshold; the other three are reported-but-non-gating
Mediums. Decision: **stay on Python 3.13 for now** and accept all four as tracked risk — suppressed
in `ci/grype.yaml` with per-group review dates (Group A / 2026-15308 + 2026-12003 sooner, tied to
CPython point-release cadence; Group B / 2025-15366 + 2025-15367 later, tied to the 3.14 upgrade
horizon), each referencing tracking issue #52. The now-stale `ci/grype.yaml` note claiming 3.13's
current patch carries the interpreter fixes is corrected in the same change. The move to Python 3.14
was evaluated and **deferred to a separate, deliberately-scoped project** (handoff doc:
`python-3.14.md`), not undertaken as a reaction to this scan.
**Why:** All four are genuinely unfixable-by-us on 3.13 today — two await an unreleased 3.13.x point
release, two are permanently 3.15+-only — which is exactly the "only genuinely unfixable upstream/
OS-level items may remain, tracked" carve-out in CLAUDE.md § Dependency hygiene. Moving to 3.14 is
not a clean win: it is a hard dependency bump (pydantic ≥2.12 for a cp314 `pydantic-core` wheel,
uvicorn ≥0.38.0, an explicit `greenlet` pin for SQLAlchemy async) that still leaves
CVE-2026-15308/-12003 unresolved on 3.14, so it warrants its own scoped compatibility pass rather
than a rushed CVE-driven bump. **No CLAUDE.md amendment is required:** §2 already locks the runtime
to "Python 3.13" with no CVE caveat, so staying on 3.13 changes no standing rule (checked this
session). Resolution triggers, tracked in #52: 15366/15367 close when the 3.14 upgrade lands;
15308/12003 close on the next 3.13.x point release, pending Grype-DB recognition of the backport
(its `FIXED IN` currently reports 3.15.x only).
**Plan section affected:** §0 (#7, runtime lock — reaffirmed, not changed), §2 (tech stack —
unchanged), §9.1 (base image / dogfood self-scan), §12 (Phase 6 self-scan), CLAUDE.md
§ Dependency hygiene.

### 2026-07-20 — Post-v1 — Frontend jsdom + React Testing Library test harness
**What changed:** Added the DOM test infrastructure the frontend suite was missing so
component- and page-level render tests are possible (previously Vitest ran only in the `node`
environment, which limited coverage to the pure `src/lib/` helpers). New dev dependencies
(all exact-pinned): `jsdom@26.1.0`, `@testing-library/react@16.3.0`, `@testing-library/dom@10.4.1`,
`@testing-library/user-event@14.6.1`, `@testing-library/jest-dom@6.9.1`. Vitest now runs **two
projects** split by file extension (`frontend/vite.config.ts`): `*.test.ts` under `node` (the
existing `src/lib/` helper tests, untouched) and `*.test.tsx` under `jsdom` with a `src/test/setup.ts`
(jest-dom matchers, per-test unmount, and `matchMedia`/`ResizeObserver`/`scrollIntoView` polyfills
Mantine needs). A shared `src/test/render.tsx` wraps components in `MantineProvider` + a router and
re-exports the Testing Library surface. One smoke test (`src/pages/NewScanPage.test.tsx`) proves the
harness end-to-end — render, query, and a Retry click — against the already-shipped **P3-3**
credential-load-failure warning. `eslint.config.js` gained a small override turning off
`react-refresh/only-export-components` for test files/utilities (they're outside the Fast-Refresh
graph). CONTRIBUTING.md § Testing documents the `.test.ts`→node / `.test.tsx`→jsdom convention and
the `renderWithProviders` pattern.
**Why:** Four already-shipped fixes (P3-3, and M19/M20/M21's page-effect wiring) had only helper-level
or no tests because there was no DOM harness to render components under — see `STATUS.md`
§ "Test debt on already-shipped fixes." This lands the infrastructure and proves it works; it does
**not** backfill the M19/M20/M21/P3-3 page-level tests (that's follow-up work now unblocked). Aligns
with CLAUDE.md § Testing ("the frontend uses Vitest … expanding over time"). Test-tooling only — no
runtime dependency, schema, security-model, or job-model change.
**Plan section affected:** CLAUDE.md § Testing (frontend Vitest coverage expanding), § Coding
standards (TypeScript); `STATUS.md` § "Remaining work" test-debt section. No change to
§0/§2/§4/§7.

### 2026-07-24 — Post-v1 — Docker socket proxy migrated `tecnativa` → `wollomatic/socket-proxy` (issue #63, M23/SC-7 deferred half)
**What changed:** The `docker-env` sidecar in `docker/docker-compose.yml` — the only container in
the stack that mounts `/var/run/docker.sock` — moved from
`tecnativa/docker-socket-proxy:v0.4.2` (HAProxy on Alpine, `USER root`, coarse env-var toggles) to
`wollomatic/socket-proxy:1.12.3@sha256:74e770f5ed3cfc9ecb6350e177d2aa55873568c85bc953079834e68607dbf71b`
(a from-scratch Go binary, `USER 65534`, per-method regex request allowlisting). This completes the
half of M23/SC-7 that was deliberately deferred out of the 2026-07-13 supply-chain batch.

**Allowlist mapping — this is the point of the migration.** The backend makes exactly one request
of this proxy: `GET /images/json` (`backend/app/core/docker_proxy.py`; `list_images()` is the only
caller, and the `core/egress.py` guard in front of it is DNS-only and issues no HTTP). The previous
configuration permitted vastly more than that:

| Previously (tecnativa) | Source | Now (wollomatic) |
|---|---|---|
| `GET /containers…` — incl. `/containers/{id}/json` (**every container's env vars and command line**), `/logs`, `/top`, `/stats`, `/changes`, `/export` (**container filesystem tarball**), `/archive` (**arbitrary file read out of any container**) | `CONTAINERS=1` | **denied (403)** |
| `GET /images…` — incl. `/images/{n}/json`, `/images/{n}/history`, `/images/search`, `/images/{n}/get` (**image tarball export**) | `IMAGES=1` | **denied (403)** except the listing |
| `GET /info` | `INFO=1` | **denied (403)** |
| `GET /events`, `GET /_ping`, `GET /version` | image defaults `EVENTS`/`PING`/`VERSION`=1 | **denied (403)** |
| `GET /images/json` | `IMAGES=1` | **allowed** — the only thing allowed |
| any non-`GET` method | `POST=0` denied POST; HAProxy denied the rest | **denied (405)** |
| any source on `scrye_net` | tecnativa has no source allowlist | **only the `scrye` container** (`-allowfrom=scrye`) |

The new allowlist is the single flag `-allowGET=(/v1\.[0-9]{1,2})?/images/json`. wollomatic anchors
every pattern itself (`regexp.Compile("^"+regex+"$")`) and matches it against the URL **path** only,
and answers 405 for any method that has no `-allow*` entry — so omitting the other five method flags
is what makes the proxy read-only, replacing `POST=0`. The optional group accepts the `/v1.NN` API
version prefix a Docker CLI would send for the same endpoint; it adds no endpoint. The tecnativa
rules were **prefix** matches (`^(/v[\d\.]+)?/images`, unanchored at the end), which is why a single
`IMAGES=1`/`CONTAINERS=1` toggle opened a whole route family.

**Hardening deltas.** Dropped the `/run` tmpfs entirely — INF-5 existed only because the HAProxy
image needed a writable pid/stats path under `read_only: true`; a static Go binary needs no writable
path, so the sidecar now runs read-only with **no** tmpfs. Memory cap 128M → 64M. Healthcheck moved
off the proxied API (`wget http://localhost:2375/info`) onto the image's bundled `/healthcheck`
binary against the separate `-allowhealthcheck` listener on `127.0.0.1:55555` — which is why `/info`
no longer has to be exposed at all just to have a liveness probe. Added `-watchdoginterval=3600`
`-stoponwatchdog` so a socket broken by a Docker engine update is recovered by `restart:
unless-stopped`. `cap_drop: ALL`, `no-new-privileges`, digest pin, no host port, capped logging, and
CPU limit are unchanged.

**One operational difference operators must act on.** tecnativa ran as root in-container and could
read the socket regardless of ownership. wollomatic ships `USER 65534:65534`, and
`/var/run/docker.sock` is `root:docker` mode 0660 — so the container's **GID must be the host's
docker group**. The service is therefore `user: "65534:${DOCKER_GID:-999}"`, and the operator sets
`DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"`. The `999` default is a Debian/Ubuntu
convention, not a guarantee; a wrong GID surfaces as a socket permission error at proxy start. This
is a deployment prerequisite only — no application behavior, API contract, schema, or client code
changed, and `SCRYE_DOCKER_PROXY_URL` / port 2375 are unchanged.

**Verification.** No Docker daemon was reachable in the environment where this was prepared, and
Docker Hub's blob CDN (`production.cloudfront.docker.com`) is egress-blocked, so the published image
could not be pulled or booted. Instead the request-handling path was exercised directly: upstream's
`handlehttprequest.go` and `bindmount.go` at tag `1.12.3` were compiled **verbatim** (the module is
stdlib-only) against a minimal `internal/config` carrying upstream's `AllowList` types and
`compileRegexp` unmodified, put in front of a stub Docker API on a real unix socket, and configured
with the `-allowGET` pattern **read out of `docker-compose.yml`**. Against that: the real
`docker_proxy.list_images()` enumerated images successfully; all 11 previously-permitted sensitive
paths returned 403; HEAD/POST/PUT/DELETE/PATCH returned 405; the `/v1.NN` form and a query string
were accepted; and the stub socket's access log confirmed **only** the 4 allowed requests ever
reached it while all 16 blocked ones stopped at the proxy. `docker compose --profile docker-env
config` renders the service (regex and `DOCKER_GID` interpolation intact). **Still to do on a
Docker-capable host:** one `docker compose --profile docker-env up` to confirm the published image
boots under the full hardened option set and that `DOCKER_GID` is correct for that host.

`backend/tests/test_compose_hardening.py` gained seven regression tests that keep the allowlist tied
to the client: the `-allowGET` pattern is compiled the way upstream compiles it and checked against
the path `list_images()` is *observed* to request (not a hardcoded string), checked to reject every
previously-allowed sensitive path, and checked for method flags, source restriction, digest pin,
unprivileged uid, and the absence of a re-introduced writable `/run`. Each was verified to fail
against a deliberately widened Compose config before being committed.
**Why:** Issue #63. This is the highest-value hardening target in the stack — the one container
holding the Docker socket — and the migration turns "read access to the whole Docker API's GET
surface, from anywhere on the network" into "one image-listing endpoint, from one container."
**Plan section affected:** locked decision §0.4 is satisfied unchanged (still a read-only
socket-proxy sidecar; the app still never mounts the socket) — only the implementing image and its
allowlist mechanism changed. README § Optional sidecars, § Configuration, and § Security model
updated. No schema, job-model, API-contract, or auth change.

### 2026-07-25 — Post-v1 — List-response envelope standardized behind shared helpers (L13 / APIR-8 deferred half)
**What changed:** The broad list-envelope standardization that #61 deliberately deferred — #61 was
held to the single `entries`→`items` rename on `/api/audit` per maintainer direction, with the rest
tracked in `docs/ROADMAP.md` § Backend structural cleanup. This entry closes that deferral.

Thirteen endpoints that returned bare JSON arrays now return the shared `{total, items}` envelope:
`GET /api/registries`, `/api/git-credentials`, `/api/users`, `/api/notifications`,
`/api/scan-schedules`, `/api/api-tokens`, `/api/backups`, `/api/filter-presets`,
`/api/docker-environments`, `/api/trivy/vex-documents`, `/api/trivy/ignore-rules`,
`/api/auth/sessions`, and `/api/scans/{id}/artifacts`. They remain unpaginated, so `total` always
equals `len(items)` today.

**The rule, not a one-off call.** The split was made derivable so a future endpoint's shape doesn't
need a decision: **persisted resource collections** — rows that grow with usage, where a count is a
meaningful answer and pagination is a plausible future need — take the envelope; **fixed
enumerations and live, non-persisted data** stay bare arrays, because `total` there answers a
question nobody asks. Four endpoints are therefore deliberately *not* enveloped:
`/api/registries/options` and `/api/git-credentials/options` (id/name value lists feeding a
`<Select>`), `/api/notifications/events` (a fixed `list[str]` vocabulary), and
`/api/docker-environments/{id}/images` (live enumeration proxied off a Docker daemon; nothing
persisted). The rule and the four exceptions are documented in `CONTRIBUTING.md` § API conventions
so a later review reads them as a decision rather than as drift — the same treatment the other
deferrals got in `STATUS.md` § 2.

**Behind shared helpers, per the ROADMAP note.** New `backend/app/api/pagination.py` holds
`Page[ItemT]` and `full_page(items)`; each route declares `response_model=Page[ThingOut]` and
returns `full_page([...])` rather than hand-rolling `{"total": …, "items": …}`, so the convention is
enforced structurally. The three pre-existing envelopes were re-based onto it — `AuditPageOut`,
`ScanHistoryPage`, and `FindingsPage` are now `Page[T]` subclasses, which collapses the duplicated
field declarations while **keeping their OpenAPI component names unchanged** (a bare `Page[T]` would
have renamed them to `Page_AuditEntryOut_` etc. and churned a future generated client for no gain).
`Page`/`full_page` use PEP 695 type-parameter syntax, which `ruff`'s UP046/UP047 require on the
3.13 runtime.

**Frontend absorbed the change at the client boundary.** `apiList<T>(path)` in
`frontend/src/api/client.ts` unwraps the envelope, so the thirteen client functions keep their
`Promise<Thing[]>` signatures and **no page component or existing test changed** — the SPA's
page-level tests mock the API-client functions rather than `fetch`, so all 18 frontend test files
passed untouched. `FindingsPage`/`ScanHistoryPage` in `api/scans.ts` became aliases of a shared
`Page<T>` interface.

**`GET /api/scans` was left frozen and only deprecated.** It is the one bare array that *is*
paginated (`limit`/`offset`, no total) and so the one the envelope would materially fix, but its
shape is a documented frozen contract from Phase P4. Re-shaping it as a side effect of this cleanup
would have been exactly the kind of scope creep this cycle has avoided elsewhere; if that contract
should be revisited, it warrants its own scoped decision and its own §14 entry. It now carries
`deprecated=True` plus a description naming both the replacement (`GET /api/scans/history`) and the
reason (no total ⇒ a client cannot detect exhaustion), so a reader of the generated client sees the
why and the where-to-go rather than only a flag. `listScans` in the TS client carries the matching
`@deprecated` JSDoc. This closes APIR-8 as its own fix direction stated it, rather than substituting
a larger change for it.

**Contract note (breaking for external consumers).** The thirteen endpoints' response shape changed;
scripts driving them with an API token must read `.items`. Recorded in `CHANGELOG.md` under
Unreleased with the endpoint list and an action-required note. The SPA is unaffected.

**Tests:** new `backend/tests/test_list_envelope.py` parametrizes over every enveloped endpoint
(shape, key set, `total == len(items)`), over the bare-array exceptions (asserting they *stay*
bare), that `total` tracks rows as a collection grows, that a paginated endpoint's `total` exceeds
its page, and that `/api/scans` is still a bare array *and* carries the deprecation marker with a
description naming the replacement. ~34 existing assertions across 15 test modules were updated
mechanically to read `["items"]`. On the frontend, `client.test.tsx` covers `apiList` directly,
including one **client/server seam** case that unwraps a verbatim serialized `full_page()` payload:
the backend proves it *sends* the envelope and the page-level tests mock the client functions, so
without it nothing would catch the two halves drifting apart — both suites would stay green while
the app broke at runtime. Backend 582 passed; frontend 59 passed across 18 files; `ruff`, `black`,
ESLint, Prettier, `tsc --noEmit`, and `vite build` all clean.
**Why:** L13 / APIR-8 — three envelope conventions coexisted, which made the contract inconsistent
for API-token consumers and would have made the planned generated client inconsistent too. The
"unpaginated by design" reasoning that deferred this remains correct and is preserved: nothing here
paginates that didn't before. It argues against *paginating* these lists, not against giving them a
uniform shape.
**Plan section affected:** none structurally (no schema, security-model, job-model, or auth change).
`docs/ROADMAP.md` § Backend structural cleanup loses its list-envelope half; the four-secret-CRUD-
router consolidation remains open. `STATUS.md` moves L13 / APIR-8 out of § 2 "Deferred
by decision". `CONTRIBUTING.md` gains § API conventions; `CHANGELOG.md` records the contract change.

### 2026-07-25 — Post-v1 — Socket-proxy follow-ups: API-version bound and `DOCKER_GID` blast radius documented (docs only)
**What changed:** Two comment/doc-only follow-ups to the 2026-07-24 wollomatic migration (#63). No
behavior change — `docker/docker-compose.yml`'s `-allowGET` value, the sidecar's option set, and the
application are all byte-for-byte unchanged in effect.

**1. The allowlist's two-digit API-version bound is now discoverable.** The pattern
`(/v1\.[0-9]{1,2})?/images/json` accepts `v1.0`–`v1.99`. The Engine API is ~v1.51 today, so this is
years of headroom, but the bound is hard rather than open: at v1.100 a client sending
`/v1.100/images/json` would stop matching and image listing would fail with a **403** — which reads
as a broken allowlist, not as a version-range issue, and would cost real debugging time to trace
back to a quantifier. A comment above the flag now states the bound, the failure it produces, and
the fix (widen to `{1,3}` *and* update the matching expectation in
`backend/tests/test_compose_hardening.py`). The regex was **deliberately not widened** — the tight
pattern is the security property; only its limits needed to be written down.

**2. The wrong-`DOCKER_GID` failure mode is confirmed and documented.** The 2026-07-24 entry noted
that a wrong GID "surfaces as a socket permission error at proxy start" but never said what that
does to the *rest* of the stack — the question an operator actually has. Verified against the
Compose file rather than assumed:

- **No `depends_on` exists anywhere in `docker/docker-compose.yml`** (no service, in any profile,
  declares one). So the `scrye` container neither waits on the proxy at startup nor is torn down
  when it fails; there is no `condition: service_healthy` gate to block on.
- The proxy's `healthcheck` is consumed by **nothing but itself** — no other service reads it, so an
  unhealthy proxy cannot hold anything back.
- `restart: unless-stopped` keeps the sidecar retrying on its own; the failure stays inside that one
  container.
- The service is `profiles: ["docker-env"]`, so it is opt-in to begin with.
- App-side, `docker_proxy.list_images()` raises `DockerProxyError`, which
  `backend/app/api/docker_environments.py` maps to a **502 Bad Gateway** on that one endpoint.
  Scans, history, schedules, reports, and auth are untouched.

Net: a permission error at proxy start means **"docker-env is unavailable"**, not "Scrye is broken."
That is now a paragraph in the README's `DOCKER_GID` note (§ Configuration), so an operator reads it
where they set the variable. Nothing was changed to make this true — the configuration already had
this property; it just wasn't written down.
**Why:** Both are latent-surprise removal on the highest-risk service in the stack. Each would
otherwise be diagnosed from a symptom (a 403; a crash-looping sidecar) that points away from its
actual cause.
**Plan section affected:** none. Docs and a Compose comment only — no schema, API-contract,
security-model, job-model, or auth change, and no change to the allowlist itself.

### 2026-07-26 — Post-v1 — Socket-proxy operational behavior from a live Debian run documented (docs only)
**What changed:** The 2026-07-24 migration entry closed with "**Still to do on a Docker-capable
host:** one `docker compose --profile docker-env up` to confirm the published image boots under the
full hardened option set and that `DOCKER_GID` is correct for that host." That run has now happened,
on a real Debian host with a live Docker daemon. Everything the docs assert about the *allowlist*
held — this entry records the four **operational** behaviors the run surfaced that the docs either
got wrong or never said. Docs only: no code, Compose, CI, or configuration change, and the
`-allowGET` pattern and option set are untouched.

**Confirmed as documented (no change needed):** the digest-pinned `wollomatic/socket-proxy:1.12.3`
image boots under `user: "65534:<gid>"` with `read_only: true`, `cap_drop: ALL`, and
`no-new-privileges`; `GET /images/json` and `GET /v1.NN/images/json` return **200**; `/info`,
`/containers/json`, and `/version` return **403**; any `POST` returns **405**. This retires the
2026-07-24 "still to do" item — the compiled-upstream harness used there predicted the published
image's behavior exactly.

**1. `999` is a convention, not a fallback anyone should rely on — the host measured `989`.** Both
the README's § Configuration note and the 2026-07-24 entry called `999` "the Debian/Ubuntu default,"
which reads as "probably right." On the Debian host actually used, `stat -c '%g' /var/run/docker.sock`
returned **`989`**, so the Compose fallback would have failed outright. The README now calls `999` a
placeholder rather than a default and cites the measured `989`; the `stat` derivation was already
the instruction and remains it.

**2. The `-allowfrom` source check rejects before the path and method rules are evaluated.**
wollomatic resolves the client address back to a hostname and compares it to `scrye` *first*. A
request from a non-matching source gets **403** for everything — including methods that would
otherwise answer 405. So from the client, a wrong source and a disallowed path are
indistinguishable, and an operator debugging "403 on an endpoint that should work" will suspect the
`-allowGET` regex when the cause is the source check. (The proxy's own log does distinguish them:
`blocked request … forbidden IP`.) Documented in the README's § Optional sidecars and § Security
model, with the "check the log before editing the pattern" instruction attached.

**3. The wrong-GID failure mode is a crash loop, not a clean exit.** The README said the proxy
"reports a socket permission error and stays down," which sends an operator looking for a stopped
container. What actually happens: it logs
`dial unix /var/run/docker.sock: connect: permission denied`, exits, and `restart: unless-stopped`
restarts it into the identical failure, repeating under Docker's restart backoff. `docker compose ps`
shows STATUS **`Restarting`** — never `Exited`. The README now describes it that way.

**4. From the client, a crash-looping proxy is a connection error, not an HTTP status.** Nothing is
listening, so `curl` reports **`000`** and `docker_proxy.list_images()` raises `DockerProxyError`
from `httpx.HTTPError` ("Could not reach the Docker proxy at …") rather than from a non-200
response. Both paths surface as **502** on `GET /api/docker-environments/{id}/images` — the
distinguishing signal is the detail text, not the status code. That is the cheapest way to tell a
broken sidecar (connection error / `000`) from a working-but-restrictive allowlist (`returned HTTP
403`), and the README now says so at the point where the 502 is described.

**Structural re-confirmation: a crash-looping proxy does not block the app.** Re-verified against
`docker/docker-compose.yml` this session — grepped repo-wide, **no `depends_on` exists in any
Compose file, for any service, in any profile**, so there is no `condition: service_healthy` gate,
the `scrye` container neither waits on the proxy nor is torn down by it, and the proxy's healthcheck
is consumed by nothing but itself. Scrye starts and stays up while the sidecar cycles. This matches
what the 2026-07-25 entry recorded; nothing needed flagging or changing.

**Not changed, deliberately.** Two spots still carry the softer wording, left alone because this was
scoped docs-only: `docker/docker-compose.yml`'s `DOCKER_GID` comment ("a `docker` group of 999 is
the Debian/Ubuntu default") is a configuration file, and
`backend/app/core/docker_proxy.py`'s non-200 error message still advises checking that the proxy is
"read-only with `IMAGES=1`" — a stale tecnativa env-var reference that has been wrong since
2026-07-24 and is code. Both are cosmetic and tracked for a follow-up that is allowed to touch
non-doc files.
**Why:** Every one of these is a symptom that points away from its cause — a 403 that looks like a
regex bug, a crash loop that looks like a stopped container, a connection error that looks like an
API rejection, and a GID default that looks safe. They cost debugging time exactly once per
operator, and only the live run could surface them.
**Plan section affected:** none. `README.md` § Configuration, § Optional sidecars, and § Security
model, plus the `CHANGELOG.md` `docker-env` action-required note. No schema, API-contract,
security-model, job-model, or auth change; the allowlist itself is byte-for-byte unchanged.

### 2026-07-26 — Post-v1 — Stale socket-proxy wording retired from the code and Compose file
**What changed:** The 2026-07-26 entry above closed with a "**Not changed, deliberately**" paragraph
naming two spots it left carrying pre-wollomatic wording because that entry was scoped docs-only.
Both are now fixed; nothing else in this change.

**1. `backend/app/core/docker_proxy.py` — the non-200 error detail.** It advised checking that the
proxy is "read-only with `IMAGES=1` and reachable on the internal network." `IMAGES=1` is a
**tecnativa** env var that has not existed in this stack since the wollomatic migration (#89), and
this string prints in exactly the 403 case the README now teaches operators to diagnose — so it was
actively pointing them at a knob that isn't there. It now names the real causes: a non-allowlisted
path (`-allowGET` permits only `/images/json` and `/v1.NN/images/json`), a non-GET method (405), or
the `-allowfrom` source check rejecting a client that isn't the `scrye` container — with the note
that the proxy's own log distinguishes the last two (`blocked request … forbidden IP`), and a
pointer to the README's § Optional sidecars rather than a restatement of it. It stays an error
detail, not documentation.

`backend/tests/test_docker_proxy.py` gains a regression guard: it drives `list_images()` through an
`httpx.MockTransport` returning 403 and asserts the message carries `-allowGET`, `-allowfrom`, and
`forbidden IP` and does **not** carry `IMAGES=1`. No existing test asserted on the old string, so
nothing needed updating — only adding.

**2. `docker/docker-compose.yml` — the `DOCKER_GID` comment.** It called `999` "the Debian/Ubuntu
default … used here as a fallback only," the same wording the README corrected when the live run
measured **`989`** on the Debian host. It now matches the README: `999` is a **placeholder, not a
safe default**, it was `989` on the host this was last verified against, and the
`stat -c '%g' /var/run/docker.sock` derivation remains the instruction. The adjacent failure-mode
sentence ("shows up as the proxy logging a socket permission error on start") was corrected in the
same comment for the same reason the README's was — the real behavior is a **crash loop** under
`restart: unless-stopped` (STATUS `Restarting`, never `Exited`), and a comment that says "on start"
sends an operator looking for a stopped container.
**Why:** Both were tracked as follow-ups precisely because a docs-only change can't reach them, and
a stale env-var name in the one error string an operator reads while debugging a 403 is worse than
no advice at all.
**Plan section affected:** none. One error-message string, one Compose comment, one added test. No
schema, API-contract, security-model, job-model, or auth change; the `-allowGET` pattern, the option
set, and the `${DOCKER_GID:-999}` value itself are all unchanged.

### 2026-07-26 — Infra/Process — Group A interpreter CVEs re-verified against the 3.14 branch; waivers re-pointed at a Group-A-only tracking issue (#98)
**What changed:** `ci/grype.yaml`'s **Group A** waivers — CVE-2026-15308 (HIGH, `html.parser`
quadratic-complexity CPU DoS) and CVE-2026-12003 (MEDIUM, `getpath.py` in-tree search-path
fallback) — were re-verified against the runtime the image actually pins, and their tracking
reference was moved off issue #52 onto a new **Group-A-only** issue, #98. **Group B was not
touched**: CVE-2025-15366 / CVE-2025-15367 remain the standing acceptance on any interpreter below
3.15 with the annual re-confirmation the 2026-07-25 process entry gave them, and nothing about the
3.14 move changes that.

**Verification, done at the source** per CLAUDE.md § Dependency hygiene (the rule the 2026-07-25
process entry added) — the `3.14` branch and the `v3.14.6` tag were fetched and diffed file by file,
rather than reading Grype's `FIXED IN` column, which still reports 3.15.x for both:
- **CVE-2026-15308 / `Lib/html/parser.py`** — the `3.14` branch carries the buffered-`feed()`
  rewrite (`_pending` / `_pending_len` / `_parse_threshold`, with `close()` flushing the pending
  list) from backport PR python/cpython#153039, commit `07efb08`, merged 2026-07-04. `v3.14.6`
  still has the unguarded `self.rawdata = self.rawdata + data; self.goahead(0)`.
- **CVE-2026-12003 / `Modules/getpath.py`** — the `3.14` branch has the `BUILD_LANDMARK` constants
  (`Modules/Setup.local`, `%VPATH%\Modules\Setup.local`) and the `isfile(joinpath(
  real_executable_dir, BUILD_LANDMARK))` fallback removed, with an inline `gh-151544;
  CVE-2026-12003` comment in their place, from backport PR python/cpython#151682, commit `b93d6d3`,
  merged 2026-06-22. `v3.14.6` still has both.
- **Release state** — `Include/patchlevel.h` on the `3.14` branch reads `PY_VERSION "3.14.6+"`;
  there is no `v3.14.7` tag and no `Misc/NEWS.d/3.14.7.rst`. 3.14.6 (released 2026-06-10) is the
  latest 3.14.x, and both backports merged after it. **3.14.7 is the first release that will carry
  either fix**, so both waivers stand and the 2026-10-25 review date is unchanged.

**Two premises this pass was scoped on did not survive checking, and the work was adjusted rather
than forced to fit:**
1. **The Group A comment was expected to still read "next 3.13.x."** It did not — the 2026-07-25
   upgrade entry had already retargeted it to "next 3.14.x." No trigger correction was needed; what
   the block was actually missing was the concrete release (3.14.7) and any record of the fixes
   having been verified rather than assumed. Those were added instead.
2. **Issue #52 was expected to be closed.** It is open — checked twice through different APIs, and
   the repository has zero closed issues. #98 was therefore opened on the ground that does hold:
   #52 is the older all-four tracker, written end to end against the 3.13 runtime, and stale since
   the 3.14 move — including a resolution-trigger line still asserting that 3.14.6 carries the
   Group B fixes, which the 2026-07-25 entry records as false. The waiver comment says #98
   **supersedes #52 for Group A** and notes #52 is still open; it does not claim #52 is closed.
   Whether to close #52 or re-scope it to Group B is left to the maintainer.

`ci/grype.yaml` changes: the shared header no longer names a single tracking issue for all four
CVEs (the two groups have different triggers and different trackers, and one blanket "Tracked in
issue #52" line is what let a Group-A reference go stale behind a Group-B-shaped issue); the Group A
block gains the dated source-verification note, the named 3.14.7 trigger, and the #98 reference.
**Why:** The waivers' tracking reference had drifted out from under them — #52 describes a runtime
Scrye no longer runs, and its own text contradicts what §14 records as true — so a waiver reviewer
arriving on 2026-10-25 would have been sent to a document that is wrong about the thing they are
reviewing. Re-verifying at the source before re-dating anything is the 2026-07-25 rule applied to
its first real case, and it is what caught premise (1): the trigger was already correct, and a pass
that had assumed otherwise would have "fixed" it into the same state while recording a correction
that never happened.
**Plan section affected:** §9.1 (base image / dogfood self-scan), §12 (Phase 6 self-scan), CLAUDE.md
§ Dependency hygiene. Configuration and documentation only — no application code, schema,
API-contract, security-model, job-model, or auth change, and no change to the waiver list itself
(still four entries).

### 2026-07-26 — Infra/Process — CVE-2025-15366 (imaplib) regrouped from Group B to Group A: the backport did land on 3.14
**What changed:** `ci/grype.yaml`'s Group B waiver block covered two CVEs on the rationale that
upstream had declined the backport to 3.10–3.14, making them permanently unfixable below 3.15.
Checking that rationale at the source before restating it in the re-scoped tracking issue showed it
is **no longer true of CVE-2025-15366**. The waiver moved to Group A; Group B is now
CVE-2025-15367 alone. No CVE was un-waived — the list goes from four entries to four entries, three
in Group A and one in Group B.

**The evidence, not just the conclusion.** `Lib/imaplib.py` and `Lib/poplib.py` were fetched from
the `3.14` branch, the `3.13` branch, the `v3.14.6` tag and `main`, and compared:
- **imaplib — fix is on the maintenance branches.** `3.14` and `3.13` both define
  `_control_chars = re.compile(b'[\x00\r\n]')` and raise
  `ValueError("NUL, CR and LF not allowed in commands")` inside `IMAP4._command()`'s argument loop,
  before each argument is appended to the wire buffer. `v3.14.6` has neither the constant nor the
  guard. Upstream issue **gh-143921**; 3.14 backport **python/cpython#153137**, merge commit
  `2981822`, merged **2026-07-07**; 3.13 backport **python/cpython#153287**, merge commit
  `71926d9`, same day.
- **It is queued, not released.** `Misc/NEWS.d/next/Security/2026-01-16-11-41-06.gh-issue-143921.AeCOor.rst`
  ("Reject NUL, CR and LF characters in IMAP commands. Other control characters are allowed and
  sent quoted.") is present on `3.14` and `3.13` and **404s on `v3.14.6`**. Still under `next/`, so
  it ships in the next point release and has shipped in none — exactly the Group A shape.
- **poplib was NOT backported.** `POP3._putcmd()`'s
  `re.search(b'[\x00-\x1F\x7F]', line)` → `ValueError('Control characters not allowed in commands')`
  guard exists on `main` only; the `3.14` branch, the `3.13` branch and `v3.14.6` all still pass the
  line to `_putline()` unvalidated. Upstream issue **gh-143923** lists a single PR
  (**python/cpython#143924**, commit `b234a2b`, 2026-01-20, `main`) and no backport PR against any
  maintenance branch.
- **Why the companion fixes diverged** — this is the part that makes the split make sense rather
  than look arbitrary. The original imaplib fix (**python/cpython#143922**) rejected *all* control
  characters, and that breadth is what drew the compatibility-regression concern behind the original
  no-backport decision. A follow-up, **python/cpython#153067**, narrowed the check to NUL, CR and LF
  only — other control characters are legal in quoted strings and are sent quoted — and it is the
  **narrowed** version that was backported (the 3.14 commit message records it as a combined
  backport of GH-143922 and GH-153067). poplib's fix still rejects the full `[\x00-\x1F\x7F]` range
  and has had no equivalent narrowing, which is consistent with it remaining un-backported. So the
  two were never going to move together, despite the identical stated reasoning in our own record.

**On the 2026-07-25 entry: superseded for CVE-2025-15366 only, and left in place unedited.** That
entry's own reading was correct and is not being retracted — it verified **3.14.6**, the released
interpreter, and 3.14.6 genuinely lacks both guards; that remains true today. What does not survive
is the *generalisation* it drew from that reading: "upstream declined the backport to 3.10–3.14, so
these are fixed only in 3.15+ and no 3.14.x point release will ever clear them." The honest
chronology is that the imaplib backport merged on **2026-07-07**, **18 days before** that entry was
written — so the claim was already stale when recorded, not overtaken afterwards. The check looked
at the released tag and concluded something about the maintenance *branch*, which the tag cannot
tell you. **Nothing in the 2026-07-25 entry was edited**; it stands as written and this entry
supersedes it on that one point.

**The lesson is narrower than "verify at the source," which was already the rule.** Source
verification was performed on 2026-07-25 and still produced a wrong standing conclusion, because
the ref it read could not answer the question being asked. A claim about whether a fix *will ever*
arrive on a line is a claim about the **branch**; only a claim about what is shipping *today* can be
settled from a tag. Both refs are cheap to check — this pass read four — and a waiver whose
rationale is "permanently unfixable" should be pinned to the branch, not the release.

`ci/grype.yaml` changes: CVE-2025-15366 moved into the Group A list with the imaplib backport added
to the Group A source-verification block; Group B rewritten for poplib alone, with its own
source-verification lines, the divergence explanation, and issue #52 as its tracker; the shared
header's ARCHIVE pointer extended to this entry. The Group B **review cadence (annual, next
2027-07-25)**, the standing-acceptance framing, and the explicit "do not scope a 3.15 move as a
reaction to this" instruction are all carried over unchanged — the acceptance itself was not
re-opened, only its membership.
**Why:** A waiver is only as good as the rationale beside it, and this one had drifted from
"accepted because unfixable" to "accepted because unfixable, except it was fixed three weeks ago."
Regrouping keeps the two blocks meaning what they say — Group A has a trigger and a review date
tied to a release, Group B is a standing acceptance with an annual re-confirmation — so a reviewer
arriving on either date knows which question they are being asked.
**Plan section affected:** §9.1 (base image / dogfood self-scan), §12 (Phase 6 self-scan),
CLAUDE.md § Dependency hygiene. Configuration and documentation only — no application code, schema,
API-contract, security-model, job-model, or auth change.

---

### 2026-07-26 — Infra/Process — Dependabot told to stop proposing Mantine/React majors (locked decision §2)

**What changed:** `.github/dependabot.yml`'s npm entry gained an `ignore:` block that drops
**major** updates for `@mantine/*`, `react`, `react-dom`, `@types/react` and `@types/react-dom`.
Minor and patch updates inside Mantine v7 and React 18 are untouched and still open as usual. No
other ecosystem entry changed.

**Why:** locked decision §2 fixes the frontend at **React 18 + Mantine v7**. Dependabot did not
know that, so the weekly frontend group PR (#86, 25 updates) proposed `@mantine/*`
7.15.2 → **9.4.2** and `react`/`react-dom` 18.3.1 → **19.2.8** — two locked decisions re-opened by
a bot, in the same PR as a dozen updates that are perfectly fine. That grouping is the actual
problem, not the majors themselves: because Dependabot groups the whole ecosystem into one branch,
a single unmergeable entry makes the entire PR unmergeable, and closing it throws away the
mergeable bumps sitting next to it. #86 was closed by hand for exactly this reason. Without the
ignores, next week's run rebuilds the same PR and the same manual close happens again — the config
is where the lock has to be expressed, once, or it gets re-litigated weekly.

**Why `@types/react*` are in the list even though the ask named only Mantine and React.** Their
major version tracks React's: `@types/react` 19 against `react` 18 is a type-level mismatch, and
this repo turned on **type-aware ESLint** on 2026-07-24, so that mismatch surfaces as a failing
lint gate rather than as a quiet inconsistency. Ignoring the runtime majors while letting their
`@types` majors through would leave the group unmergeable for the same reason it already was.

**What this deliberately does not do.** It does not touch the frontend **tooling** majors that #86
also proposed — TypeScript 5.7 → 7.0, ESLint 9 → 10, `typescript-eslint` 8.19 → 8.65, Vite 6 → 8,
Vitest 3 → 4, jsdom 26 → 29. Those are not locked, they are wanted, and all of them land on the
type-aware ESLint gate, so they are real work with a real chance of churn in the lint config —
scoped as their own PR rather than folded into a config change or into a bump PR. Nor is it a
permanent verdict on React 19 / Mantine v9: an ignore rule is a statement that a bot may not make
this decision, not that the decision can never be made. Lifting either line is a locked-decision
change and goes through the user first (CLAUDE.md § When to ask vs. decide).

**Plan section affected:** CLAUDE.md locked decision §2, § Dependency hygiene, § Required
deliverables (`.github/dependabot.yml`). Repository configuration only — no application code,
schema, API-contract, security-model, job-model, or auth change, and no dependency version moved
in either direction by this entry.

---

## 15. Finding-ID index (decoder for §14's citations)

§14 cites bare finding IDs — `SC-12`, `P3-4`, `QUA-17`, `H5/CON-4` — and never re-explains them.
Those IDs came from ten review documents that lived under `` and ``
until 2026-07-26, when they were deleted: every finding in them was closed, and a folder of
closed findings sitting beside the two live documents was costing more than it returned. This
section is what replaced them — **a decoder, not a summary**. It resolves an ID to one line of
what it was and, where known, the PR that closed it. It is not a backlog: nothing here is open.

**The originals are still retrievable.** They were removed in a single commit; the commit
immediately before it is recorded in the 2026-07-26 §14 entry "Review documents retired…", and
`git show <sha>:<file>` prints any of them verbatim. Use that when one line here
isn't enough — the reasoning lives in git, not in the working tree.

**Two namespaces reuse the same prefix.** `SEC-*` means one thing in the 2026-07-12
`security-review.md` and a different thing in the 2026-07-05 `full-audit-2026-07-05.md`; the two
sets are unrelated and are labelled **(review)** and **(audit)** below. `SEC-1` is the case that
actually bites: the *review's* SEC-1 is the repository-target local-path read (#53), the *audit's*
SEC-1 is the plaintext webhook URL (2026-07-05 P0). §14 flags this inline at the H1 back-fill entry.

---

### Summary IDs (`00-summary.md`, 2026-07-12) → source finding

The severity-ranked backlog used its own H/M/L numbering on top of the source reports. §14 cites
both forms, often paired (`H5/CON-4`, `M23/SC-7`). Resolving PRs are on the source rows below.

`H1`=SEC-1(review) · `H2`=CON-1 · `H3`=CON-2 · `H4`=CON-3 · `H5`=CON-4 · `H6`=P1-1+SEC-5(review) ·
`H7`=APIR-1 · `H8`=APIR-2 · `H9`=SC-2 · `H10`=SC-3 · `H11`=SC-1

`M1`=SEC-2(review) · `M2`=SEC-3 · `M3`=SEC-4 · `M4`=SEC-5 · `M5`=SEC-6 · `M6`=CON-5 · `M7`=CON-6 ·
`M8`=CON-7 · `M9`=CON-8 · `M10`=CON-9 · `M11`=CON-10 · `M12`=CON-11 · `M13`=CON-12 · `M14`=CON-13 ·
`M15`=APIR-3 · `M16`=APIR-4 · `M17`=APIR-5 · `M18`=APIR-6 · `M19`=P1-2 · `M20`=P1-3 · `M21`=P1-4 ·
`M22`=SC-6 · `M23`=SC-7 · `M24`=SC-4 · `M25`=SC-5 · `M26`=SC-8

`L1`=SEC-7(review) · `L2`=SEC-8 · `L3`=SEC-9 · `L4`=SEC-10 · `L5`=CON-14 · `L6`=CON-15 ·
`L7`=CON-16 · `L8`=CON-17 · `L9`=CON-18 · `L10`=CON-19 · `L11`=CON-20 · `L12`=APIR-7 ·
`L13`=APIR-8 · `L14`=APIR-9 · `L15`=APIR-10 · `L16`=P2-1 · `L17`=P2-2 · `L18`=P2-3 · `L19`=P2-4 ·
`L20`=P2-5 · `L21`=P2-6 · `L22`=P2-7 · `L23`=SC-9 · `L24`=SC-11 · `L25`=D3/SC-10

---

### `SEC-*` (review) — `security-review.md`, 2026-07-12

| ID | Finding | Closed by |
|---|---|---|
| SEC-1 | `repository` scan targets accepted local paths, bypassing the filesystem-scan allowlist → arbitrary host-file read | #53 |
| SEC-2 | Backup restore trusted bundle-supplied scrypt cost params with no ceiling → pre-passphrase memory-exhaustion DoS | #54 |
| SEC-3 | No entropy floor / key stretching on the master key | #64 |
| SEC-4 | Log redaction only prefix-masked unquoted secrets containing spaces or commas | #64 |
| SEC-5 | No CSP / `X-Frame-Options` / `nosniff` / `Referrer-Policy`; CSRF cookie JS-readable by design | #55 |
| SEC-6 | SSRF: notification / registry / docker-proxy fetchers reached arbitrary internal and link-local hosts | #64 |
| SEC-7 | Field-encryption AAD bound to the column, not the row | #64 (row-bindable, lazy upgrade-on-write) |
| SEC-8 | Mandatory-MFA policy not enforced on the OIDC login path | #64 (accepted limitation + audit visibility) |
| SEC-9 | Forced-enrollment window let a password-only attacker bind their own TOTP | #64 (same) |
| SEC-10 | Auth rate-limiter and pending-MFA store grew unbounded by distinct key | #64 |

### `SC-*` — `supply-chain-review.md`, 2026-07-12

| ID | Finding | Closed by |
|---|---|---|
| SC-1 | No backend lockfile — transitive Python deps floated unpinned at every image build | #64 |
| SC-2 | Every workflow `uses:` tag-pinned, not SHA-pinned, incl. the `packages: write` publish paths | #57 |
| SC-3 | Dependabot watched only `github-actions`; pip, npm and docker unmonitored | #57 |
| SC-4 | Published images carried no SLSA provenance or SBOM attestation | #64 |
| SC-5 | No scheduled re-scan of the already-published `:latest`/`:dev` images | #64 (`rescan.yml`) |
| SC-6 | `node:22-bookworm-slim` build-stage digest stale | #64 |
| SC-7 | `tecnativa/docker-socket-proxy:0.3.0` ~15 months stale — the one sidecar holding the socket | #64 (→v0.4.2), #89 (→wollomatic) |
| SC-8 | Scanner `checksums.txt` verified same-origin only, no signature check | #64 (cosign keyless) |
| SC-9 | `# syntax=docker/dockerfile:1.7` BuildKit frontend tag-pinned, not digest-pinned | #64 |
| SC-10 | `ci.yml` and the composite build action pinned different majors of the same actions | #57 |
| SC-11 | `persist-credentials: false` missing on token-bearing workflow checkouts | #57 (publish), #67 (`ci.yml`) |
| SC-12 | `[build-system].requires = setuptools>=75` — the one floating, unhashed build-time dep | #80 |
| SC-13 | Mantine 7.15.2 is two majors behind current | **Not a defect** — locked decision §2 pins v7 |
| SC-14 | Runtime image shipped `backend/tests/` and `backend/scripts/` | #77 |

### `APIR-*` — `api-review.md`, 2026-07-12

| ID | Finding | Closed by |
|---|---|---|
| APIR-1 | Timezone-aware `expires_at` on Trivy ignore rules stored with its offset silently dropped | #61 |
| APIR-2 | Two incompatible 422 body shapes; the SPA rendered only one → blank "Request failed (422)" | #61 |
| APIR-3 | Scan-diff: SPA's Compare gate missed `target_type`; diff payload omitted `location` | #61 |
| APIR-4 | Filtered-history export silently truncated at 5 000 scans with no signal | #61 |
| APIR-5 | Naive-UTC timestamps serialized with no `Z`; one consumer already parsed them wrong | #61 |
| APIR-6 | Update paths accepted states create paths forbid on secret-bearing resources | #61 |
| APIR-7 | "Run now" left `last_run_at`/`last_status` stale, contradicting `last_scan_id` | #60 (via CON-17), assertion #61 |
| APIR-8 | Three list-envelope conventions across endpoints | #61 (`entries`→`items`), 2026-07-25 (full standardization) |
| APIR-9 | List/history rows shipped `options` + unbounded `error` text the views never render | #61 |
| APIR-10 | Scanner↔target matrix defined twice and already drifted | #61 |

### `CON-*` — `concurrency-review.md`, 2026-07-12

| ID | Finding | Closed by |
|---|---|---|
| CON-1 | SQLite lock contention unhandled → scans stuck `running` forever, artifact files deleted | #54 |
| CON-2 | `proc.kill()` signalled only the direct child; credential-bearing git/scanner grandchildren survived | #56 |
| CON-3 | Restore's "no active scans" guard was check-then-act across the upload `await` | #54 |
| CON-4 | Scanner JSON parse/normalize ran on the event loop; a large report froze the app | #67 |
| CON-5 | Synchronous SQLite commits/reads on the event loop in async contexts | #54 (claim/fail), #60 (rest) |
| CON-6 | Shutdown arithmetic exceeded Docker's 10 s stop grace → SIGKILL mid-commit | #60 |
| CON-7 | Lifespan shutdown unshielded; a second cancellation skipped `worker.shutdown()` | #60 |
| CON-8 | `PendingMfaStore` not thread-safe but shared across threadpool threads | #60 |
| CON-9 | Backup bundle had no single-transaction snapshot; scheduled path had no active-scan guard | #60 |
| CON-10 | Every running scan pinned a pooled DB connection for its full wall-clock | #60 |
| CON-11 | Scans committed `queued` and never submitted on shutdown races; caller still saw 201 | #54 (watchdog) |
| CON-12 | Scanner-DB auto-update marked itself done *before* running → failure not retried for a full interval | #60 |
| CON-13 | Maintenance tick fully serialized; slow DB updates delayed schedules/retention ~20 min | #60 |
| CON-14 | `proc.kill()` unprotected against `ProcessLookupError`; on the cancel path could replace the cancellation | #56 |
| CON-15 | Notification dispatch ran while the scan still held its concurrency-semaphore slot | #60 |
| CON-16 | Per-scan task exceptions outside `_execute`'s `try` never retrieved; task spawning unbounded | #60 |
| CON-17 | "Run now" raced the cron tick — duplicate scans, lost `last_scan_id` | #60 |
| CON-18 | Dashboard `gather` without `return_exceptions` abandoned in-flight probe subprocesses | #60 |
| CON-19 | Worker could notify for a scan deleted milliseconds earlier (stale identity-map read) | #60 |
| CON-20 | Multi-GB checkout `shutil.rmtree` ran synchronously on the event loop | #60 |

### `P1-*` / `P2-*` / `P3-*` — `frontend-review.md`, 2026-07-12

| ID | Finding | Closed by |
|---|---|---|
| P1-1 | XSS: scanner-derived `primary_url` rendered as an unvalidated `href` | #55 (`safeHttpUrl`) |
| P1-2 | Settings forms rendered editable before their initial GET resolved → Save could write defaults | #62 (tests back-filled 2026-07-24) |
| P1-3 | Scan-detail poller never stopped or backed off on errors, behind a stale "running" badge | #62 |
| P1-4 | History fetch had no stale-response guard — table could contradict the filter controls | #62 |
| P2-1 | Tag draft wiped every 2.5 s by the status poll | #62 |
| P2-2 | Navigating between scan details mixed two scans' state | #62 |
| P2-3 | Findings panel: empty-state flash, stale rows during filter changes, no loading flag | #62 |
| P2-4 | Unguarded double-fire mutations — incl. minting an invisible second API token | #62 |
| P2-5 | History table unusable by keyboard: click-only sort, click-only row navigation | #62 |
| P2-6 | Unlabeled form controls (filters, tags input, segmented controls, MFA PinInput) | #62 |
| P2-7 | All navigation disappeared below the `sm` breakpoint | #62 |
| P3-1 | History filters lived only in memory — Back/bookmark/share lost the view | batch 2026-07-24 |
| P3-2 | Compare selection drifted from the visible table (phantom "1/2", deleted-scan 404) | batch 2026-07-24 |
| P3-3 | Silent empty catches hid credential/filter fetch failures → private target scanned anonymously | #77 |
| P3-4 | Auth refresh could resurrect a logged-out session (narrow race) | #82 |
| P3-5 | 500-row findings table re-rendered on every unrelated keystroke and poll | batch 2026-07-24 |
| P3-6 | Loading states silent for screen readers; chart ARIA inert | batch 2026-07-24 |
| P3-7 | Theme-token drift (hardcoded severity colors, pinned `teal-6` chart) | batch 2026-07-24 |
| P3-8 | TypeScript strictness gaps: blind `as T` casts, `noUncheckedIndexedAccess`, type-aware ESLint | #81 (casts), batch 2026-07-24 (both flags) |

**Mirror finding:** issue **#83** is P3-4's companion running the other way — a stale pre-login
`refresh()` wiping a just-completed `login()` — fixed in **#87**.

### `D-*` / `R-*` — `claude-md-compliance.md`, 2026-07-12

| ID | Finding | Closed by |
|---|---|---|
| D1 | ~100 dead `docs/PLAN.md` references across backend, frontend and Dockerfile | #65 |
| D2 | Stale "no registry publishing" comments contradicting locked decision §6 | #65 |
| D3 | Composite build action pinned older action majors than `ci.yml`; Dependabot didn't reach it | #57 |
| D4 | 8 squash-merge commits authored as "Tyler Richardson" (GitHub profile display name) | #65 / §14 — doc-side only; the profile setting is still open, see `ROADMAP.md` |
| D5a | The one `except Exception` in `inprocess.py` without an explanatory comment | batch hygiene |
| D5b | `test_migrations.py` import block that a newer ruff would re-sort (latent `I001`) | #80 |
| R1 | CLAUDE.md still mandated an OpenAPI-*generated* API client; FE-2 kept the hand-written one | #65 |
| R2 | CLAUDE.md said CI resolves "all fixable findings"; the gate is fixable HIGH/CRITICAL (INF-10) | #65 |
| R3 | CLAUDE.md referenced frontend tests that did not exist (FE-10) | #65 |
| R4 | CLAUDE.md's `.env.example` rule named an `OIDC_CLIENT_SECRET` placeholder that must not exist | #65 |
| R5 | Required-deliverables list missing CHANGELOG, SECURITY.md, CODEOWNERS, ROADMAP, dependabot, `ci/` | #65 |
| R6 | Code comments still pointing at `docs/PLAN.md` (with D1/D2) | #65 |
| R7 | Squash-merge authorship follows the GitHub *profile display name*, not `git config` | #65 / §14 2026-07-13 |
| R8 | Promotion-PR title convention (`Promote dev to main: …`) undefined | §14 2026-07-13 |

That report also carried pass/fail checkpoints under four prefixes — `LD1–LD7` (locked decisions),
`HS1–HS7` (hard security rules), `GP1–GP7` (git & PR conventions), `CS1–CS8` (coding standards).
All passed except `GP4` (author identity → D4) and `GP6` (Conventional Commits on promotions → R8),
which are the only two §14 cites.

---

### `full-audit-2026-07-05.md` — `INF-*` / `SEC-*` (audit) / `SCN-*` / `API-*` / `FE-*` / `FEAT-*` / `QUA-*` / `DOC-*`

Remediated in tiers **P0–P5**, each with its own dated 2026-07-05 §14 entry; those entries name the
IDs they closed. Where a row says "P0"…"P5" below, that is the tier entry that closed it.

**`INF-*` — infrastructure & deployment**

| ID | Finding | Closed by |
|---|---|---|
| INF-1 | Actions tag-pinned, not SHA-pinned | P2 (Dependabot), #57 (SHA pins) |
| INF-2 | `:dev` publish silently failed for merged fork PRs (secrets withheld) | 2026-07-06, fully retired 2026-07-09 |
| INF-3 | Locked decision §6 text contradicted the implemented `:dev` trigger | P2 |
| INF-4 | `trivy-server` sidecar runs as root | P2 — documented exception (still true) |
| INF-5 | `docker-socket-proxy` under `read_only` + `cap_drop: ALL` needed a writable `/run` | P2; moot after #89 (wollomatic needs none) |
| INF-6 | Dockerfile / Compose "no registry publishing" comments stale | P3 / #65 (= D2) |
| INF-7 | Dockerfile comment overstated verification — checksums same-origin, not signed | P2 wording; #64 added cosign (= SC-8) |
| INF-8 | Two near-simultaneous release tags could leave `:latest` on the older version | Accepted — single-maintainer release flow |
| INF-9 | No CI ran on `dev` while `:dev` was built from the merge commit | Retired by the 2026-07-06 nightly split |
| INF-10 | Dogfood gate is HIGH/CRITICAL-only while CLAUDE.md said "all fixable" | Logged deviation 2026-07-05; CLAUDE.md amended in #65 (= R2) |
| INF-11 | README said generic private repos clone into tmpfs; they check out under `/cache/tmp` | P3 |
| INF-12 | Generic private-repo `git clone` ran with a minimal env dropping proxy/TLS vars | Accepted — deliberate env stripping |
| INF-13 | Healthchecks hard-coded port 8089 while `SCRYE_PORT` is configurable | Info-level; unchanged |
| INF-14 | `trivy-server` healthcheck (`trivy version`) didn't test the listener | Info-level; unchanged |
| INF-15 | `trivy-server` tmpfs unsized and root-owned | Info-level; unchanged |
| INF-16 | Release publish had no dependency on a green CI run for the tagged commit | Accepted — promotion PR is the gate |
| INF-17 | Production image shipped the full `backend/` tree incl. `tests/`/`scripts/` | #77 (= SC-14) |
| INF-18 | README quick start only built locally; the published image was documented in CONTRIBUTING | P3 (= DOC-1) |
| INF-19 | Large multipart uploads spooled to the 200 MB `/tmp` tmpfs | P1 (`read_upload_capped`) |

**`SEC-*` (audit) — distinct from the review's SEC-\* above**

| ID | Finding | Closed by |
|---|---|---|
| SEC-1 | Token-bearing generic-webhook URL stored in plaintext and returned on read | P0 |
| SEC-2 | `logging.py` comment claimed OIDC `code`/`state` redaction that did not exist | Comment corrected |
| SEC-3 | Password-gated re-auth endpoints not rate-limited | Info-level |
| SEC-4 | Auth rate-limiter per-IP bucket map grew unbounded | #64 (= SEC-10 review) |
| SEC-5 | Unauthenticated OIDC login endpoint created DB rows with no rate limit | Info-level |
| SEC-6 | TOTP codes had no replay/last-used tracking within their validity window | Info-level |
| SEC-7 | API-token display prefix exposed 4 characters of the secret body | Accepted — prefix is for display |
| SEC-8 | Registry *create* encrypted a secret for credential-helper auth types that *update* rejects | Validation inconsistency |
| SEC-9 | `registry_check` returned a raw exception string to the response | No secret leaked; noted |

**`SCN-*` — scanner orchestration, workers, credentials-at-scan-time**

| ID | Finding | Closed by |
|---|---|---|
| SCN-1 | Unbounded scanner stdout read into memory (no output size cap) | P1 (`SCRYE_SCANNER_MAX_OUTPUT_BYTES`) |
| SCN-2 | Docker-proxy and registry-check responses read without a size limit | Low |
| SCN-3 | `list[str]` settings couldn't be parsed from their documented comma-separated env form | P2 (startup bug) |
| SCN-4 | `git checkout <commit>` had no `--` end-of-options terminator | 2026-07-04 audit remediation |
| SCN-5 | Registry credential forwarded to a bearer realm chosen by the probed registry | 2026-07-04 (refuses non-HTTPS realms) |
| SCN-6 | Multi-step scans had no aggregate wall-clock bound (~2× the configured timeout) | Low |
| SCN-7 | Cron evaluated in UTC with no timezone affordance | Documented |
| SCN-8 | A DB error on one schedule aborted the whole due-firing batch for that tick | Low |
| SCN-9 | Filesystem-allowlist TOCTOU and symlinks inside an allowed root (PLAUSIBLE) | Documented — admin-configured roots |
| SCN-10 | Deleting a credential NULLed the schedule FK but left the stale id in `options` JSON | Fails closed (= QUA-2) |

**`API-*` — API layer, data model, reports, backup/restore, performance**

| ID | Finding | Closed by |
|---|---|---|
| API-1 | N+1 lazy-load of `scan.tags` in `list_scans`/`list_history` | P1 |
| API-2 | `restore_bundle` (scrypt + full DB rebuild) ran directly on the event loop | P0 |
| API-3 | Bundle build materialized the whole DB as in-memory JSON, held ~3× | P0 |
| API-4 | Upload endpoints read the entire body into memory *before* the size cap | P1 |
| API-5 | Worker persisted findings and raw artifacts synchronously on the event loop | P1 |
| API-6 | Large findings commit could exceed `busy_timeout` and surface as a 500 (PLAUSIBLE) | #54 (= CON-1) |
| API-7 | Dashboard/metrics hydrated a full ORM row per target, unbounded and uncached | P1 (TTL cache) |
| API-8 | Backup download read the whole bundle into memory instead of streaming | Low |
| API-9 | Malformed-but-decryptable bundles crashed restore with a 500 instead of a 400 | 2026-07-13 (`BackupError`) |
| API-10 | Backups carried no artifact files; restore produced rows pointing at nothing | P0 |
| API-11 | Restore didn't pause the worker; concurrent scans raced the table wipe | P0 (409), #54 (worker pause) |
| API-12 | `scans` composite index uses `created_at`, plan §7 promised `started_at` | Logged deviation 2026-07-05 — index kept |
| API-13 | History predicates on `created_by_username`/`highest_severity` unindexed | Low |
| API-14 | Scan diff returned every added/removed finding uncapped | Low |
| API-15 | Retention pruning and schedule firing ran sync DB + file I/O on the loop each tick | P1 |
| API-16 | `GET /api/settings/about` spawned three uncached scanner subprocesses per request | 2026-07-04 (TTL cache) |
| API-17 | Pagination envelope naming drift (`entries` vs `items` vs bare array) | #61, then 2026-07-25 (= QUA-9 / APIR-8) |
| API-18 | `FilterPresetIn.filters` an unbounded, unvalidated `dict[str, Any]`, no per-user cap | Low |
| API-19 | Diff `severity_delta` counts deduplicated keys (PLAUSIBLE) | Info-level |
| API-20 | `load_only` report queries had no `raiseload` guard against future drift | Info-level |
| API-21 | `delete_backup` unlinked the file before the DB commit | Info-level (= QUA-18) |

**`FE-*` — frontend (audit numbering; distinct from `P1/P2/P3-*`)**

| ID | Finding | Closed by |
|---|---|---|
| FE-1 | No global 401/session-expiry handling; stale authenticated shell after session death | P4 |
| FE-2 | API client hand-rolled, not generated from the OpenAPI schema | Logged deviation 2026-07-05 — kept; CLAUDE.md amended #65 (= R1) |
| FE-3 | Account/Backups/Schedules rendered naive-UTC timestamps as local | P4 (`lib/dates.ts`) |
| FE-4 | `BackupsPanel` restore file held in `useRef`; "No file selected" never updated | P4 |
| FE-5 | `ScheduledScansPanel` had no scanner/target matrix and no role gating | P4 |
| FE-6 | History fetch had an out-of-order response race | #62 (= P1-4) |
| FE-7 | Status polling recreated its interval every tick, no backoff, no hidden-tab pause | #62 (= P1-3) |
| FE-8 | 422 `detail` arrays surfaced as a generic "Request failed (422)" | #61 (= APIR-2) |
| FE-9 | Finding `primary_url` rendered as an anchor with no scheme validation | #55 (= P1-1) |
| FE-10 | Zero frontend tests and no test runner | #78 (Vitest), #78+ (jsdom/RTL harness) |
| FE-11 | `UsersPanel` docstring promised a reset-password action with no UI | Info-level |
| FE-12 | Forced-MFA enrollment stored `otpauth_uri` but never rendered it; no QR anywhere | Info-level |
| FE-13 | `UserMenu` logout swallowed a rejected `apiLogout` with no catch | Info-level |
| FE-14 | Date-range filters serialized local day boundaries as naive UTC | Info-level |
| FE-15 | `AuthenticationPanel` OIDC save had redundant secret handling + an unchecked cast | Info-level |
| FE-16 | Assorted small UI items (partial row-click, hidden token expiry, shared `busy` flag, …) | Info-level |

**`FEAT-*` — feature completeness vs. the plan**

| ID | Finding | Closed by |
|---|---|---|
| FEAT-1 | Uploaded image-tar (`docker save`) targets not implemented | De-scoped in docs (P3); on `ROADMAP.md` |
| FEAT-2 | "Scan running images" is enumerate-only; no multi-select launch | De-scoped (P3); on `ROADMAP.md` |
| FEAT-3 | Grype filesystem "uploaded archive" target missing | De-scoped (P3); on `ROADMAP.md` |
| FEAT-4 | Scanner-DB update schedule was a stored no-op | P3 (`workers/db_update.py`) |
| FEAT-5 | Offline / air-gapped DB import missing entirely | De-scoped (P3); on `ROADMAP.md` |
| FEAT-6 | Grype ignore rules stored but never applied at scan time | P3 (`scanners/grype_policy.py`) |
| FEAT-7 | Scanner default options/thresholds stored but applied nowhere | P3 (New Scan prefill) |
| FEAT-8 | VEX and `.trivyignore` are global-only, not the per-scan options the plan lists | Documented (P3) |
| FEAT-9 | Trivy server URL is deploy-time env only, not a Scanners setting | Documented |
| FEAT-10 | Key rotation has no admin-facing bulk re-encryption path | De-scoped (P3); on `ROADMAP.md` |
| FEAT-11 | `SCRYE_DOCKER_PROXY_URL` is a dead config knob | Info-level (= QUA-20) |
| FEAT-12 | SBOM generation unavailable for repository scans | Info-level |
| FEAT-13 | Restore's destructive confirm is a single click | Info-level |
| FEAT-14 | Audit log has an admin API but no UI | Info-level |

**`QUA-*` — backend code quality**

| ID | Finding | Closed by |
|---|---|---|
| QUA-1 | API-token minting capped against the *owner's* role, not the effective role → privilege escalation | P0 |
| QUA-2 | `ScanSchedule` stores credential references twice; the FK `SET NULL` is cosmetic | Low (= SCN-10) |
| QUA-3 | Five `ScannerSettings` fields editable via the API but consumed by nothing | P3 (= FEAT-4/6/7) |
| QUA-4 | Four near-identical secret-CRUD routers (~900 lines of parallel code) | **Deferred** — `ROADMAP.md` § Backend structural cleanup |
| QUA-5 | `_ALLOWED_SCANNERS` matrix duplicated with divergence | #61 (= APIR-10) |
| QUA-6 | Scan-from-template construction duplicated across two modules | Low |
| QUA-7 | Pagination params re-declared per endpoint with four different caps | Low |
| QUA-8 | Trivy version probe implemented twice | Low |
| QUA-9 | Three list-envelope conventions across phases | #61, then 2026-07-25 (= APIR-8) |
| QUA-10 | Create schemas strip/validate; Update schemas don't | #61 (= APIR-6) |
| QUA-11 | Notification secret rules asymmetric between create and update | #61 (= APIR-6) |
| QUA-12 | Two mask literals — 8-bullet `SECRET_MASK` vs 6-bullet `_URL_MASK` | Low |
| QUA-13 | Name-clash check idioms differ between routers | Trivial |
| QUA-14 | `filter_presets` router skips auditing and uses a different commit pattern | Trivial (plausibly intended) |
| QUA-15 | `run_schedule_now` left `last_run_at`/`last_status` stale (PLAUSIBLE) | #60 (= CON-17 / APIR-7) |
| QUA-16 | No type checker anywhere | **Deferred** — `ROADMAP.md` § Type-checking in CI (blocked on QUA-17) |
| QUA-17 | Annotation lies and `Any` seams (`-> object`, un-parameterized dicts, `**vars(p)` reflection) | **Open** — the blocker under QUA-16 |
| QUA-18 | `delete_backup` unlinks before commit; `create_backup` writes before insert | Info (= API-21) |
| QUA-19 | `backups.py` re-validates a passphrase length the schema already enforces | Trivial (unreachable) |
| QUA-20 | `Settings.docker_proxy_url` dead knob | Info (= FEAT-11) |
| QUA-21 | `backup/store.py` write/read/delete helpers exported but never called | Trivial |
| QUA-22 | `workers/schedules.py` `if created: db.commit() else: db.commit()` — identical branches | Trivial |
| QUA-23 | `conftest.py` built the schema via `create_all`, never the Alembic chain | P5 (`tests/test_migrations.py`) |
| QUA-24 | Coverage gaps — no test for the QUA-1 hole, no rate-limiter unit test | P5 + later back-fills |

**`DOC-*` — documentation deliverables**

| ID | Finding | Closed by |
|---|---|---|
| DOC-1 | README contradicted locked decision §6 on registry publishing | P3 |
| DOC-2 | README overstated unimplemented features (image-tar, multi-select, archive upload) | P3 |
| DOC-3 | README config table omitted `SCRYE_FORWARDED_ALLOW_IPS` and `SCRYE_SCANNER_CACHE_DIR` | Low |
| DOC-4 | Duplicate `## Releasing` heading in `CONTRIBUTING.md` | Low |
| DOC-5 | README advertised ECR/GCR/ACR helpers without noting the binaries aren't bundled | P3 |

---

### Documents this index replaces

All were deleted 2026-07-26; recover any of them with `git show <sha>:<path>` using the SHA in that
day's §14 entry.

| Path | What it held |
|---|---|
| `docs/reviews/00-summary.md` | The H/M/L severity backlog + Top-5; the summary-ID → source-ID map above |
| `docs/reviews/security-review.md` | `SEC-*` (review) |
| `docs/reviews/supply-chain-review.md` | `SC-*` |
| `docs/reviews/api-review.md` | `APIR-*` |
| `docs/reviews/frontend-review.md` | `P1-*`, `P2-*`, `P3-*` |
| `docs/reviews/concurrency-review.md` | `CON-*` |
| `docs/reviews/claude-md-compliance.md` | `D*`, `R*`, `LD*`/`HS*`/`GP*`/`CS*` |
| `docs/reviews/full-audit-2026-07-05.md` | `INF-*`, `SEC-*` (audit), `SCN-*`, `API-*`, `FE-*`, `FEAT-*`, `QUA-*`, `DOC-*` |
| `docs/reviews/STATUS.md` | Remediation tracker — the ID → resolving-PR column above came from its §3 ledger |
| `docs/reviews/fix-verification.md` | A 2026-07-13 verification pass, superseded by STATUS.md |
| `docs/reviews/phase3-finding2-resolution.md` | Pre-implementation design note for generic-host git auth (§14 2026-07-03 implements it) |
| `docs/reviews/CLEANUP-AUDIT.md` | The 2026-07-26 audit that produced this cleanup; its conclusions are the §14 entry |
| `docs/upgrades/python-3.14.md` | Python 3.14 scoping/handoff doc — superseded by §14 2026-07-25, and wrong on its central CVE premise |

---

## Build performance

Durable notes on why the image build is structured the way it is, and — critically —
what **not** to undo. Cross-referenced from `CLAUDE.md` § Coding standards → Build
performance, `docker/Dockerfile`, and the four build workflows. Read this before
restructuring the Dockerfile or the build workflows' caching.

### Why the build was slow, and what was changed (2026-07-07)

**Diagnosis (from actual CI logs, not the YAML).** The CI "image" work is four jobs:
`backend`, `frontend`, the amd64-only `image` (build + Trivy/Grype dogfood scan), and
`image-multiarch` (a `linux/amd64,linux/arm64` build-only check). The first three each
finish in 1–5 min; the ~12 min wall-clock was set almost entirely by **`image-multiarch`**.
Reading the buildkit step timings for a representative run:

- The arm64 leg runs the whole Dockerfile under **QEMU emulation**, which is 5–15× slower
  than the native amd64 leg per step (e.g. `apt-get install` 15s→333s, `npm ci` 26s→278s,
  `npm run build` 20s→328s, `pip install` 21s→231s under emulation).
- **The GHA layer cache was cold on essentially every run** (0 `CACHED` layers observed).
  Root cause: the recent cost-reduction pass partitioned the `type=gha` cache into per-build
  scopes (`amd64-ci`, `multiarch`, `dev-multiarch`) to stop them evicting each other under
  the repo's 10 GB budget — correct — but the `multiarch` scope is *written* only by rare
  events (a PR targeting `main`, or a release tag), so between its own invocations its
  entries age out and it is cold when it next runs. A cold cache means the QEMU-emulated
  arm64 layers are **re-executed from scratch** rather than restored — a `type=gha` cache
  *hit* skips executing a layer entirely, emulation cost included. So the recurring cost was
  the cold cache forcing a full emulated rebuild, more than QEMU per se.

**Changes made (this pass). No security posture was weakened** — the scanner-binary
checksum verification, the digest-pinned base images, and the non-root/hardened final stage
are all unchanged.

1. **Cross-seed the cache scopes (config-level, all four paths).** Each build path still
   *writes* exactly one scope (preserving the 10 GB budget partitioning), but now also
   *reads* the frequently-warm sibling scope, so a rarely-run build restores warm layers
   instead of rebuilding cold:
   - `.github/actions/build-image` gained an `extra-cache-scopes` input; a shell step composes
     `cache-from` = primary + extras (read many) while `cache-to` stays primary-only (write one).
   - `image-multiarch` (ci.yml) and the tagged-release build (publish.yml): write `multiarch`,
     additionally **read** `dev-multiarch`. `main`/release content is promoted `dev`, so the
     daily nightly build usually carries bit-identical base/apt/venv/npm-ci/arm64 layers.
   - the nightly (dev-nightly.yml): writes `dev-multiarch`, additionally reads `multiarch`
     (symmetric — a recent release seeds the nightly). The nightly is what keeps
     `dev-multiarch` warm for the others to read.
   - the amd64-only `image` job (ci.yml): writes `amd64-ci`, additionally reads `dev-multiarch`
     (its amd64 layers are reusable by an amd64-only build and are refreshed daily).
2. **Persist pip/npm download caches across builds (Dockerfile).** `pip install` and `npm ci`
   use BuildKit `--mount=type=cache` mounts (and `PIP_NO_CACHE_DIR` was dropped) so an
   unchanged dependency isn't re-downloaded when its install layer rebuilds. The cache lives
   in the mount, not the image layer, so nothing bloats the (discarded) builder stages or the
   final image. (Note: BuildKit cache mounts are not exported to `type=gha`, so this mainly
   speeds **local** rebuilds and dependency-change rebuilds; the CI recurring win is item 1.)
3. **Parallelize the scanner-binary downloads (Dockerfile).** The trivy/grype/syft
   download→verify→extract pipelines were sequential; they now run concurrently in background
   subshells joined by `wait`. This roughly halves a cold scanner stage, most visibly on the
   emulated arm64 leg. **Integrity is unchanged:** each binary is still fetched with its
   publisher's signed checksums file and verified with `sha256sum -c` *before* extraction, and
   a failure in any subshell (download error or checksum mismatch) propagates through `wait`
   under `set -e` to fail the build (verified under both dash and bash).

**Expected before/after per build path** (estimates; the dominant variable is cache warmth):

| Build path | Trigger | Before | After (typical) | Mechanism |
|---|---|---|---|---|
| `image` (amd64 dogfood) | every PR / main push | ~4 min | ~2–4 min | reads warm `dev-multiarch` amd64 layers |
| `image-multiarch` | PR→main / main push | ~10–12.5 min | **~3–5 min** when `dev-multiarch` is warm (common); ~10–12 min only on a genuine cold/dep-change build | reads the nightly's warm arm64 layers → arm64 layers CACHED, QEMU rebuild skipped |
| nightly `:dev` → GHCR | 04:00 UTC (skip if idle) | ~10–12 min | ~10–12 min first build after a dep change; faster when reading a warm `multiarch` | self-warms `dev-multiarch`; still pays QEMU on true cold builds |
| tagged release → Docker Hub | `v*.*.*` on main | ~10–12 min | ~3–5 min when `dev-multiarch` is warm | reads the nightly's warm arm64 layers |

**Not done (deliberately):** switching the arm64 leg to native `ubuntu-24.04-arm` hosted
runners (matrix + manifest merge). It would remove QEMU from cold builds too (~12→~4–5 min
even cold), but this is a **private** repo, so hosted arm64 runners bill per-minute and CI
would break if the runner label isn't enabled for the account. Left as a documented future
option, gated on that cost/availability decision. If revisited, it replaces item-1's reliance
on cache warmth for the cold case; it does not conflict with items 2–3.

### Invariants — do NOT undo these

- **Keep the multi-stage split.** `frontend-builder` (Node), `scanners` (curl/tar), and
  `backend-builder` (venv) are separate stages precisely so their toolchains never reach the
  final `runtime` image. Do **not** consolidate stages or install build tooling in `runtime` —
  it would bloat the image and enlarge its attack surface. The final stage copies only the
  built venv, the three verified scanner binaries, backend source (for Alembic), the compiled
  SPA `dist/`, the entrypoint, and the licenses.
- **Keep the layer ordering.** Dependency manifests (`package*.json`, `pyproject.toml`) are
  copied and installed **before** the app source is copied, so a code-only change doesn't
  invalidate the (expensive) dependency-install layers. Do not reorder these.
- **Keep the cache scopes partitioned by *writer*.** Each build path writes exactly one
  `type=gha` scope; cross-seeding is **read-only** (`cache-from`). Do **not** make two paths
  write the same scope or have a path write multiple scopes — that reintroduces the eviction
  churn under the 10 GB budget that the partitioning exists to prevent. Broadening `cache-from`
  is safe; broadening `cache-to` is not.
- **Keep download-then-verify-then-extract for the scanner binaries.** The parallelism is
  cosmetic to the integrity control; the ordering (fetch signed checksums → `sha256sum -c` →
  only then `tar -x`) and the digest-pinned bases are the supply-chain guarantee
  (`CLAUDE.md` § Hard security rules). Do not collapse to `curl | tar`, and do not drop the
  per-binary checksum step to save time.

**Deployment note (what must reach `main`).** The default branch is `main`; scheduled
workflows and tag-triggered workflows run from the **default branch's** copy. So:
`image` (amd64) Dockerfile/cache improvements take effect on `dev` PRs as soon as this merges
to `dev`; but `image-multiarch` (runs only on main-scoped events), the release build
(publish.yml, tag on `main`), and the nightly's own symmetric `multiarch` read
(dev-nightly.yml runs from `main`) only take effect once promoted to `main`. The nightly keeps
warming `dev-multiarch` from `main`'s existing copy regardless, so the cross-seed reads in the
other paths work as soon as those paths land on their trigger branches.

**Plan section affected:** §9.1 (image build), §0.6 (distribution/CI paths), process.
