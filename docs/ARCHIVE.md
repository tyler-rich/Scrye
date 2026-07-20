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
> fix, the multi-tier security-audit remediation, etc.), and the durable **Build performance**
> notes at the end.
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
7. **Backend runtime:** **Python 3.13.** (Originally locked to Python 3.12; revised to 3.13 in
   Phase 6 to resolve Grype-flagged CPython interpreter CVEs whose fixes are only available in
   3.13+ — see § Deviations for the full rationale.)

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
| Backend | **Python 3.13 + FastAPI + Pydantic v2** | Consistent with the Lacunarr stack; strong async subprocess handling. (Bumped from 3.12 in Phase 6 — see § Deviations.) |
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
  - Prereqs (Python 3.13, Node 20+, Docker, `trivy`/`grype`/`syft` for native runs).
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
**Why:** SC-12 (supply-chain review, LOW; omitted from `00-summary.md` — see `docs/reviews/STATUS.md`).
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
`docs/reviews/supply-chain-review.md` SC-12.

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
`docs/reviews/claude-md-compliance-review.md` D5.

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
change. `docs/reviews/supply-chain-review.md` SC-14; CLAUDE.md § Hard security rules (CIS baseline —
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
posture noted in `docs/reviews/STATUS.md` § 1).
**Plan section affected:** none — UI error-surfacing only; no schema, security-model, or job-model
change. `docs/reviews/frontend-review.md` P3-3.

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
_Back-fill entry (written 2026-07-20): records a fix that merged earlier (#53) without a §14 entry — see `docs/reviews/STATUS.md` § "ARCHIVE.md §14 gaps"._
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
local-path gate); `docs/reviews/security-review.md` SEC-1. No schema or job-model change.

### 2026-07-13 — Post-release — H9/SC-2 + H10/SC-3: SHA-pin all Actions, expand Dependabot, harden publish checkouts [back-fill]
_Back-fill entry (written 2026-07-20): records a fix that merged earlier (#57) without a §14 entry — see `docs/reviews/STATUS.md` § "ARCHIVE.md §14 gaps"._
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
hygiene / CI; `docs/reviews/supply-chain-review.md` SC-2/SC-3/SC-11, `claude-md-compliance.md` D3. No
schema, application-security-model, or job-model change.

### 2026-07-13 — Docs/Process — CLAUDE.md compliance-drift closure (D1, D2, R1–R6) [back-fill]
_Back-fill entry (written 2026-07-20): records a docs-only fix that merged earlier (#65) without a §14 entry — see `docs/reviews/STATUS.md` § "ARCHIVE.md §14 gaps"._
**What changed:** Documentation-only reconciliation (#65) closing the drift flagged in
`docs/reviews/claude-md-compliance.md`. **D1:** swept ~100 dead `docs/PLAN.md` → `docs/ARCHIVE.md`
cross-references across the backend, frontend, and Dockerfile (86 files, 106 references; section anchors
unchanged; historical files under `docs/ARCHIVE.md` and `docs/reviews/` intentionally keep their PLAN.md
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
_Back-fill entry (written 2026-07-20): records a fix that merged earlier (#59) without a §14 entry — see `docs/reviews/STATUS.md` § "ARCHIVE.md §14 gaps"._
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
**Plan section affected:** CLAUDE.md § Dependency hygiene (pinned dev deps); `docs/reviews/supply-chain-review.md`
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
**Plan section affected:** `docs/reviews/concurrency-review.md` CON-4; no change to §0/§4/§7. Also folds
in L24/SC-11 (add `persist-credentials: false` to `.github/workflows/ci.yml` checkouts) as a separate
commit — CLAUDE.md hard security rules / CI hygiene.

### 2026-07-13 — Docs/Process — Squash-merge authorship follows the GitHub profile display name (D4 doc-side)
**What changed:** `CLAUDE.md` § Git & PR conventions (the author-identity rule) now records that a
GitHub **squash-merge** authors the squashed commit with the merging account's *profile display name*,
which the repo-local `git config user.name "tyler-rich"` cannot override. The rule therefore requires
the GitHub profile display name to also read `tyler-rich` for the identity convention to hold
end-to-end.
**Why:** The CLAUDE.md compliance audit (`docs/reviews/claude-md-compliance.md`, GP4/D4) found 8
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
would misdescribe it. The CLAUDE.md compliance audit (`docs/reviews/claude-md-compliance.md`, GP6) noted
the promotion titles were not Conventional-Commit-shaped; recording the convention as a stated
exception — rather than "fixing" compliant release titles toward a prefix — matches the release process
already documented in `CONTRIBUTING.md` § Releasing.
**Plan section affected:** CLAUDE.md § Coding standards (Commits). Process/docs only; no build-phase,
schema, security-model, or job-model change.

### 2026-07-13 — Post-release — Security + supply-chain review batch (H11, M2–M5, M22–M26, L1–L4, L23)
**What changed:** Worked the security-review (`docs/reviews/security-review.md`, SEC-*) and
supply-chain-review (`docs/reviews/supply-chain-review.md`, SC-*) findings summarized in
`docs/reviews/00-summary.md`, one commit per finding:
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
`docs/reviews/frontend-review.md` (summarized in `docs/reviews/00-summary.md`), one commit each.
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
`docs/reviews/api-review.md` (summarized in `docs/reviews/00-summary.md`), one commit each:
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
(`docs/reviews/concurrency-review.md` CON-2, Top 5 #4) — a leaked credential-bearing process racing
`generic_repo_checkout`'s best-effort cache cleanup. Process-group kill is the review's recommended
fix and covers every current and future scanner child through the single `run_command` seam.
**Plan section affected:** none (bug fix; no schema, security-model, or job-model change).

### 2026-07-13 — Post-release — CON-1/CON-11/CON-3/SEC-2 remediation; worker seam gains optional hooks
**What changed:** Three coupled fixes from the 2026-07-12 review batch (`docs/reviews/00-summary.md`
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
(`docs/reviews/concurrency-review.md`), each landed as its own commit with a regression test:
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
**What changed:** First tier (P0) of the full-repo audit (`docs/reviews/full-audit-2026-07-05.md`,
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
`docs/upgrades/python-3.14.md`), not undertaken as a reaction to this scan.
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
