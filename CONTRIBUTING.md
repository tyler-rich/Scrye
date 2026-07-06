# Contributing to Scrye

Thanks for your interest in Scrye! This guide covers local development, project
layout, coding standards, testing, and the pull-request process.

## Code of conduct

Be respectful, constructive, and collaborative. Assume good faith, keep
discussion focused on the work, and help maintain a welcoming project for
everyone.

---

## Local development environment

### Prerequisites

- **Python 3.13**
- **Node 20+** (the image builds with Node 22)
- **Docker** + the **Compose v2** plugin (for the integrated run; Buildx for a
  multi-arch image build)
- For native scan runs: the **`trivy`**, **`grype`**, and **`syft`** binaries on
  your `PATH`

The repo is split into `backend/` (FastAPI) and `frontend/` (React + Vite). You
can run them natively side by side, or use Compose for an integrated stack.

> **Windows contributors — line endings.** Shell scripts (`*.sh`, notably
> `docker/entrypoint.sh`) **must** stay LF-only. A CRLF checkout writes a
> `#!/bin/sh\r` shebang, and the Linux kernel then looks for an interpreter
> literally named `/bin/sh\r`, so the container dies at start with
> `exec /app/entrypoint.sh: no such file or directory`. The repo's
> `.gitattributes` pins these files to `eol=lf` and the image build strips any
> stray CRs as a backstop, so a normal `git clone` is fine. Just don't let your
> editor or a global `core.autocrlf=true` rewrite them — if a script ever comes
> back with `\r\n`, run `git add --renormalize .` to restore LF.

### Backend (FastAPI)

```bash
cd backend

# Create and activate a virtualenv
python3.13 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install the app plus dev tooling (pinned versions)
pip install -e ".[dev]"

# Point at a local SQLite database (kept out of /data during dev)
export SCRYE_DATABASE_PATH="$PWD/scrye.dev.db"
export SCRYE_ENVIRONMENT=development
export SCRYE_CORS_ORIGINS=http://localhost:5173
# Local dev runs over plain HTTP, so cookies can't carry the Secure flag:
export SCRYE_SESSION_COOKIE_SECURE=false

# Apply migrations
alembic upgrade head

# Run the API with autoreload
uvicorn app.main:app --reload --port 8089
```

The API is now at <http://localhost:8089>; check `GET /healthz` and the
interactive docs at `/docs`.

**Master key (local).** The master key is read from the file at
`SCRYE_APP_SECRET_KEY_FILE`. For native development, generate one and point the
variable at it (it is used by the crypto module from Phase 1 onward):

```bash
mkdir -p .secrets
openssl rand -base64 48 > .secrets/app_secret_key
export SCRYE_APP_SECRET_KEY_FILE="$PWD/.secrets/app_secret_key"   # never commit this
```

**Regenerating `.env.example`.** The config loader is the single source of
truth. After changing the `Settings` model, regenerate the example file:

```bash
python -m scripts.gen_env_example            # writes ../.env.example
python -m scripts.gen_env_example --check    # CI-style check (no write)
```

### Frontend (React + Vite)

```bash
cd frontend
npm install
npm run dev        # Vite dev server on http://localhost:5173
```

The dev server **proxies** `/healthz` and `/api` to the backend at
`http://localhost:8089` (override with `SCRYE_DEV_API_TARGET`), so the browser
sees a single same-origin app. Run the backend (above) at the same time.

### Integrated run with Compose

```bash
mkdir -p docker/secrets
openssl rand -base64 48 > docker/secrets/app_secret_key
docker compose -f docker/docker-compose.yml up --build
```

This builds the SPA, installs the backend, and serves everything from one
container on <http://127.0.0.1:8089>.

### Seeding a first admin user

On a fresh database Scrye shows a one-time **setup screen**: open the app in a
browser and create the first account — it becomes `admin` and is signed in
immediately. The underlying endpoint works exactly once:

```bash
curl -X POST http://localhost:8089/api/auth/setup \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "<a strong passphrase, 12+ chars>"}'
```

Once any account exists the endpoint (and screen) permanently return
409/redirect to login. Additional users are created by an admin via
`POST /api/users` or the *Settings → Users & roles* UI. OIDC users are
auto-provisioned (when enabled) with the configured default role.

---

## Branching model

- **`main`** is protected and only ever receives tagged releases — it does not take direct
  commits or day-to-day PRs.
- **`dev`** is the integration branch. Fork or branch from `dev`, and open pull requests
  **against `dev`**, not `main`.
- A release is a separate, deliberate step: `dev` is promoted to `main` via its own PR, then
  `main` is tagged. See § Releasing below.

---

## Project layout

```
scrye/
├── CLAUDE.md            # operating contract for AI-assisted work
├── README.md            # user-facing documentation
├── CONTRIBUTING.md      # this file
├── LICENSE              # MIT
├── .env.example         # generated from the backend Settings model
├── docs/
│   └── PLAN.md          # detailed build specification + deviation log
├── backend/
│   ├── app/
│   │   ├── main.py      # FastAPI app: API + SPA serving, startup key check,
│   │   │                #   scan-worker lifecycle
│   │   ├── api/         # routers: health, metrics, auth, users, audit,
│   │   │                #   dashboard, scans, scan_schedules, registries,
│   │   │                #   git_credentials, docker_environments, settings,
│   │   │                #   trivy_policy, oidc, notifications, api_tokens, backups
│   │   ├── auth/        # passwords (argon2id), sessions, RBAC/CSRF+token deps,
│   │   │                #   OIDC client, TOTP MFA, API-token minting
│   │   ├── core/        # config, crypto (AES-GCM envelope), secret_store,
│   │   │                #   app_settings, passphrase KDF, cron, dashboard,
│   │   │                #   metrics, notifications + notification_dispatch,
│   │   │                #   retention, system_info, logging/redaction, masking,
│   │   │                #   rate limiting, audit helper, artifact store, proxies
│   │   ├── scanners/    # Trivy/Grype/Syft orchestration + JSON normalization,
│   │   │                #   credential materialization, target resolution,
│   │   │                #   Trivy VEX/ignore policy materialization
│   │   ├── backup/      # portable bundle build/restore + secret re-wrap,
│   │   │                #   on-disk store, scheduled-backup logic
│   │   ├── workers/     # in-process async scan worker, backup scheduler,
│   │   │                #   maintenance scheduler (scheduled scans + retention)
│   │   └── db/          # SQLAlchemy base + session + models/
│   ├── alembic/         # migration environment + versions
│   ├── scripts/         # dev helpers (.env.example generator)
│   ├── tests/           # pytest suite
│   └── pyproject.toml   # deps + ruff/black/pytest config
├── frontend/
│   ├── src/
│   │   ├── theme.ts     # teal Mantine theme
│   │   ├── auth/        # AuthContext (login state + actions)
│   │   ├── pages/       # dashboard, login, setup, account, scans
│   │   │                #   (list/new/detail), settings (all tabs)
│   │   ├── components/  # shared components (toggle, user menu, badges),
│   │   │                #   settings/ panels
│   │   └── api/         # API client (CSRF-aware fetch + multipart upload)
│   ├── vite.config.ts
│   └── package.json
├── docker/
│   ├── Dockerfile       # multi-stage, CIS-aligned, multi-arch (amd64/arm64)
│   ├── docker-compose.yml
│   └── entrypoint.sh
├── ci/                  # dogfood self-scan triage allowlists (trivyignore, grype.yaml)
└── .github/workflows/
    └── ci.yml           # lint + tests, multi-arch build, Trivy/Grype self-scan
```

---

## Coding standards

**Python**

- Type hints everywhere; module and function docstrings.
- `ruff` + `black` clean (config in `backend/pyproject.toml`):
  ```bash
  cd backend && ruff check . && black --check .
  ```
- Meaningful `try/except` with descriptive errors — no bare excepts, no silent
  failures.
- Pydantic models for I/O validation; SQLAlchemy 2.0 typed style; an Alembic
  migration for **every** schema change.
- **Never** hardcode secrets, keys, or tokens — not in code, config, tests, or
  logs.

**TypeScript**

- ESLint + Prettier clean:
  ```bash
  cd frontend && npm run lint && npm run format:check
  ```
- Prefer Mantine components over bespoke CSS; no inline secrets or tokens.

**Commits & branches**

- [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
  `docs:`, `chore:`, …). Small, reviewable changes.
- Branch from `dev`; one PR per change against `dev` (see § Branching model above). During the
  phased build, branches are named `phase/PX` (e.g. `phase/P0`); afterwards, use a short
  descriptive branch name.
- Update docs in the same PR as the code they describe.
- Commit messages and PR descriptions carry **no AI-attribution footers**.
- Any divergence from `docs/PLAN.md` is recorded in that file's
  "Deviations from this plan" section at the time it happens.

---

## Testing

Every change ships with tests for the logic it adds — testing is not deferred to
a later phase.

```bash
# Backend
cd backend && pytest

# Frontend (build + static checks)
cd frontend && npm run build && npm run lint && npm run format:check
```

Security-sensitive code (crypto/secrets, auth) must have direct unit tests:
encrypt/decrypt round-trips, key derivation, write-only masking, and proof that
plaintext never appears in logs or API reads.

---

## Pull request process

1. Fork (or branch) from `dev` and create a `phase/PX` (or descriptive) branch.
2. Make your change with tests and updated docs.
3. Ensure the checklist holds:
   - [ ] `ruff` + `black` clean (Python), ESLint + Prettier clean (TypeScript)
   - [ ] Tests added/updated and passing
   - [ ] `docker compose up` brings the stack up and `/healthz` is healthy
   - [ ] Docs updated (README / CONTRIBUTING / `.env.example` as applicable)
   - [ ] No secrets, keys, or tokens committed
   - [ ] Any plan deviations logged in `docs/PLAN.md`
4. Open the PR against `dev` (not `main` — see § Branching model above) with a clear summary of
   what changed.

---

## Releasing

`main` is protected and only ever moves via a deliberate, maintainer-initiated release — it is
never a target for routine contribution PRs.

1. When `dev` is in a releasable state, the maintainer opens a **promotion PR** from `dev` into
   `main`. This PR must pass the same CI gate as any other before it can merge.
2. Once the promotion PR merges, `main` is **tagged** (e.g. `v0.x.0`) to mark the release.
3. Contributors don't need to do anything differently for this — keep branching from and PR'ing
   into `dev` as usual; release promotion is handled separately by the maintainer.

---

## Releasing

CI (`.github/workflows/ci.yml`) never publishes — it only lints, tests, and proves the image
builds for both architectures. Publishing is split across two registries with two distinct roles:

- **Tagged releases → Docker Hub (stable).** Handled by `.github/workflows/publish.yml`, which
  authenticates with the `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` repository secrets. Push a
  semantic-version tag `v*.*.*` on a commit that is on `main` (e.g.
  `git tag v1.4.0 && git push origin v1.4.0`). This builds the multi-arch (amd64/arm64) image and
  pushes it as `<dockerhub-user>/scrye:<version>` (the tag without its leading `v`, so `v1.4.0` →
  `<dockerhub-user>/scrye:1.4.0`) **and** `<dockerhub-user>/scrye:latest`. The job refuses to run if
  the tagged commit is not on `main`, so `:latest` and `:<version>` always come from a real
  release. Docker Hub is used **only** for releases.

- **`:dev` → GHCR (nightly build, not a release).** Handled by
  `.github/workflows/dev-nightly.yml`, which authenticates to GHCR with the built-in
  `GITHUB_TOKEN` (no Docker Hub secret). A scheduled run at **04:00 UTC** builds the current `dev`
  branch multi-arch and pushes the single **moving** tag `ghcr.io/iamgroot60/scrye:dev`, always
  overwritten. The scheduled build is **skipped** when `dev` has had no new commits in the last
  24h; a manual **Run workflow** (`workflow_dispatch`) always builds. It does **not** rebuild on
  every merge into `dev` — the per-PR CI already lints, tests, and builds the amd64 image, and the
  published image is batched to the nightly. This is **not** a stable release and **not** a version
  — it just mirrors HEAD-of-dev (`docker pull ghcr.io/iamgroot60/scrye:dev`) for testing. Do not
  treat `:dev` as production-ready; use a `:<version>` tag (or `:latest`) for that.

  Two repo settings back this path. **Settings → Actions → General → Workflow permissions** can stay
  on the restrictive **Read repository contents and packages permissions** (read-only) default —
  GHCR push does **not** need the repo-wide default to allow write. `dev-nightly.yml` declares its
  own `permissions: { contents: read, packages: write }` block, which overrides the read-only
  default for that workflow (an explicit block takes precedence and is not capped by the default);
  `publish.yml` and `ci.yml` likewise declare their own (`contents: read`). Second, after the first
  nightly push, confirm the GHCR package `ghcr.io/iamgroot60/scrye` is **Private** (it inherits the
  repository's visibility).

---

## Reporting security issues

**Please do not open public issues for security vulnerabilities.** Report them
privately to the maintainers (e.g. via a private security advisory or direct
contact) so a fix can be prepared before disclosure. Include reproduction steps
and affected versions where possible.
