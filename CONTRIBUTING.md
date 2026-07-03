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

- **Python 3.12**
- **Node 20+** (the image builds with Node 22)
- **Docker** + the **Compose v2** plugin (for the integrated run)
- For native scan runs in later phases: the **`trivy`**, **`grype`**, and
  **`syft`** binaries on your `PATH`

The repo is split into `backend/` (FastAPI) and `frontend/` (React + Vite). You
can run them natively side by side, or use Compose for an integrated stack.

### Backend (FastAPI)

```bash
cd backend

# Create and activate a virtualenv
python3.12 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install the app plus dev tooling (pinned versions)
pip install -e ".[dev]"

# Point at a local SQLite database (kept out of /data during dev)
export SCRYE_DATABASE_PATH="$PWD/scrye.dev.db"
export SCRYE_ENVIRONMENT=development
export SCRYE_CORS_ORIGINS=http://localhost:5173

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

First-run admin bootstrap is implemented in **Phase 1**. Once available, the
first account created on a fresh database is promoted to `admin`; subsequent
OIDC users default to `viewer` (configurable). This section will be expanded
when the auth layer lands.

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
│   │   ├── main.py      # FastAPI app: API + SPA serving
│   │   ├── api/         # routers (health, and more per phase)
│   │   ├── core/        # config, logging (security/crypto in Phase 1)
│   │   └── db/          # SQLAlchemy base + session
│   ├── alembic/         # migration environment + versions
│   ├── scripts/         # dev helpers (.env.example generator)
│   ├── tests/           # pytest suite
│   └── pyproject.toml   # deps + ruff/black/pytest config
├── frontend/
│   ├── src/
│   │   ├── theme.ts     # teal Mantine theme
│   │   ├── pages/       # route pages
│   │   ├── components/  # shared components
│   │   └── api/         # API client
│   ├── vite.config.ts
│   └── package.json
└── docker/
    ├── Dockerfile       # multi-stage, CIS-aligned
    ├── docker-compose.yml
    └── entrypoint.sh
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
- One branch per phase, named `phase/PX` (e.g. `phase/P0`); one PR per phase
  against `main`.
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

1. Fork (or branch) and create a `phase/PX` (or descriptive) branch.
2. Make your change with tests and updated docs.
3. Ensure the checklist holds:
   - [ ] `ruff` + `black` clean (Python), ESLint + Prettier clean (TypeScript)
   - [ ] Tests added/updated and passing
   - [ ] `docker compose up` brings the stack up and `/healthz` is healthy
   - [ ] Docs updated (README / CONTRIBUTING / `.env.example` as applicable)
   - [ ] No secrets, keys, or tokens committed
   - [ ] Any plan deviations logged in `docs/PLAN.md`
4. Open the PR against `main` with a clear summary of what changed.

---

## Reporting security issues

**Please do not open public issues for security vulnerabilities.** Report them
privately to the maintainers (e.g. via a private security advisory or direct
contact) so a fix can be prepared before disclosure. Include reproduction steps
and affected versions where possible.
