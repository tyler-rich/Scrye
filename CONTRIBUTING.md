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

- **Python 3.14** (3.14.6 or later)
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
python3.14 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install the app plus dev tooling (pinned versions)
pip install -e ".[dev]"

# Point at a local SQLite database (kept out of /data during dev)
export SCRYE_DATABASE_PATH="$PWD/scrye.dev.db"
export SCRYE_ENVIRONMENT=development
export SCRYE_CORS_ORIGINS=http://localhost:5173
# Local dev runs over plain HTTP. Cookies can't carry the Secure flag there —
# browsers discard a Secure cookie on an http:// page — so the app refuses to
# sign you in until you opt out of HTTPS enforcement explicitly:
export SCRYE_SESSION_COOKIE_SECURE=false

# Apply migrations
alembic upgrade head

# Run the API with autoreload
uvicorn app.main:app --reload --port 8089
```

The API is now at <http://localhost:8089>; check `GET /healthz` and the
interactive docs at `/docs`.

**Master key (local).** You don't have to create one: with no key supplied, the
app generates one on first start and persists it at
`SCRYE_APP_SECRET_KEY_AUTOGEN_FILE` (default `/data/app_secret_key`, which is not
writable in a native dev checkout — point it somewhere local):

```bash
export SCRYE_APP_SECRET_KEY_AUTOGEN_FILE="$PWD/.secrets/app_secret_key"   # never commit this
```

To use an explicitly generated key instead — which is what production does with a
Docker secret — set the higher-precedence variable:

```bash
mkdir -p .secrets
openssl rand -base64 48 > .secrets/app_secret_key
export SCRYE_APP_SECRET_KEY_FILE="$PWD/.secrets/app_secret_key"   # never commit this
```

Note that once `SCRYE_APP_SECRET_KEY_FILE` is set, a missing file there is a
startup error rather than a cue to generate one — an explicitly configured path is
treated as an assertion that the key lives there, because substituting a fresh key
would orphan every secret already encrypted under the real one. The same applies
if you copy `.env.example` to `.env`: comment its `SCRYE_APP_SECRET_KEY_FILE` line
out unless the file exists. The full precedence order and the rest of the
invariants are in `README.md` § The master key, and in
`backend/app/core/crypto.py:resolve_master_keys`.

**Regenerating `.env.example`.** The config loader is the single source of
truth. After changing the `Settings` model, regenerate the example file:

```bash
python -m scripts.gen_env_example            # writes ../.env.example
python -m scripts.gen_env_example --check    # CI-style check (no write)
```

**Backend dependency lock (`requirements.lock`).** `pyproject.toml` pins only the
direct runtime dependencies; the container image installs the fully-resolved,
hash-pinned transitive closure from `backend/requirements.lock` so every build is
reproducible and every package is hash-verified (`pip install --require-hashes`,
supply-chain finding SC-1). The lock is compiled with [`uv`](https://docs.astral.sh/uv/)
— a build/dev-time tool only; it is **not** added to the runtime image, and the
image still installs with plain `pip`. After changing any dependency in
`pyproject.toml`, regenerate the lock with the **pinned** uv version (CI runs the
identical command and fails if the committed lock drifts):

```bash
cd backend
pip install uv==0.8.17     # pin kept in sync with .github/workflows/ci.yml
uv pip compile pyproject.toml --group build --generate-hashes --python-version 3.14 \
  --output-file requirements.lock
```

`uv` reads the existing `requirements.lock` as a preference set, so a routine
regeneration only changes what a `pyproject.toml` edit actually requires — an
unrelated new transitive release on PyPI does not rewrite the lock.

The `--group build` flag includes the PEP 735 `build` dependency group
(`[dependency-groups]` in `pyproject.toml`), which pins the PEP 517 build
backend (`setuptools`) so it is hash-pinned in the lock alongside the runtime
deps rather than fetched unpinned during an isolated build (SC-12). Keep the
`setuptools` pin identical in `[dependency-groups].build` and
`[build-system].requires`; the image installs the lock and then builds the app
with `pip install --no-deps --no-build-isolation .`, reusing that hash-verified
`setuptools`.

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
docker compose -f docker/docker-compose.yml up --build
```

This builds the SPA, installs the backend, and serves everything from one
container on <http://127.0.0.1:8089>. The master key is generated inside the
container on first start (`/data/app_secret_key` on the `scrye_data` volume); the
compose file carries commented-out blocks for supplying it as a Docker secret
instead.

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
├── CHANGELOG.md         # Keep a Changelog format
├── SECURITY.md          # private vulnerability disclosure policy
├── LICENSE              # MIT
├── .env.example         # generated from the backend Settings model
├── .dockerignore        # keeps dev-only trees out of the build context
├── docs/
│   ├── ARCHIVE.md       # historical build record, dated deviation log (§14),
│   │                    #   finding-ID decoder (§15), build-performance notes
│   ├── ROADMAP.md       # forward-looking roadmap + known limitations
│   └── screenshots/     # images embedded in the README
├── backend/
│   ├── app/
│   │   ├── main.py      # FastAPI app: API + SPA serving, startup key check,
│   │   │                #   scan-worker lifecycle
│   │   ├── api/         # routers: health, metrics, auth, users, audit,
│   │   │                #   dashboard, scans, scan_schedules, registries,
│   │   │                #   git_credentials, docker_environments, settings,
│   │   │                #   trivy_policy, oidc, notifications, api_tokens,
│   │   │                #   backups; pagination.py holds the shared list envelope
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
│   │   ├── lib/         # pure helpers (polling, latest-wins guard, url, arrays)
│   │   ├── test/        # setup.ts (jsdom) + render.tsx (renderWithProviders)
│   │   └── api/         # API client (CSRF-aware fetch + multipart upload)
│   ├── eslint.config.js # type-aware ESLint (see § Coding standards)
│   ├── tsconfig.app.json
│   ├── vite.config.ts   # Vite + the two-project Vitest config
│   └── package.json
├── docker/
│   ├── Dockerfile       # multi-stage, CIS-aligned, multi-arch (amd64/arm64)
│   ├── docker-compose.yml
│   └── entrypoint.sh
├── ci/                  # dogfood self-scan triage allowlists (trivyignore, grype.yaml)
└── .github/
    ├── dependabot.yml   # pip, npm, docker, docker-compose, github-actions
    ├── actions/
    │   └── build-image/ # shared composite build action
    └── workflows/
        ├── ci.yml       # lint + tests, multi-arch build, Trivy/Grype self-scan
        ├── publish.yml  # tagged release → GHCR :<version> + :latest
        ├── dev-nightly.yml # nightly build of dev → GHCR :dev
        └── rescan.yml   # weekly re-scan of the published images
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

- ESLint + Prettier clean, and the type-check clean (`npm run build` runs
  `tsc -b` before `vite build`):
  ```bash
  cd frontend && npm run lint && npm run format:check && npm run build
  ```
- Prefer Mantine components over bespoke CSS; no inline secrets or tokens.

_Two strictness gates are enabled, and both fail CI._ They are not advisory —
a PR that trips either one does not build:

- **`noUncheckedIndexedAccess`** (`tsconfig.app.json`). Any indexed read —
  `arr[0]`, `record[key]` — is typed `T | undefined`. Handle the `undefined`
  case, hoist the lookup into a local, or encode the invariant in the type
  (e.g. `SCANNERS_FOR` is typed as a non-empty tuple
  `readonly [Scanner, ...Scanner[]]` so its first element is `Scanner` by
  construction). **Prefer that over a non-null assertion (`!`)** — the codebase
  currently has none, and `!` re-hides exactly what the flag exists to surface.
- **Type-aware ESLint** (`eslint.config.js`): `tseslint.configs.recommendedTypeChecked`
  with `projectService`, so rules that need type information are active across
  `src/` *and* the test files. The two you will meet most often are
  `no-floating-promises` and `no-misused-promises` — an `async` handler passed
  into an `onClick`/`onChange` slot that expects a `void` return. The house idiom
  is the `void` operator (`onClick={() => void save()}`), which the codebase
  already uses; make sure the handler actually handles its own errors rather than
  just silencing the rule.

_On `eslint-disable`._ Use it as a last resort, always as a targeted
`eslint-disable-next-line <rule>` — never a file-level or blanket disable, and
never for the two gates above — and always with a comment saying why the rule
does not apply here. There are nine in the tree today: two
`react-refresh/only-export-components` (each carrying its `--` justification) and
seven `react-hooks/exhaustive-deps` on deliberate mount-only effects. Adding to
that set needs a reason in review, not just a passing lint run.

**API conventions**

_List responses._ An endpoint that returns a **collection of persisted
resources** answers with the shared `{total, items}` envelope
(`backend/app/api/pagination.py`), whether or not it paginates:

```jsonc
{ "total": 42, "items": [ /* … */ ] }
```

- Paginated endpoints report the number of rows matching the query in `total`,
  which is what tells a client when the pages are exhausted.
- Unpaginated endpoints return one complete page via `full_page(...)`, where
  `total == len(items)` by construction.

Use `Page[ThingOut]` as the `response_model` and return `full_page([...])` —
don't hand-roll the envelope. On the frontend, `apiList<Thing>(path)` in
`src/api/client.ts` unwraps it, so client functions keep returning `Thing[]` and
page components are unaffected.

**The rule for a new endpoint:** _persisted resource collections_ — rows that
grow with usage, where a count is a meaningful answer and pagination is a
plausible future need — get the envelope. _Fixed enumerations_ and _live,
non-persisted data_ stay bare arrays, because `total` there answers a question
nobody asks. Enveloping the unpaginated lists also keeps adding pagination
additive later: a `limit`/`offset` parameter can be introduced without changing
a shape consumers already parse.

**Deliberate bare-array exceptions** (these are decisions, not drift — please
don't "fix" them):

| Endpoint | Why it stays bare |
|---|---|
| `GET /api/registries/options` | id/name value list for a `<Select>`, not a resource view |
| `GET /api/git-credentials/options` | same |
| `GET /api/notifications/events` | fixed enumeration of event names (`list[str]`) |
| `GET /api/docker-environments/{id}/images` | live enumeration proxied from a Docker daemon; nothing persisted |

`GET /api/scans` is a fifth bare array, but a different case: it is a **frozen
legacy contract** from Phase P4, superseded by `GET /api/scans/history`. It is
marked `deprecated` in OpenAPI and its shape will not change. New clients should
use `/api/scans/history`.

`backend/tests/test_list_envelope.py` asserts all of the above, so a regression
in either direction fails CI. Background: L13 / APIR-8 — see the finding-ID index
in [`docs/ARCHIVE.md` §15](docs/ARCHIVE.md#15-finding-id-index-decoder-for-14s-citations),
and §14's 2026-07-25 entry for the full rationale.

**Commits & branches**

- [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
  `docs:`, `chore:`, …). Small, reviewable changes.
- Branch from `dev`; one PR per change against `dev` (see § Branching model above). Use a short,
  descriptive branch name.
- Update docs in the same PR as the code they describe.
- Commit messages and PR descriptions carry **no AI-attribution footers**.
- The dated deviation log lives in [`docs/ARCHIVE.md`](docs/ARCHIVE.md) (the historical build
  record); forward-looking work is tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Testing

Every change ships with tests for the logic it adds — testing is not deferred to
a later phase.

```bash
# Backend
cd backend && pytest

# Frontend (unit tests + build + static checks)
cd frontend && npm test && npm run build && npm run lint && npm run format:check
```

Frontend tests run under **Vitest** (`npm test`); place them next to the code
they cover. The suite runs in two environments, chosen automatically by file
extension (see `frontend/vite.config.ts`):

- **`*.test.ts` → Node.** Pure-helper tests with no DOM (e.g. everything in
  `src/lib/`). This is the default, lightweight harness.
- **`*.test.tsx` → jsdom + React Testing Library.** Component and page render
  tests. jsdom provides a DOM, and `src/test/setup.ts` registers the jest-dom
  matchers, unmounts each tree after the test, and polyfills the browser APIs
  Mantine expects (`matchMedia`, `ResizeObserver`, `scrollIntoView`).

For a component/page test, render through the shared helper in
`src/test/render.tsx` rather than bare Testing Library — it wraps the subtree in
the providers every page assumes (`MantineProvider` + a router) and re-exports
`screen`, `userEvent`, `waitFor`, etc. so a test imports everything from one
place. Stub API modules and `useAuth` with `vi.mock` to drive the state you want:

```tsx
import { renderWithProviders, screen, userEvent } from '../test/render';
import { MyPage } from './MyPage';

vi.mock('../api/something', () => ({ loadThing: vi.fn() }));

it('renders and reacts to a click', async () => {
  const user = userEvent.setup();
  renderWithProviders(<MyPage />);
  expect(await screen.findByText(/expected/i)).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: /go/i }));
});
```

`src/pages/NewScanPage.test.tsx` is the reference example (it covers the P3-3
credential-load-failure warning and its retry).

Security-sensitive code (crypto/secrets, auth) must have direct unit tests:
encrypt/decrypt round-trips, key derivation, write-only masking, and proof that
plaintext never appears in logs or API reads.

---

## Pull request process

1. Fork (or branch) from `dev` and create a short, descriptively named branch.
2. Make your change with tests and updated docs.
3. Ensure the checklist holds:
   - [ ] `ruff` + `black` clean (Python); ESLint + Prettier + `tsc -b` clean (TypeScript)
   - [ ] Tests added/updated and passing (`pytest`; `npm test`)
   - [ ] `docker compose up` brings the stack up and `/healthz` is healthy
   - [ ] Docs updated (README / CONTRIBUTING / `.env.example` as applicable)
   - [ ] `requirements.lock` regenerated if `pyproject.toml` dependencies changed
   - [ ] Any deviation from the documented design logged in
         [`docs/ARCHIVE.md`](docs/ARCHIVE.md) § Deviations, dated
   - [ ] No secrets, keys, or tokens committed
4. Open the PR against `dev` (not `main` — see § Branching model above) with a clear summary of
   what changed. Commit messages and the PR body carry **no AI-attribution
   footers** — no "Generated by …" line, co-author trailer, or session link. If
   your tooling appends one, re-read the PR body after opening and strip it.
5. CI (`.github/workflows/ci.yml`) is the gate: lint + tests for both halves, the
   `.env.example` and `requirements.lock` drift checks, and the image build with
   the Trivy/Grype dogfood self-scan. A PR is not ready to merge until it is green.

---

## Releasing

Releasing is a deliberate, maintainer-initiated step. `main` is protected and only ever moves via
a release — it is never a target for routine contribution PRs. Contributors don't need to do
anything differently: keep branching from and PR'ing into `dev` as usual.

### Before you tag

Run through this first — every item is something that is permanent, or expensive to undo, once
the tag exists.

- [ ] **`CHANGELOG.md` `## [Unreleased]` reviewed for stale or false claims.** It ships *verbatim*
      as the release notes, so anything wrong in it becomes permanent published history. Re-check
      any claim that depends on the outside world (CVE status, upstream fix versions, issue
      numbers) against the current source rather than against what the entry said when written.
- [ ] **`THIRD_PARTY_LICENSES/` verified against the Trivy / Grype / Syft versions actually
      pulled at build time.** The version table in its `README.md` must match the `TRIVY_VERSION`
      / `GRYPE_VERSION` / `SYFT_VERSION` args in `docker/Dockerfile`, and each bundled
      `LICENSE`/`NOTICE` must be the file upstream ships at that tag (see `CLAUDE.md`
      § Third-party license attribution — Apache-2.0 §4 requires the real text, not a paraphrase).
- [ ] **Open Dependabot PRs triaged.** Land, close, or consciously defer each one; don't tag on
      top of an unreviewed queue. Check any bump against the locked decisions in `CLAUDE.md` §
      Locked decisions before merging — a grouped PR can quietly propose a major that a locked
      decision forbids. **Check each PR's base branch too**: security updates open against `main`,
      not `dev` — see § Dependabot security updates target `main` below.
- [ ] **`backend/requirements.lock` regenerated if backend deps moved.** Any change to
      `pyproject.toml`'s dependencies needs the pinned `uv pip compile --generate-hashes` rerun
      (see § Backend dependency lock); CI fails on lock drift, so catch it before the tag.

And immediately after the tag:

- [ ] **Back-merge `main` into `dev`** — see step 3 below and `CLAUDE.md` § Git & PR conventions.
- [ ] **Re-run `rescan.yml`** (Actions → *Run workflow*) to confirm the newly published image is
      clean. The weekly re-scan opens/updates a tracking issue against `:latest`; running it on
      demand is what closes out a release whose whole point was shipping accumulated fixes.

### Promoting `dev` to `main`, then back-merging

1. When `dev` is in a releasable state, the maintainer opens a **promotion PR** from `dev` into
   `main`. This PR must pass the same CI gate as any other before it can merge. A promotion PR
   is the one **exception** to the Conventional Commits rule above: title it plainly as
   `Promote dev to main: <what the release contains>`, not `feat:`/`fix:` — the merge subject names
   a release action, not a code change. Promotions are merged with a **regular merge commit** —
   *"Create a merge commit"*, never *"Squash and merge"* — so `main` keeps the individual commits
   and `dev`'s history stays an ancestor of `main`'s. Contribution PRs into `dev` are still
   squash-merged; this applies only to promotions. (Changed 2026-07-31 — see `docs/ARCHIVE.md` §14.)
2. Once the promotion PR merges, `main` is **tagged** (e.g. `v0.x.0`) to mark the release. The tag
   is what triggers publishing (below).
3. **Immediately back-merge `main` into `dev`** (`git fetch origin main dev && git checkout dev &&
   git merge origin/main && git push`) so `dev` shows 0 commits behind `main` again. With a
   merge-commit promotion `dev`'s tip is already an ancestor of `main`'s, so the back-merge of a
   promotion alone is a **fast-forward with nothing to resolve** — the whole point of the merge
   method. The only content it should actually bring into `dev` is anything that landed on `main`
   **independently** of the promotion (a Dependabot security update or a hotfix targeted at `main`).
   If that independent commit touched a file `dev` has also changed, resolve in favour of `dev` —
   but first confirm `dev` is genuinely ahead: check that no package or change is present on `main`
   and absent from `dev`, so the resolution cannot revert a fix that only `main` carries. Verify
   before committing that the net diff against `dev`'s pre-merge tip is exactly those independent
   changes and nothing else (`git diff <dev-before> HEAD`). Skipping this is what leaves `dev`
   accumulating phantom "behind" commits after each release.

   **This is also a pre-promotion check.** If something landed on `main` since the last promotion
   and was *replicated* on `dev` rather than merged, `main` is not an ancestor of `dev` and the
   promotion PR will open as `dirty`. Reconcile with the same merge before opening it — or if it is
   already open, push the reconciliation to `dev` and the PR updates itself. Do not close and reopen
   the PR.

### Dependabot security updates target `main`

`.github/dependabot.yml` sets `target-branch: dev` for every ecosystem, and that is honoured for
routine **version** updates. It is **not** honoured for **security** updates: those always open
against the repository's **default branch**, which here is `main`. That is a GitHub limitation —
the `target-branch` key is documented as applying to version updates only — not a mistake in this
repo's configuration, and no setting changes it.

The practical consequence is that a Dependabot PR's base branch is not predictable from the config,
so **read `baseRefName` before doing anything with one**. Two responses are correct:

- **Merge it into `main`**, then immediately back-merge `main` into `dev` (step 3 above). Note this
  puts a commit on `main` outside a release, which is allowed for security fixes but means `main`
  now carries something `dev` does not until the back-merge lands.
- **Close it and apply the bump on `dev` directly**, in a normal PR. Regenerate the lockfile with
  the real package manager (`npm update <pkg>`, `uv pip compile --generate-hashes`) rather than
  editing version strings by hand, so integrity hashes and the resolved tree stay consistent.

**Retargeting the PR to `dev` is not a third option.** Changing the base does not recompute the
diff against the new base, so the PR keeps the file contents it was opened with; once `dev` has
moved ahead of that snapshot, merging it can revert newer work — including, in the worst case, the
very fix the PR exists to deliver. It also does not re-run CI (`on: pull_request` does not fire on
`edited`), so the green check shown after a retarget is from the old base. PR #120 on 2026-07-31 is
the worked example: retargeted, went stale, closed, and the bump was reapplied on `dev` instead.

### What gets published

CI (`.github/workflows/ci.yml`) never publishes — it only lints, tests, and proves the image
builds for both architectures. Everything is published to a **single registry, GHCR**
(`ghcr.io/tyler-rich/scrye`), with two tag roles. Both authenticate with the built-in
`GITHUB_TOKEN` — there are **no Docker Hub or other registry secrets** in the repo.

- **Tagged releases → `:latest` + `:<version>`.** Handled by `.github/workflows/publish.yml`. Push
  a semantic-version tag `v*.*.*` on a commit that is on `main` (e.g.
  `git tag v1.4.0 && git push origin v1.4.0`). This builds the multi-arch (amd64/arm64) image and
  pushes it as `ghcr.io/tyler-rich/scrye:<version>` (the tag without its leading `v`, so `v1.4.0` →
  `ghcr.io/tyler-rich/scrye:1.4.0`) **and** `ghcr.io/tyler-rich/scrye:latest`. The job refuses to
  run unless the tagged commit is on `main`, so `:latest`/`:<version>` always come from a real
  release.

- **`:dev` (nightly build, not a release).** Handled by `.github/workflows/dev-nightly.yml`. A
  scheduled run at **04:00 UTC** builds the current `dev` branch multi-arch and pushes the single
  **moving** tag `ghcr.io/tyler-rich/scrye:dev`, always overwritten. The scheduled build is
  **skipped** when `dev` has had no new commits in the last 24h; a manual **Run workflow**
  (`workflow_dispatch`) always builds. It does **not** rebuild on every merge into `dev` — the
  per-PR CI already lints, tests, and builds the amd64 image, and the published image is batched to
  the nightly. This is **not** a stable release and **not** a version — it just mirrors HEAD-of-dev
  (`docker pull ghcr.io/tyler-rich/scrye:dev`) for testing. Use a `:<version>` tag (or `:latest`)
  for production.

**Provenance + SBOM.** Both publish paths attach a BuildKit SLSA provenance attestation and an
SPDX SBOM to the pushed image manifest (`provenance: mode=max` + `sbom: true`), and add a
**GitHub-signed** build-provenance attestation via `actions/attest-build-provenance`. Consumers can
verify a pulled image was built by this repo's workflow from a given commit with
`gh attestation verify oci://ghcr.io/tyler-rich/scrye:<tag> --owner tyler-rich`. The CI build-only
check (`push: false`) leaves both off.

Both publish workflows declare their own job-level `permissions`: `contents: read` + `packages:
write` (GHCR push) plus `id-token: write` + `attestations: write` (only for the signed provenance
attestation). So **Settings → Actions → General → Workflow permissions** can stay on the restrictive
read-only default (an explicit block takes precedence and is not capped by the repo default);
`ci.yml` declares only `contents: read` and never publishes. The repo is **public**, so the GHCR
package is public — no per-package visibility change is needed. Because both publish paths are
triggered outside `pull_request` (a tag push, and a schedule), a fork's pull request never has a
secret-bearing publish path — going public does not reopen the old fork-secrets gap (audit INF-2).

---

## Reporting security issues

**Please do not open public issues for security vulnerabilities.** Report them
privately via GitHub's private vulnerability reporting (the **Report a
vulnerability** button on the repository's **Security** tab) — see
[SECURITY.md](./SECURITY.md) for the full policy — so a fix can be prepared before
disclosure. Include reproduction steps
and affected versions where possible.
