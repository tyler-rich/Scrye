# CLAUDE.md — Scrye

Operating contract for Claude Code on the **Scrye** project. Read this first, every session.
The historical build record and dated deviation log live in `docs/ARCHIVE.md`; forward-looking
work lives in `docs/ROADMAP.md`. This file is the condensed, authoritative ruleset. When this
file and the archive disagree, **this file wins**; if either conflicts with explicit user
instructions in the session, the user wins.

## When to ask vs. decide
**Pause and ask** before making any choice that affects the **security model**, the **data model/
schema**, or any **locked decision** (see below) — even if the plan is silent on it. For routine
implementation detail not covered by the plan (file layout within a module, helper naming, minor
library choices, test structure), **use your judgment and proceed** — just log it if it diverges
from anything the plan states (see Git & PR conventions).

---

## What Scrye is
A self-hosted, browser-based web UI that unifies the **Trivy** and **Grype** scanners. Trivy:
container images, git repos, and images in a Docker environment — scanning for CVEs, SBOM/OS
packages & dependencies, IaC misconfigurations, secrets, and licenses. Grype: vulnerability
scanning of images, filesystems, and SBOMs, including private registries. Results export to
CSV/Markdown/JSON; full history with filters; backup/restore; local + OIDC auth.

## Locked decisions — do not re-open
1. **Name:** Scrye.
2. **Stack:** React 18 + TS + Vite + **Mantine v7** frontend; **Python 3.13 + FastAPI + Pydantic
   v2 + SQLAlchemy 2.0 + Alembic** backend; **SQLite**. (Originally locked to Python 3.12;
   revised to 3.13 in Phase 6 — see `docs/ARCHIVE.md` § Deviations.)
3. **Job model:** single-container **in-process async worker** (DB-backed `scans` table +
   concurrency semaphore). **No Redis/arq in v1** — but keep a thin worker interface so it could be
   swapped later.
4. **"Scan running images":** **in v1**, via read-only **`docker-socket-proxy`**. The app **never**
   mounts `/var/run/docker.sock`.
5. **Secrets at rest:** **application-layer AES-256-GCM field encryption** (required). **SQLCipher
   is deferred** — leave a seam, don't build it.
6. **Distribution:** the image builds locally, and is **published to a single registry — GHCR
   (`ghcr.io/iamgroot60/scrye`) — with two tag roles**, both authenticated by the built-in
   `GITHUB_TOKEN` (`packages: write`). **No Docker Hub, no PAT, no long-lived registry secret
   anywhere in the repo.**
   - **Releases** (in `.github/workflows/publish.yml`): pushing a semver tag `v*.*.*` builds the
     multi-arch (amd64/arm64) image and pushes `ghcr.io/iamgroot60/scrye:<version>` (the tag
     **without** the leading `v`) **and** `ghcr.io/iamgroot60/scrye:latest`. Runs **only** when the
     tagged commit is on `main` (the job verifies main-ancestry and is guarded to the canonical
     repo).
   - **Dev** (in `.github/workflows/dev-nightly.yml`): a **nightly scheduled** build (04:00 UTC) of
     the `dev` branch pushes the single **moving** tag `ghcr.io/iamgroot60/scrye:dev` (always
     overwritten — not a version, not `latest`), so the current state of `dev` can be tested
     without cutting a release. The scheduled run **skips** the build when `dev` has had no new
     commits in the last 24h; a manual `workflow_dispatch` always builds. It does **not** build on
     every push/merge to `dev` — CI already lints/tests/builds each dev PR, and the image is
     batched to the nightly.
   No other registries or tags. `latest`/`:<version>` come **only** from tagged main releases;
   `:dev` **only** from the nightly build. The repo is **public**, so the GHCR package is public.
   Both publish paths are triggered outside `pull_request` (a tag push / a schedule), so a fork PR
   never has a secret-bearing publish path — this fully retires the fork-secrets gap the audit
   logged as INF-2; see `docs/ARCHIVE.md` § Deviations.
7. **Theme:** **teal** primary (`primaryColor: 'teal'`), first-class **light and dark** modes.

## Hard security rules (non-negotiable)
- **Never** hardcode credentials, secrets, API keys, tokens, or other sensitive values — not in
  code, config, Compose, image layers, tests, or logs. Use the secret-file master key + env vars
  for non-sensitive config.
- Stored secrets (registry creds, git tokens, OIDC client secret, API tokens) are **field-encrypted
  with AES-256-GCM**; the **master key comes from a Docker secret file** (`APP_SECRET_KEY_FILE`),
  never an env var or image layer.
- Secret API fields are **write-only**: accept on write, return a mask (`••••`) + timestamp on
  read. Never return or log plaintext secrets. Add a logging redaction filter.
- Decrypt secrets **only at scan time**, in memory, into **tmpfs** credential files, and shred them
  after the subprocess exits.
- All Docker work follows the **CIS Docker Benchmark baseline**: pinned image digests, non-root
  `USER`/`user:`, `cap_drop: ALL`, `no-new-privileges`, read-only root FS + tmpfs, resource limits,
  healthchecks, loopback port binding (`127.0.0.1`), restart policies, capped json-file logging.
  The only `docker.sock` mount permitted is on the read-only socket-proxy sidecar — document the
  residual risk.
- CSRF protection on state-changing endpoints; rate-limit auth endpoints; maintain an audit log.

## Git & PR conventions
- **Branching model:** `main` is protected and receives only tagged releases. `dev` is the
  integration branch for day-to-day work and external contributions. Feature/fix branches (e.g.
  `phase/PX` during the phased build, or a descriptive name for later work) are created **from
  `dev`** and PR'd **into `dev`** by default — not `main`. Promotion from `dev` to `main` is a
  separate, deliberate PR that only happens when the user explicitly requests it to cut a release
  (see `CONTRIBUTING.md` § Releasing). Everything else in this section — git identity, no
  attribution footers, CI-green, deviations logging — applies the same way, just against `dev` as
  the usual PR target instead of `main`.
- **Back-merge `main` into `dev` after anything lands on `main`.** Immediately after each `dev` →
  `main` promotion merges (and after any commit that lands on `main` directly — e.g. a Dependabot
  or hotfix PR targeted at `main`), back-merge `main` into `dev`
  (`git fetch origin main dev && git checkout dev && git merge origin/main && git push`) so the
  branches stay reconciled and `dev` doesn't accumulate phantom "behind" commits. Do it promptly,
  before `dev` diverges further — the merge is trivial then. Because promotions are **squash**-
  merged, `main`'s squashed copy of already-promoted work will conflict with `dev`'s newer versions
  of the same files; resolve every such conflict by **keeping `dev`'s side**. The only content a
  back-merge should actually introduce to `dev` is commits that landed on `main` independently of a
  promotion (e.g. a Dependabot bump). Verify this before committing: the net diff of the resolved
  merge against `dev`'s pre-merge tip should be exactly those independent changes and nothing else
  (`git diff <dev-before> HEAD`). This keeps the git-identity and no-attribution-footer rules; the
  merge commit is authored as the user like any other.
- **Landing a multi-PR stacked batch is not "merge each PR in order and walk away."** When a
  batch of stacked PRs (each built on the previous, e.g. child PR B based on parent PR A) is being
  landed:
  - **Retarget immediately after each parent merges.** The instant a parent PR merges, retarget
    every remaining child PR's base from the now-merged parent branch to the true target branch
    (e.g. `dev`) before doing anything else — do not leave a child pointed at a branch that is
    about to go stale or be deleted. Do this one merge at a time, not as a batch fix at the end.
  - **Re-state the full merge procedure before each merge, not just once at the start of the
    batch.** Treat each merge in the stack as its own operation: re-confirm the current base,
    the merge method, and the CI-green/identity/footer checks immediately before that specific
    merge — don't rely on a plan you stated for the batch several merges ago.
  - **Verify the target branch's actual content after the batch is reported complete.** Don't
    report "done" on the assumption that merge order alone flows every change through the stack
    into the target branch. Confirm it directly: `git fetch origin <target-branch>` and diff/log
    against what was claimed to have landed, or check a marker file/line unique to the final
    change, and only then report the batch complete.
- **CI is created in Phase 0 and is the gate for every PR thereafter, including Phase 0's own.**
  `.github/workflows/ci.yml` runs on every pull request and push to `main`: lint the backend
  (`ruff` + `black --check`) and frontend (ESLint + Prettier), and run `pytest` plus any frontend
  tests. CI never publishes — GHCR publishing lives in the separate `publish.yml` (releases) and
  `dev-nightly.yml` (nightly `:dev`) workflows (locked decision §6). A phase's PR is not done until
  its CI run is green — do not ask the user to merge a PR with failing or missing checks.
- **All commits and PRs are authored as the user, not as Claude.** Configure the local git identity
  for this repo (not global) before the first commit:
  `git config user.name "IamGroot60"` and
  `git config user.email "170156756+IamGroot60@users.noreply.github.com"`.
  Every commit and PR must use this name/email — no Claude/Anthropic identity, no co-author
  trailer, no bot account. This is in addition to, not instead of, the no-attribution-footer rule
  below.
- **Commit messages and PR descriptions contain no attribution footers.** Do not add
  "Generated by Claude Code," "Co-Authored-By: Claude," a session URL/link, or any similar
  signature. Commits and PRs should read as if written directly by the developer — plain
  Conventional Commit messages and a normal PR description (summary, what changed).
- **This has regressed before — treat it as untrusted until verified, every time.** Some tooling
  auto-appends an attribution footer or sets the commit author *after* you've composed the
  commit/PR, so believing you followed the rule is not sufficient. Before opening any PR, and
  again immediately after opening it, actively check the actual result, not your intent:
  `git log --format="%an <%ae>%n%B" -n <N>` for every commit on the branch, and the live PR
  description via the GitHub API/CLI (not just what you typed). If either shows a Claude/Anthropic
  identity, a co-author trailer, a session link, or any "Generated by..." text, fix it immediately
  — rebase and re-author with `--force-with-lease`, and edit the PR body directly — before telling
  the user the PR is ready. Do not report this check as passed without having actually run it this
  session.
- **Deviations from `docs/ARCHIVE.md` are recorded in `docs/ARCHIVE.md` itself, not only in the PR.**
  The moment you implement something differently than the plan specifies, say so inline in the
  session as you do it, and add a dated entry to the "Deviations from this plan" section at the
  bottom of `docs/ARCHIVE.md` (what changed, why, which phase). The PR description only needs a
  one-line pointer — e.g. "See `docs/ARCHIVE.md` § Deviations for changes made in this phase" — not
  the full explanation repeated there.

## Definition of done (per phase — all must hold before opening the PR)
1. Lint clean — `ruff` + `black` (Python), ESLint + Prettier (TypeScript).
2. Tests for the phase's logic exist and pass.
3. CI (`.github/workflows/ci.yml`) is green on the PR.
4. `docker compose up` brings the stack up and `/healthz` returns healthy.
5. Docs touched by the phase are updated (README/CONTRIBUTING/`.env.example` as applicable).
6. Any deviations are logged in `docs/ARCHIVE.md` § Deviations.
7. No secrets, keys, or tokens committed; `.gitignore` still covers all sensitive paths.
8. Commits/PR are **verified** — not assumed — to be under the user's git identity with no
   attribution footers, checked via `git log --format="%an <%ae>%n%B"` and the live PR body,
   immediately before and after opening the PR.

## Coding standards
- **Python:** type hints everywhere; module/function docstrings; `ruff` + `black` clean; meaningful
  `try/except` with descriptive errors (no bare excepts, no silent failures); Pydantic models for
  I/O validation; SQLAlchemy 2.0 typed style; Alembic migration for every schema change.
- **TypeScript:** ESLint + Prettier clean; typed API client generated from the FastAPI OpenAPI
  schema; Mantine components over bespoke CSS; no inline secrets or tokens.
- **Commits:** Conventional Commits. Small, reviewable changes. Update docs in the same PR as the
  code they describe.
- **Scanner faithfulness:** orchestrate the official `trivy`/`grype`/`syft` binaries and parse
  their **JSON** output. Persist raw scanner JSON as the source of truth; normalize into the
  shared findings model for display. Don't reimplement scanner logic.
- **Third-party license attribution:** Trivy, Grype, and Syft are all Apache-2.0 — bundling their
  unmodified binaries is fully permitted (no copyleft, no obligation to open-source Scrye). Apache
  2.0 §4 requires, for each bundled project: (a) a copy of the Apache-2.0 license text travels with
  the distribution; (c) copyright/patent/trademark/attribution notices from that project's Source
  form are retained (i.e. reproduce their actual `LICENSE`/`NOTICE` verbatim — don't paraphrase or
  summarize it); (d) if the project ships a `NOTICE` file, its content is carried forward — the
  license permits doing this via a NOTICE file, via documentation, or via an in-app display, so a
  docs-based approach is sufficient. Clause (b) — marking changed files — does not apply, since
  these binaries are pulled unmodified. Satisfy this by including each project's `LICENSE` (and
  `NOTICE`, if the upstream repo has one) as pulled at build time under `THIRD_PARTY_LICENSES/` in
  the image, and noting in the README ("Integrations" section) that Scrye bundles Trivy, Grype, and
  Syft under Apache-2.0 with a pointer to that directory. Do this once, whenever the Dockerfile
  first pulls these binaries.
- **Testing:** every phase ships with tests covering the logic it adds — don't defer testing to a
  later phase. The Phase 1 crypto/secrets and auth code **must** have direct unit tests (encrypt/
  decrypt round-trips, key derivation, write-only masking, that plaintext never appears in logs or
  API reads). Tests must pass before a phase's PR is opened.
- **Dependency hygiene:** pin every dependency to a specific, **current, actively-maintained**
  version (Python and npm) — pinned, not floating/`latest`, to preserve reproducibility. Do not
  pull in unvetted or abandoned packages. Choose versions with **no known vulnerabilities** at
  build time. Since Scrye is itself a vulnerability scanner, **dogfood it**: CI runs Trivy + Grype
  against Scrye's own image and resolves all *fixable* findings; only genuinely unfixable
  upstream/OS-level items may remain, and those are noted in the README.
- **Build performance:** `docker/Dockerfile` changes must preserve the multi-stage build
  boundaries and layer ordering that keep build times down and the final image slim — the
  stage split exists to keep the Node/Python build toolchains out of the runtime image, and
  dependency installs are ordered before app-code copies so a code-only change doesn't
  invalidate them. The CI build-cache scopes are partitioned deliberately (each build path
  *writes* one scope and only *reads* warm sibling scopes) to stay within the 10 GB GHA cache
  budget without going cold. **Read `docs/ARCHIVE.md` § Build performance before restructuring the
  Dockerfile, consolidating stages, reordering layers, or changing the build workflows' cache
  scopes** — those shapes are load-bearing for build time, not incidental.

## Required deliverables (build these — they are not optional)
- **`README.md`** — full docs: what it is, features, integrations, architecture, requirements,
  quick start, configuration (env vars + secret-key mechanism), usage per scan type, security
  model, backup/restore, roadmap, contributing/license links. (See plan §10.1.)
- **`CONTRIBUTING.md`** — full local-dev setup (backend venv + migrations + secret key + FastAPI
  reload; frontend Vite dev server; Compose integrated run; first-admin seed), project layout,
  coding standards, testing, PR process, private security-disclosure note. (See plan §10.2.)
- **`LICENSE`** — MIT unless told otherwise.
- **`.env.example`** — generate it in Phase 0–1 **from the Pydantic `Settings` model** (the config
  loader is the single source of truth — keep the two in sync). **Non-sensitive configuration vars
  only.** The master key is never included (it comes from the Docker secret file
  `APP_SECRET_KEY_FILE`); secrets like `OIDC_CLIENT_SECRET` appear as a named placeholder with a
  comment, never a real value. `.gitignore` already ignores `.env` but allows `.env.example`.
- **`.github/workflows/ci.yml`** — created in **Phase 0**, before that phase's own PR is opened.
  Runs lint + tests on every PR/push to `main`. No publish/registry job — GHCR publishing is
  handled separately by `.github/workflows/publish.yml` (releases) and `dev-nightly.yml` (nightly
  `:dev`) (locked decision §6). This is the gate every subsequent phase's PR must pass (see Git &
  PR conventions).
- **`THIRD_PARTY_LICENSES/`** — created in the Dockerfile phase (Phase 0), containing the
  Apache-2.0 `LICENSE` (and `NOTICE`, if present) for Trivy, Grype, and Syft, plus a README pointer
  to it. See Coding standards § Third-party license attribution.

## Build order
Follow the phased roadmap in `docs/ARCHIVE.md` §12 (Phase 0 scaffold → Phase 6 polish).
Create `README.md`, `CONTRIBUTING.md`, `LICENSE`, `.gitignore`, `.github/workflows/ci.yml`, and
`THIRD_PARTY_LICENSES/` in Phase 0 — CI must exist and pass before Phase 0's own PR is opened;
generate `.env.example` from the `Settings` model once the config layer exists (Phase 0–1); and
finalize the docs in Phase 6 to match the shipped app.

## Deployment target (context, not a build step)
DockHand stack on `<the deployment host>` (`<your-deployment-host-ip>`); env vars in the DockHand stack editor (no `.env` on
disk); app secret key as a Docker secret file; fronted by Caddy at `scrye.your-domain.tld`
(acme.sh wildcard TLS); persistent data under `/mnt/appdata/scrye`; OIDC via Pocket ID at
`https://pocket-id.your-domain.tld`.

## Out of scope for v1 (do not build)
arq/Redis scale-out · SQLCipher full-DB encryption. (Registry publishing to GHCR **is**
in scope — see locked decision §6.)
