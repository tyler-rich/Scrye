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
2. **Stack:** React 18 + TS + Vite + **Mantine v7** frontend; **Python 3.14 + FastAPI + Pydantic
   v2 + SQLAlchemy 2.0 + Alembic** backend; **SQLite**. The runtime floor is **3.14.6** —
   never 3.14.0–3.14.4, whose incremental GC leaked resident memory in long-running servers
   (reverted in 3.14.5). (Originally locked to Python 3.12; revised to 3.13 in Phase 6, then to
   3.14 post-v1 — see `docs/ARCHIVE.md` § Deviations.)
3. **Job model:** single-container **in-process async worker** (DB-backed `scans` table +
   concurrency semaphore). **No Redis/arq in v1** — but keep a thin worker interface so it could be
   swapped later.
4. **"Scan running images":** **in v1**, via read-only **`docker-socket-proxy`**. The app **never**
   mounts `/var/run/docker.sock`.
5. **Secrets at rest:** **application-layer AES-256-GCM field encryption** (required). **SQLCipher
   is deferred** — leave a seam, don't build it.
6. **Distribution:** the image builds locally, and is **published to a single registry — GHCR
   (`ghcr.io/tyler-rich/scrye`) — with two tag roles**, both authenticated by the built-in
   `GITHUB_TOKEN` (`packages: write`). **No Docker Hub, no PAT, no long-lived registry secret
   anywhere in the repo.**
   - **Releases** (in `.github/workflows/publish.yml`): pushing a semver tag `v*.*.*` builds the
     multi-arch (amd64/arm64) image and pushes `ghcr.io/tyler-rich/scrye:<version>` (the tag
     **without** the leading `v`) **and** `ghcr.io/tyler-rich/scrye:latest`. Runs **only** when the
     tagged commit is on `main` (the job verifies main-ancestry and is guarded to the canonical
     repo).
   - **Dev** (in `.github/workflows/dev-nightly.yml`): a **nightly scheduled** build (04:00 UTC) of
     the `dev` branch pushes the single **moving** tag `ghcr.io/tyler-rich/scrye:dev` (always
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
  with AES-256-GCM**; the **master key comes from a file — never an env var or image layer**. The
  **Docker secret file** (`APP_SECRET_KEY_FILE`) is the recommended production mechanism and keeps
  its precedence over everything else; when no secret is supplied, the key is **generated on first
  launch** and persisted mode-0600 at `APP_SECRET_KEY_AUTOGEN_FILE` (default `/data/app_secret_key`)
  so a fresh deployment starts without pre-seeding a secret. **An existing key file is always used
  and never replaced:** a key file that exists but fails to load stops startup rather than being
  regenerated, because a second key silently orphans every stored secret. See `docs/ARCHIVE.md`
  § Deviations (2026-07-29) and README § The master key.
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
  before `dev` diverges further — the merge is trivial then. Because promotions are merged with a
  **regular merge commit** (see below), `dev`'s tip is already an ancestor of `main`'s, so the
  back-merge of a promotion alone is a **fast-forward with nothing to resolve**. The only content a
  back-merge should actually introduce to `dev` is commits that landed on `main` independently of a
  promotion (e.g. a Dependabot security bump). If such a commit touched a file `dev` also changed,
  resolve by **keeping `dev`'s side** — but first confirm `dev` is genuinely ahead, i.e. that
  nothing is present on `main` and absent from `dev`, so the resolution cannot revert a fix only
  `main` carries. Verify before committing: the net diff of the resolved merge against `dev`'s
  pre-merge tip should be exactly those independent changes and nothing else
  (`git diff <dev-before> HEAD`). This keeps the git-identity and no-attribution-footer rules; the
  merge commit is authored as the user like any other.
- **`dev` → `main` promotions are merged with a regular merge commit, never squashed.** Use
  GitHub's *"Create a merge commit"* — not *"Squash and merge"*. A squash replaces `dev`'s commits
  with one new commit that has no ancestry link to them, so `main` and `dev` diverge the instant the
  promotion lands and every subsequent back-merge is a conflict-resolution exercise against `main`'s
  squashed copy of work `dev` already has. A merge commit keeps `dev`'s history as an ancestor of
  `main`'s: the back-merge fast-forwards, `main` keeps the individual commits a release is supposed
  to preserve, and a later promotion cannot open `dirty` merely because the previous one squashed.
  **Contribution/feature PRs into `dev` are still squash-merged** — this applies only to promotions.
  (Changed 2026-07-31; promotions were squash-merged before. See `docs/ARCHIVE.md` §14.)
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
- **Retargeting a stacked child PR after its parent was squash-merged requires
  `git rebase --onto`, not just changing the base in the UI.** A squash-merge does not preserve
  the parent branch's commits — it replaces them with one new commit on the target branch — so the
  child's original commits are orphaned. Flipping the base in the GitHub UI does **not** re-parent
  them: GitHub recomputes the merge base against the new target, finds the old parent commits
  absent from its history, and falls back to a much older common ancestor, so the PR's diff
  balloons to include everything the parent already landed. Rebase the child onto the true target
  first, then change the base:
  `git fetch origin <target> && git rebase --onto origin/<target> <old-parent-branch> <child-branch>`
  followed by `git push --force-with-lease`. **Verify the diff after retargeting, every time** — a
  child PR that suddenly shows its parent's files is this failure, not a conflict, and merging it
  would re-apply already-landed work.
- **A base-branch change alone never re-runs CI.** `on: pull_request` with no explicit `types:`
  defaults to `opened`, `synchronize`, and `reopened` — it does **not** include `edited`, and
  changing a PR's base is an `edited` event, not a `synchronize`. So after retargeting a stacked
  PR the checks shown are the ones from the *old* base and are stale, even though they read green.
  Either push a commit (any `synchronize` re-triggers the full workflow), re-run the workflow
  manually, or close-and-reopen the PR — and **never treat a green check from before a base change
  as the CI gate** required by § Definition of done item 3. A workflow that genuinely needs to
  react to retargeting must opt in explicitly with
  `on: pull_request: types: [opened, synchronize, reopened, edited]`.
- **CI is created in Phase 0 and is the gate for every PR thereafter, including Phase 0's own.**
  `.github/workflows/ci.yml` runs on every pull request and push to `main`: lint the backend
  (`ruff` + `black --check`) and frontend (ESLint + Prettier), and run `pytest` plus the frontend
  Vitest suite (`npm test`). CI never publishes — GHCR publishing lives in the separate
  `publish.yml` (releases) and
  `dev-nightly.yml` (nightly `:dev`) workflows (locked decision §6). A phase's PR is not done until
  its CI run is green — do not ask the user to merge a PR with failing or missing checks.
- **All commits and PRs are authored as the user, not as Claude.** Configure the local git identity
  for this repo (not global) before the first commit:
  `git config user.name "tyler-rich"` and
  `git config user.email "170156756+tyler-rich@users.noreply.github.com"`.
  Every commit and PR must use this name/email — no Claude/Anthropic identity, no co-author
  trailer, no bot account. This is in addition to, not instead of, the no-attribution-footer rule
  below. Note: GitHub authors a **squash-merge** commit — and the **merge commit** a promotion
  produces — as the merging account's *profile display name*, which the repo-local
  `git config user.name` cannot override. So the GitHub profile display name must also read
  `tyler-rich` for this rule to hold end-to-end on anything merged through the web UI. (A merge
  commit leaves the individual promoted commits' own authorship intact, so only the merge commit
  itself is affected. See `docs/ARCHIVE.md` § Deviations, 2026-07-13 squash-merge authorship.)
- **Commit messages and PR descriptions contain no attribution footers.** Do not add
  "Generated by Claude Code," "Co-Authored-By: Claude," a session URL/link, or any similar
  signature. Commits and PRs should read as if written directly by the developer — plain
  Conventional Commit messages and a normal PR description (summary, what changed).
- **After opening any PR, re-check the *live* PR body and strip any auto-appended attribution
  footer.** In this environment tooling has appended an attribution footer (e.g. "Generated by
  Claude Code", a "🤖 Generated with…" line, a session/`claude.ai` link) to the PR **body** on
  essentially every PR in this effort — often *after* a clean description was submitted, so a body
  that looked correct when composed is not proof. Therefore, immediately after opening (or editing)
  a PR, fetch the live body via the GitHub API/CLI (not what you typed) and remove any such footer:
  the PR body must carry **no** Claude/Anthropic identity, co-author trailer, session URL, or
  "Generated by…"/"Generated with…" text — the same no-attribution standard the commit-authorship
  rule holds for commits. Edit the PR body in place to strip it **before** telling the user the PR
  is ready, and don't report this as done without having actually re-read the live body this
  session.
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
- **TypeScript:** ESLint + Prettier clean; hand-written typed API client in `frontend/src/api/`
  (generating one from the FastAPI OpenAPI schema remains a possible future improvement — see
  `docs/ARCHIVE.md` § Deviations, FE-2); Mantine components over bespoke CSS; no inline secrets
  or tokens.
- **Commits:** Conventional Commits. Small, reviewable changes. Update docs in the same PR as the
  code they describe. (Exception: `dev` → `main` **promotion** PRs use a plain
  `Promote dev to main: …` title rather than a Conventional-Commit prefix — see
  `CONTRIBUTING.md` § Releasing and `docs/ARCHIVE.md` § Deviations, 2026-07-13 promotion-title.)
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
  API reads). The backend is comprehensively covered with `pytest`; the frontend uses **Vitest**
  (`npm test`), added post-v1 and covering the shared `frontend/src/lib/` helpers `polling`, `url`,
  `arrays`, and `latest` today, expanding over time (see `docs/ARCHIVE.md` § Deviations). Tests must
  pass before a phase's PR is opened.
- **Dependency hygiene:** pin every dependency to a specific, **current, actively-maintained**
  version (Python and npm) — pinned, not floating/`latest`, to preserve reproducibility. Do not
  pull in unvetted or abandoned packages. Choose versions with **no known vulnerabilities** at
  build time. Since Scrye is itself a vulnerability scanner, **dogfood it**: CI runs Trivy + Grype
  against Scrye's own image and **gates on fixable HIGH/CRITICAL findings** (fixable lower-severity
  items are surfaced in the non-gating informational scans); only genuinely unfixable
  upstream/OS-level items may remain, and those are noted in the README. (See `docs/ARCHIVE.md`
  § Deviations, INF-10, for the gate floor.)
  The backend also ships a hash-pinned lockfile: `pyproject.toml` pins the direct runtime deps and
  `backend/requirements.lock` is their fully-resolved, hash-verified closure (the image installs it
  with `pip --require-hashes`). **Whenever `pyproject.toml` dependencies change, regenerate the lock
  with the pinned `uv pip compile --generate-hashes` command** — uv is build/dev-time only, never in
  the runtime image — and CI fails on lock drift. See `CONTRIBUTING.md` § Backend dependency lock.
- **Dependabot *security* updates open against `main`, not `dev` — check `baseRefName` before
  touching one.** `.github/dependabot.yml` sets `target-branch: dev` on every ecosystem, but that
  key governs **version updates only**. Security updates ignore it and always open against the
  repository's **default branch** (`main`). This is a documented GitHub limitation, not a
  misconfiguration in this repo, and there is no config that changes it. So the first thing to
  check on any Dependabot PR is its base branch, and there are exactly two correct responses:
  **(a)** merge it into `main` and immediately back-merge `main` into `dev` (§ Git & PR
  conventions), or **(b)** close it and apply the same bump on `dev` directly, regenerating the
  lockfile with the real package manager rather than hand-editing version strings.
  **Retargeting the PR's base to `dev` is not a third option and does not work** — the diff stays
  computed against the branch point it was opened from, so it goes stale the moment `dev` moves
  ahead, and merging it can resolve *away* from the security fix. This is what happened to
  **#120** (brace-expansion) on 2026-07-31; it was closed and the bump reapplied on `dev`. See
  `docs/ARCHIVE.md` §14 (2026-07-31) and `CONTRIBUTING.md` § Releasing.
- **Interpreter CVEs: verify against the target version's source before a bump is justified on
  security grounds.** Scanner output, advisory "fixed in" fields, and this repo's own issue
  summaries are **evidence, not proof** — none of them is sufficient on its own to claim that
  moving the runtime to version X clears CVE Y. Before a runtime bump is argued as a security fix,
  confirm the fix is actually present in the target interpreter: read the relevant stdlib module in
  that exact version (unpack the pinned base image if needed) and check that the patched behavior is
  there. If it isn't, the bump does not clear that CVE, whatever the metadata says. This rule is
  **earned, not theoretical** — both interpreter bumps so far were decided from Grype's `FIXED IN`
  column without ever reading CPython:
  - **3.12 → 3.13** (2026-07-03) got the right outcome by luck, not method. The same entry that
    justified it recorded the triggering CVEs' fixes as landing in "3.13+/**3.14+/3.15+**" — i.e.
    the metadata itself said some were *not* fixed in 3.13 — yet the post-bump scan came back clean
    anyway. Metadata that is wrong in the pessimistic direction is still wrong.
  - **3.13 → 3.14** (2026-07-25) got the wrong outcome. The scoping doc and issue #52's
    resolution-trigger line both asserted 3.14.6 carried the CVE-2025-15366/-15367 fixes; 3.14.6's
    `imaplib`/`poplib` show it does not, and the bump cleared **nothing**. Issue #52 even contained
    the correct fact ("declined backport to 3.10–3.14") in a different paragraph.

  A runtime bump is still perfectly legitimate on **support-lifecycle, ecosystem, or dependency-
  currency** grounds — those need no CVE argument and are what actually carried the 3.14 move. Just
  don't sell a bump as a CVE fix that hasn't been verified at the source. See `docs/ARCHIVE.md` §14
  (2026-07-25) for both cases.
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
  only.** The master key content is never included (only the *paths* it is read
  from/generated at — `APP_SECRET_KEY_FILE`, `APP_SECRET_KEY_AUTOGEN_FILE`); stored application secrets — registry creds, git tokens, the OIDC client
  secret, API tokens — are **not** environment variables at all: they are configured through the app
  and held field-encrypted in the database, so no secret placeholder appears in `.env.example`.
  `.gitignore` already ignores `.env` but allows `.env.example`.
- **`.github/workflows/ci.yml`** — created in **Phase 0**, before that phase's own PR is opened.
  Runs lint + tests on every PR/push to `main`. No publish/registry job — GHCR publishing is
  handled separately by `.github/workflows/publish.yml` (releases) and `dev-nightly.yml` (nightly
  `:dev`) (locked decision §6). This is the gate every subsequent phase's PR must pass (see Git &
  PR conventions).
- **`THIRD_PARTY_LICENSES/`** — created in the Dockerfile phase (Phase 0), containing the
  Apache-2.0 `LICENSE` (and `NOTICE`, if present) for Trivy, Grype, and Syft, plus a README pointer
  to it. See Coding standards § Third-party license attribution.
- **Additional maintained project files** (added after the original Phase-0 list, now load-bearing —
  see `docs/ARCHIVE.md` § Deviations): `CHANGELOG.md` (Keep a Changelog), `SECURITY.md` (private
  vulnerability disclosure), `.github/CODEOWNERS`, `docs/ROADMAP.md` (forward-looking work),
  `.github/dependabot.yml`, and `ci/` (dogfood triage allowlists: `trivyignore`, `grype.yaml`).

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
