# CLAUDE.md compliance audit — 2026-07-12

Full-codebase audit of Scrye against the operating contract in `CLAUDE.md`, using
`docs/ARCHIVE.md` (the historical build record and its § Deviations log) to distinguish
intentional, recorded decisions from actual drift. Audited at `dev` tip
(`81d35fe`, 2026-07-09 state). No code was changed by this audit.

**Legend:** ✅ adheres · ⚠️ drift · 📝 logged deviation (recorded in ARCHIVE.md § Deviations —
intentional, not drift) · 🔄 rule outgrown (code and contract have diverged in a way that
warrants a doc update, not a code fix).

---

## Executive summary

The codebase is in **strong compliance** with CLAUDE.md. Every locked decision is implemented
as written (or as revised via a dated deviation entry), the hard security rules are enforced
consistently and tested, the deliverables all exist, dependency pinning is exact, and the git
history is clean of attribution footers. The deviations-logging discipline is demonstrably
alive — every material divergence found in this audit was already recorded in
`docs/ARCHIVE.md` § Deviations.

The real findings are almost all **documentation rot and consistency debt**, in three groups:

1. **~100 stale `docs/PLAN.md` references** across backend docstrings, frontend comments, and
   `docker/Dockerfile` — the file was renamed to `docs/ARCHIVE.md`, and no `docs/PLAN.md`
   exists. Every one of these cross-references is now a dead link. (§ Drift D1)
2. **Stale "no registry publishing" comments** in `docker/Dockerfile` and
   `docker/docker-compose.yml` that contradict the current locked decision §6 (GHCR
   publishing is in scope). (§ Drift D2)
3. **CLAUDE.md text the code has outgrown** — five rules where the contract still states the
   original plan but the recorded, kept decision differs (hand-rolled API client, dogfood gate
   severity floor, `OIDC_CLIENT_SECRET` env placeholder, frontend tests, deliverables list).
   ARCHIVE.md § Deviations records each; CLAUDE.md was never amended. (§ Rules to update)

One process inconsistency in git history (8 commits authored as "Tyler Richardson" instead of
the mandated `tyler-rich`) and one CI-hygiene inconsistency (the composite build action pins
older action versions than `ci.yml`) round out the list.

---

## 1. Locked decisions

### LD1 — Name: Scrye ✅
Used consistently: `backend/pyproject.toml:2` (`name = "scrye"`),
`frontend/package.json:2` (`scrye-frontend`), `README.md:1`, image tags
`ghcr.io/tyler-rich/scrye` throughout the workflows.

### LD2 — Stack ✅
- React 18 + TS + Vite + Mantine v7: `frontend/package.json` — `react 18.3.1`,
  `@mantine/core 7.15.2`, `vite 6.4.3`, `typescript 5.7.2`.
- Python 3.13: `backend/pyproject.toml:5` (`requires-python = ">=3.13"`),
  `docker/Dockerfile:104` (`python:3.13-slim-bookworm@sha256:…`),
  `.github/workflows/ci.yml:40` (CI on 3.13), `[tool.black]`/`[tool.ruff]`
  `target-version = py313` (`backend/pyproject.toml:47,51`). The 3.12→3.13 revision is the
  logged 2026-07-03 deviation 📝; CLAUDE.md §2 already carries the amendment.
- FastAPI + Pydantic v2 + SQLAlchemy 2.0 + Alembic + SQLite: `backend/pyproject.toml:14-23`;
  `SCRYE_DATABASE_PATH=/data/scrye.db` (`docker/docker-compose.yml:30`).

### LD3 — Job model: in-process async worker, no Redis/arq, thin seam ✅
`backend/app/workers/__init__.py:6-7` documents the swap seam explicitly ("interface so a
Redis/arq-backed implementation could replace it later… explicitly out of scope for v1").
DB-backed `scans` table + semaphore in `backend/app/workers/inprocess.py`. No `redis`/`arq`
dependency anywhere in `backend/pyproject.toml`. The only other mentions are seam notes
(`backend/app/core/ratelimit.py:3`).

### LD4 — Docker socket only via read-only socket-proxy ✅
The app service mounts no socket (`docker/docker-compose.yml:36-39` — only `scrye_data`,
`scrye_cache`, tmpfs). The only `docker.sock` mount in the repo is the profile-gated proxy
sidecar, read-only, with the residual risk documented in place
(`docker/docker-compose.yml:131` — `/var/run/docker.sock:/var/run/docker.sock:ro # documented
residual risk`; `POST=0` at line 128). App-side enforcement:
`backend/app/core/docker_proxy.py:3-5` and the http(s)-only proxy-URL constraint (2026-07-04
audit remediation 📝).

### LD5 — AES-256-GCM field encryption; SQLCipher deferred with a seam ✅
`backend/app/core/crypto.py:1-21`: AES-256-GCM, per-secret 96-bit nonce, HKDF-SHA256
derivation, versioned tokens (`scrye$v1$…`), rotation support. The SQLCipher seam is named in
the module docstring (`backend/app/core/crypto.py:15-16`). No SQLCipher code exists —
correctly deferred (also on `docs/ROADMAP.md:97`).

### LD6 — Distribution: GHCR only, two tag roles, GITHUB_TOKEN ✅
- **Releases** — `.github/workflows/publish.yml`: `on: push: tags: v*.*.*`; canonical-repo
  guard (`publish.yml:46`); main-ancestry verification before building (`publish.yml:57-63`,
  `git merge-base --is-ancestor`); version derived by stripping the leading `v`
  (`publish.yml:68`); pushes `:<version>` **and** `:latest` (`publish.yml:88-90`); GHCR login
  with `secrets.GITHUB_TOKEN` (`publish.yml:71-76`); least-privilege
  `permissions: contents: read / packages: write` (`publish.yml:30-32`).
- **Dev nightly** — `.github/workflows/dev-nightly.yml`: `cron: "0 4 * * *"` (line 26) +
  `workflow_dispatch`; 24h freshness skip on scheduled runs only (lines 57-72, dispatch
  bypasses it as required); single moving `:dev` tag (line 92); fork guard (line 44); same
  `GITHUB_TOKEN` auth. Not triggered by pushes to `dev` — exactly the batched-nightly model.
- **No Docker Hub / PAT anywhere**: repo-wide grep finds `DOCKERHUB`/Docker Hub only in
  historical documents (`docs/ARCHIVE.md`, `docs/reviews/full-audit-2026-07-05.md`) — no
  workflow, no secret reference. `ci.yml` never publishes (`load: true` only, `ci.yml:115`).
- ⚠️ **D2 (comment drift):** `docker/Dockerfile:3` still says "built locally; no registry
  publishing" and `docker/docker-compose.yml:1,17` still say "locally built image; no
  registry" / "no registry publishing (locked decision #6)" — these predate the 2026-07-04→
  2026-07-09 revisions of §6 and now misquote it. The *behavior* is compliant (CI never
  publishes; publishing lives in publish.yml/dev-nightly.yml); the comments are stale. See
  § Rules to update, R6.

### LD7 — Teal theme, first-class light/dark ✅ 📝
`frontend/src/theme.ts:29-30` — `primaryColor: 'teal'`, `primaryShade: {light: 7, dark: 6}`
over a custom Tailwind-teal ramp with `autoContrast` and documented WCAG AA ratios
(lines 6-27). The custom ramp replacing Mantine's built-in teal is the logged 2026-07-09
deviation 📝. Light/dark toggle: `frontend/src/components/ColorSchemeToggle.tsx`.

---

## 2. Hard security rules

### HS1 — No hardcoded secrets ✅
Repo-wide grep found no credentials, tokens, or key material in code, config, Compose,
workflows, or tests. `.env.example` contains only non-sensitive values (see § Deliverables).
Compose instructs generating the key outside the repo (`docker/docker-compose.yml:9-10`
`openssl rand -base64 48 > docker/secrets/app_secret_key`), and `docker/secrets/` is ignored
(`.gitignore:16`).

### HS2 — Master key from a secret file, never env/image ✅
`backend/app/core/config.py:96-100`: only the *path* (`SCRYE_APP_SECRET_KEY_FILE`) is
configurable; the field description states "The key content is NEVER set via an environment
variable." `backend/app/core/crypto.py:5-6,261` reads key material exclusively from that file;
multi-version `v<N>:<base64>` rotation format is the logged 2026-07-03 deviation 📝. Minimum
256-bit material enforced (`crypto.py:46`, `_MIN_KEY_BYTES = 32`). No key material appears in
`docker/Dockerfile` or any layer.

### HS3 — Write-only secret fields ✅
Centralized in `backend/app/core/masking.py:17-39` (`SECRET_MASK = "••••••••"`,
`MaskedSecret` returns mask + `updated_at`, "never plaintext, and never the ciphertext
either"). Used by all secret-bearing read models (registries, git credentials, notifications,
OIDC settings — `backend/app/api/target_schemas.py:4` documents the SecretStr-on-write /
masked-on-read convention). The Discord/generic-webhook URL-as-credential handling is the
logged SEC-1 remediation 📝. Unit-tested (write-only masking covered in the auth/secret test
files; `backend/tests/test_crypto.py` has 19 tests incl. round-trips and key derivation).

### HS4 — Logging redaction ✅
`backend/app/core/logging.py`: `SecretRedactionFilter` masks key/value secret fields, quoted
multi-word values, `Bearer` credentials, and URL userinfo (`logging.py:65-85`), and covers
exception tracebacks and uvicorn's non-propagating loggers (lines 106-117; the traceback and
uvicorn coverage were the logged 2026-07-04 hardening 📝). Plaintext-never-in-logs is directly
tested — `backend/tests/test_redaction.py` (12 tests).

### HS5 — Decrypt at scan time, tmpfs, shred ✅
`backend/app/scanners/credentials.py`: transient Docker `config.json` (mode 0600) in a fresh
tmpfs dir, yielded as `DOCKER_CONFIG`, shredded in `finally` (`credentials.py:125-137`);
generic-git `GIT_ASKPASS` helper in tmpfs with the clone checkout on `/cache` scratch (the
logged 2026-07-04 "third hardened path" fix 📝), both cleaned in `finally`
(`credentials.py:255-292`). `_shred_file` overwrites then unlinks (`credentials.py:98-108`).
Covered by `backend/tests/test_credentials.py`.

### HS6 — CIS Docker baseline ✅ 📝
- `docker/Dockerfile`: all three base images digest-pinned (lines 17, 32, 104); scanner
  binaries fetched with publisher checksums and verified **before** extraction
  (lines 57-95), never `curl | bash`; non-root `USER 1000:1000` (line 152); `COPY` only;
  `HEALTHCHECK` (lines 155-156); no secrets in layers.
- `docker/docker-compose.yml`: every service has `read_only: true`, `no-new-privileges`,
  `cap_drop: ALL`, resource limits, healthcheck, `restart: unless-stopped`, and capped
  json-file logging; the app binds `127.0.0.1:8089:8089` (line 27); tmpfs `/tmp` is
  200 MB/uid-1000 with the RAM-vs-disk rationale documented in place (lines 40-48).
- Documented exceptions, both logged 📝: `trivy-server` runs as root (INF-4, risk note at
  lines 71-81) and the socket-proxy's writable `/run` tmpfs (INF-5, lines 137-142).

### HS7 — CSRF, auth rate-limiting, audit log ✅
- CSRF: `backend/app/auth/deps.py:107-118` (`require_csrf`, constant-time compare, cookie-auth
  only — the bearer-token exemption is the logged Phase 5 decision 📝). **Every** API module
  that declares a POST/PUT/PATCH/DELETE route uses it — verified by sweeping all
  25 `backend/app/api/*.py` modules: the 14 modules with mutating routes all import and apply
  `require_csrf`; the remainder are read-only or schema-only modules.
- Rate limiting: `backend/app/api/auth.py:51,105,134,199` — enforced on login, MFA verify, and
  setup paths; in-process store per the locked single-container model
  (`backend/app/core/ratelimit.py:3`).
- Audit log: `backend/app/core/audit.py`, recorded across all 13 security-relevant routers
  (spot-counted: auth.py 13 call sites, settings/scans/schedules/registries/oidc/notifications/
  backups 5 each, git_credentials/docker_environments 4, users/api_tokens 3).

---

## 3. Git & PR conventions

### GP1 — Branching model ✅
`main` receives only promotions; `dev` is the integration branch. History confirms: promotion
squash-merges on `main` ("Promote dev to main: …" #32/#37/#41/#49), day-to-day PRs into `dev`.
This audit's branch (`claude/claude-md-compliance-audit-lr5l7n`) is cut from `origin/dev`'s
tip (`81d35fe`), per convention.

### GP2 — Back-merge after promotions ✅
`git rev-list --left-right --count origin/main...origin/dev` → `0 29`: nothing on `main` is
missing from `dev`; `dev` is strictly ahead. The two most recent commits on `dev` are exactly
the documented back-merge merges (`81d35fe` "Merge remote-tracking branch 'origin/dev'…",
`2390020` "Merge remote-tracking branch 'origin/main' into dev"). The process adopted in the
2026-07-07 deviation entry 📝 is being followed.

### GP3 — CI as the gate ✅
`.github/workflows/ci.yml:12-15`: `on: push: branches: [main]` + `pull_request:` (all PRs,
i.e. both `dev`- and `main`-targeted) — matches CLAUDE.md's "every pull request and push to
`main`" literally. Backend lint (`ruff`, `black --check`), frontend lint (ESLint, Prettier),
`pytest`, plus the image dogfood jobs. CI never publishes (see LD6).

### GP4 — Author identity ⚠️ (inconsistent)
Mandated: `tyler-rich <170156756+tyler-rich@users.noreply.github.com>`. Actual on `origin/dev`:

- ✅ 88 commits as `tyler-rich <170156756+tyler-rich@users.noreply.github.com>`
- ⚠️ **8 commits authored as `Tyler Richardson <170156756+tyler-rich@users.noreply.github.com>`**
  — all 2026-07-09 squash-merges (#42–#49, e.g. `97a72f7`, `1827288`, `6ab4cf6`, `2c1a6a7`).
  Same account and mandated email; the *name* diverges. These are GitHub-side squash-merge
  authorships, which take the account's **profile display name** at merge time — the local
  `git config user.name "tyler-rich"` rule cannot reach them. Practical fix going forward:
  keep the GitHub profile display name aligned with the convention, or accept squash-merge
  authorship as an exception and say so in CLAUDE.md (see § Rules to update, R7).
- `dependabot[bot]` authored 1 commit (its own dependency bump PR) — expected; the identity
  rule governs work authored by/through Claude sessions, not bot PRs.

### GP5 — No attribution footers ✅
`git log origin/dev --format='%B'` grepped for `co-authored-by|generated with|anthropic|
claude|session`: **zero** Claude/Anthropic identities, co-author trailers, session links, or
"Generated by…" text on any commit. The single `Co-authored-by:` in history is
`dependabot[bot]` on its own PR. All `claude` hits are legitimate references to the file
`CLAUDE.md` in commit bodies.

### GP6 — Conventional Commits ✅ (minor inconsistency)
The last 40 non-merge subjects on `dev` are Conventional Commits except two shapes:
- `Promote dev to main: …` (#37, #41, #49) — the promotion-PR title convention from
  `CONTRIBUTING.md` § Releasing; deliberate, but not Conventional-Commit-shaped.
- `Land P1–P5 audit remediation on dev (P0 already merged via #23) (#29)` — a one-off batch
  squash title without a type prefix.
Low-severity; if strictness is wanted, promotions could adopt `release:` or
`chore(release):` prefixes (see § Rules to update, R8).

### GP7 — Deviations logged in ARCHIVE.md ✅
The discipline is demonstrably alive: 40+ dated entries through 2026-07-09, including
retroactive logging of missed items (the 2026-07-05 "Deviation-logging debt" entry). Every
material divergence this audit found was already recorded there.

---

## 4. Definition of done (spot-check at current tip)

1. **Lint clean ✅** — verified this audit with the *pinned* toolchain: `ruff 0.8.6` → "All
   checks passed!", `black 24.10.0` → "150 files would be left unchanged."
   *Footnote:* a modern ruff (0.15.x) flags one `I001` import-block in
   `backend/tests/test_migrations.py:11` — worth fixing pre-emptively before the next ruff
   version bump.
2. **Tests exist and pass ✅** — 30+ test modules under `backend/tests/`; CI runs them on every
   PR (`ci.yml:57`). The specifically mandated crypto/auth coverage exists:
   `test_crypto.py` (19 tests — round-trips, key derivation, versioning),
   `test_redaction.py` (12 — plaintext never in logs), `test_auth.py` (15),
   `test_passphrase.py` (11), plus `test_credentials.py` (tmpfs/shred) and
   `test_migrations.py` (Alembic chain vs models).
3. **CI green ✅** — enforced per-PR by branch process; not re-executed in this audit.
4. **`docker compose up` + `/healthz` ✅** — healthcheck wired in compose and Dockerfile; the
   live end-to-end verification is on record in ARCHIVE.md (2026-07-03 cache-fix entries).
5. **Docs updated with code ✅** — e.g. the 2026-07-09 GHCR consolidation updated README,
   CONTRIBUTING, ROADMAP, and CLAUDE.md in the same change.
6. **Deviations logged ✅** — see GP7.
7. **No secrets committed; .gitignore coverage ✅** — see HS1; `.gitignore` covers `secrets/`,
   `app_secret_key`, `.env` (allowing `.env.example`), `*.db`, `backups/`, `artifacts/`,
   transient `config.json`, plus a deliberate `!frontend/src/lib/` carve-out from the Python
   `lib/` ignore (`.gitignore:52-55`).
8. **Identity/footer verification ✅/⚠️** — footers clean (GP5); identity has the
   squash-merge display-name gap (GP4).

---

## 5. Coding standards

### CS1 — Python ✅
- **Type hints:** effectively universal — a repo-wide sweep of `backend/app` found exactly
  **1** non-dunder function without a return annotation. Enforced culturally, not by a
  checker (mypy/pyright deferred — logged QUA-16 📝).
- **Docstrings:** enforced mechanically — ruff `D` rules are enabled
  (`backend/pyproject.toml:56` `select = [… "D"]`) with tests/alembic exempted
  (lines 63-65), and the tree is ruff-clean. Module docstrings consistently cite the design
  doc (though under its old name — see D1).
- **No bare/silent excepts:** zero `except:` in `backend/app`; all 12 `except Exception` sites
  are deliberate best-effort boundaries with explanatory `noqa: BLE001` comments (worker
  loops, notification dispatch, backup scheduler — e.g. `backend/app/workers/inprocess.py:191`
  "notification failures never fail a scan"). One site lacks the explanatory comment
  (`backend/app/workers/inprocess.py:416`) — trivial inconsistency.
- **Pydantic I/O models:** consistent across routers (`response_model=` everywhere; SecretStr
  write models per `target_schemas.py`).
- **SQLAlchemy 2.0 typed style:** `Mapped[]`/`mapped_column` throughout
  `backend/app/db/models/`.
- **Alembic migration per schema change:** migration chain `0001`–`0008+` under
  `backend/alembic/versions/`, and `backend/tests/test_migrations.py` asserts the chain
  matches `Base.metadata` (QUA-23 📝) — the strongest possible enforcement of this rule.

### CS2 — TypeScript ✅ / 🔄
- **ESLint + Prettier:** configured and CI-enforced (`frontend/package.json` scripts `lint`,
  `format:check`; `ci.yml:73-79`).
- **Strict TS:** `frontend/tsconfig.app.json:16` `"strict": true`; **zero** `: any`/`as any`
  in `frontend/src`.
- **Typed API client from OpenAPI:** 🔄 **not** how it's built — `frontend/src/api/*` is a
  hand-written typed `fetch` wrapper. This is the logged FE-2 deviation 📝, explicitly *kept*;
  but CLAUDE.md § Coding standards still states the generated-client rule verbatim. This is
  the clearest case of a rule the code has outgrown → update CLAUDE.md (R1).
- **Mantine over bespoke CSS:** holds — no bespoke stylesheets beyond Mantine/postcss setup;
  pages compose Mantine components.
- **No inline secrets:** clean.
- **Consistency note:** date rendering is centralized in `frontend/src/lib/dates.ts` and used
  by the pages that render timestamps (FE-3 📝); the one remaining raw `new Date(…)` use
  (`frontend/src/pages/ScansPage.tsx:208`) is a sort comparator, not display formatting —
  acceptable.

### CS3 — Commits ✅
See GP6.

### CS4 — Scanner faithfulness ✅
`backend/app/scanners/` orchestrates the official binaries via async subprocess
(`base.py` `run_command` with output caps), parses their JSON with shape-guarded loaders
(`load_json_output`/`check_success` — 2026-07-04 parser hardening 📝), persists raw scanner
JSON as the source-of-truth artifact even when parsing fails
(`backend/app/workers/inprocess.py` `_store_failure_output`), and normalizes into the shared
findings model. The in-repo cron evaluator (`backend/app/core/cron.py`) is scheduling
infrastructure, not scanner logic — logged 📝.

### CS5 — Third-party license attribution ✅
`THIRD_PARTY_LICENSES/` carries `trivy/LICENSE` + `trivy/NOTICE`, `grype/LICENSE`,
`syft/LICENSE` (Grype/Syft ship no upstream NOTICE — stated in
`THIRD_PARTY_LICENSES/README.md:16-17`); the version table (v0.72.0 / v0.115.0 / v1.46.0)
matches the `docker/Dockerfile:35-37` pins exactly; the directory is copied into the image
(`Dockerfile:141`); README § Integrations carries the Apache-2.0 note and pointer
(`README.md:137`, `README.md:908`).

### CS6 — Testing ✅ / 🔄
Backend: comprehensive (see DoD 2). Frontend: 🔄 **no test runner or tests exist** — logged
FE-10 📝 and deferred, and `ci.yml:81-82` carries a comment that `npm test` "can be added
here in a later phase." CLAUDE.md's blanket "every phase ships with tests" has effectively
never applied to the frontend; either add vitest (ROADMAP already suggests `lib/dates.ts` as
the first target) or scope the rule (R3).

### CS7 — Dependency hygiene ✅ 📝
- **Exact pins everywhere:** all 14 runtime + 4 dev Python deps are `==`-pinned
  (`backend/pyproject.toml:12-36`, including the deliberately pinned `starlette==1.3.1`
  transitive); every `frontend/package.json` dependency (24 entries) is exact — no `^`/`~`
  anywhere. (Only the build backend floats: `setuptools>=75`, `pyproject.toml:39` — build
  tooling, not a shipped dependency.)
- **Dogfood self-scan:** `ci.yml` `image` job scans the built image with Trivy and Grype
  digest-pinned at the bundled versions, gating on fixable findings with triaged allowlists
  in `ci/trivyignore` / `ci/grype.yaml`. Two scoped carve-outs, both logged 📝: the gate floor
  is HIGH/CRITICAL not all-severities (INF-10 — CLAUDE.md not amended, see R2), and the
  bundled scanner binaries are skipped as genuinely-unfixable upstream artifacts (with the
  informational scans keeping them visible, and the 2026-07-09 CVE-tracking entry showing the
  treadmill is actively worked).
- **Unfixable-findings README note:** present (`README.md:883` — bundled binaries tracked as
  upstream items).

### CS8 — Build performance invariants ✅
All four ARCHIVE.md § Build performance invariants hold in `docker/Dockerfile` and the
workflows:
- Multi-stage split intact: `frontend-builder` (line 17) / `scanners` (line 32) /
  `backend-builder` (line 104) / `runtime` (line 118); runtime copies only venv, verified
  binaries, backend source, SPA dist, entrypoint, licenses.
- Layer ordering intact: `package*.json` copied and `npm ci` run before `COPY frontend/`
  (lines 25-29); `pyproject.toml` before app source install (lines 115-117); BuildKit cache
  mounts on both.
- Cache scopes partitioned by writer, cross-seeded read-only: `image` writes `amd64-ci`
  reads `dev-multiarch` (`ci.yml:123-126`); `image-multiarch` and `publish` write `multiarch`
  read `dev-multiarch` (`ci.yml:225-226`, `publish.yml:85-86`); nightly writes
  `dev-multiarch` reads `multiarch` (`dev-nightly.yml:95-96`). The composite action enforces
  write-one/read-many structurally (`.github/actions/build-image/action.yml:60-84`).
- Download→verify→extract preserved with parallelism explicitly documented as cosmetic to the
  integrity control (`Dockerfile:41-56`).

---

## 6. Required deliverables

| Deliverable | Status | Evidence |
|---|---|---|
| `README.md` | ✅ | All mandated sections present: features (`README.md:71`), integrations w/ license note (133), architecture (154), requirements (194), quick start (227-364), configuration + master-key mechanism (448, 494), reverse-proxy (513), usage (677), security model (728), backup/restore (802), roadmap (892), contributing/license (900, 908). GHCR-only; no stale Docker Hub text. |
| `CONTRIBUTING.md` | ✅ | Full local-dev setup incl. venv, migrations, local secret key, reload (38-84), Vite dev server (85), Compose run (97), first-admin seed (108), branching model (127), layout (138), standards (200), testing (237), PR process (256), releasing/promotion+back-merge (271-293), private security disclosure (328). |
| `LICENSE` | ✅ | MIT. |
| `.env.example` | ✅ | **Exact 1:1 sync** with the `Settings` model (26 fields ↔ 26 vars, verified this audit), generated by `backend/scripts/gen_env_example.py`, and — better than the contract requires — **enforced in CI** (`ci.yml:54` `gen_env_example --check`). Non-sensitive only; no key material. 🔄 CLAUDE.md's "`OIDC_CLIENT_SECRET` as a named placeholder" is outdated — OIDC config (incl. its client secret) lives field-encrypted in the DB settings store, not env (see R4). |
| `.github/workflows/ci.yml` | ✅ | See GP3/CS7. |
| `THIRD_PARTY_LICENSES/` | ✅ | See CS5. |
| 🔄 Not in the deliverables list but now existing and load-bearing | — | `CHANGELOG.md` (Keep-a-Changelog, v0.1.0), `SECURITY.md`, `.github/CODEOWNERS`, `docs/ROADMAP.md`, `ci/` (dogfood allowlists), `.github/dependabot.yml`. CLAUDE.md § Required deliverables was never extended (R5). |

Version consistency ✅: `0.1.0` identical across `backend/app/__init__.py:3`,
`backend/pyproject.toml:3`, `frontend/package.json:4`, and `CHANGELOG.md`'s latest entry.

No leaked deployment identifiers ✅: only sanitized placeholders
(`scrye.your-domain.tld`, `pocket-id.your-domain.tld`, `<the deployment host>`) appear; no
real hostnames or non-RFC1918/documentation IPs anywhere.

---

## 7. Drift findings (things to fix)

### D1 — ~100 dead references to `docs/PLAN.md` (systemic doc rot) ⚠️
`docs/PLAN.md` no longer exists — it became `docs/ARCHIVE.md` — but roughly 100 docstrings
and comments across the codebase still cite it as the design authority, including:
- ~70 backend module docstrings (`backend/app/core/crypto.py:3`,
  `backend/app/core/masking.py:4`, `backend/app/api/scans.py:3`,
  `backend/app/db/base.py:6`, `backend/app/scanners/credentials.py:25`, …),
- ~11 frontend comments (`frontend/src/pages/Dashboard.tsx:100`,
  `frontend/src/api/scans.ts:167`, `frontend/src/components/ColorSchemeToggle.tsx:6`, …),
- 2 in `docker/Dockerfile` (lines 55, 122 — the line-55 one sits inside the build-performance
  guardrail comment, pointing readers at a nonexistent file for a load-bearing rationale),
- 2 in tests (`backend/tests/test_scanners.py:5`, `backend/tests/test_credentials.py:8`).
**Fix:** mechanical `docs/PLAN.md` → `docs/ARCHIVE.md` sweep (the § references still line up —
ARCHIVE.md kept the section numbering verbatim by design).

### D2 — Stale "no registry publishing" comments ⚠️
`docker/Dockerfile:3` and `docker/docker-compose.yml:1,17` still describe the original
local-build-only distribution model and cite "locked decision #6" for it — §6 has since been
revised twice and now *mandates* GHCR publishing. Comment-only fix; behavior is compliant.

### D3 — Composite build action pins older action versions than ci.yml ⚠️
`.github/actions/build-image/action.yml:49,52,88` pin `setup-qemu-action@v3`,
`setup-buildx-action@v3`, `build-push-action@v6`, while `ci.yml:107,110` use
`setup-buildx-action@v4` and `build-push-action@v7`. `.github/dependabot.yml:13` claims its
`directory: "/"` entry "Covers .github/workflows/* and the composite action under
.github/actions/" — the version skew suggests it doesn't (Dependabot's `github-actions`
ecosystem needs a separate `directory` entry per composite action). Either add
`directory: "/.github/actions/build-image"` to dependabot.yml or bump the composite action's
pins manually alongside the workflows. (Related: SHA-pinning of all `uses:` is the logged
INF-1 remainder 📝, tracked on `docs/ROADMAP.md:38`.)

### D4 — 8 squash-merge commits authored as "Tyler Richardson" ⚠️
See GP4. History rewrite is not warranted (they're merged history on `dev`/`main`); the fix is
forward-looking (profile display name, or amend the rule — R7).

### D5 — Minor code-hygiene stragglers ⚠️ (low severity)
- `backend/app/workers/inprocess.py:416`: the one `except Exception` without an explanatory
  comment, unlike its 11 siblings.
- `backend/tests/test_migrations.py:11`: import block that future ruff versions (0.15.x)
  flag as `I001`; clean under the pinned 0.8.6.
- Promotion/batch squash titles not Conventional-Commit-shaped (GP6).

---

## 8. Conventions followed inconsistently

1. **List-endpoint envelopes** — 17 endpoints across 12 modules return bare
   `response_model=list[…]` while the history endpoint returns `{total, items}`
   (`GET /api/scans/history`) and filter options return dedicated shapes. This is the logged
   QUA-9 deferral 📝, but it remains the largest live inconsistency: new frontend code has to
   know per-endpoint which shape it gets. The deferred consolidation (with QUA-4's
   secret-CRUD-router unification) is still worth scheduling.
2. **Action version pinning** between workflows and the composite action (D3).
3. **`except Exception` commenting** — 11 of 12 sites explain themselves (D5).
4. **Squash-merge authorship names** — 88 vs 8 split (D4).

Notably *not* inconsistent (checked because they commonly drift): CSRF coverage (all mutating
modules guarded), audit coverage (all security-relevant routers), secret masking (single
shared helper), date formatting (single shared helper), dependency pinning style (exact
everywhere), compose hardening keys (uniform across all three services).

---

## 9. Rules the code has outgrown — recommended doc updates

These are cases where ARCHIVE.md § Deviations records a kept decision but the corresponding
CLAUDE.md rule text was never amended, so the contract misstates current reality. Per
CLAUDE.md's own precedence ("when this file and the archive disagree, this file wins"), the
stale CLAUDE.md text is technically the binding rule — which makes these worth fixing soon,
before a future session "corrects" compliant code back toward an abandoned plan.

- **R1 — CLAUDE.md § Coding standards (TypeScript):** still mandates a "typed API client
  generated from the FastAPI OpenAPI schema." FE-2 (2026-07-05 📝) records keeping the
  hand-rolled typed client. Amend to: hand-written typed client in `frontend/src/api/`;
  OpenAPI generation remains a possible future improvement.
- **R2 — CLAUDE.md § Dependency hygiene:** says CI "resolves all *fixable* findings." The
  implemented, logged gate (INF-10 📝) is fixable **HIGH/CRITICAL** with lower severities
  informational, plus the bundled-binary carve-out. Amend the sentence to match the gate (or
  consciously raise the gate).
- **R3 — CLAUDE.md § Testing / § Git & PR conventions:** "run `pytest` plus any frontend
  tests" — no frontend tests or runner exist (FE-10 📝). Either add vitest (preferred;
  ROADMAP already names the first target) or state that frontend verification is
  tsc/ESLint/Prettier/build until a runner lands.
- **R4 — CLAUDE.md § Required deliverables (.env.example):** "secrets like
  `OIDC_CLIENT_SECRET` appear as a named placeholder" — OIDC configuration (including its
  client secret) is stored field-encrypted in the DB settings area, not env vars, so no such
  placeholder exists or should. Drop the OIDC example from the rule.
- **R5 — CLAUDE.md § Required deliverables:** extend the list with the deliverables that now
  exist and are maintained: `CHANGELOG.md`, `SECURITY.md`, `.github/CODEOWNERS`,
  `docs/ROADMAP.md`, `ci/` triage allowlists, `.github/dependabot.yml`.
- **R6 — Code comments (with D1/D2):** the `docs/PLAN.md` → `docs/ARCHIVE.md` sweep and the
  two "no registry publishing" headers.
- **R7 — CLAUDE.md § Git & PR conventions (identity):** note that GitHub squash-merges author
  as the account's *profile display name*, so the profile name must match `tyler-rich` for
  the rule to hold end-to-end (or explicitly accept squash authorship as-is).
- **R8 — (optional) CLAUDE.md § Git & PR conventions:** if Conventional-Commit strictness on
  `main` matters, define the promotion-PR title convention (`release: …` /
  `chore(release): …`) instead of the current free-form "Promote dev to main: …".

---

## 10. Method

Audited with CLAUDE.md and the full `docs/ARCHIVE.md` (all 40+ deviation entries and the
Build performance appendix) as the baseline. Evidence gathered by direct file reads of all
workflows, Docker assets, dependency manifests, the security core (crypto, masking, logging,
credentials, deps, ratelimit, audit), and docs; repo-wide greps for secrets, Docker Hub
remnants, socket mounts, stale references, and exception patterns; sweeps of all 25 API
modules for CSRF/audit coverage; git-history analysis of authorship, footers, subjects, and
branch topology; and a live run of the pinned lint toolchain (ruff 0.8.6, black 24.10.0).
Findings were only reported where the evidence was directly observed; ARCHIVE.md § Deviations
was consulted before classifying anything as drift.
