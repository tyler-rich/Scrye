# Supply-chain security review — 2026-07-12

Scope: Python and JS dependency hygiene (CVEs, pinning, abandonment, licenses),
`docker/Dockerfile` and `docker/docker-compose.yml` (base-image digest pinning, build
reproducibility, multi-stage layout), and the GitHub Actions CI/CD + GHCR publishing pipeline
(action pinning, token scopes, secret exposure, provenance/attestation). Review only — no code
was changed. Branch state reviewed: `dev` tip as of this date (v0.1.0 released).

**Verification method.** Every claim below is tagged by how it was established:

- **[live]** — verified against the source of record during this review: PyPI JSON API
  (versions, licenses, and per-version OSV advisories), the npm registry, `npm audit
  --package-lock-only` against the committed lockfile, and the Docker Hub API (current digests
  and tag push dates).
- **[unverified]** — the lookup path was blocked from this review environment (GitHub API and
  github.com are unreachable through the egress proxy), so the claim rests on repo-internal
  records or training knowledge and must be re-checked where GitHub is reachable. This
  affects: current commit SHAs for GitHub Actions, and the very latest Grype release (the
  repo's own dated check of 2026-07-09 found `0.115.0` current; web search surfaced nothing
  newer).

## Summary

The overall posture is strong for a v1 project: base images digest-pinned, scanner binaries
checksum-verified before extraction, a healthy npm lockfile, least-privilege workflow tokens,
no secret-bearing `pull_request` paths, a main-ancestry guard on releases, and a CI dogfood
gate with empty (honest) triage allowlists. **Zero known vulnerabilities were found in any
pinned Python or JS dependency** [live], and **all dependency licenses are permissive and
compatible** with the MIT project + bundled Apache-2.0 binaries [live].

The gaps are structural rather than acute, and they compound: there is **no automated
dependency monitoring for anything except GitHub Actions** (SC-3), which is visibly already
producing stale pins (a 15-month-old socket-proxy image, a superseded Node base digest, a
backend stack drifting behind patch releases); the **backend has no lockfile**, so every image
build resolves transitive Python packages fresh from PyPI (SC-1); **actions are still
tag-pinned, not SHA-pinned** (SC-2, already tracked on the roadmap); and the **published
images carry no provenance or SBOM attestation** (SC-4) — a notable omission for a project
whose product is SBOM/vulnerability scanning.

---

## 1. Python dependencies (`backend/pyproject.toml`)

All 13 runtime pins and 4 dev pins were checked against PyPI's per-version OSV advisory feed
[live]: **every pinned version is free of known advisories.** Versions and licenses as of
2026-07-12:

| Package | Pinned | Latest | Advisories vs pin | License |
|---|---|---|---|---|
| fastapi | 0.139.0 | 0.139.0 ✓ current | clean | MIT |
| starlette | 1.3.1 | 1.3.1 ✓ current | clean | BSD-3-Clause |
| uvicorn[standard] | 0.34.0 | 0.51.0 (17 minors behind) | clean | BSD-3-Clause |
| pydantic | 2.10.4 | 2.13.4 | clean | MIT |
| pydantic-settings | 2.7.1 | 2.14.2 | clean | MIT |
| sqlalchemy | 2.0.36 | 2.0.51 | clean | MIT |
| alembic | 1.14.0 | 1.18.5 | clean | MIT |
| argon2-cffi | 25.1.0 | 25.1.0 ✓ current | clean | MIT |
| cryptography | 49.0.0 | 49.0.0 ✓ current | clean | Apache-2.0 OR BSD-3-Clause |
| httpx | 0.28.1 | 0.28.1 ✓ current | clean | BSD-3-Clause |
| python-multipart | 0.0.32 | 0.0.32 ✓ current | clean | Apache-2.0 |
| authlib | 1.7.2 | 1.7.2 ✓ current | clean | BSD-3-Clause |
| pyotp | 2.10.0 | 2.10.0 ✓ current | clean | MIT |
| pytest (dev) | 8.3.4 | 9.1.1 | clean | MIT |
| pytest-asyncio (dev) | 0.25.1 | 1.4.0 | clean | Apache-2.0 |
| ruff (dev) | 0.8.6 | 0.15.21 | clean | MIT |
| black (dev) | 24.10.0 | 26.5.1 | clean | MIT |

No abandoned packages: every dependency is actively maintained (the packages that sit at
their pinned version — argon2-cffi, httpx, pyotp, authlib — are current, not stale) [live].

### SC-1 — HIGH: no backend lockfile; transitive dependencies float at every image build

`pyproject.toml` pins only **direct** dependencies. The Docker build (`docker/Dockerfile`
stage 3, `pip install .`) and CI (`pip install -e ".[dev]"`) resolve every transitive package
— `anyio`, `certifi`, `h11`, `click`, `greenlet`, `typing-extensions`, `uvloop`, `httptools`,
`websockets`, `cffi`, `Mako`, `jinja2` (via alembic/Mako), etc. — **fresh from PyPI at build
time, unpinned and without hash verification**. Consequences:

- Two builds of the same commit can produce different images (reproducibility broken — the
  same property the frontend already has via `npm ci` + lockfile).
- A newly published malicious or compromised transitive release is picked up silently on the
  next build, with no review step. This is the classic PyPI supply-chain entry point.
- The build backend floats too: `requires = ["setuptools>=75"]` (SC-12).

The CI dogfood scan partially compensates *after the fact* (a known-CVE transitive in the
built image gates CI), but it cannot catch malicious-but-not-yet-flagged packages and does
not restore reproducibility.

**Remediation:** generate a hash-pinned lock for the runtime set — e.g. `uv pip compile
pyproject.toml -o requirements.lock --generate-hashes` (or `pip-compile
--generate-hashes`) — commit it, and install in the Dockerfile with
`pip install --no-deps --require-hashes -r requirements.lock` followed by
`pip install --no-deps .`. Add a CI check that the lock is in sync with `pyproject.toml`
(same pattern as the existing `.env.example` sync check). A dev-extra lock for CI is a
nice-to-have second step.

### SC-12 — LOW: floating build backend

`[build-system] requires = ["setuptools>=75"]` resolves to whatever setuptools is current at
build time. Fold it into the lockfile work (SC-1), or pin `setuptools==<current>` there.

### Staleness (no advisories, fold into SC-3)

`uvicorn` 0.34.0 → 0.51.0 is the largest drift; pydantic/pydantic-settings/sqlalchemy/alembic
are behind by multiple patch/minor releases. All clean today [live], but nothing watches them
(SC-3): the current process only notices a dependency when the dogfood gate turns red, which
requires (a) a CVE to be published to the scanners' DBs and (b) a CI run to happen.

---

## 2. JS dependencies (`frontend/package.json` + `package-lock.json`)

**Lockfile health [live]:** `lockfileVersion: 3`, 282 packages, **every** entry carries a
`sha512` integrity hash, zero `sha1-` (weak) entries, and every `resolved` URL points at
`registry.npmjs.org` (no git/tarball/mirror origins). `npm ci` is used in both the Dockerfile
and CI, so installs are exactly reproducible from the lock. **`npm audit --package-lock-only`:
0 vulnerabilities across the full locked tree** [live].

| Package | Pinned | Latest | Advisories vs pin | License | Exposure |
|---|---|---|---|---|---|
| @mantine/core, /form, /hooks | 7.15.2 | 9.4.1 (2 majors) | clean | MIT | runtime bundle |
| @tabler/icons-react | 3.26.0 | 3.44.0 | clean | MIT | runtime bundle |
| react / react-dom | 18.3.1 | 19.2.7 | clean | MIT | runtime bundle |
| react-router-dom | 7.18.1 | 7.18.1 ✓ current | clean | MIT | runtime bundle |
| vite | 6.4.3 | 8.1.4 (2 majors) | clean | MIT | build/dev only |
| @vitejs/plugin-react | 4.3.4 | 6.0.3 | clean | MIT | build/dev only |
| typescript | 5.7.2 | 7.0.2 | clean | Apache-2.0 | build/dev only |
| eslint / @eslint/js | 9.39.4 | 10.7.0 | clean | MIT | dev only |
| typescript-eslint | 8.19.0 | 8.63.0 | clean | MIT | dev only |
| postcss | 8.5.16 | 8.5.18 | clean | MIT | build only |
| postcss-preset-mantine | 1.17.0 | 1.18.0 | clean | MIT | build only |
| postcss-simple-vars | 7.0.1 | 7.0.1 ✓ current | clean | MIT | build only |
| prettier | 3.4.2 | 3.9.5 | clean | MIT | dev only |
| globals | 15.14.0 | 17.7.0 | clean | MIT | dev only |

Notes:

- Exposure matters for triage: only react, react-dom, react-router-dom, Mantine, and the
  Tabler icons ship to users in the SPA bundle; everything else runs at build/dev time only,
  so a dev-server CVE (the historical Vite class) never touches production deployments that
  pull the image.
- `postcss-simple-vars` (7.0.1, current) is a small, feature-complete, low-activity package —
  stable rather than abandoned; no action needed.
- **SC-13 — INFO:** Mantine 7.15.2 is two majors behind (9.x current). Mantine **v7** is a
  locked decision (CLAUDE.md §2), so this is recorded, not flagged for action — but be aware
  that upstream security/bug fixes will land on 9.x, not 7.x. If an advisory ever lands on
  Mantine 7 with a fix only in a later major, the lock will need to be revisited (a user
  decision, per CLAUDE.md § When to ask vs. decide).

---

## 3. License compatibility

Context: Scrye itself is MIT; it bundles unmodified Trivy/Grype/Syft binaries under
Apache-2.0 (attribution satisfied via `THIRD_PARTY_LICENSES/` + README pointer, per
CLAUDE.md § Third-party license attribution — verified present).

- **Every direct Python and JS dependency is permissive** (MIT / BSD-3-Clause / Apache-2.0 /
  Apache-2.0-OR-BSD-3-Clause) [live — see tables above]. Apache-2.0 items (python-multipart,
  cryptography's dual license, pytest-asyncio, typescript) are one-way compatible with an MIT
  project: their notices must be preserved when redistributing (pip/npm metadata inside the
  image already carries them), and they impose nothing on Scrye's own MIT license.
- **No copyleft (GPL/LGPL/AGPL/SSPL) anywhere** in the direct dependency set.
- Transitives worth naming: `certifi` (via httpx) is **MPL-2.0** — file-level weak copyleft
  that is a non-issue for unmodified use and universally shipped in Python images;
  `caniuse-lite` (via browserslist, build-time only) is CC-BY-4.0 data. Neither affects
  distribution of the MIT app or the Apache-2.0 binaries.

**Conclusion: no license incompatibilities.** One hygiene suggestion: the lockfile work in
SC-1 makes it trivial to add a CI license-allowlist check later (e.g. `pip-licenses` /
`license-checker`), turning this one-time audit into an enforced invariant.

---

## 4. Dockerfile (`docker/Dockerfile`)

The load-bearing shape (multi-stage split, dependency-install-before-source layer ordering,
download-then-verify-then-extract scanner install) documented in `docs/ARCHIVE.md` § Build
performance is intact and correct — nothing below proposes restructuring it.

**Verified good:** all four `FROM` lines pin tag **and** digest (tag+digest together is the
right practice — human-readable and immutable); `python:3.13-slim-bookworm@sha256:fcbd8d…`
and `debian:bookworm-slim@sha256:60eac7…` are **byte-current with upstream** as of today
[live]; scanner binaries are fetched with the publisher's `checksums.txt` and verified via
`sha256sum -c` *before* `tar -x`, with subshell failures propagating through `wait` under
`set -e`; final stage runs `USER 1000:1000`, `COPY` only (no `ADD`), `HEALTHCHECK` present,
no secrets in any layer; `.dockerignore` excludes `secrets/`, keys, `.env*`, `.git/` — the
build context is clean.

### SC-6 — MEDIUM: `node:22-bookworm-slim` digest is stale

The pinned digest `sha256:813a74…` has been superseded upstream: Docker Hub's current
`node:22-bookworm-slim` is `sha256:53ada1…`, pushed **2026-07-07** [live]. The frontend
builder is therefore building on an OS snapshot that is at least one Debian patch cycle
behind. Exposure is limited (builder stage only — nothing from it ships to the runtime image
except the compiled `dist/`), but the same staleness mechanism will eventually hit the
runtime `python` digest too, and nothing automates the refresh (SC-3: Dependabot's `docker`
ecosystem is not enabled, so base digests never get bump PRs).

**Remediation:** bump the node digest now; enable Dependabot `docker` ecosystem for
`docker/Dockerfile` and `docker/docker-compose.yml` (weekly, target `dev`) so all digest
refreshes arrive as reviewable PRs.

### SC-8 — MEDIUM/LOW: scanner checksums are same-origin and unsigned-verified

`checksums.txt` is downloaded from the **same GitHub release** as the tarball it verifies. That
defeats transit corruption and a compromised mirror, but not a compromised release: an
attacker who can replace the tarball can regenerate the checksum file beside it. Both Anchore
(grype/syft) and Aqua (trivy) publish **cosign signatures** for their release checksum files
[unverified — release-asset layout per training knowledge; confirm when GitHub is reachable].

**Remediation (hardening, keeps the existing flow):** in the `scanners` stage, add cosign
keyless verification of each `checksums.txt` (`cosign verify-blob` with
`--certificate-identity-regexp` pinned to the upstream project's release workflow and
`--certificate-oidc-issuer https://token.actions.githubusercontent.com`) before the existing
`sha256sum -c`. This upgrades the guarantee from "matches what GitHub serves" to "signed by
the upstream project's own release pipeline."

### SC-9 — LOW: `# syntax=docker/dockerfile:1.7` is tag-pinned

The BuildKit frontend image is resolved by mutable tag from Docker Hub at build time — the one
component of the build not pinned by digest. Low risk (official Docker image), but for
consistency pin it by digest (`docker/dockerfile:1.7@sha256:…`) or drop the directive (the
features used — cache mounts — are in every current BuildKit).

### Reproducibility summary

`npm ci` from the committed lockfile: reproducible. `pip install .`: **not** reproducible
(SC-1 — the dominant gap). `apt-get install` without version pins: acceptable as documented
(package versions track the digest-pinned base snapshot, so they only change when the digest
is deliberately bumped). Bit-for-bit image reproducibility (SOURCE_DATE_EPOCH etc.) is not a
goal worth chasing here; provenance attestation (SC-4) is the practical alternative.

### SC-14 — INFO: runtime image carries `backend/tests/` and `backend/scripts/`

`COPY --chown=1000:1000 backend/ /app/backend/` ships the test suite and scripts into the
production image. No secret or vulnerability exposure (verified — tests use fixtures, no
credentials), just bloat and surface. If trimmed later, keep `alembic/`, `alembic.ini`,
`app/`, `pyproject.toml`.

---

## 5. Compose sidecars (`docker/docker-compose.yml`)

Both sidecar images are digest-pinned, profile-gated, and heavily hardened (read-only FS,
`cap_drop: ALL`, `no-new-privileges`, resource limits, no host ports) — good. The
`aquasec/trivy:0.72.0` pin matches the bundled Trivy version and its digest is current with
Docker Hub [live]. The trivy-server-runs-as-root exception (INF-4) remains a documented,
bounded residual risk — unchanged assessment.

### SC-7 — MEDIUM: `tecnativa/docker-socket-proxy:0.3.0` is ~15 months stale

The pinned `0.3.0` was pushed **2024-09-09**. Upstream has since shipped a `v0.4.x` line —
`v0.4.0` (2025-08), `v0.4.1` (2025-09), and current stable **`v0.4.2` (2025-12-16)** [live —
Docker Hub tag listing; note upstream now prefixes tags with `v`]. This sidecar is the single
most security-sensitive container in the stack — the only one holding the Docker socket — and
it is running a year-plus-old HAProxy base with whatever OS/HAProxy fixes have shipped since.
The pinned digest does still match the `0.3.0` tag (no tag drift) [live], but the version
itself is old.

**Remediation:** bump to `tecnativa/docker-socket-proxy:v0.4.2@<resolved digest>`, re-verify
the profile boots under the hardened options (the compose file's own INF-5 note — read-only
FS + `/run` tmpfs + `cap_drop: ALL`) since the entrypoint/privilege-drop behavior may have
changed across 0.3 → 0.4, and let the Dependabot `docker` ecosystem (SC-3) keep it rolling
thereafter.

---

## 6. GitHub Actions CI/CD and GHCR publishing

**Verified good:**

- **Token scopes are least-privilege and correctly split.** `ci.yml`: `contents: read` only,
  no secrets anywhere in its jobs — safe to run on fork PRs. `publish.yml` and
  `dev-nightly.yml`: `contents: read` + `packages: write` (the minimum for GHCR push), both
  triggered only outside `pull_request` (tag push / schedule / dispatch), so **no
  secret-bearing path is reachable from a fork PR** — the INF-2 closure holds. No
  `pull_request_target` anywhere.
- **No script-injection sinks.** All `${{ }}` interpolations in `run:` blocks are
  non-attacker-controlled (`github.workspace`) or passed via `env` (`PRIMARY_SCOPE`,
  `EXTRA_SCOPES` in the composite action — correctly shell-quoted); ref names are consumed as
  `$GITHUB_REF_NAME`/`$GITHUB_SHA` env vars, not inline-interpolated.
- **Release integrity guard.** `publish.yml` verifies the tagged commit is an ancestor of
  `main` before building, and both publish workflows carry
  `github.repository == 'tyler-rich/Scrye'` fork guards.
- **Build-cache poisoning is bounded by GitHub's cache isolation.** A fork PR's
  `cache-to: scope=amd64-ci` write lands in a cache keyed to that PR's merge ref; GitHub
  Actions cache ACLs prevent other refs (main, dev, schedule runs) from *reading* a PR's
  cache entries — they can only read caches written on their own ref or the default branch.
  The publish paths read `multiarch`/`dev-multiarch`, which are written only by
  trusted-context runs (main pushes/PRs-to-main, the schedule, release tags). No
  fork-PR-to-release cache path exists.
- **Dogfood gate hygiene:** `ci/trivyignore` and `ci/grype.yaml` contain zero triaged CVE
  exceptions — the allowlist mechanism exists but is honestly empty; scanner images used by
  CI are digest-pinned.

### SC-2 — HIGH: actions are tag-pinned, not SHA-pinned (known; now overdue)

Every `uses:` resolves a **mutable tag**: `actions/checkout@v7`, `actions/setup-python@v6`,
`actions/setup-node@v6`, `docker/setup-buildx-action@v4` (ci.yml) and `@v3` (composite),
`docker/setup-qemu-action@v3`, `docker/build-push-action@v7` (ci.yml) and `@v6` (composite),
`docker/login-action@v4`. A compromised action repo can move a major tag to malicious code
that then runs **with `packages: write` in the publish workflows** — i.e. the ability to push
a poisoned `ghcr.io/tyler-rich/scrye:latest`. This is exactly the tj-actions/changed-files
attack class, and the risk went up when the repo went public. Already flagged (audit INF-1)
and tracked on `docs/ROADMAP.md`; recording it here as the top actionable workflow item.

**Remediation:** pin every `uses:` to a full 40-char commit SHA with the version as a trailing
comment (`uses: actions/checkout@<sha> # v7.x.y`). Current SHAs could **not** be resolved
from this review environment (GitHub egress blocked [unverified]) — resolve them from a
machine with GitHub access, or take the pins from Dependabot's first grouped PR after
switching (Dependabot rewrites SHA pins and keeps the comment in sync). While doing it, also
fix **SC-10 — LOW:** ci.yml and the composite action use different majors of the same actions
(buildx v4 vs v3, build-push v7 vs v6) — converge on one (the newer) so behavior and audit
surface are identical across paths.

### SC-3 — HIGH: Dependabot watches only `github-actions`; pip, npm, and docker are unmonitored

`.github/dependabot.yml` has a single `github-actions` entry. There is **no automated
monitoring or update path** for: Python deps (`backend/pyproject.toml`), npm deps
(`frontend/package.json`), or Docker base images/sidecars (`docker/`). The concrete
consequences are visible in this review: SC-6 (stale node digest), SC-7 (15-month-old
socket-proxy), uvicorn 17 minors behind. The dogfood CI gate only fires on known CVEs and
only when CI runs.

**Remediation:** add three ecosystems to `dependabot.yml`, all `target-branch: dev`, weekly,
grouped: `pip` (directory `/backend`), `npm` (directory `/frontend`), `docker` (directory
`/docker`). Additionally enable **Dependabot security alerts + security updates** in the repo
settings (already on the ROADMAP governance checklist — alerts cover the full dependency
graph including transitives, which matters until SC-1 lands a lockfile Dependabot can see;
note Dependabot reads `package-lock.json` today but has no visibility into unpinned Python
transitives at all).

### SC-4 — MEDIUM: published images have no provenance or SBOM attestation

Neither `publish.yml` nor `dev-nightly.yml` generates SLSA provenance, an SBOM attestation,
or a signature for the pushed images. Consumers of `ghcr.io/tyler-rich/scrye` cannot verify
that `:latest` was built by this repo's workflow from a given commit — and for a tool whose
entire purpose is SBOM/vulnerability transparency, shipping an unattested image is a
credibility gap as much as a security one.

**Remediation (incremental):**
1. Cheapest: add `provenance: mode=max` and `sbom: true` inputs to `docker/build-push-action`
   in `.github/actions/build-image` (plumb through as composite inputs; leave them off for
   the `push: false` CI check). This attaches BuildKit SLSA provenance + SPDX SBOM to the
   image manifest with no new permissions.
2. Stronger: add an `actions/attest-build-provenance` step after the push (needs
   `id-token: write` + `attestations: write` — add at **job** level in the two publish
   workflows only), giving `gh attestation verify`-able GitHub-signed provenance.
3. Optional: cosign keyless image signing. Do 1 now, 2 when convenient.

### SC-5 — MEDIUM: no scheduled vulnerability re-scan of the shipped image

The dogfood gate runs only on `pull_request` and pushes to `main`; the nightly builds `:dev`
but never scans it, and skips entirely when `dev` is idle. During any quiet period, a newly
disclosed CVE in the published `:latest`/`:dev` image goes unnoticed until the next
unrelated PR. The 2026-07-09 bundled-binary CVE check in `docs/ARCHIVE.md` was manual — this
finding is about making that loop automatic.

**Remediation:** add a small scheduled workflow (e.g. weekly, or piggyback on
`dev-nightly.yml` after a successful build) that pulls the published `:latest` and `:dev`
images and runs the same gate scans (`--ignore-unfixed`/`--only-fixed`, HIGH/CRITICAL,
bundled-binary exclusions), opening an issue on failure instead of gating a merge. This also
automates the scanner-binary treadmill check the archive currently does by hand.

### SC-11 — LOW: `persist-credentials: false` not set on checkouts

`actions/checkout` persists the job's `GITHUB_TOKEN` into `.git/config` for subsequent steps.
In `publish.yml`/`dev-nightly.yml` that token has `packages: write`. All current post-checkout
steps are trusted (pinning them via SC-2 is what keeps this true), so this is hygiene, not a
hole: set `persist-credentials: false` on every checkout except `publish.yml`'s (which needs
`git fetch origin main` for the ancestry check — that fetch works credentialed; on a public
repo it would also work without, so `false` is likely safe there too — verify in a dry run).

---

## 7. Prioritized remediation list

Ordered by risk reduction per unit effort. Items 1–3 are one small PR each; none require
re-opening a locked decision.

| # | Finding | Severity | Action | Effort |
|---|---|---|---|---|
| 1 | SC-2 (+SC-10) | HIGH | SHA-pin all 8 action refs (resolve SHAs where GitHub is reachable, or take Dependabot's first rewrite); converge the ci.yml/composite version skew while touching them | ~1 hour |
| 2 | SC-3 | HIGH | Add `pip`, `npm`, `docker` ecosystems to `dependabot.yml` (target `dev`, weekly, grouped); enable Dependabot security alerts + updates in repo settings | ~30 min + settings |
| 3 | SC-7 | MEDIUM | Bump `tecnativa/docker-socket-proxy` 0.3.0 → v0.4.2 (new digest); live-verify the `docker-env` profile under the hardened options | ~30 min + verify |
| 4 | SC-6 | MEDIUM | Refresh the stale `node:22-bookworm-slim` digest (then automated by #2) | ~10 min |
| 5 | SC-1 (+SC-12) | HIGH (impact) / medium (urgency — OSV-clean today) | Introduce a hash-pinned backend lock (`uv pip compile --generate-hashes`); switch Dockerfile + CI to `--require-hashes`; add a lock-sync CI check; pin the build backend | ~half day |
| 6 | SC-4 | MEDIUM | `provenance: mode=max` + `sbom: true` in the composite build action for push builds; then `attest-build-provenance` with job-level `id-token: write` + `attestations: write` | ~1–2 hours |
| 7 | SC-5 | MEDIUM | Scheduled (weekly/nightly) gate-scan of published `:latest`/`:dev`, failure → issue | ~1–2 hours |
| 8 | SC-8 | MEDIUM/LOW | cosign `verify-blob` of the scanner `checksums.txt` files (identity-pinned keyless) before the existing `sha256sum -c` | ~2 hours |
| 9 | SC-11 | LOW | `persist-credentials: false` on checkouts (verify publish.yml's ancestry fetch) | ~15 min |
| 10 | SC-9 | LOW | Digest-pin (or drop) the `docker/dockerfile:1.7` syntax directive | ~10 min |
| 11 | SC-13/SC-14 | INFO | Monitor Mantine 7.x for advisories (locked decision — revisit only if a fix lands 9.x-only); optionally trim tests/scripts from the runtime image | as needed |

**Not findings (explicitly checked, verified sound):** workflow token scopes; fork-PR secret
exposure; `pull_request_target` usage (none); script injection in `run:` blocks; GHA
build-cache poisoning paths; release main-ancestry + repo guards; npm lockfile integrity
(sha512, registry-only, `npm ci` everywhere); OSV status of every pinned Python and npm
version (all clean); license compatibility (all permissive; no copyleft; Apache-2.0
attribution deliverables in place); python/debian base digest currency; trivy sidecar digest
currency; scanner pin currency (trivy 0.72.0 and syft 1.46.0 confirmed latest [live via web
search]; grype 0.115.0 latest per the repo's 2026-07-09 dated check, nothing newer surfaced
[unverified]); `.dockerignore` secret coverage; dogfood allowlist emptiness.
