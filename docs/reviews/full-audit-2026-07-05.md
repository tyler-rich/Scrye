# Scrye — Full Repository Audit (2026-07-05)

> **Report-only audit.** No code was changed. This document is written to be actioned
> by a separate implementation session with no memory of how it was produced — every
> finding carries a file:line reference, a concrete failure scenario, a severity, a
> confidence marker, and a fix direction (not fix code).
>
> **Confidence markers:** **CONFIRMED** = verified against the actual source, with the
> triggering line quoted or cited. **PLAUSIBLE** = the mechanism is real and present in
> the source, but the exact trigger conditions are less certain (often runtime/volume
> dependent, or dependent on a library behavior not executed here).
>
> **Scope covered:** infrastructure & deployment (Dockerfile, compose, CI/publish
> workflows, hardened-container posture); backend security (auth, sessions, secrets,
> crypto, RBAC, CSRF, rate limiting, audit); scanner orchestration, workers &
> schedulers, credentials-at-scan-time; API layer, data model/migrations,
> reports/exports/diff, backup/restore, dashboard/metrics, performance; frontend;
> feature completeness vs `docs/PLAN.md`; documentation deliverables; and the
> previously-logged known limitations in `docs/PLAN.md` § Deviations.
>
> **Finding-ID prefixes:** `INF-` infrastructure · `SEC-` backend security ·
> `SCN-` scanners/workers · `API-` API/data/perf · `FE-` frontend · `FEAT-` feature
> completeness · `DOC-` documentation · `QUA-` backend code quality. IDs are stable —
> cite them in commits/PRs.

---

## 0. Executive summary

Scrye is a mature, carefully-built codebase. It shows clear evidence of prior security
review: synchronizer-token CSRF, argon2id with timing equalization, AES-256-GCM field
encryption with per-column AAD, `__Host-` OIDC binding cookies, a last-admin guard,
off-argv git credentials, argv option-injection terminators, and scanner parser
shape-guards are all present and correct. The **"hardened container lacks a writable
path" bug class is confirmed closed** — every scanner subprocess (and every probe) runs
through the `scanner_cache_env()` overlay routing cache/temp writes onto the `/cache`
volume, and the exhaustive sweep found no unrouted persistent write.

The audit nonetheless surfaced a number of real issues. The headline items:

- **One confirmed privilege-escalation bug** (QUA-1 / SEC-adjacent): a low-privilege
  API token belonging to an admin can mint a full-admin token, because the mint check
  reads the owner's role instead of the token's effective (capped) role.
- **Backup/restore does not survive real data volume** (API-2, API-3): restore runs
  scrypt + a row-by-row full-DB rebuild directly on the event loop — the container's own
  healthcheck can kill it mid-restore — and backup bundles materialize the entire
  findings table as one in-memory JSON blob, OOMing a memory-limited container.
- **The scan worker persists 10k+ findings synchronously on the event loop** (API-5),
  contradicting its own "short writes" docstring and stalling `/healthz` and other scans.
- **Three Settings → Scanners knobs are stored and editable but wired to nothing**
  (FEAT-4/6/7, QUA-3): Grype ignore rules, default severities/ignore-unfixed, and the
  DB-update schedule silently do nothing — the UI lies to the admin.
- **Supply-chain gaps in the publishing pipeline** (INF-1, INF-2): the workflow that
  holds the Docker Hub token uses mutable action tags (not SHA-pinned), and the `:dev`
  publish silently fails for the merged fork PRs that `dev` exists to serve (fork PRs
  don't get repo secrets).
- **A masked-secret gap** (SEC-1): generic webhook URLs that embed a token (Slack,
  Teams, Mattermost) are stored in plaintext and returned on read — only Discord is
  special-cased.
- **Several plan-mandated features are missing entirely** (FEAT-1/2/3/5): image-tar
  upload, Docker-environment multi-select scan, filesystem-archive upload, and
  offline/air-gapped DB import.
- **The README contradicts a locked decision** (DOC-1): it still says there is no
  published registry image, months after Docker Hub publishing became in-scope.

No Critical findings. The prioritized action list is in §10.

**All nine previously-logged known limitations are still present** (§9), with one that
has quietly compounded: because the backup scrypt work factor was already bumped once
(2^15 → 2^17), any bundle produced before that bump is now unrestorable, since restore
derives the key from the module constants rather than the envelope's advertised params.

---

## 1. Infrastructure & deployment

### The tmpfs / writable-path bug class — CONFIRMED CLOSED
An exhaustive sweep of every subprocess invocation and filesystem write in `backend/app`
confirms the fix is complete:
- `scanner_cache_env()` (`backend/app/scanners/base.py:174-218`) sets `TMPDIR`, `HOME`,
  `XDG_CACHE_HOME`, `TRIVY_CACHE_DIR`, `GRYPE_DB_CACHE_DIR` under `/cache` and is applied
  at **every** invocation: Trivy image/repo scans + in-scan version probe
  (`trivy.py:279,299-310`), Grype image/dir/sbom (`grype.py:169-171`), Syft
  (`syft.py:89-91`), and all four About/dashboard probes (`system_info.py:70-159`).
- The only `mkdtemp`-into-`/tmp` users are intended tmpfs tenants: transient Docker
  registry config (`credentials.py:125`, 0600, shredded), the `GIT_ASKPASS` helper
  (`credentials.py:256`, 0700, shredded), Trivy policy/VEX files (`trivy_policy.py:111`).
  The generic-repo **checkout** correctly goes to `/cache/tmp` (`credentials.py:259-261`).
- All persistent writes go to `/data`; backup restore is in-DB (no temp files);
  `PYTHONDONTWRITEBYTECODE=1` prevents `.pyc` writes to the read-only root. Compose tmpfs
  options match the deviation claims exactly: `/tmp:size=200m,mode=1700,uid=1000,gid=1000`.

One residual item in this class is **INF-19** (upload spooling), below.

### Findings

**INF-1 — GitHub Actions are tag-pinned, not SHA-pinned, in the workflow holding the Docker Hub token**
- Confidence: **CONFIRMED** · Severity: **Medium (supply chain)**
- `.github/workflows/publish.yml:53,75,81,102,107,113`; `.github/workflows/ci.yml:34,37,66,69,102,106,109,194`; `.github/actions/build-image/action.yml:29,32,35`
- All `uses:` reference mutable major tags (`actions/checkout@v4`, `docker/login-action@v3`, `docker/build-push-action@v6`). The dogfood scanner *images* are digest-pinned (ci.yml:127) and CLAUDE.md mandates "pinned image digests" / "pin every dependency", but the actions are not.
- **Scenario:** A compromised/retagged release of any of these actions executes inside `publish.yml` where `secrets.DOCKERHUB_TOKEN` is live (publish.yml:78) — the classic `tj-actions/changed-files` attack. The attacker exfiltrates the token and pushes a malicious `<dockerhub-user>/scrye:latest`. For a security-scanner product this is the worst-case supply-chain outcome.
- **Fix:** Pin every `uses:` to a full commit SHA (with a version comment), including inside the composite action; add Dependabot/Renovate to bump the SHAs.

**INF-2 — `:dev` publish silently fails for merged fork PRs (secrets unavailable) and never fires on direct pushes**
- Confidence: **CONFIRMED** (documented GitHub behavior) · Severity: **Medium**
- `.github/workflows/publish.yml:30-33,93-116`
- The dev job triggers `on: pull_request: types:[closed]` gated on `merged==true`. GitHub does not expose repo secrets to `pull_request` workflows whose head is a **fork** — so for an external contributor's PR merged into `dev` (the explicit purpose of `dev` per CLAUDE.md: "external contributions"), `docker/login-action` (publish.yml:107) gets empty credentials and the job fails; `:dev` is not updated and the run shows red. A *direct* push to `dev` (no PR) never triggers publishing at all.
- **Scenario:** External PR merged into `dev` → publish run fails at login → `<dockerhub-user>/scrye:dev` goes stale while everyone believes it mirrors `dev`.
- **Fix:** Switch the dev job to a base-repo-context trigger with secrets (`on: push: branches:[dev]`, which also matches CLAUDE.md's own wording — see INF-3), or a `workflow_run`/environment-scoped trigger.

**INF-3 — Locked decision §6 text and the implemented `:dev` trigger contradict each other**
- Confidence: **CONFIRMED** · Severity: **Low**
- `CLAUDE.md:43-48` ("every push to the `dev` branch ... pushes `:dev`") vs `publish.yml:30-33` (merged-PR-only). The re-scope is logged in `docs/PLAN.md:1414-1419` but CLAUDE.md — the authoritative "this file wins" document — was never updated.
- **Scenario:** A future session follows CLAUDE.md (which wins over the plan by its own precedence rule) and "fixes" publish.yml back to push-based, re-introducing the double-publish problem the re-scope solved.
- **Fix:** Amend CLAUDE.md §6 to describe the merged-PR trigger (or revert to push-based, which would also fix INF-2).

**INF-4 — `trivy-server` sidecar runs as root (no `user:`, cache mount hard-codes `/root`)**
- Confidence: **CONFIRMED** · Severity: **Medium**
- `docker/docker-compose.yml:70-102` — has read_only/no-new-privileges/cap_drop/limits/healthcheck, but no `user:` key, and mounts `trivy_cache:/root/.cache/trivy` (line 82), only sensible for uid 0. The `aquasec/trivy` image sets no non-root `USER`. CLAUDE.md hard rule: "non-root `USER`/`user:`", with no documented exception here (unlike the socket-proxy's documented residual risk).
- **Scenario:** An RCE in the Trivy server (it parses untrusted vuln-DB content and app network input) yields uid-0 in-container; with a container-escape bug that is host root.
- **Fix:** Add a non-root `user:` and move the cache mount to a matching path (e.g. `--cache-dir`/`XDG_CACHE_HOME`), or document the exception with rationale as the socket proxy does.

**INF-5 — `docker-socket-proxy` under `read_only` + `cap_drop: ALL` with no tmpfs may crash-loop**
- Confidence: **PLAUSIBLE** · Severity: **Medium**
- `docker/docker-compose.yml:109-146` — `read_only: true` (121) + `cap_drop: ALL` (124-125) but **no tmpfs**. `tecnativa/docker-socket-proxy` is HAProxy-based; HAProxy conventionally needs a writable `/run` (pid/stats socket), and upstream hardened examples pair `read_only` with `tmpfs:[/run]`. If the image drops privileges via `setuid`, that needs `CAP_SETUID/SETGID` which `cap_drop: ALL` removes. The service is profile-gated (`--profile docker-env`) so the default `docker compose up` definition-of-done check likely never exercises it.
- **Scenario:** Operator enables `--profile docker-env` → proxy restart-loops (read-only write failure or setuid `EPERM`) → "scan running images" dead; `restart: unless-stopped` masks it as a silent crash-loop.
- **Fix:** Start the profile once and observe; if it fails add a small `tmpfs:[/run]` (and only if required `cap_add:[SETUID,SETGID]` with a comment). Record the verification either way.

**INF-7 — Dockerfile comment overstates verification: checksums are same-origin, not signed**
- Confidence: **CONFIRMED** · Severity: **Low**
- `docker/Dockerfile:7-8,42-67` — header claims binaries are "verified against the publishers' **signed** checksum files", but the build fetches `*_checksums.txt` from the same GitHub release over the same channel and runs `sha256sum -c`. No signature (cosign/GPG) is verified. This defends against corrupt downloads, not a compromised release/CDN.
- **Scenario:** An attacker who can tamper with the GitHub release assets (or MITM despite TLS via a poisoned proxy CA) replaces tarball + checksums; the build passes and ships a trojaned scanner in every image.
- **Fix:** Verify the checksum files' cosign signatures (Trivy and Anchore both publish them), or correct the comment to claim only same-origin integrity.

**INF-8 — Two near-simultaneous release tags can leave `:latest` pointing at the older version**
- Confidence: **CONFIRMED** (race is real; trigger unusual) · Severity: **Low**
- `publish.yml:42-44,80-86` — `concurrency: group: publish-${{ github.ref }}`; distinct tags have distinct refs so they don't serialize, and both push `:latest` with no version ordering.
- **Scenario:** Push `v1.4.1` then immediately `v1.5.0`; the 1.4.1 build finishes last → `:latest` = 1.4.1 while 1.5.0 exists.
- **Fix:** Serialize release jobs under one concurrency group without cancel-in-progress, or apply `:latest` only when the tag is the highest semver.

**INF-9 — No CI runs on `dev`, yet `:dev` is built from the merge commit — the published commit can be untested**
- Confidence: **CONFIRMED** · Severity: **Low**
- `ci.yml:11-14` (push only on `main`) vs `publish.yml:101-104` (builds `merge_commit_sha`). A PR's checks ran against an earlier ephemeral merge ref; the actual merge commit that ships as `:dev` never gets its own CI run.
- **Scenario:** PR A and PR B both pass CI against old `dev`; both merge; the combined state fails tests — but `:dev` builds and pushes from it anyway.
- **Fix:** Add `dev` to `ci.yml` `push.branches` (cheap amd64 jobs), and/or require branch-up-to-date before merge.

**INF-10 — Dogfood gate is HIGH/CRITICAL-only while CLAUDE.md requires resolving *all* fixable findings**
- Confidence: **CONFIRMED** · Severity: **Low**
- `ci.yml:136-146,161-170` — Trivy `--severity HIGH,CRITICAL`; Grype `--fail-on high`. Fixable LOW/MEDIUM appear only in non-gating informational steps (`|| true`). CLAUDE.md § Dependency hygiene says CI "resolves **all fixable findings**". The severity floor is not logged as a deviation (the bundled-binary skip *is*).
- **Scenario:** A fixable MEDIUM OS-package CVE with a patched version in bookworm sits in the image indefinitely with a permanently green gate.
- **Fix:** Gate on all fixable severities (drop the `--severity` filter on the gating run) or log the HIGH/CRITICAL floor as an explicit deviation.

**INF-13 — scrye healthchecks hard-code port 8089 while `SCRYE_PORT` is configurable**
- Confidence: **CONFIRMED** · Severity: **Info**
- `docker/docker-compose.yml:57` and `docker/Dockerfile:124-125` probe `:8089`; `entrypoint.sh:33` uses `--port "${SCRYE_PORT:-8089}"` and `.env.example:27` documents `SCRYE_PORT`.
- **Scenario:** Operator sets `SCRYE_PORT=9000` → app healthy on 9000, healthcheck probes 8089 → container flaps `unhealthy`; anything keyed on health (Caddy, `depends_on: condition`) misbehaves.
- **Fix:** Use the env var in the healthcheck (`CMD-SHELL` with `${SCRYE_PORT:-8089}`), or document that the port must not change in container deployments.

**INF-14 — `trivy-server` healthcheck (`trivy version`) does not test the server listener**
- Confidence: **CONFIRMED** · Severity: **Low**
- `docker/docker-compose.yml:90-96` — `test: ["CMD","trivy","version"]`.
- **Scenario:** The `trivy server` process wedges / fails to bind :4954 while the binary still runs `version` fine → healthy forever; scans using `SCRYE_TRIVY_SERVER_URL` fail with connection errors and nothing flags the sidecar.
- **Fix:** Probe the actual `/healthz` endpoint (needs a TCP/HTTP probe in the image), or accept and document the limitation.

**INF-15 — `trivy-server` tmpfs is unsized and root-owned (`- /tmp`)**
- Confidence: **CONFIRMED** · Severity: **Info**
- `docker/docker-compose.yml:83-84` — `tmpfs: - /tmp` with no `size=`/`mode=`/`uid=`, defaulting to 50% of host RAM; tmpfs pages count against the 1G cgroup limit, so a large temp write OOM-kills the server rather than a clean ENOSPC — the exact mode the app-container fix chose to avoid.
- **Fix:** Add a modest `size=` (and ownership if INF-4 introduces a non-root user).

**INF-12 — Generic private-repo `git clone` runs with a minimal env that drops proxy/TLS vars**
- Confidence: **CONFIRMED** (env content) / PLAUSIBLE (trigger) · Severity: **Low**
- `backend/app/scanners/credentials.py:278-286` — the clone env is a full replacement `{PATH, GIT_ASKPASS, GIT_TERMINAL_PROMPT, GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, SCRYE_GIT_USERNAME, SCRYE_GIT_PASSWORD}`, not an overlay. Unlike scanner subprocesses (which go through `inherited_env()` keeping TLS/proxy vars, base.py:344-354), the git child gets no `HTTPS_PROXY`/`NO_PROXY`/`SSL_CERT_FILE`/`GIT_SSL_CAINFO`.
- **Scenario:** Deployment behind a mandatory egress proxy or custom CA (common in Scrye's homelab/enterprise targets): Trivy image/repo scans work (inherit proxy vars) but generic-host private clones fail with an opaque "Failed to clone the private repository".
- **Fix:** Build the clone env from `inherited_env()` plus the SCRYE_GIT_* keys (SCRYE_* stripping already removes app config).

**INF-16 — Release publish has no dependency on a green CI run for the tagged commit**
- Confidence: **CONFIRMED** · Severity: **Info**
- `publish.yml:47-86` gates only on tag pattern + main-ancestry; nothing checks `ci.yml` passed for `$GITHUB_SHA`. Not a rule violation (CI-green is phrased per-PR), but a commit reaching main via admin bypass could be tagged and published while red.
- **Fix:** Add a check-run success gate or make publish `workflow_run`-triggered on CI success, or rely on documented branch protection and note it.

**INF-17 — Production image ships the full `backend/` tree, including `tests/` and `scripts/`**
- Confidence: **CONFIRMED** · Severity: **Info**
- `docker/Dockerfile:110` — `COPY backend/ /app/backend/`. The venv already has the installed `app` package; the source copy is needed only for Alembic, yet copies everything. `WORKDIR /app/backend` also puts the source `app/` ahead of the venv on `sys.path`, creating a dual import source that can drift.
- **Scenario:** Larger scan/attack surface; a test fixture with dummy-looking secrets would appear in Scrye's own dogfood self-scan.
- **Fix:** Copy only `alembic/`, `alembic.ini`, `app/` (or add `backend/tests` to `.dockerignore`), and pick one canonical import source.

**INF-19 — Large multipart uploads (SBOM, backup restore) spool to the 200 MB `/tmp` tmpfs**
- Confidence: **CONFIRMED** (mechanism) / PLAUSIBLE (trigger) · Severity: **Info** (see also API-4)
- `backend/app/api/scans.py:212-262`, `backups.py:209-236`; tmpfs budget `docker-compose.yml:39-48`. Starlette `UploadFile` spills bodies >~1 MB to `tempfile.gettempdir()` = the 200 MB RAM-backed `/tmp`, shared with transient credential/policy files, before the app copies to `/data`.
- **Scenario:** Two concurrent ~120 MB uploads → ENOSPC on the spool → 500s on unrelated in-flight scans needing `/tmp` for credential materialization.
- **Fix:** Enforce an upload size cap at the API layer (see API-4) and/or point Starlette's spool at `/cache/tmp` for these endpoints; note the shared budget in the README.

**INF-6 / INF-11 / INF-18 — Stale infra docs/comments** (Confidence: CONFIRMED · Severity: Info)
- **INF-6:** `docker/Dockerfile:3`, `docker/docker-compose.yml:1,17` still say "no registry publishing" / cite locked decision §6 as forbidding it, which now contradicts §6.
- **INF-11:** `README.md:299-304` says generic private repos are "cloned into tmpfs"; actual behavior checks out under `/cache/tmp` (`credentials.py:259-262`) since the 2026-07-04 fix — only the askpass helper stays in tmpfs.
- **INF-18:** `README.md:205` quick start only builds locally; the published `<dockerhub-user>/scrye` image is documented only in CONTRIBUTING. (See also DOC-1.)
- **Fix:** Update the three sets of stale text.

### Infra verified-good
scrye service: `user 1000:1000`, read_only, no-new-privileges, cap_drop ALL, loopback-only `127.0.0.1:8089`, cpu/mem limits+reservation, healthcheck (curl genuinely installed, Dockerfile:93-94), restart, capped json-file logging, Docker-secret-file master key — all present. trivy-server & socket-proxy: digest-pinned, cap_drop/no-new-privileges/limits/healthcheck/restart/logging/no-host-port present (gaps are INF-4/5/14/15). Dockerfile: all four bases digest-pinned, multi-stage, COPY-only, sha256-verified binaries, non-root USER, HEALTHCHECK, no secrets in layers, THIRD_PARTY_LICENSES copied, exact-pinned deps. `.dockerignore`/`.gitignore` cover secrets/.env/data/keys. entrypoint: `set -eu`, migrations-before-serve, `--forwarded-allow-ips` defaults to `172.16.0.0/12` (not `*`). CI: runs on every PR + push-to-main, gates ruff/black/`.env.example`-sync/pytest/ESLint/Prettier/type-check/build, never publishes, `permissions: contents: read`, dogfood self-scan with digest-pinned scanner images. **publish.yml release ancestry check is sound**: `fetch-depth:0` + explicit `git fetch origin main` + `git merge-base --is-ancestor "$GITHUB_SHA" FETCH_HEAD` *before* any build/login, hard-fails otherwise; no check-then-fetch race, annotated tags peeled by merge-base. `ci/trivyignore` has zero suppressions; `ci/grype.yaml` suppresses only the three bundled binaries by exact location — nothing stale/overbroad.

---

## 2. Backend security (auth, sessions, secrets, crypto, RBAC, CSRF, rate limiting, audit)

No Critical and no plaintext-secret leak in a standard API read/log path. The one
genuine escalation bug is filed under §7 as **QUA-1** (token minting); it is
security-relevant and cross-referenced here.

**SEC-1 — Token-bearing generic-webhook URL stored in plaintext and returned on read**
- Confidence: **CONFIRMED** · Severity: **Medium**
- `backend/app/api/notifications.py:51-62` (`_masked_config`), `:89` (`config: dict` in read model), `backend/app/db/models/notification.py:69`. `_masked_config` masks the URL **only** for `NotificationType.DISCORD`: `if channel.type is NotificationType.DISCORD and config.get("url"): config["url"] = _URL_MASK`. For `WEBHOOK` the raw `config["url"]` is stored unencrypted in the `config` JSON column and echoed verbatim on `GET /notifications`. (Verified directly against source this session.)
- **Scenario:** An admin creates a generic `webhook` channel whose URL embeds the credential in the path (Slack `hooks.slack.com/services/T…/B…/XXXX`, Teams, Mattermost, Google Chat). That URL *is* the whole credential. Any admin-session viewer — or a DB read, which §6's threat model explicitly targets — recovers a live credential. Discord is special-cased for exactly this property; every other webhook provider with it is not.
- **Fix:** Treat any `WEBHOOK` `config["url"]` as a write-only secret like Discord (route into encrypted `secret_ciphertext`, mask on read), or at minimum mask all webhook URLs on read and store field-encrypted.

**SEC-3 — Password-gated re-auth endpoints are not rate-limited**
- Confidence: **CONFIRMED** · Severity: **Low** (Medium if weak passwords allowed)
- `backend/app/api/auth.py:248` (`/auth/password`), `:327` (`/auth/mfa/enroll` re-enroll), `:366` (`/auth/mfa/activate`), `:384` (`/auth/mfa/disable`) — none call `_enforce_rate_limit` (invoked only in setup/login/verify_mfa).
- **Scenario:** An attacker with a stolen session cookie + readable CSRF token (subdomain XSS, shared/kiosk browser) but not the password can brute-force `current_password` against MFA-disable / password-change / MFA-re-enroll at argon2 speed with no lockout.
- **Fix:** Apply the existing per-IP auth limiter (or a per-user counter) to the password-verifying branches; audit repeated failures.

**SEC-4 — Auth rate-limiter's per-IP bucket map grows unbounded**
- Confidence: **CONFIRMED** · Severity: **Low**
- `backend/app/core/ratelimit.py:28,44-51` — `self._events: dict[str, deque[float]]` gains a key per distinct client IP via `setdefault`; entries are trimmed only *within* a deque, empty deques/keys are never removed (only test-only `reset()` clears).
- **Scenario:** A long-lived instance seeing many distinct source IPs accumulates one dict entry per IP forever — slow unbounded memory growth.
- **Fix:** Drop the key when its window is empty after pruning inside `allow`, or sweep idle keys on a timer.

**SEC-5 — Unauthenticated OIDC login endpoint creates DB rows with no rate limit**
- Confidence: **CONFIRMED** · Severity: **Low**
- `backend/app/api/oidc.py:216-247` — `oidc_login` inserts an `OidcLoginFlow` row + commits on every unauthenticated GET; only a 10-min TTL purge bounds it.
- **Scenario:** A scripted loop of `GET /api/auth/oidc/login` inflates the DB and issues outbound discovery traffic faster than the purge removes rows.
- **Fix:** Apply the auth rate limiter keyed on client IP, consistent with local login.

**SEC-6 — TOTP codes have no replay/last-used tracking within their validity window**
- Confidence: **CONFIRMED** (behavior) / PLAUSIBLE (exploit) · Severity: **Low**
- `backend/app/auth/mfa.py:36-41` — `verify_code` uses `valid_window=1`, accepting a code across three 30s steps with no persisted last-consumed step.
- **Scenario:** An observed code can be reused within ~60–90s. Mitigated: each login MFA challenge is single-use (`PendingMfaStore.consume` pops before verify), so replay still needs a fresh password-authenticated challenge.
- **Fix:** Persist the last-accepted timestep per user and reject codes at or below it, if the residual is judged material.

**SEC-7 — API-token display prefix exposes 4 characters of the secret body**
- Confidence: **CONFIRMED** · Severity: **Info**
- `backend/app/auth/api_tokens.py:17,19,33-34` — `TOKEN_PREFIX="scrye_pat_"` (10 chars) with `_PREFIX_DISPLAY_LEN=14`, so `raw[:14]` includes 4 chars of the `token_urlsafe(32)` body, stored in `token_prefix` and returned in `ApiTokenOut`.
- **Scenario:** Reveals ~24 bits to anyone reading the owner's token list; remaining ~232 bits keep it unguessable — minor, not practically exploitable.
- **Fix:** Put only the fixed marker (or marker + a non-secret token id) in the display prefix.

**SEC-2 / SEC-8 / SEC-9 — Minor** (Confidence: CONFIRMED · Severity: Low/Info)
- **SEC-2:** `backend/app/core/logging.py:140-141` comment claims OIDC `code`/`state` query params are redacted, but `_SECRET_FIELD_NAMES` (`:23-44`) contains no such entry and no URL-query redaction exists. The `code` is single-use/PKCE/nonce/binding-bound and the flow row is deleted on callback, so exposure is limited — but the comment misleads. Fix: add query-param redaction or correct the comment.
- **SEC-8:** `backend/app/api/registries.py:115-119` (create) encrypts a secret even for credential-helper auth types, while `update` (`:168-172`) rejects it via `SECRET_BEARING_AUTH_TYPES`. No leak (the stored secret is unused at scan time) — a validation inconsistency. Fix: apply the same guard on create.
- **SEC-9:** `backend/app/core/registry_check.py:118-119` returns `f"Could not reach the registry: {exc}."` — the credential is passed via `auth=` tuple/header, never the URL, so no secret leaks; noted as the one raw-exception-to-response path. Fix: prefer `type(exc).__name__`.

### Security verified-good
CSRF is a **synchronizer token** compared server-side with `hmac.compare_digest` (`deps.py:107-119`), stronger than double-submit; **every** state-changing endpoint enumerated (incl. Phase-6 additions: schedules/`run`, notifications/`test`, backups/`restore`/`schedule`, trivy-policy, tags, presets, oidc config) depends on `require_csrf` — no gaps. Sessions: opaque 256-bit tokens, only SHA-256 hash stored, revocable+expiring, new session per login (no fixation), password-change revokes all *other* sessions; cookies HttpOnly+SameSite=Lax+Secure-per-config. Passwords: argon2id, `check_needs_rehash` upgrade, unknown-user timing equalization with a real verify. Crypto: AES-256-GCM, HKDF-SHA256 per key version, random 96-bit nonce, versioned self-describing token, per-column AAD, uniform `InvalidTag` (no oracle), malformed token → `SecretDecryptError`. Secrets: master key only from `app_secret_key_file`; all secret reads masked; decrypt only at scan time into tmpfs with shred in `finally`. OIDC: state+nonce+PKCE-S256+`__Host-` binding cookie (compare_digest), `alg` allowlist strips `none`, iss/aud/exp essential, flow deleted before use, `_synced_role` absent-claim-preserves-role + `_other_active_admin_exists` last-admin guard both present (no zero-admin bypass constructible). RBAC: credential lists admin-only with operator `/options` returning id/name only; API-token role re-evaluated as `min(token,user)` on every request. MFA: forced-enrollment never mints a full pre-verification session; re-enroll requires current password whenever any secret exists (incl. pending); challenge tokens 256-bit, one-time, TTL-pruned. Audit coverage of security-relevant actions is comprehensive. Deferred items confirmed as documented (AAD binds column not row; restore uses module scrypt constants).

---

## 3. Scanner orchestration, workers & schedulers, credentials-at-scan-time

**SCN-1 — Unbounded scanner stdout read into memory (no output size cap)**
- Confidence: **CONFIRMED** · Severity: **Medium**
- `backend/app/scanners/base.py:122` — `proc.communicate()` reads the child's entire stdout into one `bytes` with no ceiling; stored whole (`raw_output`) and re-parsed with `json.loads`.
- **Scenario:** A `trivy image` of a large image emits hundreds of MB of JSON (the deviations log records a real 7,072-finding scan). With a 2 GB container limit and `max_concurrent_scans=2`, two large scans each buffering full JSON + the `json.loads` copy + the normalized list can OOM-kill the container; a hostile registry image crafted to maximize output amplifies this.
- **Fix:** Impose a max captured-output byte budget (stream stdout, kill the subprocess with a `ScannerOutputError` past the budget), and/or stream raw output to the artifact file instead of holding it all in RAM.

**SCN-3 — `list[str]` settings can't be parsed from their documented comma-separated env form**
- Confidence: **CONFIRMED** (source + description verified; runtime not executed) · Severity: **Medium (security-relevant)**
- `backend/app/core/config.py:80-86` (`cors_origins`), `:174-181` (`filesystem_scan_roots`). pydantic-settings (pinned 2.7.x) parses `list[str]` env values by attempting `json.loads`; a value like `SCRYE_FILESYSTEM_SCAN_ROOTS=/mnt/a,/mnt/b` (or even a single `/mnt/a`) is not valid JSON → `SettingsError` at startup. No `field_validator(mode="before")`/custom source exists (grep-confirmed), yet both field descriptions and `.env.example` say "Comma-separated". Tests only pass Python lists, so the env path is unexercised.
- **Scenario:** An admin follows `.env.example` and sets `SCRYE_FILESYSTEM_SCAN_ROOTS=/srv/scan` to enable filesystem scanning — the documented *enable switch* for a security-gated feature — and the app fails to start (or mis-parses). CORS origins have the same problem.
- **Fix:** Add a `field_validator(mode="before")` that splits a plain string on commas (trim, drop empties) for both fields, plus a test that constructs `Settings` from the env var specifically.

**SCN-2 — Docker-proxy and registry-check responses read without a size limit**
- Confidence: **CONFIRMED** · Severity: **Low/Medium**
- `backend/app/core/docker_proxy.py:84-97` and `backend/app/core/registry_check.py:101,111` — `httpx.get()` + `.json()` buffer the full body; only a 10s timeout, no size cap.
- **Scenario:** A compromised/malfunctioning proxy (untrusted, internal-net) or a malicious registry under test streams a multi-GB body within the timeout and exhausts memory. Admin/operator-gated, limiting blast radius.
- **Fix:** Bound the response with a streaming read + byte cap before `.json()`; reject over-limit as `DockerProxyError`/failed check.

**SCN-4 — `git checkout <commit>` has no `--` end-of-options terminator**
- Confidence: **CONFIRMED** · Severity: **Low** (defense-in-depth)
- `backend/app/scanners/credentials.py:216-218` — `["git","-C",str(checkout),"checkout","--quiet",str(commit)]`, no `--` before `str(commit)`, unlike the clone at `:208` and every scanner builder. The leading-`-` reject in `ScanCreateIn` (`scan_schemas.py:91-100`) currently closes the practical vector.
- **Scenario:** Any future path that builds a scan's `options` without going through `ScanCreateIn` (migration, import/restore, direct DB edit) reaches this argv unterminated; a commit like `--upload-pack=...` parses as a flag.
- **Fix:** Insert `"--"` before `str(commit)` for consistency; treat the schema validator as one layer, not the only one.

**SCN-5 — Registry credential forwarded to an arbitrary bearer-realm host chosen by the probed registry**
- Confidence: **CONFIRMED** · Severity: **Low**
- `backend/app/core/registry_check.py:59-65` — `realm` comes from the untrusted registry's `Www-Authenticate` header; only its scheme (https) and non-redirect are enforced, not its **host**. The stored Basic credential is then sent there.
- **Scenario:** An admin adds a typo'd/malicious `registry_host`; its 401 challenge returns `realm="https://attacker.example/token"`; the stored credential is sent there (SSRF-adjacent, TLS-only). Inherent to Docker bearer auth, admin-gated.
- **Fix:** Constrain the realm host to match (or be same-registrable-domain as) `registry_host`, or document this as accepted residual risk (the README documents the socket-proxy risk but not this).

**SCN-6 — Multi-step scans have no aggregate wall-clock bound (~2× the configured timeout)**
- Confidence: **CONFIRMED** · Severity: **Low**
- `backend/app/workers/inprocess.py:300-301` (SBOM then image), `:328-332` (clone then repo); `run_command` timeout is **per-subprocess** (`base.py:122`).
- **Scenario:** With `scan_timeout_seconds=1800`, an image+SBOM or generic-repo scan can hold a concurrency slot ~60 min instead of 30; with `max_concurrent_scans=2`, two such scans stall the queue for an hour. Not permanent (there *is* a timeout).
- **Fix:** Track a per-scan overall deadline and derive each subprocess timeout from the remaining budget, or document the multiple.

**SCN-8 — A DB error on one schedule aborts the whole due-firing batch for that tick**
- Confidence: **CONFIRMED** · Severity: **Low**
- `backend/app/workers/schedules.py:51-83` — the per-schedule `try/except` covers only `CronError`; a DB error in one schedule's `add/flush/record_audit` propagates out of `fire_due_schedules`, is caught at `maintenance.py:107`, and rolls back the whole uncommitted batch.
- **Scenario:** One schedule hitting an integrity error prevents every other due schedule that tick from firing (and rolls back their `last_status`/`last_run_at`). Self-heals next tick, but a persistently-bad schedule starves the batch.
- **Fix:** Wrap each schedule's scan creation in its own try/except + savepoint so one bad row is recorded and skipped.

**SCN-7 / SCN-9 / SCN-10 — Minor** (Confidence: CONFIRMED except SCN-9 PLAUSIBLE · Severity: Low/Info)
- **SCN-7:** Cron is evaluated in **UTC** with no timezone affordance (`cron.py:142-156`, `schedules.py:47`); `0 2 * * *` fires at 02:00 UTC, not local. Fix: document the UTC basis or add a per-schedule timezone.
- **SCN-9 (PLAUSIBLE):** Filesystem-scan allowlist containment is sound, but (a) TOCTOU between the worker re-check and Grype reading the tree, and (b) symlinks *inside* an allowed root pointing outside it may be followed by `grype dir:` (`targets.py:117-144`). Opt-in feature, admin-configured roots. Fix: document that roots must not contain untrusted symlinks; disable symlink-following if an option exists.
- **SCN-10:** Deleting a registry/git credential NULLs the schedule's FK column but leaves the stale id in the schedule's `options` JSON (`scan_schedules.py:138-142`), which is what the worker reads. Fails closed (`TargetError "registry no longer exists"`). Fix: scrub the id from referencing schedules' options on delete, or read the FK column. (Same root cause as QUA-2.)

### Scanner/worker verified-good
Subprocess timeout exists (`base.py:121-132`, `wait_for` + `proc.kill()` on timeout/cancel) — the "hung trivy forever" worry does **not** apply. argv option-injection defense is comprehensive on the primary path (`--` in every builder + leading-`-` reject on target/branch/commit/tag; proxy-listed image names are re-validated as a scan target). Credential lifecycle: decrypt-at-scan-time only, tmpfs 0600/0700, shred+rmtree in `finally` on success/failure/cancel; GitHub/GitLab use native env tokens off-argv; `command` not persisted. `inherited_env` strips `SCRYE_*`. Cancel/claim race handled with atomic conditional UPDATEs both sides. Crash recovery marks orphaned RUNNING scans FAILED + re-submits QUEUED on startup. Loop resilience: per-scan try/except, best-effort notify/fail. Parser hardening (`load_json_output`/shape guards), raw bytes persisted even on parse failure, secret findings store only category/title. Cron Vixie semantics correct (dow 7→0, N/step to max, */step unrestricted, ≤366-day catch-up clamp). Docker-proxy/registry transport: http(s)-constrained, enumeration gated on enabled+risk_ack, fails closed on non-https host, refuses non-https bearer realms, `follow_redirects=False`, enumerated data treated as untrusted. Artifact path-traversal guarded. VEX/trivyignore off-argv via env, rmtree in finally, expired rules filtered. Notification dispatch best-effort with non-secret fields. Redaction covers URL userinfo/Bearer/Basic/quoted multi-word, attached to uvicorn loggers.

---

## 4. API layer, data model, reports/exports/diff, backup/restore, dashboard/metrics, performance

**API-2 — `restore_bundle` (scrypt + full DB rebuild) runs directly on the event loop**
- Confidence: **CONFIRMED** · Severity: **High (availability)**
- `backend/app/api/backups.py:209-251` — `async def restore_backup` calls `restore_bundle(db, data, passphrase)` (line 236) with no `run_in_threadpool`. `restore_bundle` does `scrypt(N=2**17, r=8)` (~128 MiB, hundreds of ms; `core/passphrase.py:26-28,60-68`), AES-decrypts the full payload, then **one `db.execute(insert)` per row** (`bundle.py:254`).
- **Scenario:** Restoring a bundle from an instance with ~1M finding rows blocks the event loop for scrypt + ~1M individual INSERTs — realistically minutes. During that window every endpoint including `/healthz` is unresponsive; the container HEALTHCHECK fails and Docker's restart policy can kill the container **mid-restore** (transaction rolls back, restore silently lost, admin sees a dropped connection).
- **Fix:** Run the whole restore in `run_in_threadpool` (contrast `create_backup`, a sync `def`, already off-loop).

**API-3 — Backup bundle build materializes the entire DB (all findings, audit log) as in-memory JSON, held ~3×**
- Confidence: **CONFIRMED** · Severity: **High (availability at volume)**
- `backend/app/backup/bundle.py:106-146` (build), `:213-255` (restore). `findings` (with ~4 kB `description`) and `audit_log` are **not** in `_EXCLUDED_TABLES` (`:50-52`). `inner = json.dumps(...)` then `payload = pass_cipher.encrypt(inner, ...)` holds row dicts + JSON string + ciphertext + base64 simultaneously; `create_backup` then also holds `data` for `sha256_hex(data)` and re-parses via `read_manifest(data)` (`backups.py:129-141`).
- **Scenario:** 1M findings × ~700 B ≈ 700 MB inner JSON → peak RSS well over the 2 GB container limit; the scheduled backup fires nightly and OOM-kills the container. Restore has the same profile plus 1M single-row INSERTs (no `executemany`).
- **Fix:** Stream the dump (per-table `yield_per`, incremental JSON/JSONL to a temp file, chunked/streaming encryption), batch restore inserts with `executemany`, and/or cap-and-warn on findings-table size. At minimum document a practical size ceiling.

**API-5 — Scan worker persists findings and raw artifacts synchronously on the event loop**
- Confidence: **CONFIRMED** · Severity: **Medium-High (performance)**
- `backend/app/workers/inprocess.py:232` (call site), `:342-411` (`_persist_success`) — a plain `def` invoked directly from `async def _run`, no threadpool. It does `store_artifact` (synchronous `path.write_bytes` of the full raw JSON, `core/artifacts.py:55`), one ORM `Finding` per parsed finding in a loop (`:377-392`), and `session.commit()`.
- **Scenario:** A Trivy scan yielding 15k findings + 60 MB raw JSON blocks the loop for the disk write + ~0.5–2 s ORM flush; during that window the whole API (incl. `/healthz` and other scans' subprocess I/O pumping) stalls. The module docstring's "short SQLite writes ... fine at this scale" does not describe a 10k-findings flush.
- **Fix:** Wrap `_persist_success` (and `_store_failure_output`) in `anyio.to_thread.run_sync`, as `BackupScheduler._check_once` already does.

**API-4 — Upload endpoints read the entire body into memory *before* the size cap; no global body limit**
- Confidence: **CONFIRMED** · Severity: **Medium (DoS; auth'd operator/admin + CSRF)**
- `backend/app/api/backups.py:229-231`, `scans.py:228-234` — `data = await file.read()` precedes the `len(data) > _MAX_*` check; `create_app` registers no body-size middleware and uvicorn has no default cap.
- **Scenario:** An operator (or stolen operator token) POSTs a 20 GB "SBOM" to `/api/scans/sbom`; the server allocates 20 GB at `file.read()` — the 25 MiB check never runs — and OOMs.
- **Fix:** Check `file.size`/`Content-Length` first and/or read in chunks up to cap+1, rejecting as soon as exceeded; consider a global max-body middleware.

**API-7 — Dashboard/metrics `latest_succeeded_scans` hydrates a full ORM row per distinct target, unbounded, uncached**
- Confidence: **CONFIRMED** · Severity: **Medium (performance at volume)**
- `backend/app/core/dashboard.py:67-82`, consumed `:110-126`; `core/metrics.py:40` calls `compute_dashboard(db)`. `select(Scan).where(Scan.id.in_(latest_ids))` — no `load_only`, no limit — hydrates a full `Scan` (incl. `options`, `severity_counts`, `error`) per distinct `(scanner, target_type, target)`. Only scanner-DB probes are TTL-cached; the aggregation is recomputed per request.
- **Scenario:** A CI pipeline scanning 5,000 distinct targets over a year: every dashboard load *and every Prometheus scrape* (15–60s interval) hydrates 5,000 ORM rows + a `GROUP BY scanner,target_type,target` over the whole table (no covering index). The metrics scrape additionally computes `scans_over_time` the renderer never uses. Load grows linearly with history.
- **Fix:** Select only needed columns (`load_only`), push critical/high sums into SQL, add a short TTL cache like the scanner-DB one, skip the time series for `/metrics`; add an index on `(status, scanner, target_type, target)`.

**API-1 — N+1 lazy-load of `scan.tags` in `list_scans` and `list_history`**
- Confidence: **CONFIRMED** · Severity: **Medium (performance)**
- `backend/app/api/scans.py:281-287` (list_scans), `:311-319` (list_history); property `db/models/scan.py:150-153`. `ScanOut.model_validate(s)` reads the lazy `tag_rows` relationship; neither endpoint applies `selectinload(Scan.tag_rows)` (only `/scans/export` and dashboard `recent_scans` do).
- **Scenario:** History at `limit=200` → 1 page query + 1 count + **200 individual `SELECT FROM scan_tags`**. Cheap per-query on SQLite but multiplies statement volume ~100× per request and competes more often with the worker's write lock. (Not a regression of the logged eager-load fix, which only claimed export/diff — an adjacent gap.)
- **Fix:** Add `.options(selectinload(Scan.tag_rows))` to both list endpoints.

**API-10 — Backups do not carry artifact files; restore produces rows pointing at nonexistent files**
- Confidence: **CONFIRMED** (behavior); PLAUSIBLE (as a gap — plan says "optionally") · Severity: **Medium (data integrity)**
- `backend/app/backup/bundle.py:50-52` excludes `backups` but **not** `artifacts`; files live outside the DB (`core/artifacts.py`); plan `docs/PLAN.md:258` says "Bundle = SQLite dump + ... + **optionally stored artifacts**" but no artifact option exists and the Deviations entry never states files are excluded.
- **Scenario:** DR restore onto a fresh host: findings/history/counts restore fine, but every artifact download returns 404 "Artifact file is missing" (`scans.py:434`), sha256/size metadata dangles, and re-running an SBOM-target scan fails because `resolve_sbom_path` can't find the SBOM. "Raw scanner JSON is the source of truth" (CLAUDE.md) — the source of truth doesn't survive backup/restore.
- **Fix:** Implement the plan's optional artifact inclusion (tar sidecar or per-artifact blobs with size warnings), or explicitly log the exclusion in Deviations + README and skip/flag orphaned artifact rows on restore.

**API-11 — Restore does not pause the worker/schedulers; concurrent scans race the table wipe**
- Confidence: **PLAUSIBLE** · Severity: **Medium**
- `backend/app/api/backups.py:209-251`; worker keeps its own sessions; `main.py:75-91` runs worker + 2 schedulers always.
- **Scenario:** Restore while a scan is running: the restore transaction deletes all `scans` rows and repopulates ids; the worker then commits Finding rows / status keyed to a replaced or vanished `scan.id`. With `foreign_keys=ON`, findings inserts FK-fail (scan flips to failed), or worse the reused autoincrement id makes the worker's findings attach to a *different* restored scan. Scheduler ticks can interleave writes mid-wipe.
- **Fix:** Before restoring, stop accepting work and drain/cancel the worker + schedulers, or refuse restore while any scan is queued/running.

**API-9 — Malformed-but-decryptable bundles crash restore with a 500 instead of a 400**
- Confidence: **CONFIRMED** · Severity: **Low** (integrity preserved — nothing commits before the endpoint's commit; `get_db` discards the open transaction)
- `backend/app/backup/bundle.py:251-254`; catch at `backups.py:236-239` catches only `BackupError`. `datetime.fromisoformat(bad)` → ValueError; NULL-in-NOT-NULL/dup PK → IntegrityError; non-dict row → TypeError — all propagate as a generic 500.
- **Fix:** Wrap the row-replay loop, re-raising `ValueError/TypeError/KeyError/IntegrityError` as `BackupError("bundle row data is malformed: table X")`.

**API-8 — Backup download reads the whole bundle into memory instead of streaming**
- Confidence: **CONFIRMED** · Severity: **Low/Medium**
- `backend/app/api/backups.py:170-179` — `data = BackupStore().read(...)` → `Response(content=data)`. Two concurrent ~200 MB downloads = 400 MB spike in a memory-limited container.
- **Fix:** Use `FileResponse` (the artifact-download pattern, `scans.py:435-439`); the traversal-safe path is available from `BackupStore._resolved`.

**API-15 — Retention pruning and schedule firing run synchronous DB + file I/O on the event loop each tick**
- Confidence: **CONFIRMED** · Severity: **Low-Medium**
- `backend/app/workers/maintenance.py:73-94` — `_run_retention()` is a direct sync call from `async def tick`; `prune_expired_artifacts` (`core/retention.py:38-52`) loads all matching Artifact rows, `unlink()`s each file, and row-by-row `db.delete()`s before one commit. (Contrast `BackupScheduler`, which hops to a thread.)
- **Scenario:** Enabling retention on an instance with 2 years of history: the *first* tick prunes ~20k rows + files — tens of seconds of loop-blocked unlink+delete; `/healthz` misses its window. Steady-state ticks are small.
- **Fix:** Run `_run_retention` (and `fire_due_schedules`) via `anyio.to_thread.run_sync`; batch deletes with a single `DELETE ... WHERE id IN (...)`.

**API-16 — `GET /api/settings/about` spawns three uncached scanner subprocesses per request**
- Confidence: **CONFIRMED** · Severity: **Low**
- `backend/app/api/settings.py:189-213`; `core/system_info.py:83-93` — `scanner_versions()` has no TTL cache (unlike `scanner_db_status`); `get_about` is `async def` also doing sync DB work inline.
- **Scenario:** A user leaving the About tab on a refresh loop generates constant subprocess churn (3 execs/request, up to 10s timeout each) inside a `cap_drop: ALL` container.
- **Fix:** Reuse the TTL-cache pattern; versions change only on image upgrade so a long TTL is safe.

**API-6 / API-13 / API-14 / API-18 — Contention, missing indexes, unbounded payloads** (Confidence: CONFIRMED except API-6 PLAUSIBLE · Severity: Low/Low-Medium)
- **API-6:** SQLite single-writer — a large findings commit (20k rows on a slow bind-mount) can exceed `busy_timeout=5000` (`session.py:34-36`) and surface `database is locked` as a 500 to a concurrent `POST /scans`. Compounds with API-5. Fix: off-loop persistence + chunked flush; optionally raise busy_timeout for the worker.
- **API-13:** History predicates on `created_by_username` and `highest_severity` have **no indexes** (`scan.py:120-132`); `GET /scans/filter-options` (called on every history mount) does a full-table `DISTINCT created_by_username`. Fix: single-column indexes + brief filter-options cache.
- **API-14:** Scan diff returns every added/removed finding in one JSON with no cap (`scans.py:571-583`); diffing a 0-finding scan vs a 30k-finding scan serializes ~8–10 MB and freezes the browser render. Fix: cap `added`/`removed` (worst-N by severity) with `*_count` fields, or paginate.
- **API-18:** `FilterPresetIn.filters` is an unbounded unvalidated `dict[str, Any]` (`history_schemas.py:97`), no per-user preset cap; a viewer can store a 50 MB filters blob (or 100k presets), bloating the DB and every backup bundle. Fix: validate against known filter keys, cap serialized size (~4 KB) and count.

**API-12 / API-17 / API-19 / API-20 / API-21 — Info-level drift/fragility** (Confidence: CONFIRMED except API-19 PLAUSIBLE)
- **API-12:** The `scans` composite index uses `created_at`, but plan §7 promised `scans(scanner, status, started_at)` (`scan.py:148`, `0003_scan_tables.py:98-103`) — the implemented index is actually the more useful one; only the deviation-logging discipline is at issue. Fix: add a one-line Deviations entry.
- **API-17:** Pagination envelope naming drift: `/audit` returns `{total, entries}` while findings/history return `{total, items}`; `/scans` returns a bare array. (See QUA-9.)
- **API-19:** Diff `severity_delta` counts deduplicated keys (`reports/diff.py:96-115`), so it can disagree with a scan's stored `severity_counts` when the parser emits duplicate rows. Fix: document, or expose both raw and deduped counts.
- **API-20:** `load_only` report queries have no `raiseload` guard (`scans.py:490-517`) — a future exporter field silently reintroduces per-row lazy loads. Fix: add `raiseload("*")` so drift is a loud test failure.
- **API-21:** `delete_backup` unlinks the file before the DB commit (`backups.py:194-206`) — a commit failure leaves a row pointing at nothing (converges via 410). Fix: delete the row, commit, then unlink.

### API/data/perf verified-good
The 2026-07-04 review fixes named in the brief **all hold in code**: diff identity drops location only for VULNERABILITY findings with a vuln_id (`diff.py:35-37`); diff requires same scanner+target_type+target (`scans.py:561-569`); export/diff eager-load tags (`selectinload`, `scans.py:354`) and use `load_only` excluding `description` (`:490-517`); dashboard aggregation runs `run_in_threadpool` (`dashboard.py:102-105`); dashboard grouping is per `(scanner, target_type, target)`; `/metrics` is viewer-authenticated + escaped + sync-def (off-loop); scanner-DB freshness is TTL-cached. CSV formula injection neutralized (`_csv_safe` covers `= + - @ \t \r`, applied to every string cell); Markdown escapes pipes + flattens newlines + formula-guards target/initiator/tags/filters; no Content-Disposition injection (filenames server-generated); backup-store path traversal guarded (bare-name + `.scryebak` suffix); artifact reads root-confined. Restore destructive-confirm present (`confirm=true`, admin+CSRF, sessions wiped, schema-version fail-closed, wrong passphrase → clean 400). WAL + busy_timeout + FK pragmas per connection. Migration chain linear 0001→0008; plan-promised indexes exist (`findings(scan_id, severity, vuln_id)`, `scan_tags`, presets unique) with model/migration parity exact. Pagination caps everywhere (`le=200/1000/500`); history export capped at 5,000. Artifact download streams via `FileResponse`. Cancel/claim race handled.

---

## 5. Frontend

No Critical/High findings. Strictly typed (`strict: true`, zero `any`/`@ts-ignore`/`dangerouslySetInnerHTML`/`localStorage`), lint-disciplined, teal theme first-class in both schemes, CSRF echoed correctly on all mutations, no secrets in code.

**FE-1 — No global 401/session-expiry handling; stale authenticated shell after session death**
- Confidence: **CONFIRMED** · Severity: **Medium**
- `frontend/src/api/client.ts:48-57` only throws `ApiError`; `auth/AuthContext.tsx:43-60` fetches auth status once on mount. Nothing checks `err.status === 401` (the only status check anywhere is the 403 branch in `AccountPage.tsx:99`).
- **Scenario:** Session expires/revoked while the SPA is open → every action shows a per-widget red error but the authenticated shell keeps rendering; the user must know to hard-reload. (No infinite-loop risk.)
- **Fix:** In `api()`, on 401 dispatch an auth-invalidated event that flips `AuthContext.user` to null so `<App>` falls back to `<LoginPage>`.

**FE-3 — Inconsistent UTC parsing: Account/Backups/Schedules render UTC times as local**
- Confidence: **CONFIRMED** · Severity: **Medium**
- Correct (appends `Z`): `ScanDetailPage.tsx:53`, `ScansPage.tsx:63`. Wrong: `AccountPage.tsx:264`, `BackupsPanel.tsx:195,309`, `ScheduledScansPanel.tsx:178`, `Dashboard.tsx:91`. The backend serializes **naive UTC** (`core/timeutil.py`), so `new Date("...")` with no `Z` parses as local.
- **Scenario:** A UTC-7 user sees session "last seen" and backup timestamps 7 hours off; scan timestamps on other pages are correct, making the inconsistency obvious. Classic Phase 2–4 vs Phase 5–6 drift.
- **Fix:** Extract the duplicated `formatWhen` (in ScanDetailPage + ScansPage) into a shared `lib/dates.ts` and use it everywhere a backend timestamp renders.

**FE-4 — BackupsPanel restore file held in `useRef`; "No file selected" label never updates**
- Confidence: **CONFIRMED** · Severity: **Medium** (destructive flow)
- `frontend/src/components/settings/BackupsPanel.tsx:47` (`useRef<File|null>`), `:250` (`onChange={(f) => (restoreFile.current = f)}`), `:258` (`{restoreFile.current?.name ?? 'No file selected'}`). Assigning to `ref.current` doesn't re-render.
- **Scenario:** Admin picks a `.scryebak`, still sees "No file selected", doubts it, then hits the destructive Restore with no confirmation of *which* file. `NewScanPage.tsx:94` uses `useState` correctly — drift within the codebase.
- **Fix:** Change `restoreFile` to `useState<File|null>`.

**FE-5 — ScheduledScansPanel: no scanner/target-type matrix and no role gating**
- Confidence: **CONFIRMED** · Severity: **Medium** (backend enforces, so no security hole)
- `frontend/src/components/settings/ScheduledScansPanel.tsx:221-234` (independent Scanner/Target-type Selects), `:133` (unconditional Add), `:183-193` (Run/Delete for all roles). `NewScanPage.tsx:63-68` has a `SCANNERS_FOR` matrix and the backend rejects invalid combos (`scan_schedules.py:44-46`); the panel does no `useAuth` gating while siblings gate on `canManage`, and `/settings` is route-unguarded (only the nav link is hidden, `App.tsx:28-31`).
- **Scenario:** (a) user schedules a Trivy filesystem scan → 400 only after filling the whole form; (b) a viewer opens `/settings` by URL, sees enabled Add/Run/Delete, and every click 403s.
- **Fix:** Reuse `SCANNERS_FOR` to constrain the scanner Select; add the same `canOperate` gating as siblings.

**FE-2 / FE-10 — Standing process deviations** (Confidence: CONFIRMED · Severity: Medium, process)
- **FE-2:** The API client is **hand-rolled**, not generated from the OpenAPI schema as CLAUDE.md § Coding standards requires; 15 shim modules still carry "generated client comes later" comments (e.g. `api/auth.ts:1`, `api/health.ts:2-4`), and no deviation is logged in `docs/PLAN.md` § 14. Fix: generate the client (openapi-typescript) keeping the thin fetch wrapper, or log the dated deviation.
- **FE-10:** **Zero frontend tests** — `package.json:7-14` has no test runner and no `*.test.*` files exist; CI's "pytest plus any frontend tests" is vacuously satisfied. CLAUDE.md: "every phase ships with tests". FE-3 is exactly the kind of bug a test would have caught. Fix: add vitest + unit tests for `historyFilterParams`, `SCANNERS_FOR`, `SeverityBadge`, date formatting; wire into CI.

**FE-6 through FE-9, FE-11 through FE-16 — Lower-severity** (all CONFIRMED at cited lines · Low/Info)
- **FE-6:** ScansPage history fetch has an out-of-order response race (`ScansPage.tsx:101-121`, no AbortController/sequence guard) — fast typing can overwrite the table with stale results. Fix: request-id/AbortController guard.
- **FE-7:** Scan-status polling tears down/recreates the interval every tick (`ScanDetailPage.tsx:141-145`, `scan` in deps), no backoff, no hidden-tab pause; ScansPage `running` badges never auto-refresh. Fix: depend on `scan?.status`.
- **FE-8:** 422 validation bodies (a `detail` array) surface as generic "Request failed (422)" (`client.ts:50-52`). Fix: join `msg`/`loc` when `detail` is an array.
- **FE-9:** Finding `primary_url` rendered as an anchor with no scheme validation and no explicit `rel` (`ScanDetailPage.tsx:388`); `javascript:` would be honored on click (mostly-trusted vuln-DB data). Fix: render only for `http(s):`, add `rel="noopener noreferrer"`.
- **FE-11:** UsersPanel docstring promises "reset password" but there's no UI; `UserUpdate.password` (`api/users.ts:15`) is dead. Fix: add a set-password action or correct the docstring.
- **FE-12:** Forced-MFA enrollment stores `otpauth_uri` but never renders it and no QR anywhere (`LoginPage.tsx:68`, `AccountPage.tsx:177-179` prints raw text) — users hand-type the base32 secret. Fix: render the URI/QR.
- **FE-13:** `UserMenu` logout swallows a rejected `apiLogout` with no catch (`UserMenu.tsx:42-44`, `AuthContext.tsx:84-87`) — on failure the user stays visually logged in. Fix: catch and clear local auth state regardless.
- **FE-14:** Date-range filters serialize local dates as naive `T00:00:00` interpreted as UTC (`ScansPage.tsx:67-73`) — boundary-day scans appear/disappear for non-UTC users. Fix: convert day boundaries to UTC or label the filter UTC.
- **FE-15:** AuthenticationPanel OIDC save has redundant secret handling + an unchecked cast (`AuthenticationPanel.tsx:97-104`) — correct behavior, fragile code. Fix: build the payload explicitly.
- **FE-16:** Assorted (row-click only on 2 of 9 cells; ApiTokensPanel hides expiry/last-used so an expired token looks active; shared `busy` flag; missing favicon; unchecked `as` casts on Select onChange; unused `LoginResponse.csrf_token`; `NaN` scan ids → ugly error instead of 404; findings hard-capped at 500 with no paging — which positively **prevents** the 10k-row render freeze).

### Frontend verified-good
`strict: true` + noUnused*/noFallthrough; zero `any`/`@ts-ignore`/`dangerouslySetInnerHTML`/storage APIs. Schema fidelity spot-checked against backend (Severity union, ScanOut/FindingOut nullability, HistorySort, the SCANNERS_FOR matrix) — matches. CSRF echoed on all non-GET incl. multipart. No secrets; secret inputs are `PasswordInput`; masked-secret "leave blank to keep" pattern consistent. All deps exact-pinned, lockfile consistent. Theme teal with primaryShade light6/dark8, `auto` scheme, no hardcoded colors (both schemes first-class). Uniform inline-Alert error convention across all pages/panels (no half-migrated notifications). Severity color centralized in `SeverityBadge`. Polling cleanup correct (no leaked intervals). Stable list keys. Cancel affordance mirrors backend queued-only semantics. Dev proxy matches CONTRIBUTING.

---

## 6. Feature completeness vs docs/PLAN.md

Full matrix and evidence are in the source-of-record; the gaps (anything not fully implemented) are below.

**FEAT-1 — Uploaded image-tar targets not implemented (Trivy and Grype)**
- Confidence: **CONFIRMED** · Severity: **Medium** (High combined with DOC-2)
- Plan §4.1 ("registry ref **or uploaded tar**"), §4.2 ("registry ref or tar"). No tar endpoint, no `TargetType`, no worker path, no UI (`db/models/scan.py:40`, `api/scans.py`, `NewScanPage.tsx`). README.md:54 claims it exists.
- **Manifestation:** A user with a `docker save` tar (air-gapped/local image) cannot scan it at all.
- **Fix:** Add a multipart endpoint mirroring `POST /scans/sbom` that stores the tar as an input artifact and feeds `docker-archive:<path>` / Trivy `--input`; or correct README/plan.

**FEAT-2 — "Scan running images" is enumerate-only; no multi-select scan launch**
- Confidence: **CONFIRMED** · Severity: **Medium**
- Plan §4.1 target 2 ("multi-select, scan each"). Enumeration is complete (`api/docker_environments.py:177-200`) but the only UI is a read-only list modal telling the user to hand-copy each ref (`DockerEnvironmentsPanel.tsx:224-251`).
- **Manifestation:** Scanning 15 running images = 15 manual copy/paste submissions.
- **Fix:** Checkbox list in the modal (or a Docker-environment source on New Scan) that POSTs one image scan per selected ref.

**FEAT-3 — Grype filesystem "uploaded archive" target missing**
- Confidence: **CONFIRMED** · Severity: **Low-Medium**
- Plan §4.2 ("uploaded archive or mounted path"). Only the mounted-path variant exists, allowlist-gated off by default (empty `SCRYE_FILESYSTEM_SCAN_ROOTS`).
- **Manifestation:** On the default deployment (no roots) filesystem scanning is entirely unusable and there is no upload alternative.
- **Fix:** Archive upload → extract into `/cache` scratch → `grype dir:`; or document the reduced scope.

**FEAT-4 — Scanner-DB update schedule is a stored no-op**
- Confidence: **CONFIRMED** · Severity: **Medium** (misleading UI)
- `core/app_settings.py:62-64` (`auto_update_db`, `db_update_interval_hours`) editable in `ScannersPanel.tsx:99-106`, but `workers/maintenance.py:73-94` ticks only `fire_due_schedules` + `run_retention`; nothing runs `grype db update` / a Trivy refresh. Phase 5 deferred it to Phase 6; Phase 6 shipped without it and no deviation records the drop.
- **Manifestation:** A quiet instance's DB goes stale regardless of the setting. (DBs do refresh implicitly when scans run, since the scanners auto-update by default — but the knob itself does nothing.)
- **Fix:** A maintenance-tick step honoring the interval (`grype db update`, `trivy image --download-db-only`), or remove/annotate the setting.

**FEAT-5 — Offline/air-gapped DB import missing entirely**
- Confidence: **CONFIRMED** · Severity: **Medium** for air-gapped, Low otherwise
- Plan §4.2/§4.5. No endpoint/worker/UI; `grype.py:66` still calls it "a later phase".
- **Manifestation:** Air-gapped installs cannot load a vuln DB through the product at all (only an undocumented manual `/cache` volume drop works).
- **Fix:** Admin upload endpoint writing to `GRYPE_DB_CACHE_DIR`/`TRIVY_CACHE_DIR` + `grype db import`; document until then.

**FEAT-6 — Grype ignore rules stored but never applied at scan time**
- Confidence: **CONFIRMED** · Severity: **Medium-High** (silently wrong results)
- `ScannerSettings.grype_ignore` (`core/app_settings.py:61`) editable in `ScannersPanel.tsx:94`, referenced nowhere else; the worker builds an empty Grype policy overlay (`workers/inprocess.py:241-255`: "Grype scans carry no such policy").
- **Manifestation:** An admin pastes ignore rules, saves, and Grype keeps reporting the ignored findings with no error or hint.
- **Fix:** Materialize the YAML into tmpfs and pass `GRYPE_CONFIG`/`--config` (mirroring `materialize_trivy_policy`), or remove the field.

**FEAT-7 — Scanner default options/thresholds stored but applied nowhere**
- Confidence: **CONFIRMED** · Severity: **Medium** (same silent-no-op class)
- `default_severities`, `default_ignore_unfixed` (`core/app_settings.py:56-57`) have no consumers: the backend fills absent options with hardcoded all-severities/false (`trivy.py:62-63`), and `NewScanPage.tsx:118-131` hardcodes its initial form values instead of loading `getScannerSettings()`.
- **Manifestation:** Changing instance defaults in Settings → Scanners has zero effect on any scan.
- **Fix:** Prefill the New Scan form (and/or worker fallback) from the scanners settings group.

**FEAT-10 — Key rotation has no admin-facing re-encryption path**
- Confidence: **CONFIRMED** · Severity: **Medium**
- `SecretCipher.rotate()` (`core/crypto.py:253`) is called only by tests. The multi-version key file makes old versions *readable*, but nothing re-encrypts stored rows under the new version, so the old `v1` line can never be dropped. README.md:280-283 tells operators "existing secrets can be re-encrypted, after which the old line can be removed" — no tool does this.
- **Fix:** An admin endpoint/management command walking `SECRET_COLUMNS` calling `rotate()`; until then correct the README.

**FEAT-8 / FEAT-9 / FEAT-11 / FEAT-12 / FEAT-13 / FEAT-14 — Lower-impact gaps** (Confidence: CONFIRMED · Low unless noted)
- **FEAT-8:** VEX policy and `.trivyignore` are **global-only**, not the per-scan options §4.1 lists (`scanners/trivy_policy.py`, `TrivyPolicyPanel.tsx`). Deviation logged, but README.md:60-61 still advertises them per-scan (see DOC-2). Fix: README wording; optional per-scan overrides later.
- **FEAT-9:** Trivy server URL is deploy-time env only (`trivy.py:80-81`); §4.5 expects a Scanners *setting* — `ScannersPanel` has no field. Fix: add the runtime setting or document env-only. (See also FEAT-11.)
- **FEAT-11:** `SCRYE_DOCKER_PROXY_URL` is a **dead config knob** — defined (`config.py:129`), in `.env.example:57`, in the README table, in the plan's compose, but read nowhere (Docker environments carry their own `proxy_url`). Fix: remove it, or use it to seed a default Docker environment. (= QUA-20.)
- **FEAT-12:** SBOM generation is unavailable for repository scans (`scan_schemas.py:110-125`, `NewScanPage.tsx:140`). Fix: allow a Syft pass over the repo checkout, or document.
- **FEAT-13:** Restore's destructive confirm is a single click — backend requires `confirm=true` but the client hardcodes it (`api/backups.ts:52`); UI is a warning alert + one button (`BackupsPanel.tsx:243-272`), no type-to-confirm. Fix: a `@mantine/modals` confirm step.
- **FEAT-14:** Audit log has an admin API (`api/audit.py`) but **no UI** (zero frontend references). Plan requires maintaining the log (done), not a viewer — polish gap only.

---

## 7. Backend code quality (duplication, drift, type-safety, error handling)

Ruff and Black both pass clean (144 files). Docstrings on every module/function (lint-enforced). Zero TODO/FIXME/XXX in the whole backend. No bare `except:`; every broad `except Exception` (7 sites) is `# noqa: BLE001`-justified, logged, and rolls back. 100% SQLAlchemy 2.0 typed style; migration/model table parity exact; cascades correct at ORM+DB level; async tasks never dropped.

**QUA-1 — API-token minting checks the owner's role, not the effective role: privilege escalation** ⚠️
- Confidence: **CONFIRMED** · Severity: **High**
- `backend/app/api/api_tokens.py:84-88`:
  ```python
  role = payload.role or auth.user.role
  if ROLE_RANK[role] > ROLE_RANK[auth.user.role]:
  ```
  `POST /api-tokens` is guarded by `require_csrf`, which passes **bearer-token** callers straight through (`auth/deps.py:114`). `AuthContext.effective_role` (`deps.py:42-46`) deliberately caps a token's privilege at `min(token.role, user.role)`, but the mint check compares against `auth.user.role`. (Verified directly against source this session.)
- **Scenario:** A stolen or deliberately-scoped **viewer**-role API token belonging to an **admin** calls `POST /api-tokens` with `role: admin`. The cap check compares against the owner's role (admin), passes, and mints a fresh **admin**-role token — defeating the entire point of scoped tokens (the `deps.py` docstring: "downgrading an account also downgrades its tokens"). No test covers minting-via-token.
- **Fix:** Compare against `auth.effective_role` and default `role` to `auth.effective_role`, not `auth.user.role`.

**QUA-3 — Five ScannerSettings fields editable via the API but consumed by nothing**
- Confidence: **CONFIRMED** · Severity: **Medium** (aggregates FEAT-4/6/7)
- `core/app_settings.py:56-67` — `default_severities`, `default_ignore_unfixed`, `grype_ignore`, `auto_update_db`, `db_update_interval_hours` have zero consumers outside `app_settings.py` (only `trivyignore` is used). Admins PUT them at `/api/settings/scanners` and the UI implies behavior that doesn't exist.
- **Fix:** Wire them (see FEAT-4/6/7) or remove the fields.

**QUA-2 — ScanSchedule stores credential references twice; the FK `SET NULL` is cosmetic**
- Confidence: **CONFIRMED** · Severity: **Medium**
- `db/models/scan_schedule.py:40-45` declares `registry_id`/`git_credential_id` with `ondelete="SET NULL"`, and `_apply_template` (`api/scan_schedules.py:130-142`) writes them to the columns **and** into `options` JSON (via `to_options()`), but scans are built **only from `options`** (`workers/schedules.py:27-38`). Deleting a registry NULLs the column while the JSON copy survives, so the schedule keeps firing failing scans and the two stores can silently disagree. (= root cause of SCN-10.)
- **Fix:** Make one representation authoritative (read the FK columns when building the scan, or drop the columns).

**QUA-4 — Four near-identical secret-resource CRUD routers (~900 lines of parallel code)**
- Confidence: **CONFIRMED** · Severity: **Medium** (maintainability)
- `api/registries.py`, `git_credentials.py`, `docker_environments.py`, `notifications.py` (+ partly `oidc.py`, `backups.py`) each hand-roll `_to_out`, `_get_or_404`, a name-uniqueness 409, the `changes` accumulate→`record_audit`→commit PATCH pattern, and the encrypt-secret+`secret_updated_at` write. They have **already drifted** (QUA-8/9/10/12).
- **Fix:** A small generic helper module (`get_or_404`, `apply_secret_update`, name-clash checker) — no framework.

**QUA-9 — Three list-envelope conventions across phases**
- Confidence: **CONFIRMED** · Severity: **Medium** (API consistency)
- Bare arrays (`/scans`, `/users`, `/backups`, `/registries`, `/scan-schedules`, `/notifications`, ...); `{total, items}` (`/scans/history`, findings); `{total, entries}` (`/audit` — same concept, different key). Also `/scans` (Phase 2) is now a strict subset of `/scans/history` (Phase 4).
- **Fix:** Standardize on `{total, items}` when the API is next versioned; consider retiring the bare `/scans`.

**QUA-16 — No type checker anywhere**
- Confidence: **CONFIRMED** · Severity: **Medium**
- `pyproject.toml` has no mypy/pyright, ruff's `ANN` rules aren't selected, and CI runs only ruff/black/pytest. CLAUDE.md's "type hints everywhere" is convention-only; the annotation lies in QUA-17 are invisible to CI.
- **Fix:** Add mypy or pyright (even non-strict) to CI.

**QUA-5 through QUA-24 — Duplication / drift / type / dead-code (grouped)** (all CONFIRMED except QUA-15 PLAUSIBLE · Low/trivial)
- **QUA-5:** `_ALLOWED_SCANNERS` matrix duplicated with divergence (`scans.py:77-82` vs `scan_schedules.py:43-47`).
- **QUA-6:** Scan-from-template construction duplicated (`workers/schedules.py:27-38` vs `scan_schedules.py:262-271`).
- **QUA-7:** Pagination params re-declared per endpoint with four different caps.
- **QUA-8:** Trivy version probe implemented twice (`trivy.py:243-266`, `system_info.py:126-146`).
- **QUA-10:** Create schemas strip/validate; Update schemas don't (`target_schemas.py` — `RegistryUpdateIn` etc.); `DockerEnvironmentUpdateIn._check_proxy_scheme` validates a stripped value but stores the unstripped one.
- **QUA-11:** Notification secret rules asymmetric between create (refuses missing) and update (allows clearing) — a state create would 422.
- **QUA-12:** Two mask literals — `SECRET_MASK` 8 bullets (`masking.py:17`) vs `_URL_MASK` 6 bullets (`notifications.py:48`); a client echoing the 8-bullet mask into `config.url` would have the mask itself encrypted and stored as the webhook URL.
- **QUA-13:** Name-clash check idioms differ (self-exclude via `Model.id != id` vs a `name != current.name` pre-guard).
- **QUA-14:** `filter_presets` router skips auditing and uses a different commit pattern (the only CRUD surface invisible to the audit log; plausibly intended).
- **QUA-15 (PLAUSIBLE):** `run_schedule_now` leaves `last_run_at`/`last_status` stale (sets only `last_scan_id`), so `last_status` can describe a firing that isn't `last_scan_id`'s.
- **QUA-17:** Annotation lies / `Any` seams (`require_role(...) -> object`; `_SORT_COLUMNS: dict[str, object]`; un-parameterized `options: dict`/`base_env: dict`; reflection `ScannerInfoOut(**info.__dict__)`/`(**vars(p))` breaks silently on a field rename).
- **QUA-18:** `delete_backup` unlinks the file before commit; `create_backup` writes the file before insert with no orphan cleanup (the scan worker sets the correct pattern). (= API-21.)
- **QUA-19:** `backups.py:301-307` re-validates a passphrase length already enforced by the schema — unreachable.
- **QUA-20:** `Settings.docker_proxy_url` dead knob. (= FEAT-11.)
- **QUA-21:** `write_backup_file`/`read_backup_file`/`delete_backup_file` (`backup/store.py:70-82`) exported but never called.
- **QUA-22:** `workers/schedules.py:78-82` — `if created: db.commit() else: db.commit()` identical branches.
- **QUA-23:** `tests/conftest.py:44-59` builds schema via `create_all`, never the Alembic chain — a migration that drifts from the models passes CI. Fix: an "alembic upgrade head matches metadata" test.
- **QUA-24:** Coverage gaps — no test for token-minting via a lower-role token (the QUA-1 hole), no direct rate-limiter unit test, no dedicated `scan_filters`/`core/audit` test files.

---

## 8. Documentation deliverables

**DOC-1 — README contradicts locked decision §6 on Docker Hub publishing**
- Confidence: **CONFIRMED** · Severity: **Medium**
- `README.md:193` ("built locally (there is no published registry image yet)"), `:497-498` ("there is no published registry image (a locked decision for v1)"), `:559-560` (roadmap lists "container-registry publishing" as *deferred*). Meanwhile `publish.yml` exists and CLAUDE.md §6 / PLAN §0.6 (revised 2026-07-04) make Docker Hub publishing in-scope; only the README was never updated.
- **Fix:** Rewrite Quick start/Building/Roadmap to reference `docker pull <dockerhub-user>/scrye:…`.

**DOC-2 — README overstates unimplemented features**
- Confidence: **CONFIRMED** · Severity: **Medium**
- `README.md:54` "registry ref **or uploaded tar**" (FEAT-1 — missing); `:60-61` lists "VEX policy, `.trivyignore` rules" among **per-scan** options (FEAT-8 — global-only).
- **Fix:** Align wording with reality.

**DOC-3 / DOC-4 / DOC-5 — Lower-severity doc gaps** (Confidence: CONFIRMED · Low unless noted)
- **DOC-3:** README config table (`:245-269`) omits `SCRYE_FORWARDED_ALLOW_IPS` (discussed in prose at `:404-436`) and `SCRYE_SCANNER_CACHE_DIR`, both in `.env.example`.
- **DOC-4:** Duplicate `## Releasing` heading in CONTRIBUTING.md (`:271` and `:284`).
- **DOC-5 (Low-Medium):** README (`:66,110`) advertises "ECR/GCR/ACR credential helpers" with **no note** that the helper binaries are not bundled and must be provided by the deployment (the logged Phase 3 deviation). A user configuring an `aws_ecr` registry against the stock image gets a runtime failure with no doc trail.

### Docs verified-good
CONTRIBUTING.md is complete against §10.2 (all headings present). LICENSE present, MIT. `.env.example` is **in sync** with the `Settings` model (field-by-field diff clean; `gen_env_example.py` has a `--check` mode CI runs). THIRD_PARTY_LICENSES/ complete: trivy LICENSE+NOTICE, grype/syft LICENSE, README version table (Trivy **0.72.0** correction is in place, matching the Dockerfile; Grype 0.115.0, Syft 1.46.0 match), README "Integrations" pointer present.

---

## 9. Previously-logged known limitations — current state

| # | Limitation (from § Deviations) | State | Evidence |
|---|---|---|---|
| a | SBOM content-identity collapse (filename-based target identity) | **Still present** | `api/scans.py:243-248` stores `target=display_name`; diff/dashboard key on `(scanner, target_type, target)`. The sha256 needed for the fix is already stored on the artifact. |
| b | OIDC MFA not enforced locally | **Still present; documented as accepted** | README.md:443-451; local-only enforcement confirmed (`api/auth.py:159-181`). |
| c | Registry HTTP-scheme allowance → fixed to refuse http | **Fix verified in code** | `core/registry_check.py:89-96` refuses `http://` before any request; bearer realm must be https; credentialed redirects not followed. |
| d | Cancellation limited to queued scans | **Still present** | `api/scans.py:442-483`; worker has no subprocess-interruption channel. |
| e | Cross-version backup restore requires matching schema | **Still present (hardened: fails closed on unversioned bundle)** | `backup/bundle.py:192-204`. |
| f | AAD not bound to row id (column-level only) | **Still present, documented in-code** | `core/secret_store.py:10-16`; deferred rationale re-recorded 2026-07-04. |
| g | Restore derives passphrase key from module scrypt constants, not envelope params | **Still present — and now COMPOUNDING** | `bundle.py:206-211` reads only `kdf["salt"]`; `passphrase.py:26-28,71-78` uses module `SCRYPT_N/R/P`. **Because the constants already changed once (2^15→2^17), any bundle produced before that bump is now unrestorable.** The "compatibility seam" is live, not hypothetical. Fix: honor the envelope's advertised `kdf.n/r/p`. |
| h | Credential-helper binaries not bundled | **Still present; NOT documented in README** | `docker/Dockerfile` pulls only trivy/grype/syft; README mentions the helpers with no caveat (= DOC-5). |
| i | Generated SBOM not fed back into the same Grype run | **Still deferred as logged** | `workers/inprocess.py:286-302` runs two independent cataloging passes. |

Item **(g)** is the one that has quietly worsened and deserves attention beyond its
"documented seam" status.

---

## 10. Prioritized action list

Ranked by what to fix first. Severity in parentheses; confidence noted where not CONFIRMED.

### P0 — Correctness / security / data-loss (fix before the next release)
1. **QUA-1** (High) — API-token minting uses owner role, not effective role → privilege escalation from a low-privilege token. One-line fix: compare/default against `auth.effective_role`. Add the missing test.
2. **API-2** (High) — Restore runs scrypt + row-by-row rebuild on the event loop; the container's own healthcheck can kill it mid-restore. Wrap in `run_in_threadpool`.
3. **API-3** (High) — Backup build materializes the whole findings table in memory → OOM at volume. Stream the dump + batch restore inserts, or at minimum enforce/document a size ceiling.
4. **API-10** (Medium, data integrity) — Artifact files don't travel in backups → restored DB points at missing files; "source of truth" doesn't survive DR. Implement optional artifact inclusion or explicitly document + flag orphans on restore.
5. **SEC-1** (Medium) — Generic webhook URLs (Slack/Teams/Mattermost) stored plaintext + returned on read. Treat all webhook URLs as write-only secrets like Discord.
6. **API-11** (Medium, PLAUSIBLE) — Restore doesn't pause the worker/schedulers → id-reuse race can attach live findings to a restored scan. Drain/refuse-while-active.

### P1 — Availability / performance under real volume
7. **API-5** (Medium-High) — Worker persists 10k+ findings on the event loop. Off-load to a thread.
8. **SCN-1** (Medium) — Unbounded scanner stdout in memory → OOM on a large/hostile image. Cap captured output / stream to disk.
9. **API-4** (Medium) — Uploads read the full body before the size cap → 20 GB upload OOM. Check size first / global body limit.
10. **API-7** (Medium) — Dashboard/metrics hydrate a full ORM row per distinct target, uncached, on every scrape. `load_only` + push sums to SQL + TTL cache + covering index.
11. **API-1** (Medium) — N+1 on `scan.tags` in the two list endpoints. Add `selectinload`.
12. **API-15 / API-6** (Low-Medium) — Retention prune + large findings commit block the loop / exceed busy_timeout. Off-load; batch deletes.

### P2 — Supply chain / deployment hardening
13. **INF-1** (Medium) — SHA-pin all GitHub Actions in the token-holding workflows.
14. **INF-2** (Medium) — `:dev` publish fails for merged fork PRs; switch to a base-repo-context trigger (also reconciles **INF-3**).
15. **INF-4** (Medium) — Give `trivy-server` a non-root `user:` (or document the exception).
16. **INF-5** (Medium, PLAUSIBLE) — Verify the socket-proxy actually starts under read_only + cap_drop; add `tmpfs:[/run]` if needed.
17. **SCN-3** (Medium) — Comma-separated `list[str]` env vars don't parse → the filesystem-allowlist and CORS enable-switches fail at startup. Add a before-validator + a test.

### P3 — Feature gaps that mislead users
18. **FEAT-6 / FEAT-7 / FEAT-4** (Medium / QUA-3) — Wire the three dead Settings→Scanners knobs (Grype ignore, defaults, DB schedule) or remove them.
19. **FEAT-10** (Medium) — Provide a key-rotation re-encryption path, or correct the README claim.
20. **DOC-1 / DOC-2** (Medium) — Fix the README: Docker Hub publishing is in-scope; uploaded-tar and per-scan VEX/trivyignore are not implemented.
21. **FEAT-1 / FEAT-2 / FEAT-3 / FEAT-5** (Medium / Low-Medium) — Implement (or explicitly de-scope in docs) image-tar upload, Docker-env multi-select scan, filesystem-archive upload, offline DB import.

### P4 — Frontend correctness / UX
22. **FE-1** (Medium) — Global 401 handling → drop to login on session death.
23. **FE-3** (Medium) — Fix UTC-as-local timestamps in Account/Backups/Schedules; extract a shared date helper.
24. **FE-4** (Medium) — Restore file label never updates (`useRef` → `useState`) on a destructive flow.
25. **FE-5** (Medium) — Scanner/target matrix + role gating in ScheduledScansPanel; guard the `/settings` route.

### P5 — Maintainability, process, and the long tail
26. **item (g)** (§9) — Honor the backup envelope's scrypt params so pre-bump bundles restore; at minimum document that they can't.
27. **QUA-4 / QUA-9** — Consolidate the four secret-CRUD routers and standardize the list envelope (structurally prevents the QUA-8/10/11/12 drift family).
28. **QUA-16** — Add a type checker to CI. **QUA-23** — Add an Alembic-vs-metadata migration test. **FE-10 / FE-2** — Add frontend tests; generate the API client or log the deviation.
29. Remaining Low/Info items: INF-7/8/9/10/12/13/14/15/16/17/19, SEC-2/3/4/5/6/7/8/9, SCN-2/4/5/6/7/8/9/10, API-8/9/12/13/14/17/18/19/20/21, FE-6..FE-16, FEAT-8/9/11/12/13/14, DOC-3/4/5, QUA-5..QUA-22/24. Each has a file:line and fix direction above; batch by file when touching adjacent code.

### Deviation-logging debt (CLAUDE.md § Git & PR conventions requires these in docs/PLAN.md § Deviations)
The following are un-logged divergences from the plan and should get dated entries
regardless of whether the underlying item is "fixed": **FE-2** (hand-rolled API client),
**INF-10** (HIGH/CRITICAL-only dogfood floor), **API-12** (`created_at` vs `started_at`
index), **FEAT-4** (DB-schedule actuation dropped from Phase 6).

---

*End of report. Every finding ID is stable; cite them in follow-up commits/PRs. Where a
finding is marked PLAUSIBLE, verify the trigger condition (usually a runtime/volume or
library-behavior check) before or alongside the fix.*
