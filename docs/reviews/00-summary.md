# Consolidated review summary — 2026-07-12

Synthesizes six independent `/code-review` reports (security, supply-chain, API/data-model,
frontend, concurrency, CLAUDE.md compliance) gathered onto `feat/reviews`, cross-referenced
against `CLAUDE.md`'s locked decisions/hard security rules and `docs/ARCHIVE.md`'s build
history and deviation log. **No application code was touched to produce this summary** —
findings below are pointers into the six source reports, deduplicated where two reviews
reached the same code from different angles.

Source reports: `security-review.md` (SEC), `supply-chain-review.md` (SC), `api-review.md`
(APIR), `frontend-review.md` (P1/P2/P3), `concurrency-review.md` (CON),
`claude-md-compliance.md` (D/R).

---

## Top 5 to fix before the next release

### 1. Operator can read arbitrary host files via a "repository" scan — bypasses the filesystem allowlist
**SEC-1 (HIGH)** · `backend/app/workers/inprocess.py:329-330`, `backend/app/api/scan_schemas.py:77-89`, `backend/app/scanners/trivy.py:103-127`

The filesystem-scan allowlist (`SCRYE_FILESYSTEM_SCAN_ROOTS`) exists specifically so an
operator can't read the SQLite DB or the master-key file as scan output — but it only
gates `target_type=filesystem`. A `target_type=repository` scan with no git credential is
validated only for length/leading-dash and passed straight to `trivy repo -- <target>`,
which accepts a **local path**. An operator (not admin) can submit `target=/data` or
`target=/run/secrets` and have Trivy walk the container filesystem, with results persisted
as a downloadable artifact. This is the single clearest privilege-escalation path in the
codebase and directly undermines the master-key/secrets threat model in CLAUDE.md § Hard
security rules.
**Fix:** require repository targets to parse as remote clone URLs (reuse `is_http_url` +
ssh/git allowance), or route bare local paths through the existing
`SCRYE_FILESYSTEM_SCAN_ROOTS` gate. Add a regression test for `target="/data"`.

### 2. Scans get stuck "running" forever and lose results under write contention; a mid-scan backup restore can corrupt history
**CON-1 (HIGH)** · `backend/app/workers/inprocess.py:414-470` — **CON-3 (HIGH)** · `backend/app/api/backups.py:245-266` — **SEC-2 (MEDIUM)** · `backend/app/backup/bundle.py:262-269`, `backend/app/core/passphrase.py:73-83`

Three findings compound into one release-blocking risk theme: (a) nothing in the codebase
retries or handles `OperationalError` from SQLite's 5s `busy_timeout`, so a large findings
flush, a restore, or a retention pass can push a concurrent scan's commit past the ceiling
— the scan's artifact files get unlinked (results permanently lost) and the scan is left
`status=running` forever, unrecoverable short of a container restart; (b) the restore
endpoint's "no active scans" guard is check-then-act across a multi-MB upload `await`, so a
scan queued in that window runs against a database mid-wipe/rebuild, corrupting the
restored history; (c) restore also trusts attacker-controlled scrypt cost parameters from
the uploaded bundle with no upper bound, letting a crafted upload OOM-kill the container
before the passphrase is even checked.
**Fix:** add bounded retry-with-backoff on the worker's commits + a stale-`RUNNING`/orphaned-`QUEUED`
watchdog in the maintenance tick (retires CON-1 and CON-11 together); re-check the
active-scan count inside `restore_bundle`'s write transaction and pause the worker for the
duration of a restore (CON-3); clamp `n/r/p` and cap `maxmem` on restore-supplied scrypt
parameters (SEC-2).

### 3. Scanner-derived `href` renders unsafely, and the CSRF cookie is JS-readable — together a full account-takeover chain
**P1-1 (frontend, HIGH-equivalent)** · `frontend/src/pages/ScanDetailPage.tsx:430` — **SEC-5 (MEDIUM)** · `backend/app/main.py:160-194`, `backend/app/auth/cookies.py:29-38`

A finding's `primary_url` (sourced from scanner JSON, which can be influenced by a scanned
repo/image/SBOM) is rendered as an `<Anchor href={f.primary_url}>` with no scheme
validation — a crafted `javascript:` URL executes in the app origin when clicked. Normally
XSS-vs-CSRF-cookie is two separate hardening items, but here the app's CSRF cookie is
deliberately `httponly=False` (JS-readable, by design for the double-submit pattern) and
the app emits no CSP/`X-Frame-Options`/`nosniff` headers at all — so this specific XSS sink
fully defeats both CSRF and session protection for whoever clicks the link (an operator or
admin). This is the one raw-URL/HTML sink in an otherwise clean frontend (no `any`, no
`dangerouslySetInnerHTML`, no `innerHTML` elsewhere).
**Fix:** validate `primary_url`'s scheme (`http:`/`https:` only) before rendering as a link
(small `safeHttpUrl()` helper); add `rel="noopener noreferrer"`. Independently, ship a
baseline CSP + `X-Frame-Options: DENY` + `X-Content-Type-Options: nosniff` response
middleware so link-sink containment doesn't depend solely on this one fix.

### 4. Killing a scan subprocess leaves credential-bearing grandchild processes running
**CON-2 (HIGH)** · `backend/app/scanners/base.py:173,191,199,204`, `backend/app/scanners/credentials.py:185`

`proc.kill()` only signals the direct child; `git clone` spawns `git-remote-https`, and
trivy/grype can spawn their own helpers. On timeout, output-cap overflow, or a shutdown
cancellation mid-clone, the parent is killed but the grandchild survives with
`SCRYE_GIT_PASSWORD`/`GIT_ASKPASS` still in its environment, racing the checkout
directory's cleanup (`shutil.rmtree(ignore_errors=True)`). This is a credential-exposure
bug wearing a concurrency-bug hat, and it is not covered by the security review's (correct)
finding that git tokens are otherwise kept off argv and shredded — this is the one abort
path that circumvents that discipline.
**Fix:** `create_subprocess_exec(..., start_new_session=True)` and kill the whole process
group (`os.killpg`) on all three abort paths (timeout, overflow, cancellation).

### 5. CI Actions are tag-pinned (not SHA-pinned) and dependency monitoring covers only GitHub Actions
**SC-2 (HIGH)** · `.github/workflows/*.yml`, `.github/actions/build-image/action.yml` — **SC-3 (HIGH)** · `.github/dependabot.yml`

Every `uses:` in the workflows resolves a mutable tag (`actions/checkout@v7`, etc.). A
compromised action repo moving its tag runs arbitrary code inside `publish.yml`/
`dev-nightly.yml`, which hold `packages: write` — the ability to push a poisoned
`ghcr.io/tyler-rich/scrye:latest`. This is the exact class of the tj-actions/changed-files
attack and is already tracked as ROADMAP/INF-1, but is unresolved and the risk went up when
the repo went public. Compounding it, `dependabot.yml` watches only the `github-actions`
ecosystem — there is no automated update path for Python (`pyproject.toml`), npm
(`package.json`), or Docker base images, which has already let real drift accumulate
(15-month-old `docker-socket-proxy` pin, stale `node` base digest, `uvicorn` 17 minors
behind).
**Fix:** SHA-pin all `uses:` refs (resolve from a GitHub-reachable environment, or take
Dependabot's first rewrite once enabled); add `pip`, `npm`, `docker` ecosystems to
`dependabot.yml` (target `dev`, weekly, grouped); enable Dependabot security alerts in repo
settings.

---

## Full severity-ranked backlog

### High

| # | Finding | Source | File:line |
|---|---|---|---|
| H1 | `repository` scans bypass the filesystem-scan allowlist → arbitrary local-path read | SEC-1 | `workers/inprocess.py:329`, `api/scan_schemas.py:77` |
| H2 | SQLite lock contention unhandled anywhere → scans stuck `running` forever, results deleted | CON-1 | `workers/inprocess.py:414-470` |
| H3 | Subprocess kill signals only the direct child → credential-bearing git/scanner grandchildren survive | CON-2 | `scanners/base.py:173,191,199,204`, `scanners/credentials.py:185` |
| H4 | Restore's active-scan guard is check-then-act across an `await` → racing scan corrupts restored DB | CON-3 | `api/backups.py:245-266` |
| H5 | Scanner JSON parse/normalize runs on the event loop → large report freezes the whole app, can fail healthcheck | CON-4 | `scanners/trivy.py:285`, `scanners/grype.py:186`, `scanners/base.py:345` |
| H6 | XSS: scanner-derived `primary_url` rendered as unvalidated `href`, compounded by JS-readable CSRF cookie + no CSP | P1-1 (FE) + SEC-5 | `pages/ScanDetailPage.tsx:430`; `main.py:160`, `auth/cookies.py:31` |
| H7 | Timezone-aware `expires_at` on Trivy ignore rules stored with UTC offset silently dropped — CVE suppression expires at the wrong time | APIR-1 | `api/trivy_policy.py:212`, `db/models/trivy_policy.py:438` |
| H8 | Two incompatible 422 error-body shapes; SPA only renders one → validation errors show as blank "Request failed (422)" | APIR-2 | `api/scans.py:120,171,616`; `frontend/src/api/client.ts:62-63` |
| H9 | GitHub Actions tag-pinned, not SHA-pinned → compromised action can push a poisoned `:latest` (tracked, overdue) | SC-2 | `.github/workflows/*.yml` |
| H10 | Dependabot watches only `github-actions`; pip/npm/docker unmonitored | SC-3 | `.github/dependabot.yml` |
| H11 | No backend lockfile — transitive Python deps float unpinned/unverified at every image build | SC-1 | `backend/pyproject.toml`, `docker/Dockerfile` |

### Medium

| # | Finding | Source | File:line |
|---|---|---|---|
| M1 | Backup restore trusts bundle-supplied scrypt cost params, no ceiling → pre-passphrase memory-exhaustion DoS | SEC-2 | `backup/bundle.py:262-269`, `core/passphrase.py:73-83` |
| M2 | No entropy floor / no key-stretching on the master key → stolen-DB brute-force if a weak-but-long key was chosen | SEC-3 | `core/crypto.py:79,167` |
| M3 | Log-redaction filter only prefix-masks unquoted secrets containing spaces/commas | SEC-4 | `core/logging.py:59-62` |
| M4 | No CSP/`X-Frame-Options`/`nosniff`/`Referrer-Policy`; relies entirely on external proxy | SEC-5 | `main.py:160-194` |
| M5 | SSRF: notification/registry/docker-proxy fetchers reach arbitrary internal/link-local hosts (admin-gated) | SEC-6 | `core/notifications.py`, `core/registry_check.py`, `core/docker_proxy.py` |
| M6 | Sync DB commits/reads on the event loop in async contexts — one slow writer stalls the whole app up to 5s | CON-5 | `workers/inprocess.py:201-266`, `workers/db_update.py:41,81`, `api/scans.py:129,143` |
| M7 | Shutdown arithmetic exceeds Docker's default 10s stop grace → busy instance SIGKILLed mid-commit | CON-6 | `workers/inprocess.py:83,157,240`, `docker-compose.yml` (no `stop_grace_period`) |
| M8 | Lifespan shutdown sequence unshielded — a forced second cancel skips worker shutdown, abandoning live scanner subprocesses | CON-7 | `main.py:96-102` |
| M9 | `PendingMfaStore` not thread-safe but shared across threadpool threads → concurrent logins can 500 | CON-8 | `auth/mfa.py:101-104` |
| M10 | Backup bundle build has no single-transaction snapshot; scheduled backups have no active-scan guard → torn restores | CON-9 | `backup/bundle.py:156`, `backup/scheduled.py` |
| M11 | Every running scan pins a pooled DB connection for its full wall-clock → concurrency silently capped by pool size, then 500s | CON-10 | `workers/inprocess.py:211`, `db/session.py:64-65` |
| M12 | Scans committed `queued` and never submitted on shutdown races; caller still sees 201 | CON-11 | `workers/inprocess.py:111-113`, `api/scans.py:144` |
| M13 | Scanner-DB auto-update marks itself "done" before running → a failed update silently isn't retried for a full interval | CON-12 | `workers/db_update.py:91` |
| M14 | Maintenance tick fully serialized — slow DB updates can delay due schedules/retention by up to ~20 min | CON-13 | `workers/maintenance.py:77-85` |
| M15 | Scan-diff contract drift: SPA enables Compare without checking `target_type` (guaranteed 422); diff payload omits `location`, making distinct findings indistinguishable | APIR-3 | `api/scans.py:623-631`, `pages/ScansPage.tsx:202-204`, `api/history_schemas.py:64-75` |
| M16 | Filtered-history export silently truncates at 5,000 scans with no truncation signal | APIR-4 | `api/scans.py:90,365`, `reports/exporters.py:376-391` |
| M17 | Naive-UTC timestamps serialized with no `Z` designator; one consumer already parses them wrong, can invert a scan diff | APIR-5 | all response models; `frontend/src/pages/ScansPage.tsx:208` |
| M18 | Update endpoints accept states create endpoints forbid on secret-bearing resources (e.g. clearing a mandatory webhook secret) | APIR-6 | `api/notifications.py:269-277`, `api/target_schemas.py:72-83` |
| M19 | Settings forms render editable before their initial GET resolves — Save can silently write defaults over live config (retention, backups, new-scan prefill) | P1-2 | `RetentionPanel.tsx:14-21`, `GeneralPanel.tsx`, `BackupsPanel.tsx:58-73`, `NewScanPage.tsx:144-162` |
| M20 | Scan-detail poller never stops/backs off on fetch errors — hammers a failing endpoint forever while showing a stale "running" status | P1-3 | `ScanDetailPage.tsx:96-107,143-147` |
| M21 | History fetch has no stale-response guard — table can show results for a filter no longer selected | P1-4 | `ScansPage.tsx:98-118` |
| M22 | `node:22-bookworm-slim` build-stage digest is stale (~1 patch cycle) | SC-6 | `docker/Dockerfile` |
| M23 | `tecnativa/docker-socket-proxy:0.3.0` is ~15 months stale — the one sidecar holding the Docker socket | SC-7 | `docker/docker-compose.yml` |
| M24 | Published images carry no provenance/SBOM attestation — notable for a tool whose product is SBOM/vuln transparency | SC-4 | `.github/workflows/publish.yml`, `dev-nightly.yml` |
| M25 | No scheduled re-scan of the already-published `:latest`/`:dev` image for newly disclosed CVEs | SC-5 | CI workflows |
| M26 | Scanner-binary `checksums.txt` verified same-origin only, no cosign signature check | SC-8 | `docker/Dockerfile` |

### Low

| # | Finding | Source | File:line |
|---|---|---|---|
| L1 | Secret-field AAD binds to column not row (documented, DB-write threat) | SEC-7 | `core/secret_store.py` |
| L2 | Mandatory MFA not enforced on OIDC login path (documented) | SEC-8 | `api/oidc.py:492-511` |
| L3 | Forced-enrollment window lets a password-only attacker bind their own TOTP | SEC-9 | `api/auth.py:159-181` |
| L4 | Rate-limiter / pending-MFA store grow unbounded by distinct key | SEC-10 | `core/ratelimit.py` |
| L5 | `proc.kill()` unprotected against `ProcessLookupError`; on the cancel path can replace the cancellation itself | CON-14 | `scanners/base.py:191,199,204` |
| L6 | Notification dispatch runs while the scan still holds its concurrency-semaphore slot | CON-15 | `workers/inprocess.py:234,247` |
| L7 | Per-scan task exceptions outside `_execute`'s `try` never retrieved; unbounded task spawning | CON-16 | `workers/inprocess.py:114-116,167` |
| L8 | "Run now" races the cron tick — duplicate scans, lost `last_scan_id` | CON-17 | `api/scan_schedules.py:253+`, `workers/schedules.py:57-66` |
| L9 | Dashboard `gather` without `return_exceptions` abandons in-flight probe subprocesses on DB error | CON-18 | `api/dashboard.py:102` |
| L10 | Worker can notify for a scan deleted milliseconds earlier (stale identity-map read) | CON-19 | `workers/inprocess.py:188` |
| L11 | Multi-GB repo-checkout `shutil.rmtree` runs synchronously on the event loop | CON-20 | `scanners/credentials.py:289-294` |
| L12 | "Run now" schedule bookkeeping only sets `last_scan_id`, leaves `last_run_at`/`last_status` stale | APIR-7 | `api/scan_schedules.py:279` |
| L13 | Pagination envelopes inconsistent across list endpoints (`{total,items}` vs `{total,entries}` vs bare arrays) | APIR-8 | multiple routers |
| L14 | List/history rows ship unbounded `options`/`error` text the views never render | APIR-9 | `api/scan_schemas.py:129-149` |
| L15 | `_ALLOWED_SCANNERS` scanner↔target matrix duplicated across two routers, already drifted in shape | APIR-10 | `api/scans.py:77-83`, `api/scan_schedules.py:41-46` |
| L16 | Tag draft wiped every 2.5s while a scan is active (poll overwrites in-progress edit) | P2-1 (FE) | `ScanDetailPage.tsx:96-107` |
| L17 | Navigating between scan details mixes two scans' state (stale status gates new fetches) | P2-2 (FE) | `ScanDetailPage.tsx:150-163` |
| L18 | Findings panel: empty-state flash, stale rows during filter changes, no loading flag | P2-3 (FE) | `ScanDetailPage.tsx:403` |
| L19 | Unguarded double-fire mutations, incl. minting an invisible API token the user never sees | P2-4 (FE) | `ApiTokensPanel.tsx:210`, `ScheduledScansPanel.tsx:204`, `AccountPage.tsx:164,183,276` |
| L20 | History table unusable by keyboard — click-only sort, click-only row navigation | P2-5 (FE) | `ScansPage.tsx:566-578,485-495` |
| L21 | Unlabeled form controls (filters, tags input, segmented controls, MFA PinInput) | P2-6 (FE) | multiple |
| L22 | All navigation disappears below the `sm` breakpoint — no mobile nav fallback | P2-7 (FE) | `App.tsx:43` |
| L23 | `# syntax=docker/dockerfile:1.7` BuildKit frontend is tag-pinned, not digest-pinned | SC-9 | `docker/Dockerfile` |
| L24 | `persist-credentials: false` not set on checkouts in token-bearing publish workflows | SC-11 | `.github/workflows/publish.yml`, `dev-nightly.yml` |
| L25 | Composite build action pins older action majors than `ci.yml` (buildx v3 vs v4, build-push v6 vs v7) | D3 (compliance) | `.github/actions/build-image/action.yml` |

### Documentation / process (not code bugs — batch separately)

- **D1** — ~100 dead `docs/PLAN.md` references across backend/frontend/Dockerfile (renamed to `docs/ARCHIVE.md`).
- **D2** — Stale "no registry publishing" comments in `docker/Dockerfile`/`docker-compose.yml` contradicting locked decision §6.
- **D4** — 8 squash-merge commits authored as "Tyler Richardson" instead of `tyler-rich` (GitHub profile display-name artifact, not a Claude-session issue).
- **R1–R8** — Eight CLAUDE.md rules the code has knowingly and correctly outgrown (typed API client, dogfood severity floor, `.env.example` OIDC placeholder, frontend test runner, deliverables list, PLAN.md references, squash-merge identity, promotion commit style) — each already has a matching `docs/ARCHIVE.md § Deviations` entry; CLAUDE.md itself was never amended to match. Low urgency but worth a dedicated docs PR before they cause a future session to "fix" compliant code back toward an abandoned plan.

---

## Cross-report notes

- **Concurrency ↔ Security overlap:** CON-2 (grandchild processes survive a kill, credentials
  in their env) and CON-3/SEC-2 (restore race + restore DoS) are concurrency bugs with direct
  security consequences — filed once above (Top 5 #2 and #4), not duplicated as separate
  security findings.
- **Frontend ↔ Security overlap:** P1-1 (unsafe href) and SEC-5 (no CSP, JS-readable CSRF
  cookie) independently reach the same failure mode — combined into Top 5 #3.
- **Everything else checked as sound.** All six reports open with a "verified, no action"
  section — GCM nonce handling, key rotation, argv-injection defenses, CSRF/RBAC coverage,
  git-credential handling, path-traversal guards in artifact storage, migration-vs-model
  integrity, N+1 query patterns, secret masking, npm lockfile integrity, license compliance,
  and the queued→running claim/cancel race are all confirmed correct — not relitigated here.
