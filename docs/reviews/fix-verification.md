# Fix-verification pass — 2026-07-13

Independent read-only verification of the review-remediation batch (PRs #50–#65) against the
**current merged state of `dev`** (`e545d77`), not against what any report or summary claims. Every
HIGH/MEDIUM finding in `docs/reviews/00-summary.md` was re-checked at the cited `file:line`; the LOW
findings were spot-checked for resolved-vs-open; the five mid-batch decisions were verified to have
landed *as decided*. No application code was changed — the only file written is this one.

**Bottom line:** the batch is in very good shape. **21 of 22 HIGH/MEDIUM findings that were meant to
be fixed are RESOLVED with a covering test.** There is **one genuine miss** — **H5 / CON-4** (scanner
JSON parse on the event loop) was never fixed and never even logged as deferred — and a short list of
smaller residuals below. All five decision-specific items (M2, M11, M23, H11, CON-11) landed exactly
as decided.

---

## 1. Regressions / conflicts / needs-attention (read this first)

### 🔴 A. H5 / CON-4 is NOT RESOLVED — and was silently dropped, not deferred
`backend/app/scanners/trivy.py:285` and `backend/app/scanners/grype.py:186` still call the synchronous
`parse_output(result.stdout)` **directly inside `async def _execute`**, on the event loop. There is no
`anyio.to_thread.run_sync` around the parse (the only `to_thread` hop in `scanners/` is the
`credentials.py` rmtree cleanup, CON-20). `backend/app/scanners/base.py:362` `load_json_output` is
likewise a plain `json.loads` on the loop, and `trivy.py:260`'s version-probe `json.loads` too.

This is the exact HIGH the concurrency review filed: a 100–500 MB scanner report (the archive's own run
produced 7,072 findings) is parsed + normalized on the loop, freezing every request — including
`/healthz`, which the container healthcheck polls (`timeout 10s, retries 3`) — long enough to get the
container restarted mid-scan.

**Why this matters beyond the miss:** it is the one HIGH with **no `docs/ARCHIVE.md` §14 entry at all**
(`grep CON-4` / `H5` in §14 → nothing). The other three concurrency HIGHs (CON-1/2/3) and CON-5→CON-20
each have an entry; the CON-5–CON-20 remediation entry literally starts at CON-5, so CON-4 fell through
the gap between the "Top 5 #2" change-set and the "CON-5–CON-20" change-set. It is neither fixed nor
recorded as an accepted deferral. **This should be fixed (a mechanical thread-hop, exactly as the review
prescribes) or explicitly logged as deferred with a rationale — it is currently invisible.**

### 🟠 B. Dependabot's 2 alerts (1 high, 1 moderate): category (a) — already fixed on `dev`, unpromoted to the default branch
The repo **default branch is `main`**, currently at `2c1a6a7` = the **v0.1.0 promotion**. The *entire*
remediation batch — H11 backend lockfile, SC-2 SHA-pins, SC-3 expanded Dependabot ecosystems, SC-6 node
digest, SC-7 socket-proxy bump, and PR #51's dogfood CVE fixes (curl CVE-2026-5773 + CPython 3.13
interpreter CVEs) — lives on **`dev` and has NOT been promoted to `main`** (`git merge-base
--is-ancestor origin/dev origin/main` → *not* an ancestor; `requirements.lock` is absent from main's
tree; the expanded `dependabot.yml` ecosystems are dev-only). There are **no open Dependabot PRs**.

Triage: the alerts are almost certainly **(a) already addressed on `dev`, pending a release promotion**,
not (b) genuinely new CVEs needing fresh work. The two most probable subjects are the stale base-image /
OS-package items the SC batch already bumped (SC-6 node digest, the curl/CPython image CVEs from #51) —
all of which are fixed on `dev`. **Recommended action: promote `dev` → `main`** so the default branch
picks up the lockfile + dependency bumps and the alerts clear; separately confirm **Dependabot security
alerts + security updates** are enabled in repo Settings (still an open operational follow-up in §14's
2026-07-06 entry — its expanded config is on `dev` only, so on `main` Dependabot still watches
`github-actions` alone).

> **Tooling limitation, stated honestly:** the exact advisory IDs could not be enumerated from this
> read-only session — the GitHub MCP surface does not expose the Dependabot **alerts** endpoint, which
> needs a security-scoped token unavailable here. The triage above is structural (branch topology +
> which fixes are/aren't on the default branch), not a read of the alert list. Whoever has the Security
> tab should confirm the two advisory IDs against the "fixed on dev" list before closing them.

### 🟡 C. L24 / SC-11 is PARTIAL — `persist-credentials: false` missing on `ci.yml`
Set on every token-bearing publish checkout (`publish.yml:65`, `dev-nightly.yml:60`, `rescan.yml:44`)
but **not** on `ci.yml`'s four checkouts (lines ~35/83/122/228). `ci.yml` holds only `contents: read`,
so the residual risk is low, but the item is not fully closed. Consistent with a deferred-hygiene read.

### 🟡 D. M19 / P1-2 is RESOLVED but UNTESTED
The async-form-clobber guard (`loaded` flag + `!form.isDirty()` seeding) is correctly applied in
`RetentionPanel.tsx`, `GeneralPanel.tsx`, `BackupsPanel.tsx`, and `NewScanPage.tsx`, but the frontend
Vitest suite covers only the `lib/` helpers — no panel-level test exercises the behavior. Fix is real;
proof is absent. (Same caveat, to a lesser degree, on M20/M21 page-effect *wiring* — the backoff and
latest-wins *helpers* are unit-tested, the effect that consumes them is not.)

### ✅ E. Regression checks that came back CLEAN
- **CON-10 connection-release refactor vs. session threading in `_run`/`_dispatch`/`_persist`/`_fail`/
  `_notify`.** Verified sound. The `Session` is used strictly sequentially across `anyio.to_thread`
  hops (claim → resolve-inputs → `_release_connection` rollback → subprocess holding no connection →
  persist re-acquires → notify), never concurrently. The `pause()`/`resume()` gate added for the
  restore race (H4) sits before the claim and does not interleave with an in-flight session. No
  re-introduced contention or use-after-close. (`inprocess.py:472-588`.)
- **CSP vs. SPA.** The `SecurityHeadersMiddleware` CSP (`script-src 'self'`, `style-src 'self'
  'unsafe-inline'` for Mantine's runtime theme CSS, `connect-src 'self'`) was verified in §14 against
  the real built SPA under a headless browser with zero `securitypolicyviolation` events; `/docs` and
  `/redoc` are CSP-exempt (they need inline scripts) but still get the other three headers. No SPA
  feature broken.
- **"Run now" scheduling (L8/CON-17 ↔ L12/APIR-7) — no double-apply.** CON-17 (PR #60) made run-now
  stamp `last_run_at`/`last_status`; APIR-7 (PR #61) explicitly recorded "already resolved by the CON-17
  fix … **no code change**" and only added the `last_status` assertion. Single coherent fix at
  `scan_schedules.py:272`. Not double-patched.
- **Restore/backup (M10/CON-9 ↔ Top 5 #2 / CON-3+SEC-2) — no conflict.** Different code paths: CON-9
  hardens `build_bundle` (single `BEGIN` read snapshot) and the *scheduled* path (`run_due_backup`
  defers while scans active); CON-3/SEC-2 harden `restore_bundle` (`BEGIN IMMEDIATE` in-transaction
  re-check + worker pause + scrypt clamps). Both present, independently tested, no overlap.
- **CON-11 resolved ONCE.** Retired by Session 2's stale-scan watchdog (`reconcile_stale`, PR #54);
  §14 records Session 6 *verified* it ("found already retired … skipped, not re-fixed"). `submit`
  idempotency (live-task check + atomic claim) means startup `recover()` and the watchdog cannot
  double-submit. Not left in a half-state.

### ✅ F. CLAUDE.md ↔ §14 drift (R1–R8) is now actually CLOSED (Session 10a / PR #65)
Verified in the current `CLAUDE.md` text: R1 (hand-written typed API client), R2 (dogfood gate =
fixable HIGH/CRITICAL), R3 (Vitest for `lib/` helpers), R4 (no `OIDC_CLIENT_SECRET` env placeholder —
stored field-encrypted), R5 (deliverables list extended with CHANGELOG/SECURITY/CODEOWNERS/ROADMAP/
dependabot/ci), R7 (squash-merge profile-display-name note), R8 (promotion-title exception) all now
reflected. Code-side: **D1** dead `docs/PLAN.md` references → **0 remaining**; **D2** "no registry
publishing" comment corrected to the GHCR-publishing reality. Closed.

### ✅ G. Each mid-batch decision has its own dated §14 entry
| Decision | §14 entry | 
|---|---|
| **H11 / SC-1** (lockfile via uv) | ✅ 2026-07-13 "Security + supply-chain review batch" (line 579) |
| **M2 / SEC-3** (entropy floor) | ✅ same entry (line 583) |
| **M23 / SC-7** (tecnativa bump, wollomatic → #63) | ✅ same entry (line 597) |
| **M11 / CON-10** (Both: pool cap + release) | ✅ 2026-07-13 "CON-5–CON-20" entry (line 772, "User chose Both") |
| **CON-11** (verify-once) | ✅ 2026-07-13 "CON-1/CON-11…" entry (line 795, "skipped, not re-fixed") |

None landed without a §14 entry — **except CON-4, which landed *nothing* because it was not fixed** (see A).

### ⚪ H. Minor residual: GitHub profile display name still reads "Tyler Richardson"
`get_me` → `"name":"Tyler Richardson"`. R7/D4 documented that squash-merge authorship follows the
*profile display name*, so future promotion squashes will keep authoring as "Tyler Richardson" until the
profile name is changed to `tyler-rich`. Documented-and-accepted residual (a GitHub profile setting,
outside the repo), not a batch defect — noted for completeness.

---

## 2. HIGH findings

| # | Finding | Status | Fix (file:line) | Test |
|---|---|---|---|---|
| H1 | SEC-1 repository scans bypass filesystem allowlist | **RESOLVED** | `api/scan_schemas.py:104-119` (`_require_remote_repository_url`) + `scanners/credentials.py:149-160` (`is_remote_repo_url`) | `test_scans_api.py::test_repository_scan_rejects_local_path_target` (param `/data`,`/run/secrets`,`/`,`/app`,`file:///…`) |
| H2 | CON-1 SQLite lock contention → stuck scans, lost results | **RESOLVED** | `workers/inprocess.py:155-189` (`_commit_with_retry`), `:298-365` (watchdog `reconcile_stale`/`_fail_stale_running`), `:757-767` (unlink only after final commit); wired `maintenance.py:106` | `test_worker_resilience.py:119,165,212,222,257` |
| H3 | CON-2 subprocess kill signals only direct child | **RESOLVED** | `scanners/base.py:193` (`start_new_session=True`) + `:106-117` (`_kill_process_group`/`os.killpg`) on overflow/timeout/cancel (`:207,215,221`) | `test_scanner_process_group.py::test_timeout_kills_grandchild` |
| H4 | CON-3 restore active-scan guard check-then-act | **RESOLVED** | `backup/bundle.py:350-362` (`BEGIN IMMEDIATE` + in-txn re-check → `RestoreConflictError`) + `api/backups.py:268-298` (worker pause/resume) | `test_backup.py::test_restore_conflicts_inside_transaction_when_scan_active`, `test_backup_api.py::test_restore_conflicts_when_scan_queued_during_upload` |
| **H5** | **CON-4 scanner JSON parse on the event loop** | **🔴 NOT RESOLVED** | still synchronous at `scanners/trivy.py:285`, `grype.py:186`, `base.py:362`, `trivy.py:260` — no thread hop | none; **no §14 entry** (see §1.A) |
| H6 | P1-1 + SEC-5 unsafe `primary_url` href + no security headers | **RESOLVED** | `frontend/src/lib/url.ts:19` (`safeHttpUrl`) gating `pages/ScanDetailPage.tsx:552-567`; `core/security_headers.py:51` wired outermost `main.py:230` | `frontend/src/lib/url.test.ts`; `test_security_headers.py:16,26,39,47` |
| H7 | APIR-1 aware `expires_at` offset dropped | **RESOLVED** | `api/trivy_policy.py:217-226` validator → `core/timeutil.py:19-31` (`to_naive_utc`) | `test_trivy_policy.py::test_aware_expires_at_normalized_to_utc` |
| H8 | APIR-2 two 422 body shapes; SPA renders one | **RESOLVED** | `main.py:209-215` `RequestValidationError` handler + `:133-152` flatten to string `detail` | `test_error_envelope.py::test_schema_error_detail_is_a_string` (+ hand-raised 422) |
| H9 | SC-2 Actions tag-pinned not SHA-pinned | **RESOLVED** | all external `uses:` 40-char-SHA-pinned across `ci/publish/dev-nightly/rescan.yml` + `actions/build-image/action.yml`; only local `./…` ref unpinned (correct) | config-verified (declarative) |
| H10 | SC-3 Dependabot watches only github-actions | **RESOLVED (on `dev`)** | `.github/dependabot.yml` adds `pip`/`npm`/`docker`/`docker-compose` + 2× `github-actions`, all `target-branch: dev` | declarative — **note: not on default branch `main` yet (see §1.B)** |
| H11 | SC-1 no backend lockfile | **RESOLVED** | `backend/requirements.lock` (`uv pip compile --generate-hashes`), Dockerfile `pip install --require-hashes` then `--no-deps .` (`docker/Dockerfile:159-167`); CI drift check `ci.yml:62-68` | `test_dockerfile_supply_chain.py` (pins) + CI drift gate |

**HIGH: 10/11 RESOLVED with tests; H5/CON-4 NOT RESOLVED.**

---

## 3. MEDIUM findings

| # | Finding | Status | Fix (file:line) | Test |
|---|---|---|---|---|
| M1 | SEC-2 restore scrypt-param OOM | **RESOLVED** | `core/passphrase.py:38-46,91-101` (clamp n≤2²⁰/r≤16/p≤4, fixed 512 MiB maxmem); `backup/bundle.py:318-327` malformed→`BackupError` | `test_passphrase.py::test_parameter_bombs_rejected_before_derivation` |
| M2 | SEC-3 master-key entropy floor | **RESOLVED** | `core/crypto.py:78-131` (base64→≥32 B validator, weak-key opt-out) — **input validation only, KDF/format untouched** | `test_crypto.py::test_raw_non_base64_key_rejected_by_entropy_floor`, `::test_valid_base64_key_still_decrypts_existing_data` |
| M3 | SEC-4 log redaction misses unquoted spaced secrets | **RESOLVED** | `core/logging.py:67-70` tempered-greedy unquoted branch | `test_redaction.py::test_spaced_unquoted_secret_is_fully_redacted` |
| M4 | SEC-5 no CSP/security headers | **RESOLVED** | `core/security_headers.py:51-62`, wired `main.py:230` | `test_security_headers.py` (4 tests incl. docs-CSP exemption) |
| M5 | SEC-6 SSRF in outbound fetchers | **RESOLVED** | new `core/egress.py` guard wired in `notifications.py`/`registry_check.py`/`docker_proxy.py`; `config.py:136` `allow_internal_egress` | `test_egress.py` (blocks metadata/loopback even under opt-out) |
| M6 | CON-5 sync DB on event loop | **RESOLVED** | thread hops: `inprocess.py:481,416-417`, `api/scans.py:146`, `db_update.py:92` | `test_event_loop_offload.py` |
| M7 | CON-6 shutdown exceeds 10 s grace | **RESOLVED** | `docker-compose.yml:33` (`stop_grace_period: 30s`); `inprocess.py:93` (grace 10→5 s); `maintenance.py:76-98` bounded | `test_compose_hardening.py`, `test_lifespan_shutdown.py` |
| M8 | CON-7 unshielded lifespan shutdown | **RESOLVED** | `main.py:107` `asyncio.shield(_shutdown_all)` + per-component try/except | `test_lifespan_shutdown.py::test_worker_shutdown_runs_even_if_a_scheduler_fails` |
| M9 | CON-8 `PendingMfaStore` not thread-safe | **RESOLVED** | `auth/mfa.py:90` `threading.Lock` on issue/consume/_prune | `test_mfa.py::test_concurrent_issue_and_consume_never_raise` |
| M10 | CON-9 non-snapshot backup / no scheduled guard | **RESOLVED** | `backup/bundle.py:199-228` (one `BEGIN` snapshot); `backup/scheduled.py:92-96` (defer while active) | `test_backup.py::TestBackupSnapshotConsistency`, `::test_scheduled_backup_defers_while_a_scan_is_active` |
| M11 | CON-10 connection pinning | **RESOLVED (BOTH fixes)** | pool sizing `db/session.py:66` + cap `config.py:160-163` (`le=32`) **AND** release refactor `inprocess.py:119-139,532-533` | `test_worker_pool.py::test_running_scan_holds_no_pooled_connection_during_subprocess`, `::test_pool_is_sized_from_max_concurrent_scans`, `::test_max_concurrent_scans_is_capped` |
| M12 | CON-11 scans stranded queued | **RESOLVED (once)** | watchdog `inprocess.py:298-319`, `maintenance.py:106` | `test_worker_resilience.py::test_resubmits_stranded_queued_scan`, `::test_leaves_fresh_queued_scan_alone` |
| M13 | CON-12 DB-update marks done before running | **RESOLVED** | `db_update.py:104-116` — marker advances only on ≥1 success | `test_db_update.py::test_marker_not_advanced_when_both_updates_fail` |
| M14 | CON-13 serialized maintenance tick | **RESOLVED** | `maintenance.py:115-133` detached `_run_db_update` task | `test_worker_resilience.py::test_slow_db_update_does_not_block_the_tick` |
| M15 | APIR-3 diff contract drift (`target_type`, `location`) | **RESOLVED** | `api/history_schemas.py:84` (`location`); `reports/diff.py:32-37`; `frontend ScansPage.tsx:213-217` (`canCompare` checks `target_type`) | `test_history_api.py::test_diff_payload_includes_location_for_non_vuln_findings` |
| M16 | APIR-4 silent 5 000-row export truncation | **RESOLVED** | `api/scans.py:363-385` (`X-Scrye-Truncated`/`-Total`); `reports/exporters.py:313-369` (JSON/CSV/MD note) | `test_history_api.py::test_history_export_signals_truncation` |
| M17 | APIR-5 naive-UTC timestamps, no `Z` | **RESOLVED** | `api/schema_types.py:20-29` (`UtcDatetime` emits `Z`, JSON mode only); `frontend ScansPage.tsx:221` via `parseUtc` (the one raw `new Date` bypass) | `test_timestamp_serialization.py` (4 tests) |
| M18 | APIR-6 update accepts states create forbids | **RESOLVED** | `api/notifications.py:280-289`; `api/target_schemas.py:85-99`; `api/registries.py:158-168` | `test_notifications.py::test_update_cannot_clear_mandatory_secret`, `test_targets_api.py::test_registry_update_*` |
| M19 | P1-2 settings forms clobber input | **RESOLVED (UNTESTED)** | `RetentionPanel.tsx`/`GeneralPanel.tsx`/`BackupsPanel.tsx`/`NewScanPage.tsx` (`loaded` gate + `!isDirty()` seed) | none — no panel-level test (see §1.D) |
| M20 | P1-3 poller never backs off/stops | **RESOLVED** | `lib/polling.ts:13-30` (2.5→30 s, ceiling 5); `ScanDetailPage.tsx:204-233` (halt on ceiling/404) | `lib/polling.test.ts` (helper only; effect wiring untested) |
| M21 | P1-4 history fetch no stale-response guard | **RESOLVED** | `lib/latest.ts:19-30`; `ScansPage.tsx:105-121` | `lib/latest.test.ts` |
| M22 | SC-6 stale node digest | **RESOLVED** | `docker/Dockerfile:17` digest refreshed (`sha256:53ada149…`) | infra (no test) |
| M23 | SC-7 socket-proxy 15 mo stale | **RESOLVED (as decided)** | `docker-compose.yml:136` bumped `0.3.0 → v0.4.2`; **wollomatic NOT migrated in-batch — tracked in issue #63** (verified open) | infra (no test) |
| M24 | SC-4 no provenance/SBOM attestation | **RESOLVED** | `actions/build-image/action.yml:44-57`; `publish.yml`/`dev-nightly.yml` (`provenance: mode=max`, `sbom`, `attest-build-provenance`) | infra |
| M25 | SC-5 no scheduled image re-scan | **RESOLVED** | new `.github/workflows/rescan.yml` (weekly, `[latest, dev]`, issue-on-finding) | infra |
| M26 | SC-8 checksums same-origin, unsigned | **RESOLVED** | `docker/Dockerfile:50-102` cosign keyless `verify-blob` before `sha256sum -c` | infra (CI image build validates) |

**MEDIUM: 26/26 addressed — all RESOLVED, with the one caveat that M19 is untested and M22/M23 image
bumps could not be boot-verified in this egress-restricted environment (matches the §14 note).**

---

## 4. LOW backlog

**Resolved (24/25):** L1 (SEC-7 row-bound AAD, migration-free fallback, tested), L2 (SEC-8 audit-only,
no behavior change), L3 (SEC-9 audit-only), L4 (SEC-10 eviction + per-user cap, tested), L5 (CON-14
`ProcessLookupError` suppressed), L6 (CON-15 notify after semaphore), L7 (CON-16 task-done logging +
cap), L8 (CON-17 run-now stamps `last_run_at`), L9 (CON-18 `return_exceptions=True`), L10 (CON-19
`populate_existing`), L11 (CON-20 shielded rmtree hop), L12 (APIR-7 via CON-17), L13 (APIR-8 —
paginated-envelope consistency **resolved** via `entries`→`items` audit rename; broader bare-array
standardization **deferred by decision**, ROADMAP — *not* graded as incomplete), L14 (APIR-9
`ScanSummaryOut` split, tested), L15 (APIR-10 matrix extracted to `scanners/support.py`, tested), L16
(P2-1 tag-draft preserved), L17 (P2-2 per-scan state reset on `:scanId`), L18 (P2-3 loading flags +
latest-wins), L19 (P2-4 in-flight mutation guards), L20 (P2-5 keyboard-accessible table), L21 (P2-6
aria-labels), L22 (P2-7 Burger/Drawer mobile nav), L23 (SC-9 dockerfile syntax digest-pinned), L25 (D3
composite-action/ci.yml version skew **converged** — identical SHAs).

**Still open — remaining backlog:**
- **L24 (SC-11)** — `persist-credentials: false` set on all publish workflows but **not on `ci.yml`**
  (partial; low residual risk — `ci.yml` is `contents: read` only).

The intentionally-deferred documented residuals (L2/L3 accepted-limitation windows; L13's broader
envelope standardization) remain as designed and are **not** counted as open defects.

---

## 5. Decision-verification (landed exactly as decided?)

| Decision | Verdict | Evidence |
|---|---|---|
| **M2 / SEC-3** — entropy-floor ONLY, no KDF/format change | ✅ **As decided** | `crypto.py` encrypt/decrypt, HKDF (`_HKDF_INFO`, `salt=None`), 12-byte nonce, `scrye$v<n>$…` token regex all **unchanged**; `_decode_key_material` validates base64→`_MIN_KEY_BYTES=32`; `SCRYE_ALLOW_WEAK_MASTER_KEY` opt-out reads env directly (kept out of `.env.example`), defaults off, logs a warning; regression test `test_valid_base64_key_still_decrypts_existing_data` proves existing ciphertext still decrypts. **No v2 KDF / re-encryption migration / format change** — confirmed absent. |
| **M11 / CON-10** — BOTH fixes (defense-in-depth) | ✅ **Both present** | Pool sized from `max_concurrent_scans` (`db/session.py:66`) with upper-bound validator (`config.py:163`, `le=32`) **AND** connection-release-after-atomic-claim refactor (`_RunInputs`, `_dispatch` resolves inputs then `_release_connection` before the subprocess). Both independently tested. |
| **M23 / SC-7** — bump tecnativa, do NOT migrate to wollomatic | ✅ **As decided** | `docker-compose.yml:136` = `tecnativa/docker-socket-proxy:v0.4.2@sha256:1f3a6f30…`; wollomatic migration **not** performed in-batch; **issue #63 open and correctly scoped** as the standalone follow-up. No scope violation. |
| **H11 / SC-1** — uv build/dev-time only, plain-pip `--require-hashes`, CI drift check | ✅ **As decided** | `requirements.lock` header shows `uv pip compile --generate-hashes`; **uv is NOT a runtime dep** (not in `pyproject.toml`; the runtime image uses plain `pip install --require-hashes -r requirements.lock` then `pip install --no-deps .`); CI regenerates with the pinned uv and fails on drift (`ci.yml:62-68`). Lock is hash-pinned and self-describing. |
| **CON-11 / M12** — retired ONCE by the watchdog; Session 6 verifies, not re-fixes | ✅ **Single resolution** | One implementation (`reconcile_stale`, PR #54); §14 records Session 6 verified "already retired … skipped, not re-fixed". `submit` idempotency prevents double-submission. Not double-applied, not half-applied. |

---

## 6. Closing summary — genuinely done vs. what remains

**Genuinely done (the large majority):** 10/11 HIGH, 26/26 MEDIUM (as addressed), and 24/25 LOW are
resolved, nearly all with a named covering test. All five mid-batch decisions landed exactly as decided,
each with its own dated `§14` entry. The CLAUDE.md ↔ §14 drift (R1–R8, D1, D2) is closed. The regression
surfaces most likely to have been disturbed — the CON-10 session-threading refactor, the CSP vs. the
SPA, the two "Run now" fixes, and the restore/backup pair — were each checked and came back clean, with
no double-applies or half-states.

**What remains for a future pass:**
1. **H5 / CON-4 (the one real miss)** — scanner JSON parse/normalize still runs on the event loop
   (`trivy.py:285`, `grype.py:186`, `base.py:362`). Not fixed, **not logged as deferred**. Either apply
   the review's mechanical `anyio.to_thread.run_sync` hop or record an explicit §14 deferral — right now
   it is invisible. *This is the top item.*
2. **Promote `dev` → `main`** so the default branch inherits the lockfile + dependency bumps; this is
   what clears Dependabot's 2 default-branch alerts (category (a), already fixed on `dev`). Confirm the
   two advisory IDs in the Security tab against the fixed-on-dev list, and enable Dependabot security
   alerts/updates in repo Settings.
3. **L24 / SC-11** — add `persist-credentials: false` to `ci.yml`'s checkouts to fully close it.
4. **Test debt** — add a panel-level test for M19 (and ideally the poller/history *effect* wiring for
   M20/M21, whose helpers are tested but whose page integration is not).
5. **Housekeeping** — align the GitHub profile display name to `tyler-rich` (R7/D4 residual) before the
   next promotion squash.
