# Review-remediation status — current source of truth (2026-07-20)

This file supersedes the older per-report status tracking in `docs/reviews/` for the
2026-07 code-review remediation batch. It was produced by a fresh, read-only re-verification
of **every** finding across all six original `/code-review` reports (security, supply-chain,
api, frontend, concurrency, claude-md-compliance) — **including findings that were never
carried into `00-summary.md`'s severity tables** — against the current state of `dev` at
`file:line`. No application code was read on trust from any prior report; each status below was
re-confirmed against the actual code.

**Context.** The batch was fixed across PRs #50–#67 and **promoted to `main` in PR #70**, with
the H5/CON-4 follow-up (#67) landing after `fix-verification.md` was written. `requirements.lock`
and the expanded Dependabot config are now on `main` (verified), which clears the two
default-branch Dependabot alerts `fix-verification.md` flagged as category-(a).

**How this differs from `fix-verification.md` (2026-07-13), which is now partly stale:**
- **H5 / CON-4** — was "NOT RESOLVED, no §14 entry." **Now RESOLVED** (#67) with a §14 entry.
- **L24 / SC-11** — was "PARTIAL (missing on `ci.yml`)." **Now RESOLVED** — all four `ci.yml`
  checkouts carry `persist-credentials: false` (folded into the #67 CON-4 §14 entry).
- **"Promote `dev` → `main`"** — was the open recommendation. **Done** (#70).
- **New in this pass (not caught by `fix-verification.md`):** the H1 (#53) and H9+H10 (#57)
  fixes landed **without any `docs/ARCHIVE.md` §14 entry** — see § ARCHIVE.md §14 gaps.
  `fix-verification.md` §G asserted "none landed without a §14 entry except CON-4"; that check
  only covered the five mid-batch *decisions*, not every merged fix.

Bottom line: **all HIGH and MEDIUM findings are resolved.** Everything still open is
LOW/INFO — the frontend "Priority 3" polish batch (never summarized), two supply-chain
hygiene items, one latent lint straggler, and test debt on already-shipped fixes.

---

## 1. Remaining work (STILL OPEN — current backlog, severity-ranked)

All open items are **LOW / INFO**. There are **no open HIGH or MEDIUM findings.** The bulk of
this list is the frontend-review **Priority 3** batch (`frontend-review.md` §Priority 3), which
was never carried into `00-summary.md` and therefore never scheduled — every P3 item was
re-verified STILL OPEN against current code.

### LOW (has a correctness/security/reproducibility edge)

| ID | Finding | File:line (current) | Source |
|----|---------|---------------------|--------|
| SC-12 | Build backend floats: `[build-system] requires = ["setuptools>=75"]` — unpinned/unhashed, breaks build reproducibility the lockfile otherwise restored | `backend/pyproject.toml:38` (absent from `requirements.lock`) | supply-chain (omitted from summary) |
| P3-4 | Auth refresh can resurrect a logged-out session (narrow race) — `refresh()` unconditionally replaces auth state with no sequencing vs. `scrye:auth-invalidated` | `frontend/src/auth/AuthContext.tsx:44-57` | frontend P3-4 (omitted) |

### LOW (UX / accessibility / maintainability)

| ID | Finding | File:line (current) | Source |
|----|---------|---------------------|--------|
| P3-1 | History filters/sort/page live in `useState` only — Back/bookmark/share loses the view; not mirrored to `useSearchParams` (none in tree) | `frontend/src/pages/ScansPage.tsx:81-86` | frontend P3-1 (omitted) |
| P3-2 | Compare selection stores full row snapshots that survive filter/page changes → "1/2 selected" for an unreachable row; deleted-scan diff 404s | `frontend/src/pages/ScansPage.tsx:93,206-224` | frontend P3-2 (omitted) |
| P3-5 | 500-row findings table re-renders on every tag keystroke / 2.5 s poll (co-located with `tagDraft`); no memoized child | `frontend/src/pages/ScanDetailPage.tsx` (state `:101`, table `:549-595`) | frontend P3-5 (omitted) |
| P3-6 | Loaders have no `role="status"`/`aria-live` (announce as nothing); dashboard chart bars put `aria-label` on a plain `div` with no `role` | `frontend/src/pages/Dashboard.tsx:50-63`; all `<Loader>` sites | frontend P3-6 (omitted) |
| P3-7 | Theme-token drift: severity colors re-stated as `"red"`/`"orange"` literals; chart pins `--mantine-color-teal-6`; redundant `color="teal"` | `frontend/src/pages/Dashboard.tsx:141-142,196,201,60` | frontend P3-7 (omitted) |
| P3-8 | TS strictness residuals: blind `as T` casts (`api/client.ts:74,107`); `noUncheckedIndexedAccess` off; ESLint not type-aware (no `no-floating-promises`); `Select`-handler casts | `frontend/tsconfig.app.json`, `frontend/eslint.config.js:10`, `frontend/src/api/client.ts` | frontend P3-8 (omitted) |

### TRIVIAL / latent

| ID | Finding | File:line (current) | Source |
|----|---------|---------------------|--------|
| D5b | `test_migrations.py` import block trips `I001` under ruff ≥0.15.x; clean only because ruff is still pinned `0.8.6` — a future ruff bump breaks CI | `backend/tests/test_migrations.py:11-19`; ruff pin `backend/pyproject.toml:33` | compliance D5 (omitted) |

### Test debt on already-shipped fixes (fixes are real; proof is absent)

- **M19 / P1-2** (settings-form clobber guard) — RESOLVED in code, but **no panel-level test**;
  the Vitest suite covers only `src/lib/` helpers. (`RetentionPanel/GeneralPanel/BackupsPanel/
  NewScanPage`.)
- **M20 / P1-3, M21 / P1-4** — the backoff/latest-wins **helpers** are unit-tested
  (`lib/polling.test.ts`, `lib/latest.test.ts`), but the **page effect wiring** that consumes
  them is not.

---

## 2. Deferred by decision (tracked, intentionally not done)

| ID | Item | Decision / tracking ref |
|----|------|-------------------------|
| M23 / SC-7 | Socket-proxy migration `tecnativa` → `wollomatic` | tecnativa **bumped in-batch** to `v0.4.2` (`docker-compose.yml:136`); wollomatic migration split out to **issue #63** (open). `ARCHIVE.md §14`, 2026-07-13. |
| L13 / APIR-8 / §8.1 (QUA-9) | Broad list-envelope standardization — admin list endpoints still return bare arrays (`registries.py:64`, `git_credentials.py:59`, `users.py:39`, `notifications.py:162`, `scan_schedules.py:139`, …) vs. `{total, items}` | Scope held to the single `entries`→`items` audit rename per maintainer direction (`audit.py:46,64` done). Broader consolidation tracked in **`docs/ROADMAP.md:84-86`**. |
| SC-13 | Mantine 7.15.2 is 2 majors behind (v9 current) | **Locked decision §2** (Mantine v7). Recorded, not a drift; revisit only if an advisory lands 9.x-only. `package.json:17`. |
| L1 / SEC-7 | Field-encryption AAD bound to column, not row | Now **row-bindable** and migration-free (`secret_store.py`, #64) — resolved in mechanism; full column→row cutover of legacy ciphertext remains a lazy upgrade-on-write by design. |
| L2 / SEC-8, L3 / SEC-9 | OIDC MFA not locally enforced; forced-enrollment window | Accepted limitations; **audit visibility added** (`oidc.py:522` `mfa_delegated_to_idp`, `auth.py:229` `forced_by_policy`, #64). No behavior change by design. |

### Operational follow-ups (outside the repo — cannot be verified from a code session)

- **GitHub profile display name** still reads "Tyler Richardson" → future squash-merge
  promotions author as that name until it's set to `tyler-rich` (R7/D4; a GitHub profile
  setting).
- **Dependabot security alerts + updates** enabled in repo Settings — confirm in the Security
  tab; the two default-branch alerts should have cleared once #70 put `requirements.lock` on
  `main`.

---

## 3. Resolved (historical reference)

All HIGH + MEDIUM and 24/25 LOW findings are resolved; the 25th (L24/SC-11) is now also
resolved (#67). One-line index below; full detail lives in the per-report files and the
`docs/ARCHIVE.md §14` entries dated 2026-07-13.

| ID (summary / source) | One-line | Resolving PR |
|----|----------|--------------|
| H1 / SEC-1 | `repository` scans must be remote clone URLs — local-path read closed (`scan_schemas.py:104`, test) | #53 |
| H2 / CON-1 | Bounded commit retry + stale-scan watchdog; artifacts unlinked only after final commit | #54 |
| H3 / CON-2 | `start_new_session=True` + `os.killpg` on all three abort paths | #56 |
| H4 / CON-3 | Restore re-checks active scans inside `BEGIN IMMEDIATE`; worker paused for restore | #54 |
| H5 / CON-4 | Scanner JSON parse/normalize hopped off the event loop (`anyio.to_thread.run_sync`) | #67 |
| H6 / P1-1 + SEC-5 / M4 | `safeHttpUrl()` gate on `primary_url` + baseline security-header middleware (CSP etc.) | #55 |
| H7 / APIR-1 | Aware `expires_at` normalized to naive UTC (`to_naive_utc`) | #61 |
| H8 / APIR-2 | `RequestValidationError` handler flattens 422 to string `detail` | #61 |
| H9 / SC-2 | All external `uses:` SHA-pinned (converged SHAs across paths) | #57 |
| H10 / SC-3 | Dependabot expanded: pip/npm/docker/docker-compose + composite-action dir | #57 |
| H11 / SC-1 | Hash-pinned `requirements.lock` (uv, build-time only) + CI drift gate | #64 |
| M1 / SEC-2 | Restore scrypt params clamped; fixed 512 MiB `maxmem` | #54 |
| M2 / SEC-3 | Master-key entropy floor (≥32 B base64; weak-key opt-out) | #64 |
| M3 / SEC-4 | Log redaction tempered-greedy on unquoted spaced secrets | #64 |
| M5 / SEC-6 | `core/egress.py` SSRF guard on notification/registry/docker-proxy fetchers | #64 |
| M6 / CON-5 | Sync DB commits/reads hopped off the loop (claim/fail in #54; rest #60) | #60 |
| M7 / CON-6 | `stop_grace_period: 30s`; drain grace 10→5 s; bounded scheduler shutdown | #60 |
| M8 / CON-7 | Lifespan teardown shielded + per-component try/except | #60 |
| M9 / CON-8 | `PendingMfaStore` guarded by `threading.Lock` | #60 |
| M10 / CON-9 | Single `BEGIN` snapshot for bundles; scheduled backup defers while scans active | #60 |
| M11 / CON-10 | Connection released after atomic claim **and** pool sized/capped from `max_concurrent_scans` | #60 |
| M12 / CON-11 | Stranded-`queued` re-submit via the stale-scan watchdog | #54 |
| M13 / CON-12 | DB-update marker advances only on ≥1 success | #60 |
| M14 / CON-13 | Scanner-DB refresh detached from the serialized tick | #60 |
| M15 / APIR-3 | `DiffFindingOut` gains `location`; Compare gate checks `target_type` | #61 |
| M16 / APIR-4 | History export flags truncation (headers + JSON/CSV/MD note) | #61 |
| M17 / APIR-5 | Response timestamps serialize with explicit `Z` (`UtcDatetime`) | #61 |
| M18 / APIR-6 | Update paths re-establish create-path secret invariants | #61 |
| M19 / P1-2 | Settings forms gate on `loaded` + seed only pristine forms *(untested — see §1)* | #62 |
| M20 / P1-3 | Poller exponential backoff + halt on ceiling/404 | #62 |
| M21 / P1-4 | History/findings fetches use latest-wins guard | #62 |
| M22 / SC-6 | Stale `node:22-bookworm-slim` digest refreshed | #64 |
| M23 / SC-7 | `docker-socket-proxy` 0.3.0 → v0.4.2 *(wollomatic deferred → #63)* | #64 |
| M24 / SC-4 | Publish workflows attach SLSA provenance + SBOM + `attest-build-provenance` | #64 |
| M25 / SC-5 | `rescan.yml` weekly re-scan of published `:latest`/`:dev` | #64 |
| M26 / SC-8 | Cosign keyless `verify-blob` of scanner `checksums.txt` before `sha256sum -c` | #64 |
| L1 / SEC-7 | Row-bindable AAD, migration-free fallback | #64 |
| L2 / SEC-8, L3 / SEC-9 | Audit-visibility only (accepted limitations) | #64 |
| L4 / SEC-10 | Rate-limiter idle-key eviction + per-user pending-MFA cap | #64 |
| L5 / CON-14 | `ProcessLookupError` suppressed on kill paths | #56 |
| L6 / CON-15 | Notify dispatched after the semaphore slot is released | #60 |
| L7 / CON-16 | Task done-callback logs escaped exceptions; live-task cap | #60 |
| L8 / CON-17 | "Run now" stamps `last_run_at`/`last_status` | #60 |
| L9 / CON-18 | Dashboard `gather(return_exceptions=True)` | #60 |
| L10 / CON-19 | `_notify` re-reads scan with `populate_existing` | #60 |
| L11 / CON-20 | Checkout `rmtree` via shielded thread hop | #60 |
| L12 / APIR-7 | Run-now bookkeeping (resolved via CON-17; assertion added) | #60/#61 |
| L13 / APIR-8 | Audit `entries`→`items` rename *(broad standardization deferred — see §2)* | #61 |
| L14 / APIR-9 | `ScanSummaryOut` split (drops `options`/`error`) | #61 |
| L15 / APIR-10 | Scanner↔target matrix extracted to `scanners/support.py` | #61 |
| L16 / P2-1 | Tag draft not wiped by poll | #62 |
| L17 / P2-2 | Per-scan state reset keyed on `:scanId` | #62 |
| L18 / P2-3 | Findings loading flags + latest-wins | #62 |
| L19 / P2-4 | In-flight mutation guards (incl. API-token double-mint) | #62 |
| L20 / P2-5 | Keyboard-accessible history table | #62 |
| L21 / P2-6 | Accessible names on filters/segmented controls/PinInput | #62 |
| L22 / P2-7 | Burger/Drawer mobile nav below `sm` | #62 |
| P3-3 | Credential/filter option-fetch failures surfaced (warning + retry) instead of silently emptying the pickers — closes the "looks like none configured → scan private target anonymously" path (`NewScanPage.tsx`, `ScansPage.tsx`) | #77 |
| SC-14 | `backend/tests/` + `backend/scripts/` excluded from the runtime image via root `.dockerignore` (regression-guarded) — dev-only trees no longer ship on the published scanner image | #77 |
| L23 / SC-9 | `docker/dockerfile:1.7` syntax digest-pinned | #64 |
| L24 / SC-11 | `persist-credentials: false` on all `ci.yml` checkouts | #67 |
| L25 / D3 / SC-10 | Composite-action vs. `ci.yml` action versions converged to identical SHAs; Dependabot covers the composite dir | #57 |
| D1 | ~100 dead `docs/PLAN.md` → `docs/ARCHIVE.md` references swept | #65 |
| D2 | Stale "no registry publishing" comments corrected | #65 |
| D4 | Squash-merge authorship documented (CLAUDE.md) | #65 / §14 |
| D5a | Lone un-commented `except Exception` now annotated (`inprocess.py:413`) | batch hygiene |
| R1–R8 | CLAUDE.md text reconciled with logged deviations (typed client, dogfood floor, Vitest, OIDC env, deliverables, PLAN refs, squash identity, promotion title) | #65 |
| #51 (pre-batch) | Dogfood CVE fixes: curl CVE-2026-5773 + CPython 3.13 interpreter CVEs | #51 |

---

## 4. ARCHIVE.md §14 gaps (fixes that merged without a dated entry)

`docs/ARCHIVE.md §14` has 12 dated `2026-07-13` entries covering the batch. Cross-referencing
the actual PR history (#50–#67, promoted via #70) against those entries, the following **merged
fixes have no §14 entry** and should get a dated back-fill entry to close the record:

1. **#53 — H1 / SEC-1** (repository targets must be remote clone URLs). The headline HIGH
   security fix. **No §14 entry** — the only §14 mention of "SEC-1" is the unrelated *older*
   webhook-URL SEC-1 (`ARCHIVE.md:1870`). This is the most important gap.
2. **#57 — H9 / SC-2 + H10 / SC-3** (SHA-pin all Actions; expand Dependabot to
   pip/npm/docker/docker-compose + the composite-action directory; harden publish-workflow
   checkouts; converge the D3/SC-10/L25 version skew). Two HIGH supply-chain fixes plus a LOW,
   all in one PR. **No §14 entry.** (Note: the *later* L24/SC-11 `ci.yml` checkout hardening
   *was* logged, folded into the #67 CON-4 entry — but #57's SHA-pins and Dependabot expansion
   were not.)
3. **#65 — D1, D2, R1–R6** (PLAN.md→ARCHIVE.md sweep, registry-comment fix, CLAUDE.md text
   reconciliation). Only **R7** (squash authorship) and **R8** (promotion title) got dated §14
   entries; the substantive doc/comment changes (D1, D2) and the other CLAUDE.md amendments
   (R1–R6) have no entry. Nuance: these largely bring CLAUDE.md in line with *already-logged*
   deviations, so a short "compliance-drift closure" entry pointing at the existing ones would
   suffice.
4. **#59 — backend dev-dependency bumps** (`pytest==9.0.3`, `pytest-asyncio==1.4.0`,
   `black==26.3.1`; ruff left at `0.8.6`). Minor — a pinned-version refresh addressing the
   supply-chain review's dev-dep staleness note — but it changed pinned versions with no §14
   line. (Bumping ruff too would also close D5b above.)

*Note on `fix-verification.md`:* its §G concluded "None landed without a §14 entry — except
CON-4." That statement checked only the five mid-batch **decisions** (M2, M11, M23, H11,
CON-11), not every merged fix, so it missed gaps 1–4 here. Gap 1 (#53) and gap 2 (#57) predate
that verification pass and were resolved-in-code at the time, which is why they read as
"RESOLVED" there without a §14 cross-check.
