# Repository cleanup audit — 2026-07-26

Read-only audit of open issues, the `docs/` tree, deferred work buried in `docs/ARCHIVE.md` §14,
and general repo hygiene. **Nothing was deleted, closed, moved, or amended** — this file is the
only change in the branch that carries it. Every status below was verified against the code on
`dev` at `96264fb`, not against issue state or against what a prior document claimed.

**Standing caveat that shaped Part 1.** The default branch is `main`, but day-to-day PRs target
`dev`, so GitHub's closing keywords never fire. Every `Closes #N` written during the remediation
cycle is inert, and an open issue here carries no information about whether the work is done.
Two of the five open issues are fully resolved in code.

---

## Recommended actions, highest value first

| # | Action | Why it's first | Part |
|---|--------|----------------|------|
| 1 | **Close #63 and #83 by hand.** Both are fully resolved in code (#89 and #87). | They are the only issues misrepresenting reality; closing them makes the issue list mean something again. | 1 |
| 2 | **Fix the false CVE claim in `CHANGELOG.md` lines 18–23.** It says CVE-2025-15366 is unfixable below 3.15 and points at #52. Both are now false — §14 (2026-07-26) records the imaplib backport on the `3.14` branch, closing on 3.14.7, tracked in #98. | This is **user-facing release-note text that will ship verbatim in the next release**. It is the single highest-consequence stale claim in the tree. | 2, 4 |
| 3 | **Promote `dev` → `main` and cut v0.2.0.** `main` has had nothing since #70 (2026-07-13); `dev` is 30 commits ahead with the Python 3.14 move, the wollomatic migration, and the list-envelope contract change. | Also the fix for #75, and it unblocks the scheduled workflows (see 4). | 4 |
| 4 | **Delete `docs/upgrades/python-3.14.md` and the `docs/upgrades/` folder.** | Completed handoff doc whose body is wrong, sitting under a warning banner whose own correction is now also superseded. Two layers of wrong is worse than no document. | 2 |
| 5 | **Restructure `docs/` into `ARCHIVE` / `ROADMAP` / `screenshots` / `history/`.** Move the ten review reports under `docs/history/reviews/`, delete two of them outright. | `docs/reviews/` is 10 files / 300 KB of closed findings sitting at the same level as the two live documents. | 2 |
| 6 | **Fix `docs/ARCHIVE.md`'s broken §14 nesting.** Fourteen entries dated 2026-07-09 → 2026-07-26 — including every recent one — sit *underneath* `## Build performance`, not under §14. | It is why §14 feels unusable: the newest work is filed under an unrelated heading. Cheap to fix, big readability win. | 4 |
| 7 | **Prune 33 merged remote branches.** All verified merged; the 4 Dependabot branches and `dev`/`main` stay. | 39 branches, 2 of them real. | 4 |
| 8 | **Strike 4 completed items from `ROADMAP.md`**, one of which asserts something now false about the security model. | ROADMAP is a live document a contributor reads first. | 4 |
| 9 | **Land or close the 4 open Dependabot PRs** (#85, #86, #92, #93), oldest from 2026-07-24. | Frontend one carries 25 updates and grows staler daily. | 4 |
| 10 | **Add the two CLAUDE.md operational rules** (stacked-PR rebase; `pull_request` edited-type). | Both were learned the hard way this week and are unrecorded. | 4 |

---

# Part 1 — Open issues

Five open issues. **Two are resolved and safe to close, three are genuinely live.** No duplicates.

## #63 — Evaluate migrating the Docker socket proxy from tecnativa to wollomatic

**RESOLVED — safe to close.** Done in **PR #89** (2026-07-24), plus three follow-ups (#94, #96, #97).

Verified in code:

- `docker/docker-compose.yml:140` — `wollomatic/socket-proxy:1.12.3@sha256:74e770f5…`, digest-pinned.
- `docker/docker-compose.yml:131` — the migration comment cites issue #63 by number.
- Allowlist pinned to the single `GET /images/json` the app calls; `-allowfrom` restricts the source
  to the `scrye` service (`docker-compose.yml:158–168`).
- `backend/tests/test_compose_hardening.py` — seven regression tests tie the allowlist to the client
  path `list_images()` is observed to request, and assert the digest pin, unprivileged uid, method
  flags, source restriction, and the absence of a re-introduced writable `/run`.

All four of the issue's acceptance boxes are satisfied; the boxes are simply unticked. The last
one — a live `docker compose --profile docker-env up` on a Docker-capable host — was the "still to
do" the migration entry left open, and it was **discharged on a real Debian host** (§14, 2026-07-26,
"Socket-proxy operational behavior from a live Debian run"), which also surfaced four operational
corrections now in the README.

*Body claim to note when closing:* the issue predicts `GET /images/json` "should be straightforward"
to allow. Correct, but the live run found the `-allowfrom` source check runs **before** the path
rule, so a wrong source returns 403 for everything — the failure the issue's framing would have sent
you to debug in the regex. That is documented; nothing to change.

## #83 — A stale pre-login `refresh()` can wipe a just-completed `login()`

**RESOLVED — safe to close.** Done in **PR #87** (2026-07-24).

Verified in code at `frontend/src/auth/AuthContext.tsx:78–83`: an `applyAuthenticated()` helper burns
a token from the existing `refreshGuard` (`createLatestGuard()`, `lib/latest.ts`) before writing the
user, so any refresh already in flight is superseded and returns without writing. It is wired into
all three success paths the issue names — `login` (`:127`), `verifyMfa` (`:134`), `setup` (`:141`).

Every acceptance box is satisfied:

- The race is closed (mechanism above).
- The P3-4 invariant is untouched — `sessionGeneration` and its invalidation semantics are unchanged
  (`:59–68`, `:118`).
- `frontend/src/auth/AuthContext.test.tsx:184` — `describe('AuthProvider — #83 authentication vs. an
  in-flight refresh')`, four jsdom cases plus a non-regression case at `:248` proving a refresh
  *started after* sign-in still applies.
- Dated §14 entry exists (`ARCHIVE.md:815`), and records that the three race cases were confirmed to
  fail against the pre-fix provider.

The issue asked for "one mechanism, matching the guard idiom already in the file — not a third
pattern." That is what shipped.

## #98 — Group A CPython interpreter CVEs on 3.14

**STILL OPEN — correctly so.** This is a waiver tracker, not work. Opened 2026-07-26; body updated
the same day.

Verified: `ci/grype.yaml:67–69` carries exactly the three Group A entries the issue lists
(CVE-2026-15308, CVE-2026-12003, CVE-2025-15366). The resolution trigger — 3.14.7 in the pinned base
image — has not occurred. Review date 2026-10-25.

**No false claims found.** This is the only CVE document in the repo that is fully current: its
source verification was done against both the `3.14` branch *and* the `v3.14.6` tag, which is the
distinction the 2026-07-26 §14 entry identifies as the thing the 2026-07-25 pass got wrong.

## #52 — CVE-2025-15367 (poplib) — accepted risk on any interpreter below 3.15

**STILL OPEN — correctly so.** A standing acceptance with an annual re-confirmation (next
2027-07-25), deliberately not a deferral.

Verified: `ci/grype.yaml:95` carries CVE-2025-15367 alone in Group B, matching the issue's scope.

**Previously-false claims are now corrected, and the correction is verified.** This issue carried the
resolution-trigger line asserting 3.14.6 would clear CVE-2025-15366/-15367 — the claim §14
(2026-07-25) records as the cause of a wrongly-justified runtime bump. The body was rewritten on
2026-07-26 and is now accurate: it is scoped to poplib only, records the source verification against
four refs, and explicitly reclassifies CVE-2025-15366 out to #98. Its "why the two companion fixes
diverged" paragraph matches §14's account.

*One thing worth doing:* the issue's title and body are now poplib-only, but the issue is titled and
tracked as if re-scoped in place. That is fine and better than closing it — just note that #52's
**history** contains the wrong claim, so anyone linking to "#52" for the 3.14 rationale is linking
to a document that used to say the opposite. §14 already handles this.

## #75 — `[image-rescan]` Fixable HIGH/CRITICAL CVEs in `ghcr.io/tyler-rich/scrye:latest`

**STILL OPEN — real remaining work, and it is the one issue with a concrete deliverable.**

Opened by `github-actions` on 2026-07-20 from `.github/workflows/rescan.yml`'s weekly Monday
re-scan of the published images. No comments since; the workflow comments on the existing issue
rather than opening a new one, so silence here means it has only fired once since.

**What is actually left:** `ghcr.io/tyler-rich/scrye:latest` is still **v0.1.0**, tagged 2026-07-09
(`git ls-remote --tags` shows `v0.1.0` as the only tag). Since then `dev` has taken, among others:

- the explicit `curl`/`libcurl` pin for CVE-2026-5773 (#51, 2026-07-13),
- the Python 3.13 → 3.14.6 runtime move with `pydantic`, `uvicorn`, `sqlalchemy`, `greenlet` bumps (#91),
- a hash-pinned `requirements.lock` (#64) and pinned build backend (#80).

None of that is in the published `:latest`, because `:latest` is only produced by a semver tag on
`main`, and `main` has not moved since #70. **The fix for #75 is action 3 above — promote and cut a
release.** Re-running `rescan.yml` afterwards should close it; if findings survive, they are new and
the issue should be re-triaged rather than assumed stale.

I did not fetch the run's scanner output (Actions run 29720503825), so the specific CVE list is
unverified here — the recommendation stands on the image being 17 days of security work behind
`dev`, which is verifiable from the tag list alone.

## Cross-check: nothing STALE, nothing DUPLICATE

- No open issue's premise has evaporated. #63 and #83 were *done*, not invalidated.
- #98 and #52 are complementary, not duplicative — they were deliberately split on 2026-07-26
  because the two groups have different resolution triggers, and each issue names the other.
- **The repository has zero closed issues.** Every issue ever opened is still open, which is
  consistent with the closing-keyword problem and means the count is not a signal of anything.

---

# Part 2 — Full `docs/` inventory and disposition

Complete recursive inventory: 18 files across 4 directories, ~430 KB. "Last meaningful update" is
the last commit that touched the file, not filesystem mtime (every file's mtime is the clone date).

| Path | Size | Last meaningful update | What it is | Disposition |
|---|---|---|---|---|
| `docs/ARCHIVE.md` | 256K | 2026-07-26 (`96264fb`) | Historical build record + the §14 deviation log, still appended to on every PR | **KEEP** — the only durable record of *why*; actively written to weekly |
| `docs/ROADMAP.md` | 12K | 2026-07-25 (`0d15e0d`) | Forward-looking work + known limitations | **KEEP** — live; linked from README ×3 and CLAUDE.md ×2 |
| `docs/screenshots/dashboard.png` | 56K | 2026-07-09 | README screenshot | **KEEP** — embedded at `README.md:68` |
| `docs/screenshots/new-scan.png` | 60K | 2026-07-09 | README screenshot | **KEEP** — embedded at `README.md:68` |
| `docs/screenshots/results.png` | 76K | 2026-07-09 | README screenshot | **KEEP** — embedded at `README.md:68` |
| `docs/screenshots/history.png` | 68K | 2026-07-09 | README screenshot | **KEEP** — embedded at `README.md:68` |
| `docs/reviews/00-summary.md` | 20K | 2026-07-12 (`b8bd727`) | Severity-ranked synthesis of the six reports; the ID → finding decoder | **ARCHIVE** → `docs/history/reviews/` |
| `docs/reviews/security-review.md` | 20K | 2026-07-12 | SEC-* findings, all closed | **ARCHIVE** |
| `docs/reviews/supply-chain-review.md` | 28K | 2026-07-12 | SC-* findings, all closed | **ARCHIVE** |
| `docs/reviews/api-review.md` | 24K | 2026-07-12 | APIR-* findings, all closed | **ARCHIVE** |
| `docs/reviews/frontend-review.md` | 20K | 2026-07-12 | P1/P2/P3 findings, all closed | **ARCHIVE** |
| `docs/reviews/concurrency-review.md` | 32K | 2026-07-12 | CON-* findings, all closed | **ARCHIVE** |
| `docs/reviews/claude-md-compliance.md` | 36K | 2026-07-12 | D-*/R-* compliance drift, all closed | **ARCHIVE** |
| `docs/reviews/full-audit-2026-07-05.md` | 84K | 2026-07-05 (`ebad649`) | Full-repo audit, P0–P5; source of QUA-*/INF-*/FE-*/API-*/FEAT-* IDs | **ARCHIVE** |
| `docs/reviews/STATUS.md` | 20K | 2026-07-25 (`0d15e0d`) | Remediation tracker; §1 now empty | **ARCHIVE** after migrating two live items (below) |
| `docs/reviews/fix-verification.md` | 24K | 2026-07-13 (`8e100ee`) | One-off verification pass, superseded by STATUS.md | **DELETE** |
| `docs/reviews/phase3-finding2-resolution.md` | 12K | 2026-07-04 (`0197a17`) | Pre-implementation design note for generic-host git auth | **DELETE** |
| `docs/upgrades/python-3.14.md` | 8K | 2026-07-25 (`38a2141`) | Completed upgrade handoff; body carries a false CVE premise | **DELETE** (and remove the folder) |

## The specific questions asked

### Is `STATUS.md` §1 empty, and is STATUS.md still a live tracker?

**Confirmed empty.** `STATUS.md:47` reads "**Nothing is open.** There are no open HIGH, MEDIUM, LOW,
or INFO findings," and all four sub-buckets beneath it (LOW-with-an-edge, LOW UX/a11y, TRIVIAL,
test-debt) each say "_None open_". I re-verified the last three closures independently rather than
taking the file's word: SC-12 and D5b in #80 (§14, 2026-07-20 ×2), the M19/M20/M21 test back-fill
(§14, 2026-07-24), and P3-8's two strictness flags (§14, 2026-07-24 — `noUncheckedIndexedAccess` in
`tsconfig.app.json`, type-aware ESLint in `eslint.config.js`).

**STATUS.md is now a historical artifact, not a live tracker** — with two exceptions that should be
lifted out before it is archived:

1. **§4 "ARCHIVE.md §14 gaps" is fully discharged.** It lists four merged fixes lacking a dated §14
   entry (#53, #57, #65, #59). All four were back-filled in #76 — the entries exist at
   `ARCHIVE.md:1069` (#53 H1/SEC-1), `:1095` (#57 H9/SC-2 + H10/SC-3), `:1124` (#65 D1/D2/R1–R6),
   `:1145` (#59 dev-dep bumps), each marked `[back-fill]`. §4 is now a description of a solved
   problem.
2. **§2's "Operational follow-ups" are the only genuinely live content in the file** — and they are
   invisible where they sit, because nobody opens a status file whose §1 is empty:
   - The **GitHub profile display name** still reading "Tyler Richardson", which silently breaks the
     commit-authorship rule on every squash-merged promotion (R7/D4).
   - **Dependabot security alerts** confirmation in repo Settings.

   → **Migrate both into `ROADMAP.md` § Near-term**, appended to the existing "Finish the public-repo
   governance setup (repository settings)" checklist, which is exactly the right home and already
   exists. Then STATUS.md carries nothing live.

3. §2's other three rows (SC-13 Mantine v7 lock, L1/SEC-7 lazy AAD upgrade, L2/L3 OIDC MFA) are
   **decisions, not work**, and all three are already recorded elsewhere: SC-13 in CLAUDE.md locked
   decision §2, L2/L3 in `ROADMAP.md` § Known limitations. L1/SEC-7 is the one that needs a
   ROADMAP correction — see Part 4.

### `docs/upgrades/python-3.14.md` and whether `docs/upgrades/` should exist

**DELETE the file. DELETE the folder.**

The file is a completed handoff doc for work that shipped in #91. Its own banner says
"Status: DONE… Historical". But it is worse than merely stale — it carries **two layers of wrong
claim stacked on each other**:

- **The body** (`:30`) asserts "Python **3.14.6 already carries both fixes**" for CVE-2025-15366 and
  CVE-2025-15367. False, and §14 (2026-07-25) records it as the reason a runtime bump was justified
  on a security ground that did not exist.
- **The banner correcting it** (`:11–14`) asserts "Upstream declined the backport to **3.10 through
  3.14**… so both are fixed only in 3.15+" and "**This upgrade therefore cleared none of the four
  tracked CPython CVEs**". That is *also* now false for CVE-2025-15366 — §14 (2026-07-26) records
  the imaplib backport landing on the `3.14` branch on 2026-07-07 (python/cpython#153137, commit
  `2981822`), which means it closes on 3.14.7, not 3.15.

A document whose warning banner is itself wrong is a trap, not a record. Everything durable it
contains — the 3.14.6 GC floor and why it is load-bearing, the dependency blockers, the two blockers
the scoping missed (`sqlalchemy`, `ruff`), the pydantic compatibility pass, the `black`
target-version deviation, the validation results — is in §14 (2026-07-25) in more detail and more
accurately.

**The folder should not exist either.** It has held exactly one file, for one upgrade, and CLAUDE.md
§ Deviations already mandates that the durable record lives in §14. A per-upgrade scoping doc is a
reasonable working artifact for the duration of the work; keeping the folder invites the next one to
become the next orphan.

### Other documents still repeating the false claim

Grepped the whole repo for `15366|15367|15308|12003`:

| Location | Claim | Status |
|---|---|---|
| **`CHANGELOG.md:18–23`** | "upstream declined the backport to 3.10 through 3.14, so they remain unfixable until 3.15… **All four stay waived in the dogfood scan; see issue #52**" | **FALSE on both counts, and user-facing.** CVE-2025-15366 is fixed on the `3.14` branch and closes on 3.14.7; the Group A tracker is **#98**, not #52. This sits under `## [Unreleased]` and **ships as release notes on the next tag**. **Highest-priority correction in the tree.** |
| `docs/upgrades/python-3.14.md:10–14, 28, 46, 90` | as above | Resolved by deleting the file |
| `docs/ARCHIVE.md:61–62` (§0 locked decisions #7) | "CVE-2025-15366 / CVE-2025-15367 are **unfixable on 3.14 too**" | **FALSE for CVE-2025-15366.** This is in §0, the "what is locked" summary at the top of the archive — the part a reader treats as current, unlike the dated §14 entries. Worth a one-line amendment even though the archive is otherwise preserved verbatim. |
| `docs/ARCHIVE.md:635–636, 725–742` (§14, 2026-07-25) | same claim | **Leave alone.** The 2026-07-26 entry explicitly says "Nothing in the 2026-07-25 entry was edited; it stands as written and this entry supersedes it on that one point." Editing it now would destroy the record of the error. |
| `docs/ARCHIVE.md:2940–2965` (§14, 2026-07-13) | same claim, in its original form | **Leave alone** — dated, superseded twice over, and the trail is the point. |
| `CLAUDE.md:241` | "3.14.6's `imaplib`/`poplib` show it does not, and the bump cleared **nothing**" | **Still true as written.** It is a claim about the released 3.14.6, which genuinely lacks both guards. Accurate; leave it. |
| `ci/grype.yaml:40–95` | Group A/B split, three + one | **Current and correct.** Verified against #98/#52. |

## Blast radius — every inbound reference to a proposed DELETE or ARCHIVE

Grepped the whole repo including code comments, workflows, and config.

### `docs/reviews/*` (all ten files — ARCHIVE or DELETE)

**Live, non-historical documents that link into `docs/reviews/` — these break on any path change:**

| Referrer | Line | Target |
|---|---|---|
| `CONTRIBUTING.md` | 343 | `docs/reviews/api-review.md` (markdown link, § API conventions) |
| `CONTRIBUTING.md` | 182 | `docs/reviews/` directory, in § Project layout |
| `CHANGELOG.md` | 64 | `docs/reviews/api-review.md` (markdown link, in the L13/APIR-8 entry) |
| `.github/dependabot.yml` | 16 | `docs/reviews/claude-md-compliance.md` (code comment, D3 rationale) |
| `.github/dependabot.yml` | 35–36 | `docs/reviews/claude-md-compliance.md` (code comment, D3 rationale) |

**Historical prose in `docs/ARCHIVE.md` — ~30 references, all inside §14 entries:**

`00-summary.md`: `:944`, `:971`, `:996`, `:1218`, `:1273`, `:1306`, `:1358` ·
`security-review.md`: `:1093`, `:1216` ·
`supply-chain-review.md`: `:982`, `:1028`, `:1121`, `:1159`, `:1217` ·
`api-review.md`: `:1306` ·
`frontend-review.md`: `:844`, `:916`, `:919`, `:954`, `:1050`, `:1272`, `:1273` ·
`concurrency-review.md`: `:1182`, `:1352`, `:1393`, `:1394` ·
`claude-md-compliance.md`: `:1121`, `:1127`, `:1192`, `:1208` ·
`full-audit-2026-07-05.md`: `:2466` ·
`phase3-finding2-resolution.md`: `:1730` ·
`STATUS.md`: `:3150`

**Cross-references between the review files themselves** (these travel together, so they survive a
move intact): `00-summary.md:10–12` names all six sources; `STATUS.md` cites `00-summary.md` (×2),
`fix-verification.md` (×6), `frontend-review.md`; `fix-verification.md:5` cites `00-summary.md`;
`concurrency-review.md:12` and `api-review.md:16` cite `full-audit-2026-07-05.md`;
`api-review.md:59` cites `phase3-finding2-resolution.md`; `claude-md-compliance.md:94` cites
`full-audit-2026-07-05.md`.

**Precedent for sweeping these:** D1 (#65) rewrote ~100 dead `docs/PLAN.md` → `docs/ARCHIVE.md`
references inside the archive itself, so editing historical paths for a rename is established
practice here and does not violate the "preserved, not maintained" framing.

### `docs/reviews/fix-verification.md` (DELETE)

Inbound references: **`STATUS.md` only** — `:12`, `:14`, `:16`, `:21`, `:23`, `:218`. All six are
STATUS.md explaining *how it supersedes* fix-verification.md. If STATUS.md is archived alongside,
add one bracketed note there ("since deleted; the delta is itemized above") and nothing else breaks.
Zero references from live docs, code, CI, or config.

### `docs/reviews/phase3-finding2-resolution.md` (DELETE)

Inbound references: **two**, both historical — `docs/ARCHIVE.md:1730` and
`docs/reviews/api-review.md:59` (which is itself being archived). The §14 entry at `:1711` reproduces
the full rationale (go-git never invokes the system `git` binary, so it ignores `GIT_ASKPASS`/
`.netrc`/credential helpers; cloning with real `git` is the only off-argv path for generic hosts) and
additionally records the two adaptations made to the spec. The design doc adds nothing §14 lacks.

### `docs/upgrades/python-3.14.md` and `docs/upgrades/` (DELETE)

Inbound references: **five**.

| Referrer | Line | Note |
|---|---|---|
| `docs/ARCHIVE.md` | 661 | "Executed from the scoping/handoff doc `docs/upgrades/python-3.14.md`" |
| `docs/ARCHIVE.md` | 724 | cites it as the source of the wrong premise |
| `docs/ARCHIVE.md` | 761 | "closes out `docs/upgrades/python-3.14.md`" |
| `docs/ARCHIVE.md` | 2955 | 2026-07-13 entry, "handoff doc: `docs/upgrades/python-3.14.md`" |
| `CONTRIBUTING.md` | 183 | lists `docs/upgrades/` in § Project layout — **must be edited**, this is a live doc |

The four ARCHIVE references are dated historical prose naming a document that existed at the time.
Either leave them (the archive is explicitly a trail, and `:761` already says the doc is closed out)
or append "(since deleted — superseded by this entry)" at `:761` only. `CONTRIBUTING.md:183` is not
optional; the layout listing must drop the folder.

### `docs/screenshots/` — no change, but noting for completeness

Referenced from `README.md:68` (four `<img src>` tags) and the TOC at `README.md:33`. **KEEP.**

## Which files a maintainer actually opens six months from now

This is the distinction that should drive the structure.

**Opened routinely:**

- `docs/ARCHIVE.md` — §14 is consulted on every change (CLAUDE.md § Definition of done item 6 makes
  writing to it mandatory), and § Build performance is a hard "read before you touch the Dockerfile"
  gate cited from CLAUDE.md and four workflow files.
- `docs/ROADMAP.md` — the "what's next / what's a known limitation" answer.
- `docs/screenshots/` — indirectly, via the README.

**Opened only to answer "what did `SC-12` / `P3-4` / `QUA-17` mean?":**

- `00-summary.md` and the six source reports. §14 cites bare finding IDs relentlessly and never
  re-explains them. This is a **decoder ring, not a backlog** — real, but low-frequency, lookup-only
  value. It belongs behind one more directory level.
- `full-audit-2026-07-05.md` — same, for the `QUA-*`/`INF-*`/`FE-*`/`API-*`/`FEAT-*` namespace, and
  the only place those IDs are defined.

**Never opened again:**

- `fix-verification.md` — its one durable output (H5/CON-4 was silently dropped) is recorded in §14
  *and* in STATUS.md's "How this differs" section.
- `phase3-finding2-resolution.md` — superseded by the §14 entry that implemented it.
- `python-3.14.md` — superseded, and actively misleading.
- `STATUS.md` — once its two operational follow-ups are lifted into ROADMAP.

The honest summary the question invited: **yes, most of `docs/reviews/` can go behind a history
subtree now that everything is closed and §14 carries the decisions.** The one thing that argues
against outright deletion is not "it might be useful" — it is that §14's finding IDs are unresolvable
without the reports, and §14 is a document we are contractually obliged to keep writing to.

## Proposed structure

```
docs/
├── ARCHIVE.md                    live — build record + §14 deviation log (still written to)
├── ROADMAP.md                    live — forward-looking work + known limitations
├── screenshots/                  live — embedded in README
│   ├── dashboard.png
│   ├── new-scan.png
│   ├── results.png
│   └── history.png
└── history/                      paper trail — lookup only, not a backlog
    ├── README.md                 NEW: index — what's here, what superseded it, how to read a finding ID
    └── reviews/
        ├── 00-summary.md         the ID → finding decoder
        ├── security-review.md
        ├── supply-chain-review.md
        ├── api-review.md
        ├── frontend-review.md
        ├── concurrency-review.md
        ├── claude-md-compliance.md
        ├── full-audit-2026-07-05.md
        └── STATUS.md             archived once its two operational follow-ups move to ROADMAP
```

**Deleted:** `docs/reviews/fix-verification.md`, `docs/reviews/phase3-finding2-resolution.md`,
`docs/upgrades/python-3.14.md`, and the `docs/upgrades/` folder.

**`docs/history/README.md` should say, in about fifteen lines:** these are closed findings from the
2026-07 review cycle and the 2026-07-05 full audit; every finding in them is resolved (verified
2026-07-26); they exist so a finding ID cited in `ARCHIVE.md` §14 can be resolved to its original
text; nothing here is a backlog and nothing here should be worked from; open work lives in
`ROADMAP.md` and in GitHub issues.

**Reference sweep required by the move** (5 live-document edits + ~30 archive edits, enumerated in
the blast-radius tables above):

- `CONTRIBUTING.md:182–183` — layout listing: `reviews/` → `history/`, drop `upgrades/`.
- `CONTRIBUTING.md:343` — link → `docs/history/reviews/api-review.md`.
- `CHANGELOG.md:64` — link → `docs/history/reviews/api-review.md`.
- `.github/dependabot.yml:16, 35–36` — comment paths → `docs/history/reviews/claude-md-compliance.md`.
- `docs/ARCHIVE.md` — ~30 `docs/reviews/` → `docs/history/reviews/`, same sweep D1 performed for
  `PLAN.md`. Also fix the **broken** one at `:1004` (see Part 4).

**Alternative if you'd rather not touch 35 references:** leave the paths at `docs/reviews/` and add
`docs/reviews/README.md` with the same banner. That achieves the "don't work from this" signal at
zero blast radius but not the "current docs aren't buried" goal — `docs/` still lists ten historical
files next to two live ones. I recommend the move; the precedent exists and the sweep is mechanical.

## Disposition of this file

**This file (`docs/reviews/CLEANUP-AUDIT.md`) should not survive its own recommendations.**

It is written to `docs/reviews/` because that is where it was asked to go, but that folder is one of
the things it recommends gutting — so it would become exactly the orphan it is auditing. Proposed
lifecycle:

1. **Now → until you have accepted or rejected each proposal.** It lives at
   `docs/reviews/CLEANUP-AUDIT.md` and is the working document.
2. **When the cleanup lands.** The decisions you accept get a dated `docs/ARCHIVE.md` §14 entry —
   which is where they belong under CLAUDE.md § Deviations, and which makes this file's *conclusions*
   permanent without keeping its *reasoning*. The file itself is **DELETED** in that same PR.
3. **It should not move to `docs/history/`.** The material it preserves is a snapshot of a mess that
   will no longer exist; the §14 entry is the durable artifact. Archiving an audit of an archive is
   how the folder got to ten files in the first place.

If any proposal here is rejected and the reasoning is worth keeping (e.g. you keep `docs/reviews/`
as-is and want the record of why deleting it was considered), the two-sentence version goes in the
§14 entry — not this file.

---

# Part 3 — Unfinished work buried in `ARCHIVE.md` §14

Grepped every §14 entry for "still to do", "not done", "follow-up", "deferred", "left alone",
"tracked for", "outside this scope", "remains open", "revisit", and unchecked task boxes, then
verified each hit against the current code, `ROADMAP.md`, and the open issues.

**The good news first:** most of what §14 parked has since been done, and each closure was itself
logged. The list of genuinely outstanding items is short. The list of items that are outstanding
**and invisible** — recorded only in prose, with no ROADMAP entry and no issue — is shorter still,
and is where the risk is.

## A. Outstanding, prose-only — no live tracking reference. These are the invisible ones.

| # | Item | Source entry | Where it's recorded | Note |
|---|---|---|---|---|
| A1 | **Repo Settings → Actions → Workflow permissions should be set to read-only.** Each workflow declares its own explicit `permissions:` block, so the restrictive default breaks nothing — but it has to be set by hand in Settings. | 2026-07-06 (`ARCHIVE.md:1536`) | §14 prose only | Never migrated to ROADMAP when the governance checklist was written on 2026-07-09. A concrete, five-second hardening step that has been invisible for 20 days. |
| A2 | **Confirm GHCR package visibility.** The 2026-07-06 entry asks to confirm the package is *Private*; the repo went **public** on 2026-07-09, so the check is now the inverse — confirm it is public, per CLAUDE.md locked decision §6. | 2026-07-06 (`ARCHIVE.md:1537`) | §14 prose only | Premise inverted by a later entry. Still unverified either way. |
| A3 | **`DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` repo secrets are unused and can be deleted.** No workflow references them since the GHCR consolidation. | 2026-07-09 (`ARCHIVE.md:2683`) | §14 prose only | A dormant registry credential on a public security-tool repo. Verified: `grep -r DOCKERHUB .github/` returns nothing. |
| A4 | **Backup restore derives the passphrase key from module scrypt constants rather than the envelope's advertised parameters.** | 2026-07-04 (`ARCHIVE.md:2308`) | — | **Already resolved** — 2026-07-05 P5 entry (`:2653`) implemented it (`derive_key`/`passphrase_cipher` take explicit `n/r/p`). Listed here only so it isn't re-counted as open. |

**A1–A3 are the answer to "what goes invisible."** All three are repository-settings work that a
code session cannot do, all three were logged in prose at the moment of the decision, and none was
carried into ROADMAP's governance checklist when that checklist was created three days later.
**Recommendation: append A1, A2, A3 to `ROADMAP.md` § Near-term → "Finish the public-repo governance
setup", alongside the two operational follow-ups being lifted out of STATUS.md §2** (Part 2). That
gives all five settings-level items one home.

## B. Outstanding, and already tracked in `ROADMAP.md`

No action beyond keeping ROADMAP accurate; listed so nothing is double-counted.

| Item | Source entry | ROADMAP home |
|---|---|---|
| Four near-identical secret-CRUD routers not consolidated (QUA-4) | 2026-07-05 P5 (`:2664`); re-confirmed 2026-07-25 (`:3150`) | § Medium-term → Backend structural cleanup |
| Type checker (mypy/pyright) in CI, blocked on annotation gaps (QUA-16 / QUA-17) | 2026-07-05 P5 (`:2668`) | § Medium-term → Type-checking in CI |
| Cross-version backup restore (forward-migrate an older bundle) | 2026-07-03 P5 (`:1919`) | § Medium-term → Cross-version backup restore |
| Framed/streaming backup encryption (GCM is single-shot) | 2026-07-05 P0 (`:2479`) | § Longer-term + § Known limitations |
| Native arm64 CI runners instead of QEMU | 2026-07-07 build-perf (`:2790`) | § Longer-term → Native arm64 CI runners |
| Branch protection + signed-commit decision + private vuln reporting | 2026-07-09 (`:2702`) | § Near-term → public-repo governance |

**One correction needed in that set:** the arm64 entry at `:2790` justifies deferral on "this is a
**private** repo, so hosted arm64 runners bill per-minute." The repo went public on 2026-07-09 and
ROADMAP already records that the cost gate is gone — so §14's rationale is stale relative to
ROADMAP's. Historical prose; no edit needed, but don't read `:2790` as current.

## C. Deferred in §14, since closed — verified, listed so they aren't re-counted

| Item | Deferred in | Closed in |
|---|---|---|
| Row-bound secret AAD | 2026-07-04 (`:2304`) | #64 — `secret_store.py:54` `row_aad()`, row-bound on write with a column-only read fallback |
| List-response envelope standardization (L13/APIR-8, QUA-9) | 2026-07-05 P5 (`:2665`) | #90 — §14 2026-07-25, `backend/app/api/pagination.py` |
| Frontend test runner (FE-10) | 2026-07-05 P5 (`:2673`) | #78 — Vitest 3.2.7, `npm test`; §14 2026-07-20 |
| wollomatic socket-proxy migration (M23/SC-7 deferred half) | 2026-07-13 (`:1265`) | #89 — §14 2026-07-24; issue #63 (still open, see Part 1) |
| ruff bump / D5b latent lint | 2026-07-13 (`:1157`) | #80 (D5b), #91 (ruff 0.8.6 → 0.16.0) |
| Live `docker compose --profile docker-env up` verification | 2026-07-24 (`:3058`) | §14 2026-07-26 — real Debian host, four operational corrections |
| Two stale tecnativa wordings in Compose comment + `docker_proxy.py` error string | 2026-07-26 (`:3249`) | #97 — §14 2026-07-26 |
| P3-4 auth-refresh race | 2026-07-24 (`:952`) | #82; its mirror #83 by #87 |
| Scanner-DB schedule actuation (FEAT-4) | 2026-07-03 P5 (`:1905`) | 2026-07-05 P3 maintenance tick (`:2646` records both the gap and the fix) |
| INF-2 fork-PR publish-secret gap | 2026-07-05 P2 (`:2542`) | 2026-07-06, fully retired 2026-07-09 |

## D. Cross-check against ROADMAP and open issues — nothing double-counted, nothing orphaned

- **No §14 deferral is duplicated by an open issue.** #98 and #52 are waiver trackers with no §14
  deferral behind them; #75 is a bot artifact; #63 and #83 are resolved.
- **No ROADMAP item is silently also a §14 deferral** — the six in table B are the overlap, and each
  is the same item, correctly stated once.
- **A1, A2 and A3 are orphaned:** in §14 only, in no issue, in no ROADMAP section. That is the
  entirety of the "recorded in prose and therefore invisible" set.

---

# Part 4 — Anything else worth cleaning

## 4.1 `ARCHIVE.md` size and navigability — and one structural bug

**3,426 lines / 256 KB. §14 alone is ~2,900 of them, across roughly 70 dated entries.** It is
becoming hard to use, and there is a concrete defect making it worse.

**The bug: §14 is not contiguous.** `## Build performance` opens at `ARCHIVE.md:2721`. Everything
after it is nested under that heading — including **fourteen dated deviation entries** that are not
about build performance at all:

`:2830` (2026-07-09 teal/scan-deletion) · `:2855` (2026-07-09 bundled-binary CVEs) · `:2922`
(2026-07-13 curl pin) · `:2938` (2026-07-13 interpreter CVEs) · `:2971` (2026-07-20 Vitest harness) ·
`:2997` (2026-07-24 wollomatic) · `:3076` (2026-07-25 list envelope) · `:3153` (2026-07-25
socket-proxy follow-ups) · `:3195` (2026-07-26 live Debian run) · `:3264` (2026-07-26 stale wording) ·
`:3301` (2026-07-26 Group A re-verification) · `:3357` (2026-07-26 imaplib regrouping).

**Every entry from the last two weeks is filed under the wrong heading.** Anyone scrolling §14
"to the end" stops at line 2720 and misses all of it. This alone explains most of the
hard-to-navigate feeling.

**Also: entries are not in a consistent order.** §14 runs newest-first from `:550` (2026-07-25) back
to `:1477` (2026-07-07), then flips to oldest-first from `:1550` (2026-06-30) forward through
`:2678` (2026-07-09) — then the post-Build-performance tail runs oldest-first again. Three ordering
regimes in one section.

**Recommendation (recommend, not restructure):**

1. **Fix the nesting first — it is the cheap high-value fix.** Either move `## Build performance`
   to the end of the file so §14 is contiguous, or promote the fourteen orphaned entries back under
   a `## 14. Deviations (continued)` heading. Moving the Build performance section is less
   disruptive: it is self-contained, cross-referenced by heading name (`§ Build performance`) rather
   than by line, from CLAUDE.md and four workflow files, so moving it breaks nothing.
2. **Add a table of contents at the top of §14** — one line per entry (`date — phase — title`,
   anchored). ~70 lines that turn a 2,900-line scroll into a lookup. This is the single biggest
   usability win and costs one generated block.
3. **Pick one order and state it** at the top of §14. Newest-first matches how the file is actually
   used (the recent decisions are the ones being consulted) and matches the current head of the file.
4. **Do not split the file yet.** Splitting §14 into per-period files would break the ~30 in-repo
   `docs/ARCHIVE.md §14` references and the "one dated log" habit CLAUDE.md enforces. Revisit at
   ~5,000 lines; a TOC buys a lot of runway.

**Separate defect: one dead link inside ARCHIVE.md.** `ARCHIVE.md:1004` cites
`docs/reviews/claude-md-compliance-review.md`. **That file does not exist** — the actual filename is
`claude-md-compliance.md`. Fix it in the same pass as the Part 2 path sweep.

## 4.2 `ROADMAP.md` — items now done, and one false claim

| ROADMAP item | Line | Status | Recommended |
|---|---|---|---|
| **"Pin GitHub Actions to commit SHAs."** "the workflow `uses:` references are pinned by tag, not by full commit SHA." | 38–41 | **DONE** — H9/SC-2 in #57. Verified: `ci.yml` 8 SHA-pinned `uses:`, `dev-nightly.yml` 3, `publish.yml` 3, `rescan.yml` 2; e.g. `actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0`. | **Strike.** The description is now factually wrong about the repo. |
| **"Frontend test runner."** "There is no frontend test runner yet" | 75–78 | **DONE** — #78. Verified: `frontend/package.json:11` `"test": "vitest run"`, `vitest 3.2.7` at `:47`; 20 Vitest files; CLAUDE.md § Testing already documents it. | **Strike.** |
| **"Row-bound secret AAD."** "Each field-encrypted secret is currently bound … to its *column*, not its *row*." | 102–107 | **FALSE as stated** — L1/SEC-7 in #64. `backend/app/core/secret_store.py:54` `row_aad()` composes `"<column-tag>:<row-id>"`; `encrypt_secret()` binds to the row when given one, `decrypt_secret()` falls back to the bare column tag for legacy ciphertext. | **Rewrite, don't strike.** What remains open is only the *bulk re-encryption* that would cut legacy column-only ciphertext over eagerly — which is the "Admin bulk secret re-encryption" near-term item this one already pairs itself with. Fold it in there. |
| **"Backend structural cleanup."** | 84–87 | **Half done** — already correctly annotated with the list-envelope parenthetical. | **No change.** |
| **"Finish the public-repo governance setup."** | 42–50 | Still open | **Extend** with A1/A2/A3 from Part 3 and the two STATUS.md §2 operational follow-ups. |

## 4.3 `CHANGELOG.md` — is a release warranted?

**Yes, and it is overdue.**

`## [Unreleased]` holds **four substantial Changed entries**, all of them contract- or
deployment-affecting:

1. Python 3.13 → 3.14.6 runtime move, with four dependency bumps.
2. Thirteen list endpoints moved to the `{total, items}` envelope — **explicitly flagged "Action
   required for API-token consumers"**.
3. `GET /api/scans` deprecated.
4. Socket proxy migrated to wollomatic — **explicitly flagged "Action required if you use the
   `docker-env` profile"** (`DOCKER_GID` must now be set).

Two "action required" notices and an API contract change are sitting unreleased. Meanwhile `:latest`
is v0.1.0 from 2026-07-09, and issue #75 says it now carries fixable HIGH/CRITICAL CVEs.

**Recommendation: promote `dev` → `main` and tag `v0.2.0`** (minor, not patch — the envelope change
breaks API-token scripts, which the entry itself says). Per CLAUDE.md § Git conventions this is a
deliberate user-requested promotion, hence a recommendation rather than an action. Before tagging:

- **Correct the false CVE paragraph at `CHANGELOG.md:18–23` first** (Part 2). Once tagged, that text
  is permanent release-note history.
- Add an `### Fixed` or `### Security` line noting the base-image/dependency currency, so the release
  visibly answers #75.
- Back-merge `main` into `dev` immediately after, per CLAUDE.md.

**Also worth noting: `main` is 30 commits behind `dev` and this has an operational cost beyond
release notes.** Scheduled and tag-triggered workflows run from the **default branch's** copy — the
archive says so explicitly at `:2816`. So `dev-nightly.yml` and `rescan.yml` are currently running
the versions of themselves that were on `main` at #70 (2026-07-13), regardless of what `dev` has
since. Every workflow improvement merged to `dev` in the last two weeks is inert for the nightly and
the weekly re-scan until a promotion lands.

## 4.4 Stale remote branches

**39 branches on the remote. 2 are branch-model branches, 4 are live Dependabot PRs, and 33 are
merged leftovers.**

Because promotions and PRs are **squash-merged**, `git branch -r --merged origin/dev` reports
nothing — I mapped each branch to its PR instead and verified merge state via the API.

**Safe to prune — 33 branches, each the head of a merged PR:**

`ccr-8d4520bf-exibce` (#81) · `claude/account-takeover-chain-fix-u8h5bw` (#55) ·
`claude/api-review-findings-g80j7y` (#61) · `claude/archive-backfill-entries-51t3jj` (#76) ·
`claude/auth-refresh-logout-race-8cs4h6` (#82) · `claude/claude-docs-compliance-audit-wn4wux` (#65) ·
`claude/con-sec-retry-restore-scrypt-dd913t` (#54) · `claude/concurrency-review-fixes-opv8u6` (#60) ·
`claude/docker-proxy-wollomatic-migration-f03eif` (#89) ·
`claude/docs-audit-readme-contributing-c0tbgb` (#95) · `claude/docs-reviews-audit-banv8b` (#74) ·
`claude/frontend-review-wave-2-uin5z0` (#62) · `claude/frontend-test-harness-el4nev` (#78) ·
`claude/group-a-cve-waivers-3.14-uw1xh1` (#99) · `claude/h5-con4-scanner-parse-jwr2ad` (#67) ·
`claude/magical-brown-w9m5q9` (#57) · `claude/python-3-14-upgrade-e4bg1k` (#91) ·
`claude/regroup-imaplib-cve-2025-15366` (#100) · `claude/relaxed-ptolemy-ncig87` (#59) ·
`claude/repository-scan-allowlist-bypass-qt98tt` (#53) · `claude/review-fix-verification-k7k2tr` (#66) ·
`claude/sc12-d5b-backend-fixes-ctnioa` (#80) · `claude/scanner-subprocess-cleanup-rt3b5d` (#56) ·
`claude/security-review-findings-76qnmu` (#64) · `claude/session-9d5ra6` (#77) ·
`claude/test-debt-backfill-r5f1pi` (#84) · `claude/wollomatic-migration-followups-43jq81` (#94) ·
`feat/reviews` (#50) · `fix/curl-cve-2026-5773` (#51)

**Plus the six original code-review branches, which never had their own PR** — their reports were
collected onto `feat/reviews` and merged as #50:

`claude/api-db-models-review-e2afbf` · `claude/claude-md-compliance-audit-lr5l7n` ·
`claude/mantine-frontend-review-xap5n5` · `claude/scrye-concurrency-review-0xuywr` ·
`claude/scrye-security-review-q7973e` · `claude/supply-chain-security-review-cfgy57`

I verified these six individually rather than assuming: for each,
`git diff --stat origin/dev origin/<branch> -- docs/reviews/` shows **deletions only, zero
insertions** — i.e. every line the branch contributed is byte-identical on `dev`, and the diff is
only `dev`'s *other* reports that the branch predates. Nothing is lost by deleting them.

**Do not prune (6):** `dev`, `main`, and the four Dependabot branches backing open PRs
(`dependabot/pip/backend/dev/…`, `dependabot/docker/docker/dev/…`,
`dependabot/npm_and_yarn/frontend/dev/…`, `dependabot/github_actions/dev/…`).

**Process suggestion:** enable *Settings → General → Automatically delete head branches*. It would
have prevented all 33 and costs nothing.

## 4.5 CLAUDE.md gaps — proposed wording (not applied)

Two operational lessons from this week are unrecorded. Both are the kind of thing that costs an hour
each time it is rediscovered. Proposed as two new bullets in **§ Git & PR conventions**, placed
immediately after the existing "Landing a multi-PR stacked batch is not 'merge each PR in order and
walk away'" bullet, which is where a reader hits this problem.

**(a) Retargeting a stacked PR after a squash-merge**

> - **Retargeting a stacked child PR after its parent was squash-merged requires
>   `git rebase --onto`, not just changing the base in the UI.** A squash-merge does not preserve the
>   parent branch's commits — it replaces them with one new commit on the target branch — so the
>   child's original commits are orphaned. Flipping the base in the GitHub UI does **not** re-parent
>   them: GitHub recomputes the merge base against the new target, finds the old parent commits
>   absent from its history, and falls back to a much older common ancestor, so the PR's diff balloons
>   to include everything the parent already landed. The fix is to rebase the child onto the true
>   target first and then change the base:
>   `git fetch origin <target> && git rebase --onto origin/<target> <old-parent-branch> <child-branch>`
>   followed by `git push --force-with-lease`. **Verify the diff after retargeting, every time** — a
>   child PR that suddenly shows its parent's files is this failure, not a conflict, and merging it
>   would re-apply already-landed work.

**(b) `on: pull_request` does not fire on a base change**

> - **A base-branch change alone never re-runs CI.** `on: pull_request` with no explicit `types:`
>   defaults to `opened`, `synchronize`, and `reopened` — it does **not** include `edited`, and
>   changing a PR's base is an `edited` event, not a `synchronize`. So after retargeting a stacked PR
>   the checks shown are the ones from the *old* base and are stale, even though they read green.
>   Either push a commit (any `synchronize` re-triggers the full workflow), re-run the workflow
>   manually, or close-and-reopen the PR — and **never treat a green check from before a base change
>   as the CI gate** required by § Definition of done item 3. If a workflow genuinely needs to react
>   to retargeting, it must opt in explicitly with
>   `on: pull_request: types: [opened, synchronize, reopened, edited]`.

## 4.6 Other things a maintainer would want cleaned

**a. Four Dependabot PRs open against `dev`, none merged.**

| PR | Group | Opened |
|---|---|---|
| #85 | github-actions, 5 updates | 2026-07-24 |
| #86 | frontend, **25 updates** | 2026-07-24 |
| #92 | docker-images, 2 updates | 2026-07-25 |
| #93 | backend, 5 updates | 2026-07-25 |

Six earlier Dependabot PRs (#68, #69, #71, #72, #73, #79) were **closed without merging** — several
superseded by later grouped ones, which is normal, but the pattern is that Dependabot PRs here are
not being landed. For a project whose CLAUDE.md § Dependency hygiene requires current, no-known-vuln
pins and whose CI dogfoods its own scanner, an aging dependency queue is a direct contradiction of
the stated standard. **Recommend triaging all four before the v0.2.0 promotion** — note that #93
(backend) will require regenerating `requirements.lock` per CLAUDE.md, and #86's 25 frontend updates
should be reviewed against the type-aware ESLint gate.

**b. `docs/reviews/00-summary.md:91` cites "ROADMAP/INF-1" as "unresolved and the risk went up".**
INF-1 is the Actions SHA-pinning item, which was resolved in #57. Historical text, no action beyond
what the Part 2 archive move already does — flagged so it is not read as current if the file is
consulted.

**c. `THIRD_PARTY_LICENSES/` was not re-verified in this audit.** CLAUDE.md § Third-party license
attribution requires the bundled Trivy/Grype/Syft `LICENSE`/`NOTICE` files to match the versions
actually pulled at build time. §14 (`:2306`) records one past drift (a `THIRD_PARTY_LICENSES` Trivy
version corrected to 0.72.0). Worth a check before the v0.2.0 tag; out of scope here.

**d. No release automation gap, but a release *checklist* gap.** `CONTRIBUTING.md` § Releasing
documents the promotion-title convention and the tag mechanics. Given the number of pre-tag items
this audit surfaced (correct the CHANGELOG CVE paragraph, verify THIRD_PARTY_LICENSES, land
Dependabot, back-merge `main` → `dev` after), a short "before you tag" checklist in § Releasing would
be worth more than it costs.

**e. `docs/reviews/` has no README.** Ten files, no index, no statement that everything in them is
closed. That is the proximate reason a prior cleanup pass concluded "keep most of them" — with no
banner saying otherwise, each file reads as potentially live. The proposed `docs/history/README.md`
(Part 2) fixes this; if you take the low-churn alternative and leave the paths alone, add the README
anyway.

---

## Appendix — verification method

- **Issue status** was determined by reading the code on `dev` at `96264fb` and citing `file:line`,
  never by reading issue state or trusting a prior report. Every "RESOLVED" above names the
  file:line and the PR.
- **CVE claims** were checked against `ci/grype.yaml` as it stands and against the two 2026-07-26
  §14 entries, which are themselves the corrections to the 2026-07-25 entry. I did not independently
  re-fetch CPython refs; the §14 entries record that work with commit SHAs and merge dates, and #98's
  body reproduces it.
- **Inbound references** come from a repo-wide grep across `*.md`, `*.py`, `*.ts`, `*.tsx`, `*.yml`,
  `*.yaml`, `*.toml`, `*.json`, `*.sh`, and `Dockerfile*`, excluding `node_modules`.
- **Branch merge state** was established by mapping all 91 closed PRs to their head branches, plus a
  content diff for the six review branches that never had a PR.
- **Not verified (stated so you can weigh it):** the specific CVE list behind issue #75 (the Actions
  run output was not fetched); GitHub repository *settings* (workflow permissions, GHCR package
  visibility, branch protection, Dependabot alerts, the profile display name) — none is readable
  from a code session, which is precisely why those items keep going invisible.
