# Upgrade scoping — Python 3.13 → 3.14

> **Status: DONE (2026-07-25). Historical — kept as the record of how the upgrade was scoped, not
> as live guidance.** The runtime now runs on Python 3.14.6; locked decision §2 / §0.7 was revised
> accordingly. For what was actually implemented — including the two dependency bumps this document
> did not anticipate (`sqlalchemy`, `ruff`), the pydantic compatibility-pass result, and the
> `black` target-version deviation — see `docs/ARCHIVE.md` §14, entry dated **2026-07-25**.
>
> **⚠️ The "Why this upgrade exists" premise below is WRONG — read this first.** This document
> asserts that "Python 3.14.6 already carries both fixes" for CVE-2025-15366 and CVE-2025-15367.
> It does not. Upstream declined the backport to **3.10 through 3.14**, not just to 3.13, so both
> are fixed only in 3.15+. The CI dogfood scan reports them against interpreter 3.14.6 with
> `FIXED IN 3.15.0a6`, and 3.14.6's own `imaplib`/`poplib` confirm the fix is absent. **This
> upgrade therefore cleared none of the four tracked CPython CVEs**; all four remain waived.
> Everything else in the scoping — the 3.14.6 GC floor, the dependency blockers, the validation
> plan — held up. See `docs/ARCHIVE.md` §14 (2026-07-25) for the correction.
>
> **Cross-references:** tracking issue [#52](https://github.com/tyler-rich/Scrye/issues/52) and the
> `docs/ARCHIVE.md` §14 entry dated 2026-07-13 (the decision to defer 3.14 to this project).
>
> Everything below is the scoping as written on 2026-07-13, preserved unedited — including the
> incorrect CVE premise, so the error stays visible rather than silently rewritten.

## Why this upgrade exists

Four CPython interpreter-binary CVEs are flagged by the CI dogfood Grype scan on Python 3.13.14 and
are unfixable on the 3.13 line today (see issue #52 for the full breakdown). Two of them
(CVE-2025-15366, CVE-2025-15367) were **explicitly declined for backport to 3.13** by upstream and
are fixed only in 3.15+; the practical path to clearing them is moving the runtime forward. Python
**3.14.6 already carries both fixes.** This upgrade is the deliberate way to close that gap — *not*
a rushed, CVE-driven bump.

Note: the other two CVEs (CVE-2026-15308, CVE-2026-12003) are **not** resolved by moving to 3.14 —
their fixes are merged to both the 3.13 and 3.14 maintenance branches but not yet in any released
point version, so they close on the next 3.13.x **or** 3.14.x point release regardless of this
upgrade.

## Goal

- Move the backend runtime to **Python 3.14.6 or later** — **never 3.14.0 through 3.14.4.**
  Those releases shipped an incremental garbage collector that caused **large resident-memory
  growth (up to ~5×) in long-running web-server workloads** (a work-estimate calculation that could
  go negative and never clear the cyclic-garbage backlog). It was **reverted in 3.14.5**, which
  restored the 3.13 generational GC. 3.14.6 (2026-06-10) is the first fully-safe release after that
  revert. Pin the base image to a 3.14.6+ digest.
- Clear CVE-2025-15366 / CVE-2025-15367 (they close automatically once off the 3.13 line), then
  drop their waivers from `ci/grype.yaml`. Re-check whether CVE-2026-15308 / CVE-2026-12003 have
  landed in a released 3.14.x by then and drop those waivers too if so.

## Required dependency changes (the blocking work)

These are **hard blockers** — a 3.14 image build fails today at the current pins:

| Package | Current pin | Required | Reason |
|---|---|---|---|
| **pydantic** | `2.10.4` | **`>=2.12`** | Pinned 2.10.4 pulls **pydantic-core 2.27.2**, which has **no cp314 wheel** and **fails to build from source** on 3.14 (PyO3 ≤3.13 max; missing `PyUnicode_New`/`PyUnicode_KIND`). A cp314 wheel first appears in a later pydantic-core (e.g. 2.47.0), pulled by pydantic ≥2.12. **⚠️ This is not a routine bump** — it moves the whole Pydantic-v2 I/O-validation layer forward and, per CLAUDE.md § When to ask vs. decide (data-model / schema surface), **needs its own compatibility pass and user sign-off**, not a silent version change. |
| **uvicorn[standard]** | `0.34.0` | **`>=0.38.0`** | Official Python 3.14 support landed in uvicorn 0.38.0; 0.34.0 predates it, and the bundled `uvloop`/`httptools` aren't validated for 3.14 at that version. |
| **greenlet** | *(not pinned)* | **add an explicit pin** | SQLAlchemy 2.0.x async depends on greenlet, which no longer auto-installs; 3.14 greenlet wheels exist, but the dependency must be declared explicitly (add `greenlet` to `pyproject.toml`, or switch the SQLAlchemy dep to the `sqlalchemy[asyncio]` extra). |

## Confirmed already-compatible at their current pins

No change expected for these on 3.14 (verified via each project's 3.14 wheel/classifier status):

- **cryptography** `49.0.0` — ships cp314 wheels.
- **fastapi** `0.139.0` — declares the 3.14 classifier.
- **argon2-cffi** `25.1.0` (via cffi, which has 3.14 wheels), **httpx** `0.28.1`, **authlib**
  `1.7.2`, **pyotp** `2.10.0`, **alembic** `1.14.0`, **starlette** `1.3.1` — pure-Python or already
  3.14-ready; no blockers found.

Re-verify each at implementation time (versions may have moved), but none are expected to block.

## Runtime-behavior notes (no action needed, just awareness)

- **GC:** 3.14.6 runs the **same generational GC as 3.13** (the incremental GC was reverted in
  3.14.5). No behavior change from 3.13 on this axis — provided the base image is 3.14.6+.
- **Free-threading (PEP 703):** opt-in only, requires the separate `python3.14t` build. The standard
  `python:3.14-slim-bookworm` image is the normal GIL build → **no impact** unless deliberately
  adopted.
- **JIT (PEP 744):** experimental and **disabled by default** on Linux (needs a build-time flag).
  The slim Linux image won't have it → **no impact**.

## Required validation before the upgrade PR is considered done

1. Full backend test suite passes on 3.14.6 (the 3.12→3.13 bump validated the same way — see
   `docs/ARCHIVE.md` §14, 2026-07-03: full suite + a clean Alembic upgrade/downgrade/upgrade cycle +
   a clean app import, watching for C-extension/Rust wheel gaps).
2. `docker compose up` brings the stack up and `/healthz` returns healthy on the 3.14.6 image.
3. CI dogfood scan (Trivy + Grype) is **green, or every remaining finding is documented** — and the
   3.13-era interpreter-CVE waivers in `ci/grype.yaml` are removed for whatever the move actually
   clears (at minimum CVE-2025-15366 / CVE-2025-15367).
4. Lint clean (ruff + black; bump `target-version` to `py314`).
5. CLAUDE.md §2 and `docs/ARCHIVE.md` §0.7 updated to the new runtime lock, with a new
   `docs/ARCHIVE.md` §14 deviation entry, and issue #52 updated/closed as appropriate.
